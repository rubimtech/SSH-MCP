"""Loading and validation of ``servers.yaml``.

Supported layout (everything except ``host`` and credentials is optional)::

    defaults:
      port: 22
      username: root
      connect_timeout: 30
      keepalive_interval: 30

    settings:
      default_server: prod
      allowed_local_dirs: [D:/DEV]

    servers:
      # Comment line 1 - shown to the agent by ssh_list_servers.
      # Comment line 2.
      prod:
        host: 1.2.3.4
        username: root
        description: Production stack
        tags: [prod, docker]
        default_workdir: /opt/app
        auth:
          type: password
          password: ${PROD_PASSWORD}

      db:
        host: 10.0.0.5
        jump_via: prod
        auth:
          type: auto            # key -> agent -> password
          key_path: ~/.ssh/id_ed25519
          passphrase: ${DB_KEY_PASSPHRASE}
          password: ${DB_PASSWORD}

Any string value may reference environment variables as ``${VAR}`` or
``${VAR:-fallback}``; secrets therefore stay out of version control.

Host keys live in a ``known_hosts`` file next to this configuration (override per
server with ``known_hosts``); ``host_key_policy`` chooses between trust-on-first-use
(``auto_add``/``tofu``), strict ``reject`` and ``pin`` by ``host_key_fingerprint``
(``ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub``).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence, cast

import yaml
from dotenv import load_dotenv

from .errors import ConfigError, UnknownServerError
from .models import DEFAULT_KEEPALIVE, AuthConfig, AuthType, HostKeyPolicy, ServerProfile

DEFAULT_CONFIG_FILENAME = "servers.yaml"
KNOWN_HOSTS_FILENAME = "known_hosts"
ENV_CONFIG_PATH = "SSH_MCP_CONFIG"
ENV_CONFIG_DIR = "SSH_MCP_CONFIG_DIR"
ENV_EXTRA_DIRS = "SSH_ALLOWED_LOCAL_DIRS"
ENV_LOG_LEVEL = "SSH_MCP_LOG_LEVEL"
MAX_JUMP_DEPTH = 8

_HOST_KEY_POLICIES = {"auto_add", "tofu", "reject", "pin"}

_ENV_REF = re.compile(r"\$\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?::-(?P<fallback>[^}]*))?\}")

# ``ssh-keygen -lf`` печатает ``SHA256:<base64>`` либо ``MD5:aa:bb:...``.
_FINGERPRINT = re.compile(
    r"^(?:SHA256:[A-Za-z0-9+/]{43}=?|MD5:(?:[0-9a-fA-F]{2}:){15}[0-9a-fA-F]{2})$",
    re.IGNORECASE,
)

_SERVER_KEYS = {
    "name",
    "host",
    "hostname",
    "address",
    "port",
    "username",
    "user",
    "description",
    "comment",
    "comments",
    "notes",
    "tags",
    "jump_via",
    "via",
    "bastion",
    "default_workdir",
    "workdir",
    "connect_timeout",
    "auth_timeout",
    "keepalive_interval",
    "host_key_policy",
    "host_key_fingerprint",
    "known_hosts",
    "default",
    "auth",
    "password",
    "key_path",
    "key",
    "passphrase",
}
_AUTH_KEYS = {
    "type",
    "password",
    "key_path",
    "key",
    "passphrase",
    "use_agent",
    "password_fallback",
}
_ROOT_KEYS = {"servers", "defaults", "settings", "default_server"}
_SETTINGS_KEYS = {"default_server", "allowed_local_dirs", "log_level"}


@dataclass(frozen=True, slots=True)
class ServerRegistry:
    """Validated, immutable view over the configuration file."""

    path: Path
    servers: Mapping[str, ServerProfile]
    default_server: str
    allowed_local_dirs: tuple[Path, ...]
    jump_chains: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def names(self) -> list[str]:
        return list(self.servers)

    def describe(self) -> list[dict[str, Any]]:
        """Перечисление для агента: без адресов, портов, логинов и локальных путей."""
        return [
            self.servers[name].public(jump_chain=self.chain(name))
            for name in self.servers
        ]

    def get(self, name: str | None) -> ServerProfile:
        """Resolve a server by name, falling back to host/tag matching."""
        key = (name or "").strip() or self.default_server
        profile = self.servers.get(key)
        if profile is not None:
            return profile

        lowered = key.casefold()
        for candidate in self.servers.values():
            if candidate.name.casefold() == lowered:
                return candidate

        matches = [
            candidate
            for candidate in self.servers.values()
            if candidate.host == key or lowered in {tag.casefold() for tag in candidate.tags}
        ]
        if len(matches) == 1:
            return matches[0]
        raise UnknownServerError(key, self.names())

    def chain(self, name: str) -> tuple[str, ...]:
        """Ordered jump-host chain, first hop first, target last."""
        return self.jump_chains.get(name, (name,))

    @property
    def known_hosts_dir(self) -> Path:
        """Каталог собственного файла host key — рядом с ``servers.yaml``.

        Пользовательский ``~/.ssh/known_hosts`` намеренно не используется:
        ``HostKeys.save()`` его переписывает и выбрасывает строки
        ``@cert-authority``/``@revoked``.
        """
        return self.path.parent


def default_config_path() -> Path:
    """Resolve the configuration path from env or the package location."""
    override = os.environ.get(ENV_CONFIG_PATH, "").strip()
    if override:
        return Path(os.path.expanduser(override))
    base = os.environ.get(ENV_CONFIG_DIR, "").strip()
    if base:
        return Path(os.path.expanduser(base)) / DEFAULT_CONFIG_FILENAME
    return Path(__file__).resolve().parent.parent / DEFAULT_CONFIG_FILENAME


def load_registry(path: str | Path | None = None) -> ServerRegistry:
    """Read, interpolate and validate the configuration file."""
    config_path = Path(path).expanduser() if path else default_config_path()
    if not config_path.is_file():
        raise ConfigError(f"Configuration file not found: {config_path}")

    raw_text = config_path.read_text(encoding="utf-8")
    try:
        document = yaml.safe_load(raw_text) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"{config_path.name}: invalid YAML ({exc})") from exc
    if not isinstance(document, Mapping):
        raise ConfigError(f"{config_path.name}: top-level section must be a mapping")

    _reject_unknown_keys(document, _ROOT_KEYS, config_path.name)
    load_dotenv(config_path.parent / ".env", override=False)
    document = _expand_env(document, config_path.name)

    defaults = _as_mapping(document.get("defaults"), f"{config_path.name}: defaults")
    settings = _as_mapping(document.get("settings"), f"{config_path.name}: settings")
    _reject_unknown_keys(settings, _SETTINGS_KEYS, f"{config_path.name}: settings")

    profiles = _parse_servers(raw_text, document.get("servers"), defaults, config_path)
    jump_chains = _resolve_jump_chains(profiles, config_path.name)

    allowed_dirs = _allowed_local_dirs(settings)
    default_name = _pick_default(profiles, document.get("default_server"), settings, config_path.name)

    return ServerRegistry(
        path=config_path,
        servers=profiles,
        default_server=default_name,
        allowed_local_dirs=allowed_dirs,
        jump_chains=jump_chains,
    )


def _parse_servers(
    raw_text: str,
    node: Any,
    defaults: Mapping[str, Any],
    config_path: Path,
) -> dict[str, ServerProfile]:
    if node is None:
        raise ConfigError(f"{config_path.name}: missing required 'servers:' section")
    if not isinstance(node, Mapping) or not node:
        raise ConfigError(
            f"{config_path.name}: 'servers:' must be a non-empty mapping of "
            "'<server-name>: {...}' entries"
        )

    entry_lines = _server_entry_lines(raw_text)
    profiles: dict[str, ServerProfile] = {}
    for name, body in node.items():
        key = str(name).strip()
        if not key:
            raise ConfigError(f"{config_path.name}: server name must not be empty")
        body = _as_mapping(body, f"{config_path.name}: servers.{key}")
        merged = {**defaults, **body}
        line = entry_lines.get(key)
        profiles[key] = _build_profile(
            key,
            merged,
            comments=_comments_above(raw_text, line) if line is not None else (),
            source=_source_label(config_path.name, line),
            config_name=config_path.name,
            config_dir=config_path.parent,
        )
    return profiles


def _build_profile(
    name: str,
    data: Mapping[str, Any],
    *,
    comments: Sequence[str],
    source: str,
    config_name: str,
    config_dir: Path,
) -> ServerProfile:
    where = f"servers.{name}"
    _reject_unknown_keys(data, _SERVER_KEYS, where)

    host = _as_str(data.get("host") or data.get("hostname") or data.get("address"), f"{where}.host")
    if not host:
        raise ConfigError(f"{config_name}: {where}.host is required")
    username = _as_str(data.get("username") or data.get("user"), f"{where}.username")
    if not username:
        raise ConfigError(f"{config_name}: {where}.username is required")

    auth = _build_auth(data, where)
    extra_notes = _as_str_list(data.get("notes") or data.get("comments"), f"{where}.notes")
    single_note = _as_str(data.get("comment"), f"{where}.comment")
    if single_note:
        extra_notes.append(single_note)
    all_comments = (*comments, *extra_notes)

    description = _as_str(data.get("description"), f"{where}.description") or ""
    if not description and all_comments:
        description = all_comments[0]

    host_key_policy = cast(
        HostKeyPolicy,
        _as_choice(
            data.get("host_key_policy", "auto_add"),
            _HOST_KEY_POLICIES,
            f"{where}.host_key_policy",
        ),
    )
    fingerprint = _as_str(data.get("host_key_fingerprint"), f"{where}.host_key_fingerprint") or None
    if host_key_policy == "pin" and not fingerprint:
        raise ConfigError(
            f"{where}: host_key_policy 'pin' requires host_key_fingerprint "
            "('SHA256:...' from ssh-keygen -lf <host key>)"
        )
    if fingerprint and host_key_policy != "pin":
        raise ConfigError(
            f"{where}: host_key_fingerprint only applies to host_key_policy 'pin', "
            f"but the policy is '{host_key_policy}'"
        )
    if fingerprint and not _FINGERPRINT.match(fingerprint):
        raise ConfigError(
            f"{where}.host_key_fingerprint: expected 'SHA256:<base64>' (as printed by "
            f"ssh-keygen -lf) or 'MD5:aa:bb:...', got {fingerprint!r}"
        )

    known_hosts = _as_path(data.get("known_hosts"), f"{where}.known_hosts")
    if known_hosts is not None and not known_hosts.is_absolute():
        known_hosts = config_dir / known_hosts

    return ServerProfile(
        name=name,
        host=host,
        username=username,
        port=_as_int(data.get("port", 22), 1, 65535, f"{where}.port"),
        auth=auth,
        description=description,
        comments=all_comments,
        tags=tuple(_as_str_list(data.get("tags"), f"{where}.tags")),
        jump_via=_as_str(data.get("jump_via") or data.get("via") or data.get("bastion"), f"{where}.jump_via")
        or None,
        default_workdir=_as_str(data.get("default_workdir") or data.get("workdir"), f"{where}.default_workdir")
        or None,
        connect_timeout=_as_int(data.get("connect_timeout", 30), 1, 600, f"{where}.connect_timeout"),
        auth_timeout=_as_int(data.get("auth_timeout", 30), 1, 600, f"{where}.auth_timeout"),
        host_key_policy=host_key_policy,
        known_hosts=known_hosts or (config_dir / KNOWN_HOSTS_FILENAME),
        host_key_fingerprint=fingerprint,
        keepalive_interval=_as_int(
            data.get("keepalive_interval", DEFAULT_KEEPALIVE),
            0,
            3600,
            f"{where}.keepalive_interval",
        ),
        is_default=_as_bool(data.get("default", False), f"{where}.default"),
        defined_at=source,
    )


def _build_auth(data: Mapping[str, Any], where: str) -> AuthConfig:
    nested = _as_mapping(data.get("auth"), f"{where}.auth")
    merged = {key: data[key] for key in ("password", "key_path", "key", "passphrase") if key in data}
    merged.update(nested)
    _reject_unknown_keys(merged, _AUTH_KEYS, f"{where}.auth")

    key_path = _as_path(merged.get("key_path") or merged.get("key"), f"{where}.auth.key_path")
    password = _as_str(merged.get("password"), f"{where}.auth.password") or None
    passphrase = _as_str(merged.get("passphrase"), f"{where}.auth.passphrase") or None
    use_agent = _as_bool(merged.get("use_agent", True), f"{where}.auth.use_agent")
    password_fallback = _as_bool(
        merged.get("password_fallback", True), f"{where}.auth.password_fallback"
    )

    declared = merged.get("type")
    if declared is None:
        # Без явного типа: ключ и пароль вместе = лестница, иначе один способ.
        auth_type: str = (
            "auto"
            if key_path and password
            else "key"
            if key_path
            else "password"
            if password
            else ""
        )
    else:
        auth_type = _as_choice(declared, {"password", "key", "auto"}, f"{where}.auth.type")

    if auth_type in {"key", "auto"}:
        if auth_type == "key" and key_path is None and passphrase is not None:
            raise ConfigError(f"{where}: passphrase given without key_path")
        if key_path is None and password is None:
            raise ConfigError(f"{where}: neither auth.password nor auth.key_path is set")

    if auth_type == "password" and not password:
        raise ConfigError(f"{where}.auth.password is required for password authentication")
    if auth_type == "auto" and not (password or key_path):
        raise ConfigError(
            f"{where}: auth.type 'auto' needs at least one credential: key_path or password"
        )

    return AuthConfig(
        type=cast(AuthType, auth_type),
        key_path=key_path,
        password=password,
        passphrase=passphrase,
        use_agent=use_agent,
        password_fallback=password_fallback,
    )


def _resolve_jump_chains(
    profiles: Mapping[str, ServerProfile],
    config_name: str,
) -> dict[str, tuple[str, ...]]:
    chains: dict[str, tuple[str, ...]] = {}
    for name in profiles:
        chain: list[str] = []
        current: str | None = name
        while current is not None:
            if current in chain:
                raise ConfigError(
                    f"{config_name}: jump-host cycle detected: {' -> '.join([*chain, current])}"
                )
            if current not in profiles:
                raise ConfigError(
                    f"{config_name}: jump_via '{current}' (from '{chain[-1] if chain else name}') "
                    "is not a configured server"
                )
            chain.append(current)
            if len(chain) > MAX_JUMP_DEPTH:
                raise ConfigError(f"{config_name}: jump-host chain for '{name}' is too deep")
            current = profiles[current].jump_via
        chains[name] = tuple(reversed(chain))
    return chains


def _pick_default(
    profiles: Mapping[str, ServerProfile],
    root_default: Any,
    settings: Mapping[str, Any],
    config_name: str,
) -> str:
    if not profiles:
        raise ConfigError(f"{config_name}: no servers configured")

    declared = [name for name, profile in profiles.items() if profile.is_default]
    if len(declared) > 1:
        raise ConfigError(f"{config_name}: several servers marked as default: {', '.join(declared)}")

    if root_default is not None:
        name = str(root_default).strip()
        if name and name not in profiles:
            raise ConfigError(f"{config_name}: default_server '{name}' is not a configured server")
        if name:
            return name
    if declared:
        return declared[0]

    settings_default = settings.get("default_server")
    if settings_default:
        name = str(settings_default).strip()
        if name not in profiles:
            raise ConfigError(f"{config_name}: settings.default_server '{name}' is not configured")
        return name

    return next(iter(profiles))


def _allowed_local_dirs(settings: Mapping[str, Any]) -> tuple[Path, ...]:
    raw = list(_as_str_list(settings.get("allowed_local_dirs"), "settings.allowed_local_dirs"))
    env_value = os.environ.get(ENV_EXTRA_DIRS, "")
    raw.extend(item.strip() for item in env_value.split(os.pathsep) if item.strip())

    resolved: list[Path] = []
    for item in raw:
        path = Path(os.path.expanduser(item)).resolve()
        if path not in resolved:
            resolved.append(path)
    return tuple(resolved)


def _server_entry_lines(raw_text: str) -> dict[str, int]:
    """Map each server name to the 0-based line where its entry starts."""
    try:
        root = yaml.compose(raw_text)
    except yaml.YAMLError:
        return {}
    if not isinstance(root, yaml.MappingNode):
        return {}

    for key_node, value_node in root.value:
        if key_node.value != "servers" or not isinstance(value_node, yaml.MappingNode):
            continue
        return {
            str(entry_key.value): entry_key.start_mark.line
            for entry_key, _ in value_node.value
        }
    return {}


def _comments_above(raw_text: str, line: int) -> tuple[str, ...]:
    """Collect the ``#`` comment block written directly above ``line``."""
    lines = raw_text.splitlines()
    comments: list[str] = []
    index = line - 1
    while index >= 0 and lines[index].strip().startswith("#"):
        text = lines[index].strip().lstrip("#").strip()
        if text:
            comments.append(text)
        index -= 1
    comments.reverse()
    return tuple(comments)


def _source_label(config_name: str, line: int | None) -> str:
    return f"{config_name}:{line + 1}" if line is not None else config_name


def _expand_env(value: Any, where: str) -> Any:
    if isinstance(value, str):
        return _expand_str(value, where)
    if isinstance(value, Mapping):
        return {key: _expand_env(item, f"{where}.{key}") for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item, f"{where}[{index}]") for index, item in enumerate(value)]
    return value


def _expand_str(text: str, where: str) -> str:
    def replace(match: re.Match[str]) -> str:
        variable = match.group("name")
        fallback = match.group("fallback")
        resolved = os.environ.get(variable)
        if resolved:
            return resolved
        if fallback is not None:
            return fallback
        raise ConfigError(
            f"{where}: environment variable '{variable}' referenced by '{match.group(0)}' is not set"
        )

    return _ENV_REF.sub(replace, text)


def _reject_unknown_keys(data: Mapping[str, Any], allowed: set[str], where: str) -> None:
    unknown = sorted(str(key) for key in data if str(key) not in allowed)
    if unknown:
        raise ConfigError(
            f"{where}: unknown option(s) {', '.join(unknown)}. Allowed: {', '.join(sorted(allowed))}"
        )


def _as_mapping(value: Any, where: str) -> Mapping[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ConfigError(f"{where}: expected a mapping, got {type(value).__name__}")
    return value


def _as_str(value: Any, where: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ConfigError(f"{where}: expected a string, got {type(value).__name__}")
    return value.strip()


def _as_str_list(value: Any, where: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        items = [part.strip() for part in value.split(",")]
    elif isinstance(value, Sequence):
        items = [str(item).strip() for item in value]
    else:
        raise ConfigError(f"{where}: expected a list of strings")
    return [item for item in items if item]


def _as_int(value: Any, minimum: int, maximum: int, where: str) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{where}: expected an integer, got {value!r}") from exc
    if not minimum <= number <= maximum:
        raise ConfigError(f"{where}: must be between {minimum} and {maximum}, got {number}")
    return number


def _as_bool(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().casefold()
    if text in {"1", "true", "yes", "on"}:
        return True
    if text in {"0", "false", "no", "off", ""}:
        return False
    raise ConfigError(f"{where}: expected a boolean, got {value!r}")


def _as_choice(value: Any, allowed: set[str], where: str) -> str:
    text = _as_str(value, where).casefold()
    if text not in allowed:
        raise ConfigError(f"{where}: must be one of {', '.join(sorted(allowed))}, got {value!r}")
    return text


def _as_path(value: Any, where: str) -> Path | None:
    text = _as_str(value, where)
    return Path(os.path.expanduser(text)) if text else None