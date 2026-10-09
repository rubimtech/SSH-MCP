"""Tests for the SSH key tools: local keygen and remote authorization.

Автономно: генерация проверяется на временном каталоге внутри
``allowed_local_dirs`` фикстуры, установка — на локальном sshd (гость с паролем).
Каталог ``.ssh`` гостя удаляется после теста, чтобы не влиять на остальные.
"""

from __future__ import annotations

import json
import secrets
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.conftest import ToolCaller


@pytest.fixture()
def key_dir(sshd: Any) -> Iterator[Path]:
    """Свежий каталог для ключей внутри ``allowed_local_dirs``."""
    directory: Path = sshd.root / f"keys-{secrets.token_hex(6)}"
    directory.mkdir(parents=True, exist_ok=True)
    try:
        yield directory
    finally:
        shutil.rmtree(directory, ignore_errors=True)


def _cleanup_guest_ssh(path: Path) -> None:
    """Убрать каталог ``.ssh`` гостя, созданный тестом установки."""
    shutil.rmtree(path, ignore_errors=True)


# --- ssh_generate_key -----------------------------------------------------


def test_generates_ed25519_and_returns_only_public(call: ToolCaller, key_dir: Path) -> None:
    """Ключ создаётся, наружу уходит только публичная половина."""
    target = key_dir / "id_ed25519"
    raw = call.text("ssh_generate_key", {"key_path": str(target)})
    payload = json.loads(raw)

    assert payload["status"] == "generated"
    assert target.is_file()
    public = key_dir / "id_ed25519.pub"
    assert public.is_file()
    assert "OPENSSH PRIVATE KEY" in target.read_text(encoding="utf-8")
    assert "OPENSSH PRIVATE KEY" not in raw
    assert public.read_text(encoding="utf-8").strip() == payload["public_key"]


def test_generated_public_key_shape(call: ToolCaller, key_dir: Path) -> None:
    """Публичный ключ — строка ssh-ed25519, отпечаток в формате SHA256."""
    payload = call.json("ssh_generate_key", {"key_path": str(key_dir / "id_key")})
    assert payload["key_type"] == "ed25519"
    assert payload["fingerprint"].startswith("SHA256:")
    assert payload["public_key"].startswith("ssh-ed25519 ")
    assert payload["public_path"].endswith("id_key.pub")


def test_refuses_to_overwrite_without_flag(call: ToolCaller, key_dir: Path) -> None:
    """Повторная генерация в тот же путь без overwrite=True отклоняется."""
    target = key_dir / "id_rsa"
    call.json("ssh_generate_key", {"key_path": str(target), "key_type": "rsa", "bits": 2048})
    again = call.json("ssh_generate_key", {"key_path": str(target), "key_type": "rsa"})
    assert again["error_code"] == "invalid_input"


def test_overwrite_replaces_file(call: ToolCaller, key_dir: Path) -> None:
    """overwrite=True заменяет существующий ключ новым отпечатком."""
    target = key_dir / "id_swap"
    first = call.json("ssh_generate_key", {"key_path": str(target)})
    second = call.json("ssh_generate_key", {"key_path": str(target), "overwrite": True})
    assert second["status"] == "generated"
    assert second["fingerprint"] != first["fingerprint"]


def test_passphrase_marks_key_encrypted(call: ToolCaller, key_dir: Path) -> None:
    """С passphrase ключ помечается шифрованным, сама фраза не возвращается."""
    phrase = "wp-key-pass-123456"
    payload = call.json(
        "ssh_generate_key", {"key_path": str(key_dir / "id_enc"), "passphrase": phrase}
    )
    assert payload["encrypted"] is True
    assert phrase not in json.dumps(payload)


def test_unknown_key_type_is_rejected(call: ToolCaller, key_dir: Path) -> None:
    payload = call.json(
        "ssh_generate_key", {"key_path": str(key_dir / "id_x"), "key_type": "dsa"}
    )
    assert payload["error_code"] == "invalid_input"


def test_path_outside_allowed_dirs_is_rejected(call: ToolCaller, tmp_path: Path) -> None:
    """Путь вне allowed_local_dirs отклоняется до записи."""
    outside = tmp_path.parent / f"outside-{secrets.token_hex(4)}"
    payload = call.json("ssh_generate_key", {"key_path": str(outside)})
    assert payload["error_code"] == "local_path_error"


# --- ssh_install_key ------------------------------------------------------


def test_install_appends_then_reports_already_present(
    call: ToolCaller, sshd: Any, key_dir: Path
) -> None:
    """Ключ добавляется в authorized_keys, повторная установка — no-op."""
    generated = call.json("ssh_generate_key", {"key_path": str(key_dir / "id_install")})
    auth = sshd.home / ".ssh" / "authorized_keys"
    try:
        first = call.json(
            "ssh_install_key",
            {"server": "testbox", "public_key": generated["public_key"]},
        )
        assert first["status"] == "installed"
        assert first["fingerprint"] == generated["fingerprint"]
        blob = generated["public_key"].split()[1]
        content = auth.read_text(encoding="utf-8")
        assert blob in content

        second = call.json(
            "ssh_install_key",
            {"server": "testbox", "public_key": generated["public_key"]},
        )
        assert second["status"] == "already_present"
        assert auth.read_text(encoding="utf-8") == content
    finally:
        _cleanup_guest_ssh(sshd.home / ".ssh")


def test_install_preserves_existing_lines(
    call: ToolCaller, sshd: Any, key_dir: Path
) -> None:
    """Существующая строка не теряется при добавлении новой."""
    sshd.write_file(".ssh/authorized_keys", "ssh-rsa AAAA existing@host\n")
    generated = call.json("ssh_generate_key", {"key_path": str(key_dir / "id_keep")})
    try:
        result = call.json(
            "ssh_install_key",
            {"server": "testbox", "public_key": generated["public_key"]},
        )
        assert result["status"] == "installed"
        content = (sshd.home / ".ssh" / "authorized_keys").read_text(encoding="utf-8")
        assert "ssh-rsa AAAA existing@host" in content
        assert generated["public_key"].split()[1] in content
    finally:
        _cleanup_guest_ssh(sshd.home / ".ssh")


def test_install_rejects_malformed_key(call: ToolCaller) -> None:
    payload = call.json("ssh_install_key", {"server": "testbox", "public_key": "not-a-key"})
    assert payload["error_code"] == "invalid_input"
