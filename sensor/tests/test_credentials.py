"""Credencial en reposo: 0600 desde la creación, escritura atómica, nunca en repr/logs."""

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import (
    CredentialError,
    CredentialStore,
    atomic_write_bytes,
    unprotect_secret,
)
from tests.conftest import CREDENTIAL, enroll_identity

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")


@posix_only
def test_credential_file_is_0600_even_with_permissive_umask(config: LocalConfig) -> None:
    old = os.umask(0o000)
    try:
        store = enroll_identity(config)
    finally:
        os.umask(old)
    mode = stat.S_IMODE(store.path.stat().st_mode)
    assert mode == 0o600
    assert store.permissions_ok()


def test_roundtrip_and_repr_hides_secret(config: LocalConfig) -> None:
    store = enroll_identity(config)
    identity = store.load()
    assert identity.credential == CREDENTIAL
    assert CREDENTIAL not in repr(identity)


def test_atomic_write_leaves_no_temp_files(tmp_path: Path) -> None:
    target = tmp_path / "f.json"
    atomic_write_bytes(target, b"one")
    atomic_write_bytes(target, b"two")
    assert target.read_bytes() == b"two"
    assert [p.name for p in tmp_path.iterdir()] == ["f.json"]


def test_atomic_write_failure_keeps_previous_content(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "f.json"
    atomic_write_bytes(target, b"old")

    def boom(_src: object, _dst: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("sentra_sensor.credentials.os.replace", boom)
    with pytest.raises(OSError):
        atomic_write_bytes(target, b"new")
    assert target.read_bytes() == b"old"
    assert [p.name for p in tmp_path.iterdir()] == ["f.json"]


@posix_only
def test_detects_permissive_permissions(config: LocalConfig) -> None:
    store = enroll_identity(config)
    store.path.chmod(0o644)
    assert not store.permissions_ok()


def test_missing_and_corrupted(config: LocalConfig) -> None:
    store = CredentialStore(config.credential_file())
    with pytest.raises(CredentialError, match="not enrolled"):
        store.load()
    store.path.write_text("{not json")
    with pytest.raises(CredentialError):
        store.load()
    store.path.write_text(json.dumps({"sensor_id": "x"}))
    with pytest.raises(CredentialError):
        store.load()


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_dpapi_blob_cannot_be_read_outside_windows() -> None:
    with pytest.raises(CredentialError, match="Windows"):
        unprotect_secret({"scheme": "dpapi-user", "value": "AAAA"})
    with pytest.raises(CredentialError):
        unprotect_secret({"scheme": "rot13", "value": "x"})


def test_stored_scheme_is_plain_on_linux_dpapi_on_windows(config: LocalConfig) -> None:
    store = enroll_identity(config)
    stored = json.loads(store.path.read_text())["credential"]
    assert stored["scheme"] == ("dpapi-user" if sys.platform == "win32" else "plain")
