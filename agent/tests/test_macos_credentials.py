"""Fase 6C.5: token del agente en el Keychain de macOS (mockeado) o en fichero protegido.

El Keychain real (Security.framework) solo existe en un Mac: aquí se sustituye por el
FakeKeychain de conftest y se comprueba el contrato (identity.json solo guarda una
referencia, fallo explícito si el Keychain no funciona, migración entre almacenes, borrado
al descartar el token). La llamada real a Security.framework queda pendiente de validar en
un Mac físico (keychain del sistema como root).
"""

import json
import os
import stat
import sys
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import credentials
from sentra_agent.__main__ import EXIT_CREDENTIAL_STORE, main
from sentra_agent.config import AgentConfig
from sentra_agent.credentials import (
    SCHEME_KEYCHAIN,
    SCHEME_PLAIN,
    CredentialStoreUnavailableError,
    resolve_store,
)
from sentra_agent.identity import IdentityStore
from tests.conftest import FakeKeychain

TOKEN = "sentra_at_" + "k" * 40


@pytest.fixture
def darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")


def test_store_resolution_per_platform() -> None:
    assert resolve_store("auto", "darwin") == "keychain"
    assert resolve_store("file", "darwin") == "file"
    assert resolve_store("auto", "linux") == "file"
    assert resolve_store("auto", "win32") == "dpapi"
    with pytest.raises(ValueError, match="only available on macOS"):
        resolve_store("keychain", "linux")
    with pytest.raises(ValueError, match="DPAPI"):
        resolve_store("file", "win32")
    with pytest.raises(ValueError, match="credential_store"):
        resolve_store("plaintext", "darwin")


def test_config_rejects_store_that_does_not_apply_here(tmp_path: Path) -> None:
    if sys.platform != "darwin":
        with pytest.raises(ValueError):
            AgentConfig(state_dir=tmp_path, credential_store="keychain").validate()
    with pytest.raises(ValueError):
        AgentConfig(state_dir=tmp_path, credential_store="clear").validate()


def test_token_lives_only_in_the_keychain(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)

    raw = (tmp_path / "identity.json").read_text()
    assert TOKEN not in raw
    stored = json.loads(raw)["token"]
    assert stored == {"scheme": SCHEME_KEYCHAIN, "value": f"agent-{identity.agent_id}"}
    assert fake_keychain.items == {f"agent-{identity.agent_id}": TOKEN}

    # Reinicio: la misma identidad recupera el token del Keychain.
    again = IdentityStore(tmp_path).load_or_create()
    assert again.agent_id == identity.agent_id and again.token == TOKEN


def test_rotated_token_updates_the_same_item_and_a_dropped_one_is_deleted(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)
    identity.token = TOKEN + "-2"
    store.save(identity)
    assert list(fake_keychain.items.values()) == [TOKEN + "-2"]
    # 401 / revocación: el runner descarta el token y no queda copia en el Keychain.
    identity.token = None
    store.save(identity)
    assert fake_keychain.items == {}


def test_keychain_unavailable_fails_explicitly_before_enrolling(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    fake_keychain.available = False
    with pytest.raises(CredentialStoreUnavailableError):
        IdentityStore(tmp_path).load_or_create()
    # Nada se escribió en claro como respaldo.
    assert not (tmp_path / "identity.json").exists()


def test_keychain_failing_later_keeps_the_identity_and_does_not_reenroll(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)
    before = (tmp_path / "identity.json").read_text()
    fake_keychain.available = False
    with pytest.raises(CredentialStoreUnavailableError):
        IdentityStore(tmp_path).load_or_create()
    assert (tmp_path / "identity.json").read_text() == before


def test_missing_keychain_item_means_enroll_again_with_the_same_agent_id(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)
    fake_keychain.items.clear()  # p. ej. identity.json copiado de otro Mac
    again = IdentityStore(tmp_path).load_or_create()
    assert again.agent_id == identity.agent_id and again.token is None


def test_file_store_is_an_explicit_choice_with_private_permissions(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    os.chmod(state, 0o755)  # noqa: S103 - se parte a propósito de permisos abiertos
    store = IdentityStore(state, credential_store="file")
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(state).st_mode) == 0o700  # corregido a 0700
        assert stat.S_IMODE(os.stat(state / "identity.json").st_mode) == 0o600
    assert json.loads((state / "identity.json").read_text())["token"]["scheme"] == SCHEME_PLAIN
    assert fake_keychain.calls == []  # con "file" el Keychain ni se consulta


def test_file_store_refuses_a_directory_owned_by_someone_else(
    darwin: None, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if sys.platform == "win32" or os.name == "nt":  # permisos POSIX
        pytest.skip("permisos POSIX")
    monkeypatch.setattr(os, "geteuid", lambda: os.getuid() + 1)
    with pytest.raises(CredentialStoreUnavailableError, match="not owned"):
        credentials.ensure_private_dir(tmp_path)


def test_switching_from_file_to_keychain_migrates_the_token(
    darwin: None, tmp_path: Path, fake_keychain: FakeKeychain
) -> None:
    file_store = IdentityStore(tmp_path, credential_store="file")
    identity = file_store.load_or_create()
    identity.token = TOKEN
    file_store.save(identity)
    migrated = IdentityStore(tmp_path).load_or_create()
    assert migrated.token == TOKEN
    assert TOKEN not in (tmp_path / "identity.json").read_text()
    assert fake_keychain.items == {f"agent-{identity.agent_id}": TOKEN}
    # Y de vuelta a fichero: se borra la copia del Keychain.
    IdentityStore(tmp_path, credential_store="file").load_or_create()
    assert fake_keychain.items == {}


def test_linux_and_windows_behaviour_is_unchanged(tmp_path: Path) -> None:
    if sys.platform == "darwin":
        pytest.skip("comportamiento por defecto de Linux")
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = TOKEN
    store.save(identity)
    assert json.loads((tmp_path / "identity.json").read_text())["token"]["scheme"] in (
        SCHEME_PLAIN,
        credentials.SCHEME_DPAPI,
    )


def test_main_exits_with_a_clear_code_when_the_keychain_is_unusable(
    darwin: None,
    tmp_path: Path,
    fake_keychain: FakeKeychain,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from sentra_agent import config as config_module

    # La validación de la configuración usa la plataforma real; aquí se simula macOS.
    monkeypatch.setattr(
        config_module, "resolve_store", lambda store: resolve_store(store, "darwin")
    )
    fake_keychain.available = False
    token_file = tmp_path / "enrollment.token"
    token_file.write_text("sentra_et_" + "x" * 43)
    code = main(
        [
            "--api-url", "http://127.0.0.1:9", "--state-dir", str(tmp_path / "state"),
            "--enroll", "--enrollment-token-file", str(token_file), "--no-console-log",
        ]
    )  # fmt: skip
    assert code == EXIT_CREDENTIAL_STORE == 6
    assert "credential store unavailable" in capsys.readouterr().out
    assert token_file.exists()  # no se gastó el token de un solo uso
    assert not (tmp_path / "state" / "identity.json").exists()


def test_keychain_errors_never_contain_the_secret() -> None:
    error = credentials.keychain_error("write", credentials.ERR_SEC_INTERACTION_NOT_ALLOWED)
    assert isinstance(error, CredentialStoreUnavailableError)
    assert "locked" in str(error)
    assert not isinstance(credentials.keychain_error("read", -1), CredentialStoreUnavailableError)


def test_no_security_cli_with_secret_arguments() -> None:
    source = Path(credentials.__file__).read_text(encoding="utf-8")
    # El secreto nunca pasa por `security ... -w <secreto>` (visible en ps).
    assert "subprocess" not in source
    assert "add-generic-password" not in source


@pytest.mark.skipif(
    sys.platform != "darwin" or os.environ.get("SENTRA_TEST_REAL_KEYCHAIN") != "1",
    reason="Keychain real: solo en un Mac con SENTRA_TEST_REAL_KEYCHAIN=1",
)
def test_real_keychain_roundtrip() -> None:  # pragma: no cover - solo en un Mac
    keychain: Any = credentials.SecurityKeychain(None)
    keychain.check()
    account = "sentra-test-account"
    keychain.set(account, TOKEN)
    try:
        assert keychain.get(account) == TOKEN
    finally:
        keychain.delete(account)
    assert keychain.get(account) is None
