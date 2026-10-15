"""Privacidad del directorio de datos, la credencial y el spool (POSIX y Windows).

La lógica de decisión sobre una DACL es una función pura y se prueba en cualquier sistema;
la lectura y escritura de DACL reales se prueban en Windows con el mismo test que en POSIX
comprueba los bits de modo (ver tests/privacy.py).
"""

import os
import sys
from pathlib import Path

import pytest

from sentra_sensor import credentials, fsperm
from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import atomic_write_bytes
from sentra_sensor.fsperm import Ace, AclSnapshot, acl_is_private, dacl_sddl
from tests.conftest import CREDENTIAL, FakeClock, enroll_identity
from tests.privacy import SID_USERS, assert_private, loosen
from tests.test_spool import make_spool

ME = "S-1-5-21-1111111111-2222222222-3333333333-1001"
OTHER = "S-1-5-21-1111111111-2222222222-3333333333-1002"
SERVICE = "S-1-5-80-1234567890-1234567890-1234567890-1234567890-1234567890"
TRUSTED = (fsperm.SID_SYSTEM, fsperm.SID_ADMINISTRATORS, ME, SERVICE)
FULL = 0x1F01FF
READ = 0x120089


def allow(sid: str, mask: int = FULL) -> Ace:
    return Ace(fsperm.ACCESS_ALLOWED_ACE_TYPE, 0, mask, sid)


# --- decisión sobre la DACL (pura) -------------------------------------------------------


def test_acl_with_only_trusted_principals_is_private() -> None:
    snapshot = AclSnapshot(
        fsperm.SID_ADMINISTRATORS,
        True,
        (allow(fsperm.SID_SYSTEM), allow(fsperm.SID_ADMINISTRATORS), allow(ME), allow(SERVICE)),
    )
    assert acl_is_private(snapshot, TRUSTED)


@pytest.mark.parametrize(
    "sid",
    [
        "S-1-1-0",  # Everyone
        "S-1-5-11",  # Authenticated Users
        SID_USERS,
        "S-1-5-4",  # INTERACTIVE
        OTHER,  # otra cuenta concreta
    ],
)
def test_any_other_principal_breaks_privacy(sid: str) -> None:
    snapshot = AclSnapshot(ME, True, (allow(ME), allow(sid, READ)))
    assert not acl_is_private(snapshot, TRUSTED)


def test_null_dacl_is_never_private() -> None:
    assert not acl_is_private(AclSnapshot(ME, False, ()), TRUSTED)


def test_empty_dacl_denies_everyone_and_is_private() -> None:
    assert acl_is_private(AclSnapshot(ME, True, ()), TRUSTED)


def test_deny_entries_only_restrict() -> None:
    deny = Ace(1, 0, FULL, "S-1-1-0")
    assert acl_is_private(AclSnapshot(ME, True, (deny, allow(ME))), TRUSTED)


def test_unknown_ace_types_fail_closed() -> None:
    callback_allow = Ace(9, 0, 0, None)
    assert not acl_is_private(AclSnapshot(ME, True, (allow(ME), callback_allow)), TRUSTED)


def test_owner_is_trusted_unless_it_is_a_broad_group() -> None:
    # Ficheros creados por el servicio: propietario = su cuenta virtual, aunque quien mire
    # (un administrador con `status`) sea otra cuenta.
    owned = AclSnapshot(OTHER, True, (allow(OTHER), allow(fsperm.SID_OWNER_RIGHTS)))
    assert acl_is_private(owned, (fsperm.SID_SYSTEM, fsperm.SID_ADMINISTRATORS))
    broad_owner = AclSnapshot(SID_USERS, True, (allow(fsperm.SID_OWNER_RIGHTS),))
    assert not acl_is_private(broad_owner, TRUSTED)
    assert not acl_is_private(AclSnapshot(SID_USERS, True, (allow(SID_USERS),)), TRUSTED)


def test_written_dacl_is_protected_and_inherits_only_in_directories() -> None:
    principals = [fsperm.SID_SYSTEM, fsperm.SID_ADMINISTRATORS, ME, ME]
    assert dacl_sddl(principals, directory=True) == (
        "D:P(A;OICI;FA;;;S-1-5-18)(A;OICI;FA;;;S-1-5-32-544)(A;OICI;FA;;;" + ME + ")"
    )
    assert dacl_sddl(principals, directory=False).startswith("D:P(A;;FA;;;S-1-5-18)")
    assert "OICI" not in dacl_sddl(principals, directory=False)


# --- ficheros reales (POSIX: modo; Windows: DACL) -----------------------------------------


def test_loosened_data_dir_is_restricted_again(tmp_path: Path) -> None:
    data = tmp_path / "data"
    LocalConfig(data_dir=data).ensure_data_dir()
    assert_private(data, directory=True)
    loosen(data, directory=True)
    LocalConfig(data_dir=data).ensure_data_dir()
    assert_private(data, directory=True)


def test_files_created_inside_the_data_dir_are_private(config: LocalConfig) -> None:
    config.ensure_data_dir()
    store = enroll_identity(config)
    assert_private(store.path)
    spool = make_spool(config.spool_file(), FakeClock())
    try:
        spool.enqueue("job", "results", {"hosts": ["10.0.0.1"]}, "b1")
        assert_private(spool.path)
        for suffix in ("-wal", "-shm"):
            aux = spool.path.with_name(spool.path.name + suffix)
            assert aux.exists(), f"SQLite should keep {aux.name} open in WAL mode"
            assert_private(aux)
    finally:
        spool.close()


def test_loosened_spool_is_restricted_on_open(tmp_path: Path) -> None:
    path = tmp_path / "spool.sqlite3"
    make_spool(path, FakeClock()).close()
    loosen(path)
    spool = make_spool(path, FakeClock())
    spool.close()
    assert_private(path)


def test_credential_permissions_check_detects_exposure(config: LocalConfig) -> None:
    store = enroll_identity(config)
    assert store.permissions_ok()
    loosen(store.path)
    assert not store.permissions_ok()
    # Guardar de nuevo (p. ej. tras una rotación) deja otra vez un fichero privado.
    enroll_identity(config)
    assert store.permissions_ok()
    assert_private(store.path)


def test_secret_file_is_protected_before_the_first_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[str, int]] = []
    real = fsperm.make_private_file

    def spy(path: Path) -> None:
        seen.append((path.name, path.stat().st_size))
        real(path)

    monkeypatch.setattr(credentials, "make_private_file", spy)
    target = tmp_path / "secret.json"
    atomic_write_bytes(target, CREDENTIAL.encode())
    assert len(seen) == 1
    name, size = seen[0]
    assert name.startswith(".secret.json.") and name.endswith(".tmp")
    assert size == 0  # protegido cuando aún estaba vacío
    assert_private(target)


def test_secret_is_not_written_when_it_cannot_be_protected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(path: Path) -> None:
        raise fsperm.PrivacyError(f"cannot restrict {path}")

    monkeypatch.setattr(credentials, "make_private_file", refuse)
    target = tmp_path / "secret.json"
    with pytest.raises(fsperm.PrivacyError):
        atomic_write_bytes(target, CREDENTIAL.encode())
    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == []  # ni el temporal


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX: la umask solo existe en POSIX")
def test_posix_directory_mode_ignores_a_permissive_umask(tmp_path: Path) -> None:
    old = os.umask(0o000)
    try:
        fsperm.make_private_dir(tmp_path / "d")
    finally:
        os.umask(old)
    assert_private(tmp_path / "d", directory=True)


def test_windows_dacl_is_protected_from_parent_inheritance(tmp_path: Path) -> None:
    # Reproduce %ProgramData%: el padre concede lectura a Users y la heredan los hijos.
    # El skip va dentro para que mypy solo analice la API de Windows en win32.
    if sys.platform != "win32":
        pytest.skip("las DACL de NTFS solo existen en Windows; POSIX lo cubre con los modos")
    parent = tmp_path / "programdata"
    parent.mkdir()
    me = fsperm.current_user_sid()
    fsperm.write_dacl(parent, f"D:P(A;OICI;FA;;;{me})(A;OICI;FR;;;{SID_USERS})")
    data = parent / "Sensor"
    data.mkdir()
    assert not fsperm.is_private(data)  # heredó Users:Read
    LocalConfig(data_dir=data).ensure_data_dir()
    assert_private(data, directory=True)
    snapshot = fsperm.read_acl(data)
    assert all(ace.flags & 0x10 == 0 for ace in snapshot.aces)  # 0x10 = INHERITED_ACE
    store = enroll_identity(LocalConfig(server_url="http://127.0.0.1:8000", data_dir=data))
    assert_private(store.path)
