"""Fase 6B, fix 2: seguridad NTFS del fichero de claves SNMP (fail-closed).

Dos niveles, separados a propósito:

- Unitarias (cualquier sistema): la política (app/core/file_acl.evaluate) y el flujo de
  secret_box con un lector de seguridad simulado. NO verifican ACL reales de Windows.
- Integración (solo Windows): crean ficheros reales, cambian su DACL con la API de Windows y
  comprueban que el backend los acepta o rechaza. Solo se ejecutan en Windows.
"""

import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from app.core import file_acl, secret_box
from app.core.file_acl import (
    ACCESS_ALLOWED_ACE_TYPE,
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
    ACCESS_DENIED_ACE_TYPE,
    DELETE,
    FILE_APPEND_DATA,
    FILE_GENERIC_READ,
    FILE_WRITE_DATA,
    INHERIT_ONLY_ACE,
    INHERITED_ACE,
    READ_CONTROL,
    SID_ADMINISTRATORS,
    SID_AUTHENTICATED_USERS,
    SID_EVERYONE,
    SID_SYSTEM,
    SID_USERS,
    SYNCHRONIZE,
    WRITE_DAC,
    Ace,
    AclPolicy,
    SecuritySnapshot,
    evaluate,
    service_sid,
)
from app.core.secret_box import SecretStoreError, add_key, load_keyring, write_new_keyring

PROCESS_SID = "S-1-5-21-1000-2000-3000-1001"
OTHER_USER = "S-1-5-21-1000-2000-3000-1002"
LOCAL_SERVICE_ACCOUNT = "S-1-5-21-1000-2000-3000-1500"
API_SERVICE = service_sid("SentraAPI")
FULL = 0x001F01FF  # FILE_ALL_ACCESS

POLICY = AclPolicy(
    frozenset({SID_SYSTEM, SID_ADMINISTRATORS, PROCESS_SID}), frozenset({API_SERVICE})
)


def _private(*extra: Ace, owner: str = SID_ADMINISTRATORS) -> SecuritySnapshot:
    base = (
        Ace(ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE, FULL, SID_SYSTEM),
        Ace(ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE, FULL, SID_ADMINISTRATORS),
        Ace(ACCESS_ALLOWED_ACE_TYPE, INHERITED_ACE, FULL, PROCESS_SID),
    )
    return SecuritySnapshot(owner, True, (*extra, *base))


def _allow(sid: str, mask: int, flags: int = 0) -> Ace:
    return Ace(ACCESS_ALLOWED_ACE_TYPE, flags, mask, sid)


def _deny(sid: str, mask: int) -> Ace:
    return Ace(ACCESS_DENIED_ACE_TYPE, 0, mask, sid)


# --- política pura -------------------------------------------------------------------------


def test_service_sid_matches_windows_derivation() -> None:
    # Valor publicado por Windows para NT SERVICE\TrustedInstaller.
    assert service_sid("TrustedInstaller") == file_acl.SID_TRUSTED_INSTALLER
    assert service_sid("sentraapi") == API_SERVICE  # sin distinguir mayúsculas


def test_private_acl_with_inherited_entries_is_accepted() -> None:
    assert evaluate(_private(), POLICY, "file", "key") == []


@pytest.mark.parametrize(
    ("ace", "origin"),
    [
        (_allow(SID_USERS, FILE_GENERIC_READ, INHERITED_ACE), "inherited"),
        (_allow(SID_EVERYONE, FULL), "explicit"),
        (_allow(SID_AUTHENTICATED_USERS, FILE_WRITE_DATA), "explicit"),
        (_allow(OTHER_USER, FILE_GENERIC_READ), "explicit"),
        (_allow(SID_USERS, WRITE_DAC), "explicit"),  # permiso especial: cambiar la DACL
        (_allow(SID_USERS, DELETE), "explicit"),
    ],
)
def test_unauthorized_principals_are_rejected(ace: Ace, origin: str) -> None:
    (problem,) = evaluate(_private(ace), POLICY, "file", "key file X")
    assert ace.sid is not None and ace.sid in problem and origin in problem


def test_harmless_rights_and_inherit_only_entries_are_ignored() -> None:
    snapshot = _private(
        _allow(SID_USERS, READ_CONTROL | SYNCHRONIZE),
        # Solo para hijos nuevos: no se aplica a este objeto.
        _allow(SID_USERS, FULL, INHERIT_ONLY_ACE | INHERITED_ACE),
    )
    assert evaluate(snapshot, POLICY, "file", "key") == []


def test_service_account_reads_but_never_writes() -> None:
    assert evaluate(_private(_allow(API_SERVICE, FILE_GENERIC_READ)), POLICY, "file", "k") == []
    (problem,) = evaluate(_private(_allow(API_SERVICE, FULL)), POLICY, "file", "k")
    assert API_SERVICE in problem
    # Una cuenta local propia del servicio solo vale si se configura como lectora.
    assert evaluate(_private(_allow(LOCAL_SERVICE_ACCOUNT, FILE_GENERIC_READ)), POLICY, "file", "k")
    configured = AclPolicy(POLICY.trusted, POLICY.readers | {LOCAL_SERVICE_ACCOUNT})
    snapshot = _private(_allow(LOCAL_SERVICE_ACCOUNT, FILE_GENERIC_READ))
    assert evaluate(snapshot, configured, "file", "k") == []


def test_deny_entries_only_count_before_the_allow_for_the_same_sid() -> None:
    read = FILE_GENERIC_READ
    denied_first = _private(_deny(SID_USERS, read), _allow(SID_USERS, read))
    assert evaluate(denied_first, POLICY, "file", "k") == []
    everyone_denied = _private(_deny(SID_EVERYONE, read), _allow(SID_USERS, read))
    assert evaluate(everyone_denied, POLICY, "file", "k") == []
    # Una DENY posterior no quita lo ya concedido (orden canónico de evaluación).
    assert evaluate(_private(_allow(SID_USERS, read), _deny(SID_USERS, read)), POLICY, "file", "k")
    # Una DENY para otro grupo no se acredita: no se resuelve pertenencia (fail-closed).
    other_group = _private(_deny(SID_AUTHENTICATED_USERS, read), _allow(SID_USERS, read))
    assert evaluate(other_group, POLICY, "file", "k")


def test_owner_null_dacl_and_unknown_entries_fail_closed() -> None:
    assert "owner" in evaluate(_private(owner=OTHER_USER), POLICY, "file", "k")[0]
    assert "owner" in evaluate(_private(owner=SID_USERS), POLICY, "file", "k")[0]
    null_dacl = SecuritySnapshot(SID_ADMINISTRATORS, False, ())
    assert "no DACL" in evaluate(null_dacl, POLICY, "file", "k")[0]
    callback = Ace(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0, FILE_GENERIC_READ, SID_USERS)
    assert "unsupported" in evaluate(_private(callback), POLICY, "file", "k")[0]
    assert evaluate(_private(Ace(ACCESS_ALLOWED_ACE_TYPE, 0, FULL, None)), POLICY, "file", "k")


def test_directory_rules_for_parent_and_ancestors() -> None:
    listing = _allow(SID_USERS, FILE_GENERIC_READ | 0x20, INHERITED_ACE)
    assert evaluate(_private(listing), POLICY, "parent", "dir") == []
    # Crear ficheros en el directorio de la clave: no permitido.
    assert evaluate(_private(_allow(SID_USERS, FILE_WRITE_DATA)), POLICY, "parent", "dir")
    # En un antecesor crear entradas es inocuo (C:\ProgramData lo concede a Users)...
    programdata = _allow(SID_USERS, FILE_WRITE_DATA | FILE_APPEND_DATA, INHERITED_ACE)
    assert evaluate(_private(programdata), POLICY, "ancestor", "dir") == []
    # ...pero renombrar o borrar el siguiente componente, no (Modify en C:\Carpeta).
    modify = _allow(SID_AUTHENTICATED_USERS, 0x1301BF, INHERITED_ACE)
    assert evaluate(_private(modify), POLICY, "ancestor", "dir")


def test_creation_descriptor() -> None:
    readers = {API_SERVICE: FILE_GENERIC_READ}
    admin = file_acl.creation_sddl(POLICY, PROCESS_SID, True, readers)
    assert admin.startswith(f"O:{SID_ADMINISTRATORS}D:P")  # protegida: sin herencia
    assert f"(A;;0x120089;;;{API_SERVICE})" in admin and PROCESS_SID not in admin
    user = file_acl.creation_sddl(POLICY, PROCESS_SID, False, readers)
    assert user.startswith("D:P") and f"(A;;FA;;;{PROCESS_SID})" in user


# --- secret_box con Windows simulado --------------------------------------------------------


class FakeReader:
    """Seguridad simulada por ruta; por defecto todo es privado."""

    def __init__(self) -> None:
        self.by_path: dict[str, SecuritySnapshot] = {}
        self.reparse: set[str] = set()
        self.fail: set[str] = set()
        self.file_calls = 0

    def _get(self, path: Path) -> SecuritySnapshot:
        key = os.path.abspath(path)
        if key in self.fail:
            raise OSError(5, "access denied")
        for pattern, snapshot in self.by_path.items():
            if key == pattern or (pattern.startswith("*") and key.endswith(pattern[1:])):
                return snapshot
        return _private()

    def file_security(self, fd: int) -> SecuritySnapshot:
        self.file_calls += 1
        return self._get(Path(os.readlink(f"/proc/self/fd/{fd}")))

    def path_security(self, path: Path) -> SecuritySnapshot:
        return self._get(path)

    def is_reparse_point(self, path: Path) -> bool:
        os.lstat(path)  # como el lector real: una ruta inexistente es un error
        return os.path.abspath(path) in self.reparse

    def process_sid(self) -> str:
        return PROCESS_SID


@pytest.fixture
def windows(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeReader]:
    if not Path("/proc/self/fd").is_dir():
        pytest.skip("el lector simulado identifica el fichero abierto por /proc")
    reader = FakeReader()
    created: list[str] = []

    def fake_create(path: Path, sddl: str) -> int:
        created.append(sddl)
        return os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)

    monkeypatch.setattr(secret_box, "_is_windows", lambda: True)
    monkeypatch.setattr(secret_box, "ACL_READER_FACTORY", lambda: reader)
    monkeypatch.setattr(secret_box, "CREATE_PRIVATE_FILE", fake_create)
    monkeypatch.setattr(file_acl, "process_is_admin", lambda: True)
    reader.created = created  # type: ignore[attr-defined]
    yield reader


def _key_lines(path: Path) -> list[str]:
    return [line for line in path.read_text().splitlines() if not line.startswith("#")]


def test_private_key_file_loads_after_checking_the_open_handle(
    tmp_path: Path, windows: FakeReader
) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    windows.file_calls = 0
    assert load_keyring(keyfile).active_kid == "k1"
    assert windows.file_calls == 1  # DACL leída del descriptor abierto, no solo de la ruta
    sddl = windows.created[0]  # type: ignore[attr-defined]
    assert sddl.startswith(f"O:{SID_ADMINISTRATORS}D:P") and API_SERVICE in sddl


def test_insecure_key_file_is_refused_without_leaking_the_key(
    tmp_path: Path, windows: FakeReader
) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    secret = _key_lines(keyfile)[0].split(":", 1)[1]
    windows.by_path[str(keyfile)] = _private(_allow(SID_USERS, FILE_GENERIC_READ, INHERITED_ACE))
    with pytest.raises(SecretStoreError) as error:
        load_keyring(keyfile)
    assert SID_USERS in str(error.value) and "inherited" in str(error.value)
    assert secret not in str(error.value)


def test_insecure_directory_ancestor_reparse_and_unreadable_dacl_are_refused(
    tmp_path: Path, windows: FakeReader
) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    windows.by_path[str(tmp_path)] = _private(_allow(SID_USERS, FILE_WRITE_DATA))
    with pytest.raises(SecretStoreError, match="directory"):
        load_keyring(keyfile)
    windows.by_path.clear()
    windows.by_path[str(tmp_path.parent)] = _private(_allow(SID_AUTHENTICATED_USERS, DELETE))
    with pytest.raises(SecretStoreError, match="S-1-5-11"):
        load_keyring(keyfile)
    windows.by_path.clear()
    windows.reparse.add(str(tmp_path))
    with pytest.raises(SecretStoreError, match="junction"):
        load_keyring(keyfile)
    windows.reparse.clear()
    windows.fail.add(str(keyfile))
    with pytest.raises(SecretStoreError, match="cannot read the DACL"):
        load_keyring(keyfile)
    windows.fail = {str(tmp_path)}
    with pytest.raises(SecretStoreError, match="cannot verify"):
        load_keyring(keyfile)
    with pytest.raises(SecretStoreError, match="not found"):
        load_keyring(tmp_path / "missing.keys")


def test_file_replaced_between_check_and_open_is_refused(
    tmp_path: Path, windows: FakeReader, monkeypatch: pytest.MonkeyPatch
) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    monkeypatch.setattr(file_acl, "same_file", lambda fd, path: False)
    with pytest.raises(SecretStoreError, match="changed while"):
        load_keyring(keyfile)


def test_keygen_refuses_an_insecure_directory_and_writes_nothing(
    tmp_path: Path, windows: FakeReader
) -> None:
    windows.by_path[str(tmp_path)] = _private(_allow(SID_USERS, FILE_WRITE_DATA, INHERITED_ACE))
    with pytest.raises(SecretStoreError, match="refusing to create"):
        write_new_keyring(tmp_path / "snmp.keys", "k1")
    assert not (tmp_path / "snmp.keys").exists()


def test_new_key_file_that_fails_verification_is_removed(
    tmp_path: Path, windows: FakeReader
) -> None:
    keyfile = tmp_path / "snmp.keys"
    # El fichero nace con una DACL que la verificación posterior no acepta.
    windows.by_path[str(keyfile)] = _private(_allow(OTHER_USER, FILE_GENERIC_READ))
    with pytest.raises(SecretStoreError):
        write_new_keyring(keyfile, "k1")
    assert not keyfile.exists()


def test_rotation_keeps_every_key_and_is_atomic(tmp_path: Path, windows: FakeReader) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    before = _key_lines(keyfile)
    add_key(keyfile, "k2")
    after = _key_lines(keyfile)
    assert after[1:] == before and after[0].startswith("k2:")
    assert load_keyring(keyfile).active_kid == "k2"
    # El temporal también se creó con descriptor protegido.
    assert len(windows.created) == 2  # type: ignore[attr-defined]
    assert not list(tmp_path.glob(".*.tmp"))


def test_rotation_failure_leaves_the_original_intact(tmp_path: Path, windows: FakeReader) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    original = keyfile.read_bytes()
    # El temporal no pasa la verificación: no sustituye al original y se borra.
    windows.by_path["*.tmp"] = _private(_allow(SID_EVERYONE, FILE_GENERIC_READ))
    with pytest.raises(SecretStoreError):
        add_key(keyfile, "k2")
    assert keyfile.read_bytes() == original
    assert not list(tmp_path.glob(".*.tmp"))
    # Un keyring inseguro tampoco se rota.
    windows.by_path = {str(keyfile): _private(_allow(SID_USERS, FILE_GENERIC_READ))}
    with pytest.raises(SecretStoreError):
        add_key(keyfile, "k2")
    assert keyfile.read_bytes() == original


def test_cli_keygen_reports_without_printing_the_key(
    tmp_path: Path,
    windows: FakeReader,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from app import cli

    monkeypatch.setattr(sys, "platform", "win32")
    keyfile = tmp_path / "snmp.keys"
    assert cli._snmp_keygen(str(keyfile), "k1", add=False) == 0
    assert cli._snmp_keygen(str(keyfile), "k2", add=True) == 0
    out = capsys.readouterr().out
    assert out.count("NTFS permissions of the key file and its directories verified") == 2
    assert "keep old keys until it reports 0 unreadable" in out
    for line in _key_lines(keyfile):
        assert line.split(":", 1)[1] not in out
    windows.by_path[str(tmp_path)] = _private(_allow(SID_USERS, FILE_WRITE_DATA))
    assert cli._snmp_keygen(str(keyfile), "k3", add=True) == 1
    assert "not private" in capsys.readouterr().err


def test_settings_validate_reader_sids() -> None:
    from pydantic import ValidationError

    from app.core.config import Settings

    settings = Settings(snmp_credential_key_readers=f" {LOCAL_SERVICE_ACCOUNT} ,")
    assert settings.snmp_key_readers == (LOCAL_SERVICE_ACCOUNT,)
    with pytest.raises(ValidationError):
        Settings(snmp_credential_key_readers="NT SERVICE\\SentraAPI")


def test_api_refuses_snmp_credentials_with_an_insecure_keyring(
    client: Any, windows: FakeReader
) -> None:
    # Fail-closed en la API: con un keyring legible por Users no se crean perfiles y el
    # almacén figura como no disponible; el resto del backend sigue funcionando.
    from tests.test_network import NET, PROFILES, v3_profile
    from tests.test_sites_sensors import create_site

    site = create_site(client, "ACL", (NET,))
    keyfile = Path(os.environ["SNMP_CREDENTIAL_KEY_FILE"])
    windows.by_path[str(keyfile)] = _private(_allow(SID_USERS, FILE_GENERIC_READ))
    response = client.post(PROFILES, json=v3_profile(site["site_id"]))
    assert response.status_code == 503
    assert "S-1-5-32-545" not in response.text  # el detalle va solo al log del servidor
    listing = client.get(PROFILES)
    assert listing.status_code == 200 and listing.json()["secret_store_available"] is False
    assert client.get("/api/v1/health").status_code == 200


# --- integración real (solo Windows) --------------------------------------------------------

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="ACL reales de NTFS")


def _set_dacl(path: Path, sddl: str) -> None:
    """Sustituye la DACL de `path` (solo en estos tests) con la API de Windows."""
    # La comprobación de plataforma la entiende mypy: en Linux no analiza las API de Windows
    # (WinDLL, WinError, windll no existen en sus stubs) y en win32 las sigue tipando.
    if sys.platform != "win32":
        raise OSError("_set_dacl solo funciona en Windows")
    import ctypes
    from ctypes import wintypes

    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    descriptor = wintypes.LPVOID()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, 1, ctypes.byref(descriptor), None
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    present, dacl, defaulted = wintypes.BOOL(), wintypes.LPVOID(), wintypes.BOOL()
    if not advapi32.GetSecurityDescriptorDacl(
        descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
    ):
        raise ctypes.WinError(ctypes.get_last_error())
    # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
    code = advapi32.SetNamedSecurityInfoW(str(path), 1, 0x4 | 0x80000000, None, None, dacl, None)
    ctypes.windll.kernel32.LocalFree(descriptor)
    if code:
        raise ctypes.WinError(code)


@windows_only
def test_windows_real_private_key_file_round_trip(tmp_path: Path) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    assert load_keyring(keyfile).active_kid == "k1"
    add_key(keyfile, "k2")
    assert load_keyring(keyfile).active_kid == "k2"  # la sustitución conserva la DACL


@windows_only
def test_windows_real_users_read_ace_is_refused(tmp_path: Path) -> None:
    keyfile = tmp_path / "snmp.keys"
    write_new_keyring(keyfile, "k1")
    me = file_acl.default_reader().process_sid()
    _set_dacl(keyfile, f"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{me})(A;;FR;;;BU)")
    with pytest.raises(SecretStoreError, match="S-1-5-32-545"):
        load_keyring(keyfile)


@windows_only
def test_windows_real_insecure_directory_and_junction_are_refused(tmp_path: Path) -> None:
    # Además del marcador: mypy solo estrecha la plataforma con la comprobación en el cuerpo.
    if sys.platform != "win32":
        pytest.skip("las junctions solo existen en Windows")
    import _winapi

    secure = tmp_path / "secure"
    secure.mkdir()
    write_new_keyring(secure / "snmp.keys", "k1")
    junction = tmp_path / "via-junction"
    _winapi.CreateJunction(str(secure), str(junction))
    with pytest.raises(SecretStoreError, match="junction"):
        load_keyring(junction / "snmp.keys")
    me = file_acl.default_reader().process_sid()
    _set_dacl(secure, f"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{me})(A;;0x2;;;BU)")
    with pytest.raises(SecretStoreError, match="directory"):
        load_keyring(secure / "snmp.keys")
