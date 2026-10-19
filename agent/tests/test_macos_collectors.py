"""Fase 6C.5: adaptadores de macOS con salidas reales guardadas como fixtures.

Se ejecutan en cualquier sistema: los parsers son puros y las llamadas a herramientas se
sustituyen por un runner que devuelve la salida guardada. No sustituyen a una prueba en un
Mac real (sw_vers, ioreg, launchctl, dscl, route y scutil reales).
"""

import plistlib
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import collectors, inventory, machine_identity, macos
from sentra_agent.machine_identity import derive

FIXTURES = Path(__file__).parent / "fixtures" / "macos"


def fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def runner_for(outputs: dict[tuple[str, ...], str | Exception]) -> Any:
    calls: list[list[str]] = []

    def run(argv: list[str]) -> str:
        calls.append(argv)
        value = outputs.get(tuple(argv))
        if value is None:
            raise OSError(f"unexpected command {argv}")
        if isinstance(value, Exception):
            raise value
        return value

    run.calls = calls  # type: ignore[attr-defined]
    return run


# --- Sistema y arquitectura ----------------------------------------------------------------


def test_sw_vers_gives_product_version_and_build() -> None:
    info = macos.parse_sw_vers(fixture("sw_vers_15.txt"))
    assert info == {"ProductName": "macOS", "ProductVersion": "15.1", "BuildVersion": "24B83"}
    assert macos.os_version_label(info) == "15.1 (24B83)"
    assert macos.os_version_label(macos.parse_sw_vers(fixture("sw_vers_14.txt"))) == (
        "14.4.1 (23E224)"
    )
    assert macos.os_version_label({}) is None


def _sysctl(arm64: str | Exception, translated: str | Exception) -> dict[tuple[str, ...], Any]:
    return {
        (macos.SW_VERS,): fixture("sw_vers_15.txt"),
        (macos.SYSCTL, "-n", "hw.optional.arm64"): arm64,
        (macos.SYSCTL, "-n", "sysctl.proc_translated"): translated,
    }


def test_apple_silicon_native() -> None:
    mac = macos.detect_platform("arm64", runner_for(_sysctl("1\n", "0\n")))
    assert mac.native_architecture == "arm64"
    assert mac.process_architecture == "arm64"
    assert mac.rosetta is False
    assert mac.os_version == "15.1 (24B83)"


def test_rosetta_reports_the_real_hardware_architecture() -> None:
    # Python x86_64 en un Apple Silicon: platform.machine() dice x86_64.
    mac = macos.detect_platform("x86_64", runner_for(_sysctl("1\n", "1\n")))
    assert mac.native_architecture == "arm64"
    assert mac.process_architecture == "x86_64"
    assert mac.rosetta is True


def test_intel_mac_has_no_arm64_or_translation_keys() -> None:
    missing = OSError("sysctl: unknown oid")
    mac = macos.detect_platform("x86_64", runner_for(_sysctl(missing, missing)))
    assert mac.native_architecture == "x86_64"
    assert mac.rosetta is False


def test_host_info_on_macos_reports_product_name_version_and_native_arch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mac = macos.MacPlatform("macOS", "15.1", "24B83", "x86_64", "arm64", True)
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(collectors, "platform_info", lambda machine: mac)
    monkeypatch.setattr(collectors, "machine_id_hash", lambda: None)
    info = collectors.collect_host_info()
    assert info.os_name == "macOS"
    assert info.os_version == "15.1 (24B83)"
    assert info.architecture == "arm64"


# --- Identidad del equipo ------------------------------------------------------------------


def test_platform_uuid_is_extracted_without_the_serial_number() -> None:
    output = fixture("ioreg_platform.txt")
    uuid = macos.parse_ioreg_platform_uuid(output)
    assert uuid == "8e1a6b4c-3d2f-5a7b-9c0d-1e2f3a4b5c6d"
    # El valor que sale del equipo es el HMAC por aplicación, nunca el UUID ni el serie.
    hashed = derive(uuid)
    assert hashed is not None and len(hashed) == 64
    assert "C02XX1YZMD6T" not in hashed and uuid.replace("-", "") not in hashed


def test_machine_identity_uses_ioreg_on_macos(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(machine_identity, "_cached", (False, None))
    monkeypatch.setattr(
        macos, "platform_uuid", lambda runner=None: "8e1a6b4c-3d2f-5a7b-9c0d-1e2f3a4b5c6d"
    )
    assert machine_identity.machine_id_hash() == derive("8e1a6b4c-3d2f-5a7b-9c0d-1e2f3a4b5c6d")


def test_platform_uuid_absent_or_zero_gives_no_identity() -> None:
    assert macos.parse_ioreg_platform_uuid('"IOPlatformSerialNumber" = "C02XX"') is None
    assert derive("00000000-0000-0000-0000-000000000000") is None
    assert macos.platform_uuid(runner_for({})) is None  # ioreg falla: sin identidad


# --- launchd --------------------------------------------------------------------------------


def test_launchctl_list_maps_states() -> None:
    services = {s["name"]: s for s in macos.parse_launchctl_list(fixture("launchctl_list.txt"))}
    assert services["com.sentra.agent"]["status"] == "running"
    assert services["com.sentra.agent"]["pid"] == 372
    assert services["com.apple.SafariHistoryServiceAgent"]["status"] == "stopped"
    assert services["com.apple.SafariHistoryServiceAgent"]["pid"] is None
    assert services["com.apple.cvmsCompAgent3600_arm64"]["status"] == "signaled"
    assert services["com.example.brokenhelper"]["status"] == "failed"
    assert services["com.apple.mDNSResponder"]["status"] == "running"
    assert "PID" not in services and len(services) == 6
    # Mismo contrato que los servicios de Windows/Linux (schemas/inventory.py ServiceInfo).
    assert set(services["com.sentra.agent"]) == {
        "name", "display_name", "status", "start_type", "pid",
    }  # fmt: skip


# --- Software -------------------------------------------------------------------------------


def _app(root: Path, name: str, info: dict[str, Any] | None, binary: bool = False) -> Path:
    contents = root / f"{name}.app" / "Contents"
    contents.mkdir(parents=True)
    if info is not None:
        fmt = plistlib.FMT_BINARY if binary else plistlib.FMT_XML
        (contents / "Info.plist").write_bytes(plistlib.dumps(info, fmt=fmt))
    return contents.parent


def test_applications_and_receipts(tmp_path: Path) -> None:
    apps = tmp_path / "Applications"
    _app(apps, "Safari", {"CFBundleName": "Safari", "CFBundleShortVersionString": "18.1"})
    _app(
        apps,
        "Visual Studio Code",
        {"CFBundleDisplayName": "Code", "CFBundleVersion": "1.95.2"},
        binary=True,
    )
    _app(apps / "Utilities", "Terminal", {"CFBundleName": "Terminal", "CFBundleVersion": "455"})
    _app(apps, "Broken", None)  # sin Info.plist: no es una aplicación válida
    (apps / "Broken.app" / "Contents" / "Info.plist").write_bytes(b"not a plist")
    _app(apps / "Office" / "Deep", "TooDeep", {"CFBundleName": "TooDeep"})  # 2 niveles: no
    try:
        (apps / "Link.app").symlink_to(apps / "Safari.app", target_is_directory=True)
    except OSError as exc:
        if sys.platform != "win32" or getattr(exc, "winerror", None) != 1314:
            raise
    huge = _app(apps, "Huge", None)
    (huge / "Contents" / "Info.plist").write_bytes(b"0" * (macos.INFO_PLIST_MAX_BYTES + 1))
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    (receipts / "com.microsoft.Word.plist").write_bytes(
        plistlib.dumps(
            {
                "PackageIdentifier": "com.microsoft.package.Microsoft_Word.app",
                "PackageVersion": "16.90.24101317",
                "InstallDate": datetime(2026, 10, 1, 9, 30),
                "InstallPrefixPath": "/",
            }
        )
    )
    (receipts / "com.apple.pkg.XProtect.plist").write_bytes(
        plistlib.dumps(
            {"PackageIdentifier": "com.apple.pkg.XProtectPayloads", "PackageVersion": "1"}
        )
    )
    (receipts / "com.apple.pkg.XProtect.bom").write_bytes(b"BOMStore")

    software = macos.collect_software([str(apps)], str(receipts))

    by_name = {item["name"]: item for item in software}
    assert set(by_name) == {
        "Safari",
        "Code",
        "Terminal",
        "com.microsoft.package.Microsoft_Word.app",
    }
    assert by_name["Safari"]["version"] == "18.1"
    assert by_name["Code"]["version"] == "1.95.2"
    assert by_name["com.microsoft.package.Microsoft_Word.app"]["install_date"] == "2026-10-01"
    # Lo que Info.plist no dice de forma fiable no se inventa.
    assert by_name["Safari"]["publisher"] is None and by_name["Safari"]["install_date"] is None
    assert [item["name"] for item in software] == sorted(
        by_name, key=str.lower
    )  # ordenado como en las otras plataformas


def test_software_scan_over_its_deadline_fails_the_section(tmp_path: Path) -> None:
    apps = tmp_path / "Applications"
    _app(apps, "One", {"CFBundleName": "One"})
    with pytest.raises(TimeoutError):
        macos.collect_software([str(apps)], str(tmp_path / "none"), deadline_seconds=-1)


# --- Cuentas --------------------------------------------------------------------------------


def test_accounts_from_directory_services() -> None:
    run = runner_for(
        {
            (macos.DSCL, ".", "-list", "/Users", "UniqueID"): fixture("dscl_uniqueid.txt"),
            (macos.DSCL, ".", "-list", "/Users", "UserShell"): fixture("dscl_usershell.txt"),
            (macos.DSCL, ".", "-read", "/Groups/admin", "GroupMembership"): fixture(
                "dscl_admin.txt"
            ),
        }
    )
    accounts = {a["name"]: a for a in macos.collect_accounts(run)}
    # Sin cuentas de servicio (_*), daemon ni nobody.
    assert set(accounts) == {"alice", "bob", "root", "svc-backup"}
    assert accounts["alice"]["is_admin"] is True
    assert accounts["bob"]["is_admin"] is False
    assert accounts["root"]["is_admin"] is True
    assert accounts["svc-backup"]["enabled"] is False  # /usr/bin/false: no puede entrar
    assert accounts["alice"]["enabled"] is None  # pwpolicy no se lee: desconocido
    assert all(set(a) == {"name", "enabled", "is_admin", "last_logon"} for a in accounts.values())


def test_accounts_without_admin_group_report_unknown_admin() -> None:
    run = runner_for(
        {(macos.DSCL, ".", "-list", "/Users", "UniqueID"): "alice 501\n"}
    )  # UserShell y el grupo admin fallan
    assert macos.collect_accounts(run) == [
        {"name": "alice", "enabled": None, "is_admin": None, "last_logon": None}
    ]


# --- Red ------------------------------------------------------------------------------------


def test_network_gateways_and_dns() -> None:
    run = runner_for(
        {
            (macos.ROUTE, "-n", "get", "default"): fixture("route_default.txt"),
            (macos.ROUTE, "-n", "get", "-inet6", "default"): fixture("route_default_v6.txt"),
            (macos.SCUTIL, "--dns"): fixture("scutil_dns.txt"),
        }
    )
    assert macos.collect_network(run) == {
        "gateways": ["192.168.1.1", "fe80::1"],
        "dns_servers": ["192.168.1.1", "fd00::1"],
    }


def test_network_without_default_route() -> None:
    run = runner_for(
        {
            (macos.ROUTE, "-n", "get", "default"): OSError("route: not in table"),
            (macos.SCUTIL, "--dns"): "DNS configuration\n\nresolver #1\n  domain : local\n",
        }
    )
    assert macos.collect_network(run) == {"gateways": [], "dns_servers": []}


# --- Despacho del inventario ----------------------------------------------------------------


def test_inventory_uses_macos_sources_on_darwin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(macos, "collect_services", lambda: [{"name": "com.x"}])
    monkeypatch.setattr(macos, "collect_software", lambda: [{"name": "Safari"}])
    monkeypatch.setattr(macos, "collect_accounts", lambda: [{"name": "alice"}])
    monkeypatch.setattr(macos, "collect_network", lambda: {"gateways": [], "dns_servers": []})
    assert inventory.collect_services() == [{"name": "com.x"}]
    assert inventory.collect_software() == [{"name": "Safari"}]
    assert inventory.collect_accounts() == [{"name": "alice"}]
    assert inventory.collect_network() == {"gateways": [], "dns_servers": []}
    # El esquema actual del servidor no tiene un valor macOS: se envía sin origen.
    assert inventory.software_source() is None


@pytest.mark.skipif(sys.platform != "darwin", reason="solo en un Mac (CI macOS)")
def test_real_macos_commands_on_this_mac() -> None:
    """En CI macOS: las herramientas reales responden y los parsers entienden su salida."""
    mac = macos.detect_platform(__import__("platform").machine())
    assert mac.product_version and mac.native_architecture in ("arm64", "x86_64")
    assert isinstance(macos.collect_services(), list)
    assert macos.platform_uuid() is not None
    assert isinstance(macos.collect_network()["dns_servers"], list)
