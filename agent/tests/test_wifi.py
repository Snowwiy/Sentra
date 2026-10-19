"""Fase 6C.5: colector Wi-Fi pasivo (macOS, Windows, Linux) y su envío en el inventario.

Fixtures con salidas reales de system_profiler (macOS 15 con y sin permiso de Localización,
Wi-Fi apagado, sin adaptador), netsh en inglés y español (incluido el aviso de Localización
de Windows 11 24H2) y nmcli en modo terse. Ninguna orden escanea ni lee claves.
"""

import json
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import wifi
from sentra_agent.collectors import HostInfo
from sentra_agent.runner import Agent
from sentra_agent.syscmd import CommandOutput, CommandTimeoutError, CommandUnavailableError
from tests.conftest import FakeApiState, make_client, make_store

FIXTURES = Path(__file__).parent / "fixtures" / "wifi"
NETWORK_KEYS = {
    "ssid", "bssid", "channel", "frequency_mhz", "band", "security", "signal_dbm",
    "signal_quality", "phy_mode", "connected",
}  # fmt: skip
INTERFACE_KEYS = {"name", "mac", "connected_ssid", "connected_bssid"}


def text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def out(data: str | bytes = b"", returncode: int = 0, stderr: str = "") -> CommandOutput:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return CommandOutput(raw, stderr, returncode)


class Commands:
    """Runner falso: responde por el primer argumento distintivo y registra cada orden."""

    def __init__(self, answers: dict[str, CommandOutput | Exception]) -> None:
        self.answers = answers
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> CommandOutput:
        self.calls.append(argv)
        joined = " ".join(argv)
        for key, value in self.answers.items():
            if key in joined:
                if isinstance(value, Exception):
                    raise value
                return value
        raise AssertionError(f"unexpected command {argv}")


def assert_contract(result: dict[str, Any]) -> None:
    assert set(result) == {"status", "source", "collected_at", "interfaces", "networks"}
    assert result["status"] in ("ok", "no_adapter", "permission_limited", "unsupported", "error")
    assert result["source"] in ("macos_system_profiler", "windows_netsh", "linux_nmcli")
    assert "+00:00" in result["collected_at"]
    assert len(result["interfaces"]) <= 8 and len(result["networks"]) <= 256
    for interface in result["interfaces"]:
        assert set(interface) == INTERFACE_KEYS
    for network in result["networks"]:
        assert set(network) == NETWORK_KEYS
        assert network["band"] in ("2.4", "5", "6", None)
        assert network["signal_quality"] is None or 0 <= network["signal_quality"] <= 100
        assert isinstance(network["connected"], bool)
    json.dumps(result)  # serializable tal cual


def never_reads_keys(calls: list[list[str]]) -> None:
    for argv in calls:
        joined = " ".join(argv).lower()
        assert "key=clear" not in joined and "profile" not in joined
        assert "rescan yes" not in joined and "scan" not in argv


# --- Utilidades -----------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("7C-10-C9-AA-BB-CC", "7c:10:c9:aa:bb:cc"),
        ("a4:83:e7:1:2:3", "a4:83:e7:01:02:03"),
        ("00:00:00:00:00:00", None),
        ("not a mac", None),
        (None, None),
    ],
)
def test_normalize_mac(raw: Any, expected: str | None) -> None:
    assert wifi.normalize_mac(raw) == expected


def test_channel_frequency_and_band_follow_802_11() -> None:
    assert wifi.frequency_for_channel(6, "2.4") == 2437
    assert wifi.frequency_for_channel(14, "2.4") == 2484
    assert wifi.frequency_for_channel(149, "5") == 5745
    assert wifi.frequency_for_channel(37, "6") == 6135
    assert wifi.channel_for_frequency(5220) == 44
    assert wifi.band_for_frequency(6135) == "6"
    assert wifi.band_for_frequency(900) is None


# --- macOS ----------------------------------------------------------------------------------


def run_macos(name: str) -> tuple[dict[str, Any], Commands]:
    commands = Commands({"SPAirPortDataType": out(text(name))})
    return wifi.collect_macos(commands), commands


def test_macos_with_location_permission() -> None:
    result, commands = run_macos("system_profiler_connected.json")
    assert_contract(result)
    assert commands.calls == [["/usr/sbin/system_profiler", "SPAirPortDataType", "-json"]]
    assert result["status"] == "ok" and result["source"] == "macos_system_profiler"
    # awdl0/llw0 (AirDrop) no son interfaces Wi-Fi de usuario.
    assert result["interfaces"] == [
        {"name": "en0", "mac": "a4:83:e7:12:34:56", "connected_ssid": "Oficina-5G",
         "connected_bssid": "7c:10:c9:aa:bb:cc"},
    ]  # fmt: skip
    connected, *others = result["networks"]
    assert connected == {
        "ssid": "Oficina-5G", "bssid": "7c:10:c9:aa:bb:cc", "channel": 149,
        "frequency_mhz": 5745, "band": "5", "security": "wpa3_transition", "signal_dbm": -48,
        "signal_quality": None, "phy_mode": "802.11ax", "connected": True,
    }  # fmt: skip
    assert [(n["ssid"], n["band"], n["security"]) for n in others] == [
        ("Vecino", "2.4", "wpa2_personal"),
        ("Invitados", "6", "none"),
    ]
    # macOS no da la calidad en %: no se calcula una.
    assert all(n["signal_quality"] is None for n in result["networks"])


def test_macos_14_4_without_location_permission_hides_ssid_and_bssid() -> None:
    result, _ = run_macos("system_profiler_redacted.json")
    assert_contract(result)
    assert result["status"] == "permission_limited"
    assert result["interfaces"][0]["connected_ssid"] is None
    assert all(n["ssid"] is None and n["bssid"] is None for n in result["networks"])
    # Lo que el sistema sí da (canal, señal) se mantiene; "<redacted>" nunca se envía.
    assert result["networks"][0]["channel"] == 149
    assert result["networks"][0]["signal_dbm"] == -52
    assert "redacted" not in json.dumps(result)


def test_macos_wifi_off_and_no_adapter() -> None:
    off, _ = run_macos("system_profiler_off.json")
    assert off["status"] == "ok" and off["networks"] == []
    assert off["interfaces"][0]["connected_ssid"] is None
    none, _ = run_macos("system_profiler_no_adapter.json")
    assert_contract(none)
    assert none["status"] == "no_adapter" and none["interfaces"] == []


def test_macos_bad_output_is_an_error() -> None:
    with pytest.raises(ValueError):
        wifi.collect_macos(Commands({"SPAirPortDataType": out("[1, 2]")}))


# --- Windows --------------------------------------------------------------------------------


def run_windows(interfaces: str, networks: str | None = None) -> tuple[dict[str, Any], Commands]:
    answers: dict[str, CommandOutput | Exception] = {"show interfaces": out(text(interfaces))}
    if networks:
        answers["show networks"] = out(text(networks))
    commands = Commands(answers)
    return wifi.collect_windows(commands, netsh=r"C:\Windows\System32\netsh.exe"), commands


@pytest.mark.parametrize("language", ["en", "es"])
def test_windows_netsh_in_english_and_spanish(language: str) -> None:
    result, commands = run_windows(
        f"netsh_interfaces_{language}.txt", f"netsh_networks_{language}.txt"
    )
    assert_contract(result)
    never_reads_keys(commands.calls)
    assert commands.calls[1][1:] == ["wlan", "show", "networks", "mode=bssid"]
    assert result["status"] == "ok" and result["source"] == "windows_netsh"
    assert result["interfaces"] == [
        {"name": "Wi-Fi", "mac": "a4:c3:f0:11:22:33", "connected_ssid": "Oficina-5G",
         "connected_bssid": "7c:10:c9:aa:bb:cc"},
    ]  # fmt: skip
    connected = result["networks"][0]
    assert connected == {
        "ssid": "Oficina-5G", "bssid": "7c:10:c9:aa:bb:cc", "channel": 44,
        "frequency_mhz": 5220, "band": "5", "security": "WPA2-Personal (CCMP)",
        "signal_dbm": -48, "signal_quality": 92, "phy_mode": "802.11ax", "connected": True,
    }  # fmt: skip
    assert sum(n["connected"] for n in result["networks"]) == 1


def test_windows_networks_details() -> None:
    result, _ = run_windows("netsh_interfaces_en.txt", "netsh_networks_en.txt")
    by_bssid = {n["bssid"]: n for n in result["networks"]}
    assert len(by_bssid) == 4
    assert by_bssid["7c:10:c9:aa:bb:cd"]["band"] == "2.4"
    assert by_bssid["7c:10:c9:aa:bb:cd"]["frequency_mhz"] == 2462
    hidden = by_bssid["9a:8b:7c:6d:5e:4f"]
    assert hidden["ssid"] is None and hidden["channel"] == 100  # red oculta: SSID vacío
    # Windows 10 no informa la banda: se deduce del canal (1-14 = 2,4 GHz).
    assert by_bssid["00:1a:2b:3c:4d:5e"]["band"] == "2.4"
    assert by_bssid["00:1a:2b:3c:4d:5e"]["security"] == "Open (None)"
    spanish, _ = run_windows("netsh_interfaces_es.txt", "netsh_networks_es.txt")
    biblioteca = next(n for n in spanish["networks"] if n["ssid"] == "Biblioteca")
    assert biblioteca["band"] == "2.4" and biblioteca["security"] == "Abierta (Ninguna)"


def test_windows_unknown_language_keeps_shape_fields() -> None:
    # Etiquetas en un idioma sin tabla: canal y seguridad quedan null (sin inventar), el
    # resto se reconoce por la forma del valor.
    translated = (
        text("netsh_networks_en.txt")
        .replace("Channel   ", "Csatorna  ")
        .replace("Authentication", "Hitelesites   ")
        .replace("Encryption", "Titkositas")
    )
    networks = wifi.parse_netsh_networks(translated)
    first = networks[0]
    assert first["bssid"] == "7c:10:c9:aa:bb:cc" and first["signal_quality"] == 92
    assert first["band"] == "5" and first["phy_mode"] == "802.11ax"
    assert first["security"] is None and first["channel"] is None


@pytest.mark.parametrize(
    "fixture_name", ["netsh_no_adapter_en.txt", "netsh_no_adapter_es.txt", "netsh_wlansvc_en.txt"]
)
def test_windows_without_adapter(fixture_name: str) -> None:
    commands = Commands({"show interfaces": out(text(fixture_name), returncode=1)})
    result = wifi.collect_windows(commands, netsh="netsh.exe")
    assert_contract(result)
    assert result["status"] == "no_adapter" and len(commands.calls) == 1


def test_windows_11_location_permission() -> None:
    denied = out(text("netsh_location.txt"), returncode=1)
    commands = Commands({"show interfaces": denied, "show networks": denied})
    result = wifi.collect_windows(commands, netsh="netsh.exe")
    assert_contract(result)
    assert result["status"] == "permission_limited" and result["networks"] == []


def test_windows_networks_denied_but_interface_known() -> None:
    denied = out(text("netsh_location.txt"), returncode=1)
    commands = Commands(
        {"show interfaces": out(text("netsh_interfaces_en.txt")), "show networks": denied}
    )
    result = wifi.collect_windows(commands, netsh="netsh.exe")
    assert result["status"] == "permission_limited"
    # La red conectada sale de `show interfaces`.
    assert [n["ssid"] for n in result["networks"]] == ["Oficina-5G"]


def test_windows_oem_codepage_output_is_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wifi, "_windows_encoding", lambda: "cp850")
    raw = text("netsh_interfaces_es.txt").encode("cp850")
    blocks = wifi.parse_netsh_interfaces(wifi._decode(CommandOutput(raw, "", 0)))
    assert blocks[0]["quality"] == 92 and blocks[0]["auth"] == "WPA2-Personal"


# --- Linux ----------------------------------------------------------------------------------


def run_linux(**answers: CommandOutput | Exception) -> tuple[dict[str, Any], Commands]:
    mapping = {"dev status": answers.get("status", out(text("nmcli_devices.txt")))}
    mapping["wifi list"] = answers.get("wifi", out(text("nmcli_wifi.txt")))
    commands = Commands(mapping)
    result = wifi.collect_linux(
        commands, nmcli="/usr/bin/nmcli", mac_of=lambda d: "00:11:22:33:44:55"
    )
    return result, commands


def test_linux_nmcli_terse_without_rescan() -> None:
    result, commands = run_linux()
    assert_contract(result)
    never_reads_keys(commands.calls)
    assert commands.calls[1][-2:] == ["--rescan", "no"]
    assert result["status"] == "ok" and result["source"] == "linux_nmcli"
    assert result["interfaces"] == [
        {"name": "wlp2s0", "mac": "00:11:22:33:44:55", "connected_ssid": "Oficina-5G",
         "connected_bssid": "7c:10:c9:aa:bb:cc"},
    ]  # fmt: skip
    by_bssid = {n["bssid"]: n for n in result["networks"]}
    assert by_bssid["7c:10:c9:aa:bb:cc"]["connected"] is True
    assert by_bssid["7c:10:c9:aa:bb:cc"]["frequency_mhz"] == 5220
    assert by_bssid["9a:8b:7c:6d:5e:4f"]["ssid"] is None  # oculta
    assert by_bssid["00:1a:2b:3c:4d:5e"]["ssid"] == "Cafe:Bar"  # ":" escapado
    assert by_bssid["00:1a:2b:3c:4d:5e"]["security"] == "open"
    assert by_bssid["11:22:33:44:55:66"]["band"] == "6"
    assert by_bssid["7c:10:c9:aa:bb:cc"]["signal_quality"] == 92


def test_linux_without_wifi_device_or_networkmanager() -> None:
    result, _ = run_linux(status=out("enp0s31f6:ethernet:connected\n"))
    assert result["status"] == "no_adapter"
    result, _ = run_linux(status=out("", 8, "Error: NetworkManager is not running."))
    assert result["status"] == "unsupported"


def test_linux_without_nmcli(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wifi, "NMCLI_PATHS", ("/nonexistent/nmcli",))
    assert wifi.collect_linux(Commands({}))["status"] == "unsupported"


def test_split_terse_handles_escapes() -> None:
    assert wifi.split_terse(r"a\:b:c\\d:") == ["a:b", "c\\d", ""]


def test_network_list_is_capped_and_ordered() -> None:
    rows = "\n".join(
        f" :AA\\:BB\\:CC\\:DD\\:{i // 256:02X}\\:{i % 256:02X}:N{i}:6:2437 MHz:{i % 100}:WPA2:wlan0"
        for i in range(400)
    )
    result, _ = run_linux(status=out("wlan0:wifi:connected\n"), wifi=out(rows))
    assert len(result["networks"]) == 256
    qualities = [n["signal_quality"] for n in result["networks"]]
    assert qualities == sorted(qualities, reverse=True)


# --- Punto de entrada -----------------------------------------------------------------------


@pytest.mark.host_wireless
def test_collect_wireless_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_: Any, **__: Any) -> dict[str, Any]:
        raise CommandTimeoutError("system_profiler timed out")

    monkeypatch.setattr(wifi, "collect_macos", boom)
    assert wifi.collect_wireless("darwin")["status"] == "error"  # type: ignore[index]

    def missing(*_: Any, **__: Any) -> dict[str, Any]:
        raise CommandUnavailableError("netsh.exe not found")

    monkeypatch.setattr(wifi, "collect_windows", missing)
    result = wifi.collect_wireless("win32")
    assert result is not None and result["status"] == "unsupported"
    assert result["source"] == "windows_netsh"
    assert wifi.collect_wireless("freebsd14") is None


def test_collector_interval_reuses_last_reading() -> None:
    now = [0.0]
    reads: list[int] = []

    def collect() -> dict[str, Any]:
        reads.append(1)
        return wifi.result("ok", "linux_nmcli")

    collector = wifi.WirelessCollector(600, collect=collect, clock=lambda: now[0])
    collector.snapshot()
    now[0] = 300
    collector.snapshot()
    assert len(reads) == 1
    collector.snapshot(force=True)  # inventario pedido por Response
    now[0] = 1000
    collector.snapshot()
    assert len(reads) == 3


# --- Envío en el inventario y compatibilidad --------------------------------------------------

HOST = HostInfo("MAC-TEST", "macOS", "15.1 (24B83)", "arm64", "192.168.1.30", "0.4.0")


def build_agent(config: Any, wireless: Any) -> Agent:
    from tests.test_runner import FakeEvents, processes, sample, snapshot

    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=sample,
        inventory=snapshot,
        events=FakeEvents(),
        processes=processes,
        wireless=wireless,
    )


def test_wireless_travels_in_the_inventory(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    reading = wifi.result("permission_limited", "macos_system_profiler")
    agent = build_agent(make_config(url), lambda force: reading)
    agent.cycle()
    assert state.inventory[0]["wireless"] == reading


def test_older_server_drops_wireless_and_it_is_no_longer_collected(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.unknown_sections.add("wireless")
    reads: list[bool] = []

    def wireless(force: bool) -> dict[str, Any]:
        reads.append(force)
        return wifi.result("ok", "linux_nmcli")

    agent = build_agent(make_config(url, inventory_interval_seconds=60), wireless)
    agent.cycle()
    # 422 extra_forbidden -> se reintenta sin el campo y el resto del inventario llega.
    assert len(state.inventory) == 1 and "wireless" not in state.inventory[0]
    agent._inventory_sent_at = None
    agent.cycle()
    assert len(state.inventory) == 2 and reads == [False]


def test_disabled_in_configuration(fake_api: tuple[str, FakeApiState], make_config: Any) -> None:
    url, state = fake_api
    config = make_config(url, wireless_enabled=False)
    agent = build_agent(config, None)
    agent.cycle()
    assert "wireless" not in state.inventory[0]


def test_config_validation(make_config: Any) -> None:
    with pytest.raises(ValueError, match="wireless_interval_seconds"):
        make_config("http://127.0.0.1:1", wireless_interval_seconds=30)
    assert make_config("http://127.0.0.1:1", wireless_interval_seconds=3600)
