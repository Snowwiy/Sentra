"""Fase 6C.3: módulo SNMP wlan (IEEE802dot11-MIB, AIRESPACE-WIRELESS-MIB, UBNT-UniFi-MIB).

Agente simulado en memoria (tests/snmp_fixtures.py): nada sale a la red.
"""

from typing import Any

import pytest

from sentra_sensor import CAPABILITIES, __version__, snmp
from sentra_sensor.jobs import JobRejectedError, SnmpParameters, validate_job
from sentra_sensor.snmp import catalog
from sentra_sensor.snmp.collector import SnmpCollector, SnmpReport
from sentra_sensor.snmp.mibs import Record
from sentra_sensor.snmp.transport import Oid, SnmpAuthError, Value
from tests.conftest import SENSOR_ID, SITE_ID
from tests.snmp_fixtures import (
    FakeAgent,
    airespace_mib,
    dot11_ap_mib,
    minimal_mib,
    switch_mib,
    unifi_mib,
)
from tests.test_snmp import CONFIG, NOW, snmp_job

MODULES = ("system", "interfaces", "wlan")


def collect(agent: FakeAgent, max_rows: int = 10_000) -> tuple[SnmpReport, list[Record]]:
    emitted: list[Record] = []
    report = SnmpCollector(
        MODULES,
        lambda: agent,
        emitted.extend,
        max_varbinds=100_000,
        max_rows=max_rows,
        max_repetitions=10,
        deadline_seconds=600,
    ).run()
    return report, emitted


def kinds(records: list[Record], kind: str) -> list[Record]:
    return [r for r in records if r["kind"] == kind]


def requested_oids(agent: FakeAgent) -> list[Oid]:
    out: list[Oid] = []
    for op, target in agent.requests:
        if op == "bulk":
            out.append(target)  # type: ignore[arg-type]
        else:
            out.extend(target)  # type: ignore[arg-type]
    return out


def test_wlan_capability_and_version() -> None:
    assert __version__ == "0.5.1"
    assert "snmp.wlan" in snmp.capabilities()
    assert "snmp.wlan" in CAPABILITIES
    # Ninguna capacidad de radio: el sensor no escanea Wi-Fi por sí mismo.
    assert not any(c.startswith(("wifi", "wlan", "network.wifi")) for c in CAPABILITIES)


def test_every_wlan_oid_is_in_the_read_only_catalog() -> None:
    for root in catalog.WLAN_ROOTS:
        assert catalog.allowed(root)
    # Columnas sensibles que comparten tabla con las permitidas: nunca autorizadas.
    forbidden = (
        (*catalog.DOT11, 1, 3),  # dot11WEPDefaultKeysTable
        (*catalog.DOT11, 1, 4),  # dot11WEPKeyMappingsTable
        (*catalog.BSN_STATION, 2),  # bsnMobileStationIpAddress
        (*catalog.BSN_STATION, 3),  # bsnMobileStationUserName
        (*catalog.BSN_AP, 11),  # bsnAPReset (escribible)
    )
    for oid in forbidden:
        assert not catalog.allowed((*oid, 1))


def test_ieee802dot11_adapter() -> None:
    agent = FakeAgent(dot11_ap_mib())
    report, records = collect(agent)
    assert report.outcome == "completed"
    assert report.modules["wlan"] == "complete"
    assert kinds(records, "wlan_source") == [
        {"kind": "wlan_source", "source": "ieee802dot11", "status": "complete"}
    ]
    radios = {r["if_index"]: r for r in kinds(records, "wlan_dot11_radio")}
    assert radios[2] == {
        "kind": "wlan_dot11_radio",
        "if_index": 2,
        "station_id": "00:ca:fe:00:00:10",
        "mac_address": "00:ca:fe:00:00:10",
        "ssid": "corp-wifi",
        "bss_type": 1,
        "privacy_invoked": 1,
        "rsna_enabled": 1,
        "phy_type": 6,
        "dsss_channel": 6,
    }
    assert radios[3]["privacy_invoked"] == 2 and radios[3]["ofdm_channel"] == 36
    assert "dsss_channel" not in radios[3]
    # La columna de claves WEP nunca se pide ni aparece en los registros.
    wep = (*catalog.DOT11, 1, 3)
    assert not any(o[: len(wep)] == wep for o in requested_oids(agent))
    assert "\x00" not in str(records)


def test_airespace_adapter_minimises_client_data() -> None:
    agent = FakeAgent(airespace_mib())
    report, records = collect(agent)
    assert report.modules["wlan"] == "complete"
    aps = {r["ap_mac"]: r for r in kinds(records, "wlan_controller_ap")}
    assert aps["00:a0:f8:00:01:00"] == {
        "kind": "wlan_controller_ap",
        "ap_mac": "00:a0:f8:00:01:00",
        "name": "AP-HALL",
        "location": "Hall",
        "operation_status": 1,
        "software_version": "8.10.1",
        "model": "AIR-AP2802I-E-K9",
        "serial": "FCW0001",
        "ip_address": "10.70.0.21",
        "ethernet_mac": "00:a0:f8:00:01:ff",
    }
    # Dato que la controladora no da: se omite, no se inventa.
    assert "ethernet_mac" not in aps["00:a0:f8:00:02:00"]
    assert "location" not in aps["00:a0:f8:00:02:00"]
    radios = kinds(records, "wlan_controller_radio")
    assert len(radios) == 4
    assert {(r["slot"], r["radio_type"], r["channel"]) for r in radios} == {(0, 1, 11), (1, 2, 44)}
    assert {r["ssid"] for r in kinds(records, "wlan_ess")} == {"corp-wifi", "guest"}
    stations = kinds(records, "wlan_station")
    assert len(stations) == 3
    text = str(records)
    assert "alice@example.test" not in text and "10.70.0.99" not in text
    for forbidden in ((*catalog.BSN_STATION, 2), (*catalog.BSN_STATION, 3)):
        assert not any(o[: len(forbidden)] == forbidden for o in requested_oids(agent))


def test_unifi_adapter() -> None:
    report, records = collect(FakeAgent(unifi_mib()))
    assert report.modules["wlan"] == "complete"
    (system,) = kinds(records, "wlan_unifi_system")
    assert system == {
        "kind": "wlan_unifi_system",
        "ip_address": "10.70.0.31",
        "model": "UAP-AC-Pro",
        "firmware": "6.5.62.14789",
    }
    vaps = {r["vap_index"]: r for r in kinds(records, "wlan_vap")}
    assert vaps[1]["bssid"] == "78:8a:20:00:00:01" and vaps[1]["radio"] == "ng"
    assert vaps[2]["channel"] == 100 and vaps[2]["clients"] == 7


@pytest.mark.parametrize("mib", [switch_mib, minimal_mib])
def test_device_without_wifi_mibs_is_unsupported_not_error(mib: Any) -> None:
    report, records = collect(FakeAgent(mib()))
    assert report.outcome == "completed"
    assert report.error_code is None
    assert report.modules["wlan"] == "unsupported"
    assert not any(r["kind"].startswith("wlan") for r in records)


def test_view_without_wlan_subtrees_behaves_as_unsupported() -> None:
    """Un usuario SNMPv3 cuya vista VACM no incluye las MIBs Wi-Fi: el agente responde como
    si no existieran (GETBULK salta el subárbol, GET da noSuchObject)."""
    full = airespace_mib()
    restricted: dict[Oid, Value] = {
        oid: value for oid, value in full.items() if oid[:7] != catalog.AIRESPACE
    }
    report, _records = collect(FakeAgent(restricted))
    assert report.modules["wlan"] == "unsupported"
    assert report.error_code is None


def test_authorization_error_on_wlan_is_reported() -> None:
    agent = FakeAgent(airespace_mib(), fail_prefix=catalog.AIRESPACE, error=SnmpAuthError)
    report, records = collect(agent)
    assert report.modules["system"] == "complete"
    assert report.modules["wlan"] == "failed"
    assert report.error_code == "auth_failed"
    assert kinds(records, "system")


def test_row_limit_marks_wlan_partial() -> None:
    report, records = collect(FakeAgent(airespace_mib()), max_rows=2)
    assert report.modules["wlan"] == "partial"
    assert {"kind": "wlan_source", "source": "airespace", "status": "partial"} in records


def test_wlan_module_job_validation() -> None:
    job = validate_job(
        snmp_job(modules=["wlan", "system"]),
        sensor_id=SENSOR_ID,
        site_id=SITE_ID,
        config=CONFIG,
        now=NOW,
    )
    assert isinstance(job.parameters, SnmpParameters)
    assert job.parameters.modules == ("system", "wlan")
    with pytest.raises(JobRejectedError):
        validate_job(
            snmp_job(modules=["wlan"]), sensor_id=SENSOR_ID, site_id=SITE_ID, config=CONFIG, now=NOW
        )
