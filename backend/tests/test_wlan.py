"""Fase 6C.3: inventario Wi-Fi / AP / WLAN autorizado (docs/wlan-discovery.md).

Las fuentes SNMP no se escriben a mano: los registros los genera el colector real del sensor
(módulo wlan) contra las MIBs sintéticas de sensor/tests/snmp_fixtures.py, así el test es
también el contrato backend ↔ sensor. Los agentes se simulan con el POST /inventory real.
Nada sale a la red.
"""

import copy
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, inspect, select, text, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.db.migrations import expected_heads
from app.models.asset import Asset
from app.models.network import NetworkDevicePoll
from app.models.wlan import WlanBss, WlanClient, WlanObservation
from app.network import wlan_catalog as wc
from app.services.network_jobs import run_network_maintenance
from app.services.wlan_service import purge_wlan_history
from tests.conftest import _alembic_config, agent_payload, authenticate
from tests.test_network import (
    AUTH,
    DEVICES,
    PRIV,
    PROFILES,
    SNMP_CAPS,
    SnmpSensor,
    _sensor_modules,
    v3_profile,
)
from tests.test_sites_sensors import API, CAPS, _error, _ok, audit, create_site

WLAN = f"{API}/network/wlan"
NET = "10.70.0.0/24"
WLAN_CAPS = [*CAPS, *SNMP_CAPS, "snmp.wlan"]
CONTROLLER_IP = "10.70.0.5"
AP_HALL = "00:a0:f8:00:01:00"
AP_ROOF = "00:a0:f8:00:02:00"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


# --- utilidades -------------------------------------------------------------------------------


def wlan_records(
    mib: str, mutate: Any = None, max_rows: int = 10_000
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Registros y resumen del colector REAL del sensor contra una MIB sintética."""
    collector, fixtures = _sensor_modules()
    data = getattr(fixtures, mib)()
    if mutate is not None:
        mutate(data, fixtures)
    emitted: list[dict[str, Any]] = []
    report = collector.SnmpCollector(
        ("system", "interfaces", "wlan"),
        lambda: fixtures.FakeAgent(data),
        emitted.extend,
        max_varbinds=50_000,
        max_rows=max_rows,
        max_repetitions=10,
        deadline_seconds=60,
    ).run()
    return emitted, {
        "modules": report.modules,
        **({"error_code": report.error_code} if report.error_code else {}),
    }


def setup_wlan_device(
    client: TestClient,
    site_name: str = "Campus",
    address: str = CONTROLLER_IP,
    net: str = NET,
    version: str = "0.4.0",
    caps: list[str] | None = None,
) -> tuple[dict[str, Any], SnmpSensor, dict[str, Any]]:
    site = create_site(client, site_name, (net,))
    sensor = SnmpSensor(client, site["site_id"], caps=caps or WLAN_CAPS, version=version)
    profile = _ok(client.post(PROFILES, json=v3_profile(site["site_id"])), 201)
    device = _ok(
        client.post(
            DEVICES,
            json={
                "site_id": site["site_id"],
                "management_address": address,
                "profile_id": profile["profile_id"],
                "sensor_id": sensor.sensor_id,
            },
        ),
        201,
    )
    return site, sensor, device


def add_device(
    client: TestClient, site: dict[str, Any], sensor: SnmpSensor, address: str
) -> dict[str, Any]:
    profile = _ok(client.post(PROFILES, json=v3_profile(site["site_id"], name=address)), 201)
    return _ok(  # type: ignore[no-any-return]
        client.post(
            DEVICES,
            json={
                "site_id": site["site_id"],
                "management_address": address,
                "profile_id": profile["profile_id"],
                "sensor_id": sensor.sensor_id,
            },
        ),
        201,
    )


def poll(
    client: TestClient,
    sensor: SnmpSensor,
    device: dict[str, Any],
    records: list[dict[str, Any]],
    summary: dict[str, Any],
    outcome: str = "completed",
) -> dict[str, Any]:
    created = _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    if records:
        _ok(sensor.snmp_results(job, records))
    _ok(sensor.snmp_complete(job, summary, outcome, batches_sent=1 if records else 0))
    polls = _ok(client.get(f"{DEVICES}/{device['device_id']}/polls"))["items"]
    return next(p for p in polls if p["poll_id"] == created["poll_id"])


def aps(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    return _ok(client.get(f"{WLAN}/access-points", params=params))["items"]  # type: ignore[no-any-return]


def by_mac(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {i["radio_mac"]: i for i in items}


def register(client: TestClient, **overrides: Any) -> tuple[str, str]:
    payload = agent_payload(**overrides)
    body = _ok(client.post(f"{API}/agents/register", json=payload), 201)
    return payload["agent_id"], body["asset_id"]


def wireless(**overrides: Any) -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "ok",
        "source": "windows_netsh",
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [
            {
                "name": "Wi-Fi",
                "mac": "3C-2E-F9-00-00-01",
                "connected_ssid": "corp-wifi",
                "connected_bssid": "00:CA:FE:00:00:10",
            }
        ],
        "networks": [
            {
                "ssid": "corp-wifi",
                "bssid": "00:ca:fe:00:00:10",
                "channel": 6,
                "frequency_mhz": 2437,
                "band": "2.4",
                "security": "WPA2-Personal/CCMP",
                "signal_dbm": -48,
                "signal_quality": 90,
                "phy_mode": "802.11ax",
                "connected": True,
            },
            {
                "ssid": "cafe-libre",
                "bssid": "02:11:22:33:44:55",
                "channel": 1,
                "band": None,
                "security": "Open",
                "signal_quality": 30,
                "connected": False,
            },
            {"ssid": "hidden-bssid", "bssid": None, "security": "WPA3-Personal"},
        ],
    }
    report.update(overrides)
    return report


def send_inventory(client: TestClient, agent_id: str, report: Any, **extra: Any) -> Any:
    body: dict[str, Any] = {
        "agent_id": agent_id,
        "collected_at": datetime.now(UTC).isoformat(),
        **extra,
    }
    if report is not None:
        body["wireless"] = report
    return client.post(f"{API}/inventory", json=body)


def full_controller_poll(
    client: TestClient, sensor: SnmpSensor, device: dict[str, Any], mutate: Any = None
) -> dict[str, Any]:
    records, summary = wlan_records("airespace_mib", mutate)
    return poll(client, sensor, device, records, summary)


def drop_roof(data: dict[Any, Any], fixtures: Any) -> None:
    """Quita el AP del tejado de la controladora: sus filas (índice = MAC de radio) y las de
    los clientes asociados a él (la MAC del AP es el valor de bsnMobileStationAPMacAddr)."""
    roof = tuple(fixtures.AP2_RADIO)
    station = (1, 3, 6, 1, 4, 1, 14179, 2, 1, 4, 1)
    ap_column = (*station, 4)
    gone = {
        k[len(ap_column) :]
        for k, v in data.items()
        if k[: len(ap_column)] == ap_column and v == fixtures.AP2_RADIO
    }
    for key in list(data):
        own_row = roof == tuple(key[12:18])
        if own_row or (key[: len(station)] == station and key[len(station) + 1 :] in gone):
            del data[key]


# --- modelo y migración ---------------------------------------------------------------------


def test_wlan_migration_downgrade_and_upgrade(engine: Engine, client: TestClient) -> None:
    """head → 0034 → head en la base de test: las tablas de 6C.3 se quitan y vuelven, y el
    inventario de 6B no se toca."""
    config = _alembic_config(get_settings().test_database_url or "")
    tables = {
        "wlan_access_points",
        "wlan_bss",
        "wlan_clients",
        "wlan_configured_networks",
        "wlan_observations",
        "wlan_agent_reports",
    }
    assert tables <= set(inspect(engine).get_table_names())
    engine.dispose()
    command.downgrade(config, "0034")
    try:
        names = set(inspect(engine).get_table_names())
        assert not tables & names
        assert {"network_devices", "network_device_polls"} <= names
    finally:
        command.upgrade(config, "head")
    engine.dispose()
    assert tables <= set(inspect(engine).get_table_names())
    with engine.connect() as connection:
        version = connection.execute(text("SELECT version_num FROM alembic_version")).scalar()
    # Migraciones posteriores a 0035 también vuelven: se compara con la cabeza real.
    assert frozenset({version}) == expected_heads()


# --- capacidades y compatibilidad -----------------------------------------------------------


def test_wlan_module_only_requested_from_sensors_declaring_it(client: TestClient) -> None:
    _, old, old_device = setup_wlan_device(
        client, "Legacy", version="0.3.0", caps=[*CAPS, *SNMP_CAPS]
    )
    _ok(client.post(f"{DEVICES}/{old_device['device_id']}/polls"), 202)
    [job] = old.poll()
    assert "wlan" not in job["parameters"]["modules"]
    _, new, device = setup_wlan_device(client, "Nuevo", net="10.71.0.0/24", address="10.71.0.5")
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = new.poll()
    assert job["parameters"]["modules"][-1] == "wlan"
    assert "snmp.wlan" in new.admin()["capabilities"]


# --- SNMP: controladora Cisco (AIRESPACE) ---------------------------------------------------


def test_controller_inventory(client: TestClient, db: Session) -> None:
    site, sensor, device = setup_wlan_device(client)
    result = full_controller_poll(client, sensor, device)
    assert result["status"] == "succeeded", result
    assert result["modules"]["wlan"] == "complete"
    stored = db.scalar(
        select(NetworkDevicePoll.counts).where(NetworkDevicePoll.public_id == result["poll_id"])
    )
    assert stored is not None
    assert stored["wlan_access_points"] == 2 and stored["wlan_clients"] == 3
    assert "wlan_access_points" not in result["counts"]  # contrato de PollCounts sin cambios
    listed = _ok(client.get(f"{WLAN}/access-points", params={"site_id": site["site_id"]}))
    assert listed["total"] == 2
    hall = by_mac(listed["items"])[AP_HALL]
    assert hall["display_name"] == "AP-HALL"
    assert hall["vendor"] == "Cisco" and hall["model"] == "AIR-AP2802I-E-K9"
    assert hall["firmware"] == "8.10.1" and hall["serial_number"] == "FCW0001"
    assert hall["management_ip"] == "10.70.0.21"
    assert hall["ethernet_mac"] == "00:a0:f8:00:01:ff"
    assert hall["source"] == "snmp_airespace"
    assert hall["confidence"] == "reported_by_device"
    assert hall["authorization_status"] == "unknown"
    assert hall["reported_status"] == "up"
    assert hall["present"] is True and hall["freshness"] == "recent"
    assert hall["reported_by"]["device_id"] == device["device_id"]
    assert hall["sensor"]["sensor_id"] == sensor.sensor_id
    assert [(r["slot"], r["band"], r["channel"]) for r in hall["radios"]] == [
        (0, "2.4", 11),
        (1, "5", 44),
    ]
    assert hall["client_count"] == 2
    roof = by_mac(listed["items"])[AP_ROOF]
    # Dato que la controladora no da: null, no inventado.
    assert roof["ethernet_mac"] is None and roof["location"] is None
    clients = _ok(client.get(f"{WLAN}/clients", params={"site_id": site["site_id"]}))
    assert clients["total"] == 3
    by_client = {c["mac"]: c for c in clients["items"]}
    random_client = by_client["da:11:22:33:44:55"]
    assert random_client["mac_randomized"] is True
    assert random_client["identity_confidence"] == "observation_only"
    assert random_client["asset"] is None
    # Protocolo 8 no está en la tabla cerrada: sin estándar; la banda sale de la radio del AP.
    assert random_client["standard"] is None and random_client["band"] == "5"
    corp = by_client["3c:2e:f9:00:00:01"]
    assert corp["state"] == "associated" and corp["standard"] == "802.11n"
    assert corp["access_point"]["display_name"] == "AP-HALL"
    assert corp["bssid"] is None  # la controladora no informa el BSSID del cliente
    assert by_client["3c:2e:f9:00:00:02"]["state"] == "idle"
    ssids = {s["ssid"]: s for s in _ok(client.get(f"{WLAN}/ssids"))["items"]}
    assert ssids["corp-wifi"]["configured_on_controllers"] == 1
    assert ssids["corp-wifi"]["controller_client_count"] == 2
    # Ningún secreto SNMP ni dato de cliente no autorizado sale por la API.
    for path in ("/access-points", "/clients", "/ssids", "/overview", "/bss"):
        text_ = client.get(f"{WLAN}{path}").text
        assert AUTH not in text_ and PRIV not in text_
        assert "alice@example.test" not in text_ and "10.70.0.99" not in text_
    overview = _ok(client.get(f"{WLAN}/overview", params={"site_id": site["site_id"]}))
    assert overview["access_points"] == 2 and overview["clients"] == 3
    snmp = next(s for s in overview["sources"] if s["source"] == "snmp")
    assert snmp["availability"] == "available" and snmp["by_status"] == {"complete": 1}
    agent = next(s for s in overview["sources"] if s["source"] == "agent")
    assert agent["availability"] == "not_configured"
    assert overview["risk_engine_contribution"] is False
    detail = _ok(client.get(f"{WLAN}/access-points/{hall['access_point_id']}"))
    assert detail["observations"] and detail["observations"][0]["source"] == "snmp_airespace"
    assert detail["observations"][0]["poll_id"] == result["poll_id"]


def test_repeated_poll_is_idempotent(client: TestClient, db: Session) -> None:
    _, sensor, device = setup_wlan_device(client)
    full_controller_poll(client, sensor, device)
    count = db.scalar(select(WlanObservation.id).order_by(WlanObservation.id.desc()).limit(1))
    full_controller_poll(client, sensor, device)
    assert _ok(client.get(f"{WLAN}/access-points"))["total"] == 2
    assert _ok(client.get(f"{WLAN}/clients"))["total"] == 3
    db.expire_all()
    # Sin cambios y dentro del intervalo mínimo: el historial no crece en cada consulta.
    assert (
        db.scalar(select(WlanObservation.id).order_by(WlanObservation.id.desc()).limit(1)) == count
    )


def test_partial_cancelled_or_failed_polls_never_remove_aps(client: TestClient) -> None:
    _, sensor, device = setup_wlan_device(client)
    full_controller_poll(client, sensor, device)
    # 1) Módulo wlan parcial (tope de filas) sin el AP del tejado: sigue presente.
    records, summary = wlan_records("airespace_mib", drop_roof, max_rows=2)
    assert summary["modules"]["wlan"] == "partial"
    result = poll(client, sensor, device, records, summary)
    assert result["status"] == "partial"
    assert all(a["present"] for a in aps(client))
    # 2) Consulta cancelada a mitad, sin el AP: sigue presente.
    records, summary = wlan_records("airespace_mib", drop_roof)
    result = poll(client, sensor, device, records, summary, outcome="cancelled")
    assert result["status"] == "cancelled"
    assert all(a["present"] for a in aps(client))
    # 3) Consulta fallida (timeout, nada recibido): sigue presente.
    result = poll(client, sensor, device, [], {"modules": {}, "error_code": "timeout"}, "failed")
    assert result["status"] == "failed"
    assert all(a["present"] for a in aps(client))
    # 4) Consulta completa con la fuente completa: ahora sí deja de estar presente, sin borrarse.
    records, summary = wlan_records("airespace_mib", drop_roof)
    poll(client, sensor, device, records, summary)
    current = by_mac(aps(client))
    assert current[AP_ROOF]["present"] is False and current[AP_HALL]["present"] is True
    assert [a["radio_mac"] for a in aps(client, present="false")] == [AP_ROOF]
    clients = _ok(client.get(f"{WLAN}/clients", params={"present": "false"}))["items"]
    assert [c["mac"] for c in clients] == ["3c:2e:f9:00:00:02"]


# --- SNMP: AP autónomo (IEEE802dot11-MIB) y UniFi ----------------------------------------------


def test_standalone_dot11_ap(client: TestClient) -> None:
    site, sensor, device = setup_wlan_device(client)
    records, summary = wlan_records("dot11_ap_mib")
    poll(client, sensor, device, records, summary)
    [ap] = aps(client)
    assert ap["source"] == "snmp_ieee802dot11"
    assert ap["management_ip"] == CONTROLLER_IP
    # El AP ES el equipo consultado: vínculo con evidencia "source_device".
    assert ap["network_device"]["device_id"] == device["device_id"]
    detail = _ok(client.get(f"{WLAN}/access-points/{ap['access_point_id']}"))
    assert detail["link_evidence"]["network_device"]["basis"] == "source_device"
    bss = {b["bssid"]: b for b in detail["bss"]}
    corp = bss["00:ca:fe:00:00:10"]
    assert (corp["ssid"], corp["band"], corp["channel"], corp["frequency_mhz"]) == (
        "corp-wifi",
        "2.4",
        6,
        2437,
    )
    assert corp["protection"] == "rsn" and corp["standard"] == "802.11g"
    assert corp["findings"] == []
    guest = bss["00:ca:fe:00:00:20"]
    assert (guest["band"], guest["channel"], guest["frequency_mhz"]) == ("5", 36, 5180)
    assert guest["protection"] == "open" and guest["standard"] == "802.11ac"
    assert [f["code"] for f in guest["findings"]] == ["open_network"]
    assert guest["findings"][0]["contributes_to_risk"] is False
    assert guest["vlan_id"] is None
    assert detail["findings"][0]["code"] == "open_network"
    overview = _ok(client.get(f"{WLAN}/overview", params={"site_id": site["site_id"]}))
    assert overview["insecure_bss"] == 1 and overview["findings_by_code"] == {"open_network": 1}
    # Filtros del inventario de AP por SSID y banda.
    assert len(aps(client, ssid="guest")) == 1
    assert len(aps(client, band="6")) == 0
    insecure = _ok(client.get(f"{WLAN}/bss", params={"insecure": "true"}))["items"]
    assert [b["ssid"] for b in insecure] == ["guest"]


def test_unifi_ap(client: TestClient) -> None:
    _, sensor, device = setup_wlan_device(client)
    records, summary = wlan_records("unifi_mib")
    poll(client, sensor, device, records, summary)
    [ap] = aps(client)
    assert ap["source"] == "snmp_unifi" and ap["vendor"] == "Ubiquiti"
    assert ap["model"] == "UAP-AC-Pro" and ap["firmware"] == "6.5.62.14789"
    assert ap["management_ip"] == "10.70.0.31"
    bss = {b["bssid"]: b for b in _ok(client.get(f"{WLAN}/bss"))["items"]}
    assert bss["78:8a:20:00:00:01"]["band"] == "2.4"
    assert bss["78:8a:20:00:00:02"]["band"] == "5"
    assert bss["78:8a:20:00:00:02"]["frequency_mhz"] == 5500
    assert bss["78:8a:20:00:00:02"]["client_count"] == 7
    # UniFi no informa la protección: null, nunca supuesta.
    assert bss["78:8a:20:00:00:01"]["protection"] is None
    [ssid] = _ok(client.get(f"{WLAN}/ssids"))["items"]
    assert ssid["ssid"] == "office" and ssid["bss_count"] == 2 and ssid["client_count"] == 11
    assert ssid["bands"] == ["2.4", "5"]


def test_device_without_wifi_mibs(client: TestClient) -> None:
    _, sensor, device = setup_wlan_device(client)
    records, summary = wlan_records("minimal_mib")
    assert summary["modules"]["wlan"] == "unsupported"
    result = poll(client, sensor, device, records, summary)
    assert result["status"] == "succeeded"
    assert aps(client) == []
    snmp = next(s for s in _ok(client.get(f"{WLAN}/overview"))["sources"] if s["source"] == "snmp")
    assert snmp["availability"] == "unavailable"
    assert snmp["by_status"] == {"unsupported": 1}


# --- agentes ------------------------------------------------------------------------------------


def test_agent_wireless_ingestion(client: TestClient, db: Session) -> None:
    agent_id, asset_id = register(client)
    _ok(send_inventory(client, agent_id, wireless()), 201)
    bss = {b["bssid"]: b for b in _ok(client.get(f"{WLAN}/bss"))["items"]}
    assert set(bss) == {"00:ca:fe:00:00:10", "02:11:22:33:44:55"}
    corp = bss["00:ca:fe:00:00:10"]
    assert corp["source"] == "agent" and corp["confidence"] == "observed"
    assert corp["protection"] == "wpa2" and corp["protection_reported"] == "WPA2-Personal/CCMP"
    assert corp["standard"] == "802.11ax" and corp["signal_dbm"] == -48
    assert corp["last_agent"]["asset_id"] == asset_id
    assert corp["access_point"] is None
    assert corp["authorization_status"] == "unknown"
    cafe = bss["02:11:22:33:44:55"]
    # Canal 1 sin banda ni frecuencia: puede ser 2,4 o 6 GHz; no se adivina.
    assert cafe["band"] is None and cafe["frequency_mhz"] is None
    assert cafe["bssid_randomized"] is True
    assert [f["code"] for f in cafe["findings"]] == ["open_network"]
    # Un agente nunca crea APs: ver una red no prueba que el AP sea de la organización.
    assert aps(client) == []
    [own] = _ok(client.get(f"{WLAN}/clients"))["items"]
    assert own["identity_confidence"] == "confirmed"
    assert own["asset"]["asset_id"] == asset_id
    assert own["correlation_basis"] == "agent_self"
    assert own["mac"] == "3c:2e:f9:00:00:01" and own["bssid"] == "00:ca:fe:00:00:10"
    overview = _ok(client.get(f"{WLAN}/overview"))
    agent = next(s for s in overview["sources"] if s["source"] == "agent")
    assert agent["availability"] == "available" and agent["by_status"] == {"ok": 1}
    assert overview["bss_observed_only"] == 2
    # El campo no entra en el documento de inventario ni en sus cambios.
    inventory = _ok(client.get(f"{API}/assets/{asset_id}/inventory"))
    assert "wireless" not in inventory
    # Repetir el mismo informe no duplica nada.
    _ok(send_inventory(client, agent_id, wireless()), 201)
    assert _ok(client.get(f"{WLAN}/bss"))["total"] == 2
    assert _ok(client.get(f"{WLAN}/clients"))["total"] == 1


def test_old_agent_without_wireless_field(client: TestClient) -> None:
    agent_id, _ = register(client)
    _ok(send_inventory(client, agent_id, None), 201)
    assert _ok(client.get(f"{WLAN}/bss"))["total"] == 0
    agent = next(
        s for s in _ok(client.get(f"{WLAN}/overview"))["sources"] if s["source"] == "agent"
    )
    assert agent["availability"] == "not_configured"


def _network(**extra: Any) -> dict[str, Any]:
    return {"ssid": "x", "bssid": "00:11:22:33:44:01", **extra}


@pytest.mark.parametrize(
    "overrides",
    [
        {
            "networks": [
                _network(bssid=f"00:11:22:33:{i // 256:02x}:{i % 256:02x}") for i in range(257)
            ]
        },
        {"interfaces": [{"name": f"wlan{i}"} for i in range(9)]},
        {"networks": [_network(signal_dbm=5)]},
        {"networks": [_network(signal_quality=101)]},
        {"networks": [_network(channel=0)]},
        {"networks": [_network(frequency_mhz=900)]},
        {"networks": [_network(band="60")]},
        {"networks": [_network(bssid="not-a-mac")]},
        {"networks": [_network(ssid="x" * 65)]},
        {"networks": [_network(ssid="bad\x07ssid")]},
        {"networks": [_network(password="secret")]},
        {"status": "great"},
        {"source": "iwlist_scan"},
        {"collected_at": "2026-10-16T10:00:00"},
        {"collected_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
        {"extra": True},
    ],
)
def test_wireless_payload_limits(client: TestClient, overrides: dict[str, Any]) -> None:
    agent_id, _ = register(client)
    response = send_inventory(client, agent_id, wireless(**overrides))
    assert response.status_code == 422, response.text
    assert _ok(client.get(f"{WLAN}/bss"))["total"] == 0


def test_unusable_bssid_is_dropped_not_rejected(client: TestClient) -> None:
    agent_id, _ = register(client)
    report = wireless(
        networks=[
            _network(bssid="00:00:00:00:00:00"),
            _network(bssid="01:00:5e:00:00:01"),
            _network(bssid="00:11:22:33:44:01", signal_dbm=-80),
            _network(bssid="00-11-22-33-44-01", signal_dbm=-40),
        ],
        interfaces=[],
        status="permission_limited",
        source="macos_system_profiler",
    )
    _ok(send_inventory(client, agent_id, report), 201)
    [bss] = _ok(client.get(f"{WLAN}/bss"))["items"]
    # Duplicado en el mismo informe: una sola fila, la de más señal.
    assert bss["bssid"] == "00:11:22:33:44:01" and bss["signal_dbm"] == -40
    agent = next(
        s for s in _ok(client.get(f"{WLAN}/overview"))["sources"] if s["source"] == "agent"
    )
    assert agent["availability"] == "partial"
    assert agent["by_status"] == {"permission_limited": 1}


def test_stale_wireless_report_does_not_override(client: TestClient) -> None:
    agent_id, _ = register(client)
    _ok(send_inventory(client, agent_id, wireless()), 201)
    old = wireless(
        collected_at=(datetime.now(UTC) - timedelta(hours=3)).isoformat(),
        networks=[_network(bssid="00:ca:fe:00:00:10", ssid="renamed", signal_dbm=-90)],
    )
    _ok(send_inventory(client, agent_id, old), 201)
    corp = next(
        b for b in _ok(client.get(f"{WLAN}/bss"))["items"] if b["bssid"] == "00:ca:fe:00:00:10"
    )
    assert corp["ssid"] == "corp-wifi" and corp["signal_dbm"] == -48


def test_agent_no_longer_connected_is_not_present(client: TestClient) -> None:
    agent_id, _ = register(client)
    _ok(send_inventory(client, agent_id, wireless()), 201)
    later = wireless(
        collected_at=(datetime.now(UTC) + timedelta(seconds=1)).isoformat(),
        interfaces=[{"name": "Wi-Fi", "mac": "3c:2e:f9:00:00:01"}],
    )
    _ok(send_inventory(client, agent_id, later), 201)
    [own] = _ok(client.get(f"{WLAN}/clients"))["items"]
    assert own["present"] is False and own["state"] == "disassociated"
    # Con un error de colección no se deduce nada de la conexión propia.
    _ok(send_inventory(client, agent_id, wireless(status="error", interfaces=[], networks=[])), 201)
    assert _ok(client.get(f"{WLAN}/bss"))["total"] == 2


def test_agent_and_snmp_merge_on_the_same_bss(client: TestClient, db: Session) -> None:
    site, sensor, device = setup_wlan_device(client)
    records, summary = wlan_records("dot11_ap_mib")
    poll(client, sensor, device, records, summary)
    agent_id, asset_id = register(client)
    db.execute(update(Asset).where(Asset.agent_id == agent_id).values(site_id=_site_pk(db, site)))
    db.commit()
    _ok(send_inventory(client, agent_id, wireless()), 201)
    corp = next(
        b
        for b in _ok(client.get(f"{WLAN}/bss", params={"site_id": site["site_id"]}))["items"]
        if b["bssid"] == "00:ca:fe:00:00:10"
    )
    assert corp["confidence"] == "reported_by_device"
    assert set(corp["sources"]) == {"agent", "snmp_ieee802dot11"}
    # La MIB solo dice RSN; el agente lo precisa a WPA2. La señal solo la da el agente.
    assert corp["protection"] == "wpa2" and corp["signal_dbm"] == -48
    assert corp["ssid"] == "corp-wifi" and corp["access_point"] is not None
    [own] = _ok(client.get(f"{WLAN}/clients", params={"site_id": site["site_id"]}))["items"]
    assert own["access_point"]["access_point_id"] == corp["access_point"]["access_point_id"]
    # Una nueva consulta SNMP no degrada la protección precisada por el agente.
    poll(client, sensor, device, records, summary)
    corp = _ok(client.get(f"{WLAN}/bss/{corp['bss_id']}"))
    assert corp["protection"] == "wpa2"
    history = _ok(client.get(f"{WLAN}/bss/{corp['bss_id']}/observations"))["items"]
    assert {h["source"] for h in history} == {"agent", "snmp_ieee802dot11"}
    assert any(h["agent_asset"] and h["agent_asset"]["asset_id"] == asset_id for h in history)


def _site_pk(db: Session, site: dict[str, Any]) -> int:
    from app.models.site import Site

    value = db.scalar(select(Site.id).where(Site.public_id == site["site_id"]))
    assert value is not None
    return int(value)


# --- sites ------------------------------------------------------------------------------------


def test_site_isolation(client: TestClient, db: Session) -> None:
    site_a, sensor_a, device_a = setup_wlan_device(client, "Sede A")
    site_b, sensor_b, device_b = setup_wlan_device(
        client, "Sede B", net="10.71.0.0/24", address="10.71.0.5"
    )
    full_controller_poll(client, sensor_a, device_a)
    full_controller_poll(client, sensor_b, device_b)
    # Misma MAC de AP y cliente en dos sites: dos filas, nunca fusionadas.
    assert _ok(client.get(f"{WLAN}/access-points"))["total"] == 4
    in_a = aps(client, site_id=site_a["site_id"])
    assert len(in_a) == 2 and {a["site_name"] for a in in_a} == {"Sede A"}
    clients_b = _ok(client.get(f"{WLAN}/clients", params={"site_id": site_b["site_id"]}))
    assert clients_b["total"] == 3 and {c["site_name"] for c in clients_b["items"]} == {"Sede B"}
    ssids = _ok(client.get(f"{WLAN}/ssids"))["items"]
    assert {(s["site_name"], s["ssid"]) for s in ssids} >= {
        ("Sede A", "corp-wifi"),
        ("Sede B", "corp-wifi"),
    }
    _error(
        client.get(f"{WLAN}/access-points", params={"site_id": str(device_a["device_id"])}),
        404,
        "site_not_found",
    )
    # Un activo de la sede B con la IP del AP de la sede A no sirve como evidencia.
    agent_id, asset_id = register(client, primary_ip="10.70.0.21")
    db.execute(update(Asset).where(Asset.agent_id == agent_id).values(site_id=_site_pk(db, site_b)))
    db.commit()
    hall_a = by_mac(in_a)[AP_HALL]
    _error(
        client.post(
            f"{WLAN}/access-points/{hall_a['access_point_id']}/link", json={"asset_id": asset_id}
        ),
        409,
        "wlan_link_site_mismatch",
    )
    _error(
        client.post(
            f"{WLAN}/access-points/{hall_a['access_point_id']}/link",
            json={"network_device_id": device_b["device_id"]},
        ),
        409,
        "wlan_link_site_mismatch",
    )
    assert _ok(client.get(f"{WLAN}/access-points/{hall_a['access_point_id']}"))["asset"] is None


# --- autorización, vinculación y permisos -------------------------------------------------------


def test_authorization_is_manual_audited_and_versioned(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _, sensor, device = setup_wlan_device(client)
    full_controller_poll(client, sensor, device)
    hall = by_mac(aps(client))[AP_HALL]
    assert hall["authorization_status"] == "unknown"
    path = f"{WLAN}/access-points/{hall['access_point_id']}/authorization"
    updated = _ok(
        client.post(path, json={"status": "external", "reason": "Neighbour office", "version": 1})
    )
    assert updated["authorization_status"] == "external"
    assert updated["authorization_by"] == "admin" and updated["version"] == 2
    _error(
        client.post(path, json={"status": "authorized", "version": 1}), 409, "wlan_version_conflict"
    )
    [event] = audit(db, "wlan_authorization_changed")
    assert event.details == {"from": "unknown", "to": "external", "reason": "Neighbour office"}
    _error(client.post(path, json={"status": "rogue"}), 422, "validation_error")
    # La autorización sobrevive a nuevas consultas.
    full_controller_poll(client, sensor, device)
    assert by_mac(aps(client))[AP_HALL]["authorization_status"] == "external"
    assert len(aps(client, authorization="external")) == 1
    # BSS solo observado por un agente: también se puede clasificar.
    agent_id, _ = register(client)
    _ok(send_inventory(client, agent_id, wireless()), 201)
    cafe = next(b for b in _ok(client.get(f"{WLAN}/bss"))["items"] if b["ssid"] == "cafe-libre")
    marked = _ok(
        client.post(f"{WLAN}/bss/{cafe['bss_id']}/authorization", json={"status": "external"})
    )
    assert marked["authorization_status"] == "external"
    # Lector y analista leen pero no deciden.
    for role in ("viewer", "analyst"):
        with TestClient(client.app) as other:
            authenticate(other, engine, role, f"wlan-{role}")
            _ok(other.get(f"{WLAN}/overview"))
            _ok(other.get(f"{WLAN}/access-points/{hall['access_point_id']}"))
            _error(other.post(path, json={"status": "authorized"}), 403, "permission_denied")
            _error(
                other.post(f"{WLAN}/access-points/{hall['access_point_id']}/unlink", json={}),
                403,
                "permission_denied",
            )


def test_link_requires_evidence_and_unlink_is_sticky(client: TestClient, db: Session) -> None:
    site, sensor, device = setup_wlan_device(client)
    # Activo del mismo site con la IP de gestión del AP del vestíbulo: vínculo automático.
    agent_id, asset_id = register(client, primary_ip="10.70.0.21")
    other_id, other_asset = register(client, primary_ip="10.70.0.77")
    db.execute(
        update(Asset)
        .where(Asset.agent_id.in_([agent_id, other_id]))
        .values(site_id=_site_pk(db, site))
    )
    db.commit()
    full_controller_poll(client, sensor, device)
    hall = by_mac(aps(client))[AP_HALL]
    assert hall["asset"]["asset_id"] == asset_id
    detail = _ok(client.get(f"{WLAN}/access-points/{hall['access_point_id']}"))
    assert detail["link_evidence"]["asset"]["basis"] == "management_ip"
    assert detail["link_evidence"]["asset"]["method"] == "automatic"
    base = f"{WLAN}/access-points/{hall['access_point_id']}"
    unlinked = _ok(client.post(f"{base}/unlink", json={"target": "asset", "reason": "wrong"}))
    assert unlinked["asset"] is None and unlinked["link_suppressed"] is True
    assert audit(db, "wlan_access_point_unlinked")
    # La siguiente consulta no vuelve a vincular sola: decidió un operador.
    full_controller_poll(client, sensor, device)
    assert by_mac(aps(client))[AP_HALL]["asset"] is None
    # Sin evidencia (otra IP, otra MAC) no se vincula aunque se pida.
    _error(
        client.post(f"{base}/link", json={"asset_id": other_asset}),
        409,
        "wlan_link_evidence_insufficient",
    )
    linked = _ok(client.post(f"{base}/link", json={"asset_id": asset_id}))
    assert linked["asset"]["asset_id"] == asset_id and linked["link_suppressed"] is False
    assert linked["link_evidence"]["asset"]["method"] == "manual"
    assert linked["link_evidence"]["asset"]["by"] == "admin"
    # Identidad e historial del AP se conservan.
    assert linked["access_point_id"] == hall["access_point_id"]
    assert linked["first_seen_at"] == hall["first_seen_at"]
    _error(client.post(f"{base}/link", json={}), 422, "validation_error")


def test_client_mac_correlation_never_uses_random_macs(client: TestClient, db: Session) -> None:
    site, sensor, device = setup_wlan_device(client)
    global_id, global_asset = register(client, primary_ip="10.70.0.40")
    random_id, _ = register(client, primary_ip="10.70.0.41")
    db.execute(
        update(Asset)
        .where(Asset.agent_id.in_([global_id, random_id]))
        .values(site_id=_site_pk(db, site))
    )
    db.execute(
        update(Asset).where(Asset.agent_id == global_id).values(mac_address="3c:2e:f9:00:00:02")
    )
    db.execute(
        update(Asset).where(Asset.agent_id == random_id).values(mac_address="da:11:22:33:44:55")
    )
    db.commit()
    full_controller_poll(client, sensor, device)
    by_client = {c["mac"]: c for c in _ok(client.get(f"{WLAN}/clients"))["items"]}
    probable = by_client["3c:2e:f9:00:00:02"]
    assert probable["identity_confidence"] == "probable"
    assert probable["asset"]["asset_id"] == global_asset
    assert probable["correlation_basis"] == "mac_match"
    random_client = by_client["da:11:22:33:44:55"]
    assert random_client["identity_confidence"] == "observation_only"
    assert random_client["asset"] is None
    assert len(_ok(client.get(f"{WLAN}/clients", params={"identity": "probable"}))["items"]) == 1


# --- retención -------------------------------------------------------------------------------


def test_retention_is_opt_in(
    client: TestClient, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, sensor, device = setup_wlan_device(client)
    full_controller_poll(client, sensor, device)
    agent_id, _ = register(client)
    _ok(send_inventory(client, agent_id, wireless()), 201)
    old = datetime.now(UTC) - timedelta(days=40)
    db.execute(update(WlanObservation).values(observed_at=old))
    db.execute(update(WlanClient).values(last_seen_at=old))
    db.execute(update(WlanBss).values(last_seen_at=old))
    db.commit()
    # Sin WLAN_HISTORY_RETENTION_DAYS no se purga nada.
    run_network_maintenance(db, get_settings())
    assert db.scalar(select(WlanObservation.id).limit(1)) is not None
    counts = purge_wlan_history(db, 30)
    assert counts["wlan_observations"] > 0 and counts["wlan_clients"] == 4
    # Los BSS del agente sin AP ni decisión se purgan; los APs nunca.
    assert counts["wlan_bss"] == 2
    assert _ok(client.get(f"{WLAN}/access-points"))["total"] == 2
    monkeypatch.setenv("WLAN_HISTORY_RETENTION_DAYS", "30")
    get_settings.cache_clear()
    try:
        assert get_settings().wlan_history_retention_days == 30
    finally:
        monkeypatch.setenv("WLAN_HISTORY_RETENTION_DAYS", "")
        get_settings.cache_clear()


# --- unidades ---------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reported", "expected"),
    [
        ("Open", "open"),
        ("--", "open"),
        ("", "open"),
        ("spairport_security_mode_none", "open"),
        ("Open/WEP", "wep"),
        ("WEP", "wep"),
        ("WPA-Personal/TKIP", "wpa"),
        ("WPA1 WPA2", "wpa_wpa2"),
        ("WPA/WPA2 Personal", "wpa_wpa2"),
        ("WPA2-Personal/CCMP", "wpa2"),
        ("WPA2 802.1X", "wpa2"),
        ("spairport_security_mode_wpa2_personal", "wpa2"),
        ("WPA2/WPA3 Personal", "wpa2_wpa3"),
        ("WPA2 WPA3", "wpa2_wpa3"),
        ("WPA3-Personal", "wpa3"),
        ("SAE", "wpa3"),
        ("OWE", "owe"),
        ("Something new", "unknown"),
    ],
)
def test_security_normalization(reported: str, expected: str) -> None:
    assert wc.normalize_security(reported) == expected


def test_band_and_channel_rules() -> None:
    assert wc.band_from_frequency(2437) == "2.4"
    assert wc.band_from_frequency(5180) == "5"
    assert wc.band_from_frequency(5955) == "6"
    assert wc.band_from_frequency(900) is None
    assert wc.frequency_from_channel("6", 1) == 5955
    assert wc.frequency_from_channel(None, 1) is None
    assert wc.dot11_band(7, 1) == "2.4" and wc.dot11_band(7, 36) == "5"
    assert wc.dot11_band(14, 1) is None  # HE: 2,4 / 5 / 6 GHz, el canal no basta
    assert wc.dot11_protection(1, None) == "unknown"
    assert wc.dot11_protection(1, 2) == "legacy"
    assert wc.mac_randomized("da:11:22:33:44:55") and not wc.mac_randomized("3c:2e:f9:00:00:01")
    assert wc.insecure_finding("wpa2", "WPA2-Personal/TKIP") == "tkip_allowed"
    assert wc.insecure_finding("wpa3", "WPA3") is None


def test_snmp_record_contract_rejects_unknown_fields(client: TestClient) -> None:
    _, sensor, device = setup_wlan_device(client)
    records, _ = wlan_records("airespace_mib")
    tampered = copy.deepcopy(records)
    station = next(r for r in tampered if r["kind"] == "wlan_station")
    station["username"] = "alice@example.test"
    _ok(client.post(f"{DEVICES}/{device['device_id']}/polls"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    response = sensor.snmp_results(job, tampered)
    assert response.status_code == 422
    assert _ok(client.get(f"{WLAN}/clients"))["total"] == 0
