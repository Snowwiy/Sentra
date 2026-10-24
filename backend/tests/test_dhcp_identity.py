"""Fase 6E.2: fuentes DHCP, leases e identidad de activos (docs/dhcp-identity.md).

Primero los parsers y las reglas de asociación (sin base de datos); después la importación
manual, el job dhcp_leases de un sensor 0.6.0, la prioridad del nombre, el historial de
identidad, los motivos de "sin identificar", permisos y retención, con PostgreSQL.
"""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.dhcp import matching, parsers
from app.dhcp.service import purge_dhcp, schedule_due_reads
from app.discovery.classify import DHCP_LEASE, IdentityInput, identify
from app.models.asset import Asset, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.dhcp import AssetIdentityHistory, DhcpLease, DhcpSource
from app.models.site import SensorJob
from tests.conftest import authenticate
from tests.test_sites_sensors import SensorSim, default_site
from tests.test_topology import add_asset
from tests.test_topology import default_site as default_site_row

API = "/api/v1"
DHCP = f"{API}/dhcp"
DHCP_CAPS = ["network.discovery.basic", "network.icmp", "network.tcp", "dhcp.leases.file"]
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)


def _ok(response: Any, status: int = 200) -> Any:
    assert response.status_code == status, response.text
    return response.json()


def _error(response: Any, status: int, code: str) -> None:
    assert response.status_code == status, response.text
    assert response.json()["error"]["code"] == code


def _epoch(delta: timedelta) -> int:
    return int((datetime.now(UTC) + delta).timestamp())


# --- parsers ----------------------------------------------------------------------------------


def test_dnsmasq_parser_normalizes_and_skips_bad_lines() -> None:
    future = int((NOW + timedelta(hours=2)).timestamp())
    past = int((NOW - timedelta(hours=2)).timestamp())
    text = "\n".join(
        [
            f"{future} AA-BB-CC-00-00-01 192.168.1.10 pixel-7 01:aa:bb:cc:00:00:01",
            f"{past} aa:bb:cc:00:00:02 192.168.1.11 * ff:00:11",
            "basura",
            f"{future} zz:zz 192.168.1.12 x *",
            "duid 00:01:00:01",
        ]
    )
    result = parsers.parse("dnsmasq", text, NOW)
    assert result.skipped == 2
    first, second = result.leases
    assert (first.mac, first.ip, first.hostname, first.state) == (
        "aa:bb:cc:00:00:01",
        "192.168.1.10",
        "pixel-7",
        "active",
    )
    # El client id tipo 01 + MAC no aporta nada; uno opaco queda como huella corta.
    assert first.client_id is None
    assert second.hostname is None and second.state == "expired"
    assert second.client_id is not None and second.client_id.startswith("sha256:")
    assert len(second.client_id) == len("sha256:") + 16


def test_isc_kea_windows_and_generic_formats() -> None:
    isc = """
lease 10.0.0.5 {
  starts 4 2026/10/22 10:00:00;
  ends 4 2026/10/22 14:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "nas";
}
lease 10.0.0.5 {
  ends 4 2026/10/22 15:00:00;
  binding state active;
  hardware ethernet 00:11:22:33:44:55;
  client-hostname "nas-2";
}
"""
    [lease] = parsers.parse("isc_dhcpd", isc, NOW).leases
    assert lease.hostname == "nas-2"  # la última aparición gana
    kea = (
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state\n"
        f"10.0.0.6,00:11:22:33:44:66,,3600,{int((NOW + timedelta(hours=1)).timestamp())},1,0,0,"
        "printer.lan.,0\n"
    )
    [k] = parsers.parse("kea_csv", kea, NOW).leases
    assert k.hostname == "printer.lan" and k.state == "active" and k.starts_at is not None
    windows = (
        "#TYPE Microsoft.Management.Infrastructure.CimInstance\n"
        '"IPAddress","ClientId","HostName","AddressState","LeaseExpiryTime"\n'
        '"10.0.0.7","00-11-22-33-44-77","pc-01.corp.local","Active","2026-10-23T10:00:00Z"\n'
    )
    [w] = parsers.parse("windows_dhcp_csv", windows, NOW).leases
    assert (w.mac, w.hostname, w.state) == ("00:11:22:33:44:77", "pc-01.corp.local", "active")
    generic = "ip,mac,hostname,expires\n10.0.0.8,00:11:22:33:44:88,tv,\n"
    [g] = parsers.parse("generic_csv", generic, NOW).leases
    assert g.hostname == "tv" and g.state == "active"
    with pytest.raises(parsers.LeaseFormatError):
        parsers.parse("kea_csv", "nada,que,ver\n1,2,3\n", NOW)


def test_client_id_hash_matches_the_sensor() -> None:
    # Mismo cálculo que sentra_sensor.dhcp: octetos hex → bytes; si no, el texto.
    from hashlib import sha256

    expected = "sha256:" + sha256(bytes([0xFF, 0x00, 0x11])).hexdigest()[:16]
    assert parsers.clean_client_id("ff:00:11", "aa:bb:cc:dd:ee:ff") == expected


# --- reglas de asociación -------------------------------------------------------------------


def _cand(asset_id: int, mac: str, ip: str) -> matching.AssetCandidate:
    return matching.AssetCandidate(asset_id, mac, ip)


def test_matching_rules() -> None:
    mac = "00:11:22:33:44:55"
    one = [_cand(1, mac, "10.0.0.5")]
    assert matching.match_lease(ip="10.0.0.5", mac=mac, state="active", by_mac=one).match == (
        "mac_ip"
    )
    moved = matching.match_lease(ip="10.0.0.9", mac=mac, state="active", by_mac=one)
    assert (moved.match, moved.asset_id, moved.names_asset) == ("mac_moved", 1, False)
    two = [*one, _cand(2, mac, "10.0.0.6")]
    assert matching.match_lease(ip="10.0.0.5", mac=mac, state="active", by_mac=two).match == (
        "ambiguous"
    )
    assert matching.match_lease(ip="10.0.0.5", mac=mac, state="expired", by_mac=one).match == (
        "expired"
    )
    random_mac = "da:11:22:33:44:55"  # bit de administración local
    assert (
        matching.match_lease(ip="10.0.0.5", mac=random_mac, state="active", by_mac=[]).match
        == "randomized_mac"
    )
    # Una MAC aleatoria con MAC e IP exactas sí es la misma interfaz.
    assert (
        matching.match_lease(
            ip="10.0.0.5", mac=random_mac, state="active", by_mac=[_cand(3, random_mac, "10.0.0.5")]
        ).match
        == "mac_ip"
    )
    nothing = matching.match_lease(ip="10.0.0.5", mac=mac, state="active", by_mac=[])
    assert matching.ip_only(nothing, ip_has_asset=True).match == "ip_only"
    assert matching.ip_only(nothing, ip_has_asset=False).match == "no_asset"


@pytest.mark.parametrize(
    ("name", "usable"),
    [
        ("pixel-7", True),
        ("Salon-TV", True),
        ("android", False),
        ("android-3f2a9c11", False),
        ("iPhone", False),
        ("localhost", False),
        ("linux", False),
        ("*", False),
        (None, False),
    ],
)
def test_generic_dhcp_hostnames(name: str | None, usable: bool) -> None:
    assert matching.usable_hostname(name) is usable


def test_dhcp_name_priority_in_classify() -> None:
    # DHCP alto va detrás del agente y por delante de DNS inverso y mDNS.
    result = identify(
        IdentityInput(dhcp_hostname="pixel-7", reverse_dns="host-10-0-0-5.isp.net", mdns_name="x")
    )
    assert (result.name, result.name_source) == ("pixel-7", DHCP_LEASE)
    assert any(n["source"] == DHCP_LEASE and n["kind"] == "dhcp" for n in result.names)
    managed = identify(IdentityInput(managed=True, hostname="WS-01", dhcp_hostname="pixel-7"))
    assert managed.name is None or managed.name_source != DHCP_LEASE


# --- importación manual --------------------------------------------------------------------


def _import_source(client: TestClient, fmt: str = "dnsmasq", name: str = "router") -> Any:
    return _ok(
        client.post(f"{DHCP}/sources", json={"name": name, "kind": "lease_import", "format": fmt}),
        201,
    )


def _import(client: TestClient, source: dict[str, Any], content: str) -> Any:
    return client.post(
        f"{DHCP}/sources/{source['id']}/import",
        json={"content": content, "version": source["version"]},
    )


def test_import_names_only_exact_matches(client: TestClient, engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as db:
        site = default_site_row(db)
        exact = add_asset(db, site, "192.168.1.10", "00:11:22:33:44:01")
        moved = add_asset(db, site, "192.168.1.20", "00:11:22:33:44:02")
        by_ip = add_asset(db, site, "192.168.1.30", "00:11:22:33:44:03")
        dup_a = add_asset(db, site, "192.168.1.40", "00:11:22:33:44:04")
        dup_b = add_asset(db, site, "192.168.1.41", "00:11:22:33:44:05")
    future = _epoch(timedelta(hours=4))
    content = "\n".join(
        [
            f"{future} 00:11:22:33:44:01 192.168.1.10 pixel-7 *",
            f"{future} 00:11:22:33:44:02 192.168.1.99 laptop-ana *",
            f"{future} 00:11:22:33:44:99 192.168.1.30 intruso *",
            f"{future} 00:11:22:33:44:04 192.168.1.40 chromecast *",
            f"{future} 00:11:22:33:44:05 192.168.1.41 chromecast *",
            f"{future} da:00:00:00:00:01 192.168.1.50 iphone *",
        ]
    )
    source = _import_source(client)
    result = _ok(_import(client, source, content))
    assert (result["parsed"], result["skipped"], result["named"]) == (6, 0, 1)
    assert result["source"]["status"] == "ok" and result["source"]["lease_count"] == 6
    with Session(engine) as db:
        rows = {r.mac: r for r in db.scalars(select(DhcpLease))}
        assert rows["00:11:22:33:44:01"].match == "mac_ip"
        assert rows["00:11:22:33:44:02"].match == "mac_moved"
        assert rows["00:11:22:33:44:99"].match == "ip_only"
        assert rows["00:11:22:33:44:99"].asset_id is None
        assert rows["da:00:00:00:00:01"].match == "randomized_mac"
        named = db.get(Asset, exact.id)
        assert named is not None
        assert (named.device_name, named.name_source) == ("pixel-7", DHCP_LEASE)
        # Misma MAC con otra IP: enlazado como evidencia, sin nombre.
        assert db.get(Asset, moved.id).device_name is None  # type: ignore[union-attr]
        # Solo IP: ni nombre ni asociación (nunca se fusiona por IP).
        assert db.get(Asset, by_ip.id).device_name is None  # type: ignore[union-attr]
        # Un hostname dado a dos MACs a la vez no distingue a ninguna.
        assert db.get(Asset, dup_a.id).device_name is None  # type: ignore[union-attr]
        assert db.get(Asset, dup_b.id).device_name is None  # type: ignore[union-attr]
        # El historial de identidad registra el nombre nuevo con su fuente.
        history = db.scalars(
            select(AssetIdentityHistory).where(AssetIdentityHistory.asset_id == exact.id)
        ).all()
        assert [
            (h.field, h.new_value, h.source, h.confidence) for h in history if h.field == "name"
        ] == [("name", "pixel-7", DHCP_LEASE, "high")]
        actions = set(db.scalars(select(AuditEvent.action)))
        assert {"dhcp_source_created", "dhcp_leases_imported"} <= actions
        # La auditoría nunca guarda el contenido del fichero.
        details = db.scalars(
            select(AuditEvent.details).where(AuditEvent.action == "dhcp_leases_imported")
        ).one()
        assert "pixel-7" not in str(details)


def test_reimport_is_idempotent_and_custom_label_wins(client: TestClient, engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as db:
        asset = add_asset(db, default_site_row(db), "192.168.1.10", "00:11:22:33:44:01")
    content = f"{_epoch(timedelta(hours=4))} 00:11:22:33:44:01 192.168.1.10 pixel-7 *"
    source = _import_source(client)
    first = _ok(_import(client, source, content))
    second = _ok(_import(client, first["source"], content))
    assert second["source"]["lease_count"] == 1
    _ok(
        client.patch(
            f"{API}/assets/{asset.public_id}/label", json={"label": "Movil Ana", "version": 0}
        )
    )
    identity = _ok(client.get(f"{API}/assets/{asset.public_id}/identity"))
    assert identity["display_name"] == "Movil Ana"
    assert identity["automatic_name"] == "pixel-7" and identity["name_source"] == DHCP_LEASE
    assert identity["leases"][0]["match"] == "mac_ip"
    assert identity["unidentified_reasons"] == []
    history = _ok(client.get(f"{API}/assets/{asset.public_id}/identity/history"))
    assert history["items"][0]["field"] == "label"
    assert "name" in [e["field"] for e in history["items"]]
    labels = _ok(client.get(f"{API}/assets/{asset.public_id}/identity/history?field=label"))
    assert [e["new_value"] for e in labels["items"]] == ["Movil Ana"]


def test_import_errors(client: TestClient, engine: Engine) -> None:
    source = _import_source(client, fmt="kea_csv")
    _error(_import(client, source, "esto,no,es,kea\n1,2,3,4\n"), 422, "dhcp_format_invalid")
    stale = _ok(client.get(f"{DHCP}/sources/{source['id']}"))
    assert stale["status"] == "error" and stale["last_error_code"] == "dhcp_format_invalid"
    # Versión obsoleta.
    _error(_import(client, source, "address,hwaddr\n"), 409, "dhcp_source_conflict")
    # Tope de tamaño (DHCP_IMPORT_MAX_KB).
    settings = get_settings()
    big = "x" * (settings.dhcp_import_max_kb * 1024 + 1)
    _error(_import(client, stale, big), 422, "dhcp_file_too_large")
    # Una fuente deshabilitada no acepta importaciones.
    disabled = _ok(
        client.patch(
            f"{DHCP}/sources/{source['id']}", json={"enabled": False, "version": stale["version"]}
        )
    )
    assert disabled["status"] == "disabled"
    _error(_import(client, disabled, "address,hwaddr\n"), 409, "dhcp_source_disabled")
    # Nombre repetido en el site.
    _error(
        client.post(
            f"{DHCP}/sources",
            json={"name": source["name"], "kind": "lease_import", "format": "dnsmasq"},
        ),
        409,
        "dhcp_source_name_taken",
    )
    # lease_import no admite sensor ni intervalo.
    response = client.post(
        f"{DHCP}/sources",
        json={
            "name": "x",
            "kind": "lease_import",
            "format": "dnsmasq",
            "sensor_source_name": "lan",
        },
    )
    assert response.status_code == 422


def test_delete_source_removes_its_names(client: TestClient, engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as db:
        asset = add_asset(db, default_site_row(db), "192.168.1.10", "00:11:22:33:44:01")
    source = _import_source(client)
    imported = _ok(
        _import(client, source, f"{_epoch(timedelta(hours=4))} 00:11:22:33:44:01 192.168.1.10 tv *")
    )
    version = imported["source"]["version"]
    _error(
        client.delete(f"{DHCP}/sources/{source['id']}?version={version + 5}"),
        409,
        "dhcp_source_conflict",
    )
    assert client.delete(f"{DHCP}/sources/{source['id']}?version={version}").status_code == 204
    with Session(engine) as db:
        row = db.get(Asset, asset.id)
        assert row is not None and row.device_name is None
        assert "dhcp_lease" not in (row.identity_observations or {})
        assert db.scalar(select(DhcpLease.id)) is None


def test_unidentified_reasons(client: TestClient, engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as db:
        asset = add_asset(db, default_site_row(db), "192.168.1.60", "da:00:00:00:00:09")
    identity = _ok(client.get(f"{API}/assets/{asset.public_id}/identity"))
    assert identity["mac_randomized"] is True
    assert identity["unidentified_reasons"] == [
        "no_name_sources",
        "randomized_mac",
        "dhcp_source_missing",
    ]
    _import_source(client)
    identity = _ok(client.get(f"{API}/assets/{asset.public_id}/identity"))
    assert "dhcp_no_lease" in identity["unidentified_reasons"]
    _error(client.get(f"{API}/assets/{uuid.uuid4()}/identity"), 404, "not_found")


def test_leases_listing_filters(client: TestClient, engine: Engine) -> None:
    source = _import_source(client)
    future = _epoch(timedelta(hours=4))
    _ok(
        _import(
            client,
            source,
            f"{future} 00:11:22:33:44:01 192.168.1.10 salon-tv *\n"
            f"{future} 00:11:22:33:44:02 192.168.1.11 cocina *",
        )
    )
    everything = _ok(client.get(f"{DHCP}/leases"))
    assert everything["total"] == 2
    found = _ok(client.get(f"{DHCP}/leases", params={"search": "SALON"}))
    assert [i["hostname"] for i in found["items"]] == ["salon-tv"]
    assert _ok(client.get(f"{DHCP}/leases", params={"match": "mac_ip"}))["total"] == 0
    assert _ok(client.get(f"{DHCP}/leases", params={"search": "%"}))["total"] == 0


def test_permissions(client: TestClient, engine: Engine) -> None:
    source = _import_source(client)
    for role in ("viewer", "analyst"):
        with TestClient(client.app) as other:
            authenticate(other, engine, role, f"user-{role}")
            assert other.get(f"{DHCP}/sources").status_code == 200
            assert other.get(f"{DHCP}/leases").status_code == 200
            _error(
                other.post(
                    f"{DHCP}/sources",
                    json={"name": "y", "kind": "lease_import", "format": "dnsmasq"},
                ),
                403,
                "permission_denied",
            )
            _error(_import(other, source, "x"), 403, "permission_denied")


# --- sensor 0.6.0 ----------------------------------------------------------------------------


def _sensor_source(client: TestClient, sensor: SensorSim, **extra: Any) -> Any:
    body = {
        "name": "openwrt",
        "kind": "sensor_file",
        "format": "dnsmasq",
        "sensor_id": sensor.sensor_id,
        "sensor_source_name": "lan",
        **extra,
    }
    return _ok(client.post(f"{DHCP}/sources", json=body), 201)


def _lease(ip: str, mac: str, hostname: str | None, state: str = "active") -> dict[str, Any]:
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "client_id": None,
        "starts_at": None,
        "ends_at": (datetime.now(UTC) + timedelta(hours=2)).isoformat(),
        "state": state,
    }


def _sensor(client: TestClient, caps: list[str] = DHCP_CAPS) -> SensorSim:
    site = default_site(client)
    sim = SensorSim(client, site["site_id"])
    sim.heartbeat(sensor_version="0.6.0", capabilities=caps)
    return sim


def test_sensor_job_flow(client: TestClient, engine: Engine) -> None:
    with Session(engine, expire_on_commit=False) as db:
        asset = add_asset(db, default_site_row(db), "10.60.0.5", "00:11:22:33:44:01")
    sensor = _sensor(client)
    source = _sensor_source(client, sensor)
    requested = _ok(client.post(f"{DHCP}/sources/{source['id']}/read"), 202)
    _error(client.post(f"{DHCP}/sources/{source['id']}/read"), 409, "dhcp_read_in_progress")
    [job] = sensor.poll()
    assert job["job_id"] == requested["sensor_job_id"]
    # El sensor solo recibe el nombre de la entrada: nunca una ruta.
    assert job["job_type"] == "dhcp_leases" and job["parameters"] == {"source_name": "lan"}
    _ok(sensor.start(job))
    batch = {
        "batch_id": str(uuid.uuid4()),
        "attempt": job["attempt"],
        "leases": [_lease("10.60.0.5", "00:11:22:33:44:01", "impresora-oficina")],
    }
    first = _ok(sensor.call(f"/jobs/{job['job_id']}/results", batch))
    assert first["accepted"] == 1
    assert _ok(sensor.call(f"/jobs/{job['job_id']}/results", batch))["duplicate"] is True
    # Un lote con observaciones de discovery en un job DHCP es inválido.
    mixed = {**batch, "batch_id": str(uuid.uuid4()), "observations": [], "records": []}
    mixed["observations"] = [
        {
            "address": "10.60.0.5",
            "ports": [],
            "sources": ["arp"],
            "observed_at": datetime.now(UTC).isoformat(),
        }
    ]
    _error(sensor.call(f"/jobs/{job['job_id']}/results", mixed), 422, "sensor_batch_invalid")
    summary = {
        "format": "dnsmasq",
        "lines": 3,
        "parsed": 1,
        "skipped": 2,
        "truncated": False,
        "file_mtime": None,
        "error_code": None,
    }
    _ok(
        sensor.call(
            f"/jobs/{job['job_id']}/complete",
            {"attempt": job["attempt"], "outcome": "completed", "batches_sent": 1, "dhcp": summary},
        )
    )
    after = _ok(client.get(f"{DHCP}/sources/{source['id']}"))
    assert after["status"] == "ok" and after["last_import_at"] is not None
    assert after["last_stats"]["named"] == 1 and after["last_stats"]["skipped"] == 2
    with Session(engine) as db:
        row = db.get(Asset, asset.id)
        assert row is not None and row.device_name == "impresora-oficina"
        assert db.scalar(select(SensorJob.status)) == "succeeded"


def test_sensor_failure_and_capability(client: TestClient, engine: Engine) -> None:
    old = _sensor(client, caps=["network.discovery.basic"])
    source = _sensor_source(client, old, name="viejo")
    # Un sensor 0.5.x no declara dhcp.leases.file: no se le pide nada.
    _error(client.post(f"{DHCP}/sources/{source['id']}/read"), 409, "dhcp_sensor_unavailable")
    sensor = _sensor(client)
    source = _sensor_source(client, sensor)
    _ok(client.post(f"{DHCP}/sources/{source['id']}/read"), 202)
    [job] = sensor.poll()
    _ok(sensor.start(job))
    summary = {"format": None, "error_code": "dhcp_source_unknown"}
    _ok(
        sensor.call(
            f"/jobs/{job['job_id']}/complete",
            {
                "attempt": job["attempt"],
                "outcome": "failed",
                "errors": ["dhcp_source_unknown"],
                "dhcp": summary,
            },
        )
    )
    after = _ok(client.get(f"{DHCP}/sources/{source['id']}"))
    assert after["status"] == "error" and after["last_error_code"] == "dhcp_source_unknown"
    with Session(engine) as db:
        assert db.scalar(
            select(SensorJob.error_code).where(SensorJob.public_id == uuid.UUID(job["job_id"]))
        ) == ("dhcp_source_unknown")
    # Otro site no puede usar el sensor.
    other = _ok(client.post(f"{API}/sites", json={"name": "Remota"}), 201)
    _error(
        client.post(
            f"{DHCP}/sources",
            json={
                "site_id": other["site_id"],
                "name": "x",
                "kind": "sensor_file",
                "format": "dnsmasq",
                "sensor_id": sensor.sensor_id,
                "sensor_source_name": "otra",
            },
        ),
        404,
        "sensor_not_found",
    )


def test_scheduled_reads(client: TestClient, engine: Engine) -> None:
    sensor = _sensor(client)
    source = _sensor_source(client, sensor, poll_interval_minutes=30)
    settings = get_settings()
    with Session(engine) as db:
        assert schedule_due_reads(db, settings) == 1
        # Ya hay un job abierto: no se encola otro.
        assert schedule_due_reads(db, settings) == 0
        db.execute(update(SensorJob).values(status="succeeded"))
        db.commit()
        # Aún no vence el intervalo.
        assert schedule_due_reads(db, settings) == 0
        later = datetime.now(UTC) + timedelta(minutes=31)
        assert schedule_due_reads(db, settings, later) == 1
        row = db.scalars(select(DhcpSource).where(DhcpSource.public_id == uuid.UUID(source["id"])))
        assert row.one().last_requested_at is not None


def test_retention(client: TestClient, engine: Engine) -> None:
    source = _import_source(client)
    _ok(_import(client, source, f"{_epoch(timedelta(hours=4))} 00:11:22:33:44:01 10.0.0.1 a *"))
    settings = get_settings()
    with Session(engine) as db:
        assert purge_dhcp(db, settings, datetime.now(UTC))["dhcp_leases"] == 0
        assert settings.dhcp_lease_retention_days is not None
        future = datetime.now(UTC) + timedelta(days=settings.dhcp_lease_retention_days + 1)
        assert purge_dhcp(db, settings, future)["dhcp_leases"] == 1
        db.commit()


def test_identity_history_listener_records_agent_and_discovery_changes(
    client: TestClient, engine: Engine
) -> None:
    # `client` vacía las tablas al terminar: sin él, el activo creado aquí se quedaba en la base
    # y descuadraba tests posteriores que cuentan activos.
    with Session(engine, expire_on_commit=False) as db:
        site = default_site_row(db)
        asset = add_asset(
            db, site, "10.0.0.1", "00:11:22:33:44:aa", monitoring_method=MonitoringMethod.DISCOVERED
        )
        asset.primary_ip = "10.0.0.2"
        db.commit()
        # Sin cambio real no hay fila.
        asset.primary_ip = "10.0.0.2"
        db.commit()
        rows = db.scalars(
            select(AssetIdentityHistory).where(AssetIdentityHistory.asset_id == asset.id)
        ).all()
        assert [(r.field, r.old_value, r.new_value, r.source) for r in rows] == [
            ("ip", "10.0.0.1", "10.0.0.2", "discovery")
        ]
