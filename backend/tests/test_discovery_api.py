"""Discovery read API: assets of every kind, filters, exposure correlation, jobs, scope."""

from datetime import UTC, datetime
from typing import Any

from fastapi.testclient import TestClient
from sqlalchemy import Engine

from app.core.config import get_settings
from tests.conftest import agent_payload
from tests.test_discovery_service import Host, Lab, _service, office

ANY_ADDRESS = "0.0.0.0"  # noqa: S104  (reported by the agent, nothing binds here)


def _managed_with_listeners(client: TestClient) -> dict[str, Any]:
    payload = agent_payload(primary_ip="10.20.0.5")
    client.post("/api/v1/agents/register", json=payload)
    client.post("/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"]})
    now = datetime.now(UTC).isoformat()
    inventory = {
        "agent_id": payload["agent_id"],
        "collected_at": now,
        "interfaces": [
            {"name": "eth", "mac": "02:00:00:00:00:05", "addresses": ["10.20.0.5"], "is_up": True}
        ],
        "connections": [
            {"protocol": "tcp", "local_address": ANY_ADDRESS, "local_port": 3389,
             "status": "listen", "pid": 1180, "process_name": "svchost.exe"},
            {"protocol": "tcp", "local_address": "127.0.0.1", "local_port": 8080,
             "status": "listen", "pid": 4820, "process_name": "java.exe"},
            {"protocol": "tcp", "local_address": ANY_ADDRESS, "local_port": 49152,
             "status": "listen", "pid": 700, "process_name": "lsass.exe"},
        ],
    }  # fmt: skip
    assert client.post("/api/v1/inventory", json=inventory).status_code == 201
    processes = {
        "agent_id": payload["agent_id"],
        "collected_at": now,
        "processes": [
            {"pid": 4820, "name": "java.exe", "memory_bytes": 1,
             "exe": "C:\\Program Files\\App\\java.exe", "username": "CORP\\service-account"},
        ],
    }  # fmt: skip
    assert client.post("/api/v1/processes", json=processes).status_code == 201
    return payload


def test_assets_list_mixes_managed_and_discovered(client: TestClient, engine: Engine) -> None:
    _managed_with_listeners(client)
    _service(engine, Lab(office()), gateways={"10.20.0.1"}).run()

    items = client.get("/api/v1/assets").json()["items"]
    by_ip = {a["primary_ip"]: a for a in items}

    assert len(items) == 4  # the agent host is not duplicated
    managed = by_ip["10.20.0.5"]
    assert managed["monitoring_method"] == "agent" and managed["agent_status"] == "online"
    assert managed["network_status"] == "online" and managed["open_ports"] == [135, 445, 3389]
    printer = by_ip["10.20.0.7"]
    assert printer["monitoring_method"] == "discovered"
    assert printer["hostname"] is None and printer["display_name"] == "10.20.0.7"
    assert printer["status"] == "online" and printer["agent_status"] is None
    assert printer["device_type"] == "printer" and printer["open_ports"] == [80, 443, 9100]
    assert printer["os_name"] is None and printer["latest_telemetry"] is None
    assert by_ip["10.20.0.1"]["device_type"] == "network_device"


def test_asset_filters(client: TestClient, engine: Engine) -> None:
    _managed_with_listeners(client)
    _service(engine, Lab({**office(), "10.20.0.12": Host({22}, name="nas.corp")})).run()

    def ips(query: str) -> list[str]:
        response = client.get(f"/api/v1/assets?{query}")
        assert response.status_code == 200, response.text
        return sorted(a["primary_ip"] for a in response.json()["items"])

    assert ips("method=agent") == ["10.20.0.5"]
    assert len(ips("method=discovered")) == 4
    assert ips("device_type=printer") == ["10.20.0.7"]
    assert ips("device_type=unknown") == ["10.20.0.1", "10.20.0.12", "10.20.0.9"]
    assert ips("subnet=10.20.0.4/30") == ["10.20.0.5", "10.20.0.7"]
    assert ips("q=NAS") == ["10.20.0.12"]
    assert ips("q=02:00:00:00:00:09") == ["10.20.0.9"]
    assert ips("status=online&method=discovered") == ips("method=discovered")
    for bad in ("method=bogus", "subnet=10.20.0.5/24", "subnet=nope", "device_type=DROP%20TABLE"):
        assert client.get(f"/api/v1/assets?{bad}").status_code == 422, bad


def test_exposure_correlates_network_and_agent(client: TestClient, engine: Engine) -> None:
    _managed_with_listeners(client)
    _service(engine, Lab(office())).run()
    asset_id = next(
        a["asset_id"] for a in client.get("/api/v1/assets?method=agent").json()["items"]
    )

    body = client.get(f"/api/v1/assets/{asset_id}/exposure").json()

    ports = {p["port"]: p for p in body["ports"]}
    assert set(ports) == {135, 445, 3389}
    assert ports[3389]["state"] == "open" and ports[3389]["sensitive"]
    assert ports[3389]["service_hint"] == "rdp"
    assert ports[3389]["process"]["name"] == "svchost.exe"
    assert ports[445]["process"] is None  # the agent did not report a listener on 445
    listeners = {entry["port"]: entry for entry in body["agent_listeners"]}
    # 8080 listens on localhost only: probed (in DISCOVERY_PORTS) and not reachable.
    assert listeners[8080]["exposed"] is False
    assert listeners[8080]["process"]["exe"] == "C:\\Program Files\\App\\java.exe"
    assert listeners[8080]["process"]["username"] == "CORP\\service-account"
    assert listeners[3389]["exposed"] is True
    assert listeners[49152]["exposed"] is None  # not a probed port: unknown
    assert body["baseline_at"] is not None


def test_exposure_of_unknown_or_unscanned_asset(client: TestClient) -> None:
    payload = agent_payload()
    response = client.post("/api/v1/agents/register", json=payload)
    asset_id = response.json()["asset_id"]

    body = client.get(f"/api/v1/assets/{asset_id}/exposure").json()
    assert body["ports"] == [] and body["agent_listeners"] == [] and body["baseline_at"] is None
    missing = "00000000-0000-0000-0000-000000000000"
    assert client.get(f"/api/v1/assets/{missing}/exposure").status_code == 404


def test_jobs_and_scope(client: TestClient, engine: Engine) -> None:
    _service(engine, Lab(office())).run()
    _service(engine, Lab(office())).run()

    jobs = client.get("/api/v1/discovery/jobs").json()["items"]
    assert [j["baseline"] for j in jobs] == [False, True]  # newest first
    assert jobs[0]["status"] == "completed" and jobs[0]["hosts_scanned"] == 14
    assert jobs[0]["hosts_alive"] == 4 and jobs[0]["duration_seconds"] is not None
    assert client.get("/api/v1/discovery/jobs?limit=0").status_code == 422

    scope = client.get("/api/v1/discovery/scope").json()
    settings = get_settings()
    assert scope["enabled"] is bool(settings.discovery_allowed_networks)
    assert 3389 in scope["ports"]


def test_existing_agent_flow_is_unchanged(client: TestClient) -> None:
    payload = agent_payload()
    registered = client.post("/api/v1/agents/register", json=payload).json()
    asset = client.get(f"/api/v1/assets/{registered['asset_id']}").json()

    assert asset["monitoring_method"] == "agent"
    assert asset["hostname"] == "PC-ADMIN-01" and asset["os_name"] == "Windows"
    assert asset["status"] == "unknown" and asset["agent_status"] == "unknown"
    assert asset["network_status"] is None and asset["open_ports"] == []
    assert asset["discovery_sources"] == [] and asset["discovered_at"] is None
