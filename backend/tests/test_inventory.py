from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient


def inventory_payload(agent_id: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "agent_id": agent_id,
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [
            {
                "name": "Ethernet",
                "mac": "00-15-5D-01-02-03",
                "addresses": ["192.168.1.20", "fe80::1"],
                "is_up": True,
                "speed_mbps": 1000,
            }
        ],
        "users": [{"name": "admin", "terminal": None, "host": None, "started_at": None}],
        "processes": [{"pid": 4, "name": "System", "username": None, "memory_bytes": 1024}],
        "services": [
            {
                "name": "Dnscache",
                "display_name": "DNS Client",
                "status": "running",
                "start_type": "automatic",
            }
        ],
        "software": [{"name": "Python 3.13", "version": "3.13.1", "publisher": "PSF"}],
    }
    payload.update(overrides)
    return payload


def test_inventory_is_stored_and_returned(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]

    response = client.post("/api/v1/inventory", json=inventory_payload(agent_id))

    assert response.status_code == 201
    body = client.get(f"/api/v1/assets/{asset_id}/inventory").json()
    assert body["asset_id"] == asset_id
    assert body["interfaces"][0]["addresses"] == ["192.168.1.20", "fe80::1"]
    assert body["services"][0]["status"] == "running"
    assert body["software"][0]["name"] == "Python 3.13"
    assert "agent_id" not in body


def test_newer_snapshot_replaces_older_one_but_not_the_reverse(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]
    now = datetime.now(UTC)

    client.post("/api/v1/inventory", json=inventory_payload(agent_id, collected_at=now.isoformat()))
    stale = inventory_payload(
        agent_id, collected_at=(now - timedelta(hours=1)).isoformat(), software=[]
    )
    assert client.post("/api/v1/inventory", json=stale).status_code == 201

    body = client.get(f"/api/v1/assets/{asset_id}/inventory").json()
    assert len(body["software"]) == 1

    newer = inventory_payload(
        agent_id, collected_at=(now + timedelta(seconds=1)).isoformat(), software=[]
    )
    client.post("/api/v1/inventory", json=newer)
    assert client.get(f"/api/v1/assets/{asset_id}/inventory").json()["software"] == []


def test_inventory_marks_asset_seen(client: TestClient, registered_agent: dict[str, Any]) -> None:
    client.post(
        "/api/v1/inventory", json=inventory_payload(registered_agent["payload"]["agent_id"])
    )

    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["status"] == "online"


def test_inventory_missing_returns_not_found(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    asset_id = registered_agent["response"]["asset_id"]

    assert client.get(f"/api/v1/assets/{asset_id}/inventory").status_code == 404
    assert client.get(f"/api/v1/assets/{uuid4()}/inventory").status_code == 404


def test_inventory_from_unknown_agent_is_rejected(client: TestClient) -> None:
    assert client.post("/api/v1/inventory", json=inventory_payload(str(uuid4()))).status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"interfaces": [{"name": "eth0", "addresses": ["999.1.1.1"], "is_up": True}]},
        {"processes": [{"pid": -1, "name": "x", "memory_bytes": 0}]},
        {"software": [{"name": "x", "unexpected": 1}]},
        {"processes": [{"pid": i, "name": "p", "memory_bytes": 0} for i in range(501)]},
        {"collected_at": "2026-01-01T00:00:00"},
    ],
)
def test_invalid_inventory_is_rejected(
    client: TestClient, registered_agent: dict[str, Any], overrides: dict[str, Any]
) -> None:
    payload = inventory_payload(registered_agent["payload"]["agent_id"], **overrides)

    assert client.post("/api/v1/inventory", json=payload).status_code == 422


def test_disks_and_connections_are_stored(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    disks = [
        {
            "device": "C:\\",
            "mountpoint": "C:\\",
            "fstype": "NTFS",
            "total_bytes": 1000,
            "used_bytes": 828,
            "free_bytes": 172,
            "percent": 82.8,
        }
    ]
    connections = [
        {
            "protocol": "tcp",
            "local_address": "0.0.0.0",  # noqa: S104  (sample data, not a bind)
            "local_port": 135,
            "remote_address": None,
            "remote_port": None,
            "status": "listen",
            "pid": 1112,
            "process_name": "svchost.exe",
        }
    ]
    payload = inventory_payload(
        registered_agent["payload"]["agent_id"], disks=disks, connections=connections
    )

    assert client.post("/api/v1/inventory", json=payload).status_code == 201
    body = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}/inventory").json()
    assert body["disks"][0]["percent"] == 82.8
    assert body["connections"][0]["process_name"] == "svchost.exe"


@pytest.mark.parametrize(
    "overrides",
    [
        {"connections": [{"protocol": "icmp", "status": "listen"}]},
        {"connections": [{"protocol": "tcp", "status": "time_wait"}]},
        {"connections": [{"protocol": "tcp", "status": "listen", "local_port": 70000}]},
        {
            "disks": [
                {
                    "device": "C:",
                    "mountpoint": "C:",
                    "total_bytes": 1,
                    "used_bytes": 1,
                    "free_bytes": 0,
                    "percent": 101,
                }
            ]
        },
    ],
)
def test_invalid_disks_or_connections_are_rejected(
    client: TestClient, registered_agent: dict[str, Any], overrides: dict[str, Any]
) -> None:
    payload = inventory_payload(registered_agent["payload"]["agent_id"], **overrides)

    assert client.post("/api/v1/inventory", json=payload).status_code == 422
