from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app.schemas.process import MAX_SNAPSHOT_PROCESSES


def _process(pid: int, **overrides: Any) -> dict[str, Any]:
    process = {
        "pid": pid,
        "ppid": 4,
        "name": f"proc{pid}.exe",
        "exe": rf"C:\Program Files\App\proc{pid}.exe",
        "username": "PC\\ana",
        "cpu_percent": 1.5,
        "memory_bytes": 1024 * pid,
        "started_at": (datetime.now(UTC) - timedelta(hours=1)).isoformat(),
        "status": "running",
    }
    process.update(overrides)
    return process


def _send(client: TestClient, agent_id: str, at: datetime, processes: list[Any]) -> Any:
    return client.post(
        "/api/v1/processes",
        json={"agent_id": agent_id, "collected_at": at.isoformat(), "processes": processes},
    )


def test_latest_snapshot_replaces_the_previous_one_and_older_ones_lose(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]
    now = datetime.now(UTC)
    assert client.get(f"/api/v1/assets/{asset_id}/processes").status_code == 404

    assert _send(client, agent_id, now, [_process(10), _process(11)]).json()["stored"] is True
    late = _send(client, agent_id, now - timedelta(minutes=1), [_process(99)])

    assert late.status_code == 201 and late.json()["stored"] is False
    body = client.get(f"/api/v1/assets/{asset_id}/processes").json()
    assert [p["pid"] for p in body["processes"]] == [10, 11]
    assert body["processes"][0]["exe"].endswith("proc10.exe")


def test_process_snapshot_marks_the_asset_seen(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    _send(client, registered_agent["payload"]["agent_id"], datetime.now(UTC), [])

    asset = client.get(f"/api/v1/assets/{registered_agent['response']['asset_id']}").json()
    assert asset["status"] == "online"


@pytest.mark.parametrize(
    "bad",
    [
        _process(1, cpu_percent=101),  # machine share, never above 100
        _process(1, exe="x" * 1025),
        _process(1, name="a\x00b"),
        {**_process(1), "pid": -1},
        _process(1, started_at="2026-01-01T00:00:00"),  # naive timestamp
        {**_process(1), "cmdline": "secret --password=x"},  # unknown field: never stored
    ],
)
def test_invalid_processes_are_rejected(
    client: TestClient, registered_agent: dict[str, Any], bad: dict[str, Any]
) -> None:
    response = _send(client, registered_agent["payload"]["agent_id"], datetime.now(UTC), [bad])

    assert response.status_code == 422


def test_snapshot_size_is_bounded(client: TestClient, registered_agent: dict[str, Any]) -> None:
    too_many = [_process(i, exe=None) for i in range(MAX_SNAPSHOT_PROCESSES + 1)]

    response = _send(client, registered_agent["payload"]["agent_id"], datetime.now(UTC), too_many)

    assert response.status_code == 422


def test_processes_require_the_agent_token(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    response = client.post(
        "/api/v1/processes",
        json={
            "agent_id": registered_agent["payload"]["agent_id"],
            "collected_at": datetime.now(UTC).isoformat(),
            "processes": [],
        },
        headers={"Authorization": "Bearer wrong"},
    )

    assert response.status_code == 401
