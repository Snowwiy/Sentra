"""Inventory change detection: services, software and local accounts."""

from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi.testclient import TestClient

from app.models.change import ChangeCategory, ChangeKind
from app.services.change_detection import MAX_CHANGES, diff_inventory


def _svc(name: str, status: str = "running", start_type: str = "automatic") -> dict[str, Any]:
    return {"name": name, "status": status, "start_type": start_type}


def _kinds(changes: list[Any]) -> list[tuple[str, str, str]]:
    return [(c.category.value, c.kind.value, c.item) for c in changes]


def test_service_changes() -> None:
    before = {"services": [_svc("Spooler"), _svc("wuauserv", "stopped", "manual"), _svc("Old")]}
    after = {
        "services": [
            _svc("Spooler", "stopped"),  # automatic service stopped: news
            _svc("wuauserv", "running", "manual"),  # manual service on demand: not news
            _svc("New"),
        ]
    }

    assert _kinds(diff_inventory(before, after)) == [
        ("service", "added", "New"),
        ("service", "removed", "Old"),
        ("service", "stopped", "Spooler"),
    ]


def test_service_states_are_ignored_while_booting_but_not_structure_changes() -> None:
    before = {"services": [_svc("Spooler", "stopped"), _svc("X", start_type="manual")]}
    after = {"services": [_svc("Spooler"), _svc("X", start_type="disabled")]}

    assert _kinds(diff_inventory(before, after, booting=True)) == [
        ("service", "start_type_changed", "X")
    ]


def test_empty_or_missing_sections_are_never_read_as_everything_changed() -> None:
    full = {"services": [_svc("A")], "software": [{"name": "App", "version": "1"}]}

    assert diff_inventory(full, {"services": [], "software": []}) == []
    assert diff_inventory({}, full) == []  # older agent without the sections


def test_software_versions() -> None:
    before = {"software": [{"name": "Python", "version": "3.12"}, {"name": "Old"}]}
    after = {
        "software": [
            {"name": "Python", "version": "3.13"},
            {"name": "python", "version": "3.13"},  # same name differently cased: one item
            {"name": "New", "version": "1.0"},
        ]
    }

    changes = diff_inventory(before, after)
    assert _kinds(changes) == [
        ("software", "added", "New"),
        ("software", "removed", "Old"),
        ("software", "version_changed", "Python"),  # first spelling seen
    ]
    assert changes[2].details == {"before": ["3.12"], "after": ["3.13"]}


def test_account_changes_need_two_known_values() -> None:
    def acc(name: str, **state: Any) -> dict[str, Any]:
        return {"name": name, "enabled": True, "is_admin": False, **state}

    before = {"accounts": [acc("ana"), acc("bob"), acc("eve", is_admin=None), acc("gone")]}
    after = {
        "accounts": [
            acc("ana", enabled=False),
            acc("bob", is_admin=True),
            acc("eve", is_admin=True),  # unknown before: no conclusion
            acc("new", is_admin=True),
        ]
    }

    assert _kinds(diff_inventory(before, after)) == [
        ("account", "added", "new"),
        ("account", "removed", "gone"),
        ("account", "disabled", "ana"),
        ("account", "admin_granted", "bob"),
    ]


def test_changes_per_snapshot_are_capped() -> None:
    before = {"software": [{"name": f"old-{i}"} for i in range(MAX_CHANGES)]}
    after = {"software": [{"name": f"new-{i}"} for i in range(MAX_CHANGES)]}

    assert len(diff_inventory(before, after)) == MAX_CHANGES


def _inventory(client: TestClient, agent_id: str, at: datetime, **sections: Any) -> None:
    response = client.post(
        "/api/v1/inventory",
        json={"agent_id": agent_id, "collected_at": at.isoformat(), **sections},
    )
    assert response.status_code == 201


def test_changes_are_stored_and_listed_newest_first(
    client: TestClient, registered_agent: dict[str, Any]
) -> None:
    agent_id = registered_agent["payload"]["agent_id"]
    asset_id = registered_agent["response"]["asset_id"]
    now = datetime.now(UTC)
    _inventory(client, agent_id, now - timedelta(minutes=30), software=[{"name": "A"}])
    _inventory(
        client, agent_id, now - timedelta(minutes=15), software=[{"name": "A"}, {"name": "B"}]
    )
    # A delayed older snapshot arrives late: it is not current and produces no change.
    _inventory(client, agent_id, now - timedelta(hours=2), software=[{"name": "Z"}])
    _inventory(client, agent_id, now, software=[{"name": "B", "version": "2"}])

    body = client.get(f"/api/v1/assets/{asset_id}/changes").json()
    # Newest snapshot first; within one snapshot, in detection order reversed.
    assert [(c["kind"], c["item"]) for c in body["items"]] == [
        ("version_changed", "B"),
        ("removed", "A"),
        ("added", "B"),
    ]
    assert body["has_more"] is False
    page = client.get(f"/api/v1/assets/{asset_id}/changes", params={"limit": 1}).json()
    assert len(page["items"]) == 1 and page["has_more"] is True
    services = client.get(
        f"/api/v1/assets/{asset_id}/changes", params={"category": ChangeCategory.SERVICE.value}
    ).json()
    assert services["items"] == []
    assert ChangeKind.ADDED.value == "added"
