"""Fase 6E.3: los eventos del agente pasan la validación por evento del servidor.

El servidor valida cada evento por separado: una `source` o una acción fuera del catálogo, o
un campo conocido con un tipo incorrecto, lo rechaza; las claves desconocidas de `data` se
descartan. Si el repositorio incluye el backend, se carga su módulo de esquema (puro, sin
dependencias) por ruta y se comprueba contra eventos generados por el propio agente. En un
checkout solo del agente el test se omite.
"""

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from sentra_agent import endpoint
from sentra_agent.activity import CATEGORIES, SOURCES, make_event
from sentra_agent.sysmon import parse_sysmon
from sentra_agent.tracker import ActivityTracker, Connection
from tests.test_pollers import SCHTASKS
from tests.test_sysmon import sysmon_event
from tests.test_tracker import FakeSource

SCHEMA = Path(__file__).resolve().parents[2] / "backend" / "app" / "endpoint" / "schema.py"
WHEN = "2026-10-22T10:00:00+00:00"
# Claves que el agente envía a propósito aunque el servidor actual las descarte.
INFORMATIVE = {("process", "preexisting")}


@pytest.fixture(scope="module")
def server() -> ModuleType:
    if not SCHEMA.is_file():
        pytest.skip("backend no presente en este checkout")
    spec = importlib.util.spec_from_file_location("sentra_server_activity_schema", SCHEMA)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def agent_events(tmp_path: Path) -> list[dict[str, Any]]:
    source = FakeSource()
    source.add(1, 0, 100.0, "init")
    source.add(50, 1, 200.0, "sshd")
    source.conns = [
        Connection(50, "tcp", "0.0.0.0", 22, None, None, "listen"),  # noqa: S104
        Connection(50, "tcp", "10.0.0.5", 22, "198.51.100.7", 50000, "established"),
        Connection(50, "udp", "fe80::1%eth0", 546, None, None, None),
    ]
    tracker = ActivityTracker("boot", source)
    events = tracker.poll()
    del source.procs[50]
    events += tracker.poll()
    sysmon, _ = parse_sysmon(sysmon_event(1, 42), "boot", "redacted", lambda pid: "a" * 32)
    events += sysmon

    def add(category: str, action: str, src: str, records: dict[str, dict[str, Any]]) -> None:
        for record in records.values():
            events.append(make_event(category, action, src, endpoint.public(record), WHEN))

    add("scheduled_task", "created", "task_poll", endpoint.parse_schtasks_csv(SCHTASKS))
    add("scheduled_task", "deleted", "task_poll",
        endpoint.parse_timer_unit_files("a.timer enabled enabled\n"))  # fmt: skip
    defender = '{"realtime":true,"antivirus":true,"tamper":null,"age":3}'
    add("protection", "state", "protection_poll", endpoint.parse_defender(defender))
    add("firewall", "state", "firewall_poll", endpoint.parse_firewall_profiles(
        '[{"name":"Public","enabled":"True","inbound":"Block","outbound":"Allow"}]'))  # fmt: skip
    add("firewall", "state", "firewall_poll",
        endpoint.parse_socketfilterfw("Firewall is enabled. (State = 1)"))  # fmt: skip
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "cron.d" / "job").write_text("x")
    (tmp_path / "Library" / "LaunchAgents").mkdir(parents=True)
    (tmp_path / "Library" / "LaunchAgents" / "a.plist").write_text("x")
    for platform in ("linux", "darwin"):
        add("persistence", "created", "persistence_poll",
            endpoint.read_persistence(platform, root=str(tmp_path)))  # fmt: skip
    events.append(make_event("agent_health", "state", "agent",
                             {"cpu_percent": 0.4, "rss_bytes": 1, "queued": 0,
                              "dropped_total": 0}, WHEN))  # fmt: skip
    return events


def test_catalogs_match_the_server(server: ModuleType) -> None:
    assert set(SOURCES) == set(server.SOURCES)
    assert set(CATEGORIES) == set(server.FIELDS)


def test_every_event_passes_server_validation(server: ModuleType, tmp_path: Path) -> None:
    events = agent_events(tmp_path)
    assert {e["category"] for e in events} >= {
        "process", "network", "scheduled_task", "protection", "firewall", "persistence",
        "agent_health",
    }  # fmt: skip
    for event in events:
        assert event["source"] in server.SOURCES
        assert event["action"] in server.ACTIONS[event["category"]], event
        cleaned = server.clean_data(event["category"], event["data"])  # sin InvalidFieldError
        lost = {
            key for key, value in event["data"].items() if value is not None and key not in cleaned
        }
        assert {(event["category"], key) for key in lost} <= INFORMATIVE, event


def test_queued_events_have_exactly_the_contract_envelope(tmp_path: Path) -> None:
    """El servidor rechaza un evento con claves de más o de menos (extra="forbid")."""
    from datetime import datetime

    from sentra_agent.activity import ActivityQueue

    queue = ActivityQueue(1000, tmp_path / "queue")
    queue.extend(agent_events(tmp_path))
    keys = {"event_uid", "seq", "category", "action", "occurred_at", "source", "instance_key",
            "data"}  # fmt: skip
    for event in queue.peek(1000):
        assert set(event) == keys
        assert datetime.fromisoformat(event["occurred_at"]).tzinfo is not None
        assert 1 <= len(event["action"]) <= 24 and 1 <= len(event["source"]) <= 24
        assert event["instance_key"] is None or len(event["instance_key"]) == 32
