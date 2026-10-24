"""Fase 6E.3: tracker de procesos y conexiones con psutil simulado (sin procesos reales)."""

from collections.abc import Iterable
from pathlib import Path
from typing import Any

import psutil

from sentra_agent.activity import ACTIVE, PERMISSION_DENIED, create_time_ms, instance_key
from sentra_agent.tracker import (
    MAX_NETWORK_EVENTS,
    ActivityTracker,
    Connection,
    HashCache,
    ProcBasic,
    ProcDetails,
)

BOOT = "boot-test"


class FakeSource:
    def __init__(self) -> None:
        self.procs: dict[int, ProcBasic] = {}
        self.conns: list[Connection] = []
        self.details_calls: list[int] = []
        self.deny_connections = False

    def add(self, pid: int, ppid: int | None, created: float, name: str = "p") -> None:
        self.procs[pid] = ProcBasic(pid, ppid, name, created)

    def processes(self) -> Iterable[ProcBasic]:
        return list(self.procs.values())

    def details(self, pid: int) -> ProcDetails | None:
        self.details_calls.append(pid)
        return ProcDetails(exe=f"/usr/bin/p{pid}", cmdline=["p", "--token", "zz"], username="u")

    def connections(self) -> list[Connection]:
        if self.deny_connections:
            raise psutil.AccessDenied()
        return list(self.conns)


def key(pid: int, created: float) -> str:
    return instance_key(BOOT, pid, create_time_ms(created))


def tracker(source: FakeSource, now: list[float], **kwargs: Any) -> ActivityTracker:
    clock = iter(range(10_000))
    return ActivityTracker(
        BOOT, source, wall=lambda: now[0], perf=lambda: float(next(clock)), **kwargs
    )


def by_action(events: list[dict[str, Any]], action: str) -> list[dict[str, Any]]:
    return [e for e in events if e["action"] == action]


def test_first_pass_emits_preexisting_with_parent_relations() -> None:
    source = FakeSource()
    source.add(1, 0, 100.0, "init")
    source.add(50, 1, 200.0, "sshd")
    source.add(60, 999, 300.0, "orphan")  # padre ya no existe
    source.add(70, 80, 400.0, "child")  # su "padre" 80 arrancó después: PID reutilizado
    source.add(80, 1, 500.0, "newer")
    now = [1000.0]
    t = tracker(source, now)

    events = t.poll()

    starts = {e["data"]["pid"]: e for e in by_action(events, "start")}
    assert set(starts) == {1, 50, 60, 70, 80}
    assert all(e["data"]["preexisting"] is True for e in starts.values())
    assert starts[50]["data"]["parent_relation"] == "observed"
    assert starts[50]["data"]["parent_instance_key"] == key(1, 100.0)
    assert starts[60]["data"]["parent_relation"] == "missing"
    assert starts[60]["data"]["parent_instance_key"] is None
    assert starts[70]["data"]["parent_relation"] == "pid_reused"
    assert starts[70]["data"]["parent_instance_key"] is None
    assert starts[1]["data"]["parent_relation"] == "missing"
    assert starts[50]["instance_key"] == key(50, 200.0)
    # Padres antes que hijos (orden de create_time).
    assert [e["data"]["pid"] for e in by_action(events, "start")] == [1, 50, 60, 70, 80]
    # La política por defecto redacta la línea de comandos.
    assert "zz" not in (starts[50]["data"]["cmdline"] or "")


def test_start_stop_and_details_only_for_new_processes() -> None:
    source = FakeSource()
    source.add(1, 0, 100.0)
    now = [1000.0]
    t = tracker(source, now)
    t.poll()
    source.details_calls.clear()

    assert t.poll() == []  # nada cambió: ninguna lectura cara
    assert source.details_calls == []

    source.add(10, 1, 1003.5, "bash")
    now[0] = 1005.0
    events = t.poll()
    [start] = events
    assert "preexisting" not in start["data"]
    assert start["occurred_at"].startswith("1970-01-01T00:16:43.5")  # create_time real
    assert source.details_calls == [10]

    del source.procs[10]
    now[0] = 1010.0
    [stop] = t.poll()
    assert stop["action"] == "stop" and stop["instance_key"] == key(10, 1003.5)
    assert stop["data"]["pid"] == 10


def test_reused_pid_is_a_stop_and_a_new_start() -> None:
    source = FakeSource()
    source.add(1, 0, 100.0)
    source.add(42, 1, 200.0, "old")
    now = [1000.0]
    t = tracker(source, now)
    t.poll()

    source.add(42, 1, 900.0, "new")  # mismo PID, otro proceso
    events = t.poll()

    [stop] = by_action(events, "stop")
    [start] = by_action(events, "start")
    assert stop["instance_key"] == key(42, 200.0)
    assert start["instance_key"] == key(42, 900.0)
    assert stop["instance_key"] != start["instance_key"]
    assert t.key_for(42) == key(42, 900.0)


def test_sysmon_reported_start_is_not_repeated() -> None:
    source = FakeSource()
    now = [1000.0]
    t = tracker(source, now)
    t.poll()
    t.mark_reported(key(77, 999.0))
    source.add(77, None, 999.0)
    assert t.poll() == []


def test_network_events_dedupe_and_direction() -> None:
    source = FakeSource()
    source.add(5, 1, 100.0, "nginx")
    source.add(6, 1, 100.0, "curl")
    source.conns = [
        Connection(5, "tcp", "0.0.0.0", 443, None, None, "listen"),  # noqa: S104
        Connection(5, "tcp", "10.0.0.5", 443, "198.51.100.7", 50000, "established"),
        Connection(6, "tcp", "10.0.0.5", 40000, "203.0.113.9", 443, "established"),
        Connection(6, "tcp", "10.0.0.5", 40001, "203.0.113.9", 443, "established"),  # repetida
        Connection(None, "tcp", "10.0.0.5", 22, "192.0.2.1", 5000, "established"),  # sin dueño
        Connection(6, "tcp", "10.0.0.5", 40002, "203.0.113.10", 80, "time_wait"),  # transitoria
        Connection(6, "udp", "0.0.0.0", 5353, None, None, None),  # noqa: S104
    ]
    now = [1000.0]
    t = tracker(source, now)
    events = [e for e in t.poll() if e["category"] == "network"]

    summary = sorted(
        (e["action"], e["data"]["pid"], e["data"]["direction"], e["data"]["remote_address"])
        for e in events
    )
    assert summary == [
        ("connect", 5, "inbound", "198.51.100.7"),
        ("connect", 6, "outbound", "203.0.113.9"),
        ("listen", 5, "listen", None),
        ("listen", 6, "listen", None),
    ]
    assert all(e["instance_key"] in (key(5, 100.0), key(6, 100.0)) for e in events)
    # La siguiente pasada no repite nada.
    assert [e for e in t.poll() if e["category"] == "network"] == []


def test_network_events_are_bounded_per_pass() -> None:
    source = FakeSource()
    source.add(6, 1, 100.0)
    source.conns = [
        Connection(
            6, "tcp", "10.0.0.5", 1000 + i, f"203.0.{i // 250}.{i % 250}", 443, "established"
        )
        for i in range(MAX_NETWORK_EVENTS + 50)
    ]
    t = tracker(source, [1000.0])
    assert len([e for e in t.poll() if e["category"] == "network"]) == MAX_NETWORK_EVENTS
    assert len([e for e in t.poll() if e["category"] == "network"]) == 50


def test_access_denied_on_connections_is_reported_once() -> None:
    source = FakeSource()
    source.deny_connections = True
    t = tracker(source, [1000.0])
    t.poll()
    assert t.stats.network_status == PERMISSION_DENIED
    assert t.stats.process_status == ACTIVE
    assert t.network is False  # no se insiste en cada pasada


def test_tracker_measures_its_own_cost() -> None:
    source = FakeSource()
    for pid in range(1, 2001):
        source.add(pid, pid - 1 if pid > 1 else None, float(pid))
    t = tracker(source, [5000.0])
    t.poll()
    assert t.stats.passes == 1 and t.stats.processes == 2000
    assert t.stats.last_pass_ms == 1000.0  # reloj falso: una unidad por llamada
    # Segunda pasada sin cambios: ninguna lectura de detalles (coste lineal, no cuadrático).
    source.details_calls.clear()
    assert t.poll() == [] and source.details_calls == []


def test_hash_cache_reads_each_file_once(tmp_path: Path) -> None:
    exe = tmp_path / "tool"
    exe.write_bytes(b"binary")
    calls: list[str] = []

    def hasher(path: str, limit: int) -> str:
        calls.append(path)
        return "ab" * 32

    cache = HashCache(1024, hasher)
    assert cache.get(str(exe)) == "ab" * 32
    assert cache.get(str(exe)) == "ab" * 32
    assert calls == [str(exe)]
    big = tmp_path / "big"
    big.write_bytes(b"x" * 2048)
    assert cache.get(str(big)) is None  # por encima del tope no se lee
    assert cache.get(None) is None
