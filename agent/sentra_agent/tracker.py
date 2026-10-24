"""Tracker de actividad de procesos y conexiones (Fase 6E.3).

Cada `process_poll_seconds` compara la lista de procesos con la anterior y genera eventos
`process/start` y `process/stop`; con la red activada, también `network/connect` y
`network/listen` nuevos por proceso. Es sondeo, no un hook del núcleo: un proceso que nace y
muere entre dos pasadas no se ve (latencia honesta, documentada).

Coste acotado a propósito:
- cada pasada es O(n) en procesos: diccionarios por PID, nunca comparaciones todos contra
  todos;
- los atributos caros (ruta, línea de comandos, usuario) solo se leen de los procesos NUEVOS;
- las conexiones se deduplican con un LRU de tamaño fijo y cada pasada emite como mucho
  `MAX_NETWORK_EVENTS`;
- el tracker mide su propio coste (duración de la última pasada) para el diagnóstico.

Todo lo que toca el sistema pasa por `ProcessSource`, sustituible en los tests.
"""

import logging
import os
import socket
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Protocol

import psutil

from sentra_agent.activity import (
    ACTIVE,
    DISABLED,
    ERROR,
    PERMISSION_DENIED,
    clip,
    create_time_ms,
    file_sha256,
    instance_key,
    iso,
    make_event,
    redact_cmdline,
)

logger = logging.getLogger("sentra_agent")

MAX_NETWORK_EVENTS = 500
NETWORK_DEDUPE = 8192
HASH_CACHE = 2048


@dataclass(frozen=True)
class ProcBasic:
    """Lo barato de leer de cada proceso en cada pasada."""

    pid: int
    ppid: int | None
    name: str | None
    create_time: float


@dataclass(frozen=True)
class ProcDetails:
    """Lo caro: solo se lee una vez, cuando el proceso aparece."""

    exe: str | None = None
    cmdline: list[str] | None = None
    username: str | None = None


@dataclass(frozen=True)
class Connection:
    pid: int | None
    protocol: str  # tcp | udp
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None
    state: str | None  # listen, established, syn_sent... (None en UDP)


class ProcessSource(Protocol):
    def processes(self) -> Iterable[ProcBasic]: ...

    def details(self, pid: int) -> ProcDetails | None: ...

    def connections(self) -> list[Connection]: ...


class PsutilSource:
    """Fuente real: psutil, de solo lectura y sin privilegios."""

    def processes(self) -> Iterable[ProcBasic]:
        for proc in psutil.process_iter(["pid", "ppid", "name", "create_time"], ad_value=None):
            info = proc.info
            created = info.get("create_time")
            if created is None:
                continue  # sin create_time no hay instance_key fiable
            yield ProcBasic(
                pid=int(info["pid"]),
                ppid=info.get("ppid"),
                name=info.get("name"),
                create_time=float(created),
            )

    def details(self, pid: int) -> ProcDetails | None:
        try:
            proc = psutil.Process(pid)
            info = proc.as_dict(["exe", "cmdline", "username"], ad_value=None)
        except (psutil.Error, OSError):
            return None
        cmdline = info.get("cmdline")
        return ProcDetails(
            exe=info.get("exe") or None,
            cmdline=list(cmdline) if cmdline else None,
            username=info.get("username"),
        )

    def connections(self) -> list[Connection]:
        found = []
        for conn in psutil.net_connections(kind="inet"):
            local, remote = conn.laddr, conn.raddr
            is_tcp = conn.type == socket.SOCK_STREAM
            found.append(
                Connection(
                    pid=conn.pid or None,
                    protocol="tcp" if is_tcp else "udp",
                    local_address=local.ip.split("%", 1)[0] if local else None,
                    local_port=local.port if local else None,
                    remote_address=remote.ip.split("%", 1)[0] if remote else None,
                    remote_port=remote.port if remote else None,
                    state=conn.status.lower() if is_tcp and conn.status else None,
                )
            )
        return found


@dataclass
class _Live:
    pid: int
    create_ms: int
    key: str
    name: str | None


@dataclass
class TrackerStats:
    passes: int = 0
    last_pass_ms: float = 0.0
    max_pass_ms: float = 0.0
    processes: int = 0
    last_events: int = 0
    network_status: str = ACTIVE
    process_status: str = ACTIVE
    extra: dict[str, Any] = field(default_factory=dict)


class HashCache:
    """SHA-256 de ejecutables con caché por (ruta, mtime, tamaño) y tope de tamaño."""

    def __init__(self, max_bytes: int, hasher: Callable[[str, int], str | None] = file_sha256):
        self._max = max_bytes
        self._hasher = hasher
        self._cache: OrderedDict[tuple[str, int, int], str | None] = OrderedDict()

    def get(self, path: str | None) -> str | None:
        if not path:
            return None
        try:
            stat = os.stat(path)
        except OSError:
            return None
        if stat.st_size > self._max:
            return None
        key = (path, stat.st_mtime_ns, stat.st_size)
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        digest = self._hasher(path, self._max)
        self._cache[key] = digest
        while len(self._cache) > HASH_CACHE:
            self._cache.popitem(last=False)
        return digest


class ActivityTracker:
    def __init__(
        self,
        boot_id: str,
        source: ProcessSource | None = None,
        cmdline_policy: str = "redacted",
        network: bool = True,
        hashes: HashCache | None = None,
        wall: Callable[[], float] = time.time,
        perf: Callable[[], float] = time.perf_counter,
    ) -> None:
        self.boot_id = boot_id
        self.source: ProcessSource = source or PsutilSource()
        self.cmdline_policy = cmdline_policy
        self.network = network
        self.hashes = hashes
        self._wall = wall
        self._perf = perf
        self._live: dict[int, _Live] = {}
        self._first = True
        self._seen_conn: OrderedDict[tuple[Any, ...], None] = OrderedDict()
        # Inicios ya informados por una fuente orientada a eventos (Sysmon): el sondeo no los
        # repite. Acotado como el resto.
        self._reported: OrderedDict[str, None] = OrderedDict()
        self.stats = TrackerStats(network_status=ACTIVE if network else DISABLED)

    def key_for(self, pid: int) -> str | None:
        live = self._live.get(pid)
        return live.key if live else None

    def mark_reported(self, key: str) -> None:
        self._reported[key] = None
        while len(self._reported) > NETWORK_DEDUPE:
            self._reported.popitem(last=False)

    def poll(self) -> list[dict[str, Any]]:
        """Una pasada completa: procesos y, si toca, conexiones. Nunca lanza."""
        started = self._perf()
        events: list[dict[str, Any]] = []
        try:
            events.extend(self._poll_processes())
            self.stats.process_status = ACTIVE
        except Exception:
            logger.exception("process tracker pass failed")
            self.stats.process_status = ERROR
        if self.network:
            try:
                events.extend(self._poll_network())
                self.stats.network_status = ACTIVE
            except psutil.AccessDenied:
                # macOS sin root o políticas que lo impiden: se informa y no se insiste.
                if self.stats.network_status != PERMISSION_DENIED:
                    logger.info("process network telemetry needs more privileges; disabled")
                self.stats.network_status = PERMISSION_DENIED
                self.network = False
            except Exception:
                logger.exception("network tracker pass failed")
                self.stats.network_status = ERROR
        elapsed = (self._perf() - started) * 1000
        self.stats.passes += 1
        self.stats.last_pass_ms = round(elapsed, 2)
        self.stats.max_pass_ms = max(self.stats.max_pass_ms, self.stats.last_pass_ms)
        self.stats.last_events = len(events)
        return events

    def _poll_processes(self) -> list[dict[str, Any]]:
        now = self._wall()
        current: dict[int, ProcBasic] = {}
        for proc in self.source.processes():
            current[proc.pid] = proc
        self.stats.processes = len(current)
        events: list[dict[str, Any]] = []
        new: list[ProcBasic] = []
        for pid, proc in current.items():
            known = self._live.get(pid)
            if known is not None and known.create_ms == create_time_ms(proc.create_time):
                continue
            if known is not None:
                # Mismo PID, otro proceso: el anterior terminó entre dos pasadas.
                events.append(self._stop_event(known, now))
            new.append(proc)
        for pid in self._live.keys() - current.keys():
            events.append(self._stop_event(self._live.pop(pid), now))
        # Padres antes que hijos: el servidor puede enlazar el árbol en orden.
        new.sort(key=lambda proc: (proc.create_time, proc.pid))
        for proc in new:
            ms = create_time_ms(proc.create_time)
            self._live[proc.pid] = _Live(
                proc.pid, ms, instance_key(self.boot_id, proc.pid, ms), proc.name
            )
        for proc in new:
            event = self._start_event(proc, current, now)
            if event is not None:
                events.append(event)
        self._first = False
        return events

    def parent_of(self, proc: ProcBasic, current: dict[int, ProcBasic]) -> tuple[str | None, str]:
        """(parent_instance_key, parent_relation) según el padre vivo en esta pasada."""
        ppid = proc.ppid
        parent = current.get(ppid) if ppid else None
        if parent is None or ppid == proc.pid:
            return None, "missing"
        if parent.create_time <= proc.create_time:
            parent_ms = create_time_ms(parent.create_time)
            return instance_key(self.boot_id, parent.pid, parent_ms), "observed"
        # El padre que vemos arrancó DESPUÉS que el hijo: es otro proceso con el PID del
        # padre real (reutilizado). Nunca se enlaza con él.
        return None, "pid_reused"

    def _start_event(
        self, proc: ProcBasic, current: dict[int, ProcBasic], now: float
    ) -> dict[str, Any] | None:
        live = self._live[proc.pid]
        if live.key in self._reported:
            return None
        parent_key, relation = self.parent_of(proc, current)
        details = self.source.details(proc.pid) or ProcDetails()
        data: dict[str, Any] = {
            "pid": proc.pid,
            "ppid": proc.ppid or None,
            "parent_instance_key": parent_key,
            "parent_relation": relation,
            "name": clip(proc.name, 255),
            "exe": clip(details.exe, 1024),
            "cmdline": redact_cmdline(details.cmdline, self.cmdline_policy),
            "username": clip(details.username, 255),
            "started_at": iso(proc.create_time),
            "sha256": self.hashes.get(details.exe) if self.hashes else None,
            "signer": None,
            "integrity": None,
        }
        if self._first:
            # Ya existía al arrancar el agente: no es un inicio observado ahora.
            data["preexisting"] = True
        occurred = now if self._first else min(proc.create_time, now)
        return make_event("process", "start", "psutil_poll", data, iso(occurred), live.key)

    def _stop_event(self, live: _Live, now: float) -> dict[str, Any]:
        data = {"pid": live.pid, "name": clip(live.name, 255), "ended_at": iso(now)}
        return make_event("process", "stop", "psutil_poll", data, iso(now), live.key)

    def _poll_network(self) -> list[dict[str, Any]]:
        now = iso(self._wall())
        connections = self.source.connections()
        listening = {
            (c.pid, c.protocol, c.local_port)
            for c in connections
            if c.state == "listen" or (c.protocol == "udp" and c.remote_address is None)
        }
        events: list[dict[str, Any]] = []
        for conn in connections:
            if conn.pid is None:
                continue  # sin dueño visible (otro usuario): no aporta al árbol
            key_inst = self.key_for(conn.pid)
            is_listen = conn.state == "listen" or (
                conn.protocol == "udp" and conn.remote_address is None
            )
            if is_listen:
                dedupe: tuple[Any, ...] = (
                    key_inst or conn.pid,
                    "listen",
                    conn.local_address,
                    conn.local_port,
                    conn.protocol,
                )
                action, direction = "listen", "listen"
            elif conn.remote_address and conn.state in (None, "established", "syn_sent"):
                dedupe = (
                    key_inst or conn.pid,
                    conn.remote_address,
                    conn.remote_port,
                    conn.protocol,
                )
                action = "connect"
                inbound = (conn.pid, conn.protocol, conn.local_port) in listening
                direction = "inbound" if inbound else "outbound"
            else:
                continue
            if dedupe in self._seen_conn:
                self._seen_conn.move_to_end(dedupe)
                continue
            self._seen_conn[dedupe] = None
            while len(self._seen_conn) > NETWORK_DEDUPE:
                self._seen_conn.popitem(last=False)
            data = {
                "pid": conn.pid,
                "protocol": conn.protocol,
                "local_address": conn.local_address,
                "local_port": conn.local_port,
                "remote_address": conn.remote_address,
                "remote_port": conn.remote_port,
                "state": conn.state,
                "direction": direction,
            }
            events.append(make_event("network", action, "psutil_poll", data, now, key_inst))
            if len(events) >= MAX_NETWORK_EVENTS:
                break
        return events
