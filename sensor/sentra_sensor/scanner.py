"""Scanner básico de descubrimiento (TCP connect, ICMP opcional, ARP, DNS inverso opcional).

Diseño de seguridad:
* Solo sondea direcciones de un target YA validado (jobs.validate_job).
* TCP connect con asyncio: no necesita privilegios ni sockets raw.
* ICMP/ARP del sistema, si se usan, se lanzan con argv FIJO construido aquí con la IP
  normalizada por `ipaddress` (una IP nunca empieza por '-', así que no puede inyectar
  opciones), sin shell, con ruta resuelta al arrancar y con interruptor para desactivarlos.
* Concurrencia, sondas/segundo, timeout y deadline acotados por el job (y el job, por el
  servidor), para no saturar la red del site.

Los probers son inyectables: los tests no tocan la red real.
"""

import asyncio
import concurrent.futures
import contextlib
import errno
import ipaddress
import logging
import math
import re
import shutil
import socket
import subprocess
import sys
import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from sentra_sensor.jobs import DiscoveryParameters

logger = logging.getLogger("sentra_sensor.scanner")

PORT_OPEN = "open"
PORT_CLOSED = "closed"
PORT_FILTERED = "filtered"
# Hosts por tanda: tras cada tanda se lee la tabla ARP y se emiten observaciones, así los
# resultados van llegando al servidor durante scans largos y la memoria queda acotada.
HOST_CHUNK = 64
MAX_ERRORS = 50
MAX_UNPROBED = 4096
_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
# Errores que significan "no hay nadie ahí" (sin respuesta ARP, sin ruta): no son fallos de
# la sonda, son un resultado negativo válido.
_UNREACHABLE = {errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}


class ProbeError(Exception):
    """La sonda no pudo ejecutarse (no es "sin respuesta"): la dirección queda unprobed."""


class TcpProber(Protocol):
    async def probe(self, address: str, port: int, timeout: float) -> str: ...


class IcmpProber(Protocol):
    async def ping(self, address: str, timeout: float) -> bool: ...


class NeighborReader(Protocol):
    def read(self) -> dict[str, str]: ...


class ReverseResolver(Protocol):
    async def resolve(self, address: str, timeout: float) -> str | None: ...


# --- implementaciones reales -------------------------------------------------------------


class AsyncioTcpProber:
    async def probe(self, address: str, port: int, timeout: float) -> str:
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout
            )
        except TimeoutError:
            return PORT_FILTERED
        except ConnectionRefusedError:
            return PORT_CLOSED
        except OSError as exc:
            if exc.errno in _UNREACHABLE:
                return PORT_FILTERED
            raise ProbeError(f"tcp {port}: {exc.strerror or exc}") from exc
        writer.close()
        with contextlib.suppress(TimeoutError, OSError):
            await asyncio.wait_for(writer.wait_closed(), 1.0)
        return PORT_OPEN


def ping_argv(executable: str, address: str, timeout: float, platform: str) -> list[str]:
    """argv fijo para un único ping. `address` se re-normaliza aquí por defensa en profundidad."""
    ip = ipaddress.ip_address(address)
    if platform == "win32":
        argv = [executable, "-n", "1", "-w", str(max(1, int(timeout * 1000)))]
    else:
        argv = [executable, "-n", "-q", "-c", "1", "-W", str(max(1, math.ceil(timeout)))]
    if ip.version == 6:
        argv.append("-6")
    argv.append(str(ip))
    return argv


class SystemPingProber:
    """ICMP con el `ping` del sistema (evita necesitar sockets raw/CAP_NET_RAW en Python)."""

    def __init__(self, executable: str, platform: str = sys.platform) -> None:
        self._executable = executable
        self._platform = platform

    @classmethod
    def discover(cls) -> "SystemPingProber | None":
        path = shutil.which("ping")
        return cls(path) if path else None

    async def ping(self, address: str, timeout: float) -> bool:
        argv = ping_argv(self._executable, address, timeout, self._platform)
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            code = await asyncio.wait_for(process.wait(), timeout + 2)
        except TimeoutError:
            process.kill()
            await process.wait()
            return False
        if code == 0:
            return True
        if code == 1:
            return False  # sin respuesta
        raise ProbeError(f"ping exited with {code}")


def normalize_mac(value: str) -> str | None:
    value = value.strip().lower().replace("-", ":")
    if not _MAC.match(value) or value in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return value


class ProcNetArpReader:
    """Tabla de vecinos IPv4 del kernel Linux, leída de /proc/net/arp (sin ejecutar nada)."""

    def __init__(self, path: Path = Path("/proc/net/arp")) -> None:
        self._path = path

    def read(self) -> dict[str, str]:
        try:
            lines = self._path.read_text(encoding="ascii", errors="replace").splitlines()
        except OSError:
            return {}
        return parse_proc_net_arp(lines)


def parse_proc_net_arp(lines: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in list(lines)[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip, flags, mac = parts[0], parts[2], parts[3]
        if flags == "0x0":  # entrada incompleta: nadie respondió
            continue
        normalized = normalize_mac(mac)
        if normalized is not None:
            try:
                result[str(ipaddress.ip_address(ip))] = normalized
            except ValueError:
                continue
    return result


class WindowsArpReader:
    """`arp -a` con argv fijo y sin shell (Windows no expone la tabla en un fichero)."""

    def __init__(self, executable: str) -> None:
        self._executable = executable

    @classmethod
    def discover(cls) -> "WindowsArpReader | None":
        path = shutil.which("arp")
        return cls(path) if path else None

    def read(self) -> dict[str, str]:
        try:
            completed = subprocess.run(  # noqa: S603  (argv fijo, sin shell)
                [self._executable, "-a"],
                capture_output=True,
                timeout=10,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError):
            return {}
        return parse_arp_a(completed.stdout.decode("ascii", errors="replace").splitlines())


def parse_arp_a(lines: Iterable[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in lines:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ip = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            continue
        mac = normalize_mac(parts[1])
        if mac is not None:
            result[ip] = mac
    return result


class SystemReverseResolver:
    """DNS inverso con un pool propio para que una resolución colgada no bloquee el cierre."""

    def __init__(self) -> None:
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="sensor-rdns"
        )

    async def resolve(self, address: str, timeout: float) -> str | None:
        loop = asyncio.get_running_loop()
        try:
            name, _aliases, _addrs = await asyncio.wait_for(
                loop.run_in_executor(self._pool, socket.gethostbyaddr, address), timeout
            )
        except (TimeoutError, OSError, UnicodeError):
            return None
        return name[:253] if name else None

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


# --- scanner -----------------------------------------------------------------------------


@dataclass
class Observation:
    address: str
    ports: dict[int, str] = field(default_factory=dict)
    sources: set[str] = field(default_factory=set)
    mac: str | None = None
    reverse_dns: str | None = None
    observed_at: str = ""

    def to_json(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "address": self.address,
            "ports": [{"port": p, "state": s} for p, s in sorted(self.ports.items())],
            "sources": sorted(self.sources),
            "observed_at": self.observed_at,
        }
        if self.mac:
            body["mac"] = self.mac
        if self.reverse_dns:
            body["reverse_dns"] = self.reverse_dns
        return body


@dataclass
class ScanReport:
    hosts_scanned: int
    hosts_checked: int
    probes: int
    unprobed: list[str]
    errors: list[str]
    cancelled: bool
    timed_out: bool
    alive: int


class RateLimiter:
    """Espacia las sondas para no superar `rate` por segundo (sin ráfagas)."""

    def __init__(self, rate: int) -> None:
        self._interval = 1.0 / rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            now = loop.time()
            wait = self._next - now
            self._next = max(now, self._next) + self._interval
        if wait > 0:
            await asyncio.sleep(wait)


class Scanner:
    def __init__(
        self,
        params: DiscoveryParameters,
        emit: Callable[[list[Observation]], None],
        tcp: TcpProber | None = None,
        icmp: IcmpProber | None = None,
        neighbors: NeighborReader | None = None,
        resolver: ReverseResolver | None = None,
    ) -> None:
        self._params = params
        self._emit = emit
        self._tcp: TcpProber = tcp or AsyncioTcpProber()
        # Los métodos que el job pide pero no están disponibles en este host se omiten y se
        # informan como error (no se finge haberlos usado).
        self._icmp = icmp if params.icmp else None
        self._neighbors = neighbors if params.arp else None
        self._resolver = resolver if params.reverse_dns else None
        self._errors: list[str] = []
        self._failed: set[str] = set()
        self._probes = 0
        self._checked = 0
        self._alive = 0
        self._cancel_requested = threading.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task[None] | None = None
        self._lock = threading.Lock()
        if params.icmp and icmp is None:
            self._error("icmp requested but not available on this sensor")
        if params.arp and neighbors is None:
            self._error("arp requested but not available on this sensor")
        if params.reverse_dns and resolver is None:
            self._error("reverse_dns requested but not available on this sensor")

    def _error(self, message: str) -> None:
        if len(self._errors) < MAX_ERRORS:
            self._errors.append(message[:200])

    def request_cancel(self) -> None:
        """Seguro desde otro hilo: interrumpe el scan en curso sin esperar a la tanda."""
        self._cancel_requested.set()
        with self._lock:
            loop, task = self._loop, self._task
        if loop is not None and task is not None:
            loop.call_soon_threadsafe(task.cancel)

    @property
    def cancel_requested(self) -> bool:
        return self._cancel_requested.is_set()

    def run(self) -> ScanReport:
        return asyncio.run(self.scan())

    async def scan(self) -> ScanReport:
        hosts = [str(h) for h in self._params.target.hosts()]
        timed_out = False
        task = asyncio.current_task()
        assert task is not None  # noqa: S101  (siempre dentro de un event loop)
        with self._lock:
            self._loop, self._task = asyncio.get_running_loop(), task
        if self._cancel_requested.is_set():
            return self._report(len(hosts), timed_out=False)
        self._semaphore = asyncio.Semaphore(self._params.concurrency)
        self._rate = RateLimiter(self._params.max_probes_per_second)
        pending: dict[str, Observation] = {}
        try:
            async with asyncio.timeout(self._params.deadline_seconds):
                for start in range(0, len(hosts), HOST_CHUNK):
                    chunk = hosts[start : start + HOST_CHUNK]
                    await asyncio.gather(*(self._probe_host(h, pending) for h in chunk))
                    await self._finish_chunk(pending)
        except TimeoutError:
            timed_out = True
        except asyncio.CancelledError:
            if not self._cancel_requested.is_set():
                raise
            task.uncancel()
        finally:
            with self._lock:
                self._loop, self._task = None, None
        # Cancelado o fuera de tiempo: se entrega lo que ya estaba observado.
        if pending:
            await self._finish_chunk(pending, allow_slow=False)
        return self._report(len(hosts), timed_out)

    def _report(self, total: int, timed_out: bool) -> ScanReport:
        unprobed = sorted(self._failed, key=ipaddress.ip_address)[:MAX_UNPROBED]
        return ScanReport(
            hosts_scanned=total,
            hosts_checked=self._checked,
            probes=self._probes,
            unprobed=unprobed,
            errors=list(self._errors),
            cancelled=self._cancel_requested.is_set(),
            timed_out=timed_out and not self._cancel_requested.is_set(),
            alive=self._alive,
        )

    async def _limited(self, coro_factory: Callable[[], Any]) -> Any:
        async with self._semaphore:
            await self._rate.acquire()
            self._probes += 1
            return await coro_factory()

    async def _probe_host(self, address: str, pending: dict[str, Observation]) -> None:
        timeout = self._params.timeout_ms / 1000
        observation = Observation(address)
        failed = False
        if self._icmp is not None:
            icmp = self._icmp
            try:
                if await self._limited(lambda: icmp.ping(address, timeout)):
                    observation.sources.add("icmp")
            except ProbeError as exc:
                failed = True
                self._error(f"{address}: {exc}")

        async def port_probe(port: int) -> None:
            nonlocal failed
            try:
                state = await self._limited(lambda: self._tcp.probe(address, port, timeout))
            except ProbeError as exc:
                failed = True
                self._error(f"{address}: {exc}")
                return
            observation.ports[port] = state
            # Un RST (closed) también prueba que hay un host vivo en esa dirección.
            if state in (PORT_OPEN, PORT_CLOSED):
                observation.sources.add("tcp")

        await asyncio.gather(*(port_probe(p) for p in self._params.ports))
        observation.observed_at = datetime.now(UTC).isoformat()
        self._checked += 1
        pending[address] = observation
        if failed:
            self._failed.add(address)

    async def _finish_chunk(self, pending: dict[str, Observation], allow_slow: bool = True) -> None:
        if self._neighbors is not None:
            table = self._neighbors.read()
            for address, observation in pending.items():
                mac = table.get(address)
                if mac:
                    observation.mac = mac
                    observation.sources.add("arp")
        alive = [o for o in pending.values() if o.sources]
        if self._resolver is not None and allow_slow and alive:
            resolver = self._resolver
            timeout = min(2.0, self._params.timeout_ms / 1000 + 1)
            names = await asyncio.gather(*(resolver.resolve(o.address, timeout) for o in alive))
            for observation, name in zip(alive, names, strict=True):
                observation.reverse_dns = name
        for observation in alive:
            # Un host que respondió no es "unprobed" aunque alguna sonda suelta fallase.
            self._failed.discard(observation.address)
        self._alive += len(alive)
        pending.clear()
        if alive:
            self._emit(alive)


def default_probers(
    allow_system_ping: bool, allow_system_arp: bool, platform: str = sys.platform
) -> tuple[IcmpProber | None, NeighborReader | None, ReverseResolver]:
    icmp: IcmpProber | None = SystemPingProber.discover() if allow_system_ping else None
    neighbors: NeighborReader | None = None
    if platform.startswith("linux"):
        neighbors = ProcNetArpReader()
    elif platform == "win32" and allow_system_arp:
        neighbors = WindowsArpReader.discover()
    return icmp, neighbors, SystemReverseResolver()
