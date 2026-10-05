"""Bounded, rate-limited and cancellable scan of a list of addresses.

Three phases, so dead addresses cost little:
1. liveness: one ping (when available) and a TCP connect to a few likely ports per address;
   a reply, an accepted connection or a refusal (RST) proves the host is up;
2. the server's neighbour (ARP) table is read once: entries complete after phase 1 mark
   hosts that answered nothing else as up and give their MAC;
3. the remaining configured ports and reverse DNS, for live hosts only.

Load is bounded three ways: at most `concurrency` probes in flight, at most `max_rate`
probes started per second, and a `timeout` per probe. A whole scan also stops at its
`deadline` or when `cancel` is set; the result then says it is partial, and the caller must
not draw negative conclusions from it (a port not probed is not a closed port).
"""

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable, Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Protocol

from app.discovery import probes
from app.discovery.ports import liveness_ports
from app.discovery.probes import PortState
from app.discovery.targets import IPAddress

logger = logging.getLogger(__name__)

# Addresses handled together: bounds the number of pending tasks for large networks.
HOST_BATCH = 256
MAX_ERRORS = 50


@dataclass(frozen=True)
class ScanConfig:
    ports: tuple[int, ...]
    timeout: float = 0.8
    concurrency: int = 64
    max_rate: float = 200.0
    icmp: bool = True
    reverse_dns: bool = True
    # Seconds for the whole scan (None: no limit).
    deadline: float | None = None


@dataclass
class HostObservation:
    address: str
    alive: bool = False
    # How the host was seen: "icmp", "tcp", "arp".
    sources: set[str] = field(default_factory=set)
    mac: str | None = None
    reverse_dns: str | None = None
    # State of every port that was probed.
    ports: dict[int, PortState] = field(default_factory=dict)

    @property
    def open_ports(self) -> list[int]:
        return sorted(p for p, state in self.ports.items() if state == PortState.OPEN)


@dataclass
class ScanResult:
    hosts_scanned: int
    observations: list[HostObservation]
    errors: list[str]
    probes: int = 0
    cancelled: bool = False
    timed_out: bool = False
    # Direcciones cuya fase de liveness terminó. Igual a hosts_scanned en un scan completo;
    # menor en uno cancelado, y es lo que se informa como "hosts evaluados".
    hosts_checked: int | None = None

    @property
    def complete(self) -> bool:
        return not (self.cancelled or self.timed_out)


@dataclass(frozen=True)
class ScanProgress:
    """Contadores reales del scan en curso, leídos desde otro hilo para informar progreso.

    Solo la fase "liveness" tiene un total exacto conocido de antemano (todas las
    direcciones); la fase "details" solo afecta a los hosts vivos, que no se conocen hasta
    terminar la primera. Por eso la UI no debe inventar un porcentaje global.
    """

    phase: str
    hosts_total: int
    hosts_checked: int
    hosts_alive: int
    details_total: int
    details_done: int
    errors: int
    probes: int


class CancelSignal(Protocol):
    """Cualquier objeto con is_set(): threading.Event o una combinación de varios."""

    def is_set(self) -> bool: ...


class Prober(Protocol):
    async def tcp(self, address: IPAddress, port: int, timeout: float) -> PortState: ...

    async def ping(self, address: IPAddress, timeout_ms: int) -> bool | None: ...

    def neighbours(self) -> dict[str, str]: ...

    async def reverse_dns(self, address: IPAddress, timeout: float) -> str | None: ...


class SystemProber:
    """The real probes of this host's operating system (see probes.py)."""

    def __init__(self) -> None:
        self._ping = probes.ping_executable()
        # gethostbyaddr blocks: a small dedicated pool bounds concurrent lookups.
        self._executor = ThreadPoolExecutor(max_workers=8, thread_name_prefix="sentra-rdns")

    @property
    def ping_available(self) -> bool:
        return self._ping is not None

    async def tcp(self, address: IPAddress, port: int, timeout: float) -> PortState:
        return await probes.tcp_probe(address, port, timeout)

    async def ping(self, address: IPAddress, timeout_ms: int) -> bool | None:
        return await probes.ping(self._ping, address, timeout_ms)

    def neighbours(self) -> dict[str, str]:
        return probes.neighbour_table()

    async def reverse_dns(self, address: IPAddress, timeout: float) -> str | None:
        return await probes.reverse_dns(self._executor, address, timeout)

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


class _StopScanError(Exception):
    pass


class RateLimiter:
    """At most `rate` acquisitions per second, evenly spaced."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            loop = asyncio.get_running_loop()
            delay = self._next - loop.time()
            if delay > 0:
                await asyncio.sleep(delay)
            self._next = max(loop.time(), self._next) + self._interval


class NetworkScanner:
    def __init__(
        self,
        config: ScanConfig,
        prober: Prober | None = None,
        cancel: CancelSignal | None = None,
    ) -> None:
        self._config = config
        self._prober: Prober = prober or SystemProber()
        self._cancel: CancelSignal = cancel or threading.Event()
        self._errors: list[str] = []
        self._probes = 0
        self._timed_out = False
        # Contadores de progreso. Los escribe solo el event loop del scan y los lee el hilo
        # que reporta a la base de datos; en CPython leer un int es atómico, y un valor
        # ligeramente atrasado es aceptable para mostrar progreso.
        self._phase = "pending"
        self._total = 0
        self._checked = 0
        self._alive = 0
        self._details_total = 0
        self._details_done = 0

    def progress(self) -> ScanProgress:
        return ScanProgress(
            phase=self._phase,
            hosts_total=self._total,
            hosts_checked=self._checked,
            hosts_alive=self._alive,
            details_total=self._details_total,
            details_done=self._details_done,
            errors=len(self._errors),
            probes=self._probes,
        )

    def run(self, addresses: Sequence[IPAddress]) -> ScanResult:
        """Synchronous entry point (background thread, CLI)."""
        try:
            return asyncio.run(self.scan(addresses))
        finally:
            if isinstance(self._prober, SystemProber):
                self._prober.close()

    async def scan(self, addresses: Iterable[IPAddress]) -> ScanResult:
        loop = asyncio.get_running_loop()
        self._started = loop.time()
        self._semaphore = asyncio.Semaphore(self._config.concurrency)
        self._rate = RateLimiter(self._config.max_rate)
        targets = list(addresses)
        found = {str(a): HostObservation(str(a)) for a in targets}
        live_ports = liveness_ports(self._config.ports)
        self._total = len(targets)
        try:
            self._phase = "liveness"
            for batch in _batches(targets, HOST_BATCH):
                await asyncio.gather(*(self._liveness(a, found[str(a)], live_ports) for a in batch))
            self._from_neighbours(found)
            alive = [a for a in targets if found[str(a)].alive]
            self._alive = len(alive)
            self._phase = "details"
            self._details_total = len(alive)
            remaining = tuple(p for p in self._config.ports if p not in live_ports)
            for batch in _batches(alive, HOST_BATCH):
                await asyncio.gather(*(self._details(a, found[str(a)], remaining) for a in batch))
        except _StopScanError:
            pass
        self._phase = "done"
        observations = [o for o in found.values() if o.alive]
        return ScanResult(
            hosts_scanned=len(targets),
            observations=observations,
            errors=self._errors,
            probes=self._probes,
            cancelled=self._cancel.is_set(),
            timed_out=self._timed_out,
            hosts_checked=self._checked,
        )

    # --- phases ---------------------------------------------------------------------------

    async def _liveness(
        self, address: IPAddress, obs: HostObservation, ports: tuple[int, ...]
    ) -> None:
        tasks: list[Awaitable[None]] = [self._tcp(address, obs, port) for port in ports]
        if self._config.icmp:
            tasks.append(self._icmp(address, obs))
        await asyncio.gather(*tasks)
        # Solo cuenta como evaluada si todas sus sondas terminaron: una parada (_StopScanError)
        # sale por excepción antes de llegar aquí.
        self._checked += 1
        if obs.alive:
            self._alive += 1

    def _from_neighbours(self, found: dict[str, HostObservation]) -> None:
        try:
            table = self._prober.neighbours()
        except Exception as exc:  # reading OS state must never fail the scan
            self._error(f"neighbour table unreadable: {exc}")
            return
        for ip, mac in table.items():
            obs = found.get(ip)
            if obs is not None:
                obs.mac = mac
                obs.alive = True
                obs.sources.add("arp")

    async def _details(
        self, address: IPAddress, obs: HostObservation, ports: tuple[int, ...]
    ) -> None:
        tasks: list[Awaitable[None]] = [self._tcp(address, obs, port) for port in ports]
        if self._config.reverse_dns:
            tasks.append(self._rdns(address, obs))
        await asyncio.gather(*tasks)
        self._details_done += 1

    # --- probes ---------------------------------------------------------------------------

    async def _limited[T](self, probe: Callable[[], Awaitable[T]]) -> T:
        self._check_stop()
        async with self._semaphore:
            self._check_stop()
            await self._rate.wait()
            self._probes += 1
            return await probe()

    async def _tcp(self, address: IPAddress, obs: HostObservation, port: int) -> None:
        try:
            state = await self._limited(
                lambda: self._prober.tcp(address, port, self._config.timeout)
            )
        except _StopScanError:
            raise
        except Exception as exc:
            self._error(f"{address}:{port}: {exc!r}")
            return
        obs.ports[port] = state
        if state in (PortState.OPEN, PortState.CLOSED):
            obs.alive = True
            obs.sources.add("tcp")

    async def _icmp(self, address: IPAddress, obs: HostObservation) -> None:
        timeout_ms = int(self._config.timeout * 1000)
        try:
            replied = await self._limited(lambda: self._prober.ping(address, timeout_ms))
        except _StopScanError:
            raise
        except Exception as exc:
            self._error(f"{address} ping: {exc!r}")
            return
        if replied:
            obs.alive = True
            obs.sources.add("icmp")

    async def _rdns(self, address: IPAddress, obs: HostObservation) -> None:
        try:
            obs.reverse_dns = await self._limited(
                lambda: self._prober.reverse_dns(address, max(self._config.timeout, 1.0))
            )
        except _StopScanError:
            raise
        except Exception as exc:
            self._error(f"{address} reverse dns: {exc!r}")

    # --- control --------------------------------------------------------------------------

    def _check_stop(self) -> None:
        if self._cancel.is_set():
            raise _StopScanError
        deadline = self._config.deadline
        if deadline is not None and asyncio.get_running_loop().time() - self._started > deadline:
            self._timed_out = True
            raise _StopScanError

    def _error(self, message: str) -> None:
        if len(self._errors) < MAX_ERRORS:
            self._errors.append(message[:300])
        logger.debug("discovery probe error", extra={"error": message[:300]})


def _batches[T](items: Sequence[T], size: int) -> Iterable[Sequence[T]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]
