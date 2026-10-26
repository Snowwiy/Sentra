"""Bounded, rate-limited and cancellable scan of a list of addresses.

Three phases, so dead addresses cost little:
1. liveness: one ping (when available) and a TCP connect to a few likely ports per address;
   a reply, an accepted connection or a refusal (RST) proves the host is up;
2. the server's neighbour (ARP) table is read once: entries complete after phase 1 mark
   hosts that answered nothing else as up and give their MAC;
3. the remaining configured ports and reverse DNS, for live hosts only.
   Fase 4E: en esta fase también se piden los nombres que el propio host publica (mDNS,
   NetBIOS y la descripción UPnP tras un único M-SEARCH SSDP por scan), solo a hosts vivos
   y con el mismo límite de concurrencia, ritmo y timeout que el resto de sondas.

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

from app.discovery import fingerprint, names, probes
from app.discovery.fingerprint import FingerprintProber, MdnsServices, WebFingerprint
from app.discovery.names import IdentityProber, SsdpResponse, UpnpDescription
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
    # Sondas de nombre (mDNS, NetBIOS, SSDP/UPnP); ver app/discovery/names.py.
    identify: bool = True
    # Fase 7A.4: huellas de servicio (DNS-SD, HTTP Server/título, certificado TLS) solo en
    # puertos que el propio scan encontró abiertos; ver app/discovery/fingerprint.py.
    fingerprint: bool = False
    # Seconds for the whole scan (None: no limit).
    deadline: float | None = None
    # Fase 6A (perfiles avanzados). Los valores por defecto reproducen exactamente el
    # discovery básico anterior: sin reintentos, sin DNS directo y sin presupuesto DNS.
    # Reintentos de puertos sin respuesta, solo en la fase de detalle (hosts ya vivos): en la
    # de liveness un host apagado multiplicaría su coste sin aportar evidencia.
    tcp_retries: int = 0
    # Confirmar el nombre del DNS inverso con una consulta directa (FCrDNS). Solo compara:
    # nunca se conecta a las direcciones que devuelva (sin riesgo de DNS rebinding/SSRF).
    forward_dns: bool = False
    # Timeout de cada consulta DNS (None: el histórico max(timeout, 1 s)).
    dns_timeout: float | None = None
    # Consultas DNS máximas del scan (inversas + directas). None: sin límite (básico).
    max_dns_queries: int | None = None


@dataclass
class HostObservation:
    address: str
    alive: bool = False
    # How the host was seen: "icmp", "tcp", "arp".
    sources: set[str] = field(default_factory=set)
    mac: str | None = None
    reverse_dns: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None
    ssdp: SsdpResponse | None = None
    upnp: UpnpDescription | None = None
    # Fase 7A.4: servicios DNS-SD y modelo publicados, y huellas web/TLS.
    services: MdnsServices | None = None
    web: list[WebFingerprint] = field(default_factory=list)
    # State of every port that was probed.
    ports: dict[int, PortState] = field(default_factory=dict)
    # Fase 6A: menor tiempo de un TCP connect que obtuvo respuesta (open o RST), medido de
    # verdad en este scan. None = no se midió (nunca se inventa: el ping del sistema incluye
    # el arranque del proceso y no es un RTT).
    rtt_ms: int | None = None
    # Fase 6A: ¿el nombre del DNS inverso resuelve de vuelta a esta dirección? None = no se
    # comprobó. Es evidencia, no identidad.
    forward_dns_match: bool | None = None

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
    # Fase 5C.2: direcciones que no respondieron y cuya sonda de liveness (ping o TCP) falló
    # con un error (no "sin respuesta"): no se sondearon de verdad, así que no verlas no
    # prueba que no estén. Discovery no les cuenta un scan perdido.
    unprobed: frozenset[str] = frozenset()

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


class ForwardResolver(Protocol):
    """Opcional (Fase 6A): probers sin este método simplemente no confirman nombres."""

    async def forward_dns(self, name: str, timeout: float) -> set[str] | None: ...


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

    async def forward_dns(self, name: str, timeout: float) -> set[str] | None:
        return await probes.forward_dns(self._executor, name, timeout)

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
        identity: IdentityProber | None = None,
        fingerprints: FingerprintProber | None = None,
    ) -> None:
        self._config = config
        self._prober: Prober = prober or SystemProber()
        # Con un prober inyectado (tests) solo hay sondas de nombre si también se inyectan:
        # así ningún test envía UDP real a la red por accidente.
        if identity is None and prober is None and config.identify:
            identity = names.SystemIdentityProber()
        self._identity = identity if config.identify else None
        if fingerprints is None and prober is None and config.fingerprint:
            fingerprints = fingerprint.SystemFingerprintProber()
        self._fingerprints = fingerprints if config.fingerprint else None
        self._ssdp: dict[str, SsdpResponse] = {}
        self._cancel: CancelSignal = cancel or threading.Event()
        self._errors: list[str] = []
        # Direcciones con una sonda de liveness fallida por error (ver ScanResult.unprobed).
        self._probe_failed: set[str] = set()
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
        # Presupuesto de consultas DNS del scan (Fase 6A); None = sin límite.
        self._dns_left = config.max_dns_queries
        self._dns_budget_logged = False

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
            if alive:
                await self._ssdp_search({str(a) for a in alive})
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
            unprobed=frozenset(a for a in self._probe_failed if not found[a].alive),
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
        retries = self._config.tcp_retries
        # Con reintentos, los puertos de liveness que quedaron sin respuesta en un host que SÍ
        # está vivo se vuelven a sondear (mismo criterio que el sensor). Nunca en direcciones
        # vacías: la fase de liveness no reintenta.
        again = (
            tuple(p for p, state in obs.ports.items() if state == PortState.FILTERED)
            if retries
            else ()
        )
        tasks: list[Awaitable[None]] = [self._tcp(address, obs, port, retries) for port in ports]
        # El intento de liveness ya cuenta como el primero.
        tasks.extend(self._tcp(address, obs, port, retries - 1) for port in again)
        if self._config.reverse_dns:
            tasks.append(self._rdns(address, obs))
        if self._identity is not None:
            tasks.append(self._names(address, obs))
        await asyncio.gather(*tasks)
        if self._fingerprints is not None:
            # Después de los puertos: las huellas web solo se piden a puertos ya abiertos.
            await self._fingerprint(address, obs)
        self._details_done += 1

    # --- probes ---------------------------------------------------------------------------

    async def _limited[T](self, probe: Callable[[], Awaitable[T]]) -> T:
        self._check_stop()
        async with self._semaphore:
            self._check_stop()
            await self._rate.wait()
            self._probes += 1
            return await probe()

    async def _timed_tcp(self, address: IPAddress, port: int) -> tuple[PortState, float]:
        loop = asyncio.get_running_loop()
        started = loop.time()
        state = await self._prober.tcp(address, port, self._config.timeout)
        return state, loop.time() - started

    async def _tcp(
        self, address: IPAddress, obs: HostObservation, port: int, retries: int = 0
    ) -> None:
        attempt = 0
        while True:
            try:
                state, elapsed = await self._limited(lambda: self._timed_tcp(address, port))
            except _StopScanError:
                raise
            except Exception as exc:
                self._error(f"{address}:{port}: {exc!r}")
                self._probe_failed.add(str(address))
                return
            # Solo se reintenta "sin respuesta": un RST o una conexión aceptada ya son la
            # respuesta definitiva, y un error se informa en lugar de insistir.
            if state != PortState.FILTERED or attempt >= retries:
                break
            attempt += 1
        if state in (PortState.OPEN, PortState.CLOSED):
            measured = max(0, round(elapsed * 1000))
            obs.rtt_ms = measured if obs.rtt_ms is None else min(obs.rtt_ms, measured)
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
            self._probe_failed.add(str(address))
            return
        if replied:
            obs.alive = True
            obs.sources.add("icmp")

    def _dns_allowed(self) -> bool:
        if self._dns_left is None:
            return True
        if self._dns_left <= 0:
            if not self._dns_budget_logged:
                self._dns_budget_logged = True
                self._error("dns query budget exhausted: remaining hosts without DNS")
            return False
        self._dns_left -= 1
        return True

    async def _rdns(self, address: IPAddress, obs: HostObservation) -> None:
        timeout = self._config.dns_timeout or max(self._config.timeout, 1.0)
        if not self._dns_allowed():
            return
        try:
            obs.reverse_dns = await self._limited(
                lambda: self._prober.reverse_dns(address, timeout)
            )
        except _StopScanError:
            raise
        except Exception as exc:
            self._error(f"{address} reverse dns: {exc!r}")
            return
        resolver = getattr(self._prober, "forward_dns", None)
        name = obs.reverse_dns
        if not (self._config.forward_dns and name and resolver) or not self._dns_allowed():
            return
        try:
            addresses = await self._limited(lambda: resolver(name, timeout))
        except _StopScanError:
            raise
        except Exception as exc:
            self._error(f"{address} forward dns: {exc!r}")
            return
        # None = la consulta no dio respuesta (timeout, NXDOMAIN): no se concluye nada.
        if addresses is not None:
            obs.forward_dns_match = str(address) in addresses

    async def _ssdp_search(self, addresses: set[str]) -> None:
        identity = self._identity
        if identity is None:
            return
        try:
            self._ssdp = await self._limited(
                lambda: identity.ssdp_search(addresses, names.SSDP_WINDOW)
            )
        except _StopScanError:
            raise
        except Exception as exc:  # sin multicast (firewall, sin red) el scan sigue igual
            self._error(f"ssdp search: {exc!r}")

    async def _names(self, address: IPAddress, obs: HostObservation) -> None:
        """Nombres publicados por el host. Cada sonda falla por separado sin afectar al resto."""
        identity = self._identity
        if identity is None:
            return
        host = str(address)
        timeout = self._config.timeout
        obs.ssdp = self._ssdp.get(host)
        ssdp = obs.ssdp

        async def mdns() -> None:
            obs.mdns_name = await self._limited(lambda: identity.mdns_name(host, timeout))

        async def netbios() -> None:
            obs.netbios_name = await self._limited(lambda: identity.netbios_name(host, timeout))

        async def upnp() -> None:
            if ssdp is not None and ssdp.location:
                obs.upnp = await self._limited(
                    lambda: identity.upnp_description(ssdp, max(timeout, names.DESCRIPTION_TIMEOUT))
                )

        async def guarded(label: str, probe: Callable[[], Awaitable[None]]) -> None:
            try:
                await probe()
            except _StopScanError:
                raise
            except Exception as exc:
                self._error(f"{address} {label}: {exc!r}")

        await asyncio.gather(
            guarded("mdns", mdns), guarded("netbios", netbios), guarded("upnp", upnp)
        )

    async def _fingerprint(self, address: IPAddress, obs: HostObservation) -> None:
        """DNS-SD y huellas web/TLS. Cada sonda falla por separado sin afectar al resto."""
        prober = self._fingerprints
        if prober is None:
            return
        host = str(address)
        timeout = max(self._config.timeout, 1.0)

        async def services() -> None:
            obs.services = await self._limited(lambda: prober.mdns_services(host, timeout))

        async def web(port: int, tls: bool) -> None:
            found = await self._limited(lambda: prober.web(host, port, tls, timeout * 2))
            if found is not None:
                obs.web.append(found)

        async def guarded(label: str, probe: Awaitable[None]) -> None:
            try:
                await probe
            except _StopScanError:
                raise
            except Exception as exc:
                self._error(f"{address} {label}: {exc!r}")

        probes_ = [guarded("mdns services", services())]
        probes_.extend(
            guarded(f"web {port}", web(port, tls))
            for port, tls in fingerprint.pick_ports(obs.open_ports)
        )
        await asyncio.gather(*probes_)
        obs.web.sort(key=lambda item: item.port)

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
