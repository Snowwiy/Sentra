"""Discovery engine: allowlist safety and real TCP probing on loopback.

TCP tests open real listening sockets on 127.0.0.0/8 (every address there is this host),
so the connect/refuse/timeout handling is exercised against the real network stack, not
mocks. Nothing leaves the machine.
"""

import asyncio
import errno
import ipaddress
import socket
import threading
import time
from collections.abc import Iterator

import pytest

from app.discovery.classify import IdentityInput, identify
from app.discovery.ports import liveness_ports, parse_ports
from app.discovery.probes import (
    PortState,
    clean_hostname,
    normalize_mac,
    parse_proc_arp,
    parse_proc_route,
    parse_windows_arp,
    parse_windows_route,
    ping_succeeded,
    tcp_probe,
)
from app.discovery.scanner import NetworkScanner, RateLimiter, ScanConfig, SystemProber
from app.discovery.targets import DiscoveryScope, TargetError

# --- allowlist ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "network",
    [
        "0.0.0.0/0",
        "::/0",
        "10.0.0.0/8",  # too many hosts for the default limit
        "8.8.8.0/24",  # Internet
        "2001:4860::/120",  # Internet IPv6
        "224.0.0.0/24",  # multicast
        "240.0.0.0/24",  # reserved
        "0.0.0.0/32",
        "255.255.255.255/32",
        "192.168.1.10/24",  # host bits set: ambiguous intent
        "192.168.1.0/33",
        "not-a-network",
        "192.168.1.0/24; DROP TABLE",
    ],
)
def test_unsafe_or_invalid_allowlist_entries_are_refused(network: str) -> None:
    with pytest.raises(TargetError):
        DiscoveryScope.parse(network)


def test_valid_scope_collapses_overlaps_and_honours_exclusions() -> None:
    scope = DiscoveryScope.parse(
        "192.168.1.0/24, 192.168.1.0/25, 10.0.10.0/24,fd00::/120",
        excluded="192.168.1.1, 10.0.10.128/25",
    )

    assert [str(n) for n in scope.allowed] == ["10.0.10.0/24", "192.168.1.0/24", "fd00::/120"]
    hosts = list(scope.hosts(ipaddress.ip_network("10.0.10.0/24")))
    assert len(hosts) == 127  # .1-.127; .128/25 excluded, no network/broadcast address
    assert ipaddress.ip_address("192.168.1.1") not in set(
        scope.hosts(ipaddress.ip_network("192.168.1.0/24"))
    )
    assert scope.is_allowed(ipaddress.ip_address("192.168.1.20"))
    assert not scope.is_allowed(ipaddress.ip_address("192.168.1.1"))  # excluded
    assert not scope.is_allowed(ipaddress.ip_address("192.168.2.20"))


def test_adjacent_networks_must_still_fit_the_limit() -> None:
    # Four /24 collapse into a /22 (1024 addresses): allowed at the default limit...
    DiscoveryScope.parse("10.1.0.0/24,10.1.1.0/24,10.1.2.0/24,10.1.3.0/24")
    # ...but not with a lower one, even though each entry alone fits.
    with pytest.raises(TargetError):
        DiscoveryScope.parse("10.1.0.0/24,10.1.1.0/24", max_hosts=256)


def test_explicit_targets_must_be_inside_the_allowlist() -> None:
    scope = DiscoveryScope.parse("192.168.1.0/24")

    assert [str(n) for n in scope.resolve("192.168.1.0/28")] == ["192.168.1.0/28"]
    assert [str(n) for n in scope.resolve("192.168.1.20")] == ["192.168.1.20/32"]
    for outside in ("192.168.2.0/24", "192.168.0.0/16", "8.8.8.8", "::1"):
        with pytest.raises(TargetError):
            scope.resolve(outside)
    with pytest.raises(TargetError):
        DiscoveryScope.parse("").resolve()  # discovery disabled by default


def test_public_networks_need_an_explicit_opt_in() -> None:
    scope = DiscoveryScope.parse("203.0.113.0/28", allow_public=False)  # TEST-NET-3: not global
    assert scope.enabled
    with pytest.raises(TargetError):
        DiscoveryScope.parse("8.8.8.0/28")
    assert DiscoveryScope.parse("8.8.8.0/28", allow_public=True).enabled
    with pytest.raises(TargetError):  # the opt-in never allows everything
        DiscoveryScope.parse("0.0.0.0/0", allow_public=True)


# --- ports, parsers, classification ---------------------------------------------------------


def test_port_specs() -> None:
    assert parse_ports("minimal") == (22, 80, 443, 445, 3389)
    assert parse_ports("22, 8000-8002,22") == (22, 8000, 8001, 8002)
    assert 9100 in parse_ports("common")
    for bad in ("", "0", "65536", "http", "10-5", "1-2000"):
        with pytest.raises(ValueError):
            parse_ports(bad)
    assert liveness_ports((22, 80, 443, 445, 3389, 8081, 9999), limit=3) == (445, 80, 443)


def test_neighbour_route_and_ping_parsers() -> None:
    arp = (
        "IP address       HW type     Flags       HW address            Mask     Device\n"
        "192.168.1.1      0x1         0x2         02:FC:00:00:00:05     *        eth0\n"
        "192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        "192.168.1.255    0x1         0x2         ff:ff:ff:ff:ff:ff     *        eth0\n"
    )
    assert parse_proc_arp(arp) == {"192.168.1.1": "02:fc:00:00:00:05"}
    windows_arp = (
        "\nInterfaz: 192.168.1.20 --- 0x7\n"
        "  Dirección de Internet          Dirección física      Tipo\n"
        "  192.168.1.1           a4-91-b1-00-11-22     dinámico\n"
        "  192.168.1.255         ff-ff-ff-ff-ff-ff     estático\n"
        "  224.0.0.22            01-00-5e-00-00-16     estático\n"
    )
    assert parse_windows_arp(windows_arp) == {"192.168.1.1": "a4:91:b1:00:11:22"}
    route = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
    )
    assert parse_proc_route(route) == {"192.168.1.1"}
    windows_route = (
        "Destino de red        Máscara de red   Puerta de enlace   Interfaz  Métrica\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.20     25\n"
        "        127.0.0.0        255.0.0.0         En vínculo         127.0.0.1    331\n"
    )
    assert parse_windows_route(windows_route) == {"192.168.1.1"}
    assert normalize_mac("AA-BB-CC-00-11-22") == "aa:bb:cc:00:11:22"
    assert normalize_mac("01:00:5e:00:00:16") is None  # multicast
    assert normalize_mac("garbage") is None
    # Se conserva el uso de mayúsculas: "MNA-LX9" se muestra como lo publica el equipo.
    assert clean_hostname("PC-ADMIN-01.corp.local.", "10.0.0.5") == "PC-ADMIN-01.corp.local"
    assert clean_hostname("10.0.0.5", "10.0.0.5") is None
    assert clean_hostname("bad name\x00", "10.0.0.5") is None


def test_windows_ping_requires_a_real_echo_reply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.platform", "win32")
    reply = b"Respuesta desde 192.168.1.1: bytes=32 tiempo<1m TTL=64"
    unreachable = b"Respuesta desde 192.168.1.20: Host de destino inaccesible."
    assert ping_succeeded(0, reply)
    assert not ping_succeeded(0, unreachable)  # exit code 0 but no reply


def test_classification_is_conservative() -> None:
    def kind(**kwargs: object) -> str | None:
        result = identify(IdentityInput(**kwargs))  # type: ignore[arg-type]
        return result.device_type.value if result.device_type else None

    windows = identify(IdentityInput(open_ports=frozenset({135, 445, 3389})))
    # Puertos de Windows: SO probable Windows y "PC probable" (confianza baja), no un hecho.
    assert (windows.device_type, windows.probable_os, windows.confidence) == (
        "pc",
        "Windows",
        "low",
    )
    assert kind(open_ports=frozenset({80, 443, 9100})) == "printer"
    assert kind(open_ports=frozenset({80, 443}), is_gateway=True) == "router"
    assert kind(open_ports=frozenset({22})) is None  # SSH alone proves nothing
    assert kind(open_ports=frozenset({80, 443})) is None
    assert kind(managed=True, hostname="PC-1", os_name="Windows") == "pc"


# --- real TCP on loopback ----------------------------------------------------------------


class Listener:
    """A real listening socket that accepts and closes connections in a thread."""

    def __init__(self, address: str, port: int = 0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((address, port))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except (TimeoutError, OSError):
                continue
            self.accepted += 1
            conn.close()

    def close(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sock.close()


@pytest.fixture
def listener() -> Iterator[Listener]:
    server = Listener("127.0.0.2")
    yield server
    server.close()


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
    return port


# Real sockets: assert what every OS agrees on. A connection to a port nobody listens on is
# refused with RST on Linux (CLOSED), but Windows retries the SYN after a RST for about a
# second before reporting it, so within a short probe timeout it is FILTERED there. Both
# mean "not open"; the exact mapping of each outcome is pinned by the fake-connection tests
# below, independently of the OS.
NOT_OPEN = {PortState.CLOSED, PortState.FILTERED}


def test_tcp_probe_open_and_not_open_on_real_sockets(listener: Listener) -> None:
    address = ipaddress.ip_address("127.0.0.2")
    closed_port = _free_port()

    assert asyncio.run(tcp_probe(address, listener.port, 1.0)) == PortState.OPEN
    assert asyncio.run(tcp_probe(address, closed_port, 1.0)) in NOT_OPEN


def test_tcp_probe_honours_its_timeout_on_real_sockets() -> None:
    # A listener whose accept queue is full stops completing handshakes: Linux drops the
    # SYN (timeout, FILTERED), Windows may refuse it. Either way not open, and never slower
    # than the probe timeout allows.
    with socket.socket() as full:
        full.bind(("127.0.0.3", 0))
        full.listen(0)
        port = full.getsockname()[1]
        pending = []
        for _ in range(8):  # fill the accept queue until the OS stops accepting
            try:
                pending.append(socket.create_connection(("127.0.0.3", port), timeout=0.3))
            except OSError:  # timeout (Linux) or refusal (Windows)
                break
        try:
            started = time.monotonic()
            state = asyncio.run(tcp_probe(ipaddress.ip_address("127.0.0.3"), port, 0.3))
            assert state in NOT_OPEN
            assert time.monotonic() - started < 2
        finally:
            for conn in pending:
                conn.close()


# --- deterministic outcome mapping (no network, same result on every OS) ------------------


class _Writer:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def _probe_with(
    monkeypatch: pytest.MonkeyPatch, behaviour: object, timeout: float = 0.2
) -> PortState:
    async def fake_open_connection(host: str, port: int) -> tuple[None, _Writer]:
        if isinstance(behaviour, BaseException):
            raise behaviour
        if behaviour == "hang":
            await asyncio.sleep(3600)
        assert isinstance(behaviour, _Writer)
        return None, behaviour

    monkeypatch.setattr("app.discovery.probes.asyncio.open_connection", fake_open_connection)
    return asyncio.run(tcp_probe(ipaddress.ip_address("192.0.2.10"), 445, timeout))


def _os_error(errno_value: int | None = None, winerror: int | None = None) -> OSError:
    error = OSError(errno_value, "simulated")
    if winerror is not None:
        # Typed only on Windows (typeshed), hence the ignore when type-checking for Linux.
        error.winerror = winerror  # type: ignore[attr-defined,unused-ignore]
    return error


def test_successful_connect_is_open_and_closed_at_once(monkeypatch: pytest.MonkeyPatch) -> None:
    writer = _Writer()
    assert _probe_with(monkeypatch, writer) == PortState.OPEN
    assert writer.closed  # nothing is sent: the connection is closed right away


@pytest.mark.parametrize(
    "error",
    [ConnectionRefusedError(errno.ECONNREFUSED, "refused"), _os_error(winerror=10061)],
    ids=["refused", "windows-WSAECONNREFUSED"],
)
def test_refusal_is_closed(monkeypatch: pytest.MonkeyPatch, error: OSError) -> None:
    assert _probe_with(monkeypatch, error) == PortState.CLOSED


def test_timeout_is_filtered_and_honoured(monkeypatch: pytest.MonkeyPatch) -> None:
    started = time.monotonic()
    assert _probe_with(monkeypatch, "hang", timeout=0.2) == PortState.FILTERED
    assert time.monotonic() - started < 1.5


@pytest.mark.parametrize(
    "error",
    [
        _os_error(errno.EHOSTUNREACH),
        _os_error(errno.ENETUNREACH),
        _os_error(winerror=10065),
        _os_error(winerror=10051),
    ],
    ids=["EHOSTUNREACH", "ENETUNREACH", "WSAEHOSTUNREACH", "WSAENETUNREACH"],
)
def test_unreachable_is_reported_as_such(monkeypatch: pytest.MonkeyPatch, error: OSError) -> None:
    assert _probe_with(monkeypatch, error) == PortState.UNREACHABLE


def test_other_errors_are_errors_not_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    assert _probe_with(monkeypatch, _os_error(errno.EMFILE)) == PortState.ERROR


def test_scanner_finds_open_ports_on_real_sockets(listener: Listener) -> None:
    other = Listener("127.0.0.4")
    try:
        ports = (listener.port, other.port, _free_port())
        scanner = NetworkScanner(
            ScanConfig(ports=ports, timeout=1.0, concurrency=8, icmp=False, reverse_dns=False)
        )
        hosts = [ipaddress.ip_address(f"127.0.0.{i}") for i in (2, 4)]

        result = scanner.run(hosts)

        found = {o.address: o for o in result.observations}
        assert result.complete and result.hosts_scanned == 2
        assert found["127.0.0.2"].open_ports == [listener.port]
        assert found["127.0.0.4"].open_ports == [other.port]
        assert (
            found["127.0.0.2"].ports[ports[2]] in NOT_OPEN
        )  # CLOSED on Linux, may be FILTERED on Windows
        assert "tcp" in found["127.0.0.2"].sources
        assert listener.accepted >= 1  # a real connection was made...
    finally:
        other.close()


def test_scanner_respects_the_concurrency_limit() -> None:
    in_flight = 0
    peak = 0

    class SlowProber:
        async def tcp(self, address: object, port: int, timeout: float) -> PortState:
            nonlocal in_flight, peak
            in_flight += 1
            peak = max(peak, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return PortState.CLOSED

        async def ping(self, address: object, timeout_ms: int) -> bool | None:
            return None

        def neighbours(self) -> dict[str, str]:
            return {}

        async def reverse_dns(self, address: object, timeout: float) -> str | None:
            return None

    scanner = NetworkScanner(
        ScanConfig(ports=(1, 2, 3, 4, 5, 6), concurrency=4, max_rate=10_000, icmp=False),
        prober=SlowProber(),
    )
    hosts = [ipaddress.ip_address(f"10.0.0.{i}") for i in range(1, 41)]

    result = scanner.run(hosts)

    assert peak <= 4
    assert len(result.observations) == 40  # refused = alive
    assert result.probes == 40 * 6 + 40  # all ports + one reverse lookup per live host


def test_rate_limiter_spaces_probes() -> None:
    async def take(count: int) -> float:
        limiter = RateLimiter(50)
        start = asyncio.get_running_loop().time()
        for _ in range(count):
            await limiter.wait()
        return asyncio.get_running_loop().time() - start

    assert asyncio.run(take(11)) >= 0.19  # 10 intervals of 20 ms


def test_cancellation_and_deadline_stop_a_scan_and_mark_it_partial() -> None:
    cancel = threading.Event()
    cancel.set()
    scanner = NetworkScanner(
        ScanConfig(ports=(1,), icmp=False, reverse_dns=False), prober=SystemProber(), cancel=cancel
    )
    result = scanner.run([ipaddress.ip_address("127.0.0.2")])
    assert result.cancelled and not result.complete and result.probes == 0

    hosts = [ipaddress.ip_address(f"127.0.1.{i}") for i in range(1, 255)]
    slow = NetworkScanner(
        ScanConfig(ports=(_free_port(),), max_rate=20, icmp=False, deadline=0.3), cancel=None
    )
    started = time.monotonic()
    result = slow.run(hosts)
    assert result.timed_out and not result.complete
    assert time.monotonic() - started < 3
    assert result.probes < len(hosts)
