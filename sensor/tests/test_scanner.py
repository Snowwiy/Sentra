"""Scanner con probers falsos: nada sale a la red."""

import asyncio
import ipaddress
import threading
import time

from sentra_sensor.jobs import DiscoveryParameters
from sentra_sensor.scanner import ProbeError, Scanner
from tests.conftest import FakeTcp


def params(**overrides: object) -> DiscoveryParameters:
    values: dict[str, object] = {
        "target": ipaddress.ip_network("10.0.0.0/29"),
        "ports": (22, 80),
        "timeout_ms": 200,
        "concurrency": 8,
        "max_probes_per_second": 10_000,
        "icmp": False,
        "reverse_dns": False,
        "arp": False,
        "deadline_seconds": 30,
    }
    values.update(overrides)
    return DiscoveryParameters(**values)  # type: ignore[arg-type]


class FakeIcmp:
    def __init__(self, alive: set[str], broken: set[str] | None = None) -> None:
        self.alive = alive
        self.broken = broken or set()

    async def ping(self, address: str, timeout: float) -> bool:
        if address in self.broken:
            raise ProbeError("ping exited with 2")
        return address in self.alive


class FakeNeighbors:
    def read(self) -> dict[str, str]:
        return {"10.0.0.3": "aa:bb:cc:dd:ee:03", "10.9.9.9": "aa:bb:cc:dd:ee:99"}


class FakeResolver:
    async def resolve(self, address: str, timeout: float) -> str | None:
        return f"host-{address.split('.')[-1]}.lan"


def collect(p: DiscoveryParameters, **probers: object) -> tuple[object, list[dict[str, object]]]:
    seen: list[dict[str, object]] = []
    scanner = Scanner(p, lambda obs: seen.extend(o.to_json() for o in obs), **probers)  # type: ignore[arg-type]
    return scanner.run(), seen


def test_tcp_icmp_arp_and_rdns() -> None:
    tcp = FakeTcp({("10.0.0.1", 22): "open", ("10.0.0.2", 80): "closed"})
    report, seen = collect(
        params(icmp=True, arp=True, reverse_dns=True),
        tcp=tcp,
        icmp=FakeIcmp({"10.0.0.4"}),
        neighbors=FakeNeighbors(),
        resolver=FakeResolver(),
    )
    by_addr = {o["address"]: o for o in seen}
    assert set(by_addr) == {"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"}
    assert by_addr["10.0.0.1"]["sources"] == ["tcp"]
    assert {"port": 22, "state": "open"} in by_addr["10.0.0.1"]["ports"]  # type: ignore[operator]
    assert by_addr["10.0.0.3"]["mac"] == "aa:bb:cc:dd:ee:03"
    assert by_addr["10.0.0.3"]["sources"] == ["arp"]
    assert by_addr["10.0.0.4"]["sources"] == ["icmp"]
    assert by_addr["10.0.0.1"]["reverse_dns"] == "host-1.lan"
    assert "10.9.9.9" not in by_addr  # vecinos fuera del target no se informan
    assert report.hosts_scanned == 6 and report.hosts_checked == 6  # type: ignore[attr-defined]
    assert report.probes == 6 * 2 + 6  # type: ignore[attr-defined]
    assert not report.cancelled and not report.timed_out  # type: ignore[attr-defined]


def test_probe_errors_mark_unprobed() -> None:
    report, seen = collect(
        params(icmp=True, ports=()), tcp=FakeTcp(), icmp=FakeIcmp(set(), {"10.0.0.5"})
    )
    assert seen == []
    assert report.unprobed == ["10.0.0.5"]  # type: ignore[attr-defined]
    assert report.errors and "10.0.0.5" in report.errors[0]  # type: ignore[attr-defined]


def test_unavailable_methods_are_reported_not_faked() -> None:
    report, _seen = collect(params(icmp=True, arp=True), tcp=FakeTcp())
    errors = report.errors  # type: ignore[attr-defined]
    assert any("icmp" in e for e in errors) and any("arp" in e for e in errors)


class SlowTcp:
    async def probe(self, address: str, port: int, timeout: float) -> str:
        await asyncio.sleep(10)
        return "filtered"


def test_deadline_times_out() -> None:
    start = time.monotonic()
    report, _ = collect(params(deadline_seconds=1), tcp=SlowTcp())
    assert report.timed_out  # type: ignore[attr-defined]
    assert time.monotonic() - start < 5


class GateTcp:
    """Responde al primer host y se cuelga en el resto."""

    def __init__(self) -> None:
        self.started = threading.Event()

    async def probe(self, address: str, port: int, timeout: float) -> str:
        if address == "10.0.0.1":
            return "open"
        self.started.set()
        await asyncio.sleep(30)
        return "filtered"


def test_cancel_from_other_thread_keeps_partial_results() -> None:
    tcp = GateTcp()
    seen: list[dict[str, object]] = []
    scanner = Scanner(params(), lambda obs: seen.extend(o.to_json() for o in obs), tcp=tcp)
    result: list[object] = []
    thread = threading.Thread(target=lambda: result.append(scanner.run()))
    thread.start()
    assert tcp.started.wait(5)
    time.sleep(0.05)
    scanner.request_cancel()
    thread.join(5)
    assert not thread.is_alive()
    report = result[0]
    assert report.cancelled  # type: ignore[attr-defined]
    assert [o["address"] for o in seen] == ["10.0.0.1"]


def test_rate_limit_is_respected() -> None:
    start = time.monotonic()
    report, _ = collect(
        params(
            target=ipaddress.ip_network("10.0.0.0/30"),
            ports=(1, 2, 3, 4, 5),
            max_probes_per_second=20,
        ),
        tcp=FakeTcp(),
    )
    # 10 sondas a 20/s: al menos ~0,45 s.
    assert report.probes == 10  # type: ignore[attr-defined]
    assert time.monotonic() - start >= 0.4


def test_concurrency_limit() -> None:
    active = 0
    peak = 0

    class CountingTcp:
        async def probe(self, address: str, port: int, timeout: float) -> str:
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            return "filtered"

    collect(params(concurrency=3, ports=tuple(range(1, 9))), tcp=CountingTcp())
    assert peak <= 3
