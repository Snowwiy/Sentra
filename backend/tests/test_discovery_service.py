"""Discovery jobs against the real database: baseline, dedupe, reconciliation, changes.

Most tests use `Lab`, a deterministic stand-in for a small network (which hosts answer,
which ports are open), so every scenario (a port opening, a host leaving) is reproducible.
Everything after the probes is real: scanner, persistence, alerts, API. The last test runs
the real system probes against listeners on 127.0.0.0/8.
"""

import ipaddress
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.discovery.probes import PortState
from app.discovery.scanner import ScanConfig
from app.discovery.targets import DiscoveryScope, TargetError
from app.models.alert import Alert, AlertRule, AlertStatus
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.change import AssetChange
from app.models.discovery import DiscoveryJob, DiscoveryJobStatus, DiscoveryTrigger
from app.models.exposure import AssetPort, PortStateValue
from app.services.alert_service import AlertService, AlertThresholds
from app.services.discovery_service import DiscoveryBusyError, DiscoveryConfig, DiscoveryService
from tests.conftest import agent_payload

NETWORK = "10.20.0.0/28"


@dataclass
class Host:
    ports: set[int] = field(default_factory=set)
    mac: str | None = None
    name: str | None = None
    up: bool = True
    # Firewall that drops instead of refusing: closed ports time out.
    drops: bool = False


class Lab:
    """Fake network: answers probes from a table of hosts."""

    def __init__(self, hosts: dict[str, Host]) -> None:
        self.hosts = hosts

    async def tcp(self, address: Any, port: int, timeout: float) -> PortState:
        host = self.hosts.get(str(address))
        if host is None or not host.up:
            return PortState.FILTERED
        if port in host.ports:
            return PortState.OPEN
        return PortState.FILTERED if host.drops else PortState.CLOSED

    async def ping(self, address: Any, timeout_ms: int) -> bool | None:
        return None  # like a server without ping

    def neighbours(self) -> dict[str, str]:
        return {ip: h.mac for ip, h in self.hosts.items() if h.up and h.mac}

    async def reverse_dns(self, address: Any, timeout: float) -> str | None:
        host = self.hosts.get(str(address))
        return host.name if host else None


PORTS = (22, 80, 135, 443, 445, 3389, 8080, 9100)


def _service(
    engine: Engine,
    lab: Lab,
    *,
    allowed: str = NETWORK,
    gateways: set[str] | None = None,
    misses: int = 2,
) -> DiscoveryService:
    config = DiscoveryConfig(
        scope=DiscoveryScope.parse(allowed),
        scan=ScanConfig(ports=PORTS, timeout=0.5, concurrency=16, max_rate=5000, icmp=False),
        offline_after_misses=misses,
        heartbeat_timeout=timedelta(seconds=90),
    )
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=timedelta(seconds=90),
    )  # fmt: skip
    return DiscoveryService(
        sessionmaker(bind=engine, expire_on_commit=False),
        config,
        thresholds,
        prober_factory=lambda: lab,
        gateways=lambda: gateways or set(),
    )


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    # `client` only for its cleanup (tables truncated after each test).
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _assets(db: Session) -> dict[str, Asset]:
    db.expire_all()
    return {a.primary_ip: a for a in db.scalars(select(Asset))}


def _ports(db: Session, asset: Asset) -> dict[int, str]:
    rows = db.scalars(select(AssetPort).where(AssetPort.asset_id == asset.id))
    return {p.port: p.state.value for p in rows}


def _alerts(db: Session, rule: AlertRule | None = None) -> list[Alert]:
    db.expire_all()
    query = select(Alert)
    if rule is not None:
        query = query.where(Alert.rule == rule)
    return list(db.scalars(query))


def _changes(db: Session, asset: Asset) -> list[tuple[str, str, str]]:
    rows = db.scalars(
        select(AssetChange).where(AssetChange.asset_id == asset.id).order_by(AssetChange.id)
    )
    return [(c.category.value, c.kind.value, c.item) for c in rows]


def office() -> dict[str, Host]:
    return {
        "10.20.0.1": Host({80, 443}, mac="02:00:00:00:00:01"),
        "10.20.0.5": Host({135, 445, 3389}, mac="02:00:00:00:00:05", name="pc-admin-02.corp"),
        "10.20.0.7": Host({80, 443, 9100}, mac="02:00:00:00:00:07"),
        "10.20.0.9": Host(set(), mac="02:00:00:00:00:09", drops=True),  # answers ARP only
    }


def test_first_run_is_a_quiet_baseline(engine: Engine, db: Session) -> None:
    lab = Lab(office())

    [summary] = _service(engine, lab, gateways={"10.20.0.1"}).run()

    assert summary.status == DiscoveryJobStatus.COMPLETED and summary.baseline
    assert (summary.hosts_scanned, summary.hosts_alive, summary.hosts_new) == (14, 4, 4)
    assets = _assets(db)
    assert all(a.monitoring_method == MonitoringMethod.DISCOVERED for a in assets.values())
    assert all(a.agent_id is None and a.hostname is None for a in assets.values())
    router, pc, printer, quiet = (assets[f"10.20.0.{i}"] for i in (1, 5, 7, 9))
    assert router.device_type == "router" and router.classification_confidence == "high"
    assert pc.device_type == "pc" and pc.probable_os == "Windows"
    assert pc.reverse_dns == "pc-admin-02.corp" and pc.device_name == "pc-admin-02.corp"
    assert printer.device_type == "printer"
    assert quiet.device_type is None and quiet.device_type_reason is None  # not guessed
    assert quiet.discovery_sources == ["arp"] and quiet.mac_address == "02:00:00:00:00:09"
    assert _ports(db, pc) == {135: "open", 445: "open", 3389: "open"}
    assert pc.network_status == AssetStatus.ONLINE and pc.exposure_baseline_at is not None
    assert _alerts(db) == []  # a baseline raises nothing
    assert all(_changes(db, a) == [] for a in assets.values())


def test_later_runs_report_new_assets_and_ports_once(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()

    lab.hosts["10.20.0.5"].ports.add(8080)
    lab.hosts["10.20.0.11"] = Host({22}, mac="02:00:00:00:00:0b")
    lab.hosts["10.20.0.12"] = Host({445}, name="files.corp")
    [summary] = service.run()
    service.run()  # same state again: nothing new

    assert not summary.baseline and summary.hosts_new == 2
    pc = _assets(db)["10.20.0.5"]
    assert _changes(db, pc) == [("exposure", "port_opened", "8080/tcp (http-alt)")]
    [exposed] = _alerts(db, AlertRule.PORT_EXPOSED)
    assert exposed.occurrences == 1 and exposed.severity.value == "warning"
    assert exposed.details is not None and exposed.details["ports"][0]["port"] == 8080
    [unknown] = _alerts(db, AlertRule.UNKNOWN_DEVICE)  # no name, no type
    assert "10.20.0.11" in unknown.message
    [identified] = _alerts(db, AlertRule.ASSET_DISCOVERED)
    assert "files.corp" in identified.message
    # The new hosts' own ports are their baseline, not "new ports".
    assert len(_alerts(db, AlertRule.PORT_EXPOSED)) == 1
    assert len(_assets(db)) == 6  # duplicate discovery creates nothing


def test_sensitive_new_port_is_critical(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()
    lab.hosts["10.20.0.7"].ports.add(3389)

    service.run()

    [alert] = _alerts(db, AlertRule.PORT_EXPOSED)
    assert alert.severity.value == "critical"
    assert "3389/tcp (rdp)" in alert.message


def test_port_closes_after_two_complete_runs_and_reopens(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()
    lab.hosts["10.20.0.5"].ports.discard(3389)

    service.run()
    pc = _assets(db)["10.20.0.5"]
    assert _ports(db, pc)[3389] == "open"  # one miss is not enough
    service.run()
    assert _ports(db, pc)[3389] == "closed"
    [closed] = _alerts(db, AlertRule.PORT_CLOSED)
    assert closed.severity.value == "info"

    lab.hosts["10.20.0.5"].ports.add(3389)
    service.run()
    db.expire_all()
    row = db.scalar(select(AssetPort).where(AssetPort.asset_id == pc.id, AssetPort.port == 3389))
    assert row is not None and row.state == PortStateValue.OPEN and row.closed_at is None
    assert row.first_seen_at < row.opened_at  # first ever vs current open period
    assert [c[1] for c in _changes(db, pc)] == ["port_closed", "port_opened"]


def test_host_disappears_after_misses_and_comes_back(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab, misses=2)
    service.run()
    lab.hosts["10.20.0.7"].up = False

    service.run()
    printer = _assets(db)["10.20.0.7"]
    assert printer.network_status == AssetStatus.ONLINE and printer.network_misses == 1
    service.run()
    printer = _assets(db)["10.20.0.7"]
    assert printer.network_status == AssetStatus.OFFLINE
    assert _ports(db, printer)[9100] == "open"  # a host that is down says nothing about ports
    [gone] = _alerts(db, AlertRule.ASSET_DISAPPEARED)
    assert gone.status == AlertStatus.OPEN

    lab.hosts["10.20.0.7"].up = True
    service.run()
    printer = _assets(db)["10.20.0.7"]
    assert printer.network_status == AssetStatus.ONLINE
    assert _alerts(db, AlertRule.ASSET_DISAPPEARED)[0].status == AlertStatus.RESOLVED
    assert [c[1] for c in _changes(db, printer)] == ["disappeared", "appeared"]


def test_partial_runs_draw_no_negative_conclusions(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab, misses=1)
    service.run()
    lab.hosts["10.20.0.7"].up = False

    cancel = threading.Event()
    cancel.set()
    service._cancel = cancel  # stopped before probing anything (e.g. shutdown)
    [summary] = [service.run_network(ipaddress.ip_network(NETWORK), DiscoveryTrigger.MANUAL)]

    assert summary.status == DiscoveryJobStatus.CANCELLED
    printer = _assets(db)["10.20.0.7"]
    assert printer.network_status == AssetStatus.ONLINE and printer.network_misses == 0


def test_mac_identifies_a_host_whose_address_changed(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()
    first_id = _assets(db)["10.20.0.5"].id
    lab.hosts["10.20.0.6"] = lab.hosts.pop("10.20.0.5")  # DHCP gave it another address

    service.run()

    assets = _assets(db)
    assert "10.20.0.5" not in assets and assets["10.20.0.6"].id == first_id
    assert _alerts(db, AlertRule.UNKNOWN_DEVICE) == _alerts(db, AlertRule.ASSET_DISCOVERED) == []


def test_same_address_with_another_mac_is_another_device(engine: Engine, db: Session) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()
    lab.hosts["10.20.0.9"] = Host({22}, mac="02:00:00:00:00:99")

    service.run()

    rows = list(db.scalars(select(Asset).where(Asset.primary_ip == "10.20.0.9")))
    assert sorted(a.mac_address or "" for a in rows) == ["02:00:00:00:00:09", "02:00:00:00:00:99"]


def test_agent_host_is_matched_not_duplicated(
    client: TestClient, engine: Engine, db: Session
) -> None:
    payload = agent_payload(primary_ip="10.20.0.5")
    assert client.post("/api/v1/agents/register", json=payload).status_code == 201
    inventory = {
        "agent_id": payload["agent_id"],
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [
            {
                "name": "Ethernet",
                "mac": "02-00-00-00-00-05",
                "addresses": ["10.20.0.5"],
                "is_up": True,
            }
        ],
    }
    assert client.post("/api/v1/inventory", json=inventory).status_code == 201

    _service(engine, Lab(office())).run()

    rows = list(db.scalars(select(Asset).where(Asset.primary_ip == "10.20.0.5")))
    assert len(rows) == 1
    [managed] = rows
    assert managed.monitoring_method == MonitoringMethod.AGENT
    assert managed.mac_address == "02:00:00:00:00:05"  # from the agent's inventory
    assert managed.hostname == "PC-ADMIN-01"  # agent data is never overwritten
    assert managed.device_type == "pc" and "agente" in (managed.device_type_reason or "")
    # Datos del agente: nombre autoritativo y sin SO "probable" (manda os_name).
    assert managed.device_name == "PC-ADMIN-01" and managed.name_source == "agent_hostname"
    assert managed.probable_os is None and managed.classification_confidence == "high"
    assert managed.discovered_at is not None and _ports(db, managed)[3389] == "open"


def test_agent_installed_later_merges_the_discovered_record(
    client: TestClient, engine: Engine, db: Session
) -> None:
    lab = Lab(office())
    service = _service(engine, lab)
    service.run()
    lab.hosts["10.20.0.5"].ports.add(8080)
    service.run()  # an alert and a change on the discovered record
    discovered = _assets(db)["10.20.0.5"]
    discovered_id, discovered_at = discovered.id, discovered.discovered_at

    payload = agent_payload(primary_ip="10.20.0.77")  # address not known yet
    response = client.post("/api/v1/agents/register", json=payload)
    assert response.status_code == 201
    inventory = {
        "agent_id": payload["agent_id"],
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [
            {
                "name": "Ethernet",
                "mac": "02:00:00:00:00:05",
                "addresses": ["10.20.0.77"],
                "is_up": True,
            },
        ],
    }
    assert client.post("/api/v1/inventory", json=inventory).status_code == 201

    db.expire_all()
    rows = list(db.scalars(select(Asset).where(Asset.mac_address == "02:00:00:00:00:05")))
    assert len(rows) == 1
    [merged] = rows
    assert str(merged.public_id) == response.json()["asset_id"]
    assert merged.monitoring_method == MonitoringMethod.AGENT
    assert merged.discovered_at == discovered_at
    # Antes "PC probable" desde la red; ahora el agente es la fuente autoritativa.
    assert merged.device_type == "pc" and merged.classification_confidence == "high"
    assert merged.device_name == payload["hostname"] and merged.probable_os is None
    assert _ports(db, merged)[8080] == "open"
    assert ("exposure", "port_opened", "8080/tcp (http-alt)") in _changes(db, merged)
    assert _alerts(db, AlertRule.PORT_EXPOSED)[0].asset_id == merged.id
    assert db.get(Asset, discovered_id) is None

    # The next run attaches to the agent asset: no new "unknown device".
    service.run()
    assert len(list(db.scalars(select(Asset)))) == 4
    assert _alerts(db, AlertRule.UNKNOWN_DEVICE) == []


def test_enrollment_merges_by_address_only_without_conflicting_mac(
    client: TestClient, engine: Engine, db: Session
) -> None:
    lab = Lab({"10.20.0.3": Host({445}, mac=None)})  # routed: no MAC known
    _service(engine, lab).run()

    payload = agent_payload(primary_ip="10.20.0.3")
    assert client.post("/api/v1/agents/register", json=payload).status_code == 201

    [asset] = list(db.scalars(select(Asset)))
    db.refresh(asset)
    assert asset.agent_id is not None and asset.discovered_at is not None


def test_monitoring_lost_when_host_answers_but_agent_is_silent(
    client: TestClient, engine: Engine, db: Session
) -> None:
    payload = agent_payload(primary_ip="10.20.0.5")
    client.post("/api/v1/agents/register", json=payload)
    client.post("/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"]})
    db.execute(update(Asset).values(last_seen_at=datetime.now(UTC) - timedelta(hours=1)))
    db.commit()

    _service(engine, Lab(office())).run()
    [lost] = _alerts(db, AlertRule.MONITORING_LOST)
    assert lost.status == AlertStatus.OPEN

    client.post("/api/v1/agents/heartbeat", json={"agent_id": payload["agent_id"]})
    assert _alerts(db, AlertRule.MONITORING_LOST)[0].status == AlertStatus.RESOLVED


def test_one_running_job_per_network_and_stale_jobs_expire(engine: Engine, db: Session) -> None:
    service = _service(engine, Lab(office()))
    db.add(
        DiscoveryJob(
            target=NETWORK, trigger=DiscoveryTrigger.MANUAL, status=DiscoveryJobStatus.RUNNING,
            baseline=True, started_at=datetime.now(UTC), hosts_scanned=0, hosts_alive=0,
            hosts_new=0, open_ports=0, probes=0, error_count=0,
        )
    )  # fmt: skip
    db.commit()

    with pytest.raises(DiscoveryBusyError):
        service.run_network(ipaddress.ip_network(NETWORK), DiscoveryTrigger.MANUAL)
    assert service.run() == []  # busy networks are skipped, not run twice

    db.execute(update(DiscoveryJob).values(started_at=datetime.now(UTC) - timedelta(days=1)))
    db.commit()
    [summary] = service.run()  # a job left running by a crash no longer blocks
    assert summary.status == DiscoveryJobStatus.COMPLETED
    statuses = sorted(j.status.value for j in db.scalars(select(DiscoveryJob)))
    assert statuses == ["completed", "failed"]


def test_targets_outside_the_allowlist_are_refused(engine: Engine, db: Session) -> None:
    service = _service(engine, Lab(office()))
    for target in ("10.20.1.0/28", "10.0.0.0/8", "0.0.0.0/0", "8.8.8.8", "bogus"):
        with pytest.raises(TargetError):
            service.run(target)
    assert list(db.scalars(select(DiscoveryJob))) == []
    [summary] = service.run("10.20.0.4/30")
    assert summary.target == "10.20.0.4/30" and summary.hosts_scanned == 2


def test_real_probes_on_loopback(engine: Engine, db: Session) -> None:
    servers = []
    for address in ("127.0.0.21", "127.0.0.22"):
        sock = socket.socket()
        sock.bind((address, 0))
        sock.listen(4)
        servers.append(sock)
    ports = tuple(s.getsockname()[1] for s in servers)
    config = DiscoveryConfig(
        scope=DiscoveryScope.parse("127.0.0.20/30"),
        scan=ScanConfig(ports=ports, timeout=1.0, concurrency=8, icmp=True, reverse_dns=False),
    )
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=timedelta(seconds=90),
    )  # fmt: skip
    service = DiscoveryService(
        sessionmaker(bind=engine, expire_on_commit=False), config, thresholds
    )
    try:
        [summary] = service.run()
    finally:
        for sock in servers:
            sock.close()

    assert summary.status == DiscoveryJobStatus.COMPLETED
    assets = _assets(db)
    # 127.0.0.21 and .22 listen; every loopback address refuses the rest: all are up.
    assert set(assets) == {"127.0.0.21", "127.0.0.22"}
    assert _ports(db, assets["127.0.0.21"]) == {ports[0]: "open"}
    assert _ports(db, assets["127.0.0.22"]) == {ports[1]: "open"}
    assert "tcp" in (assets["127.0.0.21"].discovery_sources or [])


def test_agent_offline_sweeper_ignores_assets_without_agent(engine: Engine, db: Session) -> None:
    _service(engine, Lab(office())).run()
    db.execute(update(Asset).values(last_network_seen_at=datetime.now(UTC) - timedelta(days=30)))
    db.commit()
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=timedelta(seconds=1),
    )  # fmt: skip

    assert AlertService(db, thresholds).sweep_offline() == 0
    assert _alerts(db, AlertRule.ASSET_OFFLINE) == []
