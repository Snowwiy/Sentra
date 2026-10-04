"""Discovery jobs: scan an allowed network and turn what was seen into assets and changes.

One job per allowed network and run. Rules that keep the result quiet and trustworthy:

- Baseline: the first completed run of a network records what is there (assets, open
  ports) and raises no "new asset"/"new port" alert; the same holds for the first port scan
  of any single asset. Only later differences produce changes and alerts.
- No duplicates: a host is matched to an existing asset by MAC, else by address (only when
  the MACs do not contradict each other), including assets that run the agent, whose
  interface addresses and MACs come from their inventory. Agent and network views of one
  host are one asset.
- Negative conclusions (port closed, host gone) only from complete runs: a cancelled or
  timed out run did not probe everything. A port is closed after 2 such runs, a host
  disappears after DISCOVERY_OFFLINE_AFTER_MISSES.
- Agent assets never get "disappeared" alerts (their agent says more); instead, an agent
  asset that answers on the network while its agent is silent gets "monitoring lost".
- One running job per network, enforced by the database (unique partial index).
"""

import ipaddress
import logging
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import exists, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import ConflictError
from app.discovery import probes
from app.discovery.classify import classify
from app.discovery.ports import SENSITIVE_PORTS, SERVICE_HINTS, parse_ports
from app.discovery.scanner import (
    HostObservation,
    NetworkScanner,
    Prober,
    ScanConfig,
    ScanResult,
)
from app.discovery.targets import DiscoveryScope, IPNetwork
from app.models.alert import AlertRule, AlertSeverity
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.change import AssetChange, ChangeCategory, ChangeKind
from app.models.discovery import DiscoveryJob, DiscoveryJobStatus, DiscoveryTrigger
from app.models.exposure import AssetPort, PortStateValue
from app.models.inventory import AssetInventory
from app.services.alert_service import AlertService, AlertThresholds
from app.services.reconciliation import interface_identity

logger = logging.getLogger(__name__)

# Complete runs in a row that find an open port not open before it counts as closed.
PORT_CLOSE_AFTER = 2


class DiscoveryBusyError(ConflictError):
    """A job for this network is already running."""


@dataclass(frozen=True)
class DiscoveryConfig:
    scope: DiscoveryScope
    scan: ScanConfig
    offline_after_misses: int = 3
    job_timeout: timedelta = timedelta(minutes=30)
    heartbeat_timeout: timedelta = timedelta(seconds=90)

    @classmethod
    def from_settings(cls, settings: Settings) -> "DiscoveryConfig":
        return cls(
            scope=settings.discovery_scope(),
            scan=ScanConfig(
                ports=parse_ports(settings.discovery_ports),
                timeout=settings.discovery_timeout_ms / 1000,
                concurrency=settings.discovery_concurrency,
                max_rate=settings.discovery_max_probes_per_second,
                icmp=settings.discovery_icmp,
                reverse_dns=settings.discovery_reverse_dns,
                deadline=settings.discovery_job_timeout_minutes * 60,
            ),
            offline_after_misses=settings.discovery_offline_after_misses,
            job_timeout=timedelta(minutes=settings.discovery_job_timeout_minutes),
            heartbeat_timeout=timedelta(seconds=settings.heartbeat_timeout_seconds),
        )


@dataclass
class JobSummary:
    job_id: str
    target: str
    status: DiscoveryJobStatus
    baseline: bool
    hosts_scanned: int = 0
    hosts_alive: int = 0
    hosts_new: int = 0
    open_ports: int = 0
    errors: list[str] = field(default_factory=list)


class DiscoveryService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        config: DiscoveryConfig,
        thresholds: AlertThresholds,
        *,
        prober_factory: Callable[[], Prober] | None = None,
        gateways: Callable[[], set[str]] = probes.default_gateways,
        cancel: threading.Event | None = None,
    ) -> None:
        self._sessions = session_factory
        self._config = config
        self._thresholds = thresholds
        self._prober_factory = prober_factory
        self._gateways = gateways
        self._cancel = cancel or threading.Event()

    def run(
        self, target: str | None = None, trigger: DiscoveryTrigger = DiscoveryTrigger.MANUAL
    ) -> list[JobSummary]:
        """Scan one target (inside the allowlist) or every allowed network. Raises
        TargetError for anything outside the allowlist; busy networks are skipped."""
        summaries = []
        for network in self._config.scope.resolve(target):
            if self._cancel.is_set():
                break
            try:
                summaries.append(self.run_network(network, trigger))
            except DiscoveryBusyError:
                logger.info("discovery already running for network", extra={"target": str(network)})
        return summaries

    def run_network(self, network: IPNetwork, trigger: DiscoveryTrigger) -> JobSummary:
        target = str(network)
        job_id, baseline = self._start(target, trigger)
        hosts = list(self._config.scope.hosts(network))
        logger.info(
            "discovery started",
            extra={"target": target, "hosts": len(hosts), "baseline": baseline},
        )
        try:
            prober = self._prober_factory() if self._prober_factory else None
            result = NetworkScanner(self._config.scan, prober, self._cancel).run(hosts)
            with self._sessions() as session:
                summary = ResultApplier(
                    session, self._config, self._thresholds, self._gateways()
                ).apply(job_id, network, result, baseline)
                session.commit()
        except Exception as exc:
            self._fail(job_id, exc)
            raise
        logger.info(
            "discovery finished",
            extra={
                "target": target,
                "status": summary.status.value,
                "alive": summary.hosts_alive,
                "new": summary.hosts_new,
                "open_ports": summary.open_ports,
            },
        )
        return summary

    def _start(self, target: str, trigger: DiscoveryTrigger) -> tuple[int, bool]:
        now = datetime.now(UTC)
        with self._sessions() as session:
            # A job left "running" by a crashed process would block the network forever.
            session.execute(
                update(DiscoveryJob)
                .where(
                    DiscoveryJob.target == target,
                    DiscoveryJob.status == DiscoveryJobStatus.RUNNING,
                    DiscoveryJob.started_at < now - 2 * self._config.job_timeout,
                )
                .values(status=DiscoveryJobStatus.FAILED, completed_at=now, errors=["interrupted"])
            )
            baseline = not session.scalar(
                select(
                    exists().where(
                        DiscoveryJob.target == target,
                        DiscoveryJob.status == DiscoveryJobStatus.COMPLETED,
                    )
                )
            )
            scan = self._config.scan
            job = DiscoveryJob(
                target=target,
                trigger=trigger,
                status=DiscoveryJobStatus.RUNNING,
                baseline=baseline,
                started_at=now,
                hosts_scanned=0,
                hosts_alive=0,
                hosts_new=0,
                open_ports=0,
                probes=0,
                error_count=0,
                parameters={
                    "ports": list(scan.ports),
                    "timeout_ms": int(scan.timeout * 1000),
                    "concurrency": scan.concurrency,
                    "max_probes_per_second": scan.max_rate,
                    "icmp": scan.icmp,
                    "reverse_dns": scan.reverse_dns,
                },
            )
            session.add(job)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise DiscoveryBusyError(f"discovery of {target} is already running") from exc
            return job.id, baseline

    def _fail(self, job_id: int, exc: Exception) -> None:
        logger.exception("discovery failed", extra={"job": job_id})
        with self._sessions() as session:
            job = session.get(DiscoveryJob, job_id)
            if job is not None and job.status == DiscoveryJobStatus.RUNNING:
                job.status = DiscoveryJobStatus.FAILED
                job.completed_at = datetime.now(UTC)
                job.errors = [repr(exc)[:300]]
                job.error_count = 1
                session.commit()


class AssetIndex:
    """Address/MAC → asset lookups for one run, loaded once (no query per host)."""

    def __init__(self, session: Session) -> None:
        self.by_mac: dict[str, Asset] = {}
        self.by_ip: dict[str, list[Asset]] = {}
        assets = session.scalars(select(Asset)).all()
        interfaces: dict[int, Any] = {
            row[0]: row[1]
            for row in session.execute(
                select(AssetInventory.asset_id, AssetInventory.data["interfaces"])
            )
        }
        for asset in assets:
            ips, macs = (
                interface_identity(interfaces.get(asset.id))
                if asset.is_managed
                else (
                    set(),
                    set(),
                )
            )
            self.add(asset, ips, macs)

    def add(self, asset: Asset, ips: set[str] | None = None, macs: set[str] | None = None) -> None:
        for mac in (macs or set()) | ({asset.mac_address} if asset.mac_address else set()):
            # An agent asset wins over a discovered record with the same MAC.
            current = self.by_mac.get(mac)
            if current is None or (asset.is_managed and not current.is_managed):
                self.by_mac[mac] = asset
        for ip in (ips or set()) | {asset.primary_ip}:
            self.by_ip.setdefault(ip, []).append(asset)

    def match(self, address: str, mac: str | None) -> Asset | None:
        if mac and mac in self.by_mac:
            return self.by_mac[mac]
        candidates = [
            a
            for a in self.by_ip.get(address, [])
            if not (mac and a.mac_address and a.mac_address != mac)
        ]
        # Agent assets first, then the most recently seen record of that address.
        candidates.sort(
            key=lambda a: (a.is_managed, a.last_network_seen_at or a.first_seen_at), reverse=True
        )
        return candidates[0] if candidates else None


class ResultApplier:
    def __init__(
        self,
        session: Session,
        config: DiscoveryConfig,
        thresholds: AlertThresholds,
        gateways: set[str],
    ) -> None:
        self._session = session
        self._config = config
        self._alerts = AlertService(session, thresholds)
        self._gateways = gateways

    def apply(
        self, job_id: int, network: IPNetwork, result: ScanResult, baseline: bool
    ) -> JobSummary:
        now = datetime.now(UTC)
        job = self._session.get(DiscoveryJob, job_id)
        assert job is not None  # noqa: S101  (created by this run)
        index = AssetIndex(self._session)
        seen: set[int] = set()
        new_assets = 0
        open_total = 0
        matched: list[tuple[HostObservation, Asset, bool]] = []
        for obs in result.observations:
            asset = index.match(obs.address, obs.mac)
            created = asset is None
            if asset is None:
                asset = self._create(obs, now)
                index.add(asset)
                new_assets += 1
            matched.append((obs, asset, created))
        # Existing port rows of every matched asset, in batches (not one query per host).
        ports_by_asset = self._load_ports([asset.id for _, asset, _ in matched])
        for obs, asset, created in matched:
            seen.add(asset.id)
            self._update_presence(asset, obs, network, now)
            rows = ports_by_asset.setdefault(asset.id, {})
            open_ports = self._update_ports(asset, obs, rows, result.complete, now)
            open_total += len(open_ports)
            self._classify(asset, open_ports, obs.address)
            if created and not baseline:
                self._announce(asset, open_ports, now)
            self._check_agent(asset, now)
        if result.complete:
            self._mark_missing(network, seen, now)

        if result.cancelled:
            job.status = DiscoveryJobStatus.CANCELLED
        elif result.timed_out:
            job.status = DiscoveryJobStatus.CANCELLED
            result.errors.insert(0, "stopped at DISCOVERY_JOB_TIMEOUT_MINUTES (partial results)")
        else:
            job.status = DiscoveryJobStatus.COMPLETED
        job.completed_at = datetime.now(UTC)
        job.hosts_scanned = result.hosts_scanned
        job.hosts_alive = len(result.observations)
        job.hosts_new = new_assets
        job.open_ports = open_total
        job.probes = result.probes
        job.error_count = len(result.errors)
        job.errors = result.errors[:50] or None
        # A partial first run is not a baseline: the next complete run will be.
        job.baseline = baseline and result.complete
        return JobSummary(
            job_id=str(job.public_id),
            target=job.target,
            status=job.status,
            baseline=job.baseline,
            hosts_scanned=job.hosts_scanned,
            hosts_alive=job.hosts_alive,
            hosts_new=new_assets,
            open_ports=open_total,
            errors=list(result.errors[:50]),
        )

    # --- per host ---------------------------------------------------------------------------

    def _create(self, obs: HostObservation, now: datetime) -> Asset:
        asset = Asset(
            monitoring_method=MonitoringMethod.DISCOVERED,
            primary_ip=obs.address,
            mac_address=obs.mac,
            status=AssetStatus.UNKNOWN,
            first_seen_at=now,
            discovered_at=now,
            network_misses=0,
        )
        self._session.add(asset)
        self._session.flush()
        return asset

    def _update_presence(
        self, asset: Asset, obs: HostObservation, network: IPNetwork, now: datetime
    ) -> None:
        if asset.network_status == AssetStatus.OFFLINE:
            self._change(asset, ChangeCategory.NETWORK, ChangeKind.APPEARED, obs.address, now)
            self._alerts.resolve_rule(asset, AlertRule.ASSET_DISAPPEARED, now)
        asset.network_status = AssetStatus.ONLINE
        asset.network_misses = 0
        asset.last_network_seen_at = now
        asset.discovered_at = asset.discovered_at or now
        asset.discovery_network = str(network)
        asset.discovery_sources = sorted(set(asset.discovery_sources or ()) | obs.sources)
        if obs.mac and not asset.mac_address:
            asset.mac_address = obs.mac
        if obs.reverse_dns:
            asset.reverse_dns = obs.reverse_dns
        if not asset.is_managed:
            # The agent reports its own address; a discovered host is where it was seen.
            asset.primary_ip = obs.address

    def _load_ports(self, asset_ids: list[int]) -> dict[int, dict[int, AssetPort]]:
        found: dict[int, dict[int, AssetPort]] = {}
        unique = sorted(set(asset_ids))
        for start in range(0, len(unique), 5000):
            for row in self._session.scalars(
                select(AssetPort).where(
                    AssetPort.asset_id.in_(unique[start : start + 5000]),
                    AssetPort.protocol == "tcp",
                )
            ):
                found.setdefault(row.asset_id, {})[row.port] = row
        return found

    def _update_ports(
        self,
        asset: Asset,
        obs: HostObservation,
        rows: dict[int, AssetPort],
        complete: bool,
        now: datetime,
    ) -> list[int]:
        # First port scan of this asset (in any run): it is the baseline, not a change.
        first_scan = asset.exposure_baseline_at is None
        opened: list[int] = []
        closed: list[int] = []
        for port, state in sorted(obs.ports.items()):
            row = rows.get(port)
            if state == probes.PortState.OPEN:
                if row is None:
                    row = AssetPort(
                        asset_id=asset.id,
                        protocol="tcp",
                        port=port,
                        state=PortStateValue.OPEN,
                        service_hint=SERVICE_HINTS.get(port),
                        first_seen_at=now,
                        opened_at=now,
                        last_seen_at=now,
                        misses=0,
                    )
                    self._session.add(row)
                    rows[port] = row
                    if not first_scan:
                        opened.append(port)
                elif row.state == PortStateValue.CLOSED:
                    row.state = PortStateValue.OPEN
                    row.opened_at = now
                    row.closed_at = None
                    opened.append(port)
                row.last_seen_at = now
                row.misses = 0
            elif (
                row is not None
                and row.state == PortStateValue.OPEN
                and complete
                and state in (probes.PortState.CLOSED, probes.PortState.FILTERED)
            ):
                row.misses += 1
                if row.misses >= PORT_CLOSE_AFTER:
                    row.state = PortStateValue.CLOSED
                    row.closed_at = now
                    closed.append(port)
        if obs.ports and first_scan:
            asset.exposure_baseline_at = now
        for port in opened:
            self._change(asset, ChangeCategory.EXPOSURE, ChangeKind.PORT_OPENED, _label(port), now)
        for port in closed:
            self._change(asset, ChangeCategory.EXPOSURE, ChangeKind.PORT_CLOSED, _label(port), now)
        if opened:
            sensitive = [p for p in opened if p in SENSITIVE_PORTS]
            self._alerts.raise_alert(
                asset,
                AlertRule.PORT_EXPOSED,
                AlertSeverity.CRITICAL if sensitive else AlertSeverity.WARNING,
                f"New listening service detected on {asset.display_name}: "
                + ", ".join(_label(p) for p in opened),
                now,
                {"ports": _port_details(opened), "address": obs.address},
            )
        if closed:
            self._alerts.raise_alert(
                asset,
                AlertRule.PORT_CLOSED,
                AlertSeverity.INFO,
                f"Service no longer reachable on {asset.display_name}: "
                + ", ".join(_label(p) for p in closed),
                now,
                {"ports": _port_details(closed), "address": obs.address},
            )
        return sorted(p for p, row in rows.items() if row.state == PortStateValue.OPEN)

    def _classify(self, asset: Asset, open_ports: Sequence[int], address: str) -> None:
        device_type, reason = classify(
            open_ports, is_gateway=address in self._gateways, agent_os=asset.os_name
        )
        # Keep an earlier conclusion when this run saw less (e.g. a port briefly down).
        if device_type is not None:
            asset.device_type = device_type
            asset.device_type_reason = (reason or "")[:255]

    def _announce(self, asset: Asset, open_ports: Sequence[int], now: datetime) -> None:
        details: dict[str, Any] = {
            "address": asset.primary_ip,
            "mac": asset.mac_address,
            "reverse_dns": asset.reverse_dns,
            "device_type": asset.device_type,
            "open_ports": list(open_ports),
        }
        if asset.reverse_dns or asset.device_type:
            self._alerts.raise_alert(
                asset,
                AlertRule.ASSET_DISCOVERED,
                AlertSeverity.INFO,
                f"New asset discovered: {asset.display_name} ({asset.primary_ip})",
                now,
                details,
            )
        else:
            self._alerts.raise_alert(
                asset,
                AlertRule.UNKNOWN_DEVICE,
                AlertSeverity.WARNING,
                f"Previously unknown device on the network: {asset.primary_ip}",
                now,
                details,
            )

    def _check_agent(self, asset: Asset, now: datetime) -> None:
        """Agent asset reachable on the network: is its agent still reporting?"""
        if not asset.is_managed or asset.last_seen_at is None:
            return
        if now - asset.last_seen_at > self._config.heartbeat_timeout:
            self._alerts.raise_alert(
                asset,
                AlertRule.MONITORING_LOST,
                AlertSeverity.WARNING,
                f"{asset.display_name} answers on the network but its Sentra agent stopped"
                " reporting",
                now,
                {"last_agent_contact": asset.last_seen_at.isoformat(), "address": asset.primary_ip},
            )

    def _mark_missing(self, network: IPNetwork, seen: set[int], now: datetime) -> None:
        scope = self._config.scope
        # Filtered in Python: `seen` can hold tens of thousands of ids (too many SQL params).
        candidates = self._session.scalars(
            select(Asset).where(
                Asset.discovery_network == str(network), Asset.last_network_seen_at.is_not(None)
            )
        ).all()
        for asset in candidates:
            if asset.id in seen:
                continue
            try:
                address = ipaddress.ip_address(asset.primary_ip)
            except ValueError:
                continue
            # Not probed this time (now excluded, or the network shrank): no conclusion.
            if address not in network or scope.is_excluded(address):
                continue
            asset.network_misses += 1
            if (
                asset.network_misses >= self._config.offline_after_misses
                and asset.network_status != AssetStatus.OFFLINE
            ):
                asset.network_status = AssetStatus.OFFLINE
                self._change(
                    asset, ChangeCategory.NETWORK, ChangeKind.DISAPPEARED, asset.primary_ip, now
                )
                if not asset.is_managed:
                    self._alerts.raise_alert(
                        asset,
                        AlertRule.ASSET_DISAPPEARED,
                        AlertSeverity.WARNING,
                        f"Asset no longer seen on the network: {asset.display_name}",
                        now,
                        {
                            "address": asset.primary_ip,
                            "last_network_seen_at": asset.last_network_seen_at.isoformat()
                            if asset.last_network_seen_at
                            else None,
                            "missed_runs": asset.network_misses,
                        },
                    )

    def _change(
        self, asset: Asset, category: ChangeCategory, kind: ChangeKind, item: str, now: datetime
    ) -> None:
        self._session.add(
            AssetChange(
                asset_id=asset.id,
                category=category,
                kind=kind,
                item=item[:512],
                details=None,
                collected_at=now,
                detected_at=now,
            )
        )


def _label(port: int) -> str:
    hint = SERVICE_HINTS.get(port)
    return f"{port}/tcp ({hint})" if hint else f"{port}/tcp"


def _port_details(ports: Sequence[int]) -> list[dict[str, Any]]:
    return [
        {
            "port": p,
            "protocol": "tcp",
            "service_hint": SERVICE_HINTS.get(p),
            "sensitive": p in SENSITIVE_PORTS,
        }
        for p in ports
    ]
