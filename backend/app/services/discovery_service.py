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
- Jobs del dashboard: se crean en cola (queued) y los ejecuta DiscoveryRunner en segundo
  plano; el navegador consulta el estado en lugar de mantener una petición abierta. La
  cancelación se pide en la base de datos y el scan la recoge en su siguiente latido.
"""

import ipaddress
import logging
import threading
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import exists, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError
from app.discovery import probes
from app.discovery.names import IdentityProber
from app.discovery.ports import SENSITIVE_PORTS, SERVICE_HINTS, parse_ports
from app.discovery.scanner import (
    HostObservation,
    NetworkScanner,
    Prober,
    ScanConfig,
    ScanResult,
)
from app.discovery.targets import DiscoveryScope, IPNetwork, TargetError
from app.models.alert import AlertRule, AlertSeverity
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.change import AssetChange, ChangeCategory, ChangeKind
from app.models.discovery import (
    ACTIVE_JOB_STATUSES,
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryStopReason,
    DiscoveryTrigger,
)
from app.models.exposure import AssetPort, PortStateValue
from app.models.inventory import AssetInventory
from app.services.alert_service import AlertService, AlertThresholds
from app.services.identification import oui_database, record_observation, refresh_identity
from app.services.reconciliation import interface_identity

logger = logging.getLogger(__name__)

# Complete runs in a row that find an open port not open before it counts as closed.
PORT_CLOSE_AFTER = 2
# Activos nuevos que un job recuerda para su detalle; el contador hosts_new no tiene límite.
MAX_NEW_ASSET_IDS = 500


class DiscoveryBusyError(ConflictError):
    """A job for this network is already queued or running."""

    code = "discovery_busy"


class DiscoveryJobFinishedError(ConflictError):
    """Se pidió cancelar un job que ya terminó."""

    code = "discovery_job_finished"


# Sin latido durante este tiempo, un job en cola o en curso pertenece a un proceso que ya no
# existe (caída, kill, reinicio): se marca como fallido para no bloquear su red para siempre.
# Holgado frente al intervalo de latido (segundos) para tolerar pausas breves de la base de
# datos sin declarar huérfano un scan que sigue vivo.
JOB_STALE_AFTER = timedelta(minutes=5)


@dataclass(frozen=True)
class DiscoveryConfig:
    scope: DiscoveryScope
    scan: ScanConfig
    offline_after_misses: int = 3
    job_timeout: timedelta = timedelta(minutes=30)
    heartbeat_timeout: timedelta = timedelta(seconds=90)
    # Cada cuánto se escribe el progreso y se comprueba si un operador pidió cancelar.
    progress_interval: float = 1.0

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
                identify=settings.discovery_identify,
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


class _AnySet:
    """Señal de parada compuesta: el scanner se detiene si cualquiera está activa.

    Combina la parada del proceso (shutdown del scheduler/runner) con la cancelación de
    este job concreto, sin que una cancelación de operador afecte a otros jobs.
    """

    def __init__(self, *events: threading.Event) -> None:
        self._events = events

    def is_set(self) -> bool:
        return any(event.is_set() for event in self._events)


class _ProgressReporter:
    """Hilo que publica el progreso real del scan y recoge la petición de cancelación.

    Va en un hilo aparte, y no en el event loop del scan, porque escribir en la base de
    datos bloquea: así una base lenta retrasa el progreso mostrado, nunca las sondas.
    """

    def __init__(
        self,
        sessions: sessionmaker[Session],
        job_id: int,
        scanner: NetworkScanner,
        cancel: threading.Event,
        interval: float,
    ) -> None:
        self._sessions = sessions
        self._job_id = job_id
        self._scanner = scanner
        self._cancel = cancel
        self._interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._loop, name=f"discovery-progress-{job_id}", daemon=True
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=10)

    def _loop(self) -> None:
        while not self._stop.wait(self._interval):
            try:
                self.tick()
            except Exception:
                # Un fallo al publicar progreso (base de datos caída un momento) no debe
                # abortar el scan; el siguiente intento lo vuelve a publicar.
                logger.warning("discovery progress not saved", exc_info=True)

    def tick(self) -> None:
        progress = self._scanner.progress()
        with self._sessions() as session:
            requested = session.execute(
                update(DiscoveryJob)
                .where(
                    DiscoveryJob.id == self._job_id,
                    DiscoveryJob.status == DiscoveryJobStatus.RUNNING,
                )
                .values(
                    hosts_scanned=progress.hosts_checked,
                    hosts_alive=progress.hosts_alive,
                    error_count=progress.errors,
                    probes=progress.probes,
                    progress={
                        "phase": progress.phase,
                        "details_total": progress.details_total,
                        "details_done": progress.details_done,
                    },
                    heartbeat_at=datetime.now(UTC),
                )
                .returning(DiscoveryJob.cancel_requested_at)
            ).first()
            session.commit()
        if requested is not None and requested[0] is not None:
            self._cancel.set()


class DiscoveryService:
    def __init__(
        self,
        session_factory: sessionmaker[Session],
        config: DiscoveryConfig,
        thresholds: AlertThresholds,
        *,
        prober_factory: Callable[[], Prober] | None = None,
        identity_factory: Callable[[], IdentityProber] | None = None,
        gateways: Callable[[], set[str]] = probes.default_gateways,
        cancel: threading.Event | None = None,
    ) -> None:
        self._sessions = session_factory
        self._config = config
        self._thresholds = thresholds
        self._prober_factory = prober_factory
        self._identity_factory = identity_factory
        self._gateways = gateways
        # Parada de todo el proceso (shutdown). La cancelación de un job concreto la pide un
        # operador en la base de datos y la recoge _ProgressReporter.
        self._cancel = cancel or threading.Event()

    @property
    def scope(self) -> DiscoveryScope:
        return self._config.scope

    def run(
        self,
        target: str | None = None,
        trigger: DiscoveryTrigger = DiscoveryTrigger.MANUAL,
        via: str | None = None,
    ) -> list[JobSummary]:
        """Scan one target (inside the allowlist) or every allowed network. Raises
        TargetError for anything outside the allowlist; busy networks are skipped."""
        summaries = []
        for network in self._config.scope.resolve(target):
            if self._cancel.is_set():
                break
            try:
                summaries.append(self.run_network(network, trigger, via))
            except DiscoveryBusyError:
                logger.info("discovery already running for network", extra={"target": str(network)})
        return summaries

    def run_network(
        self, network: IPNetwork, trigger: DiscoveryTrigger, via: str | None = None
    ) -> JobSummary:
        """Ejecución síncrona (CLI y scheduler): crea el job ya en curso y escanea."""
        hosts_total = sum(1 for _ in self._config.scope.hosts(network))
        job_id, baseline = self._start(str(network), trigger, via, hosts_total)
        return self._execute(job_id, network, baseline)

    # --- jobs pedidos desde el dashboard (DiscoveryRunner) -------------------------------------

    def enqueue(self, target: str, via: str) -> tuple[int, uuid.UUID]:
        """Crea un job en cola para `target` y devuelve (id interno, public_id).

        Valida el target con la misma allowlist que la CLI y el scheduler (TargetError si
        está fuera); la red queda reservada desde ahora por el índice único parcial.
        """
        [network] = self._config.scope.resolve(target)
        hosts_total = sum(1 for _ in self._config.scope.hosts(network))
        now = datetime.now(UTC)
        with self._sessions() as session:
            expire_stale_jobs(session, now)
            job = DiscoveryJob(
                target=str(network),
                trigger=DiscoveryTrigger.MANUAL,
                status=DiscoveryJobStatus.QUEUED,
                baseline=False,
                started_at=now,
                heartbeat_at=now,
                requested_via=via,
                hosts_total=hosts_total,
                progress={"phase": "queued"},
                parameters=self._parameters(),
                **_ZERO_COUNTERS,
            )
            session.add(job)
            try:
                session.commit()
            except IntegrityError as exc:
                session.rollback()
                raise DiscoveryBusyError(
                    f"discovery of {network} is already queued or running"
                ) from exc
            return job.id, job.public_id

    def run_job(self, job_id: int) -> JobSummary | None:
        """Ejecuta un job en cola. None si ya no estaba en cola (cancelado o expirado)."""
        now = datetime.now(UTC)
        with self._sessions() as session:
            job = session.scalar(
                select(DiscoveryJob).where(DiscoveryJob.id == job_id).with_for_update()
            )
            if job is None or job.status != DiscoveryJobStatus.QUEUED:
                return None
            try:
                # Se revalida al empezar: la allowlist es la del proceso que escanea.
                [network] = self._config.scope.resolve(job.target)
            except TargetError as exc:
                job.status = DiscoveryJobStatus.FAILED
                job.completed_at = now
                job.stop_reason = DiscoveryStopReason.ERROR
                job.errors = [str(exc)[:300]]
                job.error_count = 1
                session.commit()
                return None
            baseline = self._is_baseline(session, job.target)
            job.status = DiscoveryJobStatus.RUNNING
            # Desde aquí cuenta la duración; mientras estaba en cola era la hora de la petición.
            job.started_at = now
            job.heartbeat_at = now
            job.baseline = baseline
            job.progress = {"phase": "pending"}
            session.commit()
        return self._execute(job_id, network, baseline)

    def touch(self, job_ids: Sequence[int]) -> None:
        """Latido de jobs en cola de este proceso, para que no se tomen por huérfanos."""
        if not job_ids:
            return
        with self._sessions() as session:
            session.execute(
                update(DiscoveryJob)
                .where(
                    DiscoveryJob.id.in_(list(job_ids)),
                    DiscoveryJob.status == DiscoveryJobStatus.QUEUED,
                )
                .values(heartbeat_at=datetime.now(UTC))
            )
            session.commit()

    def abandon(self, job_ids: Sequence[int], reason: str) -> None:
        """Cierra jobs en cola que este proceso ya no ejecutará (apagado de la API)."""
        if not job_ids:
            return
        now = datetime.now(UTC)
        with self._sessions() as session:
            session.execute(
                update(DiscoveryJob)
                .where(
                    DiscoveryJob.id.in_(list(job_ids)),
                    DiscoveryJob.status == DiscoveryJobStatus.QUEUED,
                )
                .values(
                    status=DiscoveryJobStatus.CANCELLED,
                    completed_at=now,
                    stop_reason=DiscoveryStopReason.SHUTDOWN,
                    errors=[reason],
                )
            )
            session.commit()

    # --- internals ---------------------------------------------------------------------------

    def _parameters(self) -> dict[str, Any]:
        scan = self._config.scan
        return {
            "ports": list(scan.ports),
            "timeout_ms": int(scan.timeout * 1000),
            "concurrency": scan.concurrency,
            "max_probes_per_second": scan.max_rate,
            "icmp": scan.icmp,
            "reverse_dns": scan.reverse_dns,
            "identify": scan.identify,
        }

    @staticmethod
    def _is_baseline(session: Session, target: str) -> bool:
        # La primera ejecución COMPLETA de una red es la línea base. Un job cancelado o
        # fallido no cuenta: el siguiente completo sigue siendo baseline y no genera ruido.
        return not session.scalar(
            select(
                exists().where(
                    DiscoveryJob.target == target,
                    DiscoveryJob.status == DiscoveryJobStatus.COMPLETED,
                )
            )
        )

    def _execute(self, job_id: int, network: IPNetwork, baseline: bool) -> JobSummary:
        target = str(network)
        hosts = list(self._config.scope.hosts(network))
        logger.info(
            "discovery started",
            extra={"target": target, "hosts": len(hosts), "baseline": baseline},
        )
        operator_cancel = threading.Event()
        try:
            prober = self._prober_factory() if self._prober_factory else None
            identity = self._identity_factory() if self._identity_factory else None
            scanner = NetworkScanner(
                self._config.scan, prober, _AnySet(self._cancel, operator_cancel), identity
            )
            reporter = _ProgressReporter(
                self._sessions, job_id, scanner, operator_cancel, self._config.progress_interval
            )
            reporter.start()
            try:
                result = scanner.run(hosts)
            finally:
                # Parado antes de aplicar el resultado: así no compite con la transacción
                # final por la fila del job.
                reporter.stop()
            stop_reason = None
            if result.timed_out:
                stop_reason = DiscoveryStopReason.TIMEOUT
            elif result.cancelled:
                stop_reason = (
                    DiscoveryStopReason.OPERATOR
                    if operator_cancel.is_set()
                    else DiscoveryStopReason.SHUTDOWN
                )
            with self._sessions() as session:
                summary = ResultApplier(
                    session, self._config, self._thresholds, self._gateways()
                ).apply(job_id, network, result, baseline, stop_reason)
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

    def _start(
        self, target: str, trigger: DiscoveryTrigger, via: str | None, hosts_total: int
    ) -> tuple[int, bool]:
        now = datetime.now(UTC)
        with self._sessions() as session:
            # A job left "running" by a crashed process would block the network forever.
            expire_stale_jobs(session, now)
            baseline = self._is_baseline(session, target)
            job = DiscoveryJob(
                target=target,
                trigger=trigger,
                status=DiscoveryJobStatus.RUNNING,
                baseline=baseline,
                started_at=now,
                heartbeat_at=now,
                requested_via=via,
                hosts_total=hosts_total,
                progress={"phase": "pending"},
                parameters=self._parameters(),
                **_ZERO_COUNTERS,
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
            if job is not None and job.status in ACTIVE_JOB_STATUSES:
                job.status = DiscoveryJobStatus.FAILED
                job.completed_at = datetime.now(UTC)
                job.stop_reason = DiscoveryStopReason.ERROR
                job.errors = [repr(exc)[:300]]
                job.error_count = 1
                session.commit()


_ZERO_COUNTERS: dict[str, int] = {
    "hosts_scanned": 0,
    "hosts_alive": 0,
    "hosts_new": 0,
    "open_ports": 0,
    "probes": 0,
    "error_count": 0,
    "ports_opened": 0,
    "ports_closed": 0,
}


def expire_stale_jobs(session: Session, now: datetime) -> int:
    """Marca como fallidos los jobs activos sin latido reciente (su proceso ya no existe).

    Sin esto, un job que quedó "running" o "queued" tras una caída bloquearía su red para
    siempre por el índice único. No hace commit: lo hace quien llama.
    """
    result = session.execute(
        update(DiscoveryJob)
        .where(
            DiscoveryJob.status.in_(ACTIVE_JOB_STATUSES),
            func.coalesce(DiscoveryJob.heartbeat_at, DiscoveryJob.started_at)
            < now - JOB_STALE_AFTER,
        )
        .values(
            status=DiscoveryJobStatus.FAILED,
            completed_at=now,
            stop_reason=DiscoveryStopReason.INTERRUPTED,
            errors=["interrupted"],
        )
        .execution_options(synchronize_session=False)
    )
    return int(getattr(result, "rowcount", 0) or 0)


def request_cancel(session: Session, public_id: uuid.UUID) -> DiscoveryJob:
    """Pide cancelar un job. Un job en cola se cancela en el acto; uno en curso, en cuanto
    su proceso lo lea (segundos). Lanza NotFoundError o DiscoveryJobFinishedError."""
    now = datetime.now(UTC)
    # FOR UPDATE: serializa con el runner, que reclama el job en cola con el mismo bloqueo,
    # así un job no puede quedar a la vez "cancelado" y "en curso".
    job = session.scalar(
        select(DiscoveryJob).where(DiscoveryJob.public_id == public_id).with_for_update()
    )
    if job is None:
        raise NotFoundError("Discovery job not found")
    if job.status == DiscoveryJobStatus.QUEUED:
        job.status = DiscoveryJobStatus.CANCELLED
        job.completed_at = now
        job.cancel_requested_at = now
        job.stop_reason = DiscoveryStopReason.OPERATOR
    elif job.status == DiscoveryJobStatus.RUNNING:
        job.cancel_requested_at = job.cancel_requested_at or now
    else:
        raise DiscoveryJobFinishedError(f"Discovery job already {job.status.value}")
    session.commit()
    return job


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
        # Una sola carga (cacheada) de la base OUI por job, no una por host.
        self._oui = oui_database()
        self._change_details: dict[str, Any] | None = None
        self._ports_opened = 0
        self._ports_closed = 0

    def apply(
        self,
        job_id: int,
        network: IPNetwork,
        result: ScanResult,
        baseline: bool,
        stop_reason: DiscoveryStopReason | None = None,
    ) -> JobSummary:
        now = datetime.now(UTC)
        job = self._session.get(DiscoveryJob, job_id)
        assert job is not None  # noqa: S101  (created by this run)
        # Los cambios llevan el job que los detectó, para mostrarlos en su detalle ("Ver
        # cambios") sin depender de coincidencias de fechas.
        self._change_details = {"discovery_job_id": str(job.public_id)}
        self._ports_opened = 0
        self._ports_closed = 0
        new_asset_ids: list[str] = []
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
                if len(new_asset_ids) < MAX_NEW_ASSET_IDS:
                    new_asset_ids.append(str(asset.public_id))
            matched.append((obs, asset, created))
        # Existing port rows of every matched asset, in batches (not one query per host).
        ports_by_asset = self._load_ports([asset.id for _, asset, _ in matched])
        for obs, asset, created in matched:
            seen.add(asset.id)
            self._update_presence(asset, obs, network, now)
            rows = ports_by_asset.setdefault(asset.id, {})
            open_ports = self._update_ports(asset, obs, rows, result.complete, now)
            open_total += len(open_ports)
            self._identify(asset, obs, open_ports, created, now)
            if created and not baseline:
                self._announce(asset, open_ports, now)
            self._check_agent(asset, now)
        # CRÍTICO: solo un scan completo permite conclusiones negativas (host desaparecido,
        # puerto cerrado). Un scan cancelado, con timeout o fallido no sondeó todo, así que
        # no ver un host no prueba que se haya ido.
        if result.complete:
            self._mark_missing(network, seen, now)

        if result.timed_out:
            job.status = DiscoveryJobStatus.CANCELLED
            job.stop_reason = DiscoveryStopReason.TIMEOUT
            result.errors.insert(0, "stopped at DISCOVERY_JOB_TIMEOUT_MINUTES (partial results)")
        elif result.cancelled:
            job.status = DiscoveryJobStatus.CANCELLED
            job.stop_reason = stop_reason or DiscoveryStopReason.SHUTDOWN
        else:
            job.status = DiscoveryJobStatus.COMPLETED
            job.stop_reason = None
        job.completed_at = datetime.now(UTC)
        job.heartbeat_at = job.completed_at
        # Hosts realmente evaluados: en un scan parcial son menos que el total. Un host que
        # respondió a alguna sonda antes de la parada cuenta como evaluado aunque su fase de
        # liveness no terminara, para que "encontrados" nunca supere a "evaluados".
        checked = result.hosts_checked if result.hosts_checked is not None else result.hosts_scanned
        job.hosts_scanned = max(checked, len(result.observations))
        job.ports_opened = self._ports_opened
        job.ports_closed = self._ports_closed
        job.new_asset_ids = new_asset_ids or None
        job.progress = {"phase": "done"}
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
        # La línea base de exposición solo la fija un scan completo. Bug corregido en Fase 4D:
        # un primer scan cancelado solo había sondeado los puertos de liveness, fijaba la
        # base con datos incompletos y el siguiente scan completo alertaba como "puerto
        # nuevo" de todos los demás puertos que ya estaban abiertos.
        if obs.ports and first_scan and complete:
            asset.exposure_baseline_at = now
        self._ports_opened += len(opened)
        self._ports_closed += len(closed)
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

    def _identify(
        self,
        asset: Asset,
        obs: HostObservation,
        open_ports: Sequence[int],
        created: bool,
        now: datetime,
    ) -> None:
        # Sin tabla de rutas legible no sabemos quién es el gateway: None conserva lo anterior
        # en vez de "desclasificar" el router por un fallo de lectura del propio servidor.
        is_gateway = (obs.address in self._gateways) if self._gateways else None
        record_observation(asset, obs, is_gateway)
        change = refresh_identity(asset, open_ports, self._oui)
        # Un cambio de tipo es historial, no una alerta de seguridad: una heurística que
        # mejora con más evidencia no debe despertar a nadie.
        if change.reclassified and not created:
            self._change(
                asset,
                ChangeCategory.IDENTITY,
                ChangeKind.RECLASSIFIED,
                f"{change.previous_type or 'unknown'} -> {change.device_type or 'unknown'}",
                now,
                {"from": change.previous_type, "to": change.device_type},
            )

    def _announce(self, asset: Asset, open_ports: Sequence[int], now: datetime) -> None:
        details: dict[str, Any] = {
            "address": asset.primary_ip,
            "mac": asset.mac_address,
            "reverse_dns": asset.reverse_dns,
            "device_type": asset.device_type,
            "device_name": asset.device_name,
            "device_vendor": asset.device_vendor,
            "open_ports": list(open_ports),
        }
        if asset.device_name or asset.device_type:
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
        self,
        asset: Asset,
        category: ChangeCategory,
        kind: ChangeKind,
        item: str,
        now: datetime,
        extra: dict[str, Any] | None = None,
    ) -> None:
        details = {**(self._change_details or {}), **extra} if extra else self._change_details
        self._session.add(
            AssetChange(
                asset_id=asset.id,
                category=category,
                kind=kind,
                item=item[:512],
                details=details,
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
