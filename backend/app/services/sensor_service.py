"""Sensores distribuidos (Fase 5F, docs/distributed-sensors.md y docs/sensor-security.md).

Dos superficies:
- SensorService: administración desde el dashboard (listar, revocar, deshabilitar, rotar,
  tokens de enrolamiento) y creación de jobs de discovery para un sensor.
- SensorProtocol: lo que llama el propio sensor con su credencial (enroll, heartbeat, poll,
  start, results, complete, rotación).

Modelo de amenazas resumido:
- El sensor es un dato no confiable aunque esté autenticado. El site sale SIEMPRE de su
  credencial (nunca del cuerpo), cada dirección observada debe caer dentro del target del job
  y cada hora se valida contra el desfase permitido. El servidor decide la identidad de los
  activos con su propia lógica (ResultApplier, el mismo que el discovery local).
- Catálogo cerrado: discovery_basic y (Fase 6A) discovery_advanced, con parámetros fijos
  generados por el servidor. No hay campo de comando ni ejecución arbitraria.
- Entrega al menos una vez + idempotencia en el servidor: lotes por batch_id (mismo
  contenido = duplicado inocuo; otro contenido = 409), observaciones fusionadas por
  (job, dirección) y cierre repetido con el mismo intento = la misma respuesta.
- Un job sin empezar caduca (expires_at); un lease no confirmado vuelve a la cola mientras
  queden intentos; un job en curso cuyo sensor deja de responder falla como sensor_lost sin
  conclusiones negativas (un sensor caído no "hace desaparecer" activos).
"""

import hashlib
import ipaddress
import json
import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import distinct_on
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    DiscoveryOptionsError,
    DiscoveryTargetError,
    SensorEnrollmentInvalidError,
    SensorForbiddenError,
    SensorJobNotFoundError,
    SensorNotFoundError,
    SensorUnauthorizedError,
    SiteConflictError,
    SiteNotFoundError,
    SiteValidationError,
)
from app.core.security import (
    MAX_CREDENTIAL_LENGTH,
    SENSOR_CREDENTIAL_PREFIX,
    SENSOR_ENROLLMENT_PREFIX,
    generate_sensor_credential,
    generate_sensor_enrollment_token,
    hash_token,
)
from app.discovery.ports import parse_ports
from app.discovery.probes import PortState
from app.discovery.profiles import (
    HARD_MAX_DNS_QUERIES,
    HARD_MAX_DNS_TIMEOUT_MS,
    HARD_MAX_PORTS,
    HARD_MAX_TCP_RETRIES,
    HARD_MAX_TIMEOUT_MS,
    ProfileError,
    ResolvedProfile,
    check_scope,
)
from app.discovery.scanner import HostObservation, ScanConfig, ScanResult
from app.discovery.targets import (
    DiscoveryScope,
    IPNetwork,
    TargetError,
    parse_network,
    validate_network,
)
from app.models.discovery import (
    ACTIVE_JOB_STATUSES,
    DiscoveryJob,
    DiscoveryJobStatus,
    DiscoveryStopReason,
    DiscoveryTrigger,
)
from app.models.site import (
    OPEN_SENSOR_JOB_STATUSES,
    Sensor,
    SensorEnrollmentToken,
    SensorJob,
    SensorJobBatch,
    SensorObservation,
    Site,
)
from app.network.catalog import SNMP_JOB_TYPE
from app.schemas.network_protocol import SnmpJobCredentials, SnmpRecord
from app.schemas.site import (
    ObservationIn,
    PortObservation,
    SensorAction,
    SensorConfig,
    SensorEnrollmentCreate,
    SensorEnrollmentCreated,
    SensorEnrollmentList,
    SensorEnrollmentRead,
    SensorEnrollRequest,
    SensorEnrollResponse,
    SensorHeartbeatRequest,
    SensorHeartbeatResponse,
    SensorJobComplete,
    SensorJobCompleted,
    SensorJobList,
    SensorJobOut,
    SensorJobRead,
    SensorJobStart,
    SensorJobStarted,
    SensorList,
    SensorPollRequest,
    SensorPollResponse,
    SensorRead,
    SensorResultsRequest,
    SensorResultsResponse,
    SensorRevoke,
    SensorRotateResponse,
    SensorSummary,
)
from app.sensors.catalog import (
    DISCOVERY_ADVANCED,
    DISCOVERY_BASIC,
    JOB_TYPES,
    REQUIRED_CAPABILITY,
    filter_capabilities,
    version_status,
)
from app.services import audit_service
from app.services.alert_service import AlertThresholds
from app.services.audit_service import Actor
from app.services.site_service import enabled_networks, site_refs

logger = logging.getLogger(__name__)

TERMINAL_JOB_STATUSES = ("succeeded", "failed", "cancelled", "expired")
# Prioridad al fusionar el estado de un puerto visto en dos lotes: "open" es la evidencia
# positiva y nunca la pisa un "closed"/"filtered" posterior del mismo job.
_PORT_RANK = {"filtered": 0, "closed": 1, "open": 2}


# --- utilidades compartidas -------------------------------------------------------------------


def effective_status(sensor: Sensor, now: datetime, settings: Settings) -> str:
    """Estado que ve la UI. offline/stale es "no ha hablado", no "comprometido" ni "borrado"."""
    if sensor.status == "revoked":
        return "revoked"
    if sensor.status == "disabled":
        return "disabled"
    if sensor.last_seen_at is None:
        return "pending"
    age = (now - sensor.last_seen_at).total_seconds()
    if age <= settings.sensor_offline_after_seconds:
        return "online"
    if age <= settings.sensor_stale_after_seconds:
        return "offline"
    return "stale"


def _version_status(sensor: Sensor, settings: Settings) -> str:
    return version_status(
        sensor.sensor_version, settings.sensor_min_version, settings.sensor_recommended_version
    )


def _sensor_actor(sensor: Sensor, client_ip: str | None) -> Actor:
    return Actor(f"sensor:{sensor.public_id}", None, client_ip)


def _target_network(job: SensorJob) -> IPNetwork:
    return parse_network(str(job.parameters["target"]))


def _inside_site(network: IPNetwork, allowed: Sequence[str]) -> bool:
    for cidr in allowed:
        candidate = ipaddress.ip_network(cidr, strict=False)
        if network.version == candidate.version and network.subnet_of(candidate):  # type: ignore[arg-type]
            return True
    return False


def inside_site_networks(address: str, allowed: Sequence[str]) -> bool:
    """La dirección (o red) está dentro de alguna red habilitada del site."""
    try:
        network = parse_network(address)
    except TargetError:
        return False
    return _inside_site(network, allowed)


def _required_capabilities(job: SensorJob) -> set[str]:
    """Capacidades imprescindibles para recibir el job (SNMP depende de versión y módulos)."""
    from app.services import network_jobs

    if network_jobs.is_snmp_job(job):
        return network_jobs.required_capabilities(job)
    return {REQUIRED_CAPABILITY[job.job_type]}


def _finish_job(session: Session, job: SensorJob, now: datetime) -> None:
    """Cierra lo que cuelga de un job terminado sin cierre del sensor (consulta SNMP)."""
    from app.services import network_jobs

    network_jobs.finish_poll_for_job(session, job, now)


def _finish_discovery(
    discovery: DiscoveryJob | None,
    status: DiscoveryJobStatus,
    stop_reason: str | None,
    now: datetime,
    error: str | None = None,
) -> None:
    if discovery is None or discovery.status not in ACTIVE_JOB_STATUSES:
        return
    discovery.status = status
    discovery.completed_at = now
    discovery.heartbeat_at = now
    discovery.stop_reason = stop_reason
    discovery.progress = {"phase": "done"}
    if error is not None:
        discovery.errors = [error[:300]]
        discovery.error_count = 1


def _discovery_of(session: Session, job: SensorJob) -> DiscoveryJob | None:
    return session.get(DiscoveryJob, job.discovery_job_id) if job.discovery_job_id else None


def cancel_jobs(session: Session, ids: Sequence[int], reason: str) -> int:
    """Cancela en el acto jobs de sensor abiertos (incluidos los que están en curso).

    Para revocar, deshabilitar o retirar un sensor o un site: no se espera a que el sensor
    confirme. Lo que entregue después recibe 409 sensor_job_finished y nunca se aplica. Lo ya
    recibido se conserva como evidencia. Sin commit.
    """
    if not ids:
        return 0
    now = datetime.now(UTC)
    # Mismo orden de bloqueo que _job: primero los discovery, después los jobs de sensor.
    session.execute(
        select(DiscoveryJob.id)
        .where(
            DiscoveryJob.id.in_(
                select(SensorJob.discovery_job_id).where(SensorJob.id.in_(list(ids)))
            )
        )
        .order_by(DiscoveryJob.id)
        .with_for_update()
    )
    jobs = session.scalars(
        select(SensorJob)
        .where(SensorJob.id.in_(list(ids)), SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES))
        .order_by(SensorJob.id)
        .with_for_update()
    ).all()
    for job in jobs:
        job.status = "cancelled"
        job.finished_at = now
        job.cancel_requested_at = job.cancel_requested_at or now
        job.error_code = reason[:64]
        job.lease_expires_at = None
        discovery = _discovery_of(session, job)
        if discovery is not None and discovery.status in ACTIVE_JOB_STATUSES:
            discovery.cancel_requested_at = discovery.cancel_requested_at or now
            _finish_discovery(discovery, DiscoveryJobStatus.CANCELLED, reason[:32], now)
        _finish_job(session, job, now)
    return len(jobs)


def request_sensor_cancel(session: Session, discovery: DiscoveryJob, now: datetime) -> None:
    """Cancelación pedida por un operador sobre un discovery ejecutado por un sensor.

    Sin empezar (pending/leased): se cancela al momento. En curso: se marca y el sensor lo
    recibe en su siguiente heartbeat o lote, se para y entrega lo observado como resultado
    parcial (sin conclusiones negativas). Sin commit.
    """
    job = session.scalar(
        select(SensorJob).where(SensorJob.discovery_job_id == discovery.id).with_for_update()
    )
    discovery.cancel_requested_at = discovery.cancel_requested_at or now
    if job is None or job.status in ("pending", "leased"):
        if job is not None:
            cancel_jobs(session, [job.id], DiscoveryStopReason.OPERATOR.value)
        _finish_discovery(
            discovery, DiscoveryJobStatus.CANCELLED, DiscoveryStopReason.OPERATOR, now
        )
        return
    if job.status == "running":
        job.cancel_requested_at = job.cancel_requested_at or now


def sweep(session: Session, now: datetime, sensor_id: int | None = None) -> dict[str, int]:
    """Caduca jobs sin empezar, devuelve a la cola leases vencidos y falla jobs huérfanos.

    Lo llama el job periódico sensor-maintenance y, de forma perezosa, el poll de cada sensor
    (así funciona aunque los jobs en segundo plano estén apagados). Sin commit.
    """
    counts = {"expired": 0, "requeued": 0, "lease_failed": 0, "lost": 0}
    query = (
        select(SensorJob)
        .where(
            SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES),
            (
                (SensorJob.status == "pending") & (SensorJob.expires_at <= now)
                | (SensorJob.status != "pending") & (SensorJob.lease_expires_at <= now)
            ),
        )
        .order_by(SensorJob.id)
        .limit(500)
        .with_for_update(skip_locked=True)
    )
    if sensor_id is not None:
        query = query.where(SensorJob.sensor_id == sensor_id)
    for job in session.scalars(query).all():
        discovery = _discovery_of(session, job)
        if job.status == "pending":
            job.status = "expired"
            job.finished_at = now
            job.error_code = "not_started"
            _finish_discovery(
                discovery,
                DiscoveryJobStatus.FAILED,
                DiscoveryStopReason.EXPIRED,
                now,
                "no sensor started this job before it expired",
            )
            counts["expired"] += 1
        elif job.status == "leased":
            if job.attempt < job.max_attempts and job.expires_at > now:
                # El sensor recogió el job pero no confirmó el inicio (caída, red): otro poll
                # de ESTE mismo sensor podrá recogerlo de nuevo con un intento nuevo.
                job.status = "pending"
                job.leased_at = None
                job.lease_expires_at = None
                counts["requeued"] += 1
            else:
                job.status = "failed"
                job.finished_at = now
                job.error_code = "lease_expired"
                job.lease_expires_at = None
                _finish_discovery(
                    discovery,
                    DiscoveryJobStatus.FAILED,
                    DiscoveryStopReason.EXPIRED,
                    now,
                    "the sensor never confirmed the start of this job",
                )
                counts["lease_failed"] += 1
        else:
            # En curso y sin cierre dentro de su plazo: el sensor se perdió. Lo recibido se
            # guarda como evidencia pero NO se aplica: un scan incompleto de un sensor caído no
            # permite concluir nada (ni presencia parcial sin su cierre explícito).
            job.status = "failed"
            job.finished_at = now
            job.error_code = "sensor_lost"
            job.lease_expires_at = None
            _finish_discovery(
                discovery,
                DiscoveryJobStatus.FAILED,
                DiscoveryStopReason.INTERRUPTED,
                now,
                "the sensor stopped reporting before completing this job",
            )
            counts["lost"] += 1
        if job.status in TERMINAL_JOB_STATUSES:
            _finish_job(session, job, now)
    return counts


def run_sensor_maintenance(session: Session) -> dict[str, int]:
    counts = sweep(session, datetime.now(UTC))
    session.commit()
    if any(counts.values()):
        logger.info("sensor maintenance", extra=counts)
    return counts


def _job_parameters(settings: Settings, network: IPNetwork) -> dict[str, Any]:
    """Parámetros fijos de discovery_basic, generados por el servidor (nunca por el cliente)."""
    return {
        "target": str(network),
        "ports": list(parse_ports(settings.discovery_ports)),
        "timeout_ms": settings.discovery_timeout_ms,
        "concurrency": settings.discovery_concurrency,
        "max_probes_per_second": settings.discovery_max_probes_per_second,
        "icmp": settings.discovery_icmp,
        "reverse_dns": settings.discovery_reverse_dns,
        "arp": True,
        "deadline_seconds": settings.discovery_job_timeout_minutes * 60,
    }


def _config(session: Session, settings: Settings, sensor: Sensor, site: Site) -> SensorConfig:
    jobs_enabled = (
        sensor.status == "active"
        and site.status == "active"
        and _version_status(sensor, settings) != "unsupported"
    )
    return SensorConfig(
        site_id=site.public_id,
        site_name=site.name,
        allowed_networks=enabled_networks(session, site.id) if jobs_enabled else [],
        jobs_enabled=jobs_enabled,
        heartbeat_interval_seconds=settings.sensor_heartbeat_interval_seconds,
        poll_interval_seconds=settings.sensor_poll_interval_seconds,
        max_observations_per_batch=settings.sensor_max_observations_per_batch,
        max_batch_bytes=settings.sensor_max_request_kb * 1024,
        max_ports_per_observation=settings.sensor_max_ports_per_observation,
        max_hosts_per_job=settings.discovery_max_hosts_per_network,
        max_concurrency=settings.discovery_concurrency,
        max_probes_per_second=settings.discovery_max_probes_per_second,
        max_timeout_ms=settings.discovery_timeout_ms,
        # Fase 6A: topes de discovery_advanced. Un sensor 0.1.x ignora estas claves y nunca
        # recibe jobs avanzados (no declara la capacidad).
        advanced_max_timeout_ms=HARD_MAX_TIMEOUT_MS,
        max_dns_timeout_ms=HARD_MAX_DNS_TIMEOUT_MS,
        max_tcp_retries=HARD_MAX_TCP_RETRIES,
        max_dns_queries=HARD_MAX_DNS_QUERIES,
        advanced_max_ports=HARD_MAX_PORTS,
        max_deadline_seconds=settings.discovery_job_timeout_minutes * 60,
    )


# --- administración (dashboard) --------------------------------------------------------------


@dataclass
class _JobContext:
    sensors: dict[int, uuid.UUID]
    sites: dict[int, uuid.UUID]
    discovery: dict[int, uuid.UUID]


class SensorService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- lectura -----------------------------------------------------------------------------

    def _job_reads(self, jobs: Sequence[SensorJob]) -> list[SensorJobRead]:
        if not jobs:
            return []
        session = self._session
        sensors = {
            row.id: row.public_id
            for row in session.execute(
                select(Sensor.id, Sensor.public_id).where(
                    Sensor.id.in_({job.sensor_id for job in jobs})
                )
            )
        }
        sites = {key: ref.public_id for key, ref in site_refs(session).items()}
        discovery_ids = {job.discovery_job_id for job in jobs if job.discovery_job_id}
        discovery = (
            {
                row.id: row.public_id
                for row in session.execute(
                    select(DiscoveryJob.id, DiscoveryJob.public_id).where(
                        DiscoveryJob.id.in_(discovery_ids)
                    )
                )
            }
            if discovery_ids
            else {}
        )
        ctx = _JobContext(sensors, sites, discovery)
        return [self._job_read(job, ctx) for job in jobs]

    @staticmethod
    def _job_read(job: SensorJob, ctx: _JobContext) -> SensorJobRead:
        target = job.parameters.get("target") if isinstance(job.parameters, dict) else None
        return SensorJobRead(
            job_id=job.public_id,
            site_id=ctx.sites[job.site_id],
            sensor_id=ctx.sensors[job.sensor_id],
            job_type=job.job_type,
            status=job.status,
            attempt=job.attempt,
            max_attempts=job.max_attempts,
            created_at=job.created_at,
            created_by=job.created_by,
            expires_at=job.expires_at,
            leased_at=job.leased_at,
            lease_expires_at=job.lease_expires_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            error_code=job.error_code,
            discovery_job_id=ctx.discovery.get(job.discovery_job_id)
            if job.discovery_job_id
            else None,
            target=str(target) if target else None,
            observations_received=job.observations_received,
            batches_received=job.batches_received,
        )

    def _reads(self, sensors: Sequence[Sensor]) -> list[SensorRead]:
        if not sensors:
            return []
        session = self._session
        now = datetime.now(UTC)
        ids = [sensor.id for sensor in sensors]
        sites = site_refs(session)
        pending = {
            int(sensor_id): int(count)
            for sensor_id, count in session.execute(
                select(SensorJob.sensor_id, func.count())
                .where(SensorJob.sensor_id.in_(ids), SensorJob.status == "pending")
                .group_by(SensorJob.sensor_id)
            )
        }
        # Último job de cada sensor en UNA consulta (DISTINCT ON), sin N+1.
        last_jobs = session.scalars(
            select(SensorJob)
            .where(SensorJob.sensor_id.in_(ids))
            .ext(distinct_on(SensorJob.sensor_id))
            .order_by(SensorJob.sensor_id, SensorJob.created_at.desc(), SensorJob.id.desc())
        ).all()
        last_reads = dict(
            zip((job.sensor_id for job in last_jobs), self._job_reads(last_jobs), strict=True)
        )
        reads = []
        for sensor in sensors:
            health = sensor.health or {}
            last_ok = health.get("last_successful_job_at")
            reads.append(
                SensorRead(
                    sensor_id=sensor.public_id,
                    name=sensor.name,
                    site_id=sites[sensor.site_id].public_id,
                    site_name=sites[sensor.site_id].name,
                    status=effective_status(sensor, now, self._settings),
                    hostname=sensor.hostname,
                    platform=sensor.platform,
                    sensor_version=sensor.sensor_version,
                    version_status=_version_status(sensor, self._settings),
                    capabilities=list(sensor.capabilities or []),
                    last_seen_at=sensor.last_seen_at,
                    enrolled_at=sensor.enrolled_at,
                    created_at=sensor.created_at,
                    disabled_at=sensor.disabled_at,
                    revoked_at=sensor.revoked_at,
                    revoke_reason=sensor.revoke_reason,
                    rotation_pending=sensor.rotation_requested_at is not None,
                    credential_issued_at=sensor.credential_issued_at,
                    queue_depth=health.get("queue_depth"),
                    spool_items=health.get("spool_items"),
                    uptime_seconds=health.get("uptime_seconds"),
                    last_successful_job_at=datetime.fromisoformat(last_ok) if last_ok else None,
                    clock_skew_seconds=sensor.clock_skew_seconds,
                    pending_jobs=pending.get(sensor.id, 0),
                    last_job=last_reads.get(sensor.id),
                    version=sensor.version,
                )
            )
        return reads

    def list(self, site_id: int | None = None) -> SensorList:
        query = select(Sensor).order_by(Sensor.site_id, Sensor.name, Sensor.id)
        if site_id is not None:
            query = query.where(Sensor.site_id == site_id)
        items = self._reads(self._session.scalars(query).all())
        keys = ("pending", "online", "offline", "stale", "disabled", "revoked")
        counts = dict.fromkeys(keys, 0)
        for item in items:
            counts[item.status] += 1
        return SensorList(items=items, summary=SensorSummary(total=len(items), **counts))

    def _row(self, public_id: uuid.UUID, *, lock: bool = False) -> Sensor:
        query = select(Sensor).where(Sensor.public_id == public_id)
        if lock:
            query = query.with_for_update()
        sensor = self._session.scalar(query)
        if sensor is None:
            raise SensorNotFoundError("Sensor not found")
        return sensor

    def get(self, public_id: uuid.UUID) -> SensorRead:
        return self._reads([self._row(public_id)])[0]

    def jobs(self, public_id: uuid.UUID, limit: int) -> SensorJobList:
        sensor = self._row(public_id)
        rows = self._session.scalars(
            select(SensorJob)
            .where(SensorJob.sensor_id == sensor.id)
            .order_by(SensorJob.created_at.desc(), SensorJob.id.desc())
            .limit(limit)
        ).all()
        return SensorJobList(items=self._job_reads(rows))

    # --- acciones ----------------------------------------------------------------------------

    def _locked_for_action(self, public_id: uuid.UUID, version: int) -> Sensor:
        sensor = self._row(public_id, lock=True)
        if sensor.status == "revoked":
            raise SiteConflictError("sensor_revoked", "Sensor is revoked; enroll a new sensor")
        if sensor.version != version:
            raise SiteConflictError(
                "sensor_conflict",
                "Sensor changed since it was loaded; reload and retry",
                [{"current_version": sensor.version}],
            )
        return sensor

    def _open_job_ids(self, sensor: Sensor) -> Sequence[int]:
        return list(
            self._session.scalars(
                select(SensorJob.id).where(
                    SensorJob.sensor_id == sensor.id,
                    SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES),
                )
            )
        )

    def revoke(self, public_id: uuid.UUID, body: SensorRevoke, actor: Actor) -> SensorRead:
        sensor = self._locked_for_action(public_id, body.version)
        now = datetime.now(UTC)
        sensor.status = "revoked"
        sensor.revoked_at = now
        sensor.revoked_by = actor.name
        sensor.revoke_reason = body.reason
        # La credencial pendiente de una rotación tampoco debe servir para nada.
        sensor.pending_credential_hash = None
        sensor.rotation_requested_at = None
        sensor.version += 1
        cancelled = cancel_jobs(self._session, self._open_job_ids(sensor), "sensor_revoked")
        audit_service.record(
            self._session,
            actor,
            "sensor_revoked",
            target_type="sensor",
            target_id=sensor.public_id,
            details={"reason": body.reason, "jobs_cancelled": cancelled},
            commit=False,
        )
        self._session.commit()
        logger.info("sensor revoked", extra={"sensor": str(sensor.public_id)})
        return self.get(public_id)

    def disable(self, public_id: uuid.UUID, body: SensorAction, actor: Actor) -> SensorRead:
        sensor = self._locked_for_action(public_id, body.version)
        if sensor.status != "disabled":
            sensor.status = "disabled"
            sensor.disabled_at = datetime.now(UTC)
            sensor.version += 1
            cancelled = cancel_jobs(self._session, self._open_job_ids(sensor), "sensor_disabled")
            audit_service.record(
                self._session,
                actor,
                "sensor_disabled",
                target_type="sensor",
                target_id=sensor.public_id,
                details={"jobs_cancelled": cancelled},
                commit=False,
            )
        self._session.commit()
        return self.get(public_id)

    def enable(self, public_id: uuid.UUID, body: SensorAction, actor: Actor) -> SensorRead:
        sensor = self._locked_for_action(public_id, body.version)
        if sensor.status != "active":
            sensor.status = "active"
            sensor.disabled_at = None
            sensor.version += 1
            audit_service.record(
                self._session,
                actor,
                "sensor_enabled",
                target_type="sensor",
                target_id=sensor.public_id,
                commit=False,
            )
        self._session.commit()
        return self.get(public_id)

    def request_rotation(
        self, public_id: uuid.UUID, body: SensorAction, actor: Actor
    ) -> SensorRead:
        """Pide al sensor que rote su credencial en el siguiente heartbeat (el secreto nuevo
        lo genera el servidor y solo viaja al sensor; el admin nunca lo ve)."""
        sensor = self._locked_for_action(public_id, body.version)
        sensor.rotation_requested_at = datetime.now(UTC)
        sensor.version += 1
        audit_service.record(
            self._session,
            actor,
            "sensor_credential_rotation_requested",
            target_type="sensor",
            target_id=sensor.public_id,
            commit=False,
        )
        self._session.commit()
        return self.get(public_id)

    # --- tokens de enrolamiento ---------------------------------------------------------------

    def _enrollment_read(
        self, row: SensorEnrollmentToken, now: datetime, sensors: dict[int, uuid.UUID]
    ) -> SensorEnrollmentRead:
        site = site_refs(self._session)[row.site_id]
        return SensorEnrollmentRead(
            enrollment_id=row.public_id,
            site_id=site.public_id,
            site_name=site.name,
            name=row.sensor_name,
            state=row.state(now),
            created_at=row.created_at,
            expires_at=row.expires_at,
            used_at=row.used_at,
            revoked_at=row.revoked_at,
            sensor_id=sensors.get(row.sensor_id) if row.sensor_id else None,
            created_by=row.created_by,
        )

    def _sensor_ids(self, rows: Sequence[SensorEnrollmentToken]) -> dict[int, uuid.UUID]:
        ids = {row.sensor_id for row in rows if row.sensor_id}
        if not ids:
            return {}
        return {
            row.id: row.public_id
            for row in self._session.execute(
                select(Sensor.id, Sensor.public_id).where(Sensor.id.in_(ids))
            )
        }

    def enrollment_tokens(self, site_id: int | None, limit: int = 100) -> SensorEnrollmentList:
        query = (
            select(SensorEnrollmentToken)
            .order_by(SensorEnrollmentToken.created_at.desc(), SensorEnrollmentToken.id.desc())
            .limit(limit)
        )
        if site_id is not None:
            query = query.where(SensorEnrollmentToken.site_id == site_id)
        rows = self._session.scalars(query).all()
        now = datetime.now(UTC)
        sensors = self._sensor_ids(rows)
        return SensorEnrollmentList(items=[self._enrollment_read(r, now, sensors) for r in rows])

    def create_enrollment_token(
        self, body: SensorEnrollmentCreate, actor: Actor
    ) -> SensorEnrollmentCreated:
        site = self._session.scalar(select(Site).where(Site.public_id == body.site_id))
        if site is None:
            raise SiteNotFoundError("Site not found")
        if site.status != "active":
            raise SiteConflictError("site_not_active", f"Site is {site.status}")
        now = datetime.now(UTC)
        minutes = body.ttl_minutes or self._settings.sensor_enrollment_token_ttl_minutes
        token = generate_sensor_enrollment_token()
        row = SensorEnrollmentToken(
            site_id=site.id,
            sensor_name=body.name,
            token_hash=hash_token(token),
            created_by=actor.name,
            created_at=now,
            expires_at=now + timedelta(minutes=minutes),
        )
        self._session.add(row)
        self._session.flush()
        audit_service.record(
            self._session,
            actor,
            "sensor_enrollment_token_created",
            target_type="sensor_enrollment",
            target_id=row.public_id,
            details={"site_id": str(site.public_id), "name": body.name, "ttl_minutes": minutes},
            commit=False,
        )
        self._session.commit()
        server = self._settings.agent_server_url or "https://<sentra-server>"
        return SensorEnrollmentCreated(
            **self._enrollment_read(row, now, {}).model_dump(),
            token=token,
            command_example=f"sentra-sensor enroll --server {server} --token {token}",
        )

    def revoke_enrollment_token(self, public_id: uuid.UUID, actor: Actor) -> SensorEnrollmentRead:
        row = self._session.scalar(
            select(SensorEnrollmentToken)
            .where(SensorEnrollmentToken.public_id == public_id)
            .with_for_update()
        )
        if row is None:
            raise SensorNotFoundError("Sensor enrollment token not found")
        now = datetime.now(UTC)
        if row.used_at is not None:
            raise SiteConflictError(
                "sensor_enrollment_consumed", "Token already used; revoke the sensor instead"
            )
        if row.revoked_at is None:
            row.revoked_at = now
            audit_service.record(
                self._session,
                actor,
                "sensor_enrollment_token_revoked",
                target_type="sensor_enrollment",
                target_id=row.public_id,
                commit=False,
            )
        self._session.commit()
        return self._enrollment_read(row, now, self._sensor_ids([row]))

    # --- discovery por sensor -----------------------------------------------------------------

    def create_discovery(
        self,
        target: str,
        site_public: uuid.UUID,
        sensor_public: uuid.UUID,
        actor: Actor,
        via: str,
        profile: ResolvedProfile | None = None,
    ) -> uuid.UUID:
        """Crea el discovery (en cola) y su job para el sensor indicado. Devuelve su public_id.

        Validaciones en el servidor (el formulario de la web no es una frontera): site activo;
        sensor del MISMO site, activo, con versión soportada y la capacidad necesaria; target
        válido (mismas reglas que el discovery local) y dentro de una red habilitada del site.
        """
        from app.services.discovery_service import DiscoveryBusyError

        session = self._session
        settings = self._settings
        site = session.scalar(select(Site).where(Site.public_id == site_public))
        if site is None:
            raise SiteNotFoundError("Site not found")
        if site.status != "active":
            raise SiteConflictError("site_not_active", f"Site is {site.status}")
        sensor = session.scalar(select(Sensor).where(Sensor.public_id == sensor_public))
        if sensor is None:
            raise SensorNotFoundError("Sensor not found")
        if sensor.site_id != site.id:
            raise SiteConflictError("sensor_not_available", "The sensor belongs to another site")
        if sensor.status != "active":
            raise SiteConflictError("sensor_not_available", f"Sensor is {sensor.status}")
        if _version_status(sensor, settings) == "unsupported":
            raise SiteConflictError("sensor_not_available", "Sensor version is no longer supported")
        job_type = DISCOVERY_BASIC if profile is None else DISCOVERY_ADVANCED
        if REQUIRED_CAPABILITY[job_type] not in (sensor.capabilities or []):
            # Fase 6A: un sensor 0.1.x solo declara discovery_basic; nunca recibe un job
            # avanzado que no sabe validar ni ejecutar.
            raise SiteConflictError(
                "sensor_not_available",
                "Sensor did not declare the capability for this discovery type",
                [{"required_capability": REQUIRED_CAPABILITY[job_type]}],
            )
        try:
            network = validate_network(
                parse_network(target),
                settings.discovery_max_hosts_per_network,
                settings.discovery_allow_public_networks,
            )
        except TargetError as exc:
            raise DiscoveryTargetError(str(exc)) from exc
        if not _inside_site(network, enabled_networks(session, site.id)):
            raise DiscoveryTargetError(
                f"{network} is outside the enabled networks of site {site.name!r}: refused"
            )
        hosts_total = sum(1 for _ in network.hosts())
        if profile is not None:
            try:
                check_scope(profile, hosts_total)
            except ProfileError as exc:
                raise DiscoveryOptionsError(exc.code, str(exc), exc.details) from exc
            parameters = profile.parameters(str(network), for_sensor=True)
        else:
            parameters = _job_parameters(settings, network)
        now = datetime.now(UTC)
        sweep(session, now, sensor.id)
        discovery = DiscoveryJob(
            target=str(network),
            site_id=site.id,
            execution_target="sensor",
            sensor_id=sensor.id,
            trigger=DiscoveryTrigger.MANUAL,
            status=DiscoveryJobStatus.QUEUED,
            baseline=False,
            started_at=now,
            heartbeat_at=now,
            requested_via=via,
            hosts_total=hosts_total,
            progress={"phase": "queued"},
            parameters=parameters,
            profile=profile.name if profile is not None else None,
            hosts_scanned=0,
            hosts_alive=0,
            hosts_new=0,
            open_ports=0,
            probes=0,
            error_count=0,
            ports_opened=0,
            ports_closed=0,
        )
        try:
            with session.begin_nested():
                session.add(discovery)
                session.flush()
        except IntegrityError as exc:
            raise DiscoveryBusyError(
                f"discovery of {network} in this site is already queued or running"
            ) from exc
        job = SensorJob(
            site_id=site.id,
            sensor_id=sensor.id,
            job_type=job_type,
            parameters=dict(parameters),
            status="pending",
            created_by=actor.name,
            created_at=now,
            expires_at=now + timedelta(minutes=settings.sensor_job_ttl_minutes),
            max_attempts=settings.sensor_job_max_attempts,
            idempotency_key=str(discovery.public_id),
            discovery_job_id=discovery.id,
        )
        session.add(job)
        session.flush()
        audit_service.record(
            session,
            actor,
            "sensor_job_created",
            target_type="sensor_job",
            target_id=job.public_id,
            details={
                "job_type": job_type,
                "profile": profile.name if profile is not None else None,
                "target": str(network),
                "site_id": str(site.public_id),
                "sensor_id": str(sensor.public_id),
                "discovery_job_id": str(discovery.public_id),
            },
            commit=False,
        )
        session.commit()
        return discovery.public_id


# --- protocolo del sensor ---------------------------------------------------------------------


def _payload_sha256(observations: list[ObservationIn]) -> str:
    """Huella canónica del contenido de un lote (orden de claves fijo)."""
    data = []
    for obs in observations:
        item = obs.model_dump(mode="json")
        # Fase 6A: los campos nuevos solo entran en la huella si vienen con valor. Así un
        # lote de un sensor 0.1.x reenviado tras actualizar el servidor conserva su huella y
        # sigue contando como duplicado inocuo, no como conflicto 409.
        for key in ("rtt_ms", "forward_dns_match"):
            if item.get(key) is None:
                item.pop(key, None)
        data.append(item)
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


class SensorProtocol:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    # --- identidad ---------------------------------------------------------------------------

    def enroll(
        self, token: str | None, body: SensorEnrollRequest, client_ip: str | None
    ) -> SensorEnrollResponse:
        """Canjea un token de un solo uso por la identidad del sensor.

        Mismo 401 para cualquier motivo (desconocido, caducado, usado, revocado, site
        inactivo): el motivo concreto solo va al log, con el id del token, nunca el token.
        """
        session = self._session
        invalid = SensorEnrollmentInvalidError("Invalid sensor enrollment token")
        if (
            not token
            or not token.startswith(SENSOR_ENROLLMENT_PREFIX)
            or len(token) > MAX_CREDENTIAL_LENGTH
        ):
            logger.warning("sensor enrollment rejected", extra={"reason": "malformed"})
            raise invalid
        row = session.scalar(
            select(SensorEnrollmentToken)
            .where(SensorEnrollmentToken.token_hash == hash_token(token))
            .with_for_update()
        )
        now = datetime.now(UTC)
        if row is None:
            logger.warning("sensor enrollment rejected", extra={"reason": "unknown"})
            raise invalid
        site = session.get(Site, row.site_id)
        reason = None
        if row.state(now) != "active":
            reason = row.state(now)
        elif site is None or site.status != "active":
            reason = "site_not_active"
        if reason is not None or site is None:
            logger.warning(
                "sensor enrollment rejected",
                extra={"reason": reason, "token_id": str(row.public_id)},
            )
            raise invalid
        credential = generate_sensor_credential()
        sensor = Sensor(
            site_id=site.id,
            name=row.sensor_name,
            status="active",
            credential_hash=hash_token(credential),
            credential_issued_at=now,
            enrolled_at=now,
            hostname=body.hostname,
            platform=body.platform,
            sensor_version=body.sensor_version,
            capabilities=filter_capabilities(body.capabilities),
        )
        session.add(sensor)
        session.flush()
        # Consumido en la misma transacción que crea el sensor, con la fila bloqueada.
        row.used_at = now
        row.sensor_id = sensor.id
        audit_service.record(
            session,
            _sensor_actor(sensor, client_ip),
            "sensor_enrolled",
            target_type="sensor",
            target_id=sensor.public_id,
            details={
                "site_id": str(site.public_id),
                "enrollment_id": str(row.public_id),
                "hostname": body.hostname,
                "sensor_version": body.sensor_version,
            },
            commit=False,
        )
        session.commit()
        logger.info(
            "sensor enrolled",
            extra={"sensor": str(sensor.public_id), "site": str(site.public_id)},
        )
        return SensorEnrollResponse(
            sensor_id=sensor.public_id,
            site_id=site.public_id,
            site_name=site.name,
            credential=credential,
            credential_issued_at=now,
            config=_config(session, self._settings, sensor, site),
        )

    def authenticate(self, credential: str | None, *, allow_disabled: bool = True) -> Sensor:
        """Sensor de una credencial Bearer (fila bloqueada hasta el commit de la petición).

        401 sensor_unauthorized para ausente/mal formada/desconocida; 403 sensor_revoked si
        se revocó (el sensor deja de reintentar); 403 sensor_disabled para operaciones de
        trabajo de un sensor deshabilitado (el heartbeat sigue permitido).
        """
        if (
            not credential
            or not credential.startswith(SENSOR_CREDENTIAL_PREFIX)
            or len(credential) > MAX_CREDENTIAL_LENGTH
        ):
            raise SensorUnauthorizedError("Invalid sensor credential")
        digest = hash_token(credential)
        sensor = self._session.scalar(
            select(Sensor)
            .where((Sensor.credential_hash == digest) | (Sensor.pending_credential_hash == digest))
            .with_for_update()
        )
        if sensor is None:
            raise SensorUnauthorizedError("Invalid sensor credential")
        if sensor.status == "revoked":
            raise SensorForbiddenError("sensor_revoked", "Sensor has been revoked")
        if sensor.pending_credential_hash == digest:
            # Primer uso de la credencial rotada: pasa a ser la única válida.
            sensor.credential_hash = digest
            sensor.pending_credential_hash = None
            sensor.rotation_requested_at = None
            sensor.credential_issued_at = datetime.now(UTC)
            logger.info("sensor credential activated", extra={"sensor": str(sensor.public_id)})
        if not allow_disabled and sensor.status == "disabled":
            self._session.commit()
            raise SensorForbiddenError("sensor_disabled", "Sensor is disabled")
        return sensor

    def _site(self, sensor: Sensor) -> Site:
        site = self._session.get(Site, sensor.site_id)
        assert site is not None  # noqa: S101  (FK RESTRICT)
        return site

    def heartbeat(self, sensor: Sensor, body: SensorHeartbeatRequest) -> SensorHeartbeatResponse:
        session = self._session
        settings = self._settings
        now = datetime.now(UTC)
        if body.hostname is not None:
            sensor.hostname = body.hostname
        if body.platform is not None:
            sensor.platform = body.platform
        if body.sensor_version is not None:
            sensor.sensor_version = body.sensor_version
        if body.capabilities is not None:
            sensor.capabilities = filter_capabilities(body.capabilities)
        # Solo claves conocidas y tipadas: nunca un dict libre del sensor.
        sensor.health = {
            "queue_depth": body.queue_depth,
            "spool_items": body.spool_items,
            "spool_bytes": body.spool_bytes,
            "uptime_seconds": body.uptime_seconds,
            "last_successful_job_at": body.last_successful_job_at.isoformat()
            if body.last_successful_job_at
            else None,
        }
        if body.sent_at is not None:
            sensor.clock_skew_seconds = int((body.sent_at - now).total_seconds())
        sensor.last_seen_at = now
        sweep(session, now, sensor.id)
        open_jobs = session.execute(
            select(SensorJob.public_id, SensorJob.status, SensorJob.cancel_requested_at).where(
                SensorJob.sensor_id == sensor.id,
                SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES),
            )
        ).all()
        site = self._site(sensor)
        response = SensorHeartbeatResponse(
            sensor_id=sensor.public_id,
            site_id=site.public_id,
            status="disabled" if sensor.status == "disabled" else "active",
            server_time=now,
            version_status=_version_status(sensor, settings),
            rotate_credential=sensor.rotation_requested_at is not None,
            pending_jobs=sum(1 for row in open_jobs if row.status == "pending"),
            cancel_job_ids=[row.public_id for row in open_jobs if row.cancel_requested_at],
            config=_config(session, settings, sensor, site),
        )
        session.commit()
        return response

    def rotate(self, sensor: Sensor, client_ip: str | None) -> SensorRotateResponse:
        """Emite una credencial nueva. La anterior sigue valiendo hasta el primer uso de la
        nueva: si la respuesta se pierde, el sensor no se queda sin identidad."""
        now = datetime.now(UTC)
        credential = generate_sensor_credential()
        sensor.pending_credential_hash = hash_token(credential)
        audit_service.record(
            self._session,
            _sensor_actor(sensor, client_ip),
            "sensor_credential_rotated",
            target_type="sensor",
            target_id=sensor.public_id,
            commit=False,
        )
        self._session.commit()
        return SensorRotateResponse(credential=credential, credential_issued_at=now)

    # --- jobs --------------------------------------------------------------------------------

    def poll(self, sensor: Sensor, body: SensorPollRequest) -> SensorPollResponse:
        session = self._session
        settings = self._settings
        now = datetime.now(UTC)
        sensor.last_seen_at = now
        site = self._site(sensor)
        config = _config(session, settings, sensor, site)
        sweep(session, now, sensor.id)
        out: list[SensorJobOut] = []
        if config.jobs_enabled:
            capabilities = set(sensor.capabilities or [])
            # SKIP LOCKED: dos polls simultáneos del mismo sensor nunca reciben el mismo job.
            candidates = session.scalars(
                select(SensorJob)
                .where(
                    SensorJob.sensor_id == sensor.id,
                    SensorJob.status == "pending",
                    SensorJob.expires_at > now,
                )
                .order_by(SensorJob.created_at, SensorJob.id)
                .limit(body.max_jobs)
                .with_for_update(skip_locked=True)
            ).all()
            for job in candidates:
                if job.job_type not in JOB_TYPES:
                    # Catálogo cerrado: un tipo desconocido (fila manipulada, versión futura)
                    # nunca se entrega; se falla para que no quede en cola.
                    self._fail(job, "job_type_unknown", now)
                    continue
                if not _required_capabilities(job) <= capabilities:
                    # Se queda en cola (caducará si el sensor no la adquiere): no se entrega
                    # trabajo a quien no declara poder hacerlo.
                    continue
                if not _inside_site(_target_network(job), config.allowed_networks):
                    # La red se deshabilitó o quitó después de crear el job.
                    self._fail(job, "network_not_authorized", now)
                    continue
                job.status = "leased"
                job.attempt += 1
                job.leased_at = now
                job.lease_expires_at = now + timedelta(seconds=settings.sensor_job_lease_seconds)
                assert job.lease_expires_at is not None  # noqa: S101
                out.append(
                    SensorJobOut(
                        job_id=job.public_id,
                        site_id=site.public_id,
                        sensor_id=sensor.public_id,
                        job_type=job.job_type,
                        parameters=dict(job.parameters),
                        created_at=job.created_at,
                        expires_at=job.expires_at,
                        lease_expires_at=job.lease_expires_at,
                        attempt=job.attempt,
                        idempotency_key=f"{job.public_id}:{job.attempt}",
                    )
                )
        session.commit()
        return SensorPollResponse(jobs=out, config=config)

    def _fail(self, job: SensorJob, code: str, now: datetime) -> None:
        job.status = "failed"
        job.finished_at = now
        job.error_code = code
        job.lease_expires_at = None
        discovery = _discovery_of(self._session, job)
        _finish_discovery(
            discovery, DiscoveryJobStatus.FAILED, DiscoveryStopReason.ERROR, now, code
        )
        _finish_job(self._session, job, now)

    def _job(self, sensor: Sensor, public_id: uuid.UUID) -> SensorJob:
        # Orden de bloqueo fijo: discovery y después job de sensor, el mismo que usa la
        # cancelación del operador (request_cancel → request_sensor_cancel). Al revés, un
        # complete y un cancel simultáneos se bloqueaban mutuamente (deadlock → 503).
        # discovery_job_id no cambia nunca, así que leerlo sin bloqueo es seguro.
        discovery_id = self._session.scalar(
            select(SensorJob.discovery_job_id).where(SensorJob.public_id == public_id)
        )
        if discovery_id is not None:
            self._session.execute(
                select(DiscoveryJob.id).where(DiscoveryJob.id == discovery_id).with_for_update()
            )
        job = self._session.scalar(
            select(SensorJob).where(SensorJob.public_id == public_id).with_for_update()
        )
        # El job de otro sensor responde igual que uno inexistente: no se confirma que exista.
        if job is None or job.sensor_id != sensor.id:
            raise SensorJobNotFoundError("Sensor job not found")
        return job

    @staticmethod
    def _check_open(job: SensorJob, attempt: int, statuses: tuple[str, ...]) -> None:
        if job.status in TERMINAL_JOB_STATUSES:
            raise SiteConflictError("sensor_job_finished", f"Sensor job already {job.status}")
        if job.status not in statuses or job.attempt != attempt:
            raise SiteConflictError(
                "sensor_job_not_leased", "This attempt does not hold the job (poll again)"
            )

    def start(self, sensor: Sensor, public_id: uuid.UUID, body: SensorJobStart) -> SensorJobStarted:
        session = self._session
        now = datetime.now(UTC)
        job = self._job(sensor, public_id)
        if job.status == "running" and job.attempt == body.attempt:
            # Reintento del mismo start (respuesta perdida): misma respuesta. En SNMP la
            # credencial se vuelve a validar y entregar (el sensor no la guarda en disco).
            assert job.lease_expires_at is not None  # noqa: S101
            credentials = self._snmp_credentials(sensor, job, now)
            session.commit()
            return SensorJobStarted(
                job_id=job.public_id,
                status="running",
                lease_expires_at=job.lease_expires_at,
                credentials=credentials,
            )
        self._check_open(job, body.attempt, ("leased",))
        if job.lease_expires_at is None or job.lease_expires_at <= now:
            raise SiteConflictError("sensor_job_expired", "The lease expired before the start")
        allowed = enabled_networks(session, sensor.site_id)
        if self._site(sensor).status != "active" or not _inside_site(_target_network(job), allowed):
            self._fail(job, "network_not_authorized", now)
            session.commit()
            raise SiteConflictError("sensor_job_finished", "Sensor job is no longer authorized")
        credentials = self._snmp_credentials(sensor, job, now)
        deadline = int(job.parameters.get("deadline_seconds") or 0)
        job.status = "running"
        job.started_at = now
        job.lease_expires_at = now + timedelta(
            seconds=deadline + self._settings.sensor_result_grace_seconds
        )
        discovery = _discovery_of(session, job)
        if discovery is not None and discovery.status == DiscoveryJobStatus.QUEUED:
            discovery.status = DiscoveryJobStatus.RUNNING
            discovery.started_at = now
            discovery.heartbeat_at = now
            discovery.progress = {"phase": "liveness"}
        session.commit()
        return SensorJobStarted(
            job_id=job.public_id,
            status="running",
            lease_expires_at=job.lease_expires_at,
            credentials=credentials,
        )

    def _snmp_credentials(
        self, sensor: Sensor, job: SensorJob, now: datetime
    ) -> SnmpJobCredentials | None:
        """Credencial de un job snmp_inventory; None para el resto de tipos.

        Si ya no se puede entregar (perfil revocado, reasignado, v2c deshabilitado, almacén
        de secretos ilegible), el job se falla y el sensor recibe 409 sensor_job_finished.
        """
        from app.services import network_jobs
        from app.services.snmp_profile_service import CredentialsUnavailableError

        if not network_jobs.is_snmp_job(job):
            return None
        try:
            return network_jobs.start_credentials(self._session, self._settings, sensor, job, now)
        except CredentialsUnavailableError as exc:
            logger.warning(
                "snmp credentials not delivered",
                extra={"job": str(job.public_id), "reason": exc.reason},
            )
            self._fail(job, "credentials_unavailable", now)
            self._session.commit()
            raise SiteConflictError(
                "sensor_job_finished", "The SNMP credentials of this job are no longer available"
            ) from exc

    def results(
        self, sensor: Sensor, public_id: uuid.UUID, body: SensorResultsRequest
    ) -> SensorResultsResponse:
        session = self._session
        settings = self._settings
        now = datetime.now(UTC)
        job = self._job(sensor, public_id)
        snmp = job.job_type == SNMP_JOB_TYPE
        # Cada tipo de job entrega su lista y solo esa: unos registros SNMP colados en un
        # discovery (o al revés) indican un sensor defectuoso o manipulado.
        if (snmp and body.observations) or (not snmp and body.records):
            raise SiteValidationError(
                "sensor_batch_invalid", "This job type does not accept that kind of result"
            )
        digest = _records_sha256(body.records) if snmp else _payload_sha256(body.observations)
        existing = session.scalar(
            select(SensorJobBatch).where(
                SensorJobBatch.job_id == job.id, SensorJobBatch.batch_id == body.batch_id
            )
        )
        if existing is not None:
            if existing.payload_sha256 != digest:
                raise SiteConflictError(
                    "sensor_batch_conflict", "batch_id already received with other content"
                )
            session.commit()
            return SensorResultsResponse(
                job_id=job.public_id,
                batch_id=body.batch_id,
                accepted=0,
                duplicate=True,
                observations_total=job.observations_received,
                cancel_requested=job.cancel_requested_at is not None,
            )
        self._check_open(job, body.attempt, ("running",))
        if snmp:
            return self._snmp_results(sensor, job, body, digest, now)
        if len(body.observations) > settings.sensor_max_observations_per_batch:
            raise SiteValidationError(
                "sensor_batch_too_large",
                f"At most {settings.sensor_max_observations_per_batch} observations per batch",
            )
        if job.batches_received >= settings.sensor_max_batches_per_job:
            raise SiteConflictError("sensor_batch_limit", "Too many batches for this job")
        network = _target_network(job)
        skew = timedelta(seconds=settings.sensor_max_clock_skew_seconds)
        earliest = job.created_at - skew
        merged: dict[str, ObservationIn] = {}
        for obs in body.observations:
            address = ipaddress.ip_address(obs.address)
            # Anti-spoofing: nada fuera del target autorizado del job, aunque el sensor
            # esté autenticado (se rechaza el lote entero: un sensor sano nunca lo envía).
            if address.version != network.version or address not in network:
                raise SiteValidationError(
                    "sensor_observation_out_of_scope",
                    "Observation outside the job target",
                    [{"address": obs.address}],
                )
            if obs.observed_at > now + skew or obs.observed_at < earliest:
                raise SiteValidationError(
                    "sensor_timestamp_invalid",
                    "observed_at outside the allowed clock skew",
                    [{"address": obs.address}],
                )
            if len(obs.ports) > settings.sensor_max_ports_per_observation:
                raise SiteValidationError(
                    "sensor_batch_too_large",
                    f"At most {settings.sensor_max_ports_per_observation} ports per host",
                )
            previous = merged.get(obs.address)
            merged[obs.address] = obs if previous is None else _merge_in(previous, obs)
        rows = {
            row.address: row
            for row in session.scalars(
                select(SensorObservation).where(
                    SensorObservation.job_id == job.id,
                    SensorObservation.address.in_(list(merged)),
                )
            )
        }
        for key, obs in merged.items():
            ports: dict[str, str] = {str(p.port): p.state for p in obs.ports}
            row = rows.get(key)
            if row is None:
                session.add(
                    SensorObservation(
                        job_id=job.id,
                        site_id=job.site_id,
                        sensor_id=sensor.id,
                        address=key,
                        mac=obs.mac,
                        hostname=obs.hostname,
                        reverse_dns=obs.reverse_dns,
                        ports=ports,
                        sources=sorted(set(obs.sources)),
                        rtt_ms=obs.rtt_ms,
                        forward_dns_match=obs.forward_dns_match,
                        observed_at=obs.observed_at,
                        received_at=now,
                    )
                )
            else:
                row.ports = _merge_ports(row.ports, ports)
                row.sources = sorted(set(row.sources) | set(obs.sources))
                row.mac = row.mac or obs.mac
                row.hostname = obs.hostname or row.hostname
                row.reverse_dns = obs.reverse_dns or row.reverse_dns
                row.rtt_ms = _min_rtt(row.rtt_ms, obs.rtt_ms)
                if obs.forward_dns_match is not None:
                    row.forward_dns_match = obs.forward_dns_match
                row.observed_at = max(row.observed_at, obs.observed_at)
                row.received_at = now
        session.add(
            SensorJobBatch(
                job_id=job.id,
                batch_id=body.batch_id,
                payload_sha256=digest,
                observation_count=len(body.observations),
                attempt=body.attempt,
                received_at=now,
            )
        )
        session.flush()
        job.batches_received += 1
        job.observations_received = int(
            session.scalar(
                select(func.count())
                .select_from(SensorObservation)
                .where(SensorObservation.job_id == job.id)
            )
            or 0
        )
        sensor.last_seen_at = now
        discovery = _discovery_of(session, job)
        if discovery is not None and discovery.status == DiscoveryJobStatus.RUNNING:
            discovery.heartbeat_at = now
            discovery.progress = {"phase": "details", "details_done": job.observations_received}
        session.commit()
        return SensorResultsResponse(
            job_id=job.public_id,
            batch_id=body.batch_id,
            accepted=len(merged),
            duplicate=False,
            observations_total=job.observations_received,
            cancel_requested=job.cancel_requested_at is not None,
        )

    def _snmp_results(
        self,
        sensor: Sensor,
        job: SensorJob,
        body: SensorResultsRequest,
        digest: str,
        now: datetime,
    ) -> SensorResultsResponse:
        from app.services import network_jobs

        session = self._session
        settings = self._settings
        if job.batches_received >= settings.sensor_max_batches_per_job:
            raise SiteConflictError("sensor_batch_limit", "Too many batches for this job")
        total = network_jobs.stage_records(session, settings, job, body.records)
        session.add(
            SensorJobBatch(
                job_id=job.id,
                batch_id=body.batch_id,
                payload_sha256=digest,
                observation_count=len(body.records),
                attempt=body.attempt,
                received_at=now,
            )
        )
        session.flush()
        job.batches_received += 1
        job.observations_received = total
        sensor.last_seen_at = now
        session.commit()
        return SensorResultsResponse(
            job_id=job.public_id,
            batch_id=body.batch_id,
            accepted=len(body.records),
            duplicate=False,
            observations_total=total,
            cancel_requested=job.cancel_requested_at is not None,
        )

    def complete(
        self,
        sensor: Sensor,
        public_id: uuid.UUID,
        body: SensorJobComplete,
        thresholds: AlertThresholds,
    ) -> SensorJobCompleted:
        session = self._session
        now = datetime.now(UTC)
        job = self._job(sensor, public_id)
        discovery = _discovery_of(session, job)
        discovery_public = discovery.public_id if discovery is not None else None
        if job.status in TERMINAL_JOB_STATUSES:
            summary = job.result_summary or {}
            if summary.get("attempt") == body.attempt:
                session.commit()
                return SensorJobCompleted(
                    job_id=job.public_id,
                    status=job.status,
                    duplicate=True,
                    discovery_job_id=discovery_public,
                    hosts_alive=int(summary.get("hosts_alive", 0)),
                    hosts_new=int(summary.get("hosts_new", 0)),
                    open_ports=int(summary.get("open_ports", 0)),
                )
        # Un job recogido pero no empezado puede cerrarse como fallido o cancelado (el sensor
        # lo rechazó al validar): nunca con resultados.
        allowed = (
            ("running",)
            if body.outcome in ("completed", "timed_out")
            else (
                "running",
                "leased",
            )
        )
        self._check_open(job, body.attempt, allowed)
        # Lotes anunciados que nunca llegaron (el sensor los descartó tras un 4xx). El job
        # se cierra igualmente, pero el resultado cuenta como PARCIAL: sin conclusiones
        # negativas (ni hosts desaparecidos ni puertos cerrados) con datos incompletos.
        missing = max(body.batches_sent - job.batches_received, 0)
        hosts_alive = hosts_new = open_ports = 0
        if job.job_type == SNMP_JOB_TYPE:
            self._complete_snmp(job, body, missing, now)
        elif body.outcome == "failed":
            job.status = "failed"
            job.error_code = "sensor_failed"
            job.error_message = (body.errors[0] if body.errors else "sensor reported failure")[:300]
            _finish_discovery(
                discovery,
                DiscoveryJobStatus.FAILED,
                DiscoveryStopReason.ERROR,
                now,
                job.error_message,
            )
            if discovery is not None:
                discovery.errors = body.errors[:50] or discovery.errors
                discovery.error_count = len(discovery.errors or [])
        elif discovery is not None and discovery.status in ACTIVE_JOB_STATUSES:
            summary_obj = self._apply(job, discovery, body, thresholds, missing)
            hosts_alive = summary_obj.hosts_alive
            hosts_new = summary_obj.hosts_new
            open_ports = summary_obj.open_ports
            job.status = "cancelled" if body.outcome == "cancelled" else "succeeded"
        else:
            # Sin discovery asociado (no debería pasar): se cierra sin aplicar nada.
            job.status = "cancelled" if body.outcome == "cancelled" else "succeeded"
        job.finished_at = now
        job.lease_expires_at = None
        if job.job_type == SNMP_JOB_TYPE:
            session.commit()
            return SensorJobCompleted(
                job_id=job.public_id,
                status=job.status,
                duplicate=False,
                discovery_job_id=None,
                hosts_alive=0,
                hosts_new=0,
                open_ports=0,
            )
        job.result_summary = {
            "attempt": body.attempt,
            "outcome": body.outcome,
            "hosts_alive": hosts_alive,
            "hosts_new": hosts_new,
            "open_ports": open_ports,
            "hosts_scanned": body.hosts_scanned,
            "probes": body.probes,
        }
        sensor.last_seen_at = now
        session.commit()
        logger.info(
            "sensor job completed",
            extra={
                "sensor": str(sensor.public_id),
                "job": str(job.public_id),
                "outcome": body.outcome,
                "alive": hosts_alive,
                "new": hosts_new,
            },
        )
        return SensorJobCompleted(
            job_id=job.public_id,
            status=job.status,
            duplicate=False,
            discovery_job_id=discovery_public,
            hosts_alive=hosts_alive,
            hosts_new=hosts_new,
            open_ports=open_ports,
        )

    def _complete_snmp(
        self, job: SensorJob, body: SensorJobComplete, missing: int, now: datetime
    ) -> None:
        """Cierre de un job snmp_inventory: aplica los registros y resume el job (sin datos)."""
        from app.services import network_jobs

        poll = network_jobs.complete_poll(
            self._session, self._settings, job, body.outcome, body.snmp, body.errors, missing, now
        )
        if body.outcome == "failed":
            job.status = "failed"
            job.error_code = "sensor_failed"
            job.error_message = (body.errors[0] if body.errors else "sensor reported failure")[:300]
        else:
            job.status = "cancelled" if body.outcome == "cancelled" else "succeeded"
        job.result_summary = {
            "attempt": body.attempt,
            "outcome": body.outcome,
            "poll_status": poll.status if poll is not None else None,
            "records": job.observations_received,
            "error_code": body.snmp.error_code if body.snmp is not None else None,
        }

    def _apply(
        self,
        job: SensorJob,
        discovery: DiscoveryJob,
        body: SensorJobComplete,
        thresholds: AlertThresholds,
        missing_batches: int = 0,
    ) -> Any:
        """Convierte las observaciones guardadas en activos con el MISMO motor que el
        discovery local, limitado al site del job (nunca el que diga el sensor)."""
        from app.services.discovery_service import DiscoveryConfig, ResultApplier, is_baseline

        session = self._session
        settings = self._settings
        network = _target_network(job)
        rows = session.scalars(
            select(SensorObservation)
            .where(SensorObservation.job_id == job.id)
            .order_by(SensorObservation.id)
        ).all()
        observations = []
        for row in rows:
            observations.append(
                HostObservation(
                    address=row.address,
                    alive=True,
                    sources=set(row.sources or ()),
                    mac=row.mac,
                    reverse_dns=row.reverse_dns,
                    ports={int(port): PortState(state) for port, state in row.ports.items()},
                    rtt_ms=row.rtt_ms,
                    forward_dns_match=row.forward_dns_match,
                )
            )
        incomplete = missing_batches > 0 and body.outcome == "completed"
        errors = list(body.errors)
        if missing_batches:
            errors.insert(0, f"{missing_batches} result batch(es) missing: partial result")
        result = ScanResult(
            hosts_scanned=body.hosts_scanned,
            observations=observations,
            errors=errors[:50],
            probes=body.probes,
            cancelled=body.outcome == "cancelled" or incomplete,
            timed_out=body.outcome == "timed_out",
            hosts_checked=body.hosts_checked,
            unprobed=frozenset(body.unprobed),
        )
        config = DiscoveryConfig(
            scope=DiscoveryScope(
                allowed=(network,),
                excluded=(),
                max_hosts=settings.discovery_max_hosts_per_network,
                allow_public=settings.discovery_allow_public_networks,
            ),
            scan=ScanConfig(ports=tuple(int(p) for p in job.parameters.get("ports", []))),
            offline_after_misses=settings.discovery_offline_after_misses,
            job_timeout=timedelta(minutes=settings.discovery_job_timeout_minutes),
            heartbeat_timeout=timedelta(seconds=settings.heartbeat_timeout_seconds),
        )
        stop_reason = None
        if incomplete:
            stop_reason = DiscoveryStopReason.INCOMPLETE
        elif body.outcome == "cancelled":
            stop_reason = (
                DiscoveryStopReason.OPERATOR
                if job.cancel_requested_at is not None
                else DiscoveryStopReason.SHUTDOWN
            )
        baseline = is_baseline(session, str(network), job.site_id)
        # Sin pasarelas: las del servidor no son las de la red remota del sensor.
        return ResultApplier(
            session,
            config,
            thresholds,
            set(),
            site_id=job.site_id,
            executor="sensor",
            sensor_id=job.sensor_id,
        ).apply(discovery.id, network, result, baseline, stop_reason)


def _records_sha256(records: Sequence[SnmpRecord]) -> str:
    """Huella canónica de un lote SNMP (sin campos nulos, claves ordenadas)."""
    data = [record.model_dump(mode="json", exclude_none=True) for record in records]
    raw = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _merge_ports(current: dict[str, str], new: dict[str, str]) -> dict[str, str]:
    merged = dict(current)
    for port, state in new.items():
        if _PORT_RANK.get(state, 0) >= _PORT_RANK.get(merged.get(port, "filtered"), 0):
            merged[port] = state
    return merged


def _min_rtt(current: int | None, new: int | None) -> int | None:
    if current is None:
        return new
    return current if new is None else min(current, new)


def _merge_in(first: ObservationIn, second: ObservationIn) -> ObservationIn:
    """Fusiona dos entradas de la misma dirección dentro de un lote."""
    ports = _merge_ports(
        {str(p.port): p.state for p in first.ports}, {str(p.port): p.state for p in second.ports}
    )
    return first.model_copy(
        update={
            "mac": first.mac or second.mac,
            "hostname": second.hostname or first.hostname,
            "reverse_dns": second.reverse_dns or first.reverse_dns,
            "ports": [
                PortObservation(port=int(port), state=state) for port, state in ports.items()
            ],
            "sources": sorted(set(first.sources) | set(second.sources)),
            "rtt_ms": _min_rtt(first.rtt_ms, second.rtt_ms),
            "forward_dns_match": second.forward_dns_match
            if second.forward_dns_match is not None
            else first.forward_dns_match,
            "observed_at": max(first.observed_at, second.observed_at),
        }
    )
