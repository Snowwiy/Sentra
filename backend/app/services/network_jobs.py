"""Consultas SNMP como jobs de sensor (Fase 6B): creación, entrega, resultados y cierre.

Encaja en el protocolo de sensores de la Fase 5F sin tocar sus garantías:
- El job (snmp_inventory) va siempre a UN sensor concreto del MISMO site que el equipo, y la
  dirección del equipo debe estar dentro de una red habilitada del site (se comprueba al
  crear, al entregar y al empezar, igual que el discovery).
- Los parámetros del job no contienen secretos ni OIDs: solo dirección, versión, protocolos,
  nombres de módulo del catálogo y límites. La credencial se entrega únicamente en la
  respuesta de start, tras volver a validar perfil, site, sensor y política v2c.
- Los registros se guardan en un área temporal y se aplican juntos al cerrar (apply.py). Un
  job perdido, caducado o cancelado antes de empezar nunca aplica nada.
- Una sola consulta abierta por equipo (índice único parcial).
"""

import logging
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import SiteConflictError, SiteValidationError
from app.core.secret_box import SecretDecryptError
from app.models.network import (
    OPEN_POLL_STATUSES,
    NetworkDevice,
    NetworkDevicePoll,
    NetworkInterface,
    NetworkMacEntry,
    NetworkNeighbor,
    NetworkPollRecord,
    SnmpCredentialProfile,
)
from app.models.site import OPEN_SENSOR_JOB_STATUSES, Sensor, SensorJob, Site
from app.network.apply import PollApplier
from app.network.catalog import (
    MODULE_CAPABILITY,
    MODULES,
    SNMP_JOB_TYPE,
    SNMP_SCHEMA_VERSION,
    VERSION_CAPABILITY,
)
from app.schemas.network_protocol import SnmpJobCredentials, SnmpJobSummary, SnmpRecord
from app.sensors.catalog import version_status
from app.services import audit_service
from app.services.audit_service import Actor
from app.services.snmp_profile_service import (
    CredentialsUnavailableError,
    secret_box,
    secret_context,
    secret_store_available,
)

logger = logging.getLogger(__name__)

SCHEDULER = Actor("system:snmp-scheduler")
# Equipos que el programador encola por vuelta: acota la carga si se activan muchos a la vez.
SCHEDULER_BATCH = 100
# Motivos de cancelación de jobs (cancel_jobs) que, para una consulta, son "cancelada".
_FAILED_JOB_CODES = {
    "not_started": ("expired", "job_expired"),
    "lease_expired": ("failed", "sensor_lost"),
    "sensor_lost": ("failed", "sensor_lost"),
    "network_not_authorized": ("failed", "job_rejected"),
    "job_type_unknown": ("failed", "job_rejected"),
    "credentials_unavailable": ("failed", "credentials_unavailable"),
}
_ERROR_MESSAGES = {
    "job_expired": "no sensor started this poll before it expired",
    "sensor_offline": "the assigned sensor was offline when the poll expired",
    "sensor_lost": "the sensor stopped reporting before completing this poll",
    "job_rejected": "the poll is no longer authorized (address outside the site networks)",
    "credentials_unavailable": "the SNMP profile could not be delivered to the sensor",
    "cancelled": "the poll was cancelled",
}


def is_snmp_job(job: SensorJob) -> bool:
    return job.job_type == SNMP_JOB_TYPE


# --- capacidades y parámetros -------------------------------------------------------------------


def modules_for(capabilities: Sequence[str]) -> list[str]:
    """Módulos que el sensor declara saber consultar, en el orden del catálogo.

    vlan necesita bridge (la pertenencia a VLAN se expresa en puertos de bridge que solo se
    traducen a interfaces con dot1dBasePortIfIndex): sin bridge, vlan no se pide.
    """
    declared = set(capabilities)
    modules = [m for m in MODULES if MODULE_CAPABILITY[m] in declared]
    if "vlan" in modules and "bridge" not in modules:
        modules.remove("vlan")
    return modules


def required_capabilities(job: SensorJob) -> set[str]:
    params = job.parameters if isinstance(job.parameters, dict) else {}
    version = str(params.get("snmp_version") or "")
    modules = params.get("modules") or []
    caps = {MODULE_CAPABILITY["system"], VERSION_CAPABILITY.get(version, "snmp.unknown")}
    caps |= {MODULE_CAPABILITY.get(str(m), "snmp.unknown") for m in modules}
    return caps


def _parameters(
    settings: Settings, device: NetworkDevice, profile: SnmpCredentialProfile, modules: list[str]
) -> dict[str, Any]:
    """Parámetros fijos generados por el servidor (esquema exacto, sin secretos ni OIDs)."""
    return {
        "schema_version": SNMP_SCHEMA_VERSION,
        "target": device.management_address,
        "port": device.snmp_port,
        "snmp_version": profile.snmp_version,
        "profile_id": str(profile.public_id),
        "secret_revision": profile.secret_revision,
        "auth_protocol": profile.auth_protocol,
        "priv_protocol": profile.priv_protocol,
        "modules": modules,
        "timeout_ms": settings.snmp_timeout_ms,
        "retries": settings.snmp_retries,
        "max_repetitions": 25,
        "max_varbinds": settings.snmp_max_varbinds_per_job,
        "max_rows_per_table": settings.snmp_max_rows_per_table,
        "deadline_seconds": settings.snmp_job_deadline_seconds,
    }


# --- disponibilidad -------------------------------------------------------------------------


@dataclass(frozen=True)
class PollContext:
    site: Site
    profile: SnmpCredentialProfile
    sensor: Sensor
    modules: list[str]


def poll_blockers(
    session: Session, settings: Settings, device: NetworkDevice, *, check_online: bool = True
) -> tuple[list[str], PollContext | None]:
    """Motivos por los que no se puede consultar el equipo ahora (vacío = se puede).

    La falta de credenciales o de sensor no es un error de seguridad: es configuración
    pendiente, y la UI la muestra así.
    """
    from app.services.sensor_service import effective_status
    from app.services.sensor_service import inside_site_networks as inside
    from app.services.site_service import enabled_networks

    blockers: list[str] = []
    site = session.get(Site, device.site_id)
    if device.status != "active":
        blockers.append("device_archived")
    if site is None or site.status != "active":
        blockers.append("site_not_active")
    profile = session.get(SnmpCredentialProfile, device.profile_id) if device.profile_id else None
    if profile is None:
        blockers.append("profile_missing")
    elif profile.status != "active" or not profile.secret_blob:
        blockers.append("profile_revoked")
    elif profile.site_id != device.site_id:
        blockers.append("profile_other_site")
    elif profile.snmp_version == "v2c" and not settings.snmp_allow_v2c:
        blockers.append("v2c_disabled")
    if not secret_store_available(settings):
        blockers.append("secret_store_unavailable")
    sensor = session.get(Sensor, device.sensor_id) if device.sensor_id else None
    modules: list[str] = []
    if sensor is None:
        blockers.append("sensor_missing")
    else:
        status = effective_status(sensor, datetime.now(UTC), settings)
        caps = set(sensor.capabilities or [])
        if sensor.site_id != device.site_id:
            blockers.append("sensor_other_site")
        elif status in ("revoked", "disabled"):
            blockers.append(f"sensor_{status}")
        elif check_online and status in ("offline", "stale", "pending"):
            blockers.append("sensor_offline")
        if (
            version_status(
                sensor.sensor_version,
                settings.sensor_min_version,
                settings.sensor_recommended_version,
            )
            == "unsupported"
        ):
            blockers.append("sensor_version_unsupported")
        modules = modules_for(sorted(caps))
        if "system" not in modules:
            blockers.append("sensor_without_snmp")
        elif profile is not None and VERSION_CAPABILITY.get(profile.snmp_version) not in caps:
            blockers.append("sensor_without_snmp_version")
    if site is not None and not inside(
        device.management_address, enabled_networks(session, site.id)
    ):
        blockers.append("address_out_of_scope")
    if blockers or site is None or profile is None or sensor is None:
        return blockers, None
    return [], PollContext(site, profile, sensor, modules)


def has_open_poll(session: Session, device_id: int) -> bool:
    return bool(
        session.scalar(
            select(func.count())
            .select_from(NetworkDevicePoll)
            .where(
                NetworkDevicePoll.device_id == device_id,
                NetworkDevicePoll.status.in_(OPEN_POLL_STATUSES),
            )
        )
    )


# --- creación y cancelación -----------------------------------------------------------------


def create_poll(
    session: Session,
    settings: Settings,
    device: NetworkDevice,
    actor: Actor,
    trigger: str = "manual",
) -> NetworkDevicePoll:
    """Encola la consulta y su job de sensor. Sin commit en el error; con commit si va bien."""
    from app.services.sensor_service import sweep

    blockers, ctx = poll_blockers(session, settings, device)
    if ctx is None:
        audit_service.record(
            session,
            actor,
            "network_poll_rejected",
            result=audit_service.DENIED,
            target_type="network_device",
            target_id=device.public_id,
            details={"blockers": blockers, "trigger": trigger},
        )
        raise SiteConflictError(
            "network_poll_unavailable",
            "The device cannot be polled now: " + ", ".join(blockers),
            [{"blockers": blockers}],
        )
    now = datetime.now(UTC)
    sweep(session, now, ctx.sensor.id)
    parameters = _parameters(settings, device, ctx.profile, ctx.modules)
    poll = NetworkDevicePoll(
        public_id=uuid.uuid4(),
        device_id=device.id,
        site_id=device.site_id,
        sensor_id=ctx.sensor.id,
        profile_id=ctx.profile.id,
        snmp_version=ctx.profile.snmp_version,
        status="queued",
        trigger=trigger,
        requested_by=actor.name,
        modules_requested=list(ctx.modules),
        created_at=now,
    )
    try:
        with session.begin_nested():
            session.add(poll)
            session.flush()
    except IntegrityError as exc:
        raise SiteConflictError(
            "network_poll_busy", "A poll of this device is already queued or running"
        ) from exc
    job = SensorJob(
        site_id=device.site_id,
        sensor_id=ctx.sensor.id,
        job_type=SNMP_JOB_TYPE,
        parameters=parameters,
        status="pending",
        created_by=actor.name,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.sensor_job_ttl_minutes),
        max_attempts=settings.sensor_job_max_attempts,
        idempotency_key=str(poll.public_id),
    )
    session.add(job)
    session.flush()
    poll.sensor_job_id = job.id
    device.last_poll_at = now
    audit_service.record(
        session,
        actor,
        "network_poll_requested",
        target_type="network_device",
        target_id=device.public_id,
        details={
            "poll_id": str(poll.public_id),
            "sensor_job_id": str(job.public_id),
            "sensor_id": str(ctx.sensor.public_id),
            "profile_id": str(ctx.profile.public_id),
            "modules": ctx.modules,
            "trigger": trigger,
        },
        commit=False,
    )
    session.commit()
    return poll


def _poll_of(session: Session, job: SensorJob) -> NetworkDevicePoll | None:
    return session.scalar(
        select(NetworkDevicePoll).where(NetworkDevicePoll.sensor_job_id == job.id)
    )


def _close_poll(
    session: Session,
    poll: NetworkDevicePoll,
    status: str,
    error_code: str | None,
    message: str | None,
    now: datetime,
) -> None:
    if poll.status not in OPEN_POLL_STATUSES:
        return
    poll.status = status
    poll.finished_at = now
    poll.error_code = error_code
    poll.error_message = (message or "")[:300] or None
    session.execute(delete(NetworkPollRecord).where(NetworkPollRecord.poll_id == poll.id))
    device = session.get(NetworkDevice, poll.device_id)
    if device is not None and status in ("failed", "expired"):
        device.consecutive_failures += 1
        device.last_error_code = error_code
        device.last_error_at = now


def finish_poll_for_job(session: Session, job: SensorJob, now: datetime) -> None:
    """Cierra la consulta de un job que terminó sin cierre del sensor (sweep, cancel, fallo).

    Lo llaman sweep, cancel_jobs y _fail de sensor_service. No aplica nada de lo recibido:
    sin el cierre explícito del sensor no se sabe si los datos están completos.
    """
    if not is_snmp_job(job):
        return
    poll = _poll_of(session, job)
    if poll is None:
        return
    code = job.error_code or ""
    if job.status == "cancelled":
        status, error = "cancelled", "cancelled"
    else:
        status, error = _FAILED_JOB_CODES.get(code, ("failed", "internal"))
    if error == "job_expired":
        # Si el sensor estaba caído, el motivo real es "sensor offline", no la caducidad.
        from app.core.config import get_settings
        from app.services.sensor_service import effective_status

        sensor = session.get(Sensor, job.sensor_id)
        if sensor is not None and effective_status(sensor, now, get_settings()) in (
            "offline",
            "stale",
            "pending",
        ):
            error = "sensor_offline"
    _close_poll(session, poll, status, error, _ERROR_MESSAGES.get(error, code), now)


def _cancel_polls(session: Session, polls: Sequence[NetworkDevicePoll], reason: str) -> int:
    from app.services.sensor_service import cancel_jobs

    job_ids = [p.sensor_job_id for p in polls if p.sensor_job_id is not None]
    cancel_jobs(session, job_ids, reason)
    now = datetime.now(UTC)
    for poll in polls:
        _close_poll(session, poll, "cancelled", "cancelled", reason, now)
    return len(polls)


def cancel_profile_polls(session: Session, profile_id: int, reason: str) -> int:
    polls = session.scalars(
        select(NetworkDevicePoll)
        .where(
            NetworkDevicePoll.profile_id == profile_id,
            NetworkDevicePoll.status.in_(OPEN_POLL_STATUSES),
        )
        .with_for_update()
    ).all()
    return _cancel_polls(session, polls, reason)


def cancel_device_polls(session: Session, device_id: int, reason: str) -> int:
    polls = session.scalars(
        select(NetworkDevicePoll)
        .where(
            NetworkDevicePoll.device_id == device_id,
            NetworkDevicePoll.status.in_(OPEN_POLL_STATUSES),
        )
        .with_for_update()
    ).all()
    return _cancel_polls(session, polls, reason)


def request_poll_cancel(session: Session, poll: NetworkDevicePoll, actor: Actor) -> None:
    """Cancelación pedida por un operador. En cola: se cancela ya. En curso: el sensor lo
    recibe en su siguiente heartbeat o lote, se para y cierra como cancelado (lo ya visto
    se aplica como evidencia parcial, sin marcar ausencias)."""
    if poll.status not in OPEN_POLL_STATUSES:
        raise SiteConflictError("network_poll_finished", f"Poll already {poll.status}")
    job = (
        session.scalar(
            select(SensorJob).where(SensorJob.id == poll.sensor_job_id).with_for_update()
        )
        if poll.sensor_job_id
        else None
    )
    now = datetime.now(UTC)
    if job is None or job.status in ("pending", "leased"):
        _cancel_polls(session, [poll], "operator")
    elif job.status == "running":
        job.cancel_requested_at = job.cancel_requested_at or now
    audit_service.record(
        session,
        actor,
        "network_poll_cancelled",
        target_type="network_device_poll",
        target_id=poll.public_id,
        details={"status": poll.status},
        commit=False,
    )
    session.commit()


# --- protocolo del sensor -------------------------------------------------------------------


def start_credentials(
    session: Session, settings: Settings, sensor: Sensor, job: SensorJob, now: datetime
) -> SnmpJobCredentials:
    """Credencial del job, entregada SOLO al sensor dueño del job en su start.

    Vuelve a comprobar todo lo que pudo cambiar desde que se creó el job: perfil activo y del
    mismo site, equipo con ese mismo perfil, política v2c y almacén de secretos.
    """
    poll = _poll_of(session, job)
    if poll is None or poll.profile_id is None:
        raise CredentialsUnavailableError("poll_missing")
    profile = session.get(SnmpCredentialProfile, poll.profile_id)
    device = session.get(NetworkDevice, poll.device_id)
    if profile is None or profile.status != "active" or not profile.secret_blob:
        raise CredentialsUnavailableError("profile_revoked")
    if device is None or device.status != "active" or device.profile_id != profile.id:
        raise CredentialsUnavailableError("profile_reassigned")
    params = job.parameters if isinstance(job.parameters, dict) else {}
    if params.get("secret_revision") != profile.secret_revision:
        # Defensa en profundidad: la rotación cancela los jobs abiertos, pero un job con otra
        # revisión nunca recibe la credencial nueva (el sensor tampoco la aceptaría).
        raise CredentialsUnavailableError("secret_rotated")
    if not (profile.site_id == job.site_id == sensor.site_id == device.site_id):
        # Nunca se transmiten secretos de otro site, aunque una fila esté manipulada.
        raise CredentialsUnavailableError("site_mismatch")
    if profile.snmp_version == "v2c" and not settings.snmp_allow_v2c:
        raise CredentialsUnavailableError("v2c_disabled")
    site = session.get(Site, profile.site_id)
    assert site is not None  # noqa: S101  (FK RESTRICT)
    try:
        values = secret_box(settings).decrypt(
            profile.secret_blob, secret_context(profile.public_id, site.public_id)
        )
    except SecretDecryptError as exc:
        logger.error(
            "snmp profile secret could not be decrypted", extra={"profile": str(profile.public_id)}
        )
        raise CredentialsUnavailableError("secret_unreadable") from exc
    if poll.status == "queued":
        poll.status = "running"
        poll.started_at = now
    return SnmpJobCredentials(
        profile_id=profile.public_id,
        secret_revision=profile.secret_revision,
        snmp_version=profile.snmp_version,
        username=profile.username,
        auth_protocol=profile.auth_protocol,
        priv_protocol=profile.priv_protocol,
        auth_password=values.get("auth_password"),
        priv_password=values.get("priv_password"),
        community=values.get("community"),
    )


def stage_records(
    session: Session, settings: Settings, job: SensorJob, records: Sequence[SnmpRecord]
) -> int:
    """Guarda los registros de un lote en el área temporal. Devuelve el total del job."""
    poll = _poll_of(session, job)
    if poll is None:
        raise SiteConflictError("sensor_job_finished", "The poll of this job no longer exists")
    total = poll.records_received + len(records)
    if total > settings.snmp_max_varbinds_per_job:
        raise SiteValidationError(
            "sensor_batch_too_large",
            f"At most {settings.snmp_max_varbinds_per_job} SNMP records per poll",
        )
    for record in records:
        session.add(
            NetworkPollRecord(
                poll_id=poll.id,
                kind=record.kind,
                data=record.model_dump(mode="json", exclude_none=True),
            )
        )
    poll.records_received = total
    return total


def complete_poll(
    session: Session,
    settings: Settings,
    job: SensorJob,
    outcome: str,
    summary: SnmpJobSummary | None,
    errors: Sequence[str],
    missing_batches: int,
    now: datetime,
) -> NetworkDevicePoll | None:
    """Cierre de un job snmp_inventory: aplica los registros y fija el estado de la consulta."""
    poll = _poll_of(session, job)
    if poll is None or poll.status not in OPEN_POLL_STATUSES:
        return poll
    device = session.get(NetworkDevice, poll.device_id)
    if device is None:  # pragma: no cover - FK CASCADE
        return poll
    # Solo módulos pedidos: un sensor no puede "informar" un módulo que no se le pidió.
    requested = set(poll.modules_requested or [])
    modules: dict[str, str] = {
        str(k): str(v) for k, v in (summary.modules if summary is not None else {}).items()
    }
    modules = {k: v for k, v in modules.items() if k in requested}
    poll.modules = modules
    sensor_error: str | None = summary.error_code if summary is not None else None
    records = [
        (row.kind, row.data)
        for row in session.scalars(
            select(NetworkPollRecord)
            .where(NetworkPollRecord.poll_id == poll.id)
            .order_by(NetworkPollRecord.id)
        )
    ]
    if outcome == "failed" or (not records and outcome in ("completed", "timed_out")):
        # Sin un solo registro no hay inventario que aplicar: es un fallo, con el motivo que
        # diga el sensor (timeout, credenciales, versión...) y nunca una consulta "parcial".
        fallback = "timeout" if outcome == "timed_out" else "internal"
        if any(e.startswith("job_rejected") for e in errors):
            fallback = "job_rejected"
        failed_code = sensor_error or fallback
        _close_poll(
            session, poll, "failed", failed_code, (errors[0] if errors else failed_code), now
        )
        _audit_failure(session, device, poll, failed_code)
        return poll
    full = outcome == "completed" and missing_batches == 0
    result = PollApplier(session, settings, device, poll, now).apply(records, modules, full)
    incomplete_modules = [m for m, st in modules.items() if st in ("partial", "failed")]
    code: str | None
    if outcome == "cancelled":
        status, code = "cancelled", "cancelled"
    elif not full or incomplete_modules or sensor_error in ("partial", "limit_exceeded"):
        status = "partial"
        code = sensor_error if sensor_error not in (None, "cancelled") else "partial"
        if outcome == "timed_out":
            code = "timeout"
    else:
        status, code = "succeeded", None
    message = None
    if missing_batches:
        message = f"{missing_batches} result batch(es) missing: partial result"
    elif errors:
        message = errors[0]
    poll.counts = result.counts
    poll.changes = result.changes
    _close_poll(session, poll, status, code, message, now)
    device.last_modules = modules
    if status in ("succeeded", "partial"):
        device.last_success_at = now
        device.consecutive_failures = 0
        device.last_error_code = None if status == "succeeded" else code
        device.last_error_at = None if status == "succeeded" else now
    changed = result.changes
    sensor = session.get(Sensor, job.sensor_id)
    if any(
        changed.get(key)
        for key in (
            "interfaces_added",
            "interfaces_removed",
            "neighbors_added",
            "neighbors_removed",
            "classification_changed",
        )
    ):
        audit_service.record(
            session,
            Actor(f"sensor:{sensor.public_id}" if sensor is not None else "system:snmp"),
            "network_inventory_changed",
            target_type="network_device",
            target_id=device.public_id,
            details={"poll_id": str(poll.public_id), **changed},
            commit=False,
        )
    return poll


def _audit_failure(
    session: Session, device: NetworkDevice, poll: NetworkDevicePoll, code: str
) -> None:
    # Los fallos de autenticación SNMP se auditan: pueden indicar una credencial rotada en el
    # equipo y no en Sentra, o alguien probando credenciales con un perfil equivocado.
    if code == "auth_failed":
        audit_service.record(
            session,
            Actor("system:snmp"),
            "snmp_authentication_failed",
            result=audit_service.FAILURE,
            target_type="network_device",
            target_id=device.public_id,
            details={"poll_id": str(poll.public_id)},
            commit=False,
        )


# --- programador y mantenimiento ------------------------------------------------------------


def schedule_due_polls(session: Session, settings: Settings) -> dict[str, int]:
    """Encola consultas de los equipos con monitorización activada cuyo intervalo venció.

    Un equipo que no se puede consultar (sensor caído, sin perfil) no genera un error en
    bucle: su última consulta queda registrada como fallida con el motivo concreto, y el
    siguiente intento llega en el siguiente intervalo.
    """
    counts = {"queued": 0, "blocked": 0}
    interval = settings.snmp_poll_interval_minutes
    if not interval:
        return counts
    now = datetime.now(UTC)
    cutoff = now - timedelta(minutes=interval)
    open_devices = select(NetworkDevicePoll.device_id).where(
        NetworkDevicePoll.status.in_(OPEN_POLL_STATUSES)
    )
    devices = session.scalars(
        select(NetworkDevice)
        .where(
            NetworkDevice.status == "active",
            NetworkDevice.monitoring_enabled,
            # Sin perfil o sin sensor es configuración pendiente, no un fallo: ni se encola ni
            # se registra un intento fallido (y no ocupan el lote de los que sí se pueden).
            NetworkDevice.profile_id.is_not(None),
            NetworkDevice.sensor_id.is_not(None),
            (NetworkDevice.last_poll_at.is_(None)) | (NetworkDevice.last_poll_at <= cutoff),
            NetworkDevice.id.not_in(open_devices),
        )
        .order_by(NetworkDevice.last_poll_at.asc().nullsfirst(), NetworkDevice.id)
        .limit(SCHEDULER_BATCH)
    ).all()
    for device in devices:
        blockers, ctx = poll_blockers(session, settings, device)
        if ctx is None:
            _record_blocked(session, device, blockers, now)
            counts["blocked"] += 1
            continue
        try:
            create_poll(session, settings, device, SCHEDULER, trigger="scheduled")
            counts["queued"] += 1
        except SiteConflictError:
            session.rollback()
            counts["blocked"] += 1
    return counts


def _record_blocked(
    session: Session, device: NetworkDevice, blockers: list[str], now: datetime
) -> None:
    code = "sensor_offline" if "sensor_offline" in blockers else "credentials_unavailable"
    if not any(b.startswith("sensor") for b in blockers) and "profile" not in " ".join(blockers):
        code = "job_rejected"
    poll = NetworkDevicePoll(
        device_id=device.id,
        site_id=device.site_id,
        sensor_id=device.sensor_id,
        profile_id=device.profile_id,
        status="failed",
        trigger="scheduled",
        requested_by=SCHEDULER.name,
        modules_requested=[],
        error_code=code,
        error_message=("blocked: " + ", ".join(blockers))[:300],
        created_at=now,
        finished_at=now,
    )
    session.add(poll)
    device.last_poll_at = now
    device.consecutive_failures += 1
    device.last_error_code = code
    device.last_error_at = now
    session.commit()


def purge_history(session: Session, days: int, now: datetime | None = None) -> dict[str, int]:
    """Retención opt-in (SNMP_HISTORY_RETENTION_DAYS): consultas cerradas y evidencia ausente
    más antiguas que el plazo. Lo presente y los equipos nunca se borran."""
    cutoff = (now or datetime.now(UTC)) - timedelta(days=days)
    counts: dict[str, int] = {}
    statements = {
        "polls": delete(NetworkDevicePoll).where(
            NetworkDevicePoll.status.not_in(OPEN_POLL_STATUSES),
            NetworkDevicePoll.created_at < cutoff,
        ),
        "neighbors": delete(NetworkNeighbor).where(
            NetworkNeighbor.present.is_(False), NetworkNeighbor.last_seen_at < cutoff
        ),
        "mac_entries": delete(NetworkMacEntry).where(
            NetworkMacEntry.present.is_(False), NetworkMacEntry.last_seen_at < cutoff
        ),
        "interfaces": delete(NetworkInterface).where(
            NetworkInterface.present.is_(False), NetworkInterface.last_seen_at < cutoff
        ),
    }
    for name, stmt in statements.items():
        result = session.execute(stmt.execution_options(synchronize_session=False))
        counts[name] = int(getattr(result, "rowcount", 0) or 0)
    session.commit()
    return counts


def run_network_maintenance(session: Session, settings: Settings) -> dict[str, int]:
    counts = schedule_due_polls(session, settings)
    if settings.snmp_history_retention_days:
        counts.update(purge_history(session, settings.snmp_history_retention_days))
    if settings.wlan_history_retention_days:
        from app.services.wlan_service import purge_wlan_history

        counts.update(purge_wlan_history(session, settings.wlan_history_retention_days))
    if any(counts.values()):
        logger.info("network maintenance", extra={f"network_{k}": v for k, v in counts.items()})
    return counts


def open_snmp_job_ids(session: Session, sensor_id: int) -> list[int]:
    return list(
        session.scalars(
            select(SensorJob.id).where(
                SensorJob.sensor_id == sensor_id,
                SensorJob.job_type == SNMP_JOB_TYPE,
                SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES),
            )
        )
    )
