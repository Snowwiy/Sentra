"""Fuentes DHCP, leases e identidad de activos (Fase 6E.2, docs/dhcp-identity.md).

Dos vías de entrada, mismas reglas:
- importación manual: un admin sube el texto de un fichero de leases a una fuente
  `lease_import` (POST /dhcp/sources/{id}/import);
- sensor: una fuente `sensor_file` crea un job `dhcp_leases` con el nombre de la entrada que
  el sensor tiene en su sensor.toml; los lotes llegan por /sensor/jobs/{id}/results.

Ambas acaban en apply_leases: guarda el lease, decide la asociación (app/dhcp/matching.py) y,
solo con coincidencia alta (MAC e IP), anota el hostname en identity_observations["dhcp_lease"]
y reidentifica el activo. Nunca crea ni fusiona activos, nunca borra un lease porque una
lectura no lo traiga (una lectura parcial no es una desaparición) y nunca guarda rutas.
"""

import logging
import uuid
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, distinct, func, or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NotFoundError, SensorNotFoundError, SiteNotFoundError
from app.dhcp import matching, parsers
from app.dhcp.errors import DhcpImportError, DhcpSourceConflictError, DhcpSourceNotFoundError
from app.dhcp.parsers import LeaseRecord
from app.discovery import oui
from app.models.asset import Asset
from app.models.dhcp import AssetIdentityHistory, DhcpLease, DhcpSource
from app.models.site import OPEN_SENSOR_JOB_STATUSES, Sensor, SensorJob, Site
from app.models.wlan import WlanAccessPoint, WlanClient
from app.schemas.dhcp import (
    AssetIdentityHistory as AssetIdentityHistoryOut,
)
from app.schemas.dhcp import (
    AssetIdentityHistoryEntry,
    AssetIdentityRead,
    AssetWifiRef,
    DhcpImportIn,
    DhcpImportResult,
    DhcpLeaseList,
    DhcpLeaseRead,
    DhcpReadRequested,
    DhcpSiteRef,
    DhcpSourceCreate,
    DhcpSourceList,
    DhcpSourceRead,
    DhcpSourceUpdate,
)
from app.schemas.site import SensorDhcpSummary, SensorLeaseIn
from app.sensors.catalog import DHCP_CAPABILITY, DHCP_LEASES
from app.services import audit_service
from app.services.asset_service import open_ports_by_asset
from app.services.audit_service import Actor
from app.services.identification import refresh_identity

logger = logging.getLogger(__name__)

OBSERVATION_KEY = "dhcp_lease"
BATCH = 5000
# Un nombre que deja de aparecer en leases durante este plazo se marca antiguo (misma regla
# que el resto de fuentes de nombre: identification.NAME_STALE_DAYS).
LEASES_PER_ASSET = 10


@dataclass
class Applied:
    matched: int = 0
    named: int = 0
    ambiguous: int = 0

    def add(self, other: "Applied") -> None:
        self.matched += other.matched
        self.named += other.named
        self.ambiguous += other.ambiguous


def _now() -> datetime:
    return datetime.now(UTC)


# --- aplicación de leases (común a importación y sensor) ---------------------------------------


def _set_observation(asset: Asset, source: DhcpSource, lease: DhcpLease, now: datetime) -> None:
    current: dict[str, Any] = dict(asset.identity_observations or {})
    seen: dict[str, Any] = dict(current.get("seen_at") or {})
    current[OBSERVATION_KEY] = {
        "hostname": lease.hostname,
        "source": source.name,
        "source_id": str(source.public_id),
        "ip": lease.ip,
        "mac": lease.mac,
    }
    seen[OBSERVATION_KEY] = now.isoformat()
    current["seen_at"] = seen
    # Dict nuevo para que SQLAlchemy detecte el cambio de la columna JSONB.
    asset.identity_observations = current


def _clear_observation(asset: Asset, source: DhcpSource) -> bool:
    current: dict[str, Any] = dict(asset.identity_observations or {})
    observation = current.get(OBSERVATION_KEY)
    if not isinstance(observation, dict) or observation.get("source_id") != str(source.public_id):
        return False
    current.pop(OBSERVATION_KEY, None)
    seen = dict(current.get("seen_at") or {})
    seen.pop(OBSERVATION_KEY, None)
    if seen:
        current["seen_at"] = seen
    else:
        current.pop("seen_at", None)
    asset.identity_observations = current or None
    return True


def _duplicated_hostnames(session: Session, site_id: int, names: set[str]) -> set[str]:
    """Hostnames (en minúsculas) que el site da a la vez a más de una MAC en leases activos."""
    if not names:
        return set()
    lowered = func.lower(DhcpLease.hostname)
    rows = session.scalars(
        select(lowered)
        .where(DhcpLease.site_id == site_id, DhcpLease.state == "active", lowered.in_(names))
        .group_by(lowered)
        .having(func.count(distinct(DhcpLease.mac)) > 1)
    )
    return {name for name in rows if name}


def apply_leases(
    session: Session, source: DhcpSource, records: Sequence[LeaseRecord], now: datetime
) -> Applied:
    """Guarda un lote de leases de una fuente y aplica sus conclusiones. No hace commit."""
    applied = Applied()
    if not records:
        return applied
    site_id = source.site_id
    macs = {r.mac for r in records}
    ips = {r.ip for r in records}
    live = (Asset.site_id == site_id, Asset.archived_at.is_(None))
    by_mac: dict[str, list[matching.AssetCandidate]] = defaultdict(list)
    for asset_id, mac, ip in session.execute(
        select(Asset.id, Asset.mac_address, Asset.primary_ip).where(
            *live, Asset.mac_address.in_(macs)
        )
    ):
        if mac:
            by_mac[mac].append(matching.AssetCandidate(asset_id, mac, ip))
    ip_assets = set(
        session.scalars(select(Asset.primary_ip).where(*live, Asset.primary_ip.in_(ips)))
    )
    existing = {
        (lease.ip, lease.mac): lease
        for lease in session.scalars(
            select(DhcpLease).where(DhcpLease.source_id == source.id, DhcpLease.ip.in_(ips))
        )
    }
    exact: list[tuple[int, DhcpLease]] = []
    for record in records:
        lease = existing.get((record.ip, record.mac))
        if lease is None:
            lease = DhcpLease(
                site_id=site_id,
                source_id=source.id,
                ip=record.ip,
                mac=record.mac,
                first_seen_at=now,
            )
            session.add(lease)
            existing[(record.ip, record.mac)] = lease
        lease.hostname = record.hostname
        lease.client_id = record.client_id
        lease.starts_at = record.starts_at
        lease.ends_at = record.ends_at
        lease.state = record.state
        lease.last_seen_at = now
        result = matching.ip_only(
            matching.match_lease(
                ip=record.ip, mac=record.mac, state=record.state, by_mac=by_mac.get(record.mac, ())
            ),
            record.ip in ip_assets,
        )
        lease.match = result.match
        lease.asset_id = result.asset_id
        if result.asset_id is not None:
            applied.matched += 1
        if result.match == "ambiguous":
            applied.ambiguous += 1
        if result.names_asset and result.asset_id is not None:
            exact.append((result.asset_id, lease))
    session.flush()
    if not exact:
        return applied
    duplicated = _duplicated_hostnames(
        session,
        site_id,
        {lease.hostname.lower() for _, lease in exact if lease.hostname},
    )
    assets = {
        a.id: a for a in session.scalars(select(Asset).where(Asset.id.in_({i for i, _ in exact})))
    }
    touched: set[int] = set()
    for asset_id, lease in exact:
        asset = assets[asset_id]
        hostname = lease.hostname
        if hostname and matching.usable_hostname(hostname) and hostname.lower() not in duplicated:
            _set_observation(asset, source, lease, now)
            applied.named += 1
            touched.add(asset_id)
        elif _clear_observation(asset, source):
            # El nombre que esta fuente daba ya no sirve (genérico o repetido): se retira en
            # vez de mantener un nombre que ya no distingue al equipo.
            touched.add(asset_id)
    ports = open_ports_by_asset(session, touched)
    for asset_id in touched:
        refresh_identity(assets[asset_id], ports.get(asset_id, ()))
    return applied


# --- sensor ----------------------------------------------------------------------------------


def source_for_job(session: Session, job: SensorJob, *, lock: bool = False) -> DhcpSource | None:
    name = (job.parameters or {}).get("source_name")
    query = select(DhcpSource).where(
        DhcpSource.sensor_id == job.sensor_id,
        DhcpSource.sensor_source_name == name,
        DhcpSource.site_id == job.site_id,
    )
    if lock:
        query = query.with_for_update()
    return session.scalars(query).first()


def apply_sensor_batch(
    session: Session, job: SensorJob, leases: Sequence[SensorLeaseIn], now: datetime
) -> int:
    """Lote de un job dhcp_leases. Si la fuente ya no existe o está deshabilitada no se
    aplica nada (el admin la retiró mientras el sensor leía)."""
    source = source_for_job(session, job)
    if source is None or source.status == "disabled":
        return 0
    records = []
    for item in leases:
        mac = item.mac
        records.append(
            LeaseRecord(
                ip=item.ip,
                mac=mac,
                hostname=parsers.clean_hostname(item.hostname),
                client_id=item.client_id,
                starts_at=item.starts_at,
                ends_at=item.ends_at,
                state=item.state,
            )
        )
    applied = apply_leases(session, source, records, now)
    stats = dict(source.last_stats or {})
    for key in ("matched", "named", "ambiguous"):
        stats[f"pending_{key}"] = int(stats.get(f"pending_{key}", 0)) + getattr(applied, key)
    source.last_stats = stats
    return len(records)


def complete_sensor_job(
    session: Session,
    job: SensorJob,
    outcome: str,
    summary: SensorDhcpSummary | None,
    errors: Sequence[str],
    missing: int,
    now: datetime,
) -> None:
    """Cierre de un job dhcp_leases: estado y estadísticas de la fuente."""
    source = source_for_job(session, job, lock=True)
    if source is None:
        return
    stats = dict(source.last_stats or {})
    applied = {k: int(stats.pop(f"pending_{k}", 0)) for k in ("matched", "named", "ambiguous")}
    error_code: str | None = summary.error_code if summary is not None else None
    if outcome == "failed" and error_code is None:
        error_code = "sensor_failed"
    if outcome == "completed" and missing:
        error_code = error_code or "dhcp_batches_missing"
    if source.status != "disabled":
        source.status = "error" if error_code else "ok"
    source.last_error_code = error_code
    if outcome in ("completed", "timed_out") and summary is not None:
        source.last_import_at = now
        source.last_stats = {
            "lines": summary.lines,
            "parsed": summary.parsed,
            "skipped": summary.skipped,
            "truncated": summary.truncated or bool(missing),
            "file_mtime": summary.file_mtime.isoformat() if summary.file_mtime else None,
            **applied,
        }
    else:
        source.last_stats = stats or None


def _open_job(session: Session, source: DhcpSource) -> SensorJob | None:
    if source.sensor_id is None:
        return None
    return session.scalars(
        select(SensorJob).where(
            SensorJob.sensor_id == source.sensor_id,
            SensorJob.job_type == DHCP_LEASES,
            SensorJob.status.in_(OPEN_SENSOR_JOB_STATUSES),
            SensorJob.parameters["source_name"].astext == source.sensor_source_name,
        )
    ).first()


def _sensor_ready(sensor: Sensor | None) -> bool:
    return (
        sensor is not None
        and sensor.status == "active"
        and sensor.revoked_at is None
        and sensor.disabled_at is None
        and DHCP_CAPABILITY in (sensor.capabilities or [])
    )


def _create_job(
    session: Session, settings: Settings, source: DhcpSource, sensor: Sensor, by: str, now: datetime
) -> SensorJob:
    job = SensorJob(
        site_id=source.site_id,
        sensor_id=sensor.id,
        job_type=DHCP_LEASES,
        # Esquema exacto del sensor 0.6.0: solo el nombre (cualquier otra clave se rechaza).
        parameters={"source_name": source.sensor_source_name},
        status="pending",
        created_by=by,
        created_at=now,
        expires_at=now + timedelta(minutes=settings.sensor_job_ttl_minutes),
        max_attempts=settings.sensor_job_max_attempts,
    )
    session.add(job)
    session.flush()
    source.last_requested_at = now
    return job


def schedule_due_reads(session: Session, settings: Settings, now: datetime | None = None) -> int:
    """Encola la lectura de las fuentes de sensor con poll_interval_minutes vencido."""
    now = now or _now()
    created = 0
    sources = session.scalars(
        select(DhcpSource).where(
            DhcpSource.kind == "sensor_file",
            DhcpSource.status != "disabled",
            DhcpSource.poll_interval_minutes > 0,
            DhcpSource.sensor_id.is_not(None),
        )
    ).all()
    for source in sources:
        due = source.last_requested_at is None or now - source.last_requested_at >= timedelta(
            minutes=source.poll_interval_minutes
        )
        if not due or _open_job(session, source) is not None:
            continue
        sensor = session.get(Sensor, source.sensor_id)
        if not _sensor_ready(sensor):
            continue
        assert sensor is not None  # noqa: S101
        _create_job(session, settings, source, sensor, "scheduler", now)
        created += 1
    session.commit()
    return created


# Fase 7A.4: separación mínima entre lecturas automáticas tras un discovery. Un site con
# discovery cada pocos minutos no relee el fichero de leases en cada pasada.
AUTO_READ_MIN_INTERVAL = timedelta(minutes=10)


def schedule_reads_after_discovery(
    session: Session, settings: Settings, site_id: int, now: datetime | None = None
) -> int:
    """Encola la lectura de las fuentes DHCP de sensor del site tras un discovery completo.

    Así la identificación usa los hostnames DHCP sin que nadie pulse "Leer ahora": el
    discovery acaba de ver qué hosts hay y los leases dicen cómo se llaman. Solo fuentes
    activas con sensor listo, sin otra lectura abierta y sin una lectura en los últimos
    AUTO_READ_MIN_INTERVAL. Las fuentes de importación manual no cambian (no hay nada que
    leer). No hace commit: va en la transacción que cierra el discovery.
    """
    now = now or _now()
    created = 0
    sources = session.scalars(
        select(DhcpSource).where(
            DhcpSource.site_id == site_id,
            DhcpSource.kind == "sensor_file",
            DhcpSource.status != "disabled",
            DhcpSource.sensor_id.is_not(None),
        )
    ).all()
    for source in sources:
        recent = (
            source.last_requested_at is not None
            and now - source.last_requested_at < AUTO_READ_MIN_INTERVAL
        )
        if recent or _open_job(session, source) is not None:
            continue
        sensor = session.get(Sensor, source.sensor_id)
        if not _sensor_ready(sensor):
            continue
        assert sensor is not None  # noqa: S101
        _create_job(session, settings, source, sensor, "discovery", now)
        created += 1
    return created


def purge_dhcp(session: Session, settings: Settings, now: datetime) -> dict[str, int]:
    """Retención: leases que ninguna lectura vuelve a ver e historial de identidad antiguo."""
    counts: dict[str, int] = {}
    if settings.dhcp_lease_retention_days:
        cutoff = now - timedelta(days=settings.dhcp_lease_retention_days)
        result = session.execute(delete(DhcpLease).where(DhcpLease.last_seen_at < cutoff))
        counts["dhcp_leases"] = int(getattr(result, "rowcount", 0) or 0)
    if settings.asset_identity_history_retention_days:
        cutoff = now - timedelta(days=settings.asset_identity_history_retention_days)
        result = session.execute(
            delete(AssetIdentityHistory).where(AssetIdentityHistory.observed_at < cutoff)
        )
        counts["asset_identity_history"] = int(getattr(result, "rowcount", 0) or 0)
    return counts


# --- API ----------------------------------------------------------------------------------------


class DhcpService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def _site(self, public_id: uuid.UUID | None) -> Site:
        query = select(Site)
        query = (
            query.where(Site.public_id == public_id)
            if public_id is not None
            else query.where(Site.is_default.is_(True))
        )
        site = self._session.scalars(query).first()
        if site is None:
            raise SiteNotFoundError("Site not found")
        return site

    def _source(self, public_id: uuid.UUID, *, lock: bool = False) -> DhcpSource:
        query = select(DhcpSource).where(DhcpSource.public_id == public_id)
        if lock:
            query = query.with_for_update()
        source = self._session.scalars(query).first()
        if source is None:
            raise DhcpSourceNotFoundError("DHCP source not found")
        return source

    def _reads(self, sources: Sequence[DhcpSource]) -> list[DhcpSourceRead]:
        session = self._session
        site_ids = {s.site_id for s in sources}
        sensor_ids = {s.sensor_id for s in sources if s.sensor_id is not None}
        sites = {
            row.id: row
            for row in session.execute(
                select(Site.id, Site.public_id, Site.name).where(Site.id.in_(site_ids))
            )
        }
        sensors = {
            row.id: row
            for row in session.execute(
                select(Sensor.id, Sensor.public_id, Sensor.name).where(Sensor.id.in_(sensor_ids))
            )
        }
        counts: dict[int, int] = {
            source_id: int(total)
            for source_id, total in session.execute(
                select(DhcpLease.source_id, func.count())
                .where(DhcpLease.source_id.in_([s.id for s in sources]))
                .group_by(DhcpLease.source_id)
            )
        }
        out = []
        for source in sources:
            site = sites[source.site_id]
            sensor = sensors.get(source.sensor_id) if source.sensor_id else None
            out.append(
                DhcpSourceRead(
                    id=source.public_id,
                    site=DhcpSiteRef(id=site.public_id, name=site.name),
                    name=source.name,
                    kind=source.kind,
                    format=source.format,
                    sensor_id=sensor.public_id if sensor else None,
                    sensor_name=sensor.name if sensor else None,
                    sensor_source_name=source.sensor_source_name,
                    poll_interval_minutes=source.poll_interval_minutes,
                    status=source.status,
                    last_requested_at=source.last_requested_at,
                    last_import_at=source.last_import_at,
                    last_error_code=source.last_error_code,
                    last_stats=source.last_stats,
                    lease_count=int(counts.get(source.id, 0)),
                    created_by=source.created_by,
                    created_at=source.created_at,
                    updated_at=source.updated_at,
                    version=source.version,
                )
            )
        return out

    def _read(self, source: DhcpSource) -> DhcpSourceRead:
        self._session.flush()
        self._session.refresh(source)
        return self._reads([source])[0]

    def list_sources(self, site_id: uuid.UUID | None) -> DhcpSourceList:
        query = select(DhcpSource).order_by(DhcpSource.name, DhcpSource.id)
        if site_id is not None:
            query = query.where(DhcpSource.site_id == self._site(site_id).id)
        return DhcpSourceList(items=self._reads(self._session.scalars(query).all()))

    def get_source(self, public_id: uuid.UUID) -> DhcpSourceRead:
        return self._reads([self._source(public_id)])[0]

    def create_source(self, body: DhcpSourceCreate, actor: Actor) -> DhcpSourceRead:
        session = self._session
        site = self._site(body.site_id)
        if site.status != "active":
            raise DhcpSourceConflictError("site_not_active", "The site is not active")
        if session.scalar(
            select(DhcpSource.id).where(DhcpSource.site_id == site.id, DhcpSource.name == body.name)
        ):
            raise DhcpSourceConflictError("dhcp_source_name_taken", "Name already used in site")
        sensor_id = None
        if body.sensor_id is not None:
            sensor = session.scalars(
                select(Sensor).where(Sensor.public_id == body.sensor_id)
            ).first()
            # Un sensor de otro site responde igual que uno inexistente.
            if sensor is None or sensor.site_id != site.id or sensor.revoked_at is not None:
                raise SensorNotFoundError("Sensor not found")
            if session.scalar(
                select(DhcpSource.id).where(
                    DhcpSource.sensor_id == sensor.id,
                    DhcpSource.sensor_source_name == body.sensor_source_name,
                )
            ):
                raise DhcpSourceConflictError(
                    "dhcp_sensor_source_taken", "That sensor source is already declared"
                )
            sensor_id = sensor.id
        source = DhcpSource(
            site_id=site.id,
            name=body.name,
            kind=body.kind,
            format=body.format,
            sensor_id=sensor_id,
            sensor_source_name=body.sensor_source_name,
            poll_interval_minutes=body.poll_interval_minutes,
            status="pending",
            created_by=actor.name,
        )
        session.add(source)
        session.flush()
        audit_service.record(
            session,
            actor,
            "dhcp_source_created",
            target_type="dhcp_source",
            target_id=source.public_id,
            details={"site": str(site.public_id), "kind": body.kind, "format": body.format},
            commit=False,
        )
        read = self._read(source)
        session.commit()
        return read

    def _check_version(self, source: DhcpSource, version: int) -> None:
        if source.version != version:
            raise DhcpSourceConflictError(
                "dhcp_source_conflict",
                "The source changed; reload it",
                [{"version": source.version}],
            )

    def update_source(
        self, public_id: uuid.UUID, body: DhcpSourceUpdate, actor: Actor
    ) -> DhcpSourceRead:
        session = self._session
        source = self._source(public_id, lock=True)
        self._check_version(source, body.version)
        changes: dict[str, Any] = {}
        if body.enabled is not None:
            if not body.enabled and source.status != "disabled":
                source.status = "disabled"
                changes["enabled"] = False
            elif body.enabled and source.status == "disabled":
                source.status = "pending"
                changes["enabled"] = True
        if body.format is not None and body.format != source.format:
            source.format = body.format
            changes["format"] = body.format
        if body.poll_interval_minutes is not None:
            if source.kind != "sensor_file" and body.poll_interval_minutes:
                raise DhcpImportError("dhcp_source_not_polled", "Imported sources are not polled")
            if body.poll_interval_minutes != source.poll_interval_minutes:
                source.poll_interval_minutes = body.poll_interval_minutes
                changes["poll_interval_minutes"] = body.poll_interval_minutes
        if changes:
            source.version += 1
            audit_service.record(
                session,
                actor,
                "dhcp_source_updated",
                target_type="dhcp_source",
                target_id=source.public_id,
                details=changes,
                commit=False,
            )
        read = self._read(source)
        session.commit()
        return read

    def delete_source(self, public_id: uuid.UUID, version: int, actor: Actor) -> None:
        """Borra la fuente y sus leases, y retira el nombre que dio a cada activo."""
        session = self._session
        source = self._source(public_id, lock=True)
        self._check_version(source, version)
        asset_ids = set(
            session.scalars(
                select(DhcpLease.asset_id).where(
                    DhcpLease.source_id == source.id, DhcpLease.asset_id.is_not(None)
                )
            )
        )
        assets = session.scalars(select(Asset).where(Asset.id.in_(asset_ids))).all()
        touched = [a for a in assets if _clear_observation(a, source)]
        ports = open_ports_by_asset(session, (a.id for a in touched))
        for asset in touched:
            refresh_identity(asset, ports.get(asset.id, ()))
        audit_service.record(
            session,
            actor,
            "dhcp_source_deleted",
            target_type="dhcp_source",
            target_id=source.public_id,
            details={"name": source.name, "assets_renamed": len(touched)},
            commit=False,
        )
        session.delete(source)
        session.commit()

    def import_leases(
        self, public_id: uuid.UUID, body: DhcpImportIn, actor: Actor
    ) -> DhcpImportResult:
        session = self._session
        settings = self._settings
        source = self._source(public_id, lock=True)
        self._check_version(source, body.version)
        if source.kind != "lease_import":
            raise DhcpSourceConflictError(
                "dhcp_source_kind", "Only lease_import sources accept uploads"
            )
        if source.status == "disabled":
            raise DhcpSourceConflictError("dhcp_source_disabled", "The source is disabled")
        size = len(body.content.encode("utf-8"))
        if size > settings.dhcp_import_max_kb * 1024:
            raise DhcpImportError(
                "dhcp_file_too_large",
                f"At most {settings.dhcp_import_max_kb} KiB per import",
                [{"max_kb": settings.dhcp_import_max_kb}],
            )
        now = _now()
        try:
            parsed = parsers.parse(source.format, body.content, now)
        except parsers.LeaseFormatError as exc:
            source.status = "error"
            source.last_error_code = "dhcp_format_invalid"
            source.version += 1
            audit_service.record(
                session,
                actor,
                "dhcp_leases_imported",
                result=audit_service.FAILURE,
                target_type="dhcp_source",
                target_id=source.public_id,
                details={"error": "dhcp_format_invalid"},
                commit=False,
            )
            session.commit()
            raise DhcpImportError("dhcp_format_invalid", str(exc)[:200]) from exc
        if parsed.lines and not parsed.leases and parsed.skipped:
            # Ni un registro legible: casi siempre es el formato equivocado. Se informa en vez
            # de dar por buena una importación vacía.
            source.status = "error"
            source.last_error_code = "dhcp_format_invalid"
            source.version += 1
            session.commit()
            raise DhcpImportError("dhcp_format_invalid", "No lease could be read with this format")
        applied = Applied()
        for start in range(0, len(parsed.leases), BATCH):
            applied.add(apply_leases(session, source, parsed.leases[start : start + BATCH], now))
        source.status = "ok"
        source.last_error_code = None
        source.last_import_at = now
        source.last_stats = {
            "lines": parsed.lines,
            "parsed": parsed.parsed,
            "skipped": parsed.skipped,
            "truncated": parsed.truncated,
            "matched": applied.matched,
            "named": applied.named,
            "ambiguous": applied.ambiguous,
        }
        source.version += 1
        audit_service.record(
            session,
            actor,
            "dhcp_leases_imported",
            target_type="dhcp_source",
            target_id=source.public_id,
            details={
                "bytes": size,
                "parsed": parsed.parsed,
                "skipped": parsed.skipped,
                "matched": applied.matched,
                "named": applied.named,
            },
            commit=False,
        )
        read = self._read(source)
        session.commit()
        logger.info(
            "dhcp leases imported",
            extra={
                "source": str(source.public_id),
                "parsed": parsed.parsed,
                "named": applied.named,
            },
        )
        return DhcpImportResult(
            source=read,
            lines=parsed.lines,
            parsed=parsed.parsed,
            skipped=parsed.skipped,
            truncated=parsed.truncated,
            matched=applied.matched,
            named=applied.named,
            ambiguous=applied.ambiguous,
        )

    def request_read(self, public_id: uuid.UUID, actor: Actor) -> DhcpReadRequested:
        session = self._session
        source = self._source(public_id, lock=True)
        if source.kind != "sensor_file":
            raise DhcpSourceConflictError("dhcp_source_kind", "Only sensor_file sources are read")
        if source.status == "disabled":
            raise DhcpSourceConflictError("dhcp_source_disabled", "The source is disabled")
        sensor = session.get(Sensor, source.sensor_id) if source.sensor_id else None
        if sensor is None or not _sensor_ready(sensor):
            raise DhcpSourceConflictError(
                "dhcp_sensor_unavailable",
                "The sensor is missing, disabled or does not support DHCP lease files (>= 0.6.0)",
            )
        if _open_job(session, source) is not None:
            raise DhcpSourceConflictError("dhcp_read_in_progress", "A read is already queued")
        now = _now()
        job = _create_job(session, self._settings, source, sensor, actor.name, now)
        audit_service.record(
            session,
            actor,
            "dhcp_read_requested",
            target_type="dhcp_source",
            target_id=source.public_id,
            details={"sensor_job": str(job.public_id)},
            commit=False,
        )
        read = self._read(source)
        session.commit()
        return DhcpReadRequested(source=read, sensor_job_id=job.public_id)

    # --- leases e identidad ------------------------------------------------------------------

    def _lease_reads(self, rows: Sequence[DhcpLease]) -> list[DhcpLeaseRead]:
        session = self._session
        sources = {
            row.id: row
            for row in session.execute(
                select(DhcpSource.id, DhcpSource.public_id, DhcpSource.name).where(
                    DhcpSource.id.in_({r.source_id for r in rows})
                )
            )
        }
        asset_ids = {r.asset_id for r in rows if r.asset_id is not None}
        assets = {a.id: a for a in session.scalars(select(Asset).where(Asset.id.in_(asset_ids)))}
        out = []
        for lease in rows:
            source = sources[lease.source_id]
            asset = assets.get(lease.asset_id) if lease.asset_id else None
            out.append(
                DhcpLeaseRead(
                    source_id=source.public_id,
                    source_name=source.name,
                    ip=lease.ip,
                    mac=lease.mac,
                    mac_randomized=oui.is_locally_administered(lease.mac),
                    hostname=lease.hostname,
                    hostname_usable=matching.usable_hostname(lease.hostname),
                    state=lease.state,
                    starts_at=lease.starts_at,
                    ends_at=lease.ends_at,
                    match=lease.match,
                    asset_id=asset.public_id if asset else None,
                    asset_name=asset.display_name if asset else None,
                    first_seen_at=lease.first_seen_at,
                    last_seen_at=lease.last_seen_at,
                )
            )
        return out

    def list_leases(
        self,
        site_id: uuid.UUID | None,
        source_id: uuid.UUID | None,
        match: str | None,
        search: str | None,
        limit: int,
        offset: int,
    ) -> DhcpLeaseList:
        conditions: list[Any] = []
        if site_id is not None:
            conditions.append(DhcpLease.site_id == self._site(site_id).id)
        if source_id is not None:
            conditions.append(DhcpLease.source_id == self._source(source_id).id)
        if match is not None:
            conditions.append(DhcpLease.match == match)
        if search:
            needle = search.strip().lower()
            pattern = (
                "%" + needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            )
            conditions.append(
                or_(
                    DhcpLease.ip == needle,
                    DhcpLease.mac == needle,
                    func.lower(DhcpLease.hostname).like(pattern, escape="\\"),
                )
            )
        total = int(
            self._session.scalar(select(func.count()).select_from(DhcpLease).where(*conditions))
            or 0
        )
        rows = self._session.scalars(
            select(DhcpLease)
            .where(*conditions)
            .order_by(DhcpLease.last_seen_at.desc(), DhcpLease.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return DhcpLeaseList(items=self._lease_reads(rows), total=total, limit=limit, offset=offset)

    def _asset(self, public_id: uuid.UUID) -> Asset:
        asset = self._session.scalars(select(Asset).where(Asset.public_id == public_id)).first()
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _asset_leases(self, asset: Asset) -> list[DhcpLease]:
        conditions = [DhcpLease.asset_id == asset.id]
        if asset.mac_address:
            conditions.append(DhcpLease.mac == asset.mac_address)
        return list(
            self._session.scalars(
                select(DhcpLease)
                .where(DhcpLease.site_id == asset.site_id, or_(*conditions))
                .order_by(DhcpLease.last_seen_at.desc(), DhcpLease.id.desc())
                .limit(LEASES_PER_ASSET)
            )
        )

    def _wifi(self, asset: Asset) -> AssetWifiRef | None:
        row = self._session.execute(
            select(WlanClient, WlanAccessPoint.name)
            .outerjoin(WlanAccessPoint, WlanAccessPoint.id == WlanClient.access_point_id)
            .where(WlanClient.asset_id == asset.id, WlanClient.present.is_(True))
            .order_by(WlanClient.last_seen_at.desc())
            .limit(1)
        ).first()
        if row is None:
            return None
        client, ap_name = row
        return AssetWifiRef(
            ssid=client.ssid,
            bssid=client.bssid,
            access_point_name=ap_name,
            band=client.band,
            state=client.state,
            last_seen_at=client.last_seen_at,
        )

    def _reasons(self, asset: Asset, leases: list[DhcpLease]) -> list[str]:
        """Por qué el activo no tiene nombre automático (vacío si lo tiene)."""
        if asset.device_name or (asset.is_managed and asset.hostname):
            return []
        reasons: list[str] = []
        names = asset.observed_names or []
        if not names:
            reasons.append("no_name_sources")
        elif all(n.get("kind") == "generic" for n in names):
            reasons.append("only_generic_names")
        elif all(n.get("stale") or n.get("kind") == "generic" for n in names):
            reasons.append("names_stale")
        if oui.is_locally_administered(asset.mac_address):
            reasons.append("randomized_mac")
        has_source = self._session.scalar(
            select(DhcpSource.id)
            .where(DhcpSource.site_id == asset.site_id, DhcpSource.status != "disabled")
            .limit(1)
        )
        if has_source is None:
            reasons.append("dhcp_source_missing")
        elif not leases:
            reasons.append("dhcp_no_lease")
        elif not any(
            lease.match == "mac_ip" and matching.usable_hostname(lease.hostname) for lease in leases
        ):
            reasons.append("dhcp_lease_unusable_name")
        if asset.vendor or asset.device_vendor:
            reasons.append("only_vendor")
        return reasons

    def asset_identity(self, public_id: uuid.UUID) -> AssetIdentityRead:
        asset = self._asset(public_id)
        leases = self._asset_leases(asset)
        return AssetIdentityRead(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            custom_label=asset.custom_label,
            automatic_name=asset.device_name or (asset.hostname if asset.is_managed else None),
            name_source=asset.name_source,
            names=list(asset.observed_names or []),
            ip=asset.primary_ip,
            mac=asset.mac_address,
            mac_randomized=oui.is_locally_administered(asset.mac_address),
            vendor=asset.device_vendor or asset.vendor,
            device_type=asset.device_type,
            classification_confidence=(
                asset.classification_confidence.value if asset.classification_confidence else None
            ),
            leases=self._lease_reads(leases),
            wifi=self._wifi(asset),
            unidentified_reasons=self._reasons(asset, leases),
        )

    def identity_history(
        self, public_id: uuid.UUID, before_id: int | None, limit: int, field: str | None = None
    ) -> AssetIdentityHistoryOut:
        asset = self._asset(public_id)
        query = select(AssetIdentityHistory).where(AssetIdentityHistory.asset_id == asset.id)
        if field is not None:
            query = query.where(AssetIdentityHistory.field == field)
        if before_id is not None:
            # Cursor por id (creciente con el tiempo): dos cambios en el mismo instante no se
            # pierden entre páginas, como pasaría con un cursor por fecha.
            query = query.where(AssetIdentityHistory.id < before_id)
        rows = self._session.scalars(
            query.order_by(AssetIdentityHistory.id.desc()).limit(limit + 1)
        ).all()
        page = rows[:limit]
        return AssetIdentityHistoryOut(
            asset_id=asset.public_id,
            items=[
                AssetIdentityHistoryEntry(
                    field=row.field,
                    old_value=row.old_value,
                    new_value=row.new_value,
                    source=row.source,
                    confidence=row.confidence,
                    observed_at=row.observed_at,
                )
                for row in page
            ],
            next_before_id=page[-1].id if len(rows) > limit else None,
        )
