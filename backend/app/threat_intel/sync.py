"""Sincronización e importación de fuentes de inteligencia (Fase 5C).

Flujo común: descargar (o leer el fichero) -> validar -> parsear -> staging -> aplicar en UNA
transacción -> encolar lo afectado. Si algo falla antes del commit no queda nada a medias y
la fuente conserva su última inteligencia válida ("Using cached intelligence"): el fallo se
apunta en la fuente (status, last_error) y en el historial de sincronizaciones, nunca rompe
la API ni la readiness.

Concurrencia: una sincronización o importación a la vez POR FUENTE con un advisory lock de
PostgreSQL (db/locks.threat_source_lock_key). La descarga ocurre FUERA de la transacción de
escritura (puede tardar) pero dentro del lock de la fuente.

Red: solo el job o la CLI descargan, solo si THREAT_INTEL_SYNC_ENABLED=true, solo desde la
URL por defecto del adapter o la configurada en THREAT_INTEL_SOURCE_URLS (nunca una URL que
llegue del navegador) y siempre con las defensas de http.py (SSRF, tamaño, tiempos).
"""

import hashlib
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from sqlalchemy import Engine, String, column, func, select, table, text
from sqlalchemy.orm import Session

from app.core.exceptions import (
    NotFoundError,
    ThreatIntelBusyError,
    ThreatIntelChangedError,
    ThreatIntelError,
)
from app.core.metrics import REGISTRY
from app.db.locks import singleton_lock, threat_source_lock_key
from app.models.incident import Incident, IncidentActivity, IncidentStatus, IncidentVulnerability
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelMatch,
    ThreatIntelSource,
    ThreatIntelSync,
    VulnerabilityIntel,
)
from app.models.vulnerability import VulnerabilityFinding
from app.risk.queue import request_recalculation
from app.services import audit_service
from app.services.audit_service import Actor
from app.threat_intel import store
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.errors import IntelFormatError
from app.threat_intel.http import FetchError, FetchPolicy, FetchResult, fetch
from app.threat_intel.indicators import TELEMETRY_SUPPORT
from app.threat_intel.providers import (
    ParsedFeed,
    ThreatIntelProvider,
    get_provider,
    parse_import,
    parse_vulnerability_import,
)
from app.threat_intel.records import InvalidRecord

logger = logging.getLogger(__name__)

Fetcher = Callable[..., FetchResult]

# Tras un fallo se reintenta antes que el intervalo normal (pero sin martillear la fuente).
RETRY_AFTER = timedelta(hours=1)
# Protección de feeds completos: si llega MUCHO menos de lo que había (fichero recortado por
# un proxy, feed vacío por un error del proveedor), no se desactiva medio catálogo. Se
# rechaza y la fuente conserva su estado; un administrador puede revisar e importar a mano.
SHRINK_MIN_EXISTING = 1000
SHRINK_RATIO = 0.5
# Actividad de incidentes por sincronización (cambios KEV de CVEs en casos activos).
MAX_INCIDENT_ACTIVITY = 200
_ACTIVE_INCIDENT = (
    IncidentStatus.OPEN,
    IncidentStatus.TRIAGE,
    IncidentStatus.INVESTIGATING,
    IncidentStatus.CONTAINED,
)
_KEV_SUMMARY = {
    "kev_added": "CISA KEV: {cve} añadido al catálogo de explotación conocida",
    "kev_readded": "CISA KEV: {cve} vuelve al catálogo de explotación conocida",
    "kev_removed": "CISA KEV: {cve} retirado del catálogo",
}


@dataclass
class SyncOutcome:
    source_key: str
    status: str  # success | not_modified | failed
    sync_id: int | None = None
    counts: dict[str, int] = field(default_factory=dict)
    error_code: str | None = None
    error_message: str | None = None
    assets_queued: int = 0


@dataclass
class ImportPreview:
    source_key: str
    format: str
    sha256: str
    size_bytes: int
    source_version: str | None
    total: int
    valid: int
    new: int
    updated: int
    unchanged: int
    invalid: int
    invalid_records: list[InvalidRecord]
    unsupported: dict[str, int]
    by_type: dict[str, int]
    # Indicadores válidos que NO pueden casar con datos locales (hashes, URLs, emails...).
    not_matchable: int


@dataclass
class ImportResult:
    source_key: str
    sha256: str
    new: int
    updated: int
    unchanged: int
    invalid: int
    pending_match: int


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def source_url(source: ThreatIntelSource, config: ThreatIntelConfig) -> str | None:
    """URL de descarga: la de THREAT_INTEL_SOURCE_URLS para esta fuente o la del adapter."""
    provider = get_provider(source.provider)
    return config.source_urls.get(source.source_key) or provider.default_url


def _short(value: str | None, limit: int) -> str | None:
    return value[:limit] if value else value


def propagate_cve_changes(session: Session) -> int:
    """Encola reevaluación (prioridad 5B) y riesgo de los activos con findings de CVEs que
    cambiaron (tabla temporal ti_changed_cves que deja store.apply_vulnerabilities)."""
    asset_ids = list(
        session.scalars(
            text(
                "SELECT DISTINCT f.asset_id FROM vulnerability_findings f "
                "JOIN ti_changed_cves c ON c.cve_id = f.intel_cve"
            )
        )
    )
    _queue_assets(session, asset_ids)
    return len(asset_ids)


def _queue_assets(session: Session, asset_ids: list[int]) -> None:
    # Import local: vulnerabilities.queue importa modelos que importan este paquete.
    from app.vulnerabilities.queue import mark_dirty

    if asset_ids:
        mark_dirty(session, asset_ids, "threat_intel")
        request_recalculation(session, asset_ids)


def requeue_source(session: Session, source: ThreatIntelSource) -> int:
    """Una fuente se activa, desactiva o archiva: cambia la inteligencia que cuenta.

    - KEV/EPSS: activos con findings de algún CVE de la fuente (reevaluar prioridad y riesgo);
    - IOCs: activos con matches de la fuente (recalcular riesgo).
    """
    asset_ids: list[int] = list(
        session.scalars(
            select(VulnerabilityFinding.asset_id)
            .distinct()
            .join(VulnerabilityIntel, VulnerabilityIntel.cve_id == VulnerabilityFinding.intel_cve)
            .where(VulnerabilityIntel.source_id == source.id)
        )
    )
    match_assets = list(
        session.scalars(
            select(ThreatIntelMatch.asset_id)
            .distinct()
            .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
            .where(ThreatIndicator.source_id == source.id)
        )
    )
    if asset_ids:
        _queue_assets(session, asset_ids)
    if match_assets:
        request_recalculation(session, match_assets)
    return len(set(asset_ids) | set(match_assets))


def _incident_activity(session: Session, now: datetime) -> int:
    """Timeline de incidentes ACTIVOS con un CVE que entra o sale de KEV."""
    # Tabla temporal de store.apply_vulnerabilities (misma transacción).
    changed = table("ti_changed_cves", column("cve_id", String), column("change", String))
    rows = session.execute(
        select(Incident.id, VulnerabilityFinding.intel_cve, changed.c.change)
        .select_from(IncidentVulnerability)
        .join(Incident, Incident.id == IncidentVulnerability.incident_id)
        .join(VulnerabilityFinding, VulnerabilityFinding.id == IncidentVulnerability.finding_id)
        .join(changed, changed.c.cve_id == VulnerabilityFinding.intel_cve)
        .where(Incident.status.in_(_ACTIVE_INCIDENT))
        .where(changed.c.change.in_(("kev_added", "kev_readded", "kev_removed")))
        .distinct()
        .limit(MAX_INCIDENT_ACTIVITY)
    ).all()
    for incident_id, cve, change in rows:
        session.add(
            IncidentActivity(
                incident_id=incident_id,
                occurred_at=now,
                action="threat_intel_changed",
                actor_user_id=None,
                actor="threat-intel",
                entity_type="vulnerability",
                entity_id=cve,
                summary=_KEV_SUMMARY[change].format(cve=cve),
                details={"change": change, "cve": cve},
            )
        )
    return len(rows)


class ThreatIntelSyncer:
    def __init__(
        self,
        session: Session,
        config: ThreatIntelConfig,
        *,
        fetcher: Fetcher = fetch,
        lock_engine: Callable[[], Engine] | None = None,
    ) -> None:
        self._session = session
        self._config = config
        self._fetch = fetcher
        # Sesiones de la app y de los tests van ligadas a un Engine (no a una Connection).
        bind = cast(Engine, session.get_bind())
        self._lock_engine = lock_engine or (lambda: bind)

    # --- Utilidades ------------------------------------------------------------------------------

    def _source(self, source_id: int) -> ThreatIntelSource:
        source = self._session.get(ThreatIntelSource, source_id)
        if source is None:
            raise NotFoundError("Threat intelligence source not found")
        return source

    def _xact_lock(self, source_id: int) -> None:
        acquired = self._session.scalar(
            select(func.pg_try_advisory_xact_lock(threat_source_lock_key(source_id)))
        )
        if not acquired:
            raise ThreatIntelBusyError("Another sync or import of this source is in progress")

    def _record_count(self, source: ThreatIntelSource, provider: ThreatIntelProvider) -> int:
        if provider.intel_kind is not None:
            query = select(func.count()).where(
                VulnerabilityIntel.source_id == source.id, VulnerabilityIntel.active
            )
        else:
            query = select(func.count()).where(ThreatIndicator.source_id == source.id)
        return int(self._session.scalar(query) or 0)

    def due_sources(self, now: datetime) -> list[int]:
        """Fuentes con red, activas y con sincronización pedida o vencida."""
        if not self._config.sync_enabled:
            return []
        rows = self._session.scalars(
            select(ThreatIntelSource.id)
            .where(
                ThreatIntelSource.enabled,
                ThreatIntelSource.archived_at.is_(None),
                ThreatIntelSource.network_required,
                (ThreatIntelSource.sync_requested_at.is_not(None))
                | (ThreatIntelSource.next_sync_at.is_(None))
                | (ThreatIntelSource.next_sync_at <= now),
            )
            .order_by(ThreatIntelSource.sync_requested_at.asc().nulls_last(), ThreatIntelSource.id)
        ).all()
        return list(rows)

    # --- Sincronización por red ------------------------------------------------------------------

    def sync(self, source_id: int, trigger: str, actor: Actor) -> SyncOutcome:
        """Descarga y aplica una fuente. Lanza ThreatIntelBusyError si ya hay otra en curso."""
        with singleton_lock(self._lock_engine, threat_source_lock_key(source_id)) as acquired:
            if not acquired:
                raise ThreatIntelBusyError("Another sync or import of this source is in progress")
            return self._sync_locked(source_id, trigger, actor)

    def _sync_locked(self, source_id: int, trigger: str, actor: Actor) -> SyncOutcome:
        source = self._source(source_id)
        provider = get_provider(source.provider)
        if source.archived_at is not None or not source.enabled:
            raise ThreatIntelError("threat_source_disabled", "The source is disabled")
        if not source.network_required or provider.parse_download is None:
            raise ThreatIntelError("threat_source_manual", "This source only accepts imports")
        if not self._config.sync_enabled:
            raise ThreatIntelError(
                "threat_intel_sync_disabled",
                "Network sync is disabled (THREAT_INTEL_SYNC_ENABLED=false); "
                "import offline files instead",
            )
        url = source_url(source, self._config)
        if not url:
            raise ThreatIntelError("threat_source_no_url", "The source has no download URL")
        now = datetime.now(UTC)
        sync_row = ThreatIntelSync(
            source_id=source.id,
            kind="sync",
            trigger=trigger,
            status="running",
            actor=actor.name[:64],
            started_at=now,
        )
        self._session.add(sync_row)
        source.status = "syncing"
        source.last_attempt_at = now
        source.sync_requested_at = None
        source.sync_requested_by = None
        audit_service.record(
            self._session,
            actor,
            "threat_sync_started",
            target_type="threat_source",
            target_id=source.source_key,
            details={"trigger": trigger},
            commit=False,
        )
        self._session.commit()
        sync_id = sync_row.id
        started = time.perf_counter()
        policy: FetchPolicy = self._config.fetch_policy()
        has_data = source.record_count > 0
        try:
            download = self._fetch(
                url,
                policy,
                etag=source.etag if has_data else None,
                last_modified=source.last_modified if has_data else None,
            )
        except FetchError as exc:
            return self._fail(
                source_id, sync_id, "unavailable", exc.code, exc.message, actor, started
            )
        try:
            unchanged = download.status == 304 or (
                has_data
                and download.sha256 is not None
                and download.sha256 == source.content_sha256
            )
            if unchanged:
                return self._not_modified(source_id, sync_id, download, actor, started)
            if download.body is None or provider.parse_download is None:
                raise IntelFormatError("intel_empty", "The source returned no content")
            feed = provider.parse_download(
                download.body, self._config.max_bytes, self._config.max_records
            )
            return self._apply_feed(
                source_id,
                sync_id,
                provider,
                feed,
                actor,
                started,
                content_sha256=download.sha256,
                etag=download.etag,
                last_modified=download.last_modified,
                url=url,
            )
        except IntelFormatError as exc:
            self._session.rollback()
            return self._fail(source_id, sync_id, "error", exc.code, str(exc), actor, started)
        except Exception as exc:
            self._session.rollback()
            logger.exception("threat intel sync failed", extra={"source": source.source_key})
            return self._fail(
                source_id, sync_id, "error", "internal_error", type(exc).__name__, actor, started
            )
        finally:
            download.close()

    def _finish_sync(
        self,
        sync_id: int,
        status: str,
        started: float,
        counts: dict[str, int] | None = None,
        content_sha256: str | None = None,
        error_code: str | None = None,
        error_message: str | None = None,
    ) -> ThreatIntelSync:
        sync_row = self._session.get(ThreatIntelSync, sync_id)
        if sync_row is None:  # pragma: no cover - la fila se creó en este mismo flujo
            raise NotFoundError("Sync record not found")
        sync_row.status = status
        sync_row.finished_at = datetime.now(UTC)
        sync_row.duration_ms = int((time.perf_counter() - started) * 1000)
        if counts:
            sync_row.records_seen = counts.get("seen", 0)
            sync_row.records_new = counts.get("new", 0) + counts.get("reappeared", 0)
            sync_row.records_updated = counts.get("updated", 0)
            sync_row.records_unchanged = counts.get("unchanged", 0)
            sync_row.records_removed = counts.get("removed", 0)
            sync_row.records_invalid = counts.get("invalid", 0)
        sync_row.content_sha256 = content_sha256
        sync_row.error_code = _short(error_code, 64)
        sync_row.error_message = _short(error_message, 300)
        return sync_row

    def _fail(
        self,
        source_id: int,
        sync_id: int,
        source_status: str,
        code: str,
        message: str,
        actor: Actor,
        started: float,
    ) -> SyncOutcome:
        """Fallo: la fuente conserva su inteligencia; se apunta el error y se reintenta."""
        source = self._source(source_id)
        now = datetime.now(UTC)
        source.status = source_status
        source.last_error = _short(code, 64)
        source.last_error_message = _short(message, 300)
        source.next_sync_at = now + min(
            RETRY_AFTER, timedelta(hours=source.sync_interval_hours or 24)
        )
        source.updated_at = now
        self._finish_sync(sync_id, "failed", started, error_code=code, error_message=message)
        audit_service.record(
            self._session,
            actor,
            "threat_sync_failed",
            result=audit_service.FAILURE,
            target_type="threat_source",
            target_id=source.source_key,
            details={"error": code},
            commit=False,
        )
        self._session.commit()
        REGISTRY.observe_threat_sync(source.provider, "failed", time.perf_counter() - started, 0)
        logger.warning(
            "threat intel sync failed",
            extra={"source": source.source_key, "error": code},
        )
        return SyncOutcome(source.source_key, "failed", sync_id, {}, code, message)

    def _not_modified(
        self,
        source_id: int,
        sync_id: int,
        download: FetchResult,
        actor: Actor,
        started: float,
    ) -> SyncOutcome:
        source = self._source(source_id)
        now = datetime.now(UTC)
        source.status = "ok"
        source.last_success_at = now
        source.last_error = None
        source.last_error_message = None
        source.etag = _short(download.etag, 256) or source.etag
        source.last_modified = _short(download.last_modified, 64) or source.last_modified
        source.next_sync_at = now + timedelta(hours=source.sync_interval_hours or 24)
        source.updated_at = now
        self._finish_sync(sync_id, "not_modified", started, content_sha256=source.content_sha256)
        audit_service.record(
            self._session,
            actor,
            "threat_sync_completed",
            target_type="threat_source",
            target_id=source.source_key,
            details={"result": "not_modified"},
            commit=False,
        )
        self._session.commit()
        REGISTRY.observe_threat_sync(
            source.provider, "not_modified", time.perf_counter() - started, 0
        )
        return SyncOutcome(source.source_key, "not_modified", sync_id)

    def _apply_feed(
        self,
        source_id: int,
        sync_id: int,
        provider: ThreatIntelProvider,
        feed: ParsedFeed,
        actor: Actor,
        started: float,
        *,
        content_sha256: str | None,
        etag: str | None = None,
        last_modified: str | None = None,
        url: str | None = None,
        audit_action: str = "threat_sync_completed",
    ) -> SyncOutcome:
        """Staging + aplicación de un feed de vulnerabilidades en una transacción."""
        if provider.intel_kind is None:
            raise ThreatIntelError("threat_source_manual", "This source does not take feed files")
        source = self._source(source_id)
        now = datetime.now(UTC)
        staged = store.stage_vulnerabilities(self._session, feed.vulnerabilities())
        parsed = feed.parsed
        valid = int(self._session.scalar(text("SELECT count(*) FROM ti_stage_vuln")) or 0)
        if valid == 0:
            raise IntelFormatError("intel_empty", "The feed contains no valid records")
        if parsed.complete:
            existing = int(
                self._session.scalar(
                    select(func.count()).where(
                        VulnerabilityIntel.source_id == source.id,
                        VulnerabilityIntel.kind == provider.intel_kind,
                        VulnerabilityIntel.active,
                    )
                )
                or 0
            )
            if existing >= SHRINK_MIN_EXISTING and valid < existing * SHRINK_RATIO:
                raise IntelFormatError(
                    "intel_feed_shrunk",
                    f"The feed has {valid} records but {existing} are active; "
                    "refusing to deactivate them",
                )
        result = store.apply_vulnerabilities(
            self._session,
            source.id,
            provider.intel_kind,
            now,
            sync_id,
            complete=parsed.complete,
            source_url=(url or provider.default_url or "")[:500] or None,
        )
        queued = propagate_cve_changes(self._session)
        incident_rows = _incident_activity(self._session, now)
        counts = {**result.as_dict(), "invalid": parsed.invalid_total}
        changed = result.new + result.updated + result.removed + result.reappeared
        if changed or source.revision == 0:
            source.revision += 1
        source.record_count = self._record_count(source, provider)
        source.status = "ok"
        source.last_success_at = now
        source.last_error = None
        source.last_error_message = None
        source.content_sha256 = content_sha256
        if etag is not None or last_modified is not None:
            source.etag = _short(etag, 256)
            source.last_modified = _short(last_modified, 64)
        if source.sync_interval_hours:
            source.next_sync_at = now + timedelta(hours=source.sync_interval_hours)
        source.updated_at = now
        self._finish_sync(sync_id, "success", started, counts, content_sha256)
        audit_service.record(
            self._session,
            actor,
            audit_action,
            target_type="threat_source",
            target_id=source.source_key,
            details={
                **counts,
                "format": parsed.format,
                "source_version": parsed.source_version,
                "assets_queued": queued,
                "incident_activity": incident_rows,
            },
            commit=False,
        )
        self._session.commit()
        REGISTRY.observe_threat_sync(
            source.provider, "success", time.perf_counter() - started, staged
        )
        logger.info(
            "threat intel source updated",
            extra={"source": source.source_key, "seen": result.seen, "changed": changed},
        )
        return SyncOutcome(source.source_key, "success", sync_id, counts, assets_queued=queued)

    # --- Importación offline de un feed KEV/EPSS (CLI) ------------------------------------------

    def import_feed_file(self, source_id: int, path: Path, actor: Actor) -> SyncOutcome:
        """Fichero oficial KEV/EPSS descargado en otro equipo (servidor sin Internet)."""
        with singleton_lock(self._lock_engine, threat_source_lock_key(source_id)) as acquired:
            if not acquired:
                raise ThreatIntelBusyError("Another sync or import of this source is in progress")
            source = self._source(source_id)
            provider = get_provider(source.provider)
            if provider.intel_kind is None or source.archived_at is not None:
                raise ThreatIntelError(
                    "threat_source_manual", "This source does not take feed files"
                )
            if not path.is_file():
                raise ThreatIntelError("intel_not_found", "File not found")
            now = datetime.now(UTC)
            sync_row = ThreatIntelSync(
                source_id=source.id,
                kind="import",
                trigger="cli",
                status="running",
                actor=actor.name[:64],
                started_at=now,
            )
            self._session.add(sync_row)
            source.last_attempt_at = now
            self._session.commit()
            sync_id = sync_row.id
            started = time.perf_counter()
            digest = _file_sha256(path)
            try:
                with path.open("rb") as handle:
                    feed = parse_vulnerability_import(
                        source.provider, handle, self._config.max_bytes, self._config.max_records
                    )
                    return self._apply_feed(
                        source_id,
                        sync_id,
                        provider,
                        feed,
                        actor,
                        started,
                        content_sha256=digest,
                        audit_action="threat_imported",
                    )
            except IntelFormatError as exc:
                self._session.rollback()
                return self._fail(source_id, sync_id, "error", exc.code, str(exc), actor, started)

    # --- Importación de indicadores (API y CLI) --------------------------------------------------

    def _import_source(self, source_id: int) -> ThreatIntelSource:
        source = self._source(source_id)
        provider = get_provider(source.provider)
        if source.archived_at is not None:
            raise ThreatIntelError("threat_source_archived", "The source is archived")
        if "manual_import" not in provider.capabilities:
            raise ThreatIntelError(
                "threat_source_not_importable", "This source does not accept imports"
            )
        return source

    def _parse(self, fmt: str, raw: bytes) -> ParsedFeed:
        return parse_import(fmt, raw, self._config.max_bytes, self._config.max_records)

    def preview_import(self, source_id: int, fmt: str, raw: bytes) -> ImportPreview:
        """Valida y cuenta new/updated/unchanged sin guardar nada (staging + rollback)."""
        source = self._import_source(source_id)
        feed = self._parse(fmt, raw)
        parsed = feed.parsed
        try:
            store.stage_indicators(self._session, parsed.indicators)
            counts = store.count_indicators(self._session, source.id)
        finally:
            self._session.rollback()
        by_type: dict[str, int] = {}
        for record in parsed.indicators:
            by_type[record.indicator_type] = by_type.get(record.indicator_type, 0) + 1
        not_matchable = sum(
            count for kind, count in by_type.items() if TELEMETRY_SUPPORT.get(kind) == "unsupported"
        )
        return ImportPreview(
            source_key=source.source_key,
            format=parsed.format,
            sha256=_sha256(raw),
            size_bytes=len(raw),
            source_version=parsed.source_version,
            total=len(parsed.indicators) + parsed.invalid_total,
            valid=len(parsed.indicators),
            new=counts.new,
            updated=counts.updated,
            unchanged=counts.unchanged,
            invalid=parsed.invalid_total,
            invalid_records=parsed.invalid,
            unsupported=dict(parsed.unsupported),
            by_type=by_type,
            not_matchable=not_matchable,
        )

    def import_indicators(
        self,
        source_id: int,
        fmt: str,
        raw: bytes,
        actor: Actor,
        *,
        expected_sha256: str | None,
        skip_invalid: bool,
        trigger: str,
    ) -> ImportResult:
        """Importa un lote de IOCs en UNA transacción. Sin commit: quien llama confirma.

        Nunca desactiva indicadores que no vengan en el fichero (una importación es un lote
        parcial, no el estado completo de la fuente). Para retirar uno, se reimporta con
        `revoked: true` o con `valid_until` en el pasado.
        """
        source = self._import_source(source_id)
        digest = _sha256(raw)
        if expected_sha256 is not None and digest != expected_sha256:
            raise ThreatIntelChangedError("The file differs from the previewed one; preview again")
        feed = self._parse(fmt, raw)
        parsed = feed.parsed
        if parsed.invalid_total and not skip_invalid:
            raise ThreatIntelError(
                "intel_invalid_records",
                f"{parsed.invalid_total} invalid records; confirm skip_invalid to import the rest",
            )
        if not parsed.indicators:
            raise ThreatIntelError("intel_empty", "The file contains no supported indicators")
        self._xact_lock(source.id)
        now = datetime.now(UTC)
        started = time.perf_counter()
        sync_row = ThreatIntelSync(
            source_id=source.id,
            kind="import",
            trigger=trigger,
            status="running",
            actor=actor.name[:64],
            started_at=now,
        )
        self._session.add(sync_row)
        self._session.flush()
        store.stage_indicators(self._session, parsed.indicators)
        result = store.apply_indicators(self._session, source.id, now, sync_row.id)
        provider = get_provider(source.provider)
        counts = {**result.as_dict(), "invalid": parsed.invalid_total}
        if result.new or result.updated or source.revision == 0:
            source.revision += 1
        source.record_count = self._record_count(source, provider)
        source.status = "ok"
        source.last_attempt_at = now
        source.last_success_at = now
        source.last_error = None
        source.last_error_message = None
        source.content_sha256 = digest
        source.updated_at = now
        self._finish_sync(sync_row.id, "success", started, counts, digest)
        audit_service.record(
            self._session,
            actor,
            "threat_imported",
            target_type="threat_source",
            target_id=source.source_key,
            details={
                **counts,
                "format": parsed.format,
                "unsupported": sum(parsed.unsupported.values()),
                "file_sha256": digest,
            },
            commit=False,
        )
        REGISTRY.observe_threat_sync(
            source.provider, "imported", time.perf_counter() - started, result.seen
        )
        return ImportResult(
            source_key=source.source_key,
            sha256=digest,
            new=result.new,
            updated=result.updated,
            unchanged=result.unchanged,
            invalid=parsed.invalid_total,
            pending_match=result.pending_match,
        )


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
