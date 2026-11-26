"""Hunting e investigación sobre eventos SIEM (Fase 7F.6, docs/fase-7f-correlation.md).

* Búsqueda tipada con ventana obligatoria, paginación por cursor (keyset: estable aunque
  lleguen eventos nuevos), recuento acotado y `statement_timeout` local a la transacción. Una
  búsqueda cancelada por tiempo devuelve 503 `siem_search_timeout`; nunca bloquea la base.
* Relacionados: enlaces guardados en los dos sentidos y detecciones de los activos candidatos
  en la ventana del evento. Una coincidencia SOLO de tiempo se marca `time_only` y se explica
  como contexto: nunca se presenta como causa.
* Línea de tiempo de un activo: eventos SIEM atribuidos y detecciones, acotada.
* Exportación de evidencia: eventos completos con el hash del registro original y el SHA-256
  del paquete. Auditada.
* Todo es lectura salvo las búsquedas guardadas (privadas de su autor). Añadir a un caso vive
  en el servicio de incidentes (app/services/incident_service.py).
"""

import base64
import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, and_, cast, func, or_, select, text
from sqlalchemy.dialects.postgresql import CIDR, INET
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import (
    NotFoundError,
    SiemConflictError,
    SiemEventNotFoundError,
    SiemSavedSearchNotFoundError,
    SiemSearchTimeoutError,
    SiemValidationError,
)
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.siem import (
    IncidentSiemEvent,
    SiemEvent,
    SiemEventLink,
    SiemSavedSearch,
    SiemSource,
)
from app.models.user import User
from app.schemas.siem import SiemEventDetail, SiemEventLinkRead
from app.schemas.siem_hunting import (
    IncidentSiemEventList,
    IncidentSiemEventRead,
    SiemEvidenceExport,
    SiemRelated,
    SiemRelatedDetection,
    SiemRelatedEvent,
    SiemSavedSearchCreate,
    SiemSavedSearchList,
    SiemSavedSearchRead,
    SiemSearchFilter,
    SiemSearchRequest,
    SiemSearchResult,
    SiemTimeline,
    SiemTimelineItem,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.siem.correlation import KIND_SIEM_EVENT
from app.siem.service import SiemService
from app.siem.signals import topic_of

RELATED_WINDOW = timedelta(minutes=30)
MAX_RELATED = 25
MAX_TIMELINE = 500
MAX_SAVED_SEARCHES = 50


def _cancelled(exc: BaseException) -> bool:
    # SQLSTATE 57014 (query_canceled): el texto depende de lc_messages, el código no.
    return getattr(getattr(exc, "orig", None), "sqlstate", None) == "57014"


def encode_cursor(at: datetime, event_pk: int) -> str:
    raw = json.dumps([at.isoformat(), event_pk], separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode()


def decode_cursor(value: str) -> tuple[datetime, int]:
    try:
        at, event_pk = json.loads(base64.urlsafe_b64decode(value.encode()))
        moment = datetime.fromisoformat(at)
        if not isinstance(event_pk, int) or moment.tzinfo is None:
            raise ValueError("bad cursor")
    except (ValueError, TypeError) as exc:
        raise SiemValidationError("invalid_cursor", "The cursor is not valid") from exc
    return moment, event_pk


def canonical_sha256(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _ip_condition(column: Any, network: str) -> ColumnElement[bool]:
    if "/" not in network:
        # Dirección exacta: igualdad sobre la columna de texto (usa los índices por IP).
        return column == network  # type: ignore[no-any-return]
    # Rango: los valores guardados son IP válidas normalizadas, el cast no falla.
    return cast(column, INET).op("<<=")(cast(network, CIDR))


class SiemInvestigationService(SiemService):
    def __init__(self, session: Session, settings: Settings) -> None:
        super().__init__(session, settings)

    # --- búsqueda -----------------------------------------------------------------------

    def _conditions(self, query: SiemSearchFilter, site_id: int | None) -> list[Any]:
        max_days = self._settings.siem_search_max_days
        if query.until - query.since > timedelta(days=max_days):
            raise SiemValidationError(
                "search_window_too_large", f"The search window is limited to {max_days} days"
            )
        e = SiemEvent
        conditions: list[Any] = [e.observed_at >= query.since, e.observed_at <= query.until]
        if site_id is not None:
            conditions.append(e.site_id == site_id)
        if query.source_ids:
            conditions.append(
                e.source_id.in_(
                    select(SiemSource.id).where(SiemSource.public_id.in_(query.source_ids))
                )
            )
        if query.source_types:
            conditions.append(e.source_type.in_(query.source_types))
        if query.event_types:
            conditions.append(e.event_type.in_(query.event_types))
        if query.categories:
            conditions.append(e.category.in_(query.categories))
        if query.severities:
            conditions.append(e.severity.in_(query.severities))
        if query.ip:
            conditions.append(
                or_(_ip_condition(e.src_ip, query.ip), _ip_condition(e.dst_ip, query.ip))
            )
        if query.source_ip:
            conditions.append(_ip_condition(e.src_ip, query.source_ip))
        if query.destination_ip:
            conditions.append(_ip_condition(e.dst_ip, query.destination_ip))
        if query.port is not None:
            conditions.append(or_(e.src_port == query.port, e.dst_port == query.port))
        if query.protocol:
            conditions.append(e.protocol == query.protocol)
        if query.hostname:
            conditions.append(func.lower(e.hostname) == query.hostname.lower())
        if query.username:
            conditions.append(e.username == query.username)
        if query.rule_id:
            conditions.append(e.rule_id == query.rule_id)
        if query.signature_id:
            conditions.append(e.signature_id == query.signature_id)
        if query.external_id:
            conditions.append(e.external_id == query.external_id)
        if query.flow_ref:
            conditions.append(e.flow_ref == query.flow_ref)
        if query.mitre_technique:
            conditions.append(e.mitre_techniques.contains([query.mitre_technique]))
        if query.asset_id:
            conditions.append(
                e.asset_id == select(Asset.id).where(Asset.public_id == query.asset_id)
            )
        if query.verdicts:
            conditions.append(e.attribution["verdict"].astext.in_(query.verdicts))
        if query.origins:
            conditions.append(e.attribution["origin"].astext.in_(query.origins))
        if query.text:
            conditions.append(e.message.ilike(f"%{_escape_like(query.text)}%", escape="\\"))
        return conditions

    def search(self, query: SiemSearchRequest, site_id: int | None) -> SiemSearchResult:
        started = time.perf_counter()
        conditions = self._conditions(query, site_id)
        page = list(conditions)
        if query.cursor:
            at, event_pk = decode_cursor(query.cursor)
            page.append(
                or_(
                    SiemEvent.observed_at < at,
                    and_(SiemEvent.observed_at == at, SiemEvent.id < event_pk),
                )
            )
        session = self._session
        # Local a la transacción: termina con ella, no afecta a otras peticiones de la conexión.
        session.execute(
            text("SELECT set_config('statement_timeout', :ms, true)"),
            {"ms": str(self._settings.siem_search_timeout_ms)},
        )
        try:
            rows = session.execute(
                self._event_query()
                .where(*page)
                .order_by(SiemEvent.observed_at.desc(), SiemEvent.id.desc())
                .limit(query.limit + 1)
            ).all()
            count: int | None = None
            capped = False
            if query.count:
                cap = self._settings.siem_search_count_cap
                limited = select(SiemEvent.id).where(*conditions).limit(cap + 1).subquery()
                count = int(session.scalar(select(func.count()).select_from(limited)) or 0)
                if count > cap:
                    count, capped = cap, True
        except DBAPIError as exc:
            if _cancelled(exc):
                session.rollback()
                raise SiemSearchTimeoutError(
                    "The search took too long; narrow the time window or add filters"
                ) from exc
            raise
        more = len(rows) > query.limit
        rows = rows[: query.limit]
        assets = self._candidate_assets([row[0] for row in rows])
        items = [self._event_read(ev, src, site, asset, assets) for ev, src, site, asset in rows]
        last = rows[-1][0] if rows and more else None
        return SiemSearchResult(
            items=items,
            next_cursor=encode_cursor(last.observed_at, last.id) if last is not None else None,
            count=count,
            count_capped=capped,
            took_ms=int((time.perf_counter() - started) * 1000),
        )

    # --- búsquedas guardadas ------------------------------------------------------------

    @staticmethod
    def _saved_read(row: SiemSavedSearch) -> SiemSavedSearchRead:
        return SiemSavedSearchRead(
            search_id=row.public_id,
            name=row.name,
            query=row.query,
            created_at=row.created_at,
            updated_at=row.updated_at,
        )

    def list_saved(self, user: User) -> SiemSavedSearchList:
        rows = self._session.scalars(
            select(SiemSavedSearch)
            .where(SiemSavedSearch.owner_user_id == user.id)
            .order_by(SiemSavedSearch.name)
        )
        return SiemSavedSearchList(items=[self._saved_read(r) for r in rows])

    def create_saved(self, user: User, body: SiemSavedSearchCreate) -> SiemSavedSearchRead:
        session = self._session
        owned = int(
            session.scalar(
                select(func.count())
                .select_from(SiemSavedSearch)
                .where(SiemSavedSearch.owner_user_id == user.id)
            )
            or 0
        )
        if owned >= MAX_SAVED_SEARCHES:
            raise SiemConflictError(
                "saved_search_limit", f"At most {MAX_SAVED_SEARCHES} saved searches per user"
            )
        taken = session.scalar(
            select(SiemSavedSearch.id).where(
                SiemSavedSearch.owner_user_id == user.id, SiemSavedSearch.name == body.name
            )
        )
        if taken is not None:
            raise SiemConflictError("saved_search_name_taken", "A search with that name exists")
        now = datetime.now(UTC)
        row = SiemSavedSearch(
            owner_user_id=user.id,
            name=body.name,
            query=body.query.model_dump(mode="json", exclude_defaults=True),
            created_at=now,
            updated_at=now,
        )
        session.add(row)
        session.commit()
        return self._saved_read(row)

    def delete_saved(self, user: User, search_id: UUID) -> None:
        row = self._session.scalar(
            select(SiemSavedSearch).where(
                SiemSavedSearch.public_id == search_id,
                # Otra cuenta: 404 igual que si no existiera (no se revela).
                SiemSavedSearch.owner_user_id == user.id,
            )
        )
        if row is None:
            raise SiemSavedSearchNotFoundError("Saved search not found")
        self._session.delete(row)
        self._session.commit()

    # --- detalle en bloque --------------------------------------------------------------

    def event_details(self, event_ids: list[UUID]) -> list[SiemEventDetail]:
        rows = self._session.execute(
            self._event_query()
            .where(SiemEvent.event_id.in_(event_ids))
            .order_by(SiemEvent.observed_at, SiemEvent.id)
        ).all()
        links: dict[int, list[SiemEventLinkRead]] = {}
        for link in self._session.scalars(
            select(SiemEventLink)
            .where(SiemEventLink.event_id.in_([row[0].id for row in rows]))
            .order_by(SiemEventLink.id)
        ):
            bucket = links.setdefault(link.event_id, [])
            if len(bucket) < 50:
                bucket.append(
                    SiemEventLinkRead(
                        kind=link.kind,
                        target_ref=link.target_ref,
                        method=link.method,
                        confidence=link.confidence,
                        explanation=str((link.details or {}).get("explanation") or ""),
                        created_at=link.created_at,
                    )
                )
        assets = self._candidate_assets([row[0] for row in rows])
        out: list[SiemEventDetail] = []
        for event, source, site, asset in rows:
            item = self._event_read(event, source, site, asset, assets, True, links.get(event.id))
            assert isinstance(item, SiemEventDetail)  # noqa: S101
            out.append(item)
        return out

    def _event(self, event_id: UUID) -> SiemEvent:
        event = self._session.scalar(select(SiemEvent).where(SiemEvent.event_id == event_id))
        if event is None:
            raise SiemEventNotFoundError("SIEM event not found")
        return event

    # --- relacionados -------------------------------------------------------------------

    def related(self, event_id: UUID) -> SiemRelated:
        event = self._event(event_id)
        session = self._session
        related: list[SiemRelatedEvent] = []
        outgoing = select(SiemEventLink, SiemEvent, SiemSource).where(
            SiemEventLink.event_id == event.id,
            SiemEventLink.kind == KIND_SIEM_EVENT,
            SiemEvent.id == SiemEventLink.target_id,
            SiemSource.id == SiemEvent.source_id,
        )
        incoming = select(SiemEventLink, SiemEvent, SiemSource).where(
            SiemEventLink.target_id == event.id,
            SiemEventLink.kind == KIND_SIEM_EVENT,
            SiemEvent.id == SiemEventLink.event_id,
            SiemSource.id == SiemEvent.source_id,
        )
        for direction, query in (("outgoing", outgoing), ("incoming", incoming)):
            for link, other, source in session.execute(query.limit(MAX_RELATED)):
                related.append(
                    SiemRelatedEvent(
                        event_id=other.event_id,
                        source_name=source.name,
                        source_type=other.source_type,
                        event_type=other.event_type,
                        timestamp=other.observed_at,
                        direction=direction,
                        method=link.method,
                        confidence=link.confidence,
                        explanation=str((link.details or {}).get("explanation") or ""),
                    )
                )
        asset_ids = {
            int(c["asset_id"])
            for c in (event.attribution or {}).get("candidates") or []
            if isinstance(c, dict)
            and isinstance(c.get("asset_id"), int)
            # El nombre de host es una pista: no basta para traer las detecciones de un activo.
            and c.get("method") != "hostname_match"
        }
        detections: list[SiemRelatedDetection] = []
        if asset_ids:
            techniques, categories = topic_of(event)
            rows = session.execute(
                select(Detection, Asset)
                .join(Asset, Asset.id == Detection.asset_id)
                .where(
                    Detection.asset_id.in_(sorted(asset_ids)),
                    Detection.first_seen_at <= event.observed_at + RELATED_WINDOW,
                    Detection.last_seen_at >= event.observed_at - RELATED_WINDOW,
                )
                .order_by(Detection.last_seen_at.desc())
                .limit(MAX_RELATED)
            ).all()
            for detection, asset in rows:
                technique = (detection.mitre_technique or "").split(".", 1)[0].upper()
                topic = technique in techniques or detection.rule_category in categories
                detections.append(
                    SiemRelatedDetection(
                        detection_id=detection.public_id,
                        asset_id=asset.public_id,
                        asset_name=asset.display_name,
                        rule_id=detection.rule_id,
                        title=detection.title,
                        severity=detection.severity.value,
                        first_seen_at=detection.first_seen_at,
                        last_seen_at=detection.last_seen_at,
                        match="topic" if topic else "time_only",
                        explanation=(
                            "Mismo activo, ventana de ±30 min y misma técnica MITRE o mismo"
                            " tema: probablemente describen la misma actividad."
                            if topic
                            else "Mismo activo y ventana de ±30 min, nada más. Contexto para"
                            " la investigación: no demuestra relación entre ambos."
                        ),
                    )
                )
        return SiemRelated(
            event_id=event.event_id,
            events=related,
            detections=detections,
            window_minutes=int(RELATED_WINDOW.total_seconds() // 60),
            note=(
                "Relacionar no es atribuir causa: cada elemento dice cómo se relacionó y con"
                " qué confianza."
            ),
        )

    # --- línea de tiempo ----------------------------------------------------------------

    def timeline(self, asset_id: UUID, since: datetime, until: datetime) -> SiemTimeline:
        if until <= since:
            raise SiemValidationError("invalid_window", "until must be after since")
        if until - since > timedelta(days=self._settings.siem_search_max_days):
            raise SiemValidationError("search_window_too_large", "The window is too large")
        asset = self._session.scalar(select(Asset).where(Asset.public_id == asset_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        events = self._session.execute(
            select(SiemEvent, SiemSource)
            .join(SiemSource, SiemSource.id == SiemEvent.source_id)
            .where(
                SiemEvent.asset_id == asset.id,
                SiemEvent.observed_at >= since,
                SiemEvent.observed_at <= until,
            )
            .order_by(SiemEvent.observed_at.desc())
            .limit(MAX_TIMELINE + 1)
        ).all()
        detections = list(
            self._session.scalars(
                select(Detection)
                .where(
                    Detection.asset_id == asset.id,
                    Detection.last_seen_at >= since,
                    Detection.first_seen_at <= until,
                )
                .order_by(Detection.last_seen_at.desc())
                .limit(MAX_TIMELINE + 1)
            )
        )
        truncated = len(events) > MAX_TIMELINE or len(detections) > MAX_TIMELINE
        items = [
            SiemTimelineItem(
                kind="siem_event",
                ref=event.event_id,
                at=event.observed_at,
                title=(event.message or event.event_type)[:300],
                severity=event.severity,
                source=f"{source.name} ({event.source_type})",
            )
            for event, source in events[:MAX_TIMELINE]
        ] + [
            SiemTimelineItem(
                kind="detection",
                ref=d.public_id,
                at=d.last_seen_at,
                title=f"{d.rule_id}: {d.title}"[:300],
                severity=d.severity.value,
                source="Sentra",
            )
            for d in detections[:MAX_TIMELINE]
        ]
        items.sort(key=lambda item: item.at, reverse=True)
        return SiemTimeline(
            asset_id=asset.public_id,
            since=since,
            until=until,
            items=items[:MAX_TIMELINE],
            truncated=truncated or len(items) > MAX_TIMELINE,
        )

    # --- exportación --------------------------------------------------------------------

    def export(self, event_ids: list[UUID], reason: str | None, actor: Actor) -> SiemEvidenceExport:
        unique = list(dict.fromkeys(event_ids))
        limit = self._settings.siem_export_max_events
        if len(unique) > limit:
            raise SiemValidationError(
                "export_too_large", f"At most {limit} events per evidence export"
            )
        events = self.event_details(unique)
        found = {e.event_id for e in events}
        missing = [e for e in unique if e not in found]
        digest = canonical_sha256([e.model_dump(mode="json") for e in events])
        audit_service.record(
            self._session,
            actor,
            "siem_evidence_exported",
            target_type="siem_events",
            target_id=f"{len(events)} events",
            details={"events": len(events), "missing": len(missing), "sha256": digest},
        )
        return SiemEvidenceExport(
            format="sentra-siem-evidence/1",
            exported_at=datetime.now(UTC),
            exported_by=actor.name,
            reason=reason,
            events=events,
            missing=missing,
            events_sha256=digest,
        )

    # --- casos --------------------------------------------------------------------------

    def snapshot(self, event_id: UUID) -> tuple[SiemEvent, dict[str, Any]]:
        """Evento y su copia normalizada para un caso (sin enlaces: son relaciones vivas)."""
        event = self._event(event_id)
        [detail] = self.event_details([event_id])
        return event, detail.model_dump(mode="json", exclude={"links"})

    def incident_events(self, incident_id: UUID) -> IncidentSiemEventList:
        incident = self._session.scalar(select(Incident).where(Incident.public_id == incident_id))
        if incident is None:
            raise NotFoundError("Incident not found")
        rows = self._session.scalars(
            select(IncidentSiemEvent)
            .where(IncidentSiemEvent.incident_id == incident.id)
            .order_by(IncidentSiemEvent.attached_at, IncidentSiemEvent.id)
            .limit(500)
        )
        return IncidentSiemEventList(
            items=[
                IncidentSiemEventRead(
                    event_id=row.event_public_id,
                    available=row.event_id is not None,
                    source_name=row.source_name,
                    source_type=row.source_type,
                    event_type=row.event_type,
                    timestamp=row.observed_at,
                    evidence_hash=row.evidence_hash,
                    snapshot=row.snapshot,
                    snapshot_sha256=row.snapshot_sha256,
                    note=row.note,
                    attached_at=row.attached_at,
                    attached_by=row.attached_by,
                )
                for row in rows
            ]
        )
