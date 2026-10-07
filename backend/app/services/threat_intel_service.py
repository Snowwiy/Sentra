"""Consulta y gestión de Threat Intelligence para la API (Fase 5C).

Lecturas paginadas e indexadas (nunca se recorre el catálogo de IOCs en Python) y cambios
de administración de fuentes y de triage de matches. Las rutas auditan y confirman; este
servicio no hace commit salvo donde se indica.
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID

from sqlalchemy import ColumnElement, Select, func, or_, select, update
from sqlalchemy.orm import Session

from app.core.exceptions import (
    ConflictError,
    NotFoundError,
    ThreatIntelConflictError,
    ThreatIntelError,
)
from app.incidents.workflow import incident_key
from app.models.asset import Asset
from app.models.detection import Detection
from app.models.incident import Incident, IncidentThreatMatch
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelChange,
    ThreatIntelMatch,
    ThreatIntelSource,
    ThreatIntelSync,
    VulnerabilityIntel,
)
from app.models.vulnerability import VulnerabilityFinding
from app.risk.queue import request_recalculation
from app.schemas.threat_intel import (
    IndicatorDetail,
    IndicatorList,
    IndicatorSourceRef,
    IndicatorSummary,
    MatchAssetRef,
    MatchDetail,
    MatchIncidentRef,
    MatchList,
    MatchSummary,
    ThreatChangeRead,
    ThreatIntelOverview,
    ThreatSourceCreate,
    ThreatSourceList,
    ThreatSourceRead,
    ThreatSourceUpdate,
    ThreatSyncList,
    ThreatSyncRead,
)
from app.services.audit_service import Actor
from app.threat_intel import epss
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.freshness import indicator_state, is_stale, source_state
from app.threat_intel.indicators import SUPPORT_REASONS, TELEMETRY_SUPPORT
from app.threat_intel.providers import PROVIDERS, get_provider
from app.threat_intel.store import MATCHABLE_TYPES
from app.threat_intel.sync import requeue_source, source_url
from app.vulnerabilities import workflow

IndicatorSort = Literal["retrieved_at", "value", "last_matched_at", "match_count"]
MatchSort = Literal["last_observed_at", "first_observed_at", "observation_count"]
ACTIVE_FINDING = tuple(sorted(workflow.ACTIVE_STATUSES))
MATCH_ACTIONS = {"acknowledge": "acknowledged", "dismiss": "dismissed", "reopen": "open"}
# Transiciones de un match: descartar es "falso positivo" (deja de sumar riesgo).
_ALLOWED = {
    "acknowledge": {"open"},
    "dismiss": {"open", "acknowledged"},
    "reopen": {"acknowledged", "dismissed"},
}
RECENT_CHANGES = 10


@dataclass(frozen=True)
class IndicatorFilter:
    indicator_type: str | None = None
    classification: str | None = None
    confidence: str | None = None
    source_id: int | None = None
    state: str | None = None
    matched: bool | None = None
    tag: str | None = None
    # Prefijo del valor normalizado (índice text_pattern_ops).
    search: str | None = None


@dataclass(frozen=True)
class MatchFilter:
    status: str | None = None
    active: bool = False
    classification: str | None = None
    observation_type: str | None = None
    asset_id: int | None = None
    source_id: int | None = None
    indicator_id: int | None = None


def _like_prefix(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class ThreatIntelService:
    def __init__(self, session: Session, config: ThreatIntelConfig) -> None:
        self._session = session
        self._config = config

    # --- Fuentes ---------------------------------------------------------------------------------

    def _source_read(self, source: ThreatIntelSource, now: datetime) -> ThreatSourceRead:
        provider = PROVIDERS.get(source.provider)
        url = source_url(source, self._config) if provider and provider.network_required else None
        return ThreatSourceRead(
            id=source.id,
            source_key=source.source_key,
            name=source.name,
            description=source.description,
            provider=source.provider,
            provider_title=provider.title if provider else source.provider,
            category=source.category,
            trust=source.trust,
            enabled=source.enabled,
            archived=source.archived_at is not None,
            network_required=source.network_required,
            capabilities=list(provider.capabilities) if provider else [],
            sync_interval_hours=source.sync_interval_hours,
            stale_after_hours=source.stale_after_hours,
            status=source.status,
            state=source_state(source, now),
            last_attempt_at=source.last_attempt_at,
            last_success_at=source.last_success_at,
            last_error=source.last_error,
            last_error_message=source.last_error_message,
            record_count=source.record_count,
            next_sync_at=source.next_sync_at,
            sync_requested_at=source.sync_requested_at,
            download_host=urlsplit(url).hostname if url else None,
            reference_url=provider.reference_url if provider else None,
            revision=source.revision,
            created_at=source.created_at,
            updated_at=source.updated_at,
        )

    def sources(self, include_archived: bool = False) -> ThreatSourceList:
        now = datetime.now(UTC)
        stmt = select(ThreatIntelSource).order_by(ThreatIntelSource.id)
        if not include_archived:
            stmt = stmt.where(ThreatIntelSource.archived_at.is_(None))
        return ThreatSourceList(
            items=[self._source_read(s, now) for s in self._session.scalars(stmt)],
            sync_enabled=self._config.sync_enabled,
            detection_policy=self._config.detection_policy,
        )

    def source(self, source_id: int, lock: bool = False) -> ThreatIntelSource:
        stmt = select(ThreatIntelSource).where(ThreatIntelSource.id == source_id)
        if lock:
            stmt = stmt.with_for_update()
        source = self._session.scalar(stmt)
        if source is None:
            raise NotFoundError("Threat intelligence source not found")
        return source

    def source_read(self, source: ThreatIntelSource) -> ThreatSourceRead:
        return self._source_read(source, datetime.now(UTC))

    def create_source(self, payload: ThreatSourceCreate, actor: Actor) -> ThreatIntelSource:
        if self._session.scalar(
            select(ThreatIntelSource.id).where(ThreatIntelSource.source_key == payload.source_key)
        ):
            raise ConflictError("A source with this key already exists")
        provider = get_provider(payload.provider)
        now = datetime.now(UTC)
        source = ThreatIntelSource(
            source_key=payload.source_key,
            name=payload.name,
            description=payload.description,
            provider=provider.name,
            category=payload.category if provider.intel_kind is None else provider.category,
            trust=payload.trust,
            # Una fuente de red nace desactivada: activarla es una decisión explícita.
            enabled=not provider.network_required,
            network_required=provider.network_required,
            sync_interval_hours=provider.default_interval_hours,
            stale_after_hours=provider.default_stale_hours,
            status="never",
            record_count=0,
            config={},
            revision=0,
            created_by=actor.name[:64],
            created_at=now,
            updated_at=now,
        )
        self._session.add(source)
        self._session.flush()
        return source

    def _check_revision(self, source: ThreatIntelSource, revision: int) -> None:
        if source.revision != revision:
            raise ThreatIntelConflictError(
                "The source changed; reload it",
                details=[{"revision": source.revision}],
            )

    def update_source(
        self, source_id: int, payload: ThreatSourceUpdate
    ) -> tuple[ThreatIntelSource, dict[str, Any]]:
        source = self.source(source_id, lock=True)
        self._check_revision(source, payload.revision)
        if source.archived_at is not None:
            raise ThreatIntelError("threat_source_archived", "The source is archived")
        changes: dict[str, Any] = {}
        for field in ("name", "description", "trust", "sync_interval_hours", "stale_after_hours"):
            value = getattr(payload, field)
            if value is None or value == getattr(source, field):
                continue
            scheduled = field in ("sync_interval_hours", "stale_after_hours")
            if scheduled and not source.network_required:
                raise ThreatIntelError(
                    "threat_source_manual", "Manual sources have no sync interval"
                )
            changes[field] = {"from": getattr(source, field), "to": value}
            setattr(source, field, value)
        if changes:
            source.revision += 1
            source.updated_at = datetime.now(UTC)
            if "trust" in changes:
                # La confianza en la fuente pesa en el riesgo de sus matches.
                requeue_source(self._session, source)
        return source, changes

    def set_enabled(self, source_id: int, revision: int, enabled: bool) -> ThreatIntelSource:
        source = self.source(source_id, lock=True)
        self._check_revision(source, revision)
        if source.archived_at is not None:
            raise ThreatIntelError("threat_source_archived", "The source is archived")
        if source.enabled == enabled:
            return source
        source.enabled = enabled
        source.revision += 1
        source.updated_at = datetime.now(UTC)
        if enabled and not source.next_sync_at:
            source.next_sync_at = source.updated_at
        if enabled:
            # Al activarla, sus indicadores se buscan de nuevo en los datos existentes.
            self._session.execute(
                update(ThreatIndicator)
                .where(
                    ThreatIndicator.source_id == source.id,
                    ThreatIndicator.indicator_type.in_(MATCHABLE_TYPES),
                    ~ThreatIndicator.revoked,
                )
                .values(pending_match=True)
            )
        requeue_source(self._session, source)
        return source

    def archive(self, source_id: int, revision: int) -> ThreatIntelSource:
        """Archivar en lugar de borrar: matches, historial e incidentes la referencian."""
        source = self.source(source_id, lock=True)
        self._check_revision(source, revision)
        if source.archived_at is not None:
            return source
        now = datetime.now(UTC)
        source.archived_at = now
        source.enabled = False
        source.sync_requested_at = None
        source.revision += 1
        source.updated_at = now
        requeue_source(self._session, source)
        return source

    def request_sync(self, source_id: int, actor: Actor) -> ThreatIntelSource:
        """Marca la fuente para que el job la sincronice (nunca descarga en la petición)."""
        source = self.source(source_id, lock=True)
        provider = get_provider(source.provider)
        if source.archived_at is not None or not source.enabled:
            raise ThreatIntelError("threat_source_disabled", "Enable the source first")
        if not source.network_required or provider.parse_download is None:
            raise ThreatIntelError("threat_source_manual", "This source only accepts imports")
        if not self._config.sync_enabled:
            raise ThreatIntelError(
                "threat_intel_sync_disabled",
                "Network sync is disabled on the server (THREAT_INTEL_SYNC_ENABLED=false)",
            )
        source.sync_requested_at = datetime.now(UTC)
        source.sync_requested_by = actor.name[:64]
        return source

    def syncs(self, source_id: int, limit: int, offset: int) -> ThreatSyncList:
        self.source(source_id)
        base = select(ThreatIntelSync).where(ThreatIntelSync.source_id == source_id)
        total = self._session.scalar(select(func.count()).select_from(base.subquery())) or 0
        rows = self._session.scalars(
            base.order_by(ThreatIntelSync.started_at.desc(), ThreatIntelSync.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return ThreatSyncList(
            items=[ThreatSyncRead.model_validate(row, from_attributes=True) for row in rows],
            total=total,
        )

    # --- Resumen ---------------------------------------------------------------------------------

    def _changes(
        self, stmt: Select[ThreatIntelChange, str, UUID, str], limit: int
    ) -> list[ThreatChangeRead]:
        rows = self._session.execute(
            stmt.order_by(ThreatIntelChange.occurred_at.desc(), ThreatIntelChange.id.desc()).limit(
                limit
            )
        ).all()
        return [
            ThreatChangeRead(
                occurred_at=change.occurred_at,
                source_name=name,
                record_kind=change.record_kind,
                change=change.change,
                cve_id=change.cve_id,
                indicator_id=public_id,
                indicator_value=value,
                details=change.details,
            )
            for change, name, public_id, value in rows
        ]

    def _changes_stmt(self) -> Select[ThreatIntelChange, str, UUID, str]:
        return (
            select(
                ThreatIntelChange,
                ThreatIntelSource.name,
                ThreatIndicator.public_id,
                ThreatIndicator.value_normalized,
            )
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIntelChange.source_id)
            .outerjoin(ThreatIndicator, ThreatIndicator.id == ThreatIntelChange.indicator_id)
        )

    def overview(self) -> ThreatIntelOverview:
        now = datetime.now(UTC)
        sources = list(
            self._session.scalars(
                select(ThreatIntelSource).where(ThreatIntelSource.archived_at.is_(None))
            )
        )
        enabled = [s for s in sources if s.enabled]
        stale = sum(1 for s in enabled if is_stale(s, now))
        failing = sum(1 for s in enabled if s.status in ("error", "unavailable"))
        live = (
            select(ThreatIntelSource.id)
            .where(ThreatIntelSource.enabled, ThreatIntelSource.archived_at.is_(None))
            .scalar_subquery()
        )
        evidenced = (
            VulnerabilityFinding.status.in_(ACTIVE_FINDING),
            VulnerabilityFinding.match_state.in_(("confirmed", "probable")),
        )
        kev_join = (
            select(
                func.count(VulnerabilityFinding.id.distinct()),
                func.count(VulnerabilityFinding.asset_id.distinct()),
            )
            .join(VulnerabilityIntel, VulnerabilityIntel.cve_id == VulnerabilityFinding.intel_cve)
            .where(
                *evidenced,
                VulnerabilityIntel.kind == "kev",
                VulnerabilityIntel.active,
                VulnerabilityIntel.source_id.in_(live),
            )
        )
        kev_findings, kev_assets = self._session.execute(kev_join).one()
        high_epss = self._session.scalar(
            select(func.count(VulnerabilityFinding.id.distinct()))
            .join(VulnerabilityIntel, VulnerabilityIntel.cve_id == VulnerabilityFinding.intel_cve)
            .where(
                VulnerabilityFinding.status.in_(ACTIVE_FINDING),
                VulnerabilityIntel.kind == "epss",
                VulnerabilityIntel.active,
                VulnerabilityIntel.epss_score >= epss.HIGH,
                VulnerabilityIntel.source_id.in_(live),
            )
        )
        indicators_total = self._session.scalar(select(func.count(ThreatIndicator.id))) or 0
        indicators_active = (
            self._session.scalar(
                select(func.count(ThreatIndicator.id)).where(
                    ThreatIndicator.source_id.in_(live), *self._state_condition("active", now)
                )
            )
            or 0
        )
        active_matches, malicious, assets = self._session.execute(
            select(
                func.count(ThreatIntelMatch.id),
                func.count(ThreatIntelMatch.id).filter(
                    ThreatIntelMatch.classification == "malicious"
                ),
                func.count(ThreatIntelMatch.asset_id.distinct()),
            )
            .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
            .where(ThreatIntelMatch.status != "dismissed", ThreatIndicator.source_id.in_(live))
        ).one()
        last_success = max((s.last_success_at for s in enabled if s.last_success_at), default=None)
        # La fuente local de IOCs viene activada pero vacía: sin datos no cuenta como
        # inteligencia configurada (la UI muestra "No intelligence source configured").
        configured = [s for s in enabled if s.network_required or s.record_count > 0]
        if not configured:
            status: Literal["none_configured", "ok", "degraded"] = "none_configured"
        elif stale or failing:
            status = "degraded"
        else:
            status = "ok"
        return ThreatIntelOverview(
            status=status,
            sources_total=len(sources),
            sources_enabled=len(enabled),
            sources_stale=stale,
            sources_failing=failing,
            sync_enabled=self._config.sync_enabled,
            detection_policy=self._config.detection_policy,
            last_success_at=last_success,
            kev_findings=kev_findings or 0,
            kev_assets=kev_assets or 0,
            high_epss_findings=high_epss or 0,
            indicators_total=indicators_total,
            indicators_active=indicators_active,
            active_matches=active_matches or 0,
            malicious_matches=malicious or 0,
            matched_assets=assets or 0,
            recent_changes=self._changes(self._changes_stmt(), RECENT_CHANGES),
        )

    # --- Indicadores -----------------------------------------------------------------------------

    @staticmethod
    def _state_condition(state: str, now: datetime) -> list[ColumnElement[bool]]:
        if state == "revoked":
            return [ThreatIndicator.revoked.is_(True)]
        if state == "expired":
            return [~ThreatIndicator.revoked, ThreatIndicator.valid_until <= now]
        if state == "not_yet_valid":
            return [~ThreatIndicator.revoked, ThreatIndicator.valid_from > now]
        return [
            ~ThreatIndicator.revoked,
            or_(ThreatIndicator.valid_until.is_(None), ThreatIndicator.valid_until > now),
            or_(ThreatIndicator.valid_from.is_(None), ThreatIndicator.valid_from <= now),
        ]

    def _indicator_summary(
        self, indicator: ThreatIndicator, source: ThreatIntelSource, now: datetime
    ) -> IndicatorSummary:
        return IndicatorSummary(
            indicator_id=indicator.public_id,
            indicator_type=indicator.indicator_type,
            value=indicator.value_normalized,
            classification=indicator.classification,
            confidence=indicator.confidence,
            confidence_score=indicator.confidence_score,
            state=indicator_state(
                indicator.revoked, indicator.valid_from, indicator.valid_until, now
            ),
            valid_from=indicator.valid_from,
            valid_until=indicator.valid_until,
            matching=TELEMETRY_SUPPORT.get(indicator.indicator_type, "unsupported"),
            match_count=indicator.match_count,
            last_matched_at=indicator.last_matched_at,
            tags=list(indicator.tags or []),
            source=IndicatorSourceRef(
                id=source.id, name=source.name, trust=source.trust, state=source_state(source, now)
            ),
            retrieved_at=indicator.retrieved_at,
        )

    def indicators(
        self,
        f: IndicatorFilter,
        sort: IndicatorSort,
        descending: bool,
        limit: int,
        offset: int,
    ) -> IndicatorList:
        now = datetime.now(UTC)
        conditions: list[ColumnElement[bool]] = []
        if f.indicator_type:
            conditions.append(ThreatIndicator.indicator_type == f.indicator_type)
        if f.classification:
            conditions.append(ThreatIndicator.classification == f.classification)
        if f.confidence:
            conditions.append(ThreatIndicator.confidence == f.confidence)
        if f.source_id:
            conditions.append(ThreatIndicator.source_id == f.source_id)
        if f.state:
            conditions.extend(self._state_condition(f.state, now))
        if f.matched is not None:
            conditions.append(
                ThreatIndicator.match_count > 0 if f.matched else ThreatIndicator.match_count == 0
            )
        if f.tag:
            conditions.append(ThreatIndicator.tags.contains([f.tag]))
        if f.search:
            conditions.append(
                ThreatIndicator.value_normalized.like(_like_prefix(f.search.lower()), escape="\\")
            )
        base = (
            select(ThreatIndicator, ThreatIntelSource)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .where(*conditions)
        )
        total = (
            self._session.scalar(
                select(func.count()).select_from(
                    select(ThreatIndicator.id).where(*conditions).subquery()
                )
            )
            or 0
        )
        column = {
            "retrieved_at": ThreatIndicator.retrieved_at,
            "value": ThreatIndicator.value_normalized,
            "last_matched_at": ThreatIndicator.last_matched_at,
            "match_count": ThreatIndicator.match_count,
        }[sort]
        ordering = column.desc().nulls_last() if descending else column.asc().nulls_last()
        rows = self._session.execute(
            base.order_by(ordering, ThreatIndicator.id.desc()).limit(limit).offset(offset)
        ).all()
        return IndicatorList(
            items=[self._indicator_summary(i, s, now) for i, s in rows], total=total
        )

    def indicator(self, public_id: UUID) -> IndicatorDetail:
        now = datetime.now(UTC)
        row = self._session.execute(
            select(ThreatIndicator, ThreatIntelSource)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .where(ThreatIndicator.public_id == public_id)
        ).first()
        if row is None:
            raise NotFoundError("Indicator not found")
        indicator, source = row[0], row[1]
        others = self._session.execute(
            select(ThreatIndicator, ThreatIntelSource)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .where(
                ThreatIndicator.indicator_type == indicator.indicator_type,
                ThreatIndicator.value_normalized == indicator.value_normalized,
                ThreatIndicator.id != indicator.id,
            )
            .limit(20)
        ).all()
        other_sources = [
            {
                "indicator_id": str(o.public_id),
                "source": s.name,
                "trust": s.trust,
                "classification": o.classification,
                "confidence": o.confidence,
                "state": indicator_state(o.revoked, o.valid_from, o.valid_until, now),
            }
            for o, s in others
        ]
        conflicting = any(o["classification"] != indicator.classification for o in other_sources)
        summary = self._indicator_summary(indicator, source, now)
        matches = self.matches(
            MatchFilter(indicator_id=indicator.id), "last_observed_at", True, 20, 0
        ).items
        changes = self._changes(
            self._changes_stmt().where(ThreatIntelChange.indicator_id == indicator.id), 20
        )
        support = TELEMETRY_SUPPORT.get(indicator.indicator_type, "unsupported")
        return IndicatorDetail(
            **summary.model_dump(),
            value_original=indicator.value_original,
            description=indicator.description,
            references=list(indicator.references or []),
            related=list(indicator.related or []),
            external_id=indicator.external_id,
            pattern=indicator.pattern,
            first_seen_external=indicator.first_seen_external,
            last_seen_external=indicator.last_seen_external,
            matching_reason=SUPPORT_REASONS.get(support),
            other_sources=other_sources,
            conflicting=conflicting,
            matches=matches,
            changes=changes,
        )

    def reevaluate(self) -> int:
        """Pone en cola de matching retroactivo todos los IOCs casables de fuentes activas."""
        live = select(ThreatIntelSource.id).where(
            ThreatIntelSource.enabled, ThreatIntelSource.archived_at.is_(None)
        )
        result = self._session.execute(
            update(ThreatIndicator)
            .where(
                ThreatIndicator.source_id.in_(live),
                ThreatIndicator.indicator_type.in_(MATCHABLE_TYPES),
                ~ThreatIndicator.revoked,
                ~ThreatIndicator.pending_match,
            )
            .values(pending_match=True)
        )
        return int(getattr(result, "rowcount", 0) or 0)

    # --- Matches ---------------------------------------------------------------------------------

    def _match_stmt(
        self,
    ) -> Select[ThreatIntelMatch, ThreatIndicator, ThreatIntelSource, Asset, UUID]:
        return (
            select(ThreatIntelMatch, ThreatIndicator, ThreatIntelSource, Asset, Detection.public_id)
            .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .join(Asset, Asset.id == ThreatIntelMatch.asset_id)
            .outerjoin(Detection, Detection.id == ThreatIntelMatch.detection_id)
        )

    @staticmethod
    def _match_summary(
        match: ThreatIntelMatch,
        indicator: ThreatIndicator,
        source: ThreatIntelSource,
        asset: Asset,
        detection: UUID | None,
    ) -> MatchSummary:
        return MatchSummary(
            match_id=match.public_id,
            asset=MatchAssetRef(
                asset_id=asset.public_id, name=asset.display_name, primary_ip=asset.primary_ip
            ),
            indicator_id=indicator.public_id,
            indicator_type=indicator.indicator_type,
            indicator_value=indicator.value_normalized,
            source_name=source.name,
            source_trust=source.trust,
            classification=match.classification,
            match_confidence=match.match_confidence,
            observation_type=match.observation_type,
            observed_value=match.observed_value,
            first_observed_at=match.first_observed_at,
            last_observed_at=match.last_observed_at,
            observation_count=match.observation_count,
            status=match.status,
            detection_id=detection,
            version=match.version,
        )

    def matches(
        self, f: MatchFilter, sort: MatchSort, descending: bool, limit: int, offset: int
    ) -> MatchList:
        conditions: list[ColumnElement[bool]] = []
        if f.status:
            conditions.append(ThreatIntelMatch.status == f.status)
        elif f.active:
            conditions.append(ThreatIntelMatch.status != "dismissed")
        if f.classification:
            conditions.append(ThreatIntelMatch.classification == f.classification)
        if f.observation_type:
            conditions.append(ThreatIntelMatch.observation_type == f.observation_type)
        if f.asset_id:
            conditions.append(ThreatIntelMatch.asset_id == f.asset_id)
        if f.indicator_id:
            conditions.append(ThreatIntelMatch.indicator_id == f.indicator_id)
        if f.source_id:
            conditions.append(
                ThreatIntelMatch.indicator_id.in_(
                    select(ThreatIndicator.id).where(ThreatIndicator.source_id == f.source_id)
                )
            )
        total = (
            self._session.scalar(
                select(func.count()).select_from(
                    select(ThreatIntelMatch.id).where(*conditions).subquery()
                )
            )
            or 0
        )
        column = {
            "last_observed_at": ThreatIntelMatch.last_observed_at,
            "first_observed_at": ThreatIntelMatch.first_observed_at,
            "observation_count": ThreatIntelMatch.observation_count,
        }[sort]
        ordering = column.desc() if descending else column.asc()
        rows = self._session.execute(
            self._match_stmt()
            .where(*conditions)
            .order_by(ordering, ThreatIntelMatch.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return MatchList(items=[self._match_summary(*row) for row in rows], total=total)

    def match_row(self, public_id: UUID, lock: bool = False) -> ThreatIntelMatch:
        stmt = select(ThreatIntelMatch).where(ThreatIntelMatch.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        match = self._session.scalar(stmt)
        if match is None:
            raise NotFoundError("Threat intelligence match not found")
        return match

    def match(self, public_id: UUID, *, can_triage: bool) -> MatchDetail:
        now = datetime.now(UTC)
        row = self._session.execute(
            self._match_stmt().where(ThreatIntelMatch.public_id == public_id)
        ).first()
        if row is None:
            raise NotFoundError("Threat intelligence match not found")
        match, indicator = row[0], row[1]
        incidents = [
            MatchIncidentRef(
                incident_id=incident.public_id,
                key=incident_key(incident.number),
                title=incident.title,
                status=incident.status.value,
            )
            for incident in self._session.scalars(
                select(Incident)
                .join(IncidentThreatMatch, IncidentThreatMatch.incident_id == Incident.id)
                .where(IncidentThreatMatch.match_id == match.id)
                .order_by(Incident.number.desc())
                .limit(20)
            )
        ]
        actions = (
            [name for name, allowed in _ALLOWED.items() if match.status in allowed]
            if can_triage
            else []
        )
        if can_triage and match.status != "dismissed":
            actions.append("incident")
        return MatchDetail(
            **self._match_summary(*row).model_dump(),
            observed_field=match.observed_field,
            event_id=match.event_public_id,
            evidence=match.evidence or {},
            indicator_confidence=match.indicator_confidence,
            indicator_state=indicator_state(
                indicator.revoked, indicator.valid_from, indicator.valid_until, now
            ),
            status_reason=match.status_reason,
            status_changed_at=match.status_changed_at,
            status_changed_by=match.status_changed_by,
            matched_at=match.matched_at,
            incidents=incidents,
            actions=actions,
        )

    def apply_action(
        self, public_id: UUID, action: str, version: int, reason: str | None, actor: Actor
    ) -> ThreatIntelMatch:
        match = self.match_row(public_id, lock=True)
        if match.version != version:
            raise ThreatIntelConflictError(
                "The match changed; reload it", details=[{"version": match.version}]
            )
        if match.status not in _ALLOWED[action]:
            raise ThreatIntelConflictError(f"Cannot {action} a match in status {match.status}")
        now = datetime.now(UTC)
        match.status = MATCH_ACTIONS[action]
        match.status_reason = reason
        match.status_changed_at = now
        match.status_changed_by = actor.name[:64]
        match.version += 1
        match.updated_at = now
        # Descartar o reabrir cambia lo que aporta al riesgo del activo.
        request_recalculation(self._session, [match.asset_id])
        return match
