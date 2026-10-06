"""Lectura y flujo de trabajo de detecciones (Fase 4H): listado, detalle, reconocer, resolver.

El motor (app/detection/engine.py) crea y actualiza detecciones; aquí solo las consultan y
gestionan los analistas. Resolver nunca borra: la detección y su evidencia quedan como
historial (solo la retención configurada purga las resueltas antiguas).
"""

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.orm import Session, aliased

from app.core.exceptions import ConflictError, NotFoundError
from app.detection.config import DetectionConfig
from app.detection.engine import resolve_detection_alert
from app.detection.rules import RULES_BY_ID, RuleMeta
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.detection import (
    SEVERITY_RANK,
    Detection,
    DetectionConfidence,
    DetectionEvidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.repositories.alert_repository import escape_like
from app.repositories.asset_repository import AssetRepository
from app.risk.queue import request_recalculation
from app.schemas.detection import (
    DetectionDetail,
    DetectionEvidenceRead,
    DetectionList,
    DetectionRead,
)
from app.services.asset_context_service import context_values
from app.services.detection_rule_service import rule_text

# Timeline del detalle: la evidencia está acotada a 100 por detección (engine.MAX_EVIDENCE).
EVIDENCE_LIMIT = 100


@dataclass(frozen=True)
class DetectionFilter:
    status: DetectionStatus | None = None
    # Abiertas o reconocidas; se ignora si se indica `status`.
    active: bool = False
    severity: DetectionSeverity | None = None
    # Esta severidad o más (p. ej. "high" incluye critical).
    min_severity: DetectionSeverity | None = None
    confidence: DetectionConfidence | None = None
    rule_id: str | None = None
    asset_public_id: UUID | None = None
    # Actividad (last_seen_at) dentro del rango.
    since: datetime | None = None
    until: datetime | None = None
    # Texto en título, resumen o activo.
    search: str | None = None


class DetectionService:
    def __init__(self, session: Session, config: DetectionConfig | None = None) -> None:
        self._session = session
        self._config = config or DetectionConfig()
        self._assets = AssetRepository(session)

    # --- Lecturas --------------------------------------------------------------------------

    def _base(self) -> Select[Detection, Asset, UUID]:
        alert = aliased(Alert)
        return (
            select(Detection, Asset, alert.public_id)
            .join(Asset, Detection.asset_id == Asset.id)
            .outerjoin(alert, Detection.alert_id == alert.id)
        )

    def list(self, f: DetectionFilter, limit: int, offset: int = 0) -> DetectionList:
        stmt = self._base()
        if f.status is not None:
            stmt = stmt.where(Detection.status == f.status)
        elif f.active:
            stmt = stmt.where(Detection.status != DetectionStatus.RESOLVED)
        if f.severity is not None:
            stmt = stmt.where(Detection.severity == f.severity)
        if f.min_severity is not None:
            rank = SEVERITY_RANK[f.min_severity]
            stmt = stmt.where(
                Detection.severity.in_([s for s in DetectionSeverity if SEVERITY_RANK[s] >= rank])
            )
        if f.confidence is not None:
            stmt = stmt.where(Detection.confidence == f.confidence)
        if f.rule_id:
            stmt = stmt.where(Detection.rule_id == f.rule_id)
        if f.asset_public_id is not None:
            asset = self._assets.get_by_public_id(f.asset_public_id)
            if asset is None:
                raise NotFoundError("Asset not found")
            stmt = stmt.where(Detection.asset_id == asset.id)
        if f.since is not None:
            stmt = stmt.where(Detection.last_seen_at >= f.since)
        if f.until is not None:
            stmt = stmt.where(Detection.last_seen_at <= f.until)
        if f.search:
            pattern = f"%{escape_like(f.search)}%"
            stmt = stmt.where(
                or_(
                    Detection.title.ilike(pattern, escape="\\"),
                    Detection.summary.ilike(pattern, escape="\\"),
                    Detection.rule_id.ilike(pattern, escape="\\"),
                    Asset.hostname.ilike(pattern, escape="\\"),
                    Asset.primary_ip.ilike(pattern, escape="\\"),
                )
            )
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        page = self._session.execute(
            stmt.order_by(Detection.last_seen_at.desc(), Detection.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return DetectionList(items=[_read(row[0], row[1], row[2]) for row in page], total=total)

    def get(self, public_id: UUID) -> DetectionDetail:
        row = self._session.execute(self._base().where(Detection.public_id == public_id)).first()
        if row is None:
            raise NotFoundError("Detection not found")
        detection, asset, alert_id = row[0], row[1], row[2]
        evidence = self._session.scalars(
            select(DetectionEvidence)
            .where(DetectionEvidence.detection_id == detection.id)
            .order_by(DetectionEvidence.occurred_at, DetectionEvidence.id)
            .limit(EVIDENCE_LIMIT)
        ).all()
        total = (
            self._session.scalar(
                select(func.count())
                .select_from(DetectionEvidence)
                .where(DetectionEvidence.detection_id == detection.id)
            )
            or 0
        )
        # Textos de la versión de la regla que alimentó la detección por última vez (custom y
        # Sigma); las built-in, del código.
        texts = rule_text(self._session, detection.rule_id, _last_version(detection))
        return DetectionDetail(
            **_read(detection, asset, alert_id).model_dump(),
            details=detection.details,
            description=texts.description if texts else "",
            why=texts.why if texts else "",
            recommendations=list(texts.recommendations) if texts else [],
            required_data=list(texts.required_data) if texts else [],
            evidence=[DetectionEvidenceRead.model_validate(item) for item in evidence],
            evidence_total=total,
            asset_context=context_values(self._session, [asset])[asset.id].brief(),
        )

    # --- Flujo del analista ------------------------------------------------------------------

    def acknowledge(self, public_id: UUID, username: str) -> Detection:
        """Marca como vista. Sigue activa (absorbe ocurrencias nuevas) hasta resolverse."""
        detection = self._require(public_id)
        if detection.status == DetectionStatus.RESOLVED:
            raise ConflictError("Detection is already resolved")
        if detection.status == DetectionStatus.OPEN:
            now = datetime.now(UTC)
            detection.status = DetectionStatus.ACKNOWLEDGED
            detection.acknowledged_at = now
            detection.acknowledged_by = username[:64]
            detection.updated_at = now
            # Reconocer no mitiga, pero cambia el peso de la detección en el riesgo (4I).
            request_recalculation(self._session, [detection.asset_id])
        self._session.commit()
        return detection

    def resolve(self, public_id: UUID, username: str, note: str | None) -> Detection:
        """Cierra la detección. Una nueva coincidencia posterior abre una detección nueva."""
        detection = self._require(public_id)
        if detection.status != DetectionStatus.RESOLVED:
            now = datetime.now(UTC)
            detection.status = DetectionStatus.RESOLVED
            detection.resolved_at = now
            detection.resolved_by = username[:64]
            detection.resolution_note = note[:500] if note else None
            detection.updated_at = now
            resolve_detection_alert(self._session, detection, now)
            # El riesgo no cae a cero al resolver: decae desde ahora (memoria reciente, 4I).
            request_recalculation(self._session, [detection.asset_id])
        self._session.commit()
        return detection

    def _require(self, public_id: UUID) -> Detection:
        detection = self._session.scalar(
            select(Detection).where(Detection.public_id == public_id).with_for_update()
        )
        if detection is None:
            raise NotFoundError("Detection not found")
        return detection


def _meta(rule_id: str) -> RuleMeta | None:
    rule = RULES_BY_ID.get(rule_id)
    return rule.meta if rule else None


def _last_version(detection: Detection) -> int:
    # Las custom no reescriben rule_version (versión que CREÓ la detección); la última que la
    # actualizó va en details.rule_version.
    value = (detection.details or {}).get("rule_version")
    return value if isinstance(value, int) and value > 0 else detection.rule_version


def _read(detection: Detection, asset: Asset, alert_id: UUID | None) -> DetectionRead:
    meta = _meta(detection.rule_id)
    return DetectionRead(
        detection_id=detection.public_id,
        asset_id=asset.public_id,
        hostname=asset.display_name,
        rule_id=detection.rule_id,
        rule_version=detection.rule_version,
        kind=detection.kind,
        rule_source=detection.rule_source,
        # Una regla retirada del catálogo sigue mostrando sus detecciones históricas.
        category=detection.rule_category or (meta.category if meta else "unknown"),
        severity=detection.severity,
        confidence=detection.confidence,
        status=detection.status,
        title=detection.title,
        summary=detection.summary,
        mitre_tactic=detection.mitre_tactic,
        mitre_technique=detection.mitre_technique,
        mitre_subtechnique=detection.mitre_subtechnique,
        occurrence_count=detection.occurrence_count,
        first_seen_at=detection.first_seen_at,
        last_seen_at=detection.last_seen_at,
        created_at=detection.created_at,
        updated_at=detection.updated_at,
        acknowledged_at=detection.acknowledged_at,
        acknowledged_by=detection.acknowledged_by,
        resolved_at=detection.resolved_at,
        resolved_by=detection.resolved_by,
        resolution_note=detection.resolution_note,
        alert_id=alert_id,
    )
