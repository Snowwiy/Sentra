"""Contratos de la API de detecciones (Fase 4H)."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from app.models.detection import DetectionConfidence, DetectionSeverity, DetectionStatus
from app.schemas.asset_context import AssetContextBrief
from app.schemas.common import RequestModel, ResponseModel


class DetectionRead(ResponseModel):
    detection_id: UUID
    asset_id: UUID
    hostname: str
    rule_id: str
    rule_version: int
    # Fase 5A: builtin | custom | sigma.
    rule_source: str = "builtin"
    # "single" o "correlation".
    kind: str
    category: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    status: DetectionStatus
    title: str
    # Qué pasó, generado con plantillas deterministas. Texto plano (nunca HTML).
    summary: str
    mitre_tactic: str | None
    mitre_technique: str | None
    mitre_subtechnique: str | None
    occurrence_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime
    updated_at: datetime
    acknowledged_at: datetime | None
    acknowledged_by: str | None
    resolved_at: datetime | None
    resolved_by: str | None
    resolution_note: str | None
    # Alerta security_detection asociada, si la detección fue lo bastante grave.
    alert_id: UUID | None
    # Fase 7B.1: veredicto de atribución vigente (el del analista si lo fijó). None si la regla
    # no evalúa atribución o la detección es anterior a 7B.
    attribution_verdict: str | None = None
    # Fase 7D.1 (H02): True si el resumen original se sustituyó porque la detección es de
    # actividad del endpoint y quien lee no tiene telemetry:read.
    restricted: bool = False


class DetectionList(ResponseModel):
    items: list[DetectionRead]
    # Detecciones que cumplen los filtros (todas las páginas).
    total: int


class DetectionEvidenceRead(ResponseModel):
    signal_kind: str
    # Papel en la regla: "failure", "success", "admin_change"...
    role: str | None
    source_type: str
    # Id público del origen cuando existe (p. ej. event_id de /events).
    source_id: str | None
    occurred_at: datetime
    summary: str
    data: dict[str, Any] | None
    # Fase 7D.1 (H02): evidencia de endpoint servida sin su detalle (falta telemetry:read) y
    # nombres de los campos retenidos (nunca sus valores).
    restricted: bool = False
    withheld_fields: list[str] = Field(default_factory=list)


class DetectionDetail(DetectionRead):
    # Hechos estructurados de la conclusión (cuenta, contadores, ventana...).
    details: dict[str, Any] | None
    # Fase 7D.1 (H02): claves de `details` retenidas por la política de endpoint.
    withheld_details: list[str] = Field(default_factory=list)
    # Del catálogo de reglas: qué detecta, por qué importa y qué revisar (defensivo).
    description: str
    why: str
    recommendations: list[str]
    required_data: list[str]
    # Timeline en orden cronológico (como mucho las 100 evidencias guardadas por detección).
    evidence: list[DetectionEvidenceRead]
    evidence_total: int
    # Fase 4L: contexto del activo para valorar el IMPACTO de negocio. Es independiente de
    # la severidad de la detección (que la fija la regla y no cambia por el activo).
    asset_context: AssetContextBrief | None = None


class DetectionAction(RequestModel):
    # Nota opcional del analista al resolver (queda en la detección y en la auditoría).
    note: str | None = Field(default=None, max_length=500)
