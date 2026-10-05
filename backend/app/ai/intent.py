"""Resolución determinista del alcance de una pregunta de Ask Sentra AI (Fase 4J).

La pregunta del analista NO decide consultas: este módulo, sin IA, elige uno de los
contextos cerrados del context builder (activo, detección o flota) y sus parámetros
(ventana, severidad mínima). El modelo solo recibe lo que se recuperó aquí.

Orden de decisión:
1. referencias explícitas de la UI (detection_id, asset_id), que son lo más fiable;
2. un UUID escrito en la pregunta que corresponda a una detección o a un activo;
3. un nombre de activo mencionado (hostname, nombre resuelto o IP) que coincida con
   exactamente un activo;
4. si no, visión de flota (SOC) con la ventana y la severidad deducidas de palabras clave.
"""

import re
from dataclasses import dataclass
from typing import Literal
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.detection import Detection, DetectionSeverity

_UUID = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
# Palabras candidatas a nombre de equipo o IP: letras, dígitos, guion, punto, guion bajo.
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,62}")
MAX_TOKENS = 30


@dataclass(frozen=True)
class AskScope:
    kind: Literal["asset", "detection", "fleet"]
    asset_id: UUID | None = None
    detection_id: UUID | None = None
    window: Literal["24h", "7d", "30d"] = "24h"
    min_severity: DetectionSeverity = DetectionSeverity.HIGH
    # Cómo se resolvió (se guarda en el insight para auditar la decisión).
    resolved_by: str = "default"


def _window(text: str) -> Literal["24h", "7d", "30d"]:
    if re.search(r"30\s*d|mes\b|month|30 d[ií]as", text):
        return "30d"
    if re.search(r"7\s*d|semana|week|7 d[ií]as", text):
        return "7d"
    return "24h"


def _severity(text: str) -> DetectionSeverity:
    if re.search(r"cr[ií]tic", text):
        return DetectionSeverity.CRITICAL
    if re.search(r"\bmedi[ao]s?\b|medium", text):
        return DetectionSeverity.MEDIUM
    return DetectionSeverity.HIGH


def resolve_scope(
    session: Session,
    question: str,
    asset_id: UUID | None = None,
    detection_id: UUID | None = None,
) -> AskScope:
    lowered = question.lower()
    window = _window(lowered)
    severity = _severity(lowered)
    if detection_id is not None:
        return AskScope("detection", detection_id=detection_id, resolved_by="explicit_detection")
    if asset_id is not None:
        return AskScope("asset", asset_id=asset_id, resolved_by="explicit_asset")

    for match in _UUID.findall(question)[:3]:
        value = UUID(match)
        if session.scalar(select(Detection.id).where(Detection.public_id == value)):
            return AskScope("detection", detection_id=value, resolved_by="question_detection_id")
        if session.scalar(select(Asset.id).where(Asset.public_id == value)):
            return AskScope("asset", asset_id=value, resolved_by="question_asset_id")

    tokens = list(dict.fromkeys(t.lower().strip("._-") for t in _TOKEN.findall(question)))
    tokens = [t for t in tokens if len(t) >= 3][:MAX_TOKENS]
    if tokens:
        # Coincidencia exacta (sin LIKE): una palabra común nunca arrastra media flota.
        matches = session.scalars(
            select(Asset.public_id)
            .where(
                or_(
                    func.lower(Asset.hostname).in_(tokens),
                    func.lower(Asset.device_name).in_(tokens),
                    Asset.primary_ip.in_(tokens),
                )
            )
            .limit(2)
        ).all()
        if len(matches) == 1:
            return AskScope(
                "asset", asset_id=matches[0], window=window, resolved_by="question_asset_name"
            )
    return AskScope("fleet", window=window, min_severity=severity, resolved_by="fleet_keywords")
