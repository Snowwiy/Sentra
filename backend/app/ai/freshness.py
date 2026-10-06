"""Versión de los datos que respaldan un insight, para caché y estado stale (Fase 4J).

Un insight se generó sobre un estado concreto de Sentra. Si después cambia una detección
(nueva ocurrencia, evidencia, resolución), el riesgo (cambio material), la exposición
(puerto abierto o cerrado) o la criticidad, el análisis ya no describe la realidad: se
marca stale y la UI lo dice en vez de presentarlo como actual.

La huella se calcula con unas pocas consultas agregadas e indexadas (nunca reconstruyendo
el contexto completo), así listar insights no cuesta un análisis por fila. Deliberadamente
NO incluye last_seen/heartbeat ni calculated_at del riesgo: cambian cada pocos segundos o
con cada vuelta de decay y marcarían stale todo continuamente sin que nada material cambie.
"""

import hashlib
import json
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset
from app.models.asset_context import AssetBusinessContext
from app.models.detection import Detection, DetectionEvidence, DetectionStatus
from app.models.exposure import AssetPort
from app.models.incident import Incident, IncidentDetection, IncidentNote
from app.models.risk import AssetRisk, RiskSnapshot


def _digest(parts: list[Any]) -> str:
    return hashlib.sha256(json.dumps(parts, default=str).encode()).hexdigest()


def _asset_parts(session: Session, asset_pk: int) -> list[Any]:
    asset = session.get(Asset, asset_pk)
    if asset is None:
        return ["deleted"]
    risk = session.get(AssetRisk, asset_pk)
    detections = session.execute(
        select(func.count(), func.max(Detection.updated_at)).where(Detection.asset_id == asset_pk)
    ).one()
    ports = session.execute(
        select(
            func.count(),
            func.max(AssetPort.opened_at),
            func.max(AssetPort.closed_at),
        ).where(AssetPort.asset_id == asset_pk)
    ).one()
    alerts = session.execute(
        select(func.count(), func.max(Alert.opened_at)).where(
            Alert.asset_id == asset_pk, Alert.status != AlertStatus.RESOLVED
        )
    ).one()
    # Fase 4L: un cambio de contexto (version) invalida el insight cacheado del activo.
    context_version = session.scalar(
        select(AssetBusinessContext.version).where(AssetBusinessContext.asset_id == asset_pk)
    )
    return [
        asset.criticality.value,
        context_version,
        # Nivel y último cambio material: el score fino varía con el decay continuamente.
        risk.level.value if risk and risk.calculated_at else None,
        risk.changed_at if risk else None,
        list(detections),
        list(ports),
        list(alerts),
    ]


def asset_version(session: Session, asset_pk: int) -> str:
    return _digest(["asset", *_asset_parts(session, asset_pk)])


def detection_version(session: Session, detection_pk: int) -> str:
    detection = session.get(Detection, detection_pk)
    if detection is None:
        return _digest(["detection", "deleted"])
    evidence = session.scalar(
        select(func.count())
        .select_from(DetectionEvidence)
        .where(DetectionEvidence.detection_id == detection_pk)
    )
    risk = session.get(AssetRisk, detection.asset_id)
    return _digest(
        [
            "detection",
            detection.status.value,
            detection.severity.value,
            detection.occurrence_count,
            detection.updated_at,
            evidence,
            risk.level.value if risk and risk.calculated_at else None,
        ]
    )


def fleet_version(session: Session) -> str:
    detections = session.execute(
        select(func.count(), func.max(Detection.updated_at)).where(
            Detection.status != DetectionStatus.RESOLVED
        )
    ).one()
    snapshots = session.scalar(select(func.max(RiskSnapshot.calculated_at)))
    assets = session.scalar(select(func.count()).select_from(Asset))
    alerts = session.execute(
        select(func.count(), func.max(Alert.opened_at)).where(Alert.status != AlertStatus.RESOLVED)
    ).one()
    return _digest(["fleet", list(detections), snapshots, assets, list(alerts)])


def incident_version(session: Session, incident_pk: int) -> str:
    """Fase 4K: cambia con cualquier actividad del caso (estado, notas, adjuntos, merge)
    y con los cambios de sus detecciones; no con el heartbeat de sus activos."""
    incident = session.get(Incident, incident_pk)
    if incident is None:
        return _digest(["incident", "deleted"])
    detections = session.execute(
        select(func.count(), func.max(Detection.updated_at)).where(
            Detection.id.in_(
                select(IncidentDetection.detection_id).where(
                    IncidentDetection.incident_id == incident_pk
                )
            )
        )
    ).one()
    notes = session.scalar(
        select(func.count())
        .select_from(IncidentNote)
        .where(IncidentNote.incident_id == incident_pk)
    )
    return _digest(
        [
            "incident",
            incident.version,
            incident.last_activity_at,
            incident.status.value,
            list(detections),
            notes,
        ]
    )


def data_version(
    session: Session,
    asset_pk: int | None,
    detection_pk: int | None,
    incident_pk: int | None = None,
) -> str:
    """Huella según el alcance del insight: incidente, detección, activo o flota."""
    if incident_pk is not None:
        return incident_version(session, incident_pk)
    if detection_pk is not None:
        return detection_version(session, detection_pk)
    if asset_pk is not None:
        return asset_version(session, asset_pk)
    return fleet_version(session)
