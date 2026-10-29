"""Revisión auditada de correlaciones CORR-002 anteriores a la v5 (Fase 7B-Fix1).

CORR-002 v4 unía cualquier PowerShell sospechoso con cualquier servicio nuevo de la ventana
(ravenslg: WpnUserService_6df11, una instancia por usuario que apareció ANTES del script).
La v5 exige relación causal, pero las detecciones ya creadas siguen abiertas y sumando
riesgo. Aquí se reevalúan con la lógica v5 sobre su propia evidencia guardada:

- vista previa (sin efectos): veredicto `causal`, `temporal_only` o `insufficient_evidence`
  por detección, con los enlaces causales y el orden temporal;
- aplicar (admin con detections:manage, confirmación explícita y lista de ids revisados):
  solo se resuelven las `temporal_only` sin decisión previa de un analista. Nada se borra:
  la detección, su evidencia y sus SCR-001 siguen ahí; queda `details.correlation_review`,
  una entrada de auditoría y el recálculo del riesgo del activo.
"""

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.detection.rules import CORR_002, causal_links
from app.detection.service_identity import instance_name
from app.detection.signals import SignalKind
from app.models.asset import Asset
from app.models.attribution import DetectionAttributionEvent
from app.models.detection import Detection, DetectionEvidence, DetectionSignal, DetectionStatus
from app.risk.queue import request_recalculation
from app.schemas.correlation_review import (
    CorrelationReviewApply,
    CorrelationReviewApplyResult,
    CorrelationReviewItem,
    CorrelationReviewPreview,
)
from app.services import audit_service
from app.services.audit_service import Actor

REVIEW_ACTOR = "correlation_review"
REVIEW_LIMIT = 200
EVIDENCE_LIMIT = 500
_SERVICE_KINDS = {
    SignalKind.SERVICE_INSTALLED.value,
    SignalKind.SERVICE_ADDED.value,
    SignalKind.SERVICE_MODIFIED.value,
}


def _signals(session: Session, detection: Detection) -> dict[str, list[DetectionSignal]]:
    """La evidencia guardada como señales transitorias (las originales ya se purgaron)."""
    rows = session.execute(
        select(DetectionEvidence)
        .where(DetectionEvidence.detection_id == detection.id)
        .order_by(DetectionEvidence.occurred_at, DetectionEvidence.id)
        .limit(EVIDENCE_LIMIT)
    ).scalars()
    found: dict[str, list[DetectionSignal]] = {"powershell": [], "service": [], "process": []}
    for row in rows:
        data = row.data if isinstance(row.data, dict) else {}
        signal = DetectionSignal(
            asset_id=detection.asset_id,
            kind=row.signal_kind,
            occurred_at=row.occurred_at,
            subject=str(data.get("service") or data.get("script_path") or "")[:255],
            data=data,
        )
        if row.signal_kind == SignalKind.POWERSHELL_SUSPICIOUS.value:
            found["powershell"].append(signal)
        elif row.signal_kind in _SERVICE_KINDS:
            found["service"].append(signal)
        elif row.signal_kind == SignalKind.PROCESS_NEW.value:
            found["process"].append(signal)
    return found


def _analyst_decided(session: Session, detection_id: int) -> bool:
    return (
        session.scalar(
            select(DetectionAttributionEvent.id)
            .where(
                DetectionAttributionEvent.detection_id == detection_id,
                DetectionAttributionEvent.source == "analyst",
            )
            .limit(1)
        )
        is not None
    )


def review(session: Session, detection: Detection) -> dict[str, Any]:
    """Veredicto v5 de una CORR-002 con su evidencia guardada. Sin efectos."""
    signals = _signals(session, detection)
    scripts, services = signals["powershell"], signals["service"]
    if not scripts or not services:
        return {
            "verdict": "insufficient_evidence",
            "causal_links": [],
            "temporal_context": {},
            "explanation": [
                "La evidencia guardada no incluye el script y el servicio: no se puede"
                " reevaluar. Se deja como está para revisión manual."
            ],
        }
    links: list[dict[str, Any]] = []
    for service in reversed(services):
        links = causal_links(scripts, service, signals["process"])
        if links:
            break
    service = services[-1]
    first_script = min(s.occurred_at for s in scripts)
    name = str((service.data or {}).get("service") or service.subject)
    parts = instance_name(name)
    context = {
        "service": name,
        "service_source": "event_7045"
        if service.kind == SignalKind.SERVICE_INSTALLED.value
        else "inventory",
        "service_seen_at": service.occurred_at.isoformat(),
        "first_script_at": first_script.isoformat(),
        "order": "service_first" if service.occurred_at < first_script else "script_first",
        "user_service_instance_name": parts is not None,
        "script_blocks": len(scripts),
    }
    if links:
        return {
            "verdict": "causal",
            "causal_links": links,
            "temporal_context": context,
            "explanation": ["Relación causal: " + " ".join(str(x["detail"]) for x in links)],
        }
    explanation = [
        f"El servicio {name} y el PowerShell coinciden en el tiempo, pero no hay evidencia"
        " causal (ni 7045 posterior al script, ni proceso hijo que ejecute el binario, ni"
        " servicio sospechoso o modificado)."
    ]
    if context["order"] == "service_first":
        explanation.append("El servicio se vio ANTES del primer script: no pudo instalarlo.")
    if parts is not None:
        explanation.append(
            f"El nombre tiene forma de instancia por usuario de {parts[0]} (sesión _{parts[1]}),"
            " que Windows crea al iniciar sesión. El nombre por sí solo no lo demuestra."
        )
    explanation.append(
        "Los bloques de PowerShell siguen en SCR-001, activos y auditables: esta revisión solo"
        " retira la correlación."
    )
    return {
        "verdict": "temporal_only",
        "causal_links": [],
        "temporal_context": context,
        "explanation": explanation,
    }


class CorrelationReviewService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def _candidates(self, asset_public_id: UUID | None) -> Sequence[tuple[Detection, Asset]]:
        query = (
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(
                Detection.rule_id == CORR_002.id,
                Detection.rule_version < CORR_002.version,
                Detection.status != DetectionStatus.RESOLVED,
            )
            .order_by(Detection.last_seen_at.desc(), Detection.id.desc())
            .limit(REVIEW_LIMIT)
        )
        if asset_public_id is not None:
            asset_id = self._session.scalar(
                select(Asset.id).where(Asset.public_id == asset_public_id)
            )
            if asset_id is None:
                raise NotFoundError("Asset not found")
            query = query.where(Detection.asset_id == asset_id)
        return [(row[0], row[1]) for row in self._session.execute(query).all()]

    def preview(self, asset_public_id: UUID | None) -> CorrelationReviewPreview:
        items = []
        for detection, asset in self._candidates(asset_public_id):
            result = review(self._session, detection)
            items.append(
                CorrelationReviewItem(
                    detection_id=detection.public_id,
                    asset_id=asset.public_id,
                    hostname=asset.hostname,
                    rule_version=detection.rule_version,
                    status=detection.status.value,
                    title=detection.title,
                    verdict=result["verdict"],
                    would_resolve=result["verdict"] == "temporal_only"
                    and not _analyst_decided(self._session, detection.id),
                    causal_links=result["causal_links"],
                    temporal_context=result["temporal_context"],
                    explanation=result["explanation"],
                )
            )
        counts = {v: sum(1 for i in items if i.verdict == v) for v in ("causal", "temporal_only")}
        return CorrelationReviewPreview(
            items=items,
            causal=counts["causal"],
            temporal_only=counts["temporal_only"],
            insufficient_evidence=len(items) - sum(counts.values()),
        )

    def apply(self, body: CorrelationReviewApply, actor: Actor) -> CorrelationReviewApplyResult:
        """Resuelve las correlaciones revisadas que no son causales (confirmado por un admin)."""
        session = self._session
        now = datetime.now(UTC)
        from app.detection.engine import resolve_detection_alert

        reviewed = resolved = 0
        assets: set[int] = set()
        outcomes: list[dict[str, Any]] = []
        for public_id in dict.fromkeys(body.detection_ids):
            detection = session.scalars(
                select(Detection).where(Detection.public_id == public_id).with_for_update()
            ).first()
            if detection is None:
                raise NotFoundError("Detection not found")
            if detection.rule_id != CORR_002.id:
                outcomes.append({"detection_id": str(public_id), "outcome": "not_corr_002"})
                continue
            reviewed += 1
            result = review(session, detection)
            details = dict(detection.details or {})
            details["correlation_review"] = {
                "reviewed_at": now.isoformat(),
                "actor": actor.name,
                "rule_version_reviewed": detection.rule_version,
                "reviewed_with_version": CORR_002.version,
                "verdict": result["verdict"],
                "causal_links": result["causal_links"],
                "temporal_context": result["temporal_context"],
                "explanation": result["explanation"],
                "note": body.note,
            }
            detection.details = details
            detection.updated_at = now
            can_resolve = (
                result["verdict"] == "temporal_only"
                and detection.status != DetectionStatus.RESOLVED
                and not _analyst_decided(session, detection.id)
            )
            if can_resolve:
                detection.status = DetectionStatus.RESOLVED
                detection.resolved_at = now
                detection.resolved_by = REVIEW_ACTOR
                detection.resolution_note = (
                    "Revisión de correlación (CORR-002 v5): coincidencia temporal sin relación"
                    " causal. " + (body.note or "")
                ).strip()[:500]
                resolve_detection_alert(session, detection, now)
                resolved += 1
            assets.add(detection.asset_id)
            outcomes.append(
                {
                    "detection_id": str(public_id),
                    "verdict": result["verdict"],
                    "resolved": can_resolve,
                }
            )
        if assets:
            request_recalculation(session, sorted(assets))
        audit_service.record(
            session,
            actor,
            "correlation_review_applied",
            target_type="detection",
            target_id=f"{reviewed} CORR-002",
            details={"items": outcomes[:200], "resolved": resolved, "note": body.note},
            commit=False,
        )
        session.commit()
        return CorrelationReviewApplyResult(
            reviewed=reviewed, resolved=resolved, kept=reviewed - resolved
        )
