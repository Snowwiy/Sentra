"""Operaciones de mantenimiento autorizadas y veredictos de atribución (Fase 7B.1).

El cálculo está en app/detection/attribution.py (puro). Aquí se cargan los datos, se
validan las operaciones, se guardan los veredictos y su historial inmutable y se aplican
sus efectos:

- una detección SCR-001, CORR-002 o PER-001 verificada se cierra como mantenimiento
  verificado (resolved_by = "attribution", nota con la operación) y deja de sumar riesgo
  activo; su historial, su evidencia y el veredicto se conservan;
- NET-001 nunca se cierra sola: el veredicto dice si el proceso que escucha está
  autorizado, pero el puerto sigue expuesto y sigue contando (requisito de 7B.1);
- el veredicto de un analista manda sobre el del sistema: una reevaluación posterior queda
  en el historial pero no lo sustituye.

Las operaciones de un activo se aprueban de forma explícita (nunca al crearlas), caducan
(90 días como mucho) y su ventana es cerrada (72 h como mucho). Política de autorización:
una operación aprobada reconoce sola las detecciones NUEVAS (creadas después de la
aprobación, con toda su evidencia posterior a ella y dentro de la ventana) que casan
exactamente con ella; las históricas solo cambian con vista previa y confirmación de un
admin (preview/apply): recálculo controlado y auditado. MAINTENANCE_AUTO_RECOGNITION=false
desactiva el reconocimiento automático.
"""

import hashlib
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.exceptions import ConflictError, NotFoundError, SentraError
from app.detection import attribution as calc
from app.detection.exclusions import interpreter_wide
from app.detection.script_context import SENTRA_SCRIPTS
from app.models.asset import Asset
from app.models.attribution import (
    DetectionAttributionEvent,
    MaintenanceArtifact,
    MaintenanceOperation,
)
from app.models.detection import Detection, DetectionEvidence, DetectionStatus
from app.risk.queue import request_recalculation
from app.schemas.attribution import (
    AnalystVerdictIn,
    AttributionApplyResult,
    AttributionEventRead,
    AttributionPreview,
    AttributionPreviewItem,
    DetectionAttributionRead,
    MaintenanceArtifactRead,
    MaintenanceOperationCreate,
    MaintenanceOperationList,
    MaintenanceOperationRead,
    ReferenceArtifact,
    ReferenceArtifactList,
)
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)

MAX_WINDOW = timedelta(hours=72)
MAX_EXPIRY = timedelta(days=90)
# Evidencia que se compara por detección (el motor 4H guarda como mucho 100).
EVIDENCE_LIMIT = 100
# Detecciones que una vista previa o una aplicación recorren como mucho.
PREVIEW_LIMIT = 200
RESOLVABLE_RULES = calc.ATTRIBUTABLE_RULES - calc.EXPOSURE_RULES
SYSTEM_ACTOR = "attribution"
# Ficheros que distribuye Sentra y cuya huella este servidor puede calcular de su propio
# árbol (catálogo de referencia). Relativos a la raíz del repositorio/instalación.
_REFERENCE_DIRS = ("scripts", "agent/packaging/windows", "sensor/packaging/windows")


class OperationValidationError(SentraError):
    status_code = 422
    code = "maintenance_operation_invalid"


class OperationStateError(ConflictError):
    code = "maintenance_operation_state"


# --- Validación de una operación -----------------------------------------------------------


def _clean_list(values: Sequence[str], kind: str) -> list[str]:
    cleaned: list[str] = []
    for value in values:
        item = calc.canonical_path(value) if kind == "path" else calc.canonical_account(value)
        if item is None:
            raise OperationValidationError(f"Invalid {kind}: {value[:80]}")
        if item not in cleaned:
            cleaned.append(item)
    return cleaned


def validate(body: MaintenanceOperationCreate, now: datetime) -> list[dict[str, Any]]:
    """Comprueba que la operación es concreta y acotada. Devuelve los artefactos normalizados.

    Lo que se rechaza (422 maintenance_operation_invalid) es lo que convertiría la operación
    en una excepción amplia: ventanas largas o abiertas, scripts sin hash o sin cuenta,
    servicios sin ImagePath, intérpretes del sistema como binario autorizado.
    """
    if body.window_end <= body.window_start:
        raise OperationValidationError("window_end must be after window_start")
    if body.window_end - body.window_start > MAX_WINDOW:
        raise OperationValidationError("The window cannot exceed 72 hours")
    if body.expires_at < body.window_end:
        raise OperationValidationError("expires_at must be after window_end")
    if body.expires_at <= now or body.expires_at - now > MAX_EXPIRY:
        raise OperationValidationError("expires_at must be in the next 90 days")
    artifacts: list[dict[str, Any]] = []
    for item in body.artifacts:
        row: dict[str, Any] = {
            "kind": item.kind,
            "reference_source": item.reference_source,
            "signer": item.signer,
        }
        if item.kind in ("script", "binary"):
            path = calc.canonical_path(item.path)
            if path is None or item.sha256 is None:
                raise OperationValidationError(
                    "Scripts and binaries need a canonical path and a SHA-256"
                )
            if item.kind == "binary" and interpreter_wide("exe", path):
                # Autorizar powershell.exe o python.exe del sistema autorizaría cualquier
                # cosa que se ejecute con ellos.
                raise OperationValidationError("A system interpreter cannot be authorized")
            row.update(path=path, sha256=item.sha256.lower())
        else:
            name = (item.service_name or "").strip()
            image = (item.image_path or "").strip()
            if not name or not image:
                raise OperationValidationError("Services need a name and the full ImagePath")
            row.update(
                service_name=name.casefold(),
                service_display_name=(
                    item.service_display_name.strip().casefold()
                    if item.service_display_name
                    else None
                ),
                image_path=image,
                service_account=calc.canonical_account(item.service_account),
            )
        artifacts.append(row)
    if any(a["kind"] == "script" for a in artifacts) and not body.accounts:
        raise OperationValidationError("Operations with scripts must name the executing accounts")
    return artifacts


# --- Lectura -------------------------------------------------------------------------------


def _artifact_read(row: MaintenanceArtifact) -> MaintenanceArtifactRead:
    return MaintenanceArtifactRead(
        kind=row.kind,
        path=row.path,
        sha256=row.sha256,
        signer=row.signer,
        reference_source=row.reference_source,
        service_name=row.service_name,
        service_display_name=row.service_display_name,
        image_path=row.image_path,
        service_account=row.service_account,
    )


def is_active(op: MaintenanceOperation, now: datetime) -> bool:
    return op.status == "approved" and op.expires_at >= now


def _ref(op: MaintenanceOperation, artifacts: Sequence[MaintenanceArtifact]) -> calc.OperationRef:
    return calc.OperationRef(
        id=op.id,
        public_id=str(op.public_id),
        operation_key=str(op.operation_key),
        version=op.version,
        title=op.title,
        window_start=op.window_start,
        window_end=op.window_end,
        accounts=frozenset(op.accounts or ()),
        interpreters=frozenset(op.interpreters or ()),
        parents=frozenset(op.parents or ()),
        signer=op.signer,
        approved_at=op.approved_at,
        artifacts=tuple(
            calc.ArtifactRef(
                kind=a.kind,
                path=a.path,
                sha256=a.sha256,
                signer=a.signer,
                service_name=a.service_name,
                service_display_name=a.service_display_name,
                image_path=a.image_path,
                service_account=a.service_account,
            )
            for a in artifacts
        ),
    )


def active_operations(
    session: Session,
    asset_id: int,
    start: datetime,
    end: datetime,
    now: datetime,
    only: int | None = None,
) -> list[calc.OperationRef]:
    """Operaciones aprobadas y vigentes del activo cuya ventana toca [start, end]."""
    query = select(MaintenanceOperation).where(
        MaintenanceOperation.asset_id == asset_id,
        MaintenanceOperation.status == "approved",
        MaintenanceOperation.expires_at >= now,
        MaintenanceOperation.window_start <= end,
        MaintenanceOperation.window_end >= start,
    )
    if only is not None:
        query = query.where(MaintenanceOperation.id == only)
    ops = session.scalars(query.order_by(MaintenanceOperation.id)).all()
    if not ops:
        return []
    artifacts: dict[int, list[MaintenanceArtifact]] = {}
    for artifact in session.scalars(
        select(MaintenanceArtifact).where(
            MaintenanceArtifact.operation_id.in_([op.id for op in ops])
        )
    ):
        artifacts.setdefault(artifact.operation_id, []).append(artifact)
    return [_ref(op, artifacts.get(op.id, [])) for op in ops]


def _evidence(session: Session, detection_id: int) -> list[calc.EvidenceItem]:
    rows = session.execute(
        select(
            DetectionEvidence.signal_kind,
            DetectionEvidence.occurred_at,
            DetectionEvidence.data,
            DetectionEvidence.role,
        )
        .where(DetectionEvidence.detection_id == detection_id)
        .order_by(DetectionEvidence.occurred_at, DetectionEvidence.id)
        .limit(EVIDENCE_LIMIT)
    ).all()
    return [
        calc.EvidenceItem(
            signal_kind=row.signal_kind,
            occurred_at=row.occurred_at,
            data=row.data if isinstance(row.data, dict) else {},
            role=row.role,
        )
        for row in rows
    ]


def _last_analyst_event(session: Session, detection_id: int) -> DetectionAttributionEvent | None:
    return session.scalars(
        select(DetectionAttributionEvent)
        .where(
            DetectionAttributionEvent.detection_id == detection_id,
            DetectionAttributionEvent.source == "analyst",
        )
        .order_by(DetectionAttributionEvent.created_at.desc(), DetectionAttributionEvent.id.desc())
        .limit(1)
    ).first()


# Modos de evaluación (política de autorización de mantenimiento, 7B.1):
# - AUTOMATIC: motor de detección y reevaluación de un analista. Solo cuentan operaciones
#   aprobadas ANTES de la actividad y de que la detección existiera: reconocer sola una
#   detección histórica con una aprobación posterior sería reescribir el pasado sin revisión.
# - REVIEW: vista previa y aplicar de un admin (revisión explícita y auditada). Cuentan todas
#   las operaciones vigentes cuya ventana cubre la actividad.
AUTOMATIC = "automatic"
REVIEW = "review"


def _recognizes_automatically(
    op: calc.OperationRef, detection: Detection, evidence_start: datetime
) -> bool:
    if detection.attribution_operation_id == op.id:
        # Ya verificada con esta operación (sola o tras una revisión explícita): reevaluarla
        # no deshace esa decisión, pero toda la evidencia nueva debe seguir casando.
        return True
    approved = op.approved_at
    return approved is not None and approved <= evidence_start and approved <= detection.created_at


def compute(
    session: Session,
    detection: Detection,
    now: datetime,
    only: int | None = None,
    mode: str = AUTOMATIC,
) -> calc.AttributionResult | None:
    """Veredicto del sistema para una detección (sin guardar nada)."""
    if detection.rule_id not in calc.ATTRIBUTABLE_RULES:
        return None
    evidence = _evidence(session, detection.id)
    if not evidence:
        return None
    start = min(e.occurred_at for e in evidence)
    end = max(e.occurred_at for e in evidence)
    ops = active_operations(session, detection.asset_id, start, end, now, only)
    if mode == REVIEW:
        return calc.evaluate(detection.rule_id, evidence, ops)
    enabled = get_settings().maintenance_auto_recognition
    eligible = [op for op in ops if enabled and _recognizes_automatically(op, detection, start)]
    result = calc.evaluate(detection.rule_id, evidence, eligible)
    held = [op for op in ops if op not in eligible]
    if result.verdict != calc.VERIFIED and held:
        # La explicación debe decir que existe una operación que la describiría: la
        # detección sigue activa y queda pendiente de revisión, no "sin operación".
        review = calc.evaluate(detection.rule_id, evidence, held)
        if review.verdict == calc.VERIFIED and review.operation is not None:
            reason = "auto_recognition_disabled" if not enabled else "approved_after_activity"
            result.review_required = {
                "operation_id": review.operation.public_id,
                "title": review.operation.title,
                "reason": reason,
            }
            result.explanation.append(
                "La operación «"
                + review.operation.title
                + "» describiría esta actividad, pero "
                + (
                    "el reconocimiento automático está desactivado"
                    if not enabled
                    else "se aprobó después de la actividad"
                )
                + ": la detección sigue activa hasta una revisión explícita (vista previa y"
                " aplicar en Mantenimiento)."
            )
    return result


@dataclass(frozen=True)
class Applied:
    verdict: str
    resolved: bool


def persist(
    session: Session, detection: Detection, result: calc.AttributionResult, now: datetime
) -> Applied:
    """Guarda el veredicto del sistema y aplica su efecto. Sin commit.

    Solo inserta una fila de historial si el veredicto o la operación cambian: el motor
    reevalúa en cada evidencia nueva y el historial no debe llenarse de repeticiones.
    """
    payload = result.to_json(now)
    analyst = _last_analyst_event(session, detection.id)
    previous_system = (detection.attribution or {}).get("verdict")
    previous_operation = ((detection.attribution or {}).get("operation") or {}).get("operation_id")
    current_operation = payload["operation"]["operation_id"] if payload["operation"] else None
    if analyst is not None:
        payload["analyst"] = {
            "verdict": analyst.verdict,
            "actor": analyst.actor,
            "reason": analyst.reason,
            "at": analyst.created_at.isoformat(),
        }
    detection.attribution = payload
    detection.attribution_at = now
    detection.attribution_operation_id = (
        result.operation.id if result.operation and result.verdict == calc.VERIFIED else None
    )
    shown = analyst.verdict if analyst is not None else result.verdict
    changed = detection.attribution_verdict != shown
    detection.attribution_verdict = shown
    if previous_system != result.verdict or previous_operation != current_operation:
        session.add(
            DetectionAttributionEvent(
                detection_id=detection.id,
                verdict=result.verdict,
                previous_verdict=previous_system,
                source="system",
                operation_id=result.operation.id if result.operation else None,
                actor=SYSTEM_ACTOR,
                reason="; ".join(result.explanation)[:1000] or None,
                evidence={
                    "items": payload["items"][:20],
                    "missing_evidence": payload["missing_evidence"],
                    "tamper_suspected": result.tamper_suspected,
                },
                created_at=now,
            )
        )
    if (
        analyst is None
        and result.verdict != calc.VERIFIED
        and detection.status == DetectionStatus.RESOLVED
        and detection.resolved_by == SYSTEM_ACTOR
    ):
        # Evidencia nueva que la operación no describe: la detección vuelve a estar activa
        # con su severidad y pide investigación (nunca se queda cerrada por una verificación
        # anterior). El historial conserva el veredicto previo.
        detection.status = DetectionStatus.OPEN
        detection.resolved_at = None
        detection.resolved_by = None
        detection.resolution_note = None
        detection.updated_at = now
        changed = True
    resolved = False
    if (
        analyst is None
        and result.verdict == calc.VERIFIED
        and result.operation is not None
        and detection.rule_id in RESOLVABLE_RULES
        and detection.status != DetectionStatus.RESOLVED
    ):
        from app.detection.engine import resolve_detection_alert

        detection.status = DetectionStatus.RESOLVED
        detection.resolved_at = now
        detection.resolved_by = SYSTEM_ACTOR
        detection.resolution_note = (
            f"Mantenimiento verificado: {result.operation.title}"
            f" (operación {result.operation.operation_key} v{result.operation.version})"
        )[:500]
        detection.updated_at = now
        resolve_detection_alert(session, detection, now)
        session.execute(
            update(MaintenanceOperation)
            .where(MaintenanceOperation.id == result.operation.id)
            .values(matches=MaintenanceOperation.matches + 1, last_match_at=now)
        )
        resolved = True
    if changed or resolved:
        request_recalculation(session, [detection.asset_id])
    return Applied(shown, resolved)


def evaluate_detection(session: Session, detection: Detection, now: datetime) -> Applied | None:
    """Gancho del motor de detección: evalúa y guarda (sin commit). Nunca lanza."""
    try:
        with session.begin_nested():
            result = compute(session, detection, now)
            if result is None:
                return None
            return persist(session, detection, result, now)
    except Exception:
        # La atribución explica; nunca debe impedir que una detección se registre.
        logger.exception("attribution failed", extra={"rule": detection.rule_id})
        return None


# --- Catálogo de referencia ----------------------------------------------------------------


def reference_root() -> Path:
    """Raíz del árbol de Sentra desde el que corre este servidor (repositorio o instalación)."""
    return Path(__file__).resolve().parents[3]


def reference_artifacts(root: Path | None = None) -> ReferenceArtifactList:
    """SHA-256 de los scripts que distribuye Sentra, calculado de los ficheros del servidor.

    Es la referencia de confianza más cercana que existe sin firma de código: el fichero que
    se distribuye junto a esta versión del servidor. No sirve si el atacante controla el
    propio servidor, y el panel lo dice. Nunca se usa un hash observado en el equipo.
    """
    base = root or reference_root()
    items: list[ReferenceArtifact] = []
    for directory in _REFERENCE_DIRS:
        folder = base / directory
        if not folder.is_dir():
            continue
        for path in sorted(folder.glob("*.ps1")):
            if path.name.lower() not in SENTRA_SCRIPTS or not path.is_file():
                continue
            if path.is_symlink():
                continue
            data = path.read_bytes()
            items.append(
                ReferenceArtifact(
                    name=path.name,
                    relative_path=path.relative_to(base).as_posix(),
                    sha256=hashlib.sha256(data).hexdigest(),
                    size=len(data),
                )
            )
    return ReferenceArtifactList(root_available=bool(items), items=items)


# --- Servicio ------------------------------------------------------------------------------


class AttributionService:
    def __init__(self, session: Session) -> None:
        self._session = session

    # Operaciones

    def _asset(self, public_id: UUID) -> Asset:
        asset = self._session.scalars(select(Asset).where(Asset.public_id == public_id)).first()
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _operation(self, public_id: UUID, *, lock: bool = False) -> MaintenanceOperation:
        query = select(MaintenanceOperation).where(MaintenanceOperation.public_id == public_id)
        if lock:
            query = query.with_for_update()
        op = self._session.scalars(query).first()
        if op is None:
            raise NotFoundError("Maintenance operation not found")
        return op

    def _read(self, op: MaintenanceOperation, now: datetime) -> MaintenanceOperationRead:
        session = self._session
        asset = session.get(Asset, op.asset_id)
        artifacts = session.scalars(
            select(MaintenanceArtifact)
            .where(MaintenanceArtifact.operation_id == op.id)
            .order_by(MaintenanceArtifact.id)
        ).all()
        supersedes = (
            session.scalar(
                select(MaintenanceOperation.public_id).where(
                    MaintenanceOperation.id == op.supersedes_id
                )
            )
            if op.supersedes_id
            else None
        )
        return MaintenanceOperationRead(
            id=op.public_id,
            operation_key=op.operation_key,
            version=op.version,
            supersedes=supersedes,
            asset_id=asset.public_id if asset else op.public_id,
            asset_name=asset.display_name if asset else "",
            kind=op.kind,
            title=op.title,
            reason=op.reason,
            status=op.status,
            active=is_active(op, now),
            window_start=op.window_start,
            window_end=op.window_end,
            expires_at=op.expires_at,
            accounts=list(op.accounts or []),
            interpreters=list(op.interpreters or []),
            parents=list(op.parents or []),
            signer=op.signer,
            artifacts=[_artifact_read(a) for a in artifacts],
            created_by=op.created_by,
            created_at=op.created_at,
            approved_by=op.approved_by,
            approved_at=op.approved_at,
            approval_note=op.approval_note,
            revoked_by=op.revoked_by,
            revoked_at=op.revoked_at,
            revoke_reason=op.revoke_reason,
            matches=op.matches,
            last_match_at=op.last_match_at,
        )

    def list(
        self,
        site_id: int | None,
        asset_public_id: UUID | None,
        status: str | None,
        limit: int,
        offset: int,
    ) -> MaintenanceOperationList:
        query = select(MaintenanceOperation)
        if asset_public_id is not None:
            query = query.where(MaintenanceOperation.asset_id == self._asset(asset_public_id).id)
        if site_id is not None:
            query = query.where(
                MaintenanceOperation.asset_id.in_(select(Asset.id).where(Asset.site_id == site_id))
            )
        if status is not None:
            query = query.where(MaintenanceOperation.status == status)
        total = self._session.scalar(select(func.count()).select_from(query.subquery())) or 0
        rows = self._session.scalars(
            query.order_by(MaintenanceOperation.created_at.desc(), MaintenanceOperation.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        now = datetime.now(UTC)
        return MaintenanceOperationList(items=[self._read(r, now) for r in rows], total=total)

    def get(self, public_id: UUID) -> MaintenanceOperationRead:
        return self._read(self._operation(public_id), datetime.now(UTC))

    def create(self, body: MaintenanceOperationCreate, actor: Actor) -> MaintenanceOperationRead:
        session = self._session
        now = datetime.now(UTC)
        asset = self._asset(body.asset_id)
        artifacts = validate(body, now)
        accounts = _clean_list(body.accounts, "account")
        interpreters = _clean_list(body.interpreters, "path")
        parents = _clean_list(body.parents, "path")
        previous = None
        if body.supersedes is not None:
            previous = self._operation(body.supersedes, lock=True)
            if previous.asset_id != asset.id:
                raise OperationValidationError("A new version must keep the same asset")
            if previous.status not in ("approved", "pending_review"):
                raise OperationStateError("Only a pending or approved operation can be replaced")
        op = MaintenanceOperation(
            asset_id=asset.id,
            kind=body.kind,
            title=body.title.strip(),
            reason=body.reason.strip(),
            status="pending_review",
            window_start=body.window_start,
            window_end=body.window_end,
            expires_at=body.expires_at,
            accounts=accounts,
            interpreters=interpreters,
            parents=parents,
            signer=body.signer.strip() if body.signer else None,
            created_by=actor.name[:64],
            created_at=now,
        )
        if previous is not None:
            op.operation_key = previous.operation_key
            op.version = previous.version + 1
            op.supersedes_id = previous.id
        session.add(op)
        session.flush()
        for artifact in artifacts:
            session.add(MaintenanceArtifact(operation_id=op.id, **artifact))
        session.flush()
        audit_service.record(
            session,
            actor,
            "maintenance_operation_created",
            target_type="maintenance_operation",
            target_id=op.public_id,
            details={
                "asset": str(asset.public_id),
                "kind": body.kind,
                "version": op.version,
                "artifacts": len(artifacts),
                "window_start": body.window_start.isoformat(),
                "window_end": body.window_end.isoformat(),
                "expires_at": body.expires_at.isoformat(),
            },
            commit=False,
        )
        read = self._read(op, now)
        session.commit()
        return read

    def approve(self, public_id: UUID, note: str | None, actor: Actor) -> MaintenanceOperationRead:
        session = self._session
        now = datetime.now(UTC)
        op = self._operation(public_id, lock=True)
        if op.status != "pending_review":
            raise OperationStateError("Only a pending operation can be approved")
        if op.expires_at <= now:
            raise OperationStateError("The operation already expired")
        op.status = "approved"
        op.approved_by = actor.name[:64]
        op.approved_at = now
        op.approval_note = note
        if op.supersedes_id is not None:
            previous = session.get(MaintenanceOperation, op.supersedes_id, with_for_update=True)
            if previous is not None and previous.status in ("approved", "pending_review"):
                previous.status = "superseded"
        audit_service.record(
            session,
            actor,
            "maintenance_operation_approved",
            target_type="maintenance_operation",
            target_id=op.public_id,
            details={"version": op.version, "note": note} if note else {"version": op.version},
            commit=False,
        )
        read = self._read(op, now)
        session.commit()
        return read

    def revoke(self, public_id: UUID, reason: str, actor: Actor) -> MaintenanceOperationRead:
        """Revoca la operación. Los veredictos ya dados quedan en el historial; las
        detecciones nuevas dejan de verificarse con ella."""
        session = self._session
        now = datetime.now(UTC)
        op = self._operation(public_id, lock=True)
        if op.status in ("revoked", "superseded"):
            raise OperationStateError("The operation is no longer active")
        op.status = "revoked"
        op.revoked_by = actor.name[:64]
        op.revoked_at = now
        op.revoke_reason = reason
        audit_service.record(
            session,
            actor,
            "maintenance_operation_revoked",
            target_type="maintenance_operation",
            target_id=op.public_id,
            details={"reason": reason},
            commit=False,
        )
        read = self._read(op, now)
        session.commit()
        return read

    def _window_detections(self, op: MaintenanceOperation) -> Sequence[Detection]:
        # Detecciones del activo con actividad que toca la ventana: candidatas a la
        # operación. Las ya resueltas por una persona no se reabren ni se tocan.
        return self._session.scalars(
            select(Detection)
            .where(
                Detection.asset_id == op.asset_id,
                Detection.rule_id.in_(sorted(calc.ATTRIBUTABLE_RULES)),
                Detection.first_seen_at <= op.window_end,
                Detection.last_seen_at >= op.window_start,
                or_(
                    Detection.status != DetectionStatus.RESOLVED,
                    Detection.resolved_by == SYSTEM_ACTOR,
                ),
            )
            .order_by(Detection.first_seen_at, Detection.id)
            .limit(PREVIEW_LIMIT)
        ).all()

    def preview(self, public_id: UUID) -> AttributionPreview:
        """Qué pasaría con las detecciones de la ventana si se aplica (sin efectos)."""
        now = datetime.now(UTC)
        op = self._operation(public_id)
        if not is_active(op, now):
            raise OperationStateError("Only an approved, unexpired operation can be applied")
        items = []
        for detection in self._window_detections(op):
            result = compute(self._session, detection, now, only=op.id, mode=REVIEW)
            if result is None:
                continue
            items.append(
                AttributionPreviewItem(
                    detection_id=detection.public_id,
                    rule_id=detection.rule_id,
                    title=detection.title,
                    status=detection.status.value,
                    current_verdict=detection.attribution_verdict,
                    verdict=result.verdict,
                    would_resolve=(
                        result.verdict == calc.VERIFIED
                        and detection.rule_id in RESOLVABLE_RULES
                        and detection.status != DetectionStatus.RESOLVED
                        and _last_analyst_event(self._session, detection.id) is None
                    ),
                    attribution=result.to_json(now),
                )
            )
        verified = sum(1 for i in items if i.verdict == calc.VERIFIED)
        return AttributionPreview(
            operation_id=op.public_id,
            items=items,
            verified=verified,
            not_verified=len(items) - verified,
        )

    def apply(self, public_id: UUID, actor: Actor) -> AttributionApplyResult:
        """Aplica la operación a las detecciones de su ventana (confirmado por un admin)."""
        session = self._session
        now = datetime.now(UTC)
        op = self._operation(public_id, lock=True)
        if not is_active(op, now):
            raise OperationStateError("Only an approved, unexpired operation can be applied")
        evaluated = verified = resolved = 0
        for detection in self._window_detections(op):
            locked = session.get(Detection, detection.id, with_for_update=True)
            if locked is None:
                continue
            # Todas las operaciones vigentes, no solo esta: el veredicto debe ser el mismo
            # que daría el motor (si otra operación también la cubre, también vale).
            result = compute(session, locked, now, mode=REVIEW)
            if result is None:
                continue
            evaluated += 1
            applied = persist(session, locked, result, now)
            verified += applied.verdict == calc.VERIFIED
            resolved += applied.resolved
        audit_service.record(
            session,
            actor,
            "maintenance_operation_applied",
            target_type="maintenance_operation",
            target_id=op.public_id,
            details={"evaluated": evaluated, "verified": verified, "resolved": resolved},
            commit=False,
        )
        session.commit()
        return AttributionApplyResult(
            operation_id=op.public_id, evaluated=evaluated, verified=verified, resolved=resolved
        )

    # Detecciones

    def _detection(self, public_id: UUID, *, lock: bool = False) -> Detection:
        query = select(Detection).where(Detection.public_id == public_id)
        if lock:
            query = query.with_for_update()
        detection = self._session.scalars(query).first()
        if detection is None:
            raise NotFoundError("Detection not found")
        return detection

    def detection_attribution(self, public_id: UUID) -> DetectionAttributionRead:
        detection = self._detection(public_id)
        rows = self._session.execute(
            select(DetectionAttributionEvent, MaintenanceOperation.public_id)
            .outerjoin(
                MaintenanceOperation,
                MaintenanceOperation.id == DetectionAttributionEvent.operation_id,
            )
            .where(DetectionAttributionEvent.detection_id == detection.id)
            .order_by(
                DetectionAttributionEvent.created_at.desc(), DetectionAttributionEvent.id.desc()
            )
            .limit(100)
        ).all()
        return DetectionAttributionRead(
            detection_id=detection.public_id,
            rule_id=detection.rule_id,
            attributable=detection.rule_id in calc.ATTRIBUTABLE_RULES,
            verdict=detection.attribution_verdict,
            attribution=detection.attribution,
            evaluated_at=detection.attribution_at,
            history=[
                AttributionEventRead(
                    id=event.public_id,
                    verdict=event.verdict,
                    previous_verdict=event.previous_verdict,
                    source=event.source,
                    actor=event.actor,
                    reason=event.reason,
                    operation_id=operation_id,
                    created_at=event.created_at,
                    evidence=event.evidence,
                )
                for event, operation_id in rows
            ],
        )

    def evaluate(self, public_id: UUID, actor: Actor) -> DetectionAttributionRead:
        """Reevaluación manual (p. ej. tras actualizar el agente) con las mismas reglas que el
        motor: no reclasifica una detección histórica con una operación aprobada después;
        eso solo lo hace la vista previa y aplicar de un admin."""
        session = self._session
        now = datetime.now(UTC)
        detection = self._detection(public_id, lock=True)
        if detection.rule_id not in calc.ATTRIBUTABLE_RULES:
            raise OperationValidationError("This rule is not attributable")
        result = compute(session, detection, now)
        if result is not None:
            persist(session, detection, result, now)
        audit_service.record(
            session,
            actor,
            "detection_attribution_evaluated",
            target_type="detection",
            target_id=detection.public_id,
            details={"verdict": detection.attribution_verdict},
            commit=False,
        )
        session.commit()
        return self.detection_attribution(public_id)

    def analyst_verdict(
        self, public_id: UUID, body: AnalystVerdictIn, actor: Actor
    ) -> DetectionAttributionRead:
        """Decisión del analista: inmutable, manda sobre el sistema y nunca cierra sola.

        Una detección confirmada como maliciosa conserva su severidad y su estado (el
        analista la gestiona con el flujo de siempre); la confirmación sube la confianza
        del riesgo (ver risk/calculator.py).
        """
        session = self._session
        now = datetime.now(UTC)
        detection = self._detection(public_id, lock=True)
        if detection.rule_id not in calc.ATTRIBUTABLE_RULES:
            raise OperationValidationError("This rule is not attributable")
        previous = detection.attribution_verdict
        session.add(
            DetectionAttributionEvent(
                detection_id=detection.id,
                verdict=body.verdict,
                previous_verdict=previous,
                source="analyst",
                actor=actor.name[:64],
                reason=body.reason,
                evidence=None,
                created_at=now,
            )
        )
        detection.attribution_verdict = body.verdict
        detection.attribution = {
            **(detection.attribution or {}),
            "analyst": {
                "verdict": body.verdict,
                "actor": actor.name[:64],
                "reason": body.reason,
                "at": now.isoformat(),
            },
        }
        detection.updated_at = now
        request_recalculation(session, [detection.asset_id])
        audit_service.record(
            session,
            actor,
            "detection_attribution_decided",
            target_type="detection",
            target_id=detection.public_id,
            details={"verdict": body.verdict, "previous": previous},
            commit=False,
        )
        session.commit()
        return self.detection_attribution(public_id)
