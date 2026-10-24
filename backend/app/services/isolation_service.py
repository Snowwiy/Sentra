"""Aislamiento seguro de equipos (Fase 6E.7, docs/safe-isolation.md).

Flujo (solo admin con containment:isolate):
1. Previsualización (containment:preview): disponibilidad, motivos, impacto y sesión viva.
2. Petición con confirmación escrita (nombre exacto del equipo), motivo y duración acotada
   por ISOLATION_MAX_MINUTES: la sesión pasa requested → approved y se crea la ejecución
   `isolate_host` del Response Engine (misma política: agente activo, en línea, capacidad
   anunciada, permisos). Si la política la bloquea, la sesión queda failed con el motivo.
3. El helper local aplica y verifica; el resultado o el heartbeat la mueven a isolated
   (app/isolation/state.py). Nunca se marca isolated sin esa verificación.
4. Liberación (containment:release): reverting → restored con la confirmación del equipo.

Defensa en profundidad: aunque este servidor esté comprometido, el helper aplica su propia
política local (desactivada por defecto), calcula él mismo qué se permite y revierte solo al
caducar. Ver docs/safe-isolation-helper.md.
"""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import ConflictError, NotFoundError, SentraError
from app.models.asset import Asset
from app.models.isolation import ACTIVE_ISOLATION_STATES, IsolationSession
from app.models.response import ResponseExecution
from app.response.catalog import asset_platform
from app.response.policy import agent_online
from app.response.results import clean_text
from app.schemas.isolation import (
    NOT_AVAILABLE_MESSAGE,
    IsolationOverview,
    IsolationRequest,
    IsolationSessionList,
    IsolationSessionRead,
    Reason,
    ReleaseRequest,
)
from app.schemas.response import ExecutionRequest
from app.services import audit_service
from app.services.asset_lifecycle_service import credential_active
from app.services.response_service import Operator, ResponseBlockedError, ResponseService

ISOLATION_PLATFORMS = frozenset({"windows", "linux"})
IMPACT = [
    "El equipo deja de comunicarse con la red salvo con el servidor Sentra, loopback, DHCP y"
    " (si la política local lo permite) sus servidores DNS.",
    "Las sesiones remotas (RDP, SSH, compartidos) y las aplicaciones de red se cortan.",
    "El helper local revierte solo al caducar, aunque el servidor no responda.",
    "No se deshabilita el firewall ni se tocan las reglas del usuario: solo se añaden reglas"
    " propias que se borran al liberar.",
]
MANUAL = [
    "Desconectar el cable de red o el Wi-Fi del equipo físicamente.",
    "Mover el puerto del switch a una VLAN de cuarentena o deshabilitarlo.",
    "Bloquear la MAC o la IP del equipo en el router o firewall perimetral.",
]


class IsolationDisabledError(ConflictError):
    code = "isolation_disabled"


class IsolationUnavailableError(ConflictError):
    code = "isolation_unavailable"


class IsolationActiveError(ConflictError):
    code = "isolation_active"


class IsolationConfirmationError(SentraError):
    status_code = 422
    code = "isolation_confirmation_mismatch"


class IsolationDurationError(SentraError):
    status_code = 422
    code = "isolation_duration_exceeds_policy"


class IsolationStateConflictError(ConflictError):
    code = "isolation_state_conflict"


def _now() -> datetime:
    return datetime.now(UTC)


def session_read(session: Session, row: IsolationSession) -> IsolationSessionRead:
    ids = [i for i in (row.isolate_execution_id, row.release_execution_id) if i]
    publics = (
        {
            execution_id: execution_public
            for execution_id, execution_public in session.execute(
                select(ResponseExecution.id, ResponseExecution.public_id).where(
                    ResponseExecution.id.in_(ids)
                )
            )
        }
        if ids
        else {}
    )
    return IsolationSessionRead(
        id=row.public_id,
        asset_id=row.asset_public_id,
        asset_label=row.asset_label,
        status=row.status,
        reason=row.reason,
        duration_minutes=row.duration_minutes,
        requested_by=row.requested_by,
        requested_at=row.requested_at,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        expires_at=row.expires_at,
        applied_at=row.applied_at,
        released_by=row.released_by,
        release_reason=row.release_reason,
        released_at=row.released_at,
        ended_at=row.ended_at,
        method=row.method,
        verified=row.verified,
        allowed=row.allowed or [],
        rules=row.rules or [],
        error_code=row.error_code,
        reported_state=row.reported_state,
        reported_at=row.reported_at,
        isolate_execution_id=publics.get(row.isolate_execution_id)
        if row.isolate_execution_id
        else None,
        release_execution_id=publics.get(row.release_execution_id)
        if row.release_execution_id
        else None,
        version=row.version,
    )


class IsolationService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def _asset(self, public_id: uuid.UUID) -> Asset:
        asset = self._session.scalar(select(Asset).where(Asset.public_id == public_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _active(self, asset: Asset, lock: bool = False) -> IsolationSession | None:
        query = select(IsolationSession).where(
            IsolationSession.asset_id == asset.id,
            IsolationSession.status.in_(ACTIVE_ISOLATION_STATES),
        )
        if lock:
            query = query.with_for_update()
        return self._session.scalar(query)

    def _reasons(self, asset: Asset, now: datetime) -> tuple[list[Reason], str | None]:
        """Motivos por los que no se puede aislar ahora y, si son permanentes, el mensaje."""
        settings = self._settings
        reasons: list[Reason] = []
        permanent = False
        platform = asset_platform(asset.os_name)
        if asset.agent_id is None:
            permanent = True
            reasons.append(Reason(code="no_agent", message="El dispositivo no tiene agente Sentra"))
        elif platform not in ISOLATION_PLATFORMS:
            permanent = True
            reasons.append(
                Reason(
                    code="unsupported_platform",
                    message="Plataforma sin aislamiento con reversión garantizada",
                )
            )
        if not settings.isolation_enabled:
            reasons.append(
                Reason(code="isolation_disabled", message="ISOLATION_ENABLED=false en el servidor")
            )
        if not settings.response_enabled:
            reasons.append(Reason(code="response_disabled", message="Response está desactivado"))
        if asset.is_archived:
            reasons.append(Reason(code="asset_archived", message="El activo está archivado"))
        if asset.agent_id is not None and not permanent:
            if not credential_active(asset):
                reasons.append(
                    Reason(code="agent_credential_inactive", message="El agente no está activo")
                )
            if "isolate_host" not in (asset.agent_capabilities or []):
                helper = (asset.isolation_status or {}).get("helper")
                reasons.append(
                    Reason(
                        code="helper_unavailable",
                        message="El helper de aislamiento no está instalado, habilitado y sano"
                        f" en el equipo (estado: {helper or 'desconocido'})",
                    )
                )
            timeout = timedelta(seconds=settings.heartbeat_timeout_seconds)
            if not agent_online(asset, now, timeout):
                reasons.append(Reason(code="agent_offline", message="El agente no está conectado"))
        if self._active(asset) is not None:
            reasons.append(
                Reason(code="isolation_active", message="Ya hay una sesión de aislamiento viva")
            )
        return reasons, NOT_AVAILABLE_MESSAGE if permanent else None

    def overview(self, public_id: uuid.UUID) -> IsolationOverview:
        asset = self._asset(public_id)
        now = _now()
        reasons, message = self._reasons(asset, now)
        current = self._active(asset)
        return IsolationOverview(
            asset_id=asset.public_id,
            asset_label=asset.display_name,
            available=not reasons,
            unavailable_message=message,
            reasons=reasons,
            server_enabled=self._settings.isolation_enabled,
            platform=asset_platform(asset.os_name),
            helper=asset.isolation_status,
            helper_reported_at=asset.isolation_status_at,
            confirm_name=asset.display_name,
            default_minutes=min(
                self._settings.isolation_default_minutes, self._settings.isolation_max_minutes
            ),
            max_minutes=self._settings.isolation_max_minutes,
            impact=IMPACT,
            manual_recommendations=MANUAL,
            current=session_read(self._session, current) if current is not None else None,
        )

    def history(self, public_id: uuid.UUID, limit: int) -> IsolationSessionList:
        asset = self._asset(public_id)
        total = int(
            self._session.scalar(
                select(func.count())
                .select_from(IsolationSession)
                .where(IsolationSession.asset_public_id == asset.public_id)
            )
            or 0
        )
        rows = self._session.scalars(
            select(IsolationSession)
            .where(IsolationSession.asset_public_id == asset.public_id)
            .order_by(IsolationSession.requested_at.desc())
            .limit(limit)
        ).all()
        return IsolationSessionList(
            items=[session_read(self._session, r) for r in rows], total=total
        )

    def list_active(self) -> IsolationSessionList:
        rows = self._session.scalars(
            select(IsolationSession)
            .where(IsolationSession.status.in_(ACTIVE_ISOLATION_STATES))
            .order_by(IsolationSession.requested_at.desc())
            .limit(500)
        ).all()
        return IsolationSessionList(
            items=[session_read(self._session, r) for r in rows], total=len(rows)
        )

    def _audit(self, op: Operator, action: str, row: IsolationSession, **extra: object) -> None:
        audit_service.record(
            self._session,
            op.actor,
            action,
            target_type="isolation_session",
            target_id=row.public_id,
            details={
                "asset": str(row.asset_public_id),
                "status": row.status,
                "duration_minutes": row.duration_minutes,
                **extra,
            },
            commit=False,
        )

    def isolate(
        self, op: Operator, public_id: uuid.UUID, body: IsolationRequest
    ) -> IsolationSessionRead:
        settings = self._settings
        if not settings.isolation_enabled:
            raise IsolationDisabledError("Isolation is disabled on this server")
        asset = self._asset(public_id)
        if body.confirm_name.strip() != asset.display_name.strip():
            raise IsolationConfirmationError("Type the exact device name to confirm")
        if body.duration_minutes > settings.isolation_max_minutes:
            raise IsolationDurationError(
                f"Maximum isolation duration is {settings.isolation_max_minutes} minutes"
            )
        now = _now()
        reasons, message = self._reasons(asset, now)
        blocking = [r for r in reasons if r.code != "agent_offline"]
        if message is not None or any(r.code == "isolation_active" for r in blocking):
            raise IsolationUnavailableError(
                message or "There is already a live isolation session",
                details=[r.model_dump() for r in reasons],
            )
        row = IsolationSession(
            asset_id=asset.id,
            asset_public_id=asset.public_id,
            asset_label=asset.display_name[:255],
            agent_id=asset.agent_id,
            status="requested",
            reason=clean_text(body.reason, 500),
            duration_minutes=body.duration_minutes,
            requested_by=op.actor.name[:64],
            requested_at=now,
            expires_at=now + timedelta(minutes=body.duration_minutes),
            verified=False,
            allowed=[],
            rules=[],
            version=1,
        )
        try:
            with self._session.begin_nested():
                self._session.add(row)
                self._session.flush()
        except IntegrityError:
            raise IsolationActiveError("There is already a live isolation session") from None
        self._audit(op, "isolation_requested", row, reason_given=True)
        # La confirmación escrita del admin es la aprobación: se registra aparte para que la
        # auditoría muestre quién aprobó y cuándo (mismo admin en 6E; aprobación por un
        # segundo admin queda como mejora documentada).
        row.status = "approved"
        row.approved_by = op.actor.name[:64]
        row.approved_at = now
        self._audit(op, "isolation_approved", row, confirmation="device_name")
        request = ExecutionRequest(
            action_id="isolate_host",
            target_id=asset.public_id,
            parameters={"session_id": str(row.public_id), "expires_at": row.expires_at.isoformat()},
            confirm=True,
            reason=row.reason,
        )
        responses = ResponseService(self._session, settings)
        session_id = row.id
        try:
            out = responses.execute(op, request, isolation=row)
        except ResponseBlockedError as exc:
            self._session.rollback()
            failed = self._session.get(IsolationSession, session_id)
            if failed is not None:
                blockers = [d.get("code") for d in exc.details or [] if d.get("code")]
                failed.status = "failed"
                failed.error_code = str(blockers[0]) if blockers else "response_blocked"
                failed.ended_at = _now()
                failed.version += 1
                self._audit(op, "isolation_failed", failed, blockers=blockers)
                self._session.commit()
            raise
        row = self._reload(session_id)
        execution = self._session.scalar(
            select(ResponseExecution).where(ResponseExecution.public_id == out.execution_id)
        )
        row.isolate_execution_id = execution.id if execution is not None else None
        row.status = "applying"
        row.version += 1
        self._audit(op, "isolation_dispatched", row, execution=str(out.execution_id))
        read = session_read(self._session, row)
        self._session.commit()
        return read

    def _reload(self, session_id: int) -> IsolationSession:
        row = self._session.get(IsolationSession, session_id, populate_existing=True)
        if row is None:  # pragma: no cover - nunca se borran
            raise NotFoundError("Isolation session not found")
        return row

    def release(
        self, op: Operator, public_id: uuid.UUID, body: ReleaseRequest
    ) -> IsolationSessionRead:
        asset = self._asset(public_id)
        row = self._active(asset, lock=True)
        if row is None:
            raise NotFoundError("No live isolation session for this asset")
        if row.version != body.version:
            raise IsolationStateConflictError("The isolation session changed; reload it")
        if row.status not in ("applying", "isolated", "unknown"):
            raise IsolationStateConflictError(f"Cannot release a session in state {row.status}")
        row.status = "reverting"
        row.released_by = op.actor.name[:64]
        row.release_reason = clean_text(body.reason, 500)
        row.version += 1
        self._audit(op, "isolation_release_requested", row)
        session_id = row.id
        request = ExecutionRequest(
            action_id="release_isolation",
            target_id=asset.public_id,
            parameters={"session_id": str(row.public_id)},
            confirm=True,
            reason=row.release_reason,
        )
        try:
            out = ResponseService(self._session, self._settings).execute(op, request, isolation=row)
        except ResponseBlockedError as exc:
            # No se pudo enviar (agente revocado, Response desactivado...): el equipo sigue
            # como estaba y el helper revertirá al caducar. Se deja constancia sin mentir.
            self._session.rollback()
            row = self._reload(session_id)
            blockers = [d.get("code") for d in exc.details or [] if d.get("code")]
            row.status = "unknown"
            row.error_code = str(blockers[0]) if blockers else "release_blocked"
            row.released_by = op.actor.name[:64]
            row.release_reason = clean_text(body.reason, 500)
            row.version += 1
            self._audit(op, "isolation_release_blocked", row, blockers=blockers)
            self._session.commit()
            raise
        row = self._reload(session_id)
        execution = self._session.scalar(
            select(ResponseExecution).where(ResponseExecution.public_id == out.execution_id)
        )
        row.release_execution_id = execution.id if execution is not None else None
        row.version += 1
        read = session_read(self._session, row)
        self._session.commit()
        return read
