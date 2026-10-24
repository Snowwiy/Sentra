"""Estado de las sesiones de aislamiento y conciliación con lo que informa el equipo (6E.7).

El servidor nunca da un aislamiento por hecho ni por levantado sin el equipo:

- el resultado de `isolate_host`/`release_isolation` (comando de Response) mueve la sesión
  solo si el helper verificó lo aplicado leyendo sus reglas de vuelta;
- el heartbeat del agente 0.5.0 trae el estado real del helper y se concilia aquí;
- si servidor y equipo no coinciden, la sesión pasa a `unknown` y se abre la alerta
  `isolation_state` (crítica). Se resuelve sola cuando vuelven a coincidir.

Este módulo no importa el Response Engine: lo llama él (resultado de un comando y barrido).
"""

import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.asset import Asset
from app.models.isolation import ACTIVE_ISOLATION_STATES, IsolationSession
from app.models.response import TERMINAL_EXECUTION_STATUSES, AgentCommand, ResponseExecution
from app.response.results import clean_text
from app.services import audit_service
from app.services.audit_service import Actor

logger = logging.getLogger(__name__)

ISOLATION_COMMANDS = frozenset({"isolate_host", "release_isolation"})
SYSTEM = Actor("system")
# Margen sobre la caducidad: el helper revierte con su propio reloj; un heartbeat que llega
# justo al caducar no es una discrepancia.
EXPIRY_GRACE = timedelta(minutes=2)
_METHODS = frozenset({"windows_firewall", "nftables"})
HELPER_STATES = frozenset({"absent", "disabled", "ready", "error"})
REPORT_STATES = frozenset({"none", "applying", "isolated", "reverting", "failed"})


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def _code(value: Any) -> str | None:
    return clean_text(value, 64) if isinstance(value, str) and value else None


def _audit(
    session: Session, actor: Actor, action: str, row: IsolationSession, **extra: Any
) -> None:
    audit_service.record(
        session,
        actor,
        action,
        audit_service.FAILURE if row.status in ("failed", "unknown") else audit_service.SUCCESS,
        target_type="isolation_session",
        target_id=row.public_id,
        details={
            "asset": str(row.asset_public_id),
            "status": row.status,
            "error": row.error_code,
            **extra,
        },
        commit=False,
    )


def _alert(
    session: Session, asset: Asset | None, message: str, now: datetime, **details: Any
) -> None:
    if asset is None:
        return
    from app.core.config import get_settings
    from app.models.alert import AlertRule, AlertSeverity
    from app.services.alert_service import AlertService, AlertThresholds

    service = AlertService(session, AlertThresholds.from_settings(get_settings()))
    service.raise_alert(
        asset, AlertRule.ISOLATION_STATE, AlertSeverity.CRITICAL, message, now, details
    )


def _resolve_alert(session: Session, asset: Asset | None, now: datetime) -> None:
    if asset is None:
        return
    from app.core.config import get_settings
    from app.models.alert import AlertRule
    from app.services.alert_service import AlertService, AlertThresholds

    AlertService(session, AlertThresholds.from_settings(get_settings())).resolve_rule(
        asset, AlertRule.ISOLATION_STATE, now
    )


def _end(row: IsolationSession, status: str, now: datetime, error_code: str | None = None) -> None:
    row.status = status
    row.error_code = error_code
    if status in ("restored", "failed", "expired"):
        row.ended_at = now
    row.version += 1


def _unknown(
    session: Session, row: IsolationSession, asset: Asset | None, now: datetime, code: str
) -> None:
    """Servidor y equipo discrepan: unknown + alerta crítica (nunca se asume nada)."""
    if row.status == "unknown" and row.error_code == code:
        return
    _end(row, "unknown", now, code)
    _audit(session, SYSTEM, "isolation_state_unknown", row)
    _alert(
        session,
        asset,
        "El estado de aislamiento del equipo no coincide con Sentra: revisa el equipo",
        now,
        session_id=str(row.public_id),
        error_code=code,
    )


def _apply_details(row: IsolationSession, info: dict[str, Any], now: datetime) -> None:
    row.applied_at = _parse_time(info.get("applied_at")) or row.applied_at or now
    method = info.get("method")
    row.method = method if method in _METHODS else None
    row.verified = info.get("verified") is True
    allowed = info.get("allowed")
    row.allowed = [clean_text(a, 64) for a in allowed[:64]] if isinstance(allowed, list) else []
    rules = info.get("rules")
    row.rules = (
        [
            {clean_text(k, 32): clean_text(v, 128) for k, v in list(rule.items())[:8]}
            for rule in rules[:16]
            if isinstance(rule, dict)
        ]
        if isinstance(rules, list)
        else []
    )


def apply_isolation_result(
    session: Session,
    execution: ResponseExecution,
    command: AgentCommand,
    body: Any,
    now: datetime,
) -> None:
    """Resultado de isolate_host/release_isolation devuelto por el agente."""
    row = session.scalar(
        select(IsolationSession)
        .where(
            or_(
                IsolationSession.isolate_execution_id == execution.id,
                IsolationSession.release_execution_id == execution.id,
            )
        )
        .with_for_update()
    )
    if row is None:
        return
    asset = session.get(Asset, row.asset_id) if row.asset_id is not None else None
    data = body.data if isinstance(body.data, dict) else {}
    raw_info = data.get("isolation")
    info: dict[str, Any] = raw_info if isinstance(raw_info, dict) else {}
    state = info.get("state")
    same_session = info.get("session_id") == str(row.public_id)
    row.reported_state = state[:16] if isinstance(state, str) else None
    row.reported_at = now
    error = _code(body.error_code) or _code(info.get("error_code"))
    succeeded = body.status == "succeeded"
    if command.command_type == "isolate_host":
        if row.status not in ("applying", "unknown"):
            # Ya se pidió liberar (reverting) o se cerró: solo se guarda lo informado.
            if state == "isolated" and same_session:
                _apply_details(row, info, now)
            return
        if succeeded and state == "isolated" and same_session and info.get("verified") is True:
            _apply_details(row, info, now)
            _end(row, "isolated", now)
            _audit(session, SYSTEM, "isolation_applied", row, method=row.method)
            _resolve_alert(session, asset, now)
        elif state == "isolated":
            # Reglas puestas pero sin verificar: no se da por aislado ni por limpio.
            _apply_details(row, info, now)
            _unknown(session, row, asset, now, error or "verification_failed")
        else:
            # El helper rechazó o deshizo el intento (verificación fallida = revierte solo).
            _end(row, "failed", now, error or "isolation_failed")
            _audit(session, SYSTEM, "isolation_failed", row)
        return
    if row.status not in ("reverting", "unknown"):
        return
    if succeeded and state == "restored":
        row.released_at = now
        _end(row, "restored", now)
        _audit(session, SYSTEM, "isolation_restored", row)
        _resolve_alert(session, asset, now)
    else:
        _unknown(session, row, asset, now, error or "release_failed")


def reconcile_report(session: Session, asset: Asset, report: dict[str, Any], now: datetime) -> None:
    """Concilia el estado del helper que trae el heartbeat con la sesión viva del activo."""
    asset.isolation_status = report
    asset.isolation_status_at = now
    helper = report.get("helper")
    state = report.get("state")
    session_id = report.get("session_id")
    row = session.scalar(
        select(IsolationSession)
        .where(
            IsolationSession.asset_id == asset.id,
            IsolationSession.status.in_(ACTIVE_ISOLATION_STATES),
        )
        .with_for_update()
    )
    if row is None:
        if state == "isolated":
            # Aislado sin sesión viva en Sentra (p. ej. base de datos restaurada): se avisa;
            # el helper lo revierte solo al caducar.
            _alert(
                session,
                asset,
                "El equipo informa de un aislamiento que Sentra no tiene registrado",
                now,
                session_id=str(session_id) if session_id else None,
            )
        else:
            _resolve_alert(session, asset, now)
        return
    if helper not in ("ready", "disabled") or state not in REPORT_STATES:
        # Sin helper legible no hay estado fiable: no se mueve la sesión por suposición.
        return
    row.reported_state = state
    row.reported_at = now
    same = session_id == str(row.public_id)
    if state == "isolated" and not same:
        _unknown(session, row, asset, now, "session_mismatch")
        return
    if row.status in ("applying", "unknown") and state == "isolated" and same:
        if report.get("verified") is True:
            _apply_details(row, report, now)
            _end(row, "isolated", now)
            _audit(session, SYSTEM, "isolation_applied", row, source="heartbeat")
            _resolve_alert(session, asset, now)
        return
    if row.status == "isolated" and state == "isolated":
        _resolve_alert(session, asset, now)
        return
    if state == "none":
        if row.status == "reverting" or (row.status == "unknown" and row.released_by):
            row.released_at = row.released_at or now
            _end(row, "restored", now)
            _audit(session, SYSTEM, "isolation_restored", row, source="heartbeat")
            _resolve_alert(session, asset, now)
        elif row.status in ("isolated", "unknown") and now >= row.expires_at - EXPIRY_GRACE:
            # Caducó y el helper revirtió solo (lo esperado sin liberación manual).
            _end(row, "expired", now)
            _audit(session, SYSTEM, "isolation_expired", row)
            _resolve_alert(session, asset, now)
        elif row.status == "isolated":
            _unknown(session, row, asset, now, "rules_lost")
        elif row.status == "unknown":
            # El equipo ya no está aislado: se cierra la discrepancia como fallo explicado.
            _end(row, "failed", now, row.error_code or "isolation_lost")
            _audit(session, SYSTEM, "isolation_failed", row, source="heartbeat")
            _resolve_alert(session, asset, now)
        return
    if state == "failed" and same and row.status == "applying":
        _end(row, "failed", now, _code(report.get("error_code")) or "isolation_failed")
        _audit(session, SYSTEM, "isolation_failed", row, source="heartbeat")


def sweep_isolation(session: Session, now: datetime | None = None) -> dict[str, int]:
    """Cierra sesiones cuyo comando terminó sin resultado (caducado, cancelado, plazo)."""
    now = now or datetime.now(UTC)
    counts = {"failed": 0, "unknown": 0}
    rows = session.scalars(
        select(IsolationSession)
        .where(IsolationSession.status.in_(("applying", "reverting")))
        .with_for_update(skip_locked=True)
        .limit(200)
    ).all()
    for row in rows:
        execution_id = (
            row.isolate_execution_id if row.status == "applying" else row.release_execution_id
        )
        execution = session.get(ResponseExecution, execution_id) if execution_id else None
        if execution is not None and execution.status not in TERMINAL_EXECUTION_STATUSES:
            continue
        if execution is not None and execution.status == "succeeded":
            continue
        asset = session.get(Asset, row.asset_id) if row.asset_id is not None else None
        delivered = bool(
            execution is not None
            and session.scalar(
                select(AgentCommand.id).where(
                    AgentCommand.execution_id == execution.id, AgentCommand.delivery_count > 0
                )
            )
        )
        if row.status == "applying" and not delivered:
            # Nunca llegó al equipo: no se aplicó nada.
            _end(
                row, "failed", now, (execution.error_code if execution else None) or "not_delivered"
            )
            _audit(session, SYSTEM, "isolation_failed", row)
            counts["failed"] += 1
        else:
            # Entregado sin resultado: puede haberse aplicado (o no liberado). Se marca para
            # revisión; el helper revierte solo al caducar en cualquier caso.
            _unknown(session, row, asset, now, "no_result")
            counts["unknown"] += 1
    session.commit()
    return counts
