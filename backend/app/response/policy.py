"""Política única de Response (Fase 5D): la usan preview, ejecución y cada paso de playbook.

`evaluate` no tiene efectos secundarios: solo lee. Devuelve los bloqueos (blockers) que
impiden ejecutar y los avisos (warnings) que no lo impiden. El motor ejecuta solo si no hay
bloqueos, recalculándolos en la misma petición: nunca se confía en un preview anterior.

Lo que NO es un bloqueo sino un 403: que el rol no tenga los permisos de la acción. Se
comprueba antes (services/response_service.py) para que preview y ejecución respondan igual
a un usuario sin permiso, sin revelar el estado del objetivo.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.incidents.workflow import is_frozen
from app.models.asset import Asset
from app.models.response import ACTIVE_EXECUTION_STATUSES, ResponseExecution
from app.response.catalog import AGENT_COMMAND_TYPES, ActionDefinition, asset_platform
from app.response.handlers import ActionContext, Issue
from app.services.asset_lifecycle_service import credential_active


@dataclass
class Decision:
    blockers: list[Issue] = field(default_factory=list)
    warnings: list[Issue] = field(default_factory=list)
    # Comprobaciones que pasaron (para que el operador vea qué se verificó).
    preconditions: list[str] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return not self.blockers


def agent_online(asset: Asset, now: datetime, timeout: timedelta) -> bool:
    """Mismo criterio que el resto de Sentra: contacto dentro de HEARTBEAT_TIMEOUT_SECONDS."""
    return asset.last_seen_at is not None and now - asset.last_seen_at <= timeout


def active_count(session: Session, asset_id: int) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(ResponseExecution)
            .where(
                ResponseExecution.asset_id == asset_id,
                ResponseExecution.status.in_(ACTIVE_EXECUTION_STATUSES),
            )
        )
        or 0
    )


def evaluate(
    action: ActionDefinition, ctx: ActionContext, *, count_active: bool = True
) -> Decision:
    settings: Settings = ctx.settings
    decision = Decision()
    block, warn, ok = (
        decision.blockers.append,
        decision.warnings.append,
        decision.preconditions.append,
    )

    if not settings.response_enabled:
        block(Issue("response_disabled", "Response is disabled on this server"))
    if not action.available:
        block(Issue("action_not_implemented", "This action is not available in this version"))
        return decision
    ok("action_allowlisted")

    asset = ctx.asset
    if action.target_type == "asset":
        if asset is None:
            block(Issue("target_missing", "The action needs an asset"))
            return decision
        if asset.is_archived and not action.allow_archived:
            block(Issue("asset_archived", "The asset is archived; restore it first"))
        elif asset.is_archived:
            warn(Issue("asset_archived", "The asset is archived; only evidence is read"))
        else:
            ok("asset_active")
        if ctx.detection is not None and ctx.detection.asset_id != asset.id:
            block(Issue("detection_mismatch", "The detection belongs to another asset"))
    elif ctx.incident is None:
        block(Issue("target_missing", "The action needs an incident"))
        return decision

    if action.requires_agent and asset is not None:
        _check_agent(action, asset, ctx.now, settings, decision)

    # Ejecución lanzada desde un caso: queda en su timeline, que no admite cambios si está
    # cerrado o fusionado.
    if (
        ctx.incident is not None
        and action.target_type == "asset"
        and is_frozen(ctx.incident.status)
    ):
        block(Issue("incident_closed", "The incident is closed or merged"))

    if action.precheck is not None:
        for issue in action.precheck(ctx):
            block(issue)

    if count_active and asset is not None:
        active = active_count(ctx.session, asset.id)
        if active >= settings.response_max_active_per_asset:
            block(Issue("too_many_active", "Too many active response executions for this asset"))

    if action.requires_confirmation:
        warn(Issue("confirmation_required", "This action changes data; confirm to execute"))
    return decision


def _check_agent(
    action: ActionDefinition, asset: Asset, now: datetime, settings: Settings, decision: Decision
) -> None:
    block, warn, ok = (
        decision.blockers.append,
        decision.warnings.append,
        decision.preconditions.append,
    )
    if asset.agent_id is None:
        block(Issue("no_agent", "The asset has no Sentra agent"))
        return
    if not credential_active(asset):
        # Revocado o sin credencial (p. ej. agente histórico tras una reconciliación): nunca
        # recibe comandos, ni siquiera en cola.
        block(Issue("agent_credential_inactive", "The agent has no active credential"))
        return
    platform = asset_platform(asset.os_name)
    if platform is None or platform not in action.supported_platforms:
        block(Issue("unsupported_platform", "The agent platform does not support this action"))
    else:
        ok(f"platform:{platform}")
    capabilities = set(asset.agent_capabilities or []) & AGENT_COMMAND_TYPES
    if asset.agent_capabilities is None:
        block(
            Issue(
                "agent_capabilities_unknown",
                "The agent has not reported response capabilities (update the agent)",
            )
        )
    elif action.agent_command not in capabilities:
        block(Issue("unsupported_capability", "The agent does not support this action"))
    else:
        ok(f"capability:{action.agent_command}")
    if agent_online(asset, now, timedelta(seconds=settings.heartbeat_timeout_seconds)):
        ok("agent_online")
    elif settings.response_offline_agent_policy == "queue":
        warn(
            Issue(
                "agent_offline_queued",
                f"The agent is offline; the command expires after"
                f" {settings.response_command_ttl_minutes} min if it does not connect",
            )
        )
    else:
        block(Issue("agent_offline", "The agent is offline"))
