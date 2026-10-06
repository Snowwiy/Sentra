"""Asset Context (Fase 4L): lectura, edición auditada, historial y resumen de amenaza.

Reglas que este módulo garantiza (ver docs/asset-context.md):
- solo la API escribe contexto y todo lo que entra es `manual`. La identificación 4E aporta
  una SUGERENCIA de rol calculada al leer; nunca se guarda encima de un valor confirmado,
  así que una heurística posterior no puede sobrescribir en silencio a un administrador;
- desconocido es desconocido: un activo sin fila de contexto se lee con todo "unknown" y
  nada de eso suma riesgo ni se presenta como amenaza;
- concurrencia optimista con `version` (409 asset_context_conflict), como incidentes 4K;
- una operación = un evento de auditoría con diff acotado + una fila de historial por campo.
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.core.exceptions import AssetContextConflictError, AssetTagLimitError, NotFoundError
from app.discovery.device_types import DeviceType
from app.models.asset import Asset, AssetCriticality, MonitoringMethod
from app.models.asset_context import (
    AssetBusinessContext,
    AssetContextChange,
    AssetEnvironment,
    AssetRole,
    AssetTag,
    ContextSource,
    DataSensitivity,
    NetworkZone,
)
from app.models.change import AssetChange, ChangeCategory
from app.models.detection import Detection, DetectionSeverity, DetectionStatus
from app.models.incident import ACTIVE_STATUSES, LEVEL_RANK, Incident, IncidentAsset
from app.models.risk import AssetRisk
from app.schemas.asset_context import (
    MAX_TAGS,
    AssetContextBrief,
    AssetContextChangeRead,
    AssetContextHistory,
    AssetContextOptions,
    AssetContextRead,
    AssetContextUpdate,
    AssetThreatSummary,
    ContextCompleteness,
    ContextLimits,
    FieldProvenance,
    ManagedState,
    RoleSuggestion,
    ThreatRisk,
)
from app.services import audit_service
from app.services.audit_service import Actor

# Etiquetas distintas en toda la plataforma: por encima, una etiqueta NUEVA se rechaza
# (las existentes se pueden seguir asignando). Evita que un script llene la tabla.
MAX_DISTINCT_TAGS = 500
# Valores devueltos en /assets/context/options para autocompletar.
OPTIONS_LIMIT = 100
# "Reciente" en el resumen de amenaza (cambios de exposición y de contexto).
THREAT_WINDOW = timedelta(days=7)
HISTORY_VALUE_MAX = 300

# Campos administrativos que cuentan para la completitud del contexto (calidad del
# inventario, nunca riesgo).
COMPLETENESS_FIELDS = (
    "criticality",
    "role",
    "environment",
    "owner",
    "department",
    "data_sensitivity",
    "network_zone",
    "internet_exposed",
)

# Campos que son entrada del Risk Engine: si cambian, se recalcula el riesgo del activo.
RISK_FIELDS = frozenset({"criticality", "environment", "data_sensitivity", "internet_exposed"})

# Acción de auditoría específica por campo. Si una operación toca campos de varias
# acciones, se registra UN evento asset_context_updated con el diff completo.
FIELD_ACTIONS = {
    "criticality": "asset_criticality_changed",
    "criticality_rationale": "asset_criticality_changed",
    "role": "asset_role_changed",
    "owner": "asset_owner_changed",
    "department": "asset_owner_changed",
    "environment": "asset_environment_changed",
    "data_sensitivity": "asset_data_sensitivity_changed",
    "network_zone": "asset_network_zone_changed",
    "internet_exposed": "asset_internet_exposure_changed",
    "tags": "asset_tags_changed",
}
CONTEXT_UPDATED = "asset_context_updated"

# Sugerencia de rol a partir del tipo identificado (4E). Solo correspondencias directas:
# un NAS o una consola no tienen un rol de la lista sin más evidencia, así que no sugieren
# nada. "server" como tipo es una deducción (puertos, SO); se presenta como sugerencia.
_ROLE_BY_TYPE: dict[str, AssetRole] = {
    DeviceType.PC.value: AssetRole.WORKSTATION,
    DeviceType.LAPTOP.value: AssetRole.WORKSTATION,
    DeviceType.SERVER.value: AssetRole.SERVER,
    DeviceType.MOBILE.value: AssetRole.MOBILE,
    DeviceType.TABLET.value: AssetRole.MOBILE,
    DeviceType.PRINTER.value: AssetRole.PRINTER,
    DeviceType.ROUTER.value: AssetRole.ROUTER,
    DeviceType.NETWORK_SWITCH.value: AssetRole.SWITCH,
    DeviceType.ACCESS_POINT.value: AssetRole.WIRELESS_AP,
    DeviceType.IOT.value: AssetRole.IOT,
    DeviceType.VOICE_ASSISTANT.value: AssetRole.IOT,
    DeviceType.SMART_TV.value: AssetRole.IOT,
    DeviceType.VIRTUAL_MACHINE.value: AssetRole.VIRTUAL_MACHINE,
}

_MANAGED_STATE: dict[MonitoringMethod, ManagedState] = {
    MonitoringMethod.DISCOVERED: "DISCOVERED",
    MonitoringMethod.AGENTLESS: "MONITORED",
    MonitoringMethod.AGENT: "MANAGED",
}


def _now() -> datetime:
    return datetime.now(UTC)


def managed_state(asset: Asset) -> ManagedState:
    return _MANAGED_STATE[asset.monitoring_method]


# --- Lecturas por lotes (sin N+1) --------------------------------------------------------------


def contexts_by_asset(
    session: Session, asset_ids: Iterable[int]
) -> dict[int, AssetBusinessContext]:
    ids = list(asset_ids)
    if not ids:
        return {}
    rows = session.scalars(
        select(AssetBusinessContext).where(AssetBusinessContext.asset_id.in_(ids))
    )
    return {row.asset_id: row for row in rows}


def tags_by_asset(session: Session, asset_ids: Iterable[int]) -> dict[int, list[str]]:
    ids = list(asset_ids)
    if not ids:
        return {}
    result: dict[int, list[str]] = {}
    for asset_id, tag in session.execute(
        select(AssetTag.asset_id, AssetTag.tag)
        .where(AssetTag.asset_id.in_(ids))
        .order_by(AssetTag.asset_id, AssetTag.tag)
    ):
        result.setdefault(asset_id, []).append(tag)
    return result


# --- Valores efectivos (fila ausente = todo unknown) -------------------------------------------


@dataclass(frozen=True)
class ContextValues:
    """Contexto efectivo de un activo; lo que consumen Risk, incidentes, IA y la API."""

    criticality: AssetCriticality
    criticality_confirmed: bool
    role: AssetRole
    environment: AssetEnvironment
    owner: str | None
    department: str | None
    data_sensitivity: DataSensitivity
    network_zone: NetworkZone
    internet_exposed: bool | None

    @classmethod
    def of(cls, asset: Asset, ctx: AssetBusinessContext | None) -> "ContextValues":
        return cls(
            criticality=asset.criticality,
            # La criticidad por defecto (medium, 4I) no está "confirmada"; cualquier otro
            # valor solo lo pudo fijar un administrador.
            criticality_confirmed=(
                asset.criticality != AssetCriticality.MEDIUM
                or (ctx is not None and ctx.criticality_updated_at is not None)
            ),
            role=ctx.role if ctx else AssetRole.UNKNOWN,
            environment=ctx.environment if ctx else AssetEnvironment.UNKNOWN,
            owner=ctx.owner if ctx else None,
            department=ctx.department if ctx else None,
            data_sensitivity=ctx.data_sensitivity if ctx else DataSensitivity.UNKNOWN,
            network_zone=ctx.network_zone if ctx else NetworkZone.UNKNOWN,
            internet_exposed=ctx.internet_exposed if ctx else None,
        )

    def known(self, field: str) -> bool:
        if field == "criticality":
            return self.criticality_confirmed
        value = getattr(self, field)
        return value is not None and value != "unknown"

    def completeness(self) -> ContextCompleteness:
        known = [f for f in COMPLETENESS_FIELDS if self.known(f)]
        missing = [f for f in COMPLETENESS_FIELDS if f not in known]
        return ContextCompleteness(
            percent=round(100 * len(known) / len(COMPLETENESS_FIELDS)),
            complete=not missing,
            known=known,
            missing=missing,
        )

    def brief(self) -> AssetContextBrief:
        return AssetContextBrief(
            criticality=self.criticality,
            role=self.role,
            environment=self.environment,
            owner=self.owner,
            department=self.department,
            data_sensitivity=self.data_sensitivity,
            network_zone=self.network_zone,
            internet_exposed=self.internet_exposed,
            context_complete=self.completeness().complete,
        )

    def snapshot(self, now: datetime) -> dict[str, Any]:
        """Contexto crítico para un incidente: sin responsable ni etiquetas (mínimo)."""
        return {
            "criticality": self.criticality.value,
            "role": self.role.value,
            "environment": self.environment.value,
            "data_sensitivity": self.data_sensitivity.value,
            "network_zone": self.network_zone.value,
            "internet_exposed": self.internet_exposed,
            "captured_at": now.isoformat(),
        }


def context_values(session: Session, assets: Sequence[Asset]) -> dict[int, ContextValues]:
    contexts = contexts_by_asset(session, (a.id for a in assets))
    return {a.id: ContextValues.of(a, contexts.get(a.id)) for a in assets}


def role_suggestion(asset: Asset, confirmed: AssetRole) -> RoleSuggestion | None:
    """Rol que sugiere la identificación 4E, aparte del confirmado (que siempre manda)."""
    suggested = _ROLE_BY_TYPE.get(asset.device_type or "")
    if suggested is None or suggested == confirmed:
        return None
    return RoleSuggestion(
        value=suggested,
        source=ContextSource.AGENT.value if asset.is_managed else ContextSource.DISCOVERY.value,
        confidence=asset.classification_confidence,
        reason=asset.device_type_reason,
    )


def _history_value(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list):
        return ",".join(str(v) for v in value)[:HISTORY_VALUE_MAX]
    return str(getattr(value, "value", value))[:HISTORY_VALUE_MAX]


def _audit_value(value: object) -> object:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, list):
        return [str(v) for v in value]
    return str(getattr(value, "value", value))


def _is_known(value: object) -> bool:
    return value is not None and value != "unknown" and value != []


@dataclass(frozen=True)
class ContextUpdateResult:
    asset: Asset
    changed: tuple[str, ...]

    @property
    def risk_relevant(self) -> bool:
        return bool(RISK_FIELDS.intersection(self.changed))


class AssetContextService:
    def __init__(self, session: Session) -> None:
        self._session = session

    # --- Lectura --------------------------------------------------------------------------------

    def _asset(self, public_id: UUID) -> Asset:
        asset = self._session.scalar(select(Asset).where(Asset.public_id == public_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def get(self, public_id: UUID) -> AssetContextRead:
        return self.read(self._asset(public_id))

    def read(self, asset: Asset) -> AssetContextRead:
        ctx = self._session.get(AssetBusinessContext, asset.id)
        values = ContextValues.of(asset, ctx)
        tags = tags_by_asset(self._session, [asset.id]).get(asset.id, [])
        provenance: dict[str, FieldProvenance] = {}
        for field, raw in ((ctx.provenance if ctx else None) or {}).items():
            if isinstance(raw, dict) and isinstance(raw.get("source"), str):
                provenance[str(field)] = FieldProvenance(
                    source=raw["source"],
                    kind="configured" if raw["source"] == ContextSource.MANUAL else "observed",
                    updated_at=raw.get("updated_at"),
                    updated_by=raw.get("updated_by"),
                )
        sources = []
        if asset.is_managed:
            sources.append(ContextSource.AGENT.value)
        if asset.discovered_at is not None:
            sources.append(ContextSource.DISCOVERY.value)
        if provenance or tags:
            sources.append(ContextSource.MANUAL.value)
        return AssetContextRead(
            asset_id=asset.public_id,
            version=ctx.version if ctx else 0,
            criticality=values.criticality,
            criticality_confirmed=values.criticality_confirmed,
            criticality_rationale=ctx.criticality_rationale if ctx else None,
            criticality_updated_at=ctx.criticality_updated_at if ctx else None,
            criticality_updated_by=ctx.criticality_updated_by if ctx else None,
            role=values.role,
            role_suggestion=role_suggestion(asset, values.role),
            environment=values.environment,
            owner=values.owner,
            department=values.department,
            data_sensitivity=values.data_sensitivity,
            network_zone=values.network_zone,
            internet_exposed=values.internet_exposed,
            tags=tags,
            managed_state=managed_state(asset),
            visibility_sources=sources,
            provenance=provenance,
            completeness=values.completeness(),
            updated_at=ctx.updated_at if ctx else None,
            updated_by=ctx.updated_by if ctx else None,
        )

    def history(self, public_id: UUID, limit: int, offset: int) -> AssetContextHistory:
        asset = self._asset(public_id)
        where = AssetContextChange.asset_id == asset.id
        total = (
            self._session.scalar(select(func.count()).select_from(AssetContextChange).where(where))
            or 0
        )
        rows = self._session.scalars(
            select(AssetContextChange)
            .where(where)
            .order_by(AssetContextChange.changed_at.desc(), AssetContextChange.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return AssetContextHistory(
            items=[AssetContextChangeRead.model_validate(r) for r in rows], total=total
        )

    def options(self) -> AssetContextOptions:
        departments = self._session.scalars(
            select(func.min(AssetBusinessContext.department))
            .where(AssetBusinessContext.department.is_not(None))
            .group_by(func.lower(AssetBusinessContext.department))
            .order_by(func.count().desc(), func.lower(AssetBusinessContext.department))
            .limit(OPTIONS_LIMIT)
        ).all()
        tags = self._session.scalars(
            select(AssetTag.tag)
            .group_by(AssetTag.tag)
            .order_by(func.count().desc(), AssetTag.tag)
            .limit(OPTIONS_LIMIT)
        ).all()
        return AssetContextOptions(
            criticality=list(AssetCriticality),
            role=list(AssetRole),
            environment=list(AssetEnvironment),
            data_sensitivity=list(DataSensitivity),
            network_zone=list(NetworkZone),
            departments=[d for d in departments if d],
            tags=list(tags),
            limits=ContextLimits(),
        )

    # --- Escritura ------------------------------------------------------------------------------

    def _lock_context(self, asset: Asset, now: datetime) -> AssetBusinessContext:
        """Fila de contexto bloqueada (FOR UPDATE), creándola si no existe.

        La fila se crea con version=0 ("sin contexto") y la CAS de `update` la deja en 1:
        dos administradores que editan a la vez un activo sin contexto se serializan aquí y
        el segundo recibe 409, igual que en un activo con contexto. Si la petición falla,
        el rollback deshace también la fila creada.
        """
        self._session.execute(
            insert(AssetBusinessContext)
            .values(asset_id=asset.id, version=0, updated_at=now)
            .on_conflict_do_nothing(index_elements=["asset_id"])
        )
        ctx = self._session.scalar(
            select(AssetBusinessContext)
            .where(AssetBusinessContext.asset_id == asset.id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        assert ctx is not None  # noqa: S101  (se acaba de insertar o ya existía)
        return ctx

    def _check_version(self, asset: Asset, ctx: AssetBusinessContext, version: int) -> None:
        if ctx.version != version:
            raise AssetContextConflictError(
                "The asset context was changed by someone else; reload it and try again",
                details=[
                    {
                        "asset_id": str(asset.public_id),
                        "current_version": ctx.version,
                        "updated_at": ctx.updated_at.isoformat() if ctx.updated_at else None,
                        "updated_by": ctx.updated_by,
                    }
                ],
            )

    def _check_tag_budget(self, added: set[str]) -> None:
        if not added:
            return
        existing = set(
            self._session.scalars(select(AssetTag.tag).where(AssetTag.tag.in_(added)).distinct())
        )
        new = len(added - existing)
        if not new:
            return
        distinct = self._session.scalar(select(func.count(func.distinct(AssetTag.tag)))) or 0
        if distinct + new > MAX_DISTINCT_TAGS:
            raise AssetTagLimitError(
                f"The platform already has {distinct} distinct tags (limit "
                f"{MAX_DISTINCT_TAGS}); reuse an existing tag"
            )

    def update(
        self, public_id: UUID, payload: AssetContextUpdate, actor: Actor
    ) -> ContextUpdateResult:
        """Aplica un PATCH parcial con CAS sobre `version`. No hace commit."""
        asset = self._session.scalar(
            select(Asset).where(Asset.public_id == public_id).with_for_update()
        )
        if asset is None:
            raise NotFoundError("Asset not found")
        now = _now()
        ctx = self._lock_context(asset, now)
        self._check_version(asset, ctx, payload.version)

        current_tags = tags_by_asset(self._session, [asset.id]).get(asset.id, [])
        before: dict[str, Any] = {
            "criticality": asset.criticality,
            "criticality_rationale": ctx.criticality_rationale,
            "role": ctx.role,
            "environment": ctx.environment,
            "owner": ctx.owner,
            "department": ctx.department,
            "data_sensitivity": ctx.data_sensitivity,
            "network_zone": ctx.network_zone,
            "internet_exposed": ctx.internet_exposed,
            "tags": current_tags,
        }
        requested = payload.model_dump(include=payload.model_fields_set - {"version"})
        changes: list[tuple[str, Any, Any]] = []
        for field, new in requested.items():
            old = before[field]
            if field == "tags":
                if set(new) == set(old):
                    continue
            elif old == new:
                continue
            changes.append((field, old, new))
        if not changes:
            # Nada cambia: ni versión, ni auditoría, ni historial (idempotente).
            return ContextUpdateResult(asset, ())

        provenance = dict(ctx.provenance or {})
        stamp = {
            "source": ContextSource.MANUAL.value,
            "updated_at": now.isoformat(),
            "updated_by": actor.name[:64],
        }
        for field, _old, new in changes:
            if field == "criticality":
                asset.criticality = new
                ctx.criticality_updated_at = now
                ctx.criticality_updated_by = actor.name[:64]
            elif field == "tags":
                self._replace_tags(asset.id, set(current_tags), set(new), now)
            else:
                setattr(ctx, field, new)
            # Procedencia solo de los valores conocidos: volver a "unknown" la elimina.
            if _is_known(new):
                provenance[field] = stamp
            else:
                provenance.pop(field, None)
            self._session.add(
                AssetContextChange(
                    asset_id=asset.id,
                    changed_at=now,
                    field=field,
                    old_value=_history_value(_old),
                    new_value=_history_value(new),
                    source=ContextSource.MANUAL.value,
                    actor=actor.name[:64],
                    actor_user_id=actor.user_id,
                )
            )
        ctx.provenance = provenance or None
        ctx.version += 1
        ctx.updated_at = now
        ctx.updated_by = actor.name[:64]
        ctx.updated_by_user_id = actor.user_id

        fields = tuple(field for field, _, _ in changes)
        actions = {FIELD_ACTIONS[f] for f in fields}
        audit_service.record(
            self._session,
            actor,
            actions.pop() if len(actions) == 1 else CONTEXT_UPDATED,
            target_type="asset",
            target_id=asset.public_id,
            details={
                "fields": list(fields),
                "changes": [
                    {"field": f, "from": _audit_value(o), "to": _audit_value(n)}
                    for f, o, n in changes
                ],
                "version": ctx.version,
            },
            commit=False,
        )
        self._session.flush()
        return ContextUpdateResult(asset, fields)

    def _replace_tags(self, asset_id: int, old: set[str], new: set[str], now: datetime) -> None:
        removed, added = old - new, new - old
        self._check_tag_budget(added)
        if removed:
            self._session.execute(
                delete(AssetTag).where(AssetTag.asset_id == asset_id, AssetTag.tag.in_(removed))
            )
        for tag in sorted(added):
            self._session.add(AssetTag(asset_id=asset_id, tag=tag, created_at=now))

    def record_criticality(self, asset: Asset, previous: AssetCriticality, actor: Actor) -> None:
        """Criticidad cambiada por PATCH /assets/{id}/criticality (ruta de 4I).

        Mantiene la misma trazabilidad que el PATCH de contexto (quién, cuándo, historial,
        procedencia) e incrementa `version`: un editor de contexto con una versión anterior
        recibe 409 en lugar de devolver la criticidad a su valor viejo sin saberlo.
        """
        if previous == asset.criticality:
            return
        now = _now()
        ctx = self._lock_context(asset, now)
        ctx.criticality_updated_at = now
        ctx.criticality_updated_by = actor.name[:64]
        provenance = dict(ctx.provenance or {})
        provenance["criticality"] = {
            "source": ContextSource.MANUAL.value,
            "updated_at": now.isoformat(),
            "updated_by": actor.name[:64],
        }
        ctx.provenance = provenance
        ctx.version += 1
        ctx.updated_at = now
        ctx.updated_by = actor.name[:64]
        ctx.updated_by_user_id = actor.user_id
        self._session.add(
            AssetContextChange(
                asset_id=asset.id,
                changed_at=now,
                field="criticality",
                old_value=previous.value,
                new_value=asset.criticality.value,
                source=ContextSource.MANUAL.value,
                actor=actor.name[:64],
                actor_user_id=actor.user_id,
            )
        )

    # --- Resumen de amenaza interno ---------------------------------------------------------------

    def threat_summary(self, public_id: UUID) -> AssetThreatSummary:
        """Contexto de amenaza calculado de entidades existentes (nada se persiste)."""
        asset = self._asset(public_id)
        now = _now()
        since = now - THREAT_WINDOW
        active = Detection.status.in_((DetectionStatus.OPEN, DetectionStatus.ACKNOWLEDGED))
        severe = Detection.severity.in_((DetectionSeverity.HIGH, DetectionSeverity.CRITICAL))
        det = self._session.execute(
            select(
                func.count().filter(active),
                func.count().filter(active, severe),
                func.max(Detection.last_seen_at),
            ).where(Detection.asset_id == asset.id)
        ).one()
        incidents = self._session.execute(
            select(Incident.severity, func.max(Incident.last_activity_at))
            .join(IncidentAsset, IncidentAsset.incident_id == Incident.id)
            .where(IncidentAsset.asset_id == asset.id, Incident.status.in_(ACTIVE_STATUSES))
            .group_by(Incident.id, Incident.severity)
        ).all()
        highest = max((row[0] for row in incidents), key=LEVEL_RANK.__getitem__, default=None)
        exposure = self._session.execute(
            select(func.count(), func.max(AssetChange.detected_at)).where(
                AssetChange.asset_id == asset.id,
                AssetChange.category == ChangeCategory.EXPOSURE,
                AssetChange.detected_at >= since,
            )
        ).one()
        context_changes = (
            self._session.scalar(
                select(func.count())
                .select_from(AssetContextChange)
                .where(
                    AssetContextChange.asset_id == asset.id,
                    AssetContextChange.changed_at >= since,
                )
            )
            or 0
        )
        risk = self._session.get(AssetRisk, asset.id)
        activity = [det[2], exposure[1], *(row[1] for row in incidents)]
        ctx = self._session.get(AssetBusinessContext, asset.id)
        return AssetThreatSummary(
            asset_id=asset.public_id,
            window_days=THREAT_WINDOW.days,
            active_detection_count=det[0] or 0,
            high_critical_detection_count=det[1] or 0,
            open_incident_count=len(incidents),
            highest_incident_severity=highest.value if highest else None,
            current_risk=(
                ThreatRisk(
                    score=risk.score,
                    level=risk.level.value,
                    confidence=risk.confidence.value,
                    calculated_at=risk.calculated_at,
                )
                if risk is not None and risk.calculated_at is not None
                else None
            ),
            recent_exposure_changes=exposure[0] or 0,
            recent_context_changes=context_changes,
            last_security_activity=max((t for t in activity if t is not None), default=None),
            criticality=asset.criticality,
            environment=ctx.environment if ctx else AssetEnvironment.UNKNOWN,
            managed_state=managed_state(asset),
        )


# --- Fusión de activos (reconciliación discovery -> agente) -------------------------------------


def merge_context(session: Session, *, source: Asset, target: Asset) -> None:
    """Conserva el contexto del activo descubierto al fusionarlo con el del agente.

    Por campo: el valor conocido del activo superviviente (target) manda; si allí es
    desconocido, se toma el del descubierto. Etiquetas: unión hasta el límite por activo.
    El historial se mueve al superviviente. Se llama antes de borrar `source`.
    """
    contexts = contexts_by_asset(session, [source.id, target.id])
    src, dst = contexts.get(source.id), contexts.get(target.id)
    if src is not None:
        if dst is None:
            # Sin contexto en el destino: la fila entera cambia de dueño (conserva versión).
            src.asset_id = target.id
        else:
            provenance = dict(dst.provenance or {})
            for field in (
                "role",
                "environment",
                "owner",
                "department",
                "data_sensitivity",
                "network_zone",
                "internet_exposed",
            ):
                if not _is_known(getattr(dst, field)) and _is_known(getattr(src, field)):
                    setattr(dst, field, getattr(src, field))
                    if field in (src.provenance or {}):
                        provenance[field] = (src.provenance or {})[field]
            if dst.criticality_rationale is None and src.criticality_rationale:
                dst.criticality_rationale = src.criticality_rationale
            dst.provenance = provenance or None
            dst.version += 1
            session.delete(src)
    tags = tags_by_asset(session, [source.id, target.id])
    keep = set(tags.get(target.id, []))
    for tag in tags.get(source.id, []):
        if tag not in keep and len(keep) < MAX_TAGS:
            keep.add(tag)
            session.add(AssetTag(asset_id=target.id, tag=tag, created_at=_now()))
    session.execute(delete(AssetTag).where(AssetTag.asset_id == source.id))
    session.execute(
        update(AssetContextChange)
        .where(AssetContextChange.asset_id == source.id)
        .values(asset_id=target.id)
    )
    session.flush()


def filter_statement(
    stmt: Select[Asset],
    *,
    role: AssetRole | None = None,
    environment: AssetEnvironment | None = None,
    network_zone: NetworkZone | None = None,
    data_sensitivity: DataSensitivity | None = None,
    internet_exposed: str | None = None,
    department: str | None = None,
    tag: str | None = None,
) -> Select[Asset]:
    """Añade al SELECT de activos los filtros de contexto (en SQL, no en Python).

    "unknown" incluye a los activos sin fila de contexto: para Sentra son lo mismo.
    """
    ctx = AssetBusinessContext
    needs_join = any(
        v is not None
        for v in (role, environment, network_zone, data_sensitivity, internet_exposed, department)
    )
    if needs_join:
        stmt = stmt.outerjoin(ctx, ctx.asset_id == Asset.id)
    for column, value, unknown in (
        (ctx.role, role, AssetRole.UNKNOWN),
        (ctx.environment, environment, AssetEnvironment.UNKNOWN),
        (ctx.network_zone, network_zone, NetworkZone.UNKNOWN),
        (ctx.data_sensitivity, data_sensitivity, DataSensitivity.UNKNOWN),
    ):
        if value is None:
            continue
        if value == unknown:
            stmt = stmt.where((column.is_(None)) | (column == value))
        else:
            stmt = stmt.where(column == value)
    if internet_exposed == "unknown":
        stmt = stmt.where(ctx.internet_exposed.is_(None))
    elif internet_exposed in ("true", "false"):
        stmt = stmt.where(ctx.internet_exposed.is_(internet_exposed == "true"))
    if department is not None:
        stmt = stmt.where(func.lower(ctx.department) == department.lower())
    if tag is not None:
        stmt = stmt.where(
            select(AssetTag.asset_id)
            .where(AssetTag.asset_id == Asset.id, AssetTag.tag == tag)
            .exists()
        )
    return stmt
