"""Ciclo de vida de activos (Fases 5C.1 y 5C.2): archivar, restaurar, borrar, limpieza,
duplicados y reconciliación.

Conceptos (docs/agent-asset-lifecycle.md):
- la credencial del agente (token, revocación) NO es el activo: revocar nunca archiva ni
  borra nada;
- un activo que tuvo agente (Managed) nunca se borra físicamente: se archiva y conserva todo
  su historial;
- solo un descubierto sin historial que conservar Y que cumplió la política de inactividad
  (asset_lifecycle_policy.py) puede borrarse. La decisión sale de un único sitio,
  `hard_delete_decision`, que usan el check de la UI, DELETE, el preview de limpieza, el
  ejecutor (manual y automático) y la disposición del origen de una reconciliación. El
  servidor la repite dentro de la transacción del borrado con la fila bloqueada (sin TOCTOU);
- los duplicados se SUGIEREN con evidencia y confianza; nada se fusiona solo por hostname o
  IP. Reconciliar mueve el agente nuevo al activo histórico (reassign, no merge universal),
  deja constancia del linaje de agentes y archiva el activo sobrante, que conserva lo que el
  agente nuevo llegó a enviar.

Toda acción de escritura usa concurrencia optimista (`lifecycle_version`) y bloquea las filas
afectadas con FOR UPDATE antes de comprobar nada.
"""

import logging
import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select, text
from sqlalchemy.orm import Session

from app.core.exceptions import (
    AssetLifecycleConflictError,
    AssetNotDeletableError,
    AssetReconcileRefusedError,
    AssetStateError,
    NotFoundError,
)
from app.models.asset import Asset, AssetStatus, MonitoringMethod
from app.models.asset_lineage import AssetAgentLineage, LineageEndReason
from app.models.inventory import AssetInventory
from app.repositories.asset_repository import AssetRepository
from app.risk.queue import request_recalculation
from app.schemas.agent_management import CredentialStatus
from app.schemas.asset_lifecycle import (
    AssetDeleteCheck,
    CleanupCandidate,
    CleanupItem,
    CleanupItemResult,
    CleanupResult,
    DuplicateAsset,
    DuplicateCandidate,
    DuplicateEvidence,
    DuplicatePair,
    DuplicatePairList,
    ReconcilePreview,
)
from app.services import audit_service
from app.services.agent_management_service import agent_platform, credential_status
from app.services.asset_lifecycle_policy import (
    CleanupAction,
    LifecyclePolicy,
    LifecycleSource,
    LifecycleState,
    LifecycleView,
    cleanup_action,
    evaluate,
    has_managed_history,
    stale_condition,
)
from app.services.asset_service import effective_status
from app.services.audit_service import Actor
from app.services.reconciliation import adopt_label, interface_identity
from app.vulnerabilities.queue import mark_dirty

logger = logging.getLogger(__name__)

# Los recuentos de dependencias se cortan aquí: para decidir basta con saber que hay alguna
# y para la UI "10000" ya dice "mucho". Así un activo con millones de muestras de telemetría
# no convierte el check en un recorrido entero de la tabla.
COUNT_CAP = 10_000

# Dependencias que impiden el borrado físico, por motivo: nombre → fragmento FROM/WHERE con
# {id} como el id del activo. Cada una se cuenta con un subselect acotado (LIMIT COUNT_CAP)
# sobre columnas indexadas (test_every_foreign_key_is_indexed), para un activo o para un lote
# entero en UNA consulta (sin N+1).
# Detecciones "relevantes": impacto medio o superior. Las de bajo impacto de un dispositivo
# descubierto (NET-003 "dispositivo nuevo", NET-004 "desaparecido") hablan del propio
# fantasma y se borran con él; se muestran en `removes`, nunca en silencio.
_BLOCKING: dict[str, dict[str, str]] = {
    "agent_history": {
        "telemetry_samples": "telemetry_samples WHERE asset_id = {id}",
        "system_events": "system_events WHERE asset_id = {id}",
        "asset_inventories": "asset_inventories WHERE asset_id = {id}",
        "asset_process_snapshots": "asset_process_snapshots WHERE asset_id = {id}",
        "agent_enrollment_tokens": "agent_enrollment_tokens WHERE last_asset_id = {id}",
        # Fase 5C.2: agentes que informaron en este activo y ya no (reconciliación).
        "asset_agent_lineage": "asset_agent_lineage WHERE asset_id = {id}",
    },
    "detections": {
        "detections": (
            "detections WHERE asset_id = {id} AND severity IN ('medium', 'high', 'critical')"
        ),
    },
    "incidents": {
        "incident_assets": "incident_assets WHERE asset_id = {id}",
        "incident_detections": (
            "incident_detections i JOIN detections d ON d.id = i.detection_id"
            " WHERE d.asset_id = {id}"
        ),
        "incident_alerts": (
            "incident_alerts i JOIN alerts a ON a.id = i.alert_id WHERE a.asset_id = {id}"
        ),
    },
    "vulnerabilities": {
        "vulnerability_findings": "vulnerability_findings WHERE asset_id = {id}",
    },
    "threat_intel": {
        "threat_intel_matches": "threat_intel_matches WHERE asset_id = {id}",
    },
    "audit_dependency": {
        # Historial de contexto editado por un admin (4L) y análisis de IA (4J): son registros
        # de decisiones humanas sobre este activo.
        "asset_context_changes": "asset_context_changes WHERE asset_id = {id}",
        "ai_insights": "ai_insights WHERE asset_id = {id}",
    },
    "other": {
        # Una alerta sin resolver es trabajo pendiente de alguien: primero se resuelve.
        # Excepción (5C.2): "asset_disappeared" habla de la propia desaparición del
        # descubierto, justo lo que justifica limpiarlo; se borra con él y se muestra en
        # `removes`. Si no, ningún dispositivo desaparecido llegaría nunca a ser borrable.
        "active_alerts": (
            "alerts WHERE asset_id = {id} AND status <> 'resolved' AND rule <> 'asset_disappeared'"
        ),
    },
}

# Lo que desaparece con el activo (ON DELETE CASCADE), para mostrarlo antes de confirmar.
_REMOVES: dict[str, str] = {
    "ports": "asset_ports WHERE asset_id = {id}",
    "changes": "asset_changes WHERE asset_id = {id}",
    "detections": "detections WHERE asset_id = {id}",
    "alerts": "alerts WHERE asset_id = {id}",
    "risk_snapshots": "risk_snapshots WHERE asset_id = {id}",
}

# Historial que conserva cada parte de una reconciliación (preview de impacto).
_HISTORY: dict[str, str] = {
    "telemetry_samples": "telemetry_samples WHERE asset_id = {id}",
    "system_events": "system_events WHERE asset_id = {id}",
    "asset_inventories": "asset_inventories WHERE asset_id = {id}",
    "asset_process_snapshots": "asset_process_snapshots WHERE asset_id = {id}",
    "detections": "detections WHERE asset_id = {id}",
    "alerts": "alerts WHERE asset_id = {id}",
    "risk_snapshots": "risk_snapshots WHERE asset_id = {id}",
    "vulnerability_findings": "vulnerability_findings WHERE asset_id = {id}",
    "threat_intel_matches": "threat_intel_matches WHERE asset_id = {id}",
    "incident_assets": "incident_assets WHERE asset_id = {id}",
    "asset_changes": "asset_changes WHERE asset_id = {id}",
    "asset_context_changes": "asset_context_changes WHERE asset_id = {id}",
    "asset_agent_lineage": "asset_agent_lineage WHERE asset_id = {id}",
}

# Sugerencias por activo y por listado global: acotadas para no recorrer la flota entera.
MAX_CANDIDATES = 20
MAX_PAIRS = 200
# Preview de limpieza: se evalúan como mucho estos candidatos (más antiguos primero), en
# lotes de una consulta cada uno. Con más, el admin limpia y vuelve a pedir el preview.
MAX_PREVIEW_SCAN = 10_000
_PREVIEW_BATCH = 500

# Fuerza de cada señal de duplicado (docs/agent-asset-lifecycle.md, "Duplicados").
_STRENGTH: dict[str, str] = {
    "same_machine_id": "strong",
    "same_agent_lineage": "strong",
    "same_mac": "medium",
    "same_hostname": "weak",
    "same_ip": "weak",
    "same_random_mac": "weak",
    "same_os": "weak",
}
# Avisos que un admin puede aceptar; el resto de motivos bloquean siempre.
_WARNINGS = ("machine_id_mismatch", "insufficient_evidence")


def _bounded_counts(
    session: Session, queries: dict[str, str], asset_ids: Sequence[int]
) -> dict[int, dict[str, int]]:
    """Recuentos acotados por activo y dependencia en una sola consulta (lote de ids).

    Los fragmentos son constantes de este módulo: nunca llevan datos del usuario (los ids
    van como parámetro tipado).
    """
    if not asset_ids or not queries:
        return {}
    names = list(queries)
    columns = ", ".join(
        f"(SELECT count(*) FROM (SELECT 1 FROM {queries[name].format(id='ids.id')}"  # noqa: S608
        f" LIMIT {COUNT_CAP}) AS s) AS c{index}"
        for index, name in enumerate(names)
    )
    sql = f"SELECT ids.id, {columns} FROM unnest(CAST(:ids AS bigint[])) AS ids(id)"  # noqa: S608
    found: dict[int, dict[str, int]] = {}
    for row in session.execute(text(sql), {"ids": list(asset_ids)}):
        counts = {name: int(row[i + 1]) for i, name in enumerate(names) if row[i + 1]}
        found[int(row[0])] = counts
    return found


@dataclass
class DeleteDecision:
    """Decisión única de borrado físico de un activo (y acción de limpieza asociada)."""

    view: LifecycleView
    action: CleanupAction
    reasons: list[str]
    dependencies: dict[str, int]

    @property
    def can_hard_delete(self) -> bool:
        return self.action is CleanupAction.HARD_DELETE_ELIGIBLE


@dataclass
class Assessment:
    """Evidencia de que dos activos son la misma máquina y si se pueden reconciliar."""

    reasons: list[str] = field(default_factory=list)
    confidence: str | None = None
    conflicts: list[str] = field(default_factory=list)
    # Bloqueos duros: impiden reconciliar siempre.
    blockers: list[str] = field(default_factory=list)
    # Avisos: reconciliable solo si un admin los acepta (acknowledge_weak_evidence).
    warnings: list[str] = field(default_factory=list)

    @property
    def reconcilable(self) -> bool:
        return not self.blockers

    @property
    def requires_acknowledgement(self) -> bool:
        return self.reconcilable and bool(self.warnings)

    @property
    def evidence(self) -> list[DuplicateEvidence]:
        return [DuplicateEvidence(code=r, strength=_STRENGTH[r]) for r in self.reasons]


@dataclass(frozen=True)
class _Identity:
    hostname: str | None
    ips: frozenset[str]
    # MACs universales (asignadas por el fabricante) y administradas localmente (aleatorias:
    # Windows/Android/iOS las rotan por red, así que coinciden por casualidad o cambian).
    macs: frozenset[str]
    random_macs: frozenset[str]
    # Agentes que este activo tuvo o tiene (assets.agent_id + linaje).
    agents: frozenset[UUID]


def _is_random_mac(mac: str) -> bool:
    # Bit "locally administered" del primer octeto.
    return bool(int(mac[:2], 16) & 0x02)


def _identity(asset: Asset, interfaces: Any = None, lineage: Iterable[UUID] = ()) -> _Identity:
    ips, macs = interface_identity(interfaces) if interfaces else (set(), set())
    ips.add(asset.primary_ip)
    if asset.mac_address:
        macs.add(asset.mac_address)
    hostname = (asset.hostname or "").strip().lower() or None
    agents = set(lineage)
    if asset.agent_id is not None:
        agents.add(asset.agent_id)
    return _Identity(
        hostname,
        frozenset(ips),
        frozenset(m for m in macs if not _is_random_mac(m)),
        frozenset(m for m in macs if _is_random_mac(m)),
        frozenset(agents),
    )


def _platform(asset: Asset) -> str | None:
    if asset.os_name:
        return agent_platform(asset.os_name)
    return None


def credential_active(asset: Asset) -> bool:
    return asset.agent_id is not None and credential_status(asset) == CredentialStatus.ACTIVE


def assess(
    source: Asset,
    target: Asset,
    source_id: _Identity,
    target_id: _Identity,
    *,
    target_online: bool,
) -> Assessment:
    """¿`source` (agente nuevo) y `target` (activo histórico) son la misma máquina?

    Confianza (solo con la evidencia que realmente se comparó):
    - high: misma identidad de máquina (machine_id_hash) o linaje de agente compartido;
    - medium: misma MAC universal;
    - low: solo señales débiles (hostname, IP, MAC aleatoria, mismo SO), o identidades de
      máquina distintas (conflicto: equipos con el mismo nombre, VM clonada... o una
      reinstalación de Windows, que genera un MachineGuid nuevo).
    Nada se reconcilia solo. Con confianza baja o con conflicto, un admin puede reconciliar
    igualmente aceptando los avisos de forma explícita (caso real de reinstalación).
    """
    result = Assessment()
    if source.machine_id_hash and target.machine_id_hash:
        if source.machine_id_hash == target.machine_id_hash:
            result.reasons.append("same_machine_id")
        else:
            result.conflicts.append("machine_id_mismatch")
    if source_id.agents & target_id.agents:
        result.reasons.append("same_agent_lineage")
    if source_id.hostname and source_id.hostname == target_id.hostname:
        result.reasons.append("same_hostname")
    if source_id.ips & target_id.ips:
        result.reasons.append("same_ip")
    if source_id.macs & target_id.macs:
        result.reasons.append("same_mac")
    elif (source_id.random_macs | source_id.macs) & (target_id.random_macs | target_id.macs):
        result.reasons.append("same_random_mac")
    platforms = {_platform(source), _platform(target)} - {None}
    if result.reasons and len(platforms) == 1 and _platform(source) and _platform(target):
        # Señal de apoyo: el mismo SO solo no hace candidato a nadie.
        result.reasons.append("same_os")

    strengths = {_STRENGTH[r] for r in result.reasons}
    if not result.reasons:
        result.confidence = None
    elif result.conflicts:
        result.confidence = "low"
    elif "strong" in strengths:
        result.confidence = "high"
    elif "medium" in strengths:
        result.confidence = "medium"
    else:
        result.confidence = "low"

    if source.id == target.id:
        result.blockers.append("same_asset")
    if source.agent_id is None:
        result.blockers.append("source_without_agent")
    if source.archived_at is not None:
        result.blockers.append("source_archived")
    if not has_managed_history(target):
        # Un activo solo descubierto no tiene historial de agente que conservar: se resuelve
        # con la fusión automática de discovery, o borrándolo/archivándolo.
        result.blockers.append("target_never_managed")
    if target.agent_id is not None and credential_active(target) and target_online:
        # Dos agentes vivos a la vez no son una reinstalación (¿VM clonada?): nunca se toca.
        result.blockers.append("target_agent_online")
    if len(platforms) > 1:
        result.blockers.append("platform_mismatch")
    if source.site_id != target.site_id:
        # Fase 5F: nunca se reconcilia entre sites (misma IP o MAC en otra sede no prueba que
        # sea el mismo equipo). Si de verdad se trasladó, un admin lo mueve de site antes.
        result.blockers.append("different_site")
    if "machine_id_mismatch" in result.conflicts:
        result.warnings.append("machine_id_mismatch")
    if result.confidence not in ("high", "medium"):
        result.warnings.append("insufficient_evidence")
    return result


class AssetLifecycleService:
    def __init__(
        self,
        session: Session,
        heartbeat_timeout: timedelta,
        policy: LifecyclePolicy | None = None,
    ) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._timeout = heartbeat_timeout
        self._policy = policy or LifecyclePolicy()

    @property
    def policy(self) -> LifecyclePolicy:
        return self._policy

    # --- Lectura ------------------------------------------------------------------------------

    def _get(self, public_id: UUID, *, lock: bool = False) -> Asset:
        stmt = select(Asset).where(Asset.public_id == public_id)
        if lock:
            stmt = stmt.with_for_update()
        asset = self._session.scalar(stmt)
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _counts(self, queries: dict[str, str], asset_id: int) -> dict[str, int]:
        return _bounded_counts(self._session, queries, [asset_id]).get(asset_id, {})

    def _history_blockers(
        self, asset_ids: Sequence[int]
    ) -> dict[int, tuple[list[str], dict[str, int]]]:
        """Motivos por historial y recuentos de varios activos en una consulta."""
        flat = {name: sql for group in _BLOCKING.values() for name, sql in group.items()}
        counts = _bounded_counts(self._session, flat, asset_ids)
        found: dict[int, tuple[list[str], dict[str, int]]] = {}
        for asset_id in asset_ids:
            mine = counts.get(asset_id, {})
            reasons = [
                reason for reason, group in _BLOCKING.items() if any(n in mine for n in group)
            ]
            found[asset_id] = (reasons, mine)
        return found

    def _online(self, asset: Asset, now: datetime) -> bool:
        return effective_status(asset, now, self._timeout) == AssetStatus.ONLINE

    def view(self, asset: Asset, now: datetime) -> LifecycleView:
        return evaluate(asset, now, self._policy, online=self._online(asset, now))

    def hard_delete_decision(
        self, asset: Asset, now: datetime, history: tuple[list[str], dict[str, int]] | None = None
    ) -> DeleteDecision:
        """FUENTE ÚNICA de CAN_HARD_DELETE / CANNOT_HARD_DELETE + motivos.

        Combina la política de ciclo de vida (tiempo, scans perdidos, origen del activo) con
        las dependencias que obligan a conservar el activo. Para ejecutar un borrado se llama
        con la fila ya bloqueada (FOR UPDATE), dentro de la transacción que borra.
        """
        view = self.view(asset, now)
        reasons, dependencies = history or self._history_blockers([asset.id])[asset.id]
        if has_managed_history(asset):
            reasons = ["managed_history", *reasons]
        action, all_reasons = cleanup_action(
            view, reasons, credential_active=credential_active(asset)
        )
        return DeleteDecision(view, action, all_reasons, dependencies)

    def delete_check(self, public_id: UUID) -> AssetDeleteCheck:
        asset = self._get(public_id)
        now = datetime.now(UTC)
        decision = self.hard_delete_decision(asset, now)
        return AssetDeleteCheck(
            asset_id=asset.public_id,
            deletable=decision.can_hard_delete,
            # "agent_active" es de la acción de limpieza, no un motivo de borrado.
            blocking_reasons=[r for r in decision.reasons if r != "agent_active"],
            dependencies=decision.dependencies,
            removes=self._counts(_REMOVES, asset.id),
            can_archive=asset.archived_at is None and not credential_active(asset),
            version=asset.lifecycle_version,
            display_name=asset.display_name,
            hostname=asset.hostname,
            primary_ip=asset.primary_ip,
            mac_address=asset.mac_address,
            monitoring_method=asset.monitoring_method,
            last_seen_at=asset.last_seen_at or asset.last_network_seen_at,
            lifecycle_state=decision.view.state.value,
            missed_discovery_scans=asset.network_misses or 0,
            last_activity_at=decision.view.last_activity_at,
        )

    # --- Archivar / restaurar ------------------------------------------------------------------

    @staticmethod
    def _check_version(asset: Asset, version: int) -> None:
        if asset.lifecycle_version != version:
            raise AssetLifecycleConflictError(
                "The asset changed since it was loaded",
                details=[{"version": asset.lifecycle_version, "archived": asset.is_archived}],
            )

    @staticmethod
    def _mark_archived(asset: Asset, by: str, reason: str) -> None:
        asset.archived_at = datetime.now(UTC)
        asset.archived_by = by[:64]
        asset.archive_reason = " ".join(reason.split())[:500]
        asset.lifecycle_version += 1

    def archive(self, public_id: UUID, reason: str, version: int, actor: Actor) -> Asset:
        """Archiva el activo: oculto por defecto, fuera del resumen, con todo su historial.

        Un agente con credencial activa debe revocarse antes: si no, seguiría enviando datos
        a un activo que nadie ve. Revocar no archiva; archivar no revoca: son dos decisiones.
        """
        asset = self._get(public_id, lock=True)
        self._check_version(asset, version)
        if asset.archived_at is not None:
            raise AssetStateError("The asset is already archived")
        if credential_active(asset):
            raise AssetStateError(
                "Revoke the agent before archiving its asset",
                details=[{"reason": "agent_active"}],
            )
        self._mark_archived(asset, actor.name, reason)
        self._session.flush()
        return asset

    def restore(self, public_id: UUID, version: int) -> Asset:
        """Vuelve a mostrar el activo. NO reactiva la credencial del agente (revocada sigue
        revocada): eso es una decisión aparte en Agentes."""
        asset = self._get(public_id, lock=True)
        self._check_version(asset, version)
        if asset.archived_at is None:
            raise AssetStateError("The asset is not archived")
        asset.archived_at = None
        asset.archived_by = None
        asset.archive_reason = None
        asset.lifecycle_version += 1
        # Vuelve a contar en el riesgo actual: se recalcula con los datos que tenga.
        request_recalculation(self._session, [asset.id])
        self._session.flush()
        return asset

    # --- Borrado ------------------------------------------------------------------------------

    def _hard_delete(self, asset: Asset) -> dict[str, Any]:
        summary = {
            "display_name": asset.display_name,
            "primary_ip": asset.primary_ip,
            "mac_address": asset.mac_address,
            "removed": self._counts(_REMOVES, asset.id),
        }
        # Core DELETE: las tablas hijas (puertos, cambios, detecciones de bajo impacto...) se
        # borran por ON DELETE CASCADE; las que deben sobrevivir ya bloquearon antes.
        self._session.execute(delete(Asset).where(Asset.id == asset.id))
        self._session.flush()
        return summary

    def delete(self, public_id: UUID, version: int) -> dict[str, Any]:
        """Borra físicamente un descubierto elegible (hard_delete_decision). No hace commit.

        Evita TOCTOU: la fila del activo se bloquea (FOR UPDATE) ANTES de recalcular la
        decisión. Cualquier inserción concurrente que referencie el activo (un finding, un
        match, un incidente) toma FOR KEY SHARE sobre la misma fila: o terminó antes y la
        vemos aquí, o espera a este borrado y falla por la clave foránea. Discovery y los
        heartbeats actualizan la misma fila: si lo vieron justo antes, deja de ser stale.
        """
        asset = self._get(public_id, lock=True)
        self._check_version(asset, version)
        decision = self.hard_delete_decision(asset, datetime.now(UTC))
        if not decision.can_hard_delete:
            raise AssetNotDeletableError(
                "The asset has history that must be kept",
                details=[
                    {
                        "blocking_reasons": [r for r in decision.reasons if r != "agent_active"],
                        "dependencies": decision.dependencies,
                    }
                ],
            )
        return self._hard_delete(asset)

    # --- Limpieza (Fase 5C.2) -----------------------------------------------------------------

    def _candidate(self, asset: Asset, decision: DeleteDecision, now: datetime) -> CleanupCandidate:
        return CleanupCandidate(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            hostname=asset.hostname,
            primary_ip=asset.primary_ip,
            mac_address=asset.mac_address,
            platform=asset.os_name or asset.probable_os,
            monitoring_method=asset.monitoring_method,
            lifecycle_source=decision.view.source.value,
            lifecycle_state=decision.view.state.value,
            status=effective_status(asset, now, self._timeout),
            last_seen_at=asset.last_seen_at,
            last_network_seen_at=asset.last_network_seen_at,
            last_activity_at=decision.view.last_activity_at,
            missed_successful_scans=asset.network_misses or 0,
            stale_for_hours=decision.view.stale_for_hours,
            action=decision.action.value,
            hard_delete_eligible=decision.can_hard_delete,
            blocking_reasons=decision.reasons,
            dependencies=decision.dependencies,
            version=asset.lifecycle_version,
        )

    def _decide_batch(self, assets: Sequence[Asset], now: datetime) -> list[DeleteDecision]:
        # Solo los descubiertos pueden llegar a ser borrables: para el resto basta el motivo
        # de origen (managed_history / monitored_source) y no se cuenta su telemetría.
        discovered = [
            a.id for a in assets if self.view(a, now).source is LifecycleSource.DISCOVERED
        ]
        history = self._history_blockers(discovered)
        return [self.hard_delete_decision(a, now, history.get(a.id, ([], {}))) for a in assets]

    def cleanup_preview(
        self,
        *,
        action: CleanupAction | None = None,
        source: LifecycleSource | None = None,
        limit: int = 50,
        offset: int = 0,
        now: datetime | None = None,
    ) -> tuple[list[CleanupCandidate], int, dict[str, int]]:
        """Candidatos de limpieza (stale o más), con la acción que les tocaría HOY.

        Usa exactamente hard_delete_decision, como el ejecutor: lo que el preview dice
        "elegible" es lo que el ejecutor borraría si nada cambia entre medias (y si algo
        cambia, el ejecutor lo vuelve a comprobar y lo omite). No escribe nada.
        """
        now = now or datetime.now(UTC)
        ids = list(
            self._session.scalars(
                select(Asset.id)
                .where(stale_condition(self._policy, now))
                .order_by(
                    func.coalesce(
                        func.greatest(Asset.last_seen_at, Asset.last_network_seen_at),
                        Asset.discovered_at,
                        Asset.first_seen_at,
                    ),
                    Asset.id,
                )
                .limit(MAX_PREVIEW_SCAN)
            )
        )
        counts = {a.value: 0 for a in CleanupAction}
        matched: list[CleanupCandidate] = []
        for start in range(0, len(ids), _PREVIEW_BATCH):
            chunk = ids[start : start + _PREVIEW_BATCH]
            by_id = {
                a.id: a for a in self._session.scalars(select(Asset).where(Asset.id.in_(chunk)))
            }
            assets = [by_id[i] for i in chunk if i in by_id]
            for asset, decision in zip(assets, self._decide_batch(assets, now), strict=True):
                counts[decision.action.value] += 1
                if action is not None and decision.action is not action:
                    continue
                if source is not None and decision.view.source is not source:
                    continue
                matched.append(self._candidate(asset, decision, now))
        return matched[offset : offset + limit], len(matched), counts

    def execute_cleanup(
        self,
        action: str,
        items: Sequence[CleanupItem],
        actor: Actor,
        reason: str | None = None,
        *,
        automatic: bool = False,
    ) -> CleanupResult:
        """Ejecuta un lote de limpieza revalidando CADA activo. No hace commit.

        Cada activo va en su SAVEPOINT con su fila bloqueada: se vuelve a calcular la misma
        decisión que mostró el preview y, si la realidad cambió (un heartbeat, un discovery
        que lo vio, una detección nueva, otra acción de un admin), se omite con el motivo.
        Un activo omitido o que falla no deshace los demás. Audita cada borrado/archivado y
        un resumen del lote.
        """
        results: list[CleanupItemResult] = []
        for item in items:
            results.append(self._cleanup_one(action, item, actor, reason, automatic))
        succeeded = sum(1 for r in results if r.outcome != "skipped")
        audit_service.record(
            self._session,
            actor,
            "asset_cleanup_executed",
            target_type="asset",
            details={
                "action": action,
                "automatic": automatic,
                "requested": len(items),
                "succeeded": succeeded,
                "skipped": len(results) - succeeded,
                # Solo ids (acotado): el detalle de cada uno está en su propia entrada.
                "assets": [str(r.asset_id) for r in results if r.outcome != "skipped"][:100],
            },
            commit=False,
        )
        return CleanupResult(
            action=action,
            requested=len(items),
            succeeded=succeeded,
            skipped=len(results) - succeeded,
            results=results,
        )

    def _cleanup_one(
        self, action: str, item: CleanupItem, actor: Actor, reason: str | None, automatic: bool
    ) -> CleanupItemResult:
        def skipped(reasons: list[str], name: str | None = None) -> CleanupItemResult:
            return CleanupItemResult(
                asset_id=item.asset_id, outcome="skipped", reasons=reasons, display_name=name
            )

        try:
            with self._session.begin_nested():
                asset = self._session.scalar(
                    select(Asset).where(Asset.public_id == item.asset_id).with_for_update()
                )
                if asset is None:
                    return skipped(["not_found"])
                name = asset.display_name
                if asset.lifecycle_version != item.version:
                    return skipped(["version_conflict"], name)
                decision = self.hard_delete_decision(asset, datetime.now(UTC))
                if action == "hard_delete":
                    if not decision.can_hard_delete:
                        return skipped(decision.reasons or ["not_eligible"], name)
                    summary = self._hard_delete(asset)
                    audit_service.record(
                        self._session,
                        actor,
                        "asset_deleted",
                        target_type="asset",
                        target_id=item.asset_id,
                        details={**summary, "cleanup": True, "automatic": automatic},
                        commit=False,
                    )
                    return CleanupItemResult(
                        asset_id=item.asset_id, outcome="deleted", reasons=[], display_name=name
                    )
                # Archivar: solo lo que el motor considera stale (no un activo al día) y sin
                # agente con credencial activa.
                if asset.archived_at is not None:
                    return skipped(["already_archived"], name)
                if decision.view.state not in (
                    LifecycleState.STALE,
                    LifecycleState.CLEANUP_CANDIDATE,
                ):
                    return skipped(["not_stale"], name)
                if credential_active(asset):
                    return skipped(["agent_active"], name)
                self._mark_archived(asset, actor.name, reason or "Limpieza de ciclo de vida")
                self._session.flush()
                audit_service.record(
                    self._session,
                    actor,
                    "asset_archived",
                    target_type="asset",
                    target_id=item.asset_id,
                    details={
                        "reason": asset.archive_reason,
                        "managed": asset.ever_managed,
                        "cleanup": True,
                    },
                    commit=False,
                )
                return CleanupItemResult(
                    asset_id=item.asset_id, outcome="archived", reasons=[], display_name=name
                )
        except Exception:
            # Un fallo inesperado (p. ej. una FK de una inserción concurrente) deshace solo
            # este activo: el SAVEPOINT ya se revirtió al salir del bloque.
            logger.exception("cleanup of one asset failed", extra={"asset": str(item.asset_id)})
            return skipped(["error"])

    def auto_cleanup(self, batch_size: int) -> CleanupResult | None:
        """Una vuelta de limpieza automática: SOLO descubiertos elegibles para borrado.

        Solo la llama el job opcional (ASSET_AUTO_CLEANUP=true). Nunca toca gestionados ni
        monitorizados, nunca archiva y cada borrado se revalida como uno manual.
        """
        items, _, _ = self.cleanup_preview(
            action=CleanupAction.HARD_DELETE_ELIGIBLE,
            source=LifecycleSource.DISCOVERED,
            limit=batch_size,
        )
        if not items:
            return None
        return self.execute_cleanup(
            "hard_delete",
            [CleanupItem(asset_id=c.asset_id, version=c.version) for c in items],
            audit_service.Actor("system"),
            automatic=True,
        )

    # --- Duplicados ---------------------------------------------------------------------------

    def _interfaces(self, asset_ids: Iterable[int]) -> dict[int, Any]:
        ids = list(asset_ids)
        if not ids:
            return {}
        return {
            row[0]: row[1]
            for row in self._session.execute(
                select(AssetInventory.asset_id, AssetInventory.data["interfaces"]).where(
                    AssetInventory.asset_id.in_(ids)
                )
            )
        }

    def _lineage(self, asset_ids: Iterable[int]) -> dict[int, set[UUID]]:
        ids = list(asset_ids)
        found: dict[int, set[UUID]] = {}
        if not ids:
            return found
        for asset_id, agent_id in self._session.execute(
            select(AssetAgentLineage.asset_id, AssetAgentLineage.agent_id).where(
                AssetAgentLineage.asset_id.in_(ids)
            )
        ):
            found.setdefault(asset_id, set()).add(agent_id)
        return found

    def _identities(self, assets: Sequence[Asset]) -> dict[int, _Identity]:
        ids = [a.id for a in assets]
        interfaces = self._interfaces(ids)
        lineage = self._lineage(ids)
        return {a.id: _identity(a, interfaces.get(a.id), lineage.get(a.id, ())) for a in assets}

    def _read(self, asset: Asset) -> DuplicateAsset:
        return DuplicateAsset(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            hostname=asset.hostname,
            primary_ip=asset.primary_ip,
            mac_address=asset.mac_address,
            os_name=asset.os_name,
            monitoring_method=asset.monitoring_method,
            agent_version=asset.agent_version,
            credential_status=credential_status(asset) if asset.agent_id is not None else None,
            archived=asset.archived_at is not None,
            last_seen_at=asset.last_seen_at or asset.last_network_seen_at,
            first_seen_at=asset.first_seen_at,
            version=asset.lifecycle_version,
        )

    def _candidates_of(self, asset: Asset, mine: _Identity) -> Sequence[Asset]:
        conditions: list[Any] = [Asset.primary_ip == asset.primary_ip]
        if asset.machine_id_hash:
            conditions.append(Asset.machine_id_hash == asset.machine_id_hash)
        if asset.hostname:
            conditions.append(func.lower(Asset.hostname) == asset.hostname.strip().lower())
        mac_list = sorted(mine.macs | mine.random_macs)
        if mac_list:
            conditions.append(Asset.mac_address.in_(mac_list))
        agents = sorted(mine.agents)
        if agents:
            # Linaje: activos que tuvieron alguno de mis agentes, o cuyo agente actual tuve yo.
            conditions.append(
                Asset.id.in_(
                    select(AssetAgentLineage.asset_id).where(AssetAgentLineage.agent_id.in_(agents))
                )
            )
            conditions.append(Asset.agent_id.in_(agents))
        return self._session.scalars(
            select(Asset)
            # Fase 5F: los posibles duplicados se buscan solo dentro del mismo site.
            .where(Asset.id != asset.id, Asset.site_id == asset.site_id, or_(*conditions))
            .order_by(Asset.last_seen_at.desc().nulls_last(), Asset.id)
            .limit(MAX_CANDIDATES * 3)
        ).all()

    def duplicate_candidates(self, public_id: UUID) -> list[DuplicateCandidate]:
        """Posibles duplicados de un activo, con evidencia y confianza. Solo sugiere."""
        asset = self._get(public_id)
        now = datetime.now(UTC)
        mine = self._identities([asset])[asset.id]
        found = self._candidates_of(asset, mine)
        theirs = self._identities(found)
        items: list[DuplicateCandidate] = []
        for other in found:
            # El activo consultado actúa como "nuevo" (origen) y el candidato como histórico.
            result = assess(
                asset, other, mine, theirs[other.id], target_online=self._online(other, now)
            )
            if result.confidence is None:
                continue
            items.append(
                DuplicateCandidate(
                    asset=self._read(other),
                    reasons=result.reasons,
                    confidence=result.confidence,
                    reconcilable=result.reconcilable,
                    reconcile_blockers=result.blockers,
                    evidence=result.evidence,
                    conflicts=result.conflicts,
                    reconcile_warnings=result.warnings,
                    requires_acknowledgement=result.requires_acknowledgement,
                )
            )
        rank = {"high": 0, "medium": 1, "low": 2}
        items.sort(key=lambda c: (rank[c.confidence], bool(c.conflicts), c.asset.archived))
        return items[:MAX_CANDIDATES]

    def duplicate_pairs(self, min_confidence: str = "medium") -> DuplicatePairList:
        """Pares de posible duplicado en toda la flota (confianza >= min_confidence).

        Solo pares donde al menos uno tiene agente: dos dispositivos descubiertos con la misma
        IP son el caso normal de DHCP y no se listan aquí. Sin comparación O(n²): el
        self-join usa igualdades sobre columnas indexadas (identidad de máquina, lower
        (hostname), IP) y linaje, con un tope de MAX_PAIRS. La IP solo empareja activos que
        tuvieron agente los dos (el caso "equipo reinstalado con IP fija").
        """
        a, b = Asset.__table__.alias("a"), Asset.__table__.alias("b")
        lineage = AssetAgentLineage.__table__
        rows = self._session.execute(
            select(a.c.id, b.c.id)
            .where(
                a.c.id < b.c.id,
                a.c.site_id == b.c.site_id,
                or_(a.c.agent_id.is_not(None), b.c.agent_id.is_not(None)),
                or_(
                    (a.c.machine_id_hash.is_not(None))
                    & (a.c.machine_id_hash == b.c.machine_id_hash),
                    (a.c.hostname.is_not(None))
                    & (func.lower(a.c.hostname) == func.lower(b.c.hostname)),
                    (a.c.primary_ip == b.c.primary_ip) & a.c.ever_managed & b.c.ever_managed,
                    a.c.id.in_(
                        select(lineage.c.asset_id).where(lineage.c.agent_id == b.c.agent_id)
                    ),
                    b.c.id.in_(
                        select(lineage.c.asset_id).where(lineage.c.agent_id == a.c.agent_id)
                    ),
                ),
            )
            .limit(MAX_PAIRS)
        ).all()
        ids = {i for pair in rows for i in pair}
        if not ids:
            return DuplicatePairList(items=[])
        assets = {x.id: x for x in self._session.scalars(select(Asset).where(Asset.id.in_(ids)))}
        identities = self._identities(list(assets.values()))
        now = datetime.now(UTC)
        rank = {"high": 0, "medium": 1, "low": 2}
        floor = rank[min_confidence]
        items: list[DuplicatePair] = []
        for left, right in rows:
            # El más reciente es el "nuevo" (origen de una posible reconciliación).
            newer, older = sorted(
                (assets[left], assets[right]), key=lambda x: (x.first_seen_at, x.id), reverse=True
            )
            result = assess(
                newer,
                older,
                identities[newer.id],
                identities[older.id],
                target_online=self._online(older, now),
            )
            if result.confidence is None or rank[result.confidence] > floor:
                continue
            items.append(
                DuplicatePair(
                    asset=self._read(newer),
                    candidate=self._read(older),
                    reasons=result.reasons,
                    confidence=result.confidence,
                    reconcilable=result.reconcilable,
                    reconcile_blockers=result.blockers,
                    evidence=result.evidence,
                    conflicts=result.conflicts,
                    reconcile_warnings=result.warnings,
                    requires_acknowledgement=result.requires_acknowledgement,
                )
            )
        items.sort(key=lambda p: rank[p.confidence])
        return DuplicatePairList(items=items)

    def detect_for_new_agent(self, asset: Asset) -> list[tuple[Asset, Assessment]]:
        """Duplicados probables (alta/media) de un agente recién enrolado, para auditar."""
        mine = self._identities([asset])[asset.id]
        now = datetime.now(UTC)
        found: list[tuple[Asset, Assessment]] = []
        for other in self._candidates_of(asset, mine):
            result = assess(
                asset,
                other,
                mine,
                _identity(other, None, self._lineage([other.id]).get(other.id, ())),
                target_online=self._online(other, now),
            )
            if result.confidence in ("high", "medium"):
                found.append((other, result))
        return found

    # --- Reconciliación -----------------------------------------------------------------------

    def _assess_pair(self, source: Asset, target: Asset) -> Assessment:
        identities = self._identities([source, target])
        return assess(
            source,
            target,
            identities[source.id],
            identities[target.id],
            target_online=self._online(target, datetime.now(UTC)),
        )

    def reconcile_preview(self, source_public_id: UUID, target_public_id: UUID) -> ReconcilePreview:
        """Impacto de una reconciliación, sin escribir nada (paso 4 de la UI)."""
        source = self._get(source_public_id)
        target = self._get(target_public_id)
        result = self._assess_pair(source, target)
        history = _bounded_counts(self._session, _HISTORY, [source.id, target.id])
        # El source quedará sin agente pero conserva su historial de agente: el mismo gate
        # que se aplicará al ejecutar (con su agente ya movido sigue siendo Managed).
        decision = self.hard_delete_decision(source, datetime.now(UTC))
        disposition = "source_deleted" if decision.can_hard_delete else "source_archived"
        return ReconcilePreview(
            source=self._read(source),
            target=self._read(target),
            confidence=result.confidence or "low",
            reasons=result.reasons,
            evidence=result.evidence,
            conflicts=result.conflicts,
            reconcilable=result.reconcilable,
            reconcile_blockers=result.blockers,
            reconcile_warnings=result.warnings,
            requires_acknowledgement=result.requires_acknowledgement,
            source_history=history.get(source.id, {}),
            target_history=history.get(target.id, {}),
            target_has_previous_agent=target.agent_id is not None,
            source_disposition=disposition,
            source_disposition_reasons=[r for r in decision.reasons if r != "agent_active"],
        )

    def reconcile(
        self,
        source_public_id: UUID,
        target_public_id: UUID,
        version: int,
        target_version: int,
        *,
        acknowledge_weak_evidence: bool = False,
        actor: Actor | None = None,
    ) -> "ReconcileOutcome":
        """Reasigna el agente de `source` (nuevo) a `target` (histórico). No hace commit.

        No es un merge: la telemetría, eventos e inventario que el agente nuevo llegó a
        enviar se quedan en `source` (archivado; ver docs, "Historial"). El historial
        principal (detecciones, riesgo, vulnerabilidades, incidentes, contexto) sigue en
        `target`, que recibe los datos del agente desde su siguiente envío. La credencial del
        agente actual se mueve con él (el hash, nunca el token): no tiene que re-enrolarse.
        El agente anterior del target queda en su linaje sin credencial (su hash se descarta).

        Concurrencia: ambas filas se bloquean en orden de id (dos reconciliaciones cruzadas no
        se interbloquean) y se comprueban las versiones que vio la UI: de dos admins a la
        vez, el segundo espera al primero y recibe 409 asset_lifecycle_conflict. Todo va en
        una transacción: cualquier error la deshace entera.
        """
        if source_public_id == target_public_id:
            raise AssetReconcileRefusedError(
                "An asset cannot be reconciled with itself",
                details=[{"blockers": ["same_asset"]}],
            )
        locked = self._session.scalars(
            select(Asset)
            .where(Asset.public_id.in_([source_public_id, target_public_id]))
            .order_by(Asset.id)
            .with_for_update()
        ).all()
        by_public = {x.public_id: x for x in locked}
        source = by_public.get(source_public_id)
        target = by_public.get(target_public_id)
        if source is None or target is None:
            raise NotFoundError("Asset not found")
        self._check_version(source, version)
        self._check_version(target, target_version)
        result = self._assess_pair(source, target)
        if result.blockers:
            raise AssetReconcileRefusedError(
                "These assets cannot be reconciled",
                details=[
                    {
                        "blockers": result.blockers + result.warnings,
                        "reasons": result.reasons,
                        "requires_acknowledgement": False,
                    }
                ],
            )
        if result.warnings and not acknowledge_weak_evidence:
            raise AssetReconcileRefusedError(
                "Weak or contradictory evidence: an administrator must confirm it explicitly",
                details=[
                    {
                        "blockers": result.warnings,
                        "reasons": result.reasons,
                        "requires_acknowledgement": True,
                    }
                ],
            )
        actor_name = (actor.name if actor else "system")[:64]
        agent_id = source.agent_id
        assert agent_id is not None  # noqa: S101  (assess exige source con agente)
        previous_agent = target.agent_id
        reconciliation_id = uuid.uuid4()
        now = datetime.now(UTC)
        moved = {
            "agent_token_hash": source.agent_token_hash,
            "agent_token_issued_at": source.agent_token_issued_at,
            "agent_token_revoked_at": source.agent_token_revoked_at,
        }
        # Linaje: qué agente deja cada activo (solo ids y versión; nunca credenciales).
        self._session.add(
            AssetAgentLineage(
                asset_id=source.id,
                agent_id=agent_id,
                ended_at=now,
                end_reason=LineageEndReason.REASSIGNED.value,
                related_asset_id=target.id,
                reconciliation_id=reconciliation_id,
                agent_version=source.agent_version,
                actor=actor_name,
            )
        )
        if previous_agent is not None:
            self._session.add(
                AssetAgentLineage(
                    asset_id=target.id,
                    agent_id=previous_agent,
                    ended_at=now,
                    end_reason=LineageEndReason.REPLACED.value,
                    related_asset_id=source.id,
                    reconciliation_id=reconciliation_id,
                    agent_version=target.agent_version,
                    actor=actor_name,
                )
            )
        # agent_id es único: primero se libera en el duplicado y se escribe, después se asigna.
        source.agent_id = None
        source.agent_token_hash = None
        source.agent_token_issued_at = None
        source.agent_token_revoked_at = None
        self._session.flush()

        target.agent_id = agent_id
        for name, value in moved.items():
            setattr(target, name, value)
        target.monitoring_method = MonitoringMethod.AGENT
        target.ever_managed = True
        # Los datos de host pasan a ser los del agente que informa ahora.
        target.hostname = source.hostname
        target.os_name = source.os_name
        target.os_version = source.os_version
        target.architecture = source.architecture
        target.primary_ip = source.primary_ip
        target.agent_version = source.agent_version
        target.agent_installation_method = source.agent_installation_method
        # La identidad de máquina del agente actual sustituye a la anterior (reinstalación):
        # la antigua no sale nunca del servidor y ya no describe al equipo que informa.
        target.machine_id_hash = source.machine_id_hash or target.machine_id_hash
        target.event_coverage = source.event_coverage
        target.event_coverage_at = source.event_coverage_at
        # Fase 5D: las capacidades de Response son del agente, no del equipo: el activo
        # canónico pasa a ofrecer solo lo que declara el agente actual (nunca las del viejo).
        target.agent_capabilities = source.agent_capabilities
        target.agent_capabilities_at = source.agent_capabilities_at
        source.agent_capabilities = None
        source.agent_capabilities_at = None
        if source.last_seen_at and (
            target.last_seen_at is None or source.last_seen_at > target.last_seen_at
        ):
            target.last_seen_at = source.last_seen_at
            target.status = source.status
        if target.archived_at is not None:
            # El activo histórico vuelve a estar vigente: ahora tiene un agente que informa.
            target.archived_at = None
            target.archived_by = None
            target.archive_reason = None
        # Corrección 6C: la etiqueta del activo histórico se conserva; si no tenía, hereda la
        # del activo del agente nuevo (el source queda archivado con la suya).
        adopt_label(source=source, target=target)
        target.lifecycle_version += 1
        self._session.flush()

        # Disposición del source con el MISMO gate de borrado. Tuvo agente, así que es
        # Managed y el gate lo conserva: se archiva con todo lo que llegó a enviar.
        decision = self.hard_delete_decision(source, now)
        reasons = [r for r in decision.reasons if r != "agent_active"]
        if decision.can_hard_delete:
            self._hard_delete(source)
            disposition = "source_deleted"
        else:
            self._mark_archived(source, "system", f"Reconciliado con el activo {target.public_id}")
            disposition = "source_archived"
        self._session.flush()
        request_recalculation(
            self._session, [target.id] + ([source.id] if disposition == "source_archived" else [])
        )
        # Cambian SO y versión del activo histórico: se reevalúan sus vulnerabilidades.
        mark_dirty(self._session, [target.id], "os_change")
        logger.info(
            "agent reconciled with existing asset",
            extra={"from": str(source_public_id), "into": str(target.public_id)},
        )
        return ReconcileOutcome(
            target=target,
            source_public_id=source_public_id,
            assessment=result,
            agent_id=agent_id,
            previous_agent_id=previous_agent,
            reconciliation_id=reconciliation_id,
            disposition=disposition,
            disposition_reasons=reasons,
            acknowledged=list(result.warnings),
        )


@dataclass
class ReconcileOutcome:
    target: Asset
    source_public_id: UUID
    assessment: Assessment
    agent_id: UUID
    previous_agent_id: UUID | None
    reconciliation_id: UUID
    disposition: str
    disposition_reasons: list[str]
    acknowledged: list[str]
