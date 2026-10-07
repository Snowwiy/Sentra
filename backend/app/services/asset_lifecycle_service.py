"""Ciclo de vida de activos (Fase 5C.1): archivar, restaurar, borrar, duplicados y reconciliar.

Conceptos (docs/agent-asset-lifecycle.md):
- la credencial del agente (token, revocación) NO es el activo: revocar nunca archiva ni
  borra nada;
- un activo que tuvo agente (Managed) nunca se borra físicamente desde la UI: se archiva y
  conserva todo su historial;
- solo un activo Discovered sin historial que conservar puede borrarse, y el servidor lo
  comprueba dentro de la misma transacción del borrado (sin TOCTOU);
- los duplicados se SUGIEREN con razones y confianza; nada se fusiona solo por hostname o IP.
  Reconciliar mueve el agente nuevo al activo histórico (reassign, no merge universal) y
  archiva el activo sobrante, que conserva lo poco que el agente nuevo llegó a enviar.

Toda acción de escritura usa concurrencia optimista (`lifecycle_version`) y bloquea las filas
afectadas con FOR UPDATE antes de comprobar nada.
"""

import logging
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
from app.models.inventory import AssetInventory
from app.repositories.asset_repository import AssetRepository
from app.risk.queue import request_recalculation
from app.schemas.agent_management import CredentialStatus
from app.schemas.asset_lifecycle import (
    AssetDeleteCheck,
    DuplicateAsset,
    DuplicateCandidate,
    DuplicatePair,
    DuplicatePairList,
)
from app.services.agent_management_service import agent_platform, credential_status
from app.services.asset_service import effective_status
from app.services.audit_service import Actor
from app.services.reconciliation import interface_identity
from app.vulnerabilities.queue import mark_dirty

logger = logging.getLogger(__name__)

# Dependencias que impiden el borrado físico, por motivo. Cada consulta es un EXISTS/COUNT
# acotado por asset_id (todas las columnas están indexadas: test_every_foreign_key_is_indexed).
# Detecciones "relevantes": impacto medio o superior. Las de bajo impacto de un dispositivo
# descubierto (NET-003 "dispositivo nuevo", NET-004 "desaparecido") hablan del propio
# fantasma y se borran con él; se muestran en `removes`, nunca en silencio.
_BLOCKING: dict[str, dict[str, str]] = {
    "agent_history": {
        "telemetry_samples": "SELECT count(*) FROM telemetry_samples WHERE asset_id = :id",
        "system_events": "SELECT count(*) FROM system_events WHERE asset_id = :id",
        "asset_inventories": "SELECT count(*) FROM asset_inventories WHERE asset_id = :id",
        "asset_process_snapshots": (
            "SELECT count(*) FROM asset_process_snapshots WHERE asset_id = :id"
        ),
        "agent_enrollment_tokens": (
            "SELECT count(*) FROM agent_enrollment_tokens WHERE last_asset_id = :id"
        ),
    },
    "detections": {
        "detections": (
            "SELECT count(*) FROM detections WHERE asset_id = :id"
            " AND severity IN ('medium', 'high', 'critical')"
        ),
    },
    "incidents": {
        "incident_assets": "SELECT count(*) FROM incident_assets WHERE asset_id = :id",
        "incident_detections": (
            "SELECT count(*) FROM incident_detections i JOIN detections d"
            " ON d.id = i.detection_id WHERE d.asset_id = :id"
        ),
        "incident_alerts": (
            "SELECT count(*) FROM incident_alerts i JOIN alerts a ON a.id = i.alert_id"
            " WHERE a.asset_id = :id"
        ),
    },
    "vulnerabilities": {
        "vulnerability_findings": (
            "SELECT count(*) FROM vulnerability_findings WHERE asset_id = :id"
        ),
    },
    "threat_intel": {
        "threat_intel_matches": "SELECT count(*) FROM threat_intel_matches WHERE asset_id = :id",
    },
    "audit_dependency": {
        # Historial de contexto editado por un admin (4L) y análisis de IA (4J): son registros
        # de decisiones humanas sobre este activo.
        "asset_context_changes": (
            "SELECT count(*) FROM asset_context_changes WHERE asset_id = :id"
        ),
        "ai_insights": "SELECT count(*) FROM ai_insights WHERE asset_id = :id",
    },
    "other": {
        # Una alerta sin resolver es trabajo pendiente de alguien: primero se resuelve.
        "active_alerts": (
            "SELECT count(*) FROM alerts WHERE asset_id = :id AND status <> 'resolved'"
        ),
    },
}

# Lo que desaparece con el activo (ON DELETE CASCADE), para mostrarlo antes de confirmar.
_REMOVES: dict[str, str] = {
    "ports": "SELECT count(*) FROM asset_ports WHERE asset_id = :id",
    "changes": "SELECT count(*) FROM asset_changes WHERE asset_id = :id",
    "detections": "SELECT count(*) FROM detections WHERE asset_id = :id",
    "alerts": "SELECT count(*) FROM alerts WHERE asset_id = :id",
    "risk_snapshots": "SELECT count(*) FROM risk_snapshots WHERE asset_id = :id",
}

# Sugerencias por activo y por listado global: acotadas para no recorrer la flota entera.
MAX_CANDIDATES = 20
MAX_PAIRS = 200


@dataclass
class Assessment:
    """Evidencia de que dos activos son la misma máquina y si se pueden reconciliar."""

    reasons: list[str] = field(default_factory=list)
    confidence: str | None = None
    blockers: list[str] = field(default_factory=list)

    @property
    def reconcilable(self) -> bool:
        return not self.blockers


@dataclass(frozen=True)
class _Identity:
    hostname: str | None
    ips: frozenset[str]
    macs: frozenset[str]


def _identity(asset: Asset, interfaces: Any = None) -> _Identity:
    ips, macs = interface_identity(interfaces) if interfaces else (set(), set())
    ips.add(asset.primary_ip)
    if asset.mac_address:
        macs.add(asset.mac_address)
    hostname = (asset.hostname or "").strip().lower() or None
    return _Identity(hostname, frozenset(ips), frozenset(macs))


def _platform(asset: Asset) -> str | None:
    if asset.os_name:
        return agent_platform(asset.os_name)
    return None


def has_managed_history(asset: Asset) -> bool:
    # agent_id también, por si una fila se creó sin pasar por el registro (scripts, tests).
    return (
        asset.agent_id is not None
        or asset.ever_managed
        or asset.monitoring_method == MonitoringMethod.AGENT
    )


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

    Confianza:
    - high: misma identidad de máquina (machine_id_hash);
    - medium: mismo hostname y además misma MAC o misma IP; o misma MAC;
    - low: solo hostname, o solo IP (DHCP reasigna direcciones: nunca basta).
    Identidades de máquina distintas descartan la coincidencia aunque todo lo demás coincida
    (equipos con el mismo nombre). Solo high y medium permiten reconciliar.
    """
    result = Assessment()
    if source.machine_id_hash and target.machine_id_hash:
        if source.machine_id_hash == target.machine_id_hash:
            result.reasons.append("same_machine_id")
        else:
            result.blockers.append("machine_id_mismatch")
    same_host = bool(source_id.hostname and source_id.hostname == target_id.hostname)
    same_mac = bool(source_id.macs & target_id.macs)
    same_ip = bool(source_id.ips & target_id.ips)
    if same_host:
        result.reasons.append("same_hostname")
    if same_ip:
        result.reasons.append("same_ip")
    if same_mac:
        result.reasons.append("same_mac")
    if "machine_id_mismatch" in result.blockers:
        result.confidence = None
    elif "same_machine_id" in result.reasons:
        result.confidence = "high"
    elif (same_host and (same_mac or same_ip)) or same_mac:
        result.confidence = "medium"
    elif same_host or same_ip:
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
    platforms = {_platform(source), _platform(target)} - {None}
    if len(platforms) > 1:
        result.blockers.append("platform_mismatch")
    if result.confidence not in ("high", "medium") and "machine_id_mismatch" not in result.blockers:
        result.blockers.append("insufficient_evidence")
    return result


class AssetLifecycleService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._timeout = heartbeat_timeout

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
        found: dict[str, int] = {}
        for name, sql in queries.items():
            count = int(self._session.scalar(text(sql), {"id": asset_id}) or 0)
            if count:
                found[name] = count
        return found

    def _blocking(self, asset: Asset) -> tuple[list[str], dict[str, int]]:
        reasons: list[str] = []
        dependencies: dict[str, int] = {}
        if has_managed_history(asset):
            reasons.append("managed_history")
        for reason, queries in _BLOCKING.items():
            counts = self._counts(queries, asset.id)
            if counts:
                reasons.append(reason)
                dependencies.update(counts)
        return reasons, dependencies

    def delete_check(self, public_id: UUID) -> AssetDeleteCheck:
        asset = self._get(public_id)
        reasons, dependencies = self._blocking(asset)
        return AssetDeleteCheck(
            asset_id=asset.public_id,
            deletable=not reasons,
            blocking_reasons=reasons,
            dependencies=dependencies,
            removes=self._counts(_REMOVES, asset.id),
            can_archive=asset.archived_at is None and not credential_active(asset),
            version=asset.lifecycle_version,
            display_name=asset.display_name,
            hostname=asset.hostname,
            primary_ip=asset.primary_ip,
            mac_address=asset.mac_address,
            monitoring_method=asset.monitoring_method,
            last_seen_at=asset.last_seen_at or asset.last_network_seen_at,
        )

    # --- Archivar / restaurar ------------------------------------------------------------------

    @staticmethod
    def _check_version(asset: Asset, version: int) -> None:
        if asset.lifecycle_version != version:
            raise AssetLifecycleConflictError(
                "The asset changed since it was loaded",
                details=[{"version": asset.lifecycle_version, "archived": asset.is_archived}],
            )

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
        asset.archived_at = datetime.now(UTC)
        asset.archived_by = actor.name[:64]
        asset.archive_reason = " ".join(reason.split())[:500]
        asset.lifecycle_version += 1
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

    def delete(self, public_id: UUID, version: int) -> dict[str, Any]:
        """Borra físicamente un activo descubierto sin historial. No hace commit.

        Evita TOCTOU: la fila del activo se bloquea (FOR UPDATE) ANTES de recalcular las
        dependencias. Cualquier inserción concurrente que referencie el activo (un finding,
        un match, un incidente) toma FOR KEY SHARE sobre la misma fila: o terminó antes y la
        vemos aquí, o espera a este borrado y falla por la clave foránea. Nunca se borra con
        dependencias que el check anterior de la UI no vio.
        """
        asset = self._get(public_id, lock=True)
        self._check_version(asset, version)
        reasons, dependencies = self._blocking(asset)
        if reasons:
            raise AssetNotDeletableError(
                "The asset has history that must be kept",
                details=[{"blocking_reasons": reasons, "dependencies": dependencies}],
            )
        summary = {
            "display_name": asset.display_name,
            "primary_ip": asset.primary_ip,
            "mac_address": asset.mac_address,
            "removed": self._counts(_REMOVES, asset.id),
        }
        # Core DELETE: las tablas hijas (puertos, cambios, detecciones de bajo impacto...) se
        # borran por ON DELETE CASCADE; las que deben sobrevivir ya bloquearon arriba.
        self._session.execute(delete(Asset).where(Asset.id == asset.id))
        self._session.flush()
        return summary

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

    def _online(self, asset: Asset, now: datetime) -> bool:
        return effective_status(asset, now, self._timeout) == AssetStatus.ONLINE

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

    def _candidates_of(self, asset: Asset, macs: Iterable[str]) -> Sequence[Asset]:
        conditions: list[Any] = [Asset.primary_ip == asset.primary_ip]
        if asset.machine_id_hash:
            conditions.append(Asset.machine_id_hash == asset.machine_id_hash)
        if asset.hostname:
            conditions.append(func.lower(Asset.hostname) == asset.hostname.strip().lower())
        mac_list = sorted(set(macs))
        if mac_list:
            conditions.append(Asset.mac_address.in_(mac_list))
        return self._session.scalars(
            select(Asset)
            .where(Asset.id != asset.id, or_(*conditions))
            .order_by(Asset.last_seen_at.desc().nulls_last(), Asset.id)
            .limit(MAX_CANDIDATES * 3)
        ).all()

    def duplicate_candidates(self, public_id: UUID) -> list[DuplicateCandidate]:
        """Posibles duplicados de un activo, con razones y confianza. Solo sugiere."""
        asset = self._get(public_id)
        now = datetime.now(UTC)
        interfaces = self._interfaces([asset.id])
        mine = _identity(asset, interfaces.get(asset.id))
        found = self._candidates_of(asset, mine.macs)
        others = self._interfaces(c.id for c in found)
        items: list[DuplicateCandidate] = []
        for other in found:
            theirs = _identity(other, others.get(other.id))
            # El activo consultado actúa como "nuevo" (origen) y el candidato como histórico.
            result = assess(asset, other, mine, theirs, target_online=self._online(other, now))
            if result.confidence is None:
                continue
            items.append(
                DuplicateCandidate(
                    asset=self._read(other),
                    reasons=result.reasons,
                    confidence=result.confidence,
                    reconcilable=result.reconcilable,
                    reconcile_blockers=result.blockers,
                )
            )
        rank = {"high": 0, "medium": 1, "low": 2}
        items.sort(key=lambda c: (rank[c.confidence], c.asset.archived))
        return items[:MAX_CANDIDATES]

    def duplicate_pairs(self) -> DuplicatePairList:
        """Pares de posible duplicado en toda la flota (confianza media o alta).

        Solo pares donde al menos uno tiene agente: dos dispositivos descubiertos con la misma
        IP son el caso normal de DHCP y no se listan aquí. La búsqueda en SQL es por identidad
        de máquina o hostname (indexados); la MAC del inventario se añade después.
        """
        a, b = Asset.__table__.alias("a"), Asset.__table__.alias("b")
        rows = self._session.execute(
            select(a.c.id, b.c.id)
            .where(
                a.c.id < b.c.id,
                or_(a.c.agent_id.is_not(None), b.c.agent_id.is_not(None)),
                or_(
                    (a.c.machine_id_hash.is_not(None))
                    & (a.c.machine_id_hash == b.c.machine_id_hash),
                    (a.c.hostname.is_not(None))
                    & (func.lower(a.c.hostname) == func.lower(b.c.hostname)),
                ),
            )
            .limit(MAX_PAIRS)
        ).all()
        ids = {i for pair in rows for i in pair}
        if not ids:
            return DuplicatePairList(items=[])
        assets = {x.id: x for x in self._session.scalars(select(Asset).where(Asset.id.in_(ids)))}
        interfaces = self._interfaces(ids)
        now = datetime.now(UTC)
        items: list[DuplicatePair] = []
        for left, right in rows:
            # El más reciente es el "nuevo" (origen de una posible reconciliación).
            newer, older = sorted(
                (assets[left], assets[right]), key=lambda x: (x.first_seen_at, x.id), reverse=True
            )
            result = assess(
                newer,
                older,
                _identity(newer, interfaces.get(newer.id)),
                _identity(older, interfaces.get(older.id)),
                target_online=self._online(older, now),
            )
            if result.confidence not in ("high", "medium"):
                continue
            items.append(
                DuplicatePair(
                    asset=self._read(newer),
                    candidate=self._read(older),
                    reasons=result.reasons,
                    confidence=result.confidence,
                    reconcilable=result.reconcilable,
                    reconcile_blockers=result.blockers,
                )
            )
        return DuplicatePairList(items=items)

    def detect_for_new_agent(self, asset: Asset) -> list[tuple[Asset, Assessment]]:
        """Duplicados probables (alta/media) de un agente recién enrolado, para auditar."""
        interfaces = self._interfaces([asset.id])
        mine = _identity(asset, interfaces.get(asset.id))
        now = datetime.now(UTC)
        found: list[tuple[Asset, Assessment]] = []
        for other in self._candidates_of(asset, mine.macs):
            result = assess(
                asset,
                other,
                mine,
                _identity(other, None),
                target_online=self._online(other, now),
            )
            if result.confidence in ("high", "medium"):
                found.append((other, result))
        return found

    # --- Reconciliación -----------------------------------------------------------------------

    def reconcile(
        self, source_public_id: UUID, target_public_id: UUID, version: int, target_version: int
    ) -> tuple[Asset, Asset, Assessment]:
        """Reasigna el agente de `source` (nuevo) a `target` (histórico). No hace commit.

        No es un merge: la telemetría, eventos e inventario que el agente nuevo llegó a
        enviar se quedan en `source`, que pasa a estar sin agente y archivado (conserva su
        historial, Managed: no borrable). El historial principal (detecciones, riesgo,
        vulnerabilidades, incidentes, contexto) sigue en `target`, que recibe los datos del
        agente desde su siguiente envío. El token del agente se mueve con él: no tiene que
        volver a enrolarse y ninguna credencial cambia de manos fuera del servidor.
        """
        if source_public_id == target_public_id:
            raise AssetReconcileRefusedError(
                "An asset cannot be reconciled with itself",
                details=[{"blockers": ["same_asset"]}],
            )
        # Bloqueo en orden de id fijo: dos reconciliaciones cruzadas no se interbloquean.
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
        interfaces = self._interfaces([source.id, target.id])
        result = assess(
            source,
            target,
            _identity(source, interfaces.get(source.id)),
            _identity(target, interfaces.get(target.id)),
            target_online=self._online(target, datetime.now(UTC)),
        )
        if result.blockers:
            raise AssetReconcileRefusedError(
                "Not enough evidence that both assets are the same machine",
                details=[{"blockers": result.blockers, "reasons": result.reasons}],
            )
        agent_id = source.agent_id
        assert agent_id is not None  # noqa: S101  (assess exige source con agente)
        moved = {
            "agent_token_hash": source.agent_token_hash,
            "agent_token_issued_at": source.agent_token_issued_at,
            "agent_token_revoked_at": source.agent_token_revoked_at,
        }
        # agent_id es único: primero se libera en el duplicado y se escribe, después se asigna.
        source.agent_id = None
        source.agent_token_hash = None
        source.agent_token_issued_at = None
        source.agent_token_revoked_at = None
        now = datetime.now(UTC)
        source.archived_at = now
        source.archived_by = "system"
        source.archive_reason = f"Reconciliado con el activo {target.public_id}"[:500]
        source.lifecycle_version += 1
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
        target.machine_id_hash = source.machine_id_hash or target.machine_id_hash
        target.event_coverage = source.event_coverage
        target.event_coverage_at = source.event_coverage_at
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
        target.lifecycle_version += 1
        self._session.flush()
        request_recalculation(self._session, [target.id, source.id])
        # Cambian SO y versión del activo histórico: se reevalúan sus vulnerabilidades.
        mark_dirty(self._session, [target.id], "os_change")
        logger.info(
            "agent reconciled with existing asset",
            extra={"from": str(source.public_id), "into": str(target.public_id)},
        )
        return target, source, result
