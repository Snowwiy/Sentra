"""Registro y lectura del historial de topología (Fase 6E.1, docs/topology-history.md).

- `record_history` se llama dentro de cada reconstrucción (misma transacción que los enlaces):
  crea un snapshot solo si el estado cambió, registra los cambios respecto al anterior y
  concluye `link_removed` para los enlaces que llevan TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS
  reconstrucciones sin derivarse con su fuente de evidencia sana.
- `TopologyHistoryService` sirve la API: snapshots, diff entre dos estados, cambios con
  filtros, revisión, historial por nodo y por enlace, y export firmado.

Todas las lecturas filtran por site en SQL y responden 404 genérico a lo que no es del site.
"""

import csv
import hashlib
import io
import ipaddress
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import SiteValidationError
from app.models.asset import Asset
from app.models.site import Site
from app.models.topology import TopologyBuild, TopologyLink
from app.models.topology_history import NetworkChange, TopologySnapshot
from app.schemas.topology_history import (
    NetworkChangeList,
    NetworkChangeRead,
    NetworkChangeReview,
    TopologyDiff,
    TopologyDiffSummary,
    TopologyHistoryEntry,
    TopologySnapshotDetail,
    TopologySnapshotList,
    TopologySnapshotRead,
)
from app.services import audit_service
from app.services.audit_service import Actor
from app.topology.errors import (
    NetworkChangeConflictError,
    NetworkChangeNotFoundError,
    TopologyHistoryNotFoundError,
    TopologySnapshotNotFoundError,
)
from app.topology.history import (
    MAX_EVIDENCE,
    ChangeDraft,
    DiffContext,
    canonical,
    canonical_hash,
    diff_snapshots,
)


def _now() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class SnapshotContent:
    nodes: dict[str, Any]
    links: dict[str, Any]
    quality: str
    reasons: list[str] = field(default_factory=list)
    degraded_nodes: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Recorded:
    created: bool
    changes: int
    snapshot_id: int | None


def _asset_ids(session: Session, public_ids: set[str]) -> dict[str, int]:
    valid: list[UUID] = []
    for value in public_ids:
        try:
            valid.append(UUID(value))
        except ValueError:
            continue
    if not valid:
        return {}
    return {
        str(public): asset_id
        for asset_id, public in session.execute(
            select(Asset.id, Asset.public_id).where(Asset.public_id.in_(valid))
        )
    }


def _retired(session: Session, node_keys: set[str]) -> frozenset[str]:
    """Nodos de activos que faltan porque se archivaron (retirada explícita del inventario)."""
    publics = [k.split(":", 1)[1] for k in node_keys if k.startswith("asset:")]
    ids: list[UUID] = []
    for value in publics:
        try:
            ids.append(UUID(value))
        except ValueError:
            continue
    if not ids:
        return frozenset()
    archived = session.scalars(
        select(Asset.public_id).where(Asset.public_id.in_(ids), Asset.archived_at.is_not(None))
    ).all()
    return frozenset(f"asset:{public}" for public in archived)


def _store_changes(
    session: Session,
    site_id: int,
    drafts: Sequence[ChangeDraft],
    source: str,
    now: datetime,
    from_id: int | None,
    to_id: int | None,
) -> int:
    assets = _asset_ids(session, {d.asset_public_id for d in drafts if d.asset_public_id})
    for draft in drafts:
        session.add(
            NetworkChange(
                site_id=site_id,
                change_type=draft.change_type,
                subject_type=draft.subject_type,
                subject_key=draft.subject_key[:96],
                subject_label=(draft.subject_label or None) and draft.subject_label[:255],
                asset_id=assets.get(draft.asset_public_id or ""),
                before=draft.before,
                after=draft.after,
                evidence=draft.evidence[:MAX_EVIDENCE],
                source=source,
                confidence=draft.confidence,
                status="detected",
                from_snapshot_id=from_id,
                to_snapshot_id=to_id,
                detected_at=now,
            )
        )
    return len(drafts)


def record_history(
    session: Session,
    settings: Settings,
    site_id: int,
    build: TopologyBuild,
    content: SnapshotContent,
) -> Recorded:
    now = _now()
    digest = canonical_hash(content.nodes, content.links)
    last = session.scalars(
        select(TopologySnapshot)
        .where(TopologySnapshot.site_id == site_id)
        .order_by(TopologySnapshot.sequence.desc())
        .limit(1)
        .with_for_update()
    ).first()
    changes = 0
    created = False
    snapshot_id: int | None
    detail = {"reasons": content.reasons, "degraded_nodes": sorted(content.degraded_nodes)[:200]}
    if last is not None and last.content_hash == digest:
        # Mismo estado de red: solo se confirma. La calidad puede variar sin que cambie el
        # contenido (una fuente que falla y vuelve); se guarda la más reciente.
        last.confirmed_at = now
        last.confirmations += 1
        last.quality = content.quality
        last.quality_detail = detail
        snapshot_id = last.id
    else:
        snapshot = TopologySnapshot(
            site_id=site_id,
            sequence=(last.sequence + 1) if last is not None else 1,
            content_hash=digest,
            build_id=build.id,
            nodes=content.nodes,
            links=content.links,
            node_count=len(content.nodes),
            link_count=len(content.links),
            quality=content.quality,
            quality_detail=detail,
            taken_at=now,
            confirmed_at=now,
            confirmations=1,
        )
        session.add(snapshot)
        session.flush()
        created = True
        snapshot_id = snapshot.id
        if last is not None:
            # El primer snapshot de un site es la línea base: no hay «cambios» respecto a nada.
            missing = set(last.nodes) - set(content.nodes)
            ctx = DiffContext(
                quality=content.quality,
                degraded_nodes=content.degraded_nodes,
                retired_nodes=_retired(session, missing),
                observed_at=now,
            )
            drafts = diff_snapshots(last.nodes, last.links, content.nodes, content.links, ctx)
            changes += _store_changes(
                session, site_id, drafts, "topology_diff", now, last.id, snapshot.id
            )
    changes += _record_link_removals(session, settings, site_id, content, now, snapshot_id)
    return Recorded(created=created, changes=changes, snapshot_id=snapshot_id)


def _record_link_removals(
    session: Session,
    settings: Settings,
    site_id: int,
    content: SnapshotContent,
    now: datetime,
    snapshot_id: int | None,
) -> int:
    """Concluye `link_removed` solo con evidencia suficiente.

    Exige: snapshot complete (un grafo recortado o con fuentes caídas no demuestra ausencias),
    el número configurado de reconstrucciones seguidas sin el enlace, y que ninguno de sus
    extremos tenga la fuente degradada. Cada enlace se concluye una sola vez (removed_at).
    """
    needed = settings.topology_link_removal_confirmations
    if content.quality != "complete" or needed <= 0:
        return 0
    rows = session.scalars(
        select(TopologyLink).where(
            TopologyLink.site_id == site_id,
            TopologyLink.present.is_(False),
            TopologyLink.removed_at.is_(None),
            TopologyLink.absent_builds >= needed,
        )
    ).all()
    drafts: list[ChangeDraft] = []
    for row in rows:
        if {row.source_node, row.target_node} & content.degraded_nodes:
            continue
        row.removed_at = now
        asset = None
        for node in (row.target_node, row.source_node):
            if node.startswith("asset:"):
                asset = node.split(":", 1)[1]
                break
        drafts.append(
            ChangeDraft(
                "link_removed",
                "link",
                row.link_key,
                f"{row.source_node} - {row.target_node}"[:255],
                {
                    "s": row.source_node,
                    "t": row.target_node,
                    "k": row.kind,
                    "rel": row.relation,
                    "sp": row.source_port,
                    "tp": row.target_port,
                    "id": str(row.public_id),
                },
                None,
                "medium",
                [
                    {
                        "source": row.relation,
                        "detail": f"Not derived in {row.absent_builds} consecutive rebuilds"
                        " with healthy evidence sources",
                        "observed_at": now.isoformat(),
                    }
                ],
                asset,
            )
        )
    return _store_changes(session, site_id, drafts, "topology_diff", now, None, snapshot_id)


# --- lectura -----------------------------------------------------------------------------------


def snapshot_read(row: TopologySnapshot, site_public: UUID) -> TopologySnapshotRead:
    return TopologySnapshotRead(
        id=row.public_id,
        site_id=site_public,
        sequence=row.sequence,
        content_hash=row.content_hash,
        node_count=row.node_count,
        link_count=row.link_count,
        quality=row.quality,
        quality_reasons=list((row.quality_detail or {}).get("reasons") or []),
        taken_at=row.taken_at,
        confirmed_at=row.confirmed_at,
        confirmations=row.confirmations,
        preserved=row.preserved,
    )


def change_read(
    row: NetworkChange, site_public: UUID, asset_public: UUID | None
) -> NetworkChangeRead:
    return NetworkChangeRead(
        id=row.public_id,
        site_id=site_public,
        change_type=row.change_type,
        subject_type=row.subject_type,
        subject_key=row.subject_key,
        subject_label=row.subject_label,
        asset_id=asset_public,
        before=row.before,
        after=row.after,
        evidence=list(row.evidence or []),
        source=row.source,
        confidence=row.confidence,
        status=row.status,
        review_note=row.review_note,
        reviewed_by=row.reviewed_by,
        reviewed_at=row.reviewed_at,
        detected_at=row.detected_at,
        preserved=row.preserved,
        version=row.version,
    )


def _in_subnet(ip: Any, network: ipaddress.IPv4Network | ipaddress.IPv6Network | None) -> bool:
    if network is None:
        return True
    try:
        return ipaddress.ip_address(str(ip)) in network
    except ValueError:
        return False


def _parse_subnet(value: str | None) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    if value is None:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise SiteValidationError(
            "topology_invalid_subnet", "Invalid subnet", [{"subnet": value[:64]}]
        ) from None


class TopologyHistoryService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._settings = settings

    def _snapshot(self, site: Site, public_id: UUID) -> TopologySnapshot:
        row = self._session.scalars(
            select(TopologySnapshot).where(
                TopologySnapshot.public_id == public_id, TopologySnapshot.site_id == site.id
            )
        ).first()
        if row is None:
            raise TopologySnapshotNotFoundError("Topology snapshot not found")
        return row

    def _at(self, site: Site, moment: datetime) -> TopologySnapshot:
        """Estado vigente en un instante: el último snapshot tomado antes o en ese momento."""
        row = self._session.scalars(
            select(TopologySnapshot)
            .where(TopologySnapshot.site_id == site.id, TopologySnapshot.taken_at <= moment)
            .order_by(TopologySnapshot.sequence.desc())
            .limit(1)
        ).first()
        if row is None:
            raise TopologySnapshotNotFoundError("No topology snapshot exists at that time")
        return row

    def list_snapshots(
        self,
        site: Site,
        *,
        start: datetime | None,
        end: datetime | None,
        limit: int,
        before_sequence: int | None,
    ) -> TopologySnapshotList:
        query = select(TopologySnapshot).where(TopologySnapshot.site_id == site.id)
        if start is not None:
            query = query.where(TopologySnapshot.taken_at >= start)
        if end is not None:
            query = query.where(TopologySnapshot.taken_at <= end)
        if before_sequence is not None:
            query = query.where(TopologySnapshot.sequence < before_sequence)
        rows = self._session.scalars(
            query.order_by(TopologySnapshot.sequence.desc()).limit(limit + 1)
        ).all()
        more = len(rows) > limit
        rows = rows[:limit]
        return TopologySnapshotList(
            items=[snapshot_read(r, site.public_id) for r in rows],
            next_before_sequence=rows[-1].sequence if more and rows else None,
        )

    def get_snapshot(self, site: Site, public_id: UUID) -> TopologySnapshotDetail:
        row = self._snapshot(site, public_id)
        return TopologySnapshotDetail(
            **snapshot_read(row, site.public_id).model_dump(),
            nodes=row.nodes,
            links=row.links,
            degraded_nodes=list((row.quality_detail or {}).get("degraded_nodes") or []),
        )

    def diff(
        self,
        site: Site,
        *,
        from_snapshot: UUID | None,
        to_snapshot: UUID | None,
        from_time: datetime | None,
        to_time: datetime | None,
        subnet: str | None = None,
    ) -> TopologyDiff:
        """Diferencias entre dos estados elegidos por id o por instante.

        Se recalculan con las mismas reglas que el registro (diff_snapshots), así comparar
        dos fechas lejanas resume todos los cambios intermedios en el estado final, que es lo
        que pide «comparar la red entre dos fechas».
        """
        if from_snapshot is not None:
            old = self._snapshot(site, from_snapshot)
        elif from_time is not None:
            old = self._at(site, from_time)
        else:
            raise SiteValidationError(
                "topology_diff_missing_from", "from_snapshot or from_time is required", []
            )
        if to_snapshot is not None:
            new = self._snapshot(site, to_snapshot)
        elif to_time is not None:
            new = self._at(site, to_time)
        else:
            new = self._at(site, _now())
        network = _parse_subnet(subnet)
        missing = set(old.nodes) - set(new.nodes)
        ctx = DiffContext(
            quality=new.quality,
            degraded_nodes=frozenset((new.quality_detail or {}).get("degraded_nodes") or []),
            retired_nodes=_retired(self._session, missing),
            observed_at=new.taken_at,
        )
        drafts = diff_snapshots(old.nodes, old.links, new.nodes, new.links, ctx)
        if network is not None:
            drafts = [d for d in drafts if self._draft_in(d, old, new, network)]
        summary: dict[str, int] = {}
        for draft in drafts:
            summary[draft.change_type] = summary.get(draft.change_type, 0) + 1
        return TopologyDiff(
            site_id=site.public_id,
            from_snapshot=snapshot_read(old, site.public_id),
            to_snapshot=snapshot_read(new, site.public_id),
            summary=TopologyDiffSummary(total=len(drafts), by_type=summary),
            changes=[
                {
                    "change_type": d.change_type,
                    "subject_type": d.subject_type,
                    "subject_key": d.subject_key,
                    "subject_label": d.subject_label,
                    "before": d.before,
                    "after": d.after,
                    "confidence": d.confidence,
                    "evidence": d.evidence,
                }
                for d in drafts
            ],
        )

    @staticmethod
    def _draft_in(
        draft: ChangeDraft,
        old: TopologySnapshot,
        new: TopologySnapshot,
        network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    ) -> bool:
        keys: list[str] = []
        if draft.subject_type == "node":
            keys = [draft.subject_key]
        else:
            link = new.links.get(draft.subject_key) or old.links.get(draft.subject_key) or {}
            keys = [str(link.get("s")), str(link.get("t"))]
        for key in keys:
            for nodes in (new.nodes, old.nodes):
                node = nodes.get(key)
                if node and _in_subnet(node.get("ip"), network):
                    return True
        return False

    def export_diff(self, diff: TopologyDiff, fmt: str) -> tuple[bytes, str, str]:
        """Contenido, tipo MIME y SHA-256 del export (el hash va en X-Sentra-SHA256)."""
        if fmt == "csv":
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            writer.writerow(
                [
                    "change_type",
                    "subject_type",
                    "subject_key",
                    "subject_label",
                    "confidence",
                    "before",
                    "after",
                ]
            )
            for change in diff.changes:
                writer.writerow(
                    [
                        _csv_cell(change.get("change_type")),
                        _csv_cell(change.get("subject_type")),
                        _csv_cell(change.get("subject_key")),
                        _csv_cell(change.get("subject_label")),
                        _csv_cell(change.get("confidence")),
                        _csv_cell(canonical(change.get("before")).decode()),
                        _csv_cell(canonical(change.get("after")).decode()),
                    ]
                )
            body = buffer.getvalue().encode("utf-8")
            media = "text/csv; charset=utf-8"
        else:
            body = canonical(diff.model_dump(mode="json"))
            media = "application/json"
        return body, media, hashlib.sha256(body).hexdigest()

    def list_changes(
        self,
        site: Site,
        *,
        change_type: str | None,
        status: str | None,
        subject: str | None,
        asset: UUID | None,
        start: datetime | None,
        end: datetime | None,
        subnet: str | None,
        limit: int,
        offset: int,
    ) -> NetworkChangeList:
        network = _parse_subnet(subnet)
        query = (
            select(NetworkChange, Asset.public_id)
            .outerjoin(Asset, Asset.id == NetworkChange.asset_id)
            .where(NetworkChange.site_id == site.id)
        )
        if change_type is not None:
            query = query.where(NetworkChange.change_type == change_type)
        if status is not None:
            query = query.where(NetworkChange.status == status)
        if subject is not None:
            query = query.where(NetworkChange.subject_key == subject)
        if asset is not None:
            query = query.where(Asset.public_id == asset)
        if start is not None:
            query = query.where(NetworkChange.detected_at >= start)
        if end is not None:
            query = query.where(NetworkChange.detected_at <= end)
        if network is not None:
            # El filtro por subred usa la IP del activo afectado (los cambios de enlace sin
            # activo, p. ej. entre dos switches, no tienen IP propia y quedan fuera).
            query = query.where(
                func.host(func.inet(Asset.primary_ip)).is_not(None),
                func.inet(Asset.primary_ip).op("<<=")(func.cidr(str(network))),
            )
        total = int(self._session.scalar(select(func.count()).select_from(query.subquery())) or 0)
        rows = self._session.execute(
            query.order_by(NetworkChange.detected_at.desc(), NetworkChange.id.desc())
            .limit(limit)
            .offset(offset)
        ).all()
        return NetworkChangeList(
            total=total,
            items=[change_read(row, site.public_id, public) for row, public in rows],
        )

    def review(
        self, site: Site, public_id: UUID, body: NetworkChangeReview, actor: Actor
    ) -> NetworkChangeRead:
        row = self._session.scalars(
            select(NetworkChange)
            .where(NetworkChange.public_id == public_id, NetworkChange.site_id == site.id)
            .with_for_update()
        ).first()
        if row is None:
            raise NetworkChangeNotFoundError("Network change not found")
        if row.version != body.version:
            raise NetworkChangeConflictError("The change was modified; reload and try again")
        previous = row.status
        row.status = body.status
        row.review_note = body.note
        row.reviewed_by = actor.name[:64]
        row.reviewed_at = _now()
        row.version += 1
        audit_service.record(
            self._session,
            actor,
            "network_change_reviewed",
            target_type="network_change",
            target_id=row.public_id,
            details={"from": previous, "to": body.status, "change_type": row.change_type},
            commit=False,
        )
        self._session.commit()
        asset_public = (
            self._session.scalar(select(Asset.public_id).where(Asset.id == row.asset_id))
            if row.asset_id is not None
            else None
        )
        return change_read(row, site.public_id, asset_public)

    def history(
        self, site: Site, *, subject_type: str, key: str, limit: int
    ) -> list[TopologyHistoryEntry]:
        """Línea de tiempo de un nodo o enlace: sus valores en cada snapshot donde cambió."""
        column = TopologySnapshot.nodes if subject_type == "node" else TopologySnapshot.links
        rows = self._session.execute(
            select(
                TopologySnapshot.public_id,
                TopologySnapshot.sequence,
                TopologySnapshot.taken_at,
                TopologySnapshot.confirmed_at,
                column[key].label("value"),
            )
            .where(TopologySnapshot.site_id == site.id)
            .order_by(TopologySnapshot.sequence.asc())
        ).all()
        entries: list[TopologyHistoryEntry] = []
        previous: Any = object()
        for public, sequence, taken, confirmed, value in rows:
            if value == previous:
                if entries:
                    entries[-1].until = confirmed
                continue
            previous = value
            entries.append(
                TopologyHistoryEntry(
                    snapshot_id=public,
                    sequence=sequence,
                    since=taken,
                    until=confirmed,
                    present=value is not None,
                    value=value,
                )
            )
        if not any(e.present for e in entries):
            raise TopologyHistoryNotFoundError("No history for this subject")
        return entries[-limit:]

    def link_key(self, site: Site, link_id: str) -> str | None:
        """link_key de un enlace del site a partir de su id público (None si no es del site)."""
        try:
            public = UUID(link_id)
        except ValueError:
            return None
        return self._session.scalar(
            select(TopologyLink.link_key).where(
                TopologyLink.public_id == public, TopologyLink.site_id == site.id
            )
        )

    def preserve_for(self, site_id: int, moment: datetime, reason: str) -> int:
        """Marca como preservado el snapshot vigente en un instante y los cambios cercanos.

        Lo usan incidentes e investigaciones: la evidencia de red de ese momento no puede
        desaparecer por la retención mientras el caso la necesite.
        """
        snap = self._session.scalars(
            select(TopologySnapshot)
            .where(TopologySnapshot.site_id == site_id, TopologySnapshot.taken_at <= moment)
            .order_by(TopologySnapshot.sequence.desc())
            .limit(1)
        ).first()
        count = 0
        if snap is not None and not snap.preserved:
            snap.preserved = True
            snap.preserve_reason = reason[:200]
            count += 1
        window = timedelta(hours=24)
        result = self._session.execute(
            update(NetworkChange)
            .where(
                NetworkChange.site_id == site_id,
                NetworkChange.detected_at.between(moment - window, moment + window),
                NetworkChange.preserved.is_(False),
            )
            .values(preserved=True)
        )
        return count + int(getattr(result, "rowcount", 0) or 0)


def _csv_cell(value: object) -> str:
    """Celda CSV sin inyección de fórmulas (=, +, -, @ al principio se neutralizan)."""
    text = "" if value is None else str(value)
    if text[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


# --- retención y enfriamiento -----------------------------------------------------------------


def purge_topology_history(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    """Retención de 6D/6E. Cada tipo con su plazo; nada preservado se borra.

    - topology_builds: registro operativo; se conserva siempre la última de cada site.
    - topology_snapshots: se conserva siempre el último de cada site (es el estado actual).
    - network_changes: evidencia; solo los no preservados.
    - topology_links ausentes y sin revisión humana: dato derivado que la reconstrucción
      recalcularía si volviera la evidencia; los revisados se conservan (decisión humana).
    """
    now = now or _now()
    out = {"topology_builds": 0, "topology_snapshots": 0, "network_changes": 0, "topology_links": 0}
    if settings.topology_build_retention_days:
        cutoff = now - timedelta(days=settings.topology_build_retention_days)
        latest = (
            select(func.max(TopologyBuild.id)).group_by(TopologyBuild.site_id).scalar_subquery()
        )
        out["topology_builds"] = _delete(
            session,
            delete(TopologyBuild).where(
                TopologyBuild.started_at < cutoff,
                TopologyBuild.status != "running",
                TopologyBuild.id.not_in(latest),
            ),
        )
    if settings.network_change_retention_days:
        cutoff = now - timedelta(days=settings.network_change_retention_days)
        out["network_changes"] = _delete(
            session,
            delete(NetworkChange).where(
                NetworkChange.detected_at < cutoff, NetworkChange.preserved.is_(False)
            ),
        )
    if settings.topology_snapshot_retention_days:
        cutoff = now - timedelta(days=settings.topology_snapshot_retention_days)
        latest = (
            select(func.max(TopologySnapshot.id))
            .group_by(TopologySnapshot.site_id)
            .scalar_subquery()
        )
        out["topology_snapshots"] = _delete(
            session,
            delete(TopologySnapshot).where(
                TopologySnapshot.confirmed_at < cutoff,
                TopologySnapshot.preserved.is_(False),
                TopologySnapshot.id.not_in(latest),
            ),
        )
    if settings.topology_absent_link_retention_days:
        cutoff = now - timedelta(days=settings.topology_absent_link_retention_days)
        out["topology_links"] = _delete(
            session,
            delete(TopologyLink).where(
                TopologyLink.present.is_(False),
                TopologyLink.review_state == "unreviewed",
                or_(TopologyLink.absent_since.is_(None), TopologyLink.absent_since < cutoff),
                TopologyLink.last_seen_at < cutoff,
            ),
        )
    session.commit()
    return out


def _delete(session: Session, stmt: Any) -> int:
    result = session.execute(stmt)
    return int(getattr(result, "rowcount", 0) or 0)


def rebuild_cooldown_remaining(
    session: Session, settings: Settings, site_id: int, now: datetime | None = None
) -> int:
    """Segundos que faltan para permitir otra reconstrucción MANUAL del site (0 = permitida).

    Solo cuentan las manuales: la programada no debe impedir que un admin reconstruya tras
    corregir un dato, y una manual no frena a la programada.
    """
    seconds = settings.topology_manual_rebuild_cooldown_seconds
    if seconds <= 0:
        return 0
    now = now or _now()
    last = session.scalar(
        select(func.max(TopologyBuild.started_at)).where(
            TopologyBuild.site_id == site_id, TopologyBuild.trigger == "manual"
        )
    )
    if last is None:
        return 0
    remaining = int((last + timedelta(seconds=seconds) - now).total_seconds())
    return max(remaining, 0)
