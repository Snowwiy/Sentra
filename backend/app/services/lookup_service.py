"""Selectores contextuales (Fase 7C.3, docs/contextual-selectors.md).

Resuelve lo que un usuario reconoce (nombre, etiqueta personalizada, hostname, DNS, IP, MAC,
etiqueta administrativa, modelo, id de regla, número de caso) al id público que necesitan las
APIs. No es un lenguaje de consulta: el texto se compara por igualdad o con LIKE escapado
contra columnas conocidas, con tope de resultados y respetando el site elegido.

Clasificación de cada candidato:
- exacto: el texto es exactamente la IP, la MAC, la etiqueta, el nombre o el número de caso;
- parcial: empieza por el texto o lo contiene.
La resolución global (exact/ambiguous/partial/none) le dice a la UI si puede elegir sola (una
única coincidencia exacta) o si tiene que mostrar opciones. Nunca se elige entre varias
coincidencias exactas: dos equipos pueden compartir nombre y uno de ellos estaría mal.
"""

import ipaddress
import re
from collections.abc import Sequence
from typing import Any
from uuid import UUID

from sqlalchemy import String, case, cast, func, literal, or_, select
from sqlalchemy.orm import Session

from app.discovery.probes import normalize_mac
from app.models.asset import Asset
from app.models.asset_context import AssetTag
from app.models.detection import Detection
from app.models.incident import Incident
from app.models.site import Site
from app.repositories.asset_repository import display_name_expr
from app.schemas.lookup import LookupItem, LookupKind, LookupResolution, LookupResult

MAX_LIMIT = 20
_CASE = re.compile(r"^(?:INC-|#)?(\d{1,9})$", re.IGNORECASE)
_RULE = re.compile(r"^[A-Za-z]{2,6}-\d{3}$")


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _contains(value: str) -> str:
    return f"%{_escape(value)}%"


def _prefix(value: str) -> str:
    return f"{_escape(value)}%"


def _is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _resolution(items: Sequence[LookupItem]) -> LookupResolution:
    exact = sum(1 for i in items if i.exact)
    if exact == 1:
        return "exact"
    if exact > 1:
        return "ambiguous"
    return "partial" if items else "none"


class LookupService:
    def __init__(self, session: Session) -> None:
        self._session = session

    def lookup(
        self,
        kind: LookupKind,
        query: str,
        *,
        site_id: int | None,
        limit: int = 8,
        include_archived: bool = False,
    ) -> LookupResult:
        text = " ".join(query.split())
        limit = max(1, min(limit, MAX_LIMIT))
        if kind == "asset":
            items, more = self._assets(text, site_id, limit, include_archived)
        elif kind == "detection":
            items, more = self._detections(text, site_id, limit)
        else:
            items, more = self._incidents(text, limit)
        return LookupResult(
            kind=kind, query=text, resolution=_resolution(items), items=items, truncated=more
        )

    def resolve_ids(
        self, kind: LookupKind, ids: Sequence[UUID], *, site_id: int | None
    ) -> LookupResult:
        """Etiquetas de ids ya conocidos (p. ej. ?asset=<id> en la URL de la consola).

        Un id que no existe (o de otro site) simplemente no aparece: la UI lo muestra como no
        disponible, sin revelar si existe en otro site.
        """
        unique = list(dict.fromkeys(ids))[:MAX_LIMIT]
        if kind == "asset":
            stmt = self._asset_select().where(Asset.public_id.in_(unique))
            if site_id is not None:
                stmt = stmt.where(Asset.site_id == site_id)
            items = [self._asset_item(row, "id", True) for row in self._session.execute(stmt)]
        elif kind == "detection":
            dstmt = self._detection_select().where(Detection.public_id.in_(unique))
            if site_id is not None:
                dstmt = dstmt.where(Asset.site_id == site_id)
            items = [self._detection_item(row, "id", True) for row in self._session.execute(dstmt)]
        else:
            rows = self._session.scalars(select(Incident).where(Incident.public_id.in_(unique)))
            items = [self._incident_item(i, "id", True) for i in rows]
        return LookupResult(
            kind=kind,
            query="",
            resolution=_resolution(items),
            items=items,
            truncated=False,
        )

    # --- Activos ---------------------------------------------------------------------------

    def _asset_select(self) -> Any:
        return select(
            Asset.public_id,
            display_name_expr().label("label"),
            Asset.custom_label,
            Asset.device_name,
            Asset.hostname,
            Asset.reverse_dns,
            Asset.primary_ip,
            Asset.mac_address,
            Asset.device_type,
            Asset.device_vendor,
            Asset.device_model,
            Asset.archived_at,
            Asset.last_seen_at,
            Asset.last_network_seen_at,
            cast(Asset.status, String).label("status"),
            Site.name.label("site_name"),
        ).join(Site, Site.id == Asset.site_id)

    def _assets(
        self, text: str, site_id: int | None, limit: int, include_archived: bool
    ) -> tuple[list[LookupItem], bool]:
        lowered = text.lower()
        mac = normalize_mac(text)
        name_columns = {
            "label": Asset.custom_label,
            "name": Asset.device_name,
            "hostname": Asset.hostname,
            "dns": Asset.reverse_dns,
        }
        tag_match = Asset.id.in_(
            select(AssetTag.asset_id).where(AssetTag.tag.ilike(_contains(lowered), escape="\\"))
        )
        conditions: list[Any] = [
            *(
                func.lower(col).like(_contains(lowered), escape="\\")
                for col in name_columns.values()
            ),
            func.lower(func.coalesce(Asset.device_model, "")).like(_contains(lowered), escape="\\"),
            tag_match,
        ]
        if _is_ip(text):
            conditions.append(Asset.primary_ip == text)
        else:
            # Prefijo de IP ("192.168.1."): útil para elegir por subred sin escribirla entera.
            conditions.append(Asset.primary_ip.like(_prefix(text), escape="\\"))
        if mac:
            conditions.append(Asset.mac_address == mac)
        # Rango: 0 exacto, 1 empieza por, 2 contiene. Se ordena en SQL para que el tope de
        # resultados se quede con los mejores, no con los primeros por id.
        exact = or_(
            Asset.primary_ip == text,
            *(func.lower(col) == lowered for col in name_columns.values()),
            *((Asset.mac_address == mac,) if mac else ()),
        )
        starts = or_(
            *(func.lower(col).like(_prefix(lowered), escape="\\") for col in name_columns.values()),
            Asset.primary_ip.like(_prefix(text), escape="\\"),
        )
        rank = case((exact, 0), (starts, 1), else_=2)
        stmt = self._asset_select().where(or_(*conditions))
        if site_id is not None:
            stmt = stmt.where(Asset.site_id == site_id)
        if not include_archived:
            stmt = stmt.where(Asset.archived_at.is_(None))
        rows = self._session.execute(
            stmt.order_by(rank, Asset.archived_at.is_not(None), display_name_expr(), Asset.id)
            .add_columns(rank.label("rank"))
            .limit(limit + 1)
        ).all()
        tags = self._tags_matching([r.public_id for r in rows], lowered)
        items: list[LookupItem] = []
        for row in rows[:limit]:
            field, is_exact = self._asset_match(row, text, lowered, mac, tags)
            items.append(self._asset_item(row, field, is_exact))
        return items, len(rows) > limit

    def _tags_matching(self, public_ids: list[UUID], lowered: str) -> set[UUID]:
        if not public_ids:
            return set()
        return set(
            self._session.scalars(
                select(Asset.public_id)
                .join(AssetTag, AssetTag.asset_id == Asset.id)
                .where(
                    Asset.public_id.in_(public_ids),
                    AssetTag.tag.ilike(_contains(lowered), escape="\\"),
                )
            )
        )

    @staticmethod
    def _asset_match(
        row: Any, text: str, lowered: str, mac: str | None, tags: set[UUID]
    ) -> tuple[str, bool]:
        if row.primary_ip == text:
            return "ip", True
        if mac and row.mac_address == mac:
            return "mac", True
        named = (
            ("label", row.custom_label),
            ("name", row.device_name),
            ("hostname", row.hostname),
            ("dns", row.reverse_dns),
        )
        for field, value in named:
            if value and value.lower() == lowered:
                return field, True
        for field, value in named:
            if value and lowered in value.lower():
                return field, False
        if row.primary_ip.startswith(text):
            return "ip", False
        if row.public_id in tags:
            return "tag", False
        return "model", False

    @staticmethod
    def _asset_item(row: Any, field: str, exact: bool) -> LookupItem:
        kind_label = row.device_type or "tipo desconocido"
        parts = [row.primary_ip, kind_label, row.site_name]
        if row.device_model:
            parts.insert(2, row.device_model)
        return LookupItem(
            kind="asset",
            id=row.public_id,
            label=row.label,
            secondary=" · ".join(p for p in parts if p),
            match_field=field,
            exact=exact,
            archived=row.archived_at is not None,
            site_name=row.site_name,
            ip=row.primary_ip,
            mac=row.mac_address,
            device_type=row.device_type,
            status=row.status,
            last_seen_at=row.last_seen_at or row.last_network_seen_at,
        )

    # --- Detecciones ------------------------------------------------------------------------

    def _detection_select(self) -> Any:
        return (
            select(
                Detection.public_id,
                Detection.rule_id,
                Detection.title,
                cast(Detection.severity, String).label("severity"),
                cast(Detection.status, String).label("status"),
                Detection.last_seen_at,
                Asset.public_id.label("asset_public_id"),
                display_name_expr().label("asset_label"),
                Asset.primary_ip,
                Site.name.label("site_name"),
            )
            .join(Asset, Asset.id == Detection.asset_id)
            .join(Site, Site.id == Asset.site_id)
        )

    def _detections(
        self, text: str, site_id: int | None, limit: int
    ) -> tuple[list[LookupItem], bool]:
        lowered = text.lower()
        if _RULE.match(text):
            condition: Any = Detection.rule_id == text.upper()
            rank: Any = literal(0)
        else:
            # Por título, por regla o por el activo (nombre o IP): "las detecciones de PC-14".
            asset_match = or_(
                func.lower(display_name_expr()).like(_contains(lowered), escape="\\"),
                Asset.primary_ip == text,
            )
            condition = or_(
                func.lower(Detection.title).like(_contains(lowered), escape="\\"),
                func.lower(Detection.rule_id).like(_prefix(lowered), escape="\\"),
                asset_match,
            )
            rank = case((func.lower(Detection.title) == lowered, 0), else_=1)
        stmt = self._detection_select().where(condition)
        if site_id is not None:
            stmt = stmt.where(Asset.site_id == site_id)
        rows = self._session.execute(
            stmt.order_by(rank, Detection.last_seen_at.desc(), Detection.id.desc()).limit(limit + 1)
        ).all()
        items: list[LookupItem] = []
        for row in rows[:limit]:
            if _RULE.match(text):
                field, is_exact = "rule", False
            elif row.title.lower() == lowered:
                field, is_exact = "title", True
            elif lowered in row.title.lower():
                field, is_exact = "title", False
            elif row.rule_id.lower().startswith(lowered):
                field, is_exact = "rule", False
            else:
                field, is_exact = "name", False
            items.append(self._detection_item(row, field, is_exact))
        return items, len(rows) > limit

    @staticmethod
    def _detection_item(row: Any, field: str, exact: bool) -> LookupItem:
        return LookupItem(
            kind="detection",
            id=row.public_id,
            label=f"{row.rule_id} · {row.title}",
            secondary=" · ".join(
                p for p in (row.asset_label, row.primary_ip, row.severity, row.site_name) if p
            ),
            match_field=field,
            exact=exact,
            site_name=row.site_name,
            status=row.status,
            severity=row.severity,
            asset_id=row.asset_public_id,
            asset_label=row.asset_label,
            last_seen_at=row.last_seen_at,
        )

    # --- Incidentes -------------------------------------------------------------------------

    def _incidents(self, text: str, limit: int) -> tuple[list[LookupItem], bool]:
        # Los casos no pertenecen a un site (pueden abarcar varios): se buscan siempre, como en
        # la búsqueda global de la consola (7B.4).
        match = _CASE.match(text)
        if match:
            number = int(match.group(1))
            condition: Any = or_(
                Incident.number == number,
                func.lower(Incident.title).like(_contains(text.lower()), escape="\\"),
            )
            rank: Any = case((Incident.number == number, 0), else_=1)
        else:
            condition = func.lower(Incident.title).like(_contains(text.lower()), escape="\\")
            rank = case((func.lower(Incident.title) == text.lower(), 0), else_=1)
        rows = self._session.scalars(
            select(Incident).where(condition).order_by(rank, Incident.id.desc()).limit(limit + 1)
        ).all()
        items: list[LookupItem] = []
        for incident in rows[:limit]:
            if match and incident.number == int(match.group(1)):
                items.append(self._incident_item(incident, "number", True))
            else:
                exact = incident.title.lower() == text.lower()
                items.append(self._incident_item(incident, "title", exact))
        return items, len(rows) > limit

    @staticmethod
    def _incident_item(incident: Incident, field: str, exact: bool) -> LookupItem:
        status = getattr(incident.status, "value", str(incident.status))
        severity = getattr(incident.severity, "value", str(incident.severity))
        return LookupItem(
            kind="incident",
            id=incident.public_id,
            label=f"INC-{incident.number} · {incident.title}",
            secondary=f"{severity} · {status}",
            match_field=field,
            exact=exact,
            status=status,
            severity=severity,
        )
