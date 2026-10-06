from collections.abc import Callable, Sequence
from uuid import UUID

from sqlalchemy import Select, case, func, select
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality

# Los activos sin nombre resuelto se ordenan por dirección detrás de los nombrados.
_NAME_ORDER = (
    Asset.device_name.asc().nulls_last(),
    Asset.hostname.asc().nulls_last(),
    Asset.reverse_dns.asc().nulls_last(),
    Asset.primary_ip,
    Asset.id,
)
# Rango explícito (no el orden interno del enum de PostgreSQL): critical primero.
_CRITICALITY_ORDER = case(
    {c: -rank for rank, c in enumerate(AssetCriticality)}, value=Asset.criticality
)


class AssetRepository:
    def __init__(self, session: Session) -> None:
        self._session = session

    def add(self, asset: Asset) -> Asset:
        self._session.add(asset)
        return asset

    def get_by_public_id(self, public_id: UUID) -> Asset | None:
        return self._session.scalar(select(Asset).where(Asset.public_id == public_id))

    def get_by_agent_id(self, agent_id: UUID) -> Asset | None:
        return self._session.scalar(select(Asset).where(Asset.agent_id == agent_id))

    def list_all(
        self, refine: Callable[[Select[Asset]], Select[Asset]] | None = None
    ) -> Sequence[Asset]:
        """Todos los activos en orden de nombre; `refine` añade filtros SQL (Fase 4L)."""
        stmt = select(Asset)
        if refine is not None:
            stmt = refine(stmt)
        return self._session.scalars(stmt.order_by(*_NAME_ORDER)).all()

    def page(
        self,
        refine: Callable[[Select[Asset]], Select[Asset]],
        by_criticality: bool,
        limit: int,
        offset: int,
    ) -> tuple[Sequence[Asset], int]:
        """Una página ordenada y el total, todo en SQL (Fase 4L).

        Solo sirve cuando todos los filtros son SQL: el estado efectivo se calcula en Python,
        así que con filtro de estado hay que seguir usando list_all.
        """
        stmt = refine(select(Asset))
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        order = [_CRITICALITY_ORDER, *_NAME_ORDER] if by_criticality else _NAME_ORDER
        rows = self._session.scalars(stmt.order_by(*order).limit(limit).offset(offset)).all()
        return rows, total
