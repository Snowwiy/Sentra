from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import ColumnElement, Select, String, case, cast, func, literal, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session

from app.models.asset import Asset, AssetCriticality
from app.models.exposure import AssetPort, PortStateValue

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


def effective_status_expr(now: datetime, timeout: timedelta) -> ColumnElement[Any]:
    """Estado efectivo en SQL (Fase 4M): misma regla que services.asset_service.effective_status.

    Permite filtrar, ordenar y contar por estado en PostgreSQL en vez de cargar todos los
    activos en Python. Si se cambia una de las dos, hay que cambiar la otra (lo comprueba
    tests/test_production.py con activos de cada caso).
    """
    stale_before = now - timeout
    return case(
        # Sin agente: lo que dice la red (unknown hasta que un discovery lo vio).
        (Asset.agent_id.is_(None), func.coalesce(cast(Asset.network_status, String), "unknown")),
        # Registrado pero nunca informó.
        (Asset.last_seen_at.is_(None), literal("unknown")),
        (Asset.last_seen_at < stale_before, literal("offline")),
        else_=cast(Asset.status, String),
    )


def inet_expr() -> ColumnElement[Any]:
    """primary_ip como inet, o NULL si el texto no es una IP válida.

    pg_input_is_valid (PostgreSQL 16+) evita que un valor corrupto haga fallar toda la
    consulta con un error de conversión; CASE evalúa la conversión solo para filas válidas.
    """
    return case(
        (func.pg_input_is_valid(Asset.primary_ip, "inet"), cast(Asset.primary_ip, INET)),
        else_=None,
    )


def open_tcp_ports_count() -> ColumnElement[Any]:
    return (
        select(func.count())
        .where(
            AssetPort.asset_id == Asset.id,
            AssetPort.state == PortStateValue.OPEN,
            AssetPort.protocol == "tcp",
        )
        .correlate(Asset)
        .scalar_subquery()
    )


def sort_columns(sort: str, descending: bool, status: ColumnElement[Any]) -> list[Any]:
    """ORDER BY de los listados de activos. Siempre termina en el orden por nombre e id para
    que la paginación sea estable (sin filas repetidas ni saltadas entre páginas)."""
    key: Any
    match sort:
        case "criticality":
            # Más crítico primero; "desc" invierte (los menos críticos primero).
            return [_CRITICALITY_ORDER.desc() if descending else _CRITICALITY_ORDER, *_NAME_ORDER]
        case "ip":
            key = inet_expr()
        case "type":
            key = Asset.device_type
        case "status":
            key = status
        case "method":
            key = cast(Asset.monitoring_method, String)
        case "first_seen":
            key = func.coalesce(Asset.discovered_at, Asset.first_seen_at)
        case "last_seen":
            key = func.coalesce(Asset.last_seen_at, Asset.last_network_seen_at)
        case "network_seen":
            key = Asset.last_network_seen_at
        case "ports":
            key = open_tcp_ports_count()
        case _:
            if descending:
                return [
                    Asset.device_name.desc().nulls_last(),
                    Asset.hostname.desc().nulls_last(),
                    Asset.reverse_dns.desc().nulls_last(),
                    Asset.primary_ip.desc(),
                    Asset.id.desc(),
                ]
            return list(_NAME_ORDER)
    # Los valores ausentes van al final en ambas direcciones (como en el frontend).
    ordered = key.desc().nulls_last() if descending else key.asc().nulls_last()
    return [ordered, *_NAME_ORDER]


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
        order: list[Any],
        limit: int,
        offset: int,
    ) -> tuple[Sequence[Asset], int]:
        """Una página ordenada y el total que cumple el filtro, todo en SQL (Fase 4L/4M)."""
        stmt = refine(select(Asset))
        total = self._session.scalar(select(func.count()).select_from(stmt.subquery())) or 0
        rows = self._session.scalars(stmt.order_by(*order).limit(limit).offset(offset)).all()
        return rows, total

    def count_by(
        self, refine: Callable[[Select[Asset]], Select[Asset]], column: ColumnElement[Any]
    ) -> dict[str, int]:
        """Recuento agrupado (p. ej. por estado efectivo) sobre los activos del filtro."""
        bucket = column.label("bucket")
        # Mismos FROM/JOIN/WHERE que el listado, solo con la columna y el recuento.
        stmt = (
            refine(select(Asset))
            .with_only_columns(bucket, func.count(), maintain_column_froms=True)
            .group_by(bucket)
        )
        return {str(value): count for value, count in self._session.execute(stmt)}
