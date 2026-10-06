import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.core.exceptions import NotFoundError
from app.discovery.targets import IPNetwork
from app.models.asset import Asset, AssetCriticality, AssetStatus, MonitoringMethod
from app.models.asset_context import (
    AssetBusinessContext,
    AssetEnvironment,
    AssetRole,
    DataSensitivity,
    NetworkZone,
)
from app.models.exposure import AssetPort, PortStateValue
from app.models.risk import AssetRisk
from app.models.telemetry import TelemetrySample
from app.repositories.asset_repository import AssetRepository
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.asset import AssetList, AssetRead, ClassificationEvidence
from app.schemas.telemetry import TelemetrySnapshot
from app.services.asset_context_service import filter_statement
from app.services.identification import network_adapter_vendor

AssetSort = Literal["name", "criticality"]
_CRITICALITY_RANK = {c: rank for rank, c in enumerate(AssetCriticality)}


def effective_status(asset: Asset, now: datetime, timeout: timedelta) -> AssetStatus:
    """Resolve the status shown to clients from the stored status and last contact time.

    Offline is derived here instead of being written by a background job: an agent that dies
    cannot report its own death, and computing it on read keeps the API correct without a
    scheduler. The stored `status` therefore only reflects the last agent activity; any future
    query that filters by status in SQL must apply the same timeout rule.
    """
    if not asset.is_managed:
        # No agent: what the network says (unknown until a discovery run saw it).
        return asset.network_status or AssetStatus.UNKNOWN
    # Registered but never reported: we cannot claim it is up or down.
    if asset.last_seen_at is None:
        return AssetStatus.UNKNOWN
    if now - asset.last_seen_at > timeout:
        return AssetStatus.OFFLINE
    return asset.status


@dataclass(frozen=True)
class AssetFilter:
    method: MonitoringMethod | None = None
    status: AssetStatus | None = None
    device_type: str | None = None
    subnet: IPNetwork | None = None
    # Case-insensitive text in the name, reverse DNS, address or MAC.
    search: str | None = None
    # Fase 4L: filtros de contexto. Se aplican en SQL (filter_statement); "unknown" incluye
    # a los activos sin contexto guardado.
    criticality: AssetCriticality | None = None
    role: AssetRole | None = None
    environment: AssetEnvironment | None = None
    network_zone: NetworkZone | None = None
    data_sensitivity: DataSensitivity | None = None
    # "true", "false" o "unknown" (tri-estado: unknown no es false).
    internet_exposed: str | None = None
    department: str | None = None
    tag: str | None = None

    @property
    def sql_only(self) -> bool:
        """True si ningún filtro necesita Python (estado efectivo, subred, búsqueda...)."""
        return (
            self.method is None
            and self.status is None
            and self.device_type is None
            and self.subnet is None
            and not self.search
        )

    def refine(self, stmt: Select[Asset]) -> Select[Asset]:
        if self.criticality is not None:
            stmt = stmt.where(Asset.criticality == self.criticality)
        return filter_statement(
            stmt,
            role=self.role,
            environment=self.environment,
            network_zone=self.network_zone,
            data_sensitivity=self.data_sensitivity,
            internet_exposed=self.internet_exposed,
            department=self.department,
            tag=self.tag,
        )

    def matches(self, asset: Asset, status: AssetStatus) -> bool:
        if self.method is not None and asset.monitoring_method != self.method:
            return False
        if self.status is not None and status != self.status:
            return False
        if self.device_type is not None and (asset.device_type or "unknown") != self.device_type:
            return False
        if self.subnet is not None:
            try:
                address = ipaddress.ip_address(asset.primary_ip)
            except ValueError:
                return False
            if address.version != self.subnet.version or address not in self.subnet:
                return False
        if self.search:
            needle = self.search.lower()
            fields = (
                asset.device_name,
                asset.hostname,
                asset.reverse_dns,
                asset.primary_ip,
                asset.mac_address,
                asset.device_vendor,
                asset.vendor,
            )
            return any(needle in (value or "").lower() for value in fields)
        return True


def open_ports_by_asset(session: Session, asset_ids: Iterable[int]) -> dict[int, list[int]]:
    """Open TCP ports per asset in one query (no query per asset)."""
    ids = list(asset_ids)
    if not ids:
        return {}
    rows = session.execute(
        select(AssetPort.asset_id, func.array_agg(AssetPort.port).label("ports"))
        .where(
            AssetPort.asset_id.in_(ids),
            AssetPort.state == PortStateValue.OPEN,
            AssetPort.protocol == "tcp",
        )
        .group_by(AssetPort.asset_id)
    )
    return {asset_id: sorted(ports) for asset_id, ports in rows}


def context_roles(session: Session, asset_ids: list[int]) -> dict[int, AssetRole]:
    """Rol confirmado de varios activos en una consulta (Fase 4L, columna compacta)."""
    if not asset_ids:
        return {}
    rows = session.execute(
        select(AssetBusinessContext.asset_id, AssetBusinessContext.role).where(
            AssetBusinessContext.asset_id.in_(asset_ids)
        )
    )
    return {asset_id: role for asset_id, role in rows}


def risk_by_asset(session: Session, asset_ids: list[int]) -> dict[int, AssetRisk]:
    """Riesgo ya calculado de varios activos en una consulta (sin N+1). Solo lectura: las
    filas devueltas no están en la sesión (no se modifican ni se guardan)."""
    if not asset_ids:
        return {}
    rows = session.execute(
        select(AssetRisk.asset_id, AssetRisk.score, AssetRisk.level, AssetRisk.confidence).where(
            AssetRisk.asset_id.in_(asset_ids), AssetRisk.calculated_at.is_not(None)
        )
    ).all()
    return {
        row.asset_id: AssetRisk(
            asset_id=row.asset_id, score=row.score, level=row.level, confidence=row.confidence
        )
        for row in rows
    }


def evidence_items(raw: Any) -> list[ClassificationEvidence]:
    """Evidencias guardadas → API, descartando entradas mal formadas.

    La columna es JSONB y la escribe solo el servidor, pero un dato corrupto (edición manual,
    versión futura con otra forma) no debe tirar con un 500 el listado de activos entero.
    """
    items: list[ClassificationEvidence] = []
    for entry in raw if isinstance(raw, list) else ():
        if isinstance(entry, dict):
            source, value = entry.get("source"), entry.get("value")
            if isinstance(source, str) and isinstance(value, str) and source and value:
                items.append(ClassificationEvidence(source=source[:32], value=value[:255]))
    return items


class AssetService:
    def __init__(self, session: Session, heartbeat_timeout: timedelta) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._timeout = heartbeat_timeout

    def list_assets(
        self,
        f: AssetFilter | None = None,
        sort: AssetSort = "name",
        limit: int | None = None,
        offset: int = 0,
    ) -> AssetList:
        """Activos que cumplen el filtro. Sin `limit` devuelve todos (contrato previo a 4L);
        con `limit`/`offset` pagina y `total` sigue contando todos los que cumplen."""
        f = f or AssetFilter()
        now = datetime.now(UTC)
        if limit is not None and f.sql_only:
            # Con 10 000 activos, paginar en SQL evita cargar todos en memoria por página.
            page, total = self._assets.page(f.refine, sort == "criticality", limit, offset)
            assets = list(page)
        else:
            # Status is resolved at read time (see effective_status), so filtering happens here.
            assets = [
                asset
                for asset in self._assets.list_all(f.refine)
                if f.matches(asset, effective_status(asset, now, self._timeout))
            ]
            if sort == "criticality":
                # Estable: dentro de la misma criticidad se conserva el orden por nombre.
                assets.sort(key=lambda a: -_CRITICALITY_RANK[a.criticality])
            total = len(assets)
            if limit is not None:
                assets = assets[offset : offset + limit]
        # Datos derivados solo de la página (una consulta por tipo, sin N+1).
        latest = self._telemetry.latest_by_asset(asset.id for asset in assets)
        ports = open_ports_by_asset(self._session, (asset.id for asset in assets))
        risks = risk_by_asset(self._session, [asset.id for asset in assets])
        roles = context_roles(self._session, [asset.id for asset in assets])
        items = [
            self._to_read(
                asset,
                latest.get(asset.id),
                now,
                ports.get(asset.id, []),
                risks.get(asset.id),
                roles.get(asset.id, AssetRole.UNKNOWN),
            )
            for asset in assets
        ]
        return AssetList(items=items, total=total)

    def get_asset(self, public_id: UUID) -> AssetRead:
        asset = self._assets.get_by_public_id(public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        latest = self._telemetry.latest_by_asset([asset.id]).get(asset.id)
        ports = open_ports_by_asset(self._session, [asset.id]).get(asset.id, [])
        risk = risk_by_asset(self._session, [asset.id]).get(asset.id)
        role = context_roles(self._session, [asset.id]).get(asset.id, AssetRole.UNKNOWN)
        return self._to_read(asset, latest, datetime.now(UTC), ports, risk, role)

    def _to_read(
        self,
        asset: Asset,
        latest: TelemetrySample | None,
        now: datetime,
        open_ports: list[int],
        risk: AssetRisk | None = None,
        role: AssetRole = AssetRole.UNKNOWN,
    ) -> AssetRead:
        agent_status = effective_status(asset, now, self._timeout) if asset.is_managed else None
        return AssetRead(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            monitoring_method=asset.monitoring_method,
            hostname=asset.hostname,
            os_name=asset.os_name,
            os_version=asset.os_version,
            architecture=asset.architecture,
            primary_ip=asset.primary_ip,
            agent_version=asset.agent_version,
            status=effective_status(asset, now, self._timeout),
            agent_status=agent_status,
            network_status=asset.network_status,
            first_seen_at=asset.first_seen_at,
            last_seen_at=asset.last_seen_at,
            created_at=asset.created_at,
            updated_at=asset.updated_at,
            latest_telemetry=TelemetrySnapshot.model_validate(latest) if latest else None,
            mac_address=asset.mac_address,
            reverse_dns=asset.reverse_dns,
            vendor=asset.vendor,
            network_adapter_vendor=network_adapter_vendor(asset),
            device_type=asset.device_type,
            device_type_reason=asset.device_type_reason,
            device_name=asset.device_name,
            name_source=asset.name_source,
            device_vendor=asset.device_vendor,
            device_model=asset.device_model,
            probable_os=asset.probable_os,
            classification_confidence=asset.classification_confidence,
            classification_evidence=evidence_items(asset.classification_evidence),
            discovery_sources=asset.discovery_sources or [],
            discovery_network=asset.discovery_network,
            discovered_at=asset.discovered_at,
            last_network_seen_at=asset.last_network_seen_at,
            open_ports=open_ports,
            criticality=asset.criticality,
            role=role,
            risk_score=risk.score if risk else None,
            risk_level=risk.level if risk else None,
            risk_confidence=risk.confidence if risk else None,
        )
