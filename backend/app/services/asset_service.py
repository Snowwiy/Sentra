from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import ColumnElement, Select, cast, func, or_, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Session

from app.core.exceptions import AssetLabelConflictError, NotFoundError
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
from app.repositories.alert_repository import escape_like
from app.repositories.asset_repository import (
    AssetRepository,
    effective_status_expr,
    inet_expr,
    sort_columns,
)
from app.repositories.telemetry_repository import TelemetryRepository
from app.schemas.asset import AssetList, AssetRead, ClassificationEvidence, ObservedName
from app.schemas.telemetry import TelemetrySnapshot
from app.services.asset_context_service import filter_statement
from app.services.asset_lifecycle_policy import LifecyclePolicy, evaluate, stale_condition
from app.services.identification import network_adapter_vendor
from app.services.site_service import SiteRef, site_refs

AssetSort = Literal[
    "name",
    "criticality",
    "ip",
    "type",
    "status",
    "method",
    "first_seen",
    "last_seen",
    "network_seen",
    "ports",
]
# Página por defecto de GET /assets cuando el cliente no pide limit (Fase 4M).
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = 500


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
    # Case-insensitive text in the custom label, name, reverse DNS, address or MAC.
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
    # Fase 5C.1: "exclude" (por defecto: lo actual), "include" (Mostrar archivados) u "only".
    archived: str = "exclude"
    # Fase 5C.2: "stale" (stale o candidato a limpieza) o "cleanup_candidate". La condición
    # SQL la pone AssetService porque depende de la política y de la hora.
    lifecycle: str | None = None
    # Fase 5F: id interno del site (None = todos).
    site_id: int | None = None

    def refine(
        self, stmt: Select[Asset], status_expr: ColumnElement[Any], *, with_status: bool = True
    ) -> Select[Asset]:
        """Todos los filtros en SQL (Fase 4M): nada se filtra en Python.

        `with_status=False` deja fuera el filtro de estado, para contar por estado los
        activos del resto de filtros (las tarjetas Online/Offline del dashboard).
        """
        if self.archived == "exclude":
            stmt = stmt.where(Asset.archived_at.is_(None))
        elif self.archived == "only":
            stmt = stmt.where(Asset.archived_at.is_not(None))
        if self.site_id is not None:
            stmt = stmt.where(Asset.site_id == self.site_id)
        if self.method is not None:
            stmt = stmt.where(Asset.monitoring_method == self.method)
        if with_status and self.status is not None:
            stmt = stmt.where(status_expr == self.status.value)
        if self.device_type is not None:
            stmt = stmt.where(func.coalesce(Asset.device_type, "unknown") == self.device_type)
        if self.subnet is not None:
            # <<= : contenida en la red. Filas con una IP inválida (inet NULL) no coinciden.
            stmt = stmt.where(inet_expr().op("<<=")(cast(str(self.subnet), INET)))
        if self.search:
            pattern = "%" + escape_like(self.search.lower()) + "%"
            stmt = stmt.where(
                or_(
                    *(
                        func.lower(column).like(pattern, escape="\\")
                        for column in (
                            Asset.custom_label,
                            Asset.device_name,
                            Asset.hostname,
                            Asset.reverse_dns,
                            Asset.primary_ip,
                            Asset.mac_address,
                            Asset.device_vendor,
                            Asset.vendor,
                        )
                    )
                )
            )
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


def coverage_view(raw: Any) -> dict[str, str] | None:
    """Cobertura guardada → API, solo pares texto/texto acotados (columna JSONB)."""
    if not isinstance(raw, dict):
        return None
    clean = {
        str(k)[:32]: str(v)[:32]
        for k, v in list(raw.items())[:32]
        if isinstance(k, str) and isinstance(v, str)
    }
    return clean or None


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


_NAME_KINDS = frozenset({"agent", "device", "dhcp", "dns", "generic"})


def name_status(asset: Asset, names: list[ObservedName]) -> str:
    """Estado del nombre de un activo (Fase 6D.3). Solo lee lo ya guardado: no resuelve nada.

    "generic_only" distingue el caso de un altavoz que solo anuncia "linux.local" (evidencia
    real, pero que no identifica al equipo) de uno que no respondió a ninguna sonda.
    """
    if asset.custom_label:
        return "labelled"
    if asset.device_name or asset.hostname:
        return "named"
    if names and all(n.kind == "generic" for n in names):
        return "generic_only"
    return "unnamed"


def observed_name_items(raw: Any) -> list[ObservedName]:
    """Nombres observados guardados → API, descartando entradas mal formadas (como
    evidence_items: un JSONB corrupto no debe tirar el listado de activos)."""
    items: list[ObservedName] = []
    for entry in raw if isinstance(raw, list) else ():
        if not isinstance(entry, dict):
            continue
        source, value, kind = entry.get("source"), entry.get("value"), entry.get("kind")
        if not (isinstance(source, str) and isinstance(value, str) and source and value):
            continue
        if kind not in _NAME_KINDS:
            continue
        confirmed = entry.get("confirmed")
        items.append(
            ObservedName(
                source=source[:32],
                value=value[:255],
                kind=kind,
                selected=entry.get("selected") is True,
                confirmed=confirmed if isinstance(confirmed, bool) else None,
                stale=entry.get("stale") is True,
            )
        )
    return items[:16]


class AssetService:
    def __init__(
        self,
        session: Session,
        heartbeat_timeout: timedelta,
        lifecycle: LifecyclePolicy | None = None,
    ) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._telemetry = TelemetryRepository(session)
        self._timeout = heartbeat_timeout
        # Fase 5C.2: sin política explícita (CLI, otros servicios) se usan los valores por
        # defecto, que coinciden con los de config.py.
        self._lifecycle = lifecycle or LifecyclePolicy()
        self._sites: dict[int, SiteRef] | None = None

    def list_assets(
        self,
        f: AssetFilter | None = None,
        sort: AssetSort = "name",
        limit: int = DEFAULT_PAGE_SIZE,
        offset: int = 0,
        descending: bool = False,
    ) -> AssetList:
        """Una página de activos que cumplen el filtro, filtrada, ordenada y paginada en SQL.

        Fase 4M: ya no existe el modo "todos los activos" (con 10 000 activos el dashboard
        tardaba ~1,5 s por descargar y serializar la lista entera). `total` cuenta todos los
        que cumplen el filtro y `status_counts` los reparte por estado ignorando solo el
        filtro de estado (las tarjetas del dashboard).
        """
        f = f or AssetFilter()
        now = datetime.now(UTC)
        status = effective_status_expr(now, self._timeout)
        order = sort_columns(sort, descending, status)
        extra: ColumnElement[bool] | None = None
        if f.lifecycle is not None:
            extra = stale_condition(
                self._lifecycle, now, purgeable_only=f.lifecycle == "cleanup_candidate"
            )

        def refine(stmt: Select[Asset], with_status: bool = True) -> Select[Asset]:
            stmt = f.refine(stmt, status, with_status=with_status)
            return stmt if extra is None else stmt.where(extra)

        assets, total = self._assets.page(refine, order, limit, offset)
        by_status = self._assets.count_by(lambda stmt: refine(stmt, False), status)
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
        return AssetList(
            items=items,
            total=total,
            limit=limit,
            offset=offset,
            status_counts={s.value: by_status.get(s.value, 0) for s in AssetStatus},
        )

    def get_asset(self, public_id: UUID) -> AssetRead:
        asset = self._assets.get_by_public_id(public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        latest = self._telemetry.latest_by_asset([asset.id]).get(asset.id)
        ports = open_ports_by_asset(self._session, [asset.id]).get(asset.id, [])
        risk = risk_by_asset(self._session, [asset.id]).get(asset.id)
        role = context_roles(self._session, [asset.id]).get(asset.id, AssetRole.UNKNOWN)
        return self._to_read(asset, latest, datetime.now(UTC), ports, risk, role)

    def set_label(
        self, public_id: UUID, label: str | None, version: int, actor_name: str
    ) -> tuple[Asset, str | None]:
        """Guarda (o elimina, con None) la etiqueta personalizada. No hace commit.

        La fila se bloquea (FOR UPDATE) y se compara la versión que leyó el cliente: de dos
        ediciones simultáneas, la segunda espera a la primera y recibe 409 en vez de pisarla.
        Devuelve el activo y la etiqueta anterior (para la auditoría). Guardar el mismo valor
        no cambia la versión ni la fecha: no es una modificación.
        """
        asset = self._session.scalar(
            select(Asset).where(Asset.public_id == public_id).with_for_update()
        )
        if asset is None:
            raise NotFoundError("Asset not found")
        if asset.custom_label_version != version:
            raise AssetLabelConflictError(
                "The asset label changed since it was read",
                details=[
                    {
                        "current_version": asset.custom_label_version,
                        "custom_label": asset.custom_label,
                    }
                ],
            )
        previous = asset.custom_label
        if previous != label:
            asset.custom_label = label
            asset.custom_label_version = version + 1
            asset.custom_label_updated_at = datetime.now(UTC)
            asset.custom_label_updated_by = actor_name[:64]
        return asset, previous

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
        current = effective_status(asset, now, self._timeout)
        names = observed_name_items(asset.observed_names)
        lifecycle = evaluate(asset, now, self._lifecycle, online=current == AssetStatus.ONLINE)
        return AssetRead(
            asset_id=asset.public_id,
            display_name=asset.display_name,
            custom_label=asset.custom_label,
            custom_label_version=asset.custom_label_version or 0,
            custom_label_updated_at=asset.custom_label_updated_at,
            custom_label_updated_by=asset.custom_label_updated_by,
            monitoring_method=asset.monitoring_method,
            hostname=asset.hostname,
            os_name=asset.os_name,
            os_version=asset.os_version,
            architecture=asset.architecture,
            primary_ip=asset.primary_ip,
            agent_version=asset.agent_version,
            status=current,
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
            observed_names=names,
            name_status=name_status(asset, names),
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
            archived_at=asset.archived_at,
            archived_by=asset.archived_by,
            archive_reason=asset.archive_reason,
            lifecycle_version=asset.lifecycle_version,
            managed_history=asset.ever_managed or asset.agent_id is not None,
            event_coverage=coverage_view(asset.event_coverage),
            event_coverage_at=asset.event_coverage_at,
            lifecycle_state=lifecycle.state.value,
            lifecycle_source=lifecycle.source.value,
            missed_discovery_scans=asset.network_misses or 0,
            last_activity_at=lifecycle.last_activity_at,
            site_id=self._site(asset.site_id).public_id,
            site_name=self._site(asset.site_id).name,
        )

    def _site(self, site_id: int) -> SiteRef:
        # Los sites son pocos: una consulta por petición, no una por activo.
        if self._sites is None or site_id not in self._sites:
            self._sites = site_refs(self._session)
        return self._sites[site_id]
