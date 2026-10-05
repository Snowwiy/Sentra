"""Read side of discovery: an asset's exposure, discovery jobs and scope.

Exposure correlates both views of a managed host: discovery knows a port is reachable;
the agent's inventory knows which process listens on it (pid, name), and its process
snapshot adds the executable and the user. Ports the agent sees listening but the network
cannot reach are reported too (bound to localhost or firewalled), which is as useful to know
as an unexpected open port.
"""

import ipaddress
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Row, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NotFoundError
from app.discovery.ports import SENSITIVE_PORTS, parse_ports
from app.models.asset import Asset
from app.models.change import AssetChange
from app.models.discovery import ACTIVE_JOB_STATUSES, DiscoveryJob, DiscoveryTrigger
from app.models.exposure import AssetPort, PortStateValue
from app.models.inventory import AssetInventory
from app.models.process import AssetProcessSnapshot
from app.repositories.asset_repository import AssetRepository
from app.schemas.discovery import (
    AgentListener,
    DiscoveryAssetRef,
    DiscoveryChangeRead,
    DiscoveryJobDetail,
    DiscoveryJobList,
    DiscoveryJobRead,
    DiscoveryNetworkRead,
    DiscoveryProgressRead,
    DiscoveryScheduleRead,
    DiscoveryScopeRead,
    ExposedPort,
    ExposureRead,
    PortProcess,
)


class ExposureService:
    def __init__(self, session: Session, settings: Settings) -> None:
        self._session = session
        self._assets = AssetRepository(session)
        self._settings = settings

    def exposure(self, asset_public_id: UUID) -> ExposureRead:
        asset = self._assets.get_by_public_id(asset_public_id)
        if asset is None:
            raise NotFoundError("Asset not found")
        rows = self._session.scalars(
            select(AssetPort).where(AssetPort.asset_id == asset.id).order_by(AssetPort.port)
        ).all()
        listeners = self._listeners(asset.id)
        ports = [
            ExposedPort(
                protocol=row.protocol,
                port=row.port,
                state=row.state,
                service_hint=row.service_hint,
                sensitive=row.port in SENSITIVE_PORTS,
                first_seen_at=row.first_seen_at,
                opened_at=row.opened_at,
                last_seen_at=row.last_seen_at,
                closed_at=row.closed_at,
                process=listeners.get((row.protocol, row.port)),
            )
            for row in rows
        ]
        open_ports = {(r.protocol, r.port) for r in rows if r.state == PortStateValue.OPEN}
        probed = set(parse_ports(self._settings.discovery_ports))
        scanned = asset.exposure_baseline_at is not None
        agent_listeners = [
            AgentListener(
                protocol=protocol,
                port=port,
                process=process,
                exposed=(
                    True
                    if (protocol, port) in open_ports
                    else (False if scanned and protocol == "tcp" and port in probed else None)
                ),
            )
            for (protocol, port), process in sorted(listeners.items())
        ]
        return ExposureRead(
            asset_id=asset.public_id,
            baseline_at=asset.exposure_baseline_at,
            last_network_seen_at=asset.last_network_seen_at,
            ports=ports,
            agent_listeners=agent_listeners,
        )

    def _listeners(self, asset_id: int) -> dict[tuple[str, int], PortProcess]:
        """Listening sockets from the agent's latest inventory, enriched with its processes."""
        inventory = self._session.get(AssetInventory, asset_id)
        if inventory is None:
            return {}
        snapshot = self._session.get(AssetProcessSnapshot, asset_id)
        processes: dict[int, dict[str, Any]] = {}
        if snapshot is not None:
            for process in snapshot.data.get("processes") or []:
                if isinstance(process, dict) and isinstance(process.get("pid"), int):
                    processes[process["pid"]] = process
        listeners: dict[tuple[str, int], PortProcess] = {}
        for connection in inventory.data.get("connections") or []:
            if not isinstance(connection, dict) or connection.get("status") != "listen":
                continue
            port = connection.get("local_port")
            protocol = connection.get("protocol") or "tcp"
            if not isinstance(port, int) or (protocol, port) in listeners:
                continue
            pid = connection.get("pid") if isinstance(connection.get("pid"), int) else None
            details = processes.get(pid, {}) if pid is not None else {}
            listeners[(protocol, port)] = PortProcess(
                pid=pid,
                name=connection.get("process_name") or details.get("name"),
                exe=details.get("exe"),
                username=details.get("username"),
                local_address=connection.get("local_address"),
            )
        return listeners

    # --- discovery jobs and scope ------------------------------------------------------------

    def jobs(self, limit: int) -> DiscoveryJobList:
        jobs = self._session.scalars(
            select(DiscoveryJob)
            .order_by(DiscoveryJob.started_at.desc(), DiscoveryJob.id.desc())
            .limit(limit)
        ).all()
        return DiscoveryJobList(items=[_job_read(job) for job in jobs])

    def job(self, public_id: UUID) -> DiscoveryJobDetail:
        job = self._session.scalar(select(DiscoveryJob).where(DiscoveryJob.public_id == public_id))
        if job is None:
            raise NotFoundError("Discovery job not found")
        new_assets: list[DiscoveryAssetRef] = []
        if job.new_asset_ids:
            ids = [UUID(value) for value in job.new_asset_ids]
            assets = self._session.scalars(select(Asset).where(Asset.public_id.in_(ids))).all()
            # Puede haber menos que ids: un activo nuevo pudo fusionarse después con el
            # registro de su agente (reconciliación) o borrarse.
            new_assets = [
                DiscoveryAssetRef(
                    asset_id=a.public_id,
                    display_name=a.display_name,
                    primary_ip=a.primary_ip,
                    mac_address=a.mac_address,
                    device_type=a.device_type,
                    monitoring_method=a.monitoring_method,
                )
                for a in sorted(assets, key=lambda a: ipaddress_key(a.primary_ip))
            ]
        rows: Sequence[Row[AssetChange, Asset]] = []
        # Los cambios se escriben al terminar el job. La ventana de fechas usa el índice
        # ix_asset_changes_detected y el id del job en details descarta los de otros jobs
        # simultáneos; así el detalle, que la web consulta cada pocos segundos, es barato.
        if job.completed_at is not None:
            rows = self._session.execute(
                select(AssetChange, Asset)
                .join(Asset, Asset.id == AssetChange.asset_id)
                .where(
                    AssetChange.detected_at >= job.started_at,
                    AssetChange.detected_at <= job.completed_at,
                    AssetChange.details["discovery_job_id"].astext == str(job.public_id),
                )
                .order_by(AssetChange.id)
                .limit(MAX_JOB_CHANGES)
            ).all()
        changes = [
            DiscoveryChangeRead(
                asset_id=asset.public_id,
                display_name=asset.display_name,
                primary_ip=asset.primary_ip,
                category=change.category,
                kind=change.kind,
                item=change.item,
                detected_at=change.detected_at,
            )
            for change, asset in rows
        ]
        return DiscoveryJobDetail(
            **_job_read(job).model_dump(), new_assets=new_assets, changes=changes
        )

    def scope(self) -> DiscoveryScopeRead:
        settings = self._settings
        scope = settings.discovery_scope()
        return DiscoveryScopeRead(
            enabled=scope.enabled,
            allowed_networks=[str(n) for n in scope.allowed],
            networks=[
                DiscoveryNetworkRead(network=str(n), hosts=sum(1 for _ in scope.hosts(n)))
                for n in scope.allowed
            ],
            max_hosts_per_network=scope.max_hosts,
            excluded=[str(n) for n in scope.excluded],
            ports=list(parse_ports(settings.discovery_ports)),
            interval_minutes=settings.discovery_interval_minutes,
            icmp=settings.discovery_icmp,
            reverse_dns=settings.discovery_reverse_dns,
            timeout_ms=settings.discovery_timeout_ms,
            concurrency=settings.discovery_concurrency,
            max_probes_per_second=settings.discovery_max_probes_per_second,
        )

    def schedule(self, next_run_at: datetime | None, running: bool) -> DiscoveryScheduleRead:
        """Estado del scheduler. `next_run_at`/`running` los aporta el PeriodicJob de este
        proceso (no se guardan en la base de datos)."""
        settings = self._settings
        reason = None
        if not settings.discovery_scope().enabled:
            reason = "no_networks"
        elif not settings.discovery_interval_minutes:
            reason = "no_interval"
        elif not settings.background_jobs_enabled:
            reason = "background_jobs_disabled"
        last = self._session.scalar(
            select(DiscoveryJob)
            .where(DiscoveryJob.trigger == DiscoveryTrigger.SCHEDULED)
            .order_by(DiscoveryJob.started_at.desc(), DiscoveryJob.id.desc())
            .limit(1)
        )
        return DiscoveryScheduleRead(
            enabled=reason is None,
            disabled_reason=reason,
            interval_minutes=settings.discovery_interval_minutes,
            last_run_at=last.started_at if last else None,
            last_run_status=last.status if last else None,
            next_run_at=next_run_at if reason is None else None,
            running=running,
        )


# Cambios que devuelve el detalle de un job; un scan normal produce muchos menos.
MAX_JOB_CHANGES = 1000


def ipaddress_key(address: str) -> tuple[int, int]:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return (9, 0)
    return (ip.version, int(ip))


def _job_read(job: DiscoveryJob) -> DiscoveryJobRead:
    finished = job.status not in ACTIVE_JOB_STATUSES
    progress = job.progress if job.status in ACTIVE_JOB_STATUSES else None
    return DiscoveryJobRead(
        job_id=job.public_id,
        target=job.target,
        trigger=job.trigger,
        status=job.status,
        baseline=job.baseline,
        started_at=job.started_at,
        completed_at=job.completed_at,
        duration_seconds=job.duration_seconds,
        hosts_scanned=job.hosts_scanned,
        hosts_alive=job.hosts_alive,
        hosts_new=job.hosts_new,
        open_ports=job.open_ports,
        probes=job.probes,
        error_count=job.error_count,
        errors=job.errors or [],
        requested_via=job.requested_via,
        hosts_total=job.hosts_total,
        # Vistos y ya conocidos = vivos - nuevos; solo tiene sentido con el job terminado.
        hosts_updated=max(job.hosts_alive - job.hosts_new, 0) if finished else None,
        ports_opened=job.ports_opened,
        ports_closed=job.ports_closed,
        cancel_requested=job.cancel_requested_at is not None,
        stop_reason=job.stop_reason,
        progress=DiscoveryProgressRead.model_validate(progress) if progress else None,
        parameters=job.parameters,
    )
