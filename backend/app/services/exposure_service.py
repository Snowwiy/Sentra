"""Read side of discovery: an asset's exposure, discovery jobs and scope.

Exposure correlates both views of a managed host: discovery knows a port is reachable;
the agent's inventory knows which process listens on it (pid, name), and its process
snapshot adds the executable and the user. Ports the agent sees listening but the network
cannot reach are reported too (bound to localhost or firewalled), which is as useful to know
as an unexpected open port.
"""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.exceptions import NotFoundError
from app.discovery.ports import SENSITIVE_PORTS, parse_ports
from app.models.discovery import DiscoveryJob
from app.models.exposure import AssetPort, PortStateValue
from app.models.inventory import AssetInventory
from app.models.process import AssetProcessSnapshot
from app.repositories.asset_repository import AssetRepository
from app.schemas.discovery import (
    AgentListener,
    DiscoveryJobList,
    DiscoveryJobRead,
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
        return DiscoveryJobList(
            items=[
                DiscoveryJobRead(
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
                )
                for job in jobs
            ]
        )

    def scope(self) -> DiscoveryScopeRead:
        settings = self._settings
        scope = settings.discovery_scope()
        return DiscoveryScopeRead(
            enabled=scope.enabled,
            allowed_networks=[str(n) for n in scope.allowed],
            excluded=[str(n) for n in scope.excluded],
            ports=list(parse_ports(settings.discovery_ports)),
            interval_minutes=settings.discovery_interval_minutes,
            icmp=settings.discovery_icmp,
            reverse_dns=settings.discovery_reverse_dns,
            timeout_ms=settings.discovery_timeout_ms,
            concurrency=settings.discovery_concurrency,
            max_probes_per_second=settings.discovery_max_probes_per_second,
        )
