"""Retención de los datos de la Fase 6E (docs/fase-6e-recovery.md).

Un único punto de entrada para el job de retención: cada módulo nuevo añade aquí su purga,
con su propio plazo y sus propias exclusiones (lo preservado por incidentes o investigaciones
nunca se borra). Se mantiene separado de RetentionService porque aquellas retenciones son
opt-in (4M) y estas vienen activas por defecto para acotar el crecimiento.
"""

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.dhcp.service import purge_dhcp
from app.endpoint.service import purge_endpoint
from app.topology.history_service import purge_topology_history


def phase_6e_retention_enabled(settings: Settings) -> bool:
    """¿Hay alguna retención de 6E configurada? Decide si el job de retención se arranca
    aunque las retenciones opt-in de 4M estén todas apagadas."""
    return any(
        days is not None
        for days in (
            settings.topology_build_retention_days,
            settings.topology_snapshot_retention_days,
            settings.network_change_retention_days,
            settings.topology_absent_link_retention_days,
            settings.dhcp_lease_retention_days,
            settings.asset_identity_history_retention_days,
            settings.telemetry_activity_retention_days,
            settings.process_instance_retention_days,
        )
    )


def purge_phase_6e(
    session: Session, settings: Settings, now: datetime | None = None
) -> dict[str, int]:
    now = now or datetime.now(UTC)
    out: dict[str, int] = {}
    out.update(purge_topology_history(session, settings, now))
    out.update(purge_dhcp(session, settings, now))
    out.update(purge_endpoint(session, settings, now))
    session.commit()
    return out
