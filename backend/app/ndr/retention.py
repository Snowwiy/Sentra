"""Retención de NDR (Fase 7E). Los flujos son lo voluminoso: activa por defecto (7 días)."""

from datetime import datetime, timedelta

from sqlalchemy import delete
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import (
    NdrAnomaly,
    NdrBaseline,
    NdrBatch,
    NdrFlow,
    NdrIpMacBinding,
    NdrProtocolObservation,
)


def ndr_retention_enabled(settings: Settings) -> bool:
    return any(
        days is not None
        for days in (
            settings.ndr_flow_retention_days,
            settings.ndr_observation_retention_days,
            settings.ndr_batch_retention_days,
            settings.ndr_anomaly_retention_days,
            settings.ndr_binding_retention_days,
        )
    )


def purge_ndr(session: Session, settings: Settings, now: datetime) -> dict[str, int]:
    counts: dict[str, int] = {}
    for key, days, model, column in (
        ("ndr_flows", settings.ndr_flow_retention_days, NdrFlow, NdrFlow.last_seen),
        (
            "ndr_protocol_observations",
            settings.ndr_observation_retention_days,
            NdrProtocolObservation,
            NdrProtocolObservation.last_seen,
        ),
        ("ndr_batches", settings.ndr_batch_retention_days, NdrBatch, NdrBatch.received_at),
    ):
        if days is None:
            continue
        result = session.execute(delete(model).where(column < now - timedelta(days=days)))
        counts[key] = int(getattr(result, "rowcount", 0) or 0)
    if settings.ndr_binding_retention_days is not None:
        cutoff = now - timedelta(days=settings.ndr_binding_retention_days)
        result = session.execute(delete(NdrIpMacBinding).where(NdrIpMacBinding.last_seen < cutoff))
        counts["ndr_ip_mac_bindings"] = int(getattr(result, "rowcount", 0) or 0)
        # 7E.3: líneas base de equipos que dejaron de verse (mismo plazo que las asociaciones;
        # un equipo que vuelve reaprende desde cero en lugar de compararse con datos viejos).
        result = session.execute(delete(NdrBaseline).where(NdrBaseline.updated_at < cutoff))
        counts["ndr_baselines"] = int(getattr(result, "rowcount", 0) or 0)
    if settings.ndr_anomaly_retention_days is not None:
        # Solo cerradas: una anomalía abierta es trabajo pendiente y nunca caduca sola.
        cutoff = now - timedelta(days=settings.ndr_anomaly_retention_days)
        result = session.execute(
            delete(NdrAnomaly).where(
                NdrAnomaly.status.in_(("resolved", "false_positive")),
                NdrAnomaly.last_seen < cutoff,
            )
        )
        counts["ndr_anomalies"] = int(getattr(result, "rowcount", 0) or 0)
    return counts
