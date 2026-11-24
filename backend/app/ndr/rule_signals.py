"""Señales ndr_dns para reglas personalizadas y Sigma (Fase 7E.5).

Una consulta DNS de un activo inventariado del site se convierte en señal NDR_DNS del motor
de detección SOLO si hay alguna regla activa del logsource ndr_dns (misma idea que los eventos
en bruto de la Fase 5A): sin reglas, ni una fila. Las consultas ya llegan agregadas por
ventana del sensor (cliente, resolvedor, nombre, tipo), así que una señal resume muchas.
"""

from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.custom.runtime import active_logsources
from app.detection.signals import SignalKind, SourceType
from app.models.detection import DetectionSignal
from app.ndr.addresses import is_internal
from app.ndr.anomalies import resolve_asset
from app.ndr.ingest import IngestedBatch

MAX_DNS_SIGNALS_PER_BATCH = 500
DNS_LOGSOURCE = "ndr_dns"


def record_rule_signals(session: Session, settings: Settings, batch: IngestedBatch) -> None:
    if not batch.dns or DNS_LOGSOURCE not in active_logsources(session):
        return
    assets: dict[str, int | None] = {}
    now = datetime.now(UTC)
    emitted = 0
    for dns in batch.dns:
        if emitted >= MAX_DNS_SIGNALS_PER_BATCH:
            break
        if not dns.qname or not is_internal(dns.client_ip):
            continue
        if dns.client_ip not in assets:
            assets[dns.client_ip] = resolve_asset(session, batch.site.id, dns.client_ip, None)
        asset_id = assets[dns.client_ip]
        if asset_id is None:
            continue
        rcode = max(dns.rcodes.items(), key=lambda item: item[1])[0] if dns.rcodes else None
        session.add(
            DetectionSignal(
                asset_id=asset_id,
                kind=SignalKind.NDR_DNS.value,
                subject=dns.qname[:255],
                occurred_at=dns.last_seen,
                source_type=SourceType.NDR.value,
                source_id=None,
                data={
                    "qname": dns.qname,
                    "qtype": dns.qtype,
                    "client_ip": dns.client_ip,
                    "resolver_ip": dns.resolver_ip,
                    "rcode": rcode,
                    "queries": dns.queries,
                    "sensor": batch.sensor.name[:100],
                },
                created_at=now,
            )
        )
        emitted += 1
