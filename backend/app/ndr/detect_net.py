"""Reglas de protocolos y movimiento sobre los flujos de cada lote NDR (Fase 7E.3).

Se evalúan con los flujos del lote (una ventana de exportación del sensor). Un flujo visto a
medias (`midstream`) nunca cuenta como intento fallido: solo los que empezaron con SYN dentro
de la captura y no tuvieron respuesta (`no_handshake_reply`) o fueron rechazados (RST).
"""

from collections import defaultdict
from datetime import datetime

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.discovery import DiscoveryJob, DiscoveryJobStatus
from app.ndr.addresses import is_internal
from app.ndr.anomalies import Finding, record_finding
from app.ndr.ingest import IngestedBatch
from app.ndr.rules import PROTO_001, PROTO_002, SCAN_001
from app.schemas.ndr import NdrFlowIn

SCAN_SUSPICIOUS = 50
SCAN_PROBABLE = 200
LATERAL_SUSPICIOUS = 5
LATERAL_PROBABLE = 15
MAX_EXAMPLES = 10
# Servicios en claro: (transporte, puerto) -> etiqueta.
CLEARTEXT = {
    ("tcp", 21): "ftp",
    ("tcp", 23): "telnet",
    ("tcp", 512): "rexec",
    ("tcp", 513): "rlogin",
    ("tcp", 514): "rsh",
    ("udp", 69): "tftp",
}
# Servicios de administración remota usados para movimiento lateral.
LATERAL = {445: "smb", 3389: "rdp", 5985: "winrm", 5986: "winrm", 22: "ssh", 135: "msrpc"}


def _failed_attempt(flow: NdrFlowIn) -> bool:
    if flow.transport != "tcp" or "midstream" in flow.flags:
        return False
    return "no_handshake_reply" in flow.flags or (flow.state == "reset" and flow.packets_in <= 1)


def _established(flow: NdrFlowIn) -> bool:
    if flow.transport not in ("tcp", "udp") or flow.packets_in == 0:
        return False
    # Un RST como única respuesta es un rechazo, no una sesión: no cuenta como servicio usado
    # ni como movimiento lateral (sí como intento fallido de escaneo).
    return "no_handshake_reply" not in flow.flags and not _failed_attempt(flow)


def analyze_flows(session: Session, settings: Settings, batch: IngestedBatch) -> None:
    if not batch.flows:
        return
    _scan(session, batch)
    _cleartext(session, batch)
    _lateral(session, batch)


def _authorized_discovery(session: Session, site_id: int, start: datetime, end: datetime) -> bool:
    """¿Había un discovery de Sentra del site en marcha en esa ventana?"""
    return (
        session.scalar(
            select(DiscoveryJob.id)
            .where(
                DiscoveryJob.site_id == site_id,
                DiscoveryJob.started_at <= end,
                or_(
                    DiscoveryJob.completed_at.is_(None),
                    DiscoveryJob.completed_at >= start,
                ),
                DiscoveryJob.status.in_(
                    (
                        DiscoveryJobStatus.QUEUED,
                        DiscoveryJobStatus.RUNNING,
                        DiscoveryJobStatus.COMPLETED,
                        DiscoveryJobStatus.CANCELLED,
                    )
                ),
            )
            .limit(1)
        )
        is not None
    )


def _scan(session: Session, batch: IngestedBatch) -> None:
    targets: dict[str, set[tuple[str, int | None]]] = defaultdict(set)
    window: dict[str, list[datetime]] = defaultdict(list)
    for flow in batch.flows:
        if _failed_attempt(flow):
            targets[flow.src_ip].add((flow.dst_ip, flow.dst_port))
            window[flow.src_ip].extend((flow.first_seen, flow.last_seen))
    for src, seen in targets.items():
        if len(seen) < SCAN_SUSPICIOUS:
            continue
        start, end = min(window[src]), max(window[src])
        hosts = {ip for ip, _ in seen}
        ports = {port for _, port in seen}
        authorized = _authorized_discovery(session, batch.site.id, start, end)
        probable = len(seen) >= SCAN_PROBABLE
        verdict = "observed" if authorized else ("probable" if probable else "suspicious")
        shape = "vertical" if len(hosts) == 1 else ("horizontal" if len(ports) == 1 else "mixed")
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=SCAN_001,
                dedup_key=src,
                verdict=verdict,
                severity="low" if authorized else ("high" if probable else "medium"),
                summary=(
                    f"{src} intentó {len(seen)} conexiones sin respuesta a {len(hosts)} equipos"
                    f" y {len(ports)} puertos ({shape})."
                    + (" Coincide con un discovery autorizado de Sentra." if authorized else "")
                ),
                evidence={
                    "src_ip": src,
                    "targets": len(seen),
                    "hosts": len(hosts),
                    "ports": len(ports),
                    "shape": shape,
                    "authorized_discovery": authorized,
                    "example_hosts": sorted(hosts)[:MAX_EXAMPLES],
                    "example_ports": sorted(p for p in ports if p is not None)[:MAX_EXAMPLES],
                },
                at=end,
                subject_ip=src,
            ),
        )


def _cleartext(session: Session, batch: IngestedBatch) -> None:
    for flow in batch.flows:
        service = CLEARTEXT.get((flow.transport, flow.dst_port or -1))
        if service is None or not _established(flow):
            continue
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=PROTO_001,
                dedup_key=f"{flow.dst_ip}|{flow.transport}|{flow.dst_port}",
                verdict="observed",
                severity="medium" if service == "telnet" else "low",
                summary=(
                    f"{flow.src_ip} usó {service} (en claro) contra {flow.dst_ip}:{flow.dst_port}."
                ),
                evidence={
                    "service": service,
                    "server_ip": flow.dst_ip,
                    "server_port": flow.dst_port,
                    "last_client_ip": flow.src_ip,
                    "bytes": flow.bytes_out + flow.bytes_in,
                },
                at=flow.last_seen,
                subject_ip=flow.dst_ip,
            ),
        )


def _lateral(session: Session, batch: IngestedBatch) -> None:
    peers: dict[tuple[str, str], set[str]] = defaultdict(set)
    last: dict[tuple[str, str], datetime] = {}
    for flow in batch.flows:
        service = LATERAL.get(flow.dst_port or -1)
        if (
            service is None
            or flow.transport != "tcp"
            or not _established(flow)
            or not is_internal(flow.src_ip)
            or not is_internal(flow.dst_ip)
        ):
            continue
        key = (flow.src_ip, service)
        peers[key].add(flow.dst_ip)
        last[key] = max(last.get(key, flow.last_seen), flow.last_seen)
    for (src, service), hosts in peers.items():
        if len(hosts) < LATERAL_SUSPICIOUS:
            continue
        probable = len(hosts) >= LATERAL_PROBABLE
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=PROTO_002,
                dedup_key=f"{src}|{service}",
                verdict="probable" if probable else "suspicious",
                severity="high" if probable else "medium",
                summary=f"{src} abrió sesiones {service} con {len(hosts)} equipos internos.",
                evidence={
                    "src_ip": src,
                    "service": service,
                    "hosts": len(hosts),
                    "examples": sorted(hosts)[:MAX_EXAMPLES],
                },
                at=last[(src, service)],
                subject_ip=src,
            ),
        )
