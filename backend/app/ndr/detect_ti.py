"""Threat Intelligence sobre el tráfico observado por los sensores NDR (Fase 7E.5).

Reutiliza el catálogo de indicadores de la Fase 5C (mismas fuentes, mismas reglas de
indicador activo: no revocado, no benigno, vigente, fuente habilitada) y lo cruza con lo que
ve el sensor en cada lote:

- IP externa de un flujo que empieza o termina en un equipo interno (ipv4/ipv6 exactos y
  redes cidr);
- nombre consultado por DNS por un equipo interno, y sus dominios padre;
- SNI de un saludo TLS iniciado por un equipo interno.

El resultado es una anomalía NDR-TI-001 por (equipo interno, indicador). Nunca "confirmed":
un IOC externo es contexto y puede estar desactualizado (IPs compartidas, CDNs). Una red
cidr nunca pasa de suspicious porque no identifica un servidor concreto.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.ndr.addresses import is_external, is_internal
from app.ndr.anomalies import Finding, record_finding
from app.ndr.ingest import IngestedBatch
from app.ndr.rules import TI_001
from app.threat_intel.matching import _ACTIVE_INDICATOR

MAX_VALUES_PER_BATCH = 2000
TRUSTED_SOURCES = frozenset({"official", "trusted"})


@dataclass
class _Seen:
    """Una observación del lote: quién (equipo interno), qué valor y cómo se vio."""

    internal_ip: str
    value: str
    observation: str
    first: datetime
    last: datetime
    count: int = 1
    ports: set[int] = field(default_factory=set)


def _domains(name: str) -> list[str]:
    """El nombre y sus dominios padre con al menos dos etiquetas (a.b.example.com ->
    a.b.example.com, b.example.com, example.com): un IOC de dominio cubre sus subdominios."""
    labels = [label for label in name.strip(".").lower().split(".") if label]
    return [".".join(labels[i:]) for i in range(max(len(labels) - 1, 0))]


def _observations(batch: IngestedBatch) -> list[_Seen]:
    seen: dict[tuple[str, str, str], _Seen] = {}

    def add(internal: str, value: str, kind: str, first: datetime, last: datetime) -> _Seen:
        key = (internal, value, kind)
        current = seen.get(key)
        if current is None:
            current = seen[key] = _Seen(internal, value, kind, first, last)
        else:
            current.count += 1
            current.first = min(current.first, first)
            current.last = max(current.last, last)
        return current

    for flow in batch.flows:
        if is_internal(flow.src_ip) and is_external(flow.dst_ip):
            entry = add(flow.src_ip, flow.dst_ip, "flow_remote_ip", flow.first_seen, flow.last_seen)
            if flow.dst_port is not None:
                entry.ports.add(flow.dst_port)
        elif is_internal(flow.dst_ip) and is_external(flow.src_ip):
            # Conexión entrante desde una IP marcada: también es actividad con el indicador.
            entry = add(flow.dst_ip, flow.src_ip, "flow_remote_ip", flow.first_seen, flow.last_seen)
            if flow.dst_port is not None:
                entry.ports.add(flow.dst_port)
    for dns in batch.dns:
        if is_internal(dns.client_ip) and dns.qname:
            for domain in _domains(dns.qname):
                add(dns.client_ip, domain, "dns_query", dns.first_seen, dns.last_seen)
    for tls in batch.tls:
        if is_internal(tls.client_ip) and tls.sni:
            for domain in _domains(tls.sni):
                add(tls.client_ip, domain, "tls_sni", tls.first_seen, tls.last_seen)
    return list(seen.values())[:MAX_VALUES_PER_BATCH]


def _matches(session: Session, observations: list[_Seen]) -> list[tuple[int, dict[str, Any]]]:
    """(índice de la observación, indicador) para cada coincidencia, en dos consultas por
    conjuntos (valores exactos y redes cidr), como el matching de la Fase 5C."""
    if not observations:
        return []
    now = datetime.now(UTC)
    columns = (
        "o.idx, i.public_id, i.indicator_type, i.value_normalized, i.classification, "
        "i.confidence, s.name, s.trust"
    )
    joins = "JOIN threat_intel_sources s ON s.id = i.source_id"
    result: list[tuple[int, dict[str, Any]]] = []
    ips = [(n, o.value) for n, o in enumerate(observations) if o.observation == "flow_remote_ip"]
    names = [(n, o.value) for n, o in enumerate(observations) if o.observation != "flow_remote_ip"]
    queries: list[tuple[list[tuple[int, str]], str, str]] = [
        (ips, "text", "i.value_normalized = o.value AND i.indicator_type IN ('ipv4', 'ipv6')"),
        (ips, "inet", "i.network IS NOT NULL AND i.network >>= o.value"),
        (
            names,
            "text",
            "i.value_normalized = o.value AND i.indicator_type IN ('domain', 'hostname')",
        ),
    ]
    for group, cast, condition in queries:
        if not group:
            continue
        rows = session.execute(
            text(
                f"SELECT {columns} FROM unnest(CAST(:idx AS int[]), CAST(:vals AS {cast}[]))"  # noqa: S608
                f" AS o(idx, value) JOIN threat_indicators i ON {condition} {joins}"
                f" WHERE {_ACTIVE_INDICATOR}"
            ),
            {"idx": [n for n, _ in group], "vals": [v for _, v in group], "now": now},
        ).all()
        for idx, public_id, kind, value, classification, confidence, source, trust in rows:
            result.append(
                (
                    int(idx),
                    {
                        "indicator_id": str(public_id),
                        "indicator_type": kind,
                        "indicator_value": value,
                        "classification": classification,
                        "confidence": confidence,
                        "source": source,
                        "source_trust": trust,
                    },
                )
            )
    return result


def _verdict(indicator: dict[str, Any]) -> str:
    strong = (
        indicator["classification"] == "malicious"
        and indicator["confidence"] == "high"
        and indicator["source_trust"] in TRUSTED_SOURCES
        and indicator["indicator_type"] != "cidr"
    )
    return "probable" if strong else "suspicious"


def analyze_ti(session: Session, settings: Settings, batch: IngestedBatch) -> None:
    observations = _observations(batch)
    if not observations:
        return
    # Varias observaciones del mismo equipo pueden casar con el mismo indicador (IP y SNI
    # del mismo servidor): una sola anomalía con todas.
    grouped: dict[tuple[str, str], list[tuple[_Seen, dict[str, Any]]]] = defaultdict(list)
    for idx, indicator in _matches(session, observations):
        obs = observations[idx]
        grouped[(obs.internal_ip, indicator["indicator_id"])].append((obs, indicator))
    for (internal, indicator_id), hits in grouped.items():
        indicator = hits[0][1]
        verdict = _verdict(indicator)
        last = max(obs.last for obs, _ in hits)
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=TI_001,
                dedup_key=f"{internal}|{indicator_id}",
                verdict=verdict,
                severity="high" if verdict == "probable" else "medium",
                summary=(
                    f"{internal} tuvo actividad con {indicator['indicator_value']}, indicador"
                    f" {indicator['classification']} de la fuente {indicator['source']}"
                    f" (confianza {indicator['confidence']}). Es contexto externo: no confirma"
                    " un compromiso."
                ),
                evidence={
                    **indicator,
                    "internal_ip": internal,
                    "observations": [
                        {
                            "type": obs.observation,
                            "value": obs.value,
                            "count": obs.count,
                            "ports": sorted(obs.ports)[:10],
                        }
                        for obs, _ in hits
                    ],
                },
                at=last,
                subject_ip=internal,
            ),
        )
