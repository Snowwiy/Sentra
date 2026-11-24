"""Reglas DNS sobre cada lote NDR (Fase 7E.2). Solo con metadatos DNS aprobados.

Se evalúan por cliente dentro de la ventana del lote (EXPORT_INTERVAL del sensor, 60 s por
defecto): los umbrales están pensados para esa ventana y se documentan en
docs/fase-7e-ndr-detections.md. Nada aquí resuelve nombres ni contacta con dominios.
"""

import ipaddress
import math
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import NdrProtocolObservation
from app.ndr.anomalies import Finding, record_finding
from app.ndr.ingest import IngestedBatch
from app.ndr.rules import DNS_001, DNS_002, DNS_003
from app.schemas.ndr import NdrDnsIn

DNS_001_SUSPICIOUS_NAMES = 20
DNS_001_PROBABLE_NAMES = 50
DNS_001_PROBABLE_PARENTS = 10
DNS_001_MIN_RATIO = 0.5
DNS_002_NAMES = 30
DNS_002_TXT = 20
DNS_002_LABEL_LENGTH = 20
DNS_002_ENTROPY = 3.5
DNS_002_ENTROPY_MIN_LENGTH = 12
DNS_LOOKBACK = timedelta(days=7)
# Sufijos de segundo nivel habituales: example.co.uk tiene como padre "example.co.uk".
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "gob", "nom", "or", "ne"}
_IGNORED_PARENTS = ("in-addr.arpa", "ip6.arpa", "local", "localdomain", "lan", "home.arpa")
MAX_EXAMPLES = 10


def parent_domain(name: str) -> str:
    labels = [label for label in name.strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def _encoded_label(name: str, parent: str) -> bool:
    sub = name[: -len(parent)].strip(".") if name.endswith(parent) else name
    if not sub:
        return False
    first = sub.split(".")[0]
    longest = max(sub.split("."), key=len)
    return len(longest) >= DNS_002_LABEL_LENGTH or (
        len(first) >= DNS_002_ENTROPY_MIN_LENGTH and entropy(first) >= DNS_002_ENTROPY
    )


def advertised_resolvers(session: Session, site_id: int, now: Any) -> set[str]:
    rows = session.scalars(
        select(func.jsonb_array_elements_text(NdrProtocolObservation.data["dns_servers"])).where(
            NdrProtocolObservation.site_id == site_id,
            NdrProtocolObservation.kind == "dhcp",
            NdrProtocolObservation.last_seen >= now - DNS_LOOKBACK,
        )
    ).all()
    return {str(r) for r in rows}


def analyze_dns(session: Session, settings: Settings, batch: IngestedBatch) -> None:
    if not batch.dns:
        return
    by_client: dict[str, list[NdrDnsIn]] = defaultdict(list)
    for entry in batch.dns:
        by_client[entry.client_ip].append(entry)
    resolvers = advertised_resolvers(session, batch.site.id, batch.received_at)
    for client, entries in by_client.items():
        _nxdomain(session, batch, client, entries)
        _tunnel(session, batch, client, entries)
        if resolvers:
            _foreign_resolver(session, batch, client, entries, resolvers)


def _nxdomain(session: Session, batch: IngestedBatch, client: str, entries: list[NdrDnsIn]) -> None:
    responses = sum(e.responses for e in entries)
    nx_entries = [e for e in entries if e.rcodes.get("nxdomain")]
    names = {e.qname for e in nx_entries}
    nx = sum(e.rcodes.get("nxdomain", 0) for e in entries)
    if len(names) < DNS_001_SUSPICIOUS_NAMES or not responses or nx / responses < DNS_001_MIN_RATIO:
        return
    parents = {parent_domain(name) for name in names}
    probable = len(names) >= DNS_001_PROBABLE_NAMES and len(parents) >= DNS_001_PROBABLE_PARENTS
    record_finding(
        session,
        batch.site.id,
        batch.sensor.id,
        Finding(
            rule=DNS_001,
            dedup_key=client,
            verdict="probable" if probable else "suspicious",
            severity="high" if probable else "medium",
            summary=(
                f"{client} consultó {len(names)} nombres inexistentes de {len(parents)} dominios"
                f" en una ventana ({nx} de {responses} respuestas NXDOMAIN)."
            ),
            evidence={
                "client_ip": client,
                "nxdomain_names": len(names),
                "parents": len(parents),
                "nxdomain_responses": nx,
                "responses": responses,
                "examples": sorted(names)[:MAX_EXAMPLES],
            },
            at=max(e.last_seen for e in entries),
            subject_ip=client,
        ),
    )


def _tunnel(session: Session, batch: IngestedBatch, client: str, entries: list[NdrDnsIn]) -> None:
    groups: dict[str, list[NdrDnsIn]] = defaultdict(list)
    for entry in entries:
        parent = parent_domain(entry.qname)
        if parent and not parent.endswith(_IGNORED_PARENTS):
            groups[parent].append(entry)
    for parent, items in groups.items():
        encoded = {e.qname for e in items if _encoded_label(e.qname, parent)}
        txt = sum(e.queries for e in items if e.qtype in ("TXT", "NULL"))
        names_hit = len(encoded) >= DNS_002_NAMES
        txt_hit = txt >= DNS_002_TXT
        if not names_hit and not txt_hit:
            continue
        probable = names_hit and txt_hit
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=DNS_002,
                dedup_key=f"{client}|{parent}",
                verdict="probable" if probable else "suspicious",
                severity="high" if probable else "medium",
                summary=(
                    f"{client} consultó {len(encoded)} subdominios codificados de {parent}"
                    f" y {txt} consultas TXT/NULL en una ventana."
                ),
                evidence={
                    "client_ip": client,
                    "parent": parent,
                    "encoded_names": len(encoded),
                    "txt_null_queries": txt,
                    "examples": sorted(encoded)[:MAX_EXAMPLES],
                },
                at=max(e.last_seen for e in items),
                subject_ip=client,
            ),
        )


def _foreign_resolver(
    session: Session,
    batch: IngestedBatch,
    client: str,
    entries: list[NdrDnsIn],
    resolvers: set[str],
) -> None:
    for resolver in sorted({e.resolver_ip for e in entries} - resolvers - {client}):
        try:
            public = ipaddress.ip_address(resolver).is_global
        except ValueError:
            continue
        if not public:
            continue
        hits = [e for e in entries if e.resolver_ip == resolver]
        record_finding(
            session,
            batch.site.id,
            batch.sensor.id,
            Finding(
                rule=DNS_003,
                dedup_key=f"{client}|{resolver}",
                verdict="observed",
                severity="low",
                summary=(
                    f"{client} resuelve contra {resolver}, que no es un DNS anunciado por el"
                    " DHCP del site."
                ),
                evidence={
                    "client_ip": client,
                    "resolver_ip": resolver,
                    "queries": sum(e.queries for e in hits),
                    "advertised": sorted(resolvers),
                },
                at=max(e.last_seen for e in hits),
                subject_ip=client,
            ),
        )
