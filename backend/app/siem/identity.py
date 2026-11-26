"""Atribución conservadora de eventos SIEM a activos inventariados (Fase 7F.3, ampliada en 7F.6).

Modelo de identidad (docs/fase-7f-correlation.md):

* Solo activos del MISMO site que la fuente y no archivados. Las IP privadas se repiten entre
  sites: nunca se cruza.
* Una IP identifica un activo solo si exactamente UN activo del site la tiene como IP
  principal. Si la comparten varios (NAT, duplicados, IP reasignada), el evento queda sin
  atribuir (`ambiguous`), con los candidatos a la vista.
* Las IP de la red (origen y destino) dan candidatos con rol `source` o `destination`. Si las
  dos son de activos inventariados, el evento queda sin un activo único (`multiple`) y las
  señales se emiten para cada uno con su rol: no se elige uno al azar.
* El emisor de un Syslog (`peer_ip`) solo cuenta si llegó por TCP o TLS: en UDP la dirección
  de origen se falsifica (`reporter`, confianza media).
* La IP con la que un agente de Wazuh se registró (`agent_ip`, rol `host`) es una pista no
  verificada: confianza baja, media si el nombre del agente coincide con el mismo activo.
* El nombre de host que escribe la fuente (HOSTNAME de Syslog, agente de Wazuh) es una pista
  débil: solo se propone si coincide con UN activo del site y no hay nada mejor (confianza
  baja, `hostname_match`). Nunca es identidad definitiva: un candidato que solo tiene el
  nombre se muestra, pero no genera señales de detección (app/siem/signals.py).
* Sin evidencia suficiente el evento se conserva igual, con `asset_id` a NULL y el veredicto
  `insufficient_evidence`. No se crea ningún activo a partir de un evento externo.
"""

from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.asset import Asset
from app.models.siem import SiemEvent
from app.siem.ingest import IngestedSiem

ROLE_SOURCE = "source"
ROLE_DESTINATION = "destination"
ROLE_REPORTER = "reporter"
ROLE_HOST = "host"


@dataclass(frozen=True)
class Candidate:
    asset_id: int
    role: str
    method: str
    confidence: str
    value: str


def _by_ip(session: Session, site_id: int, ips: set[str]) -> dict[str, list[int]]:
    if not ips:
        return {}
    rows = session.execute(
        select(Asset.primary_ip, Asset.id).where(
            Asset.site_id == site_id,
            Asset.primary_ip.in_(sorted(ips)),
            Asset.archived_at.is_(None),
        )
    ).all()
    out: dict[str, list[int]] = {}
    for ip, asset_id in rows:
        out.setdefault(ip, []).append(int(asset_id))
    return out


def _by_hostname(session: Session, site_id: int, names: set[str]) -> dict[str, list[int]]:
    if not names:
        return {}
    lowered = func.lower(Asset.hostname)
    rows = session.execute(
        select(lowered, Asset.id).where(
            Asset.site_id == site_id,
            lowered.in_(sorted(names)),
            Asset.archived_at.is_(None),
        )
    ).all()
    out: dict[str, list[int]] = {}
    for name, asset_id in rows:
        out.setdefault(str(name), []).append(int(asset_id))
    # Nombre corto: "web01" en el log y "web01.corp.local" en el inventario (o al revés)
    # no se igualan aquí: sería adivinar el dominio.
    return out


def _peer(event: SiemEvent) -> str | None:
    data = event.data or {}
    transport = data.get("transport")
    peer = data.get("peer_ip")
    # En UDP la dirección del emisor no está autenticada: no sirve para atribuir.
    if isinstance(peer, str) and transport in ("tcp", "tls"):
        return peer
    return None


def _agent_ip(event: SiemEvent) -> str | None:
    """IP del agente que declara Wazuh (`data.agent_ip`).

    Es la dirección con la que el agente se registró en el manager: una pista mejor que el
    nombre, pero no verificada por Sentra (puede ser "any", estar detrás de un NAT o haber
    cambiado). Por eso da confianza baja, y media solo si el nombre del agente coincide con el
    mismo activo.
    """
    if event.source_type != "wazuh_alerts":
        return None
    value = (event.data or {}).get("agent_ip")
    return value if isinstance(value, str) and value else None


def attribute(session: Session, site_id: int, events: list[SiemEvent]) -> None:
    """Rellena `asset_id` y `attribution` de los eventos (en la transacción del lote)."""
    ips: set[str] = set()
    names: set[str] = set()
    for event in events:
        for value in (event.src_ip, event.dst_ip, _peer(event), _agent_ip(event)):
            if value:
                ips.add(value)
        if event.hostname:
            names.add(event.hostname.lower())
    by_ip = _by_ip(session, site_id, ips)
    by_name = _by_hostname(session, site_id, names)
    for event in events:
        candidates: list[Candidate] = []
        ambiguous: list[dict[str, Any]] = []
        for value, role in ((event.src_ip, ROLE_SOURCE), (event.dst_ip, ROLE_DESTINATION)):
            if not value:
                continue
            found = by_ip.get(value, [])
            if len(found) == 1:
                candidates.append(Candidate(found[0], role, "ip_in_site", "medium", value))
            elif len(found) > 1:
                ambiguous.append({"role": role, "value": value, "assets": len(found)})
        peer = _peer(event)
        if peer:
            found = by_ip.get(peer, [])
            if len(found) == 1:
                candidates.append(Candidate(found[0], ROLE_REPORTER, "reporter_ip", "medium", peer))
            elif len(found) > 1:
                ambiguous.append({"role": ROLE_REPORTER, "value": peer, "assets": len(found)})
        agent_ip = _agent_ip(event)
        if agent_ip:
            found = by_ip.get(agent_ip, [])
            if len(found) == 1:
                named = by_name.get((event.hostname or "").lower(), [])
                # Nombre e IP del agente apuntan al mismo activo: dos pistas independientes.
                confidence = "medium" if named == found else "low"
                candidates.append(Candidate(found[0], ROLE_HOST, "agent_ip", confidence, agent_ip))
            elif len(found) > 1:
                ambiguous.append({"role": ROLE_HOST, "value": agent_ip, "assets": len(found)})
        if not candidates and event.hostname:
            found = by_name.get(event.hostname.lower(), [])
            if len(found) == 1:
                candidates.append(
                    Candidate(found[0], ROLE_HOST, "hostname_match", "low", event.hostname)
                )
            elif len(found) > 1:
                ambiguous.append({"role": ROLE_HOST, "value": event.hostname, "assets": len(found)})
        distinct = {c.asset_id for c in candidates}
        if candidates and all(c.method == "hostname_match" for c in candidates):
            # Solo el nombre: se propone el activo, pero el evento no queda atribuido.
            verdict = "hostname_hint"
            event.asset_id = None
        elif len(distinct) == 1:
            verdict = "attributed"
            event.asset_id = candidates[0].asset_id
        elif len(distinct) > 1:
            verdict = "multiple"
            event.asset_id = None
        else:
            verdict = "ambiguous" if ambiguous else "insufficient_evidence"
            event.asset_id = None
        event.attribution = {
            "verdict": verdict,
            "candidates": [
                {
                    "asset_id": c.asset_id,
                    "role": c.role,
                    "method": c.method,
                    "confidence": c.confidence,
                    "value": c.value,
                }
                for c in candidates
            ],
            "ambiguous": ambiguous,
        }


def attribution_analyzer(session: Session, settings: Settings, ingested: IngestedSiem) -> None:
    if not ingested.event_ids:
        return
    events = list(session.scalars(select(SiemEvent).where(SiemEvent.id.in_(ingested.event_ids))))
    attribute(session, ingested.site.id, events)
    session.flush()


def candidates_of(event: SiemEvent) -> list[dict[str, Any]]:
    """Candidatos guardados de un evento (para señales y la UI)."""
    items = (event.attribution or {}).get("candidates") or []
    return [
        item for item in items if isinstance(item, dict) and isinstance(item.get("asset_id"), int)
    ]
