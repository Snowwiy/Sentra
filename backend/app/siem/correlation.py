"""Enlaces entre eventos SIEM y la evidencia propia de Sentra (Fase 7F.3, ampliada en 7F.4/7F.6).

Cada enlace dice QUÉ se relaciona, CÓMO (método) y CON QUÉ CONFIANZA. Reglas:

* Flujo NDR (`five_tuple_time`): misma 5-tupla (en cualquier sentido), mismo protocolo, mismo
  site y el instante del evento dentro de la vida del flujo con ±FLOW_SLACK de margen. Con
  NAT o rutas asimétricas la 5-tupla no coincide y no se enlaza: se prefiere no enlazar a
  enlazar mal. Un único flujo candidato = confianza `high`; varios = `medium`.
* Otro evento SIEM: el mismo `flow_ref` dentro de la misma fuente (`flow_id` de Suricata,
  `uid` de Zeek) o el mismo `community_id` entre fuentes distintas del site (Suricata y Zeek
  calculan el mismo hash de la 5-tupla), siempre dentro de una ventana de tiempo.
* Anomalía NDR (`subject_time`): una anomalía activa del MISMO activo cuyo sujeto es una de
  las IP del evento y cuya vida se solapa con el evento ±ANOMALY_SLACK. Confianza `low`:
  coincidir en el tiempo NO demuestra causalidad. Solo sirve para no contar dos veces el
  mismo hecho en el riesgo y para mostrar el contexto; la explicación lo dice.
* Entidades compartidas entre fuentes (7F.6, confianza `low`): los mismos dos extremos o el
  mismo usuario en el mismo activo, en otra fuente del site y ±ENTITY_WINDOW, con una alerta
  de por medio. Nunca solo el tiempo. No crea detecciones: es contexto de investigación
  (una detección por cada fuente ya existe; sumar otra contaría dos veces el mismo hecho).

Todo acotado: como mucho MAX_EVENTS_PER_BATCH eventos correlacionados por lote (las alertas
primero) y MAX_MATCHES candidatos por evento.
"""

from datetime import timedelta
from typing import Any

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.models.ndr import ACTIVE_ANOMALY_STATUSES, NdrAnomaly, NdrFlow
from app.models.siem import SiemEvent, SiemEventLink
from app.siem.identity import candidates_of
from app.siem.ingest import IngestedSiem

FLOW_SLACK = timedelta(seconds=120)
ANOMALY_SLACK = timedelta(minutes=10)
SIEM_WINDOW = timedelta(minutes=30)
MAX_EVENTS_PER_BATCH = 300
MAX_MATCHES = 5
FLOW_PROTOCOLS = ("tcp", "udp")

KIND_NDR_FLOW = "ndr_flow"
KIND_NDR_ANOMALY = "ndr_anomaly"
KIND_SIEM_EVENT = "siem_event"
# Detección nativa de Sentra que probablemente describe lo mismo (Wazuh, 7F.5).
KIND_DETECTION = "detection"


def link_row(
    rows: list[dict[str, Any]],
    event: SiemEvent,
    kind: str,
    target_id: int,
    target_ref: str,
    method: str,
    confidence: str,
    explanation: str,
    **details: Any,
) -> None:
    rows.append(
        {
            "event_id": event.id,
            "site_id": event.site_id,
            "kind": kind,
            "target_id": target_id,
            "target_ref": target_ref[:64],
            "method": method,
            "confidence": confidence,
            "details": {"explanation": explanation, **details},
        }
    )


def _flows(session: Session, event: SiemEvent) -> list[NdrFlow]:
    if (
        event.protocol not in FLOW_PROTOCOLS
        or not event.src_ip
        or not event.dst_ip
        or event.src_port is None
        or event.dst_port is None
    ):
        return []
    at = event.observed_at
    forward = and_(
        NdrFlow.src_ip == event.src_ip,
        NdrFlow.dst_ip == event.dst_ip,
        NdrFlow.src_port == event.src_port,
        NdrFlow.dst_port == event.dst_port,
    )
    reverse = and_(
        NdrFlow.src_ip == event.dst_ip,
        NdrFlow.dst_ip == event.src_ip,
        NdrFlow.src_port == event.dst_port,
        NdrFlow.dst_port == event.src_port,
    )
    return list(
        session.scalars(
            select(NdrFlow)
            .where(
                NdrFlow.site_id == event.site_id,
                NdrFlow.transport == event.protocol,
                NdrFlow.first_seen <= at + FLOW_SLACK,
                NdrFlow.last_seen >= at - FLOW_SLACK,
                or_(forward, reverse),
            )
            .order_by(NdrFlow.last_seen.desc())
            .limit(MAX_MATCHES)
        )
    )


def _anomalies(session: Session, event: SiemEvent) -> list[NdrAnomaly]:
    assets = {c["asset_id"] for c in candidates_of(event)}
    ips = [ip for ip in (event.src_ip, event.dst_ip) if ip]
    if not assets or not ips:
        return []
    at = event.observed_at
    return list(
        session.scalars(
            select(NdrAnomaly)
            .where(
                NdrAnomaly.site_id == event.site_id,
                NdrAnomaly.asset_id.in_(sorted(assets)),
                NdrAnomaly.status.in_(ACTIVE_ANOMALY_STATUSES),
                NdrAnomaly.subject_ip.in_(ips),
                NdrAnomaly.first_seen <= at + ANOMALY_SLACK,
                NdrAnomaly.last_seen >= at - ANOMALY_SLACK,
            )
            .order_by(NdrAnomaly.id)
            .limit(MAX_MATCHES)
        )
    )


def _same_flow_events(session: Session, event: SiemEvent) -> list[tuple[SiemEvent, str]]:
    found: list[tuple[SiemEvent, str]] = []
    at = event.observed_at
    window = (SiemEvent.observed_at >= at - SIEM_WINDOW, SiemEvent.observed_at <= at + SIEM_WINDOW)
    if event.flow_ref:
        for other in session.scalars(
            select(SiemEvent)
            .where(
                SiemEvent.source_id == event.source_id,
                SiemEvent.flow_ref == event.flow_ref,
                SiemEvent.id != event.id,
                *window,
            )
            .order_by(SiemEvent.id)
            .limit(MAX_MATCHES)
        ):
            found.append((other, "flow_ref"))
    community = (event.data or {}).get("community_id")
    if isinstance(community, str) and community:
        for other in session.scalars(
            select(SiemEvent)
            .where(
                SiemEvent.site_id == event.site_id,
                SiemEvent.source_id != event.source_id,
                SiemEvent.data["community_id"].astext == community,
                *window,
            )
            .order_by(SiemEvent.id)
            .limit(MAX_MATCHES)
        ):
            found.append((other, "community_id"))
    return found


ENTITY_WINDOW = timedelta(minutes=15)
_ALERTING = ("detection", "authentication")


def _shared_entities(
    session: Session, event: SiemEvent, skip: set[int]
) -> list[tuple[SiemEvent, str]]:
    """Fase 7F.6: otra fuente del site que vio LAS MISMAS entidades en ±15 min.

    Hacen falta dos entidades además del tiempo (los dos extremos de la comunicación, o el
    mismo usuario en el mismo activo atribuido). Para no enlazar cada conexión con cada línea
    de firewall, uno de los dos eventos tiene que ser una alerta (`detection`) o, en el caso
    del usuario, de autenticación. Confianza baja: contexto, no causa.
    """
    found: list[tuple[SiemEvent, str]] = []
    at = event.observed_at
    base = (
        SiemEvent.site_id == event.site_id,
        SiemEvent.source_id != event.source_id,
        SiemEvent.observed_at >= at - ENTITY_WINDOW,
        SiemEvent.observed_at <= at + ENTITY_WINDOW,
        SiemEvent.id != event.id,
    )
    if event.src_ip and event.dst_ip and event.src_ip != event.dst_ip:
        pair = or_(
            and_(SiemEvent.src_ip == event.src_ip, SiemEvent.dst_ip == event.dst_ip),
            and_(SiemEvent.src_ip == event.dst_ip, SiemEvent.dst_ip == event.src_ip),
        )
        scope = [] if event.category == "detection" else [SiemEvent.category == "detection"]
        for other in session.scalars(
            select(SiemEvent).where(*base, pair, *scope).order_by(SiemEvent.id).limit(MAX_MATCHES)
        ):
            if other.id not in skip:
                found.append((other, "shared_endpoints"))
    if event.username and event.asset_id is not None and event.category in _ALERTING:
        for other in session.scalars(
            select(SiemEvent)
            .where(
                *base,
                SiemEvent.asset_id == event.asset_id,
                SiemEvent.username == event.username,
                SiemEvent.category.in_(_ALERTING),
            )
            .order_by(SiemEvent.id)
            .limit(MAX_MATCHES)
        ):
            if other.id not in skip and all(other.id != o.id for o, _m in found):
                found.append((other, "same_user_asset"))
    return found


_ENTITY_EXPLANATIONS = {
    "shared_endpoints": "Otra fuente vio los mismos dos extremos (en cualquier sentido) en ±15"
    " min, y uno de los eventos es una alerta. Contexto: no demuestra que uno cause el otro.",
    "same_user_asset": "Otra fuente vio el mismo usuario en el mismo activo atribuido en ±15"
    " min. Contexto: no demuestra que uno cause el otro.",
}


def _priority(event: SiemEvent) -> tuple[int, int]:
    return (0 if event.category == "detection" else 1, event.id)


def correlation_analyzer(session: Session, settings: Settings, ingested: IngestedSiem) -> None:
    if not ingested.event_ids:
        return
    events = sorted(
        session.scalars(select(SiemEvent).where(SiemEvent.id.in_(ingested.event_ids))),
        key=_priority,
    )[:MAX_EVENTS_PER_BATCH]
    rows: list[dict[str, Any]] = []
    for event in events:
        flows = _flows(session, event)
        confidence = "high" if len(flows) == 1 else "medium"
        for flow in flows:
            link_row(
                rows,
                event,
                KIND_NDR_FLOW,
                flow.id,
                flow.uid,
                "five_tuple_time",
                confidence,
                "Misma 5-tupla y protocolo que un flujo observado por el sensor NDR del site,"
                " dentro de su ventana de tiempo.",
                candidates=len(flows),
                ndr_sensor_id=flow.sensor_id,
            )
        same_flow = _same_flow_events(session, event)
        for other, method in same_flow:
            link_row(
                rows,
                event,
                KIND_SIEM_EVENT,
                other.id,
                str(other.event_id),
                method,
                "high" if method == "flow_ref" else "medium",
                "Mismo identificador de flujo en la misma fuente."
                if method == "flow_ref"
                else "Mismo community_id (hash de la 5-tupla) en otra fuente del site.",
            )
        for other, method in _shared_entities(session, event, {o.id for o, _m in same_flow}):
            link_row(
                rows,
                event,
                KIND_SIEM_EVENT,
                other.id,
                str(other.event_id),
                method,
                "low",
                _ENTITY_EXPLANATIONS[method],
            )
        if event.category == "detection":
            for anomaly in _anomalies(session, event):
                link_row(
                    rows,
                    event,
                    KIND_NDR_ANOMALY,
                    anomaly.id,
                    str(anomaly.public_id),
                    "subject_time",
                    "low",
                    "Anomalía NDR activa del mismo activo y la misma IP en la misma ventana de"
                    " tiempo. Coincidencia temporal: no demuestra que una cause la otra.",
                    ndr_rule_id=anomaly.rule_id,
                )
    if rows:
        session.execute(
            pg_insert(SiemEventLink)
            .values(rows)
            .on_conflict_do_nothing(constraint="uq_siem_event_links_target")
        )
        session.flush()
