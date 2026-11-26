"""Señales al motor de detección desde eventos SIEM (Fase 7F.3, Wazuh en 7F.5).

No hay un segundo motor de detección: los eventos de categoría `detection` (alertas de
Suricata o Wazuh) atribuidos a un activo del site se convierten en señales SIEM_ALERT y la
regla built-in SIEM-EXT-001 decide. El resto de eventos SIEM no genera señales: son contexto
para la búsqueda, la correlación y la investigación.

Una señal por activo candidato con su rol (origen, destino, emisor). Si el evento no tiene
ningún candidato (sin activo inventariado o IP compartida), no hay señal: la alerta se
conserva como evento y aparece en la búsqueda, sin inventar un activo.

La clave (`subject`) agrupa las repeticiones de la misma firma contra el mismo activo desde
el mismo extremo: un barrido de 500 alertas idénticas es una detección con 500 señales.
Por lote se emiten como mucho MAX_SIGNALS_PER_BATCH señales.

Origen de cada alerta (se guarda en `attribution.origin` y viaja en la señal):

* `imported`: alerta externa atribuida a un activo, sin más corroboración.
* `correlated`: además, el NDR de Sentra vio la misma comunicación.
* `probable_match` (solo Wazuh): ya hay una detección NATIVA de Sentra del mismo activo, en
  la misma ventana y con la misma técnica MITRE o el mismo tema. Se guarda un enlace
  explicado a esa detección y NO se emite señal: Wazuh y el agente de Sentra suelen ver los
  mismos eventos del host, y dos detecciones darían dos incidentes del mismo hecho.
* `insufficient_evidence`: ningún activo atribuible (o solo el nombre de host): no hay señal.

Limitación: la comparación se hace al ingerir. Si la detección nativa llega después que la
alerta de Wazuh, las dos existen; la vista "Relacionados" (7F.6) las muestra juntas.
"""

from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.detection.signals import SignalKind, SourceType
from app.models.detection import Detection, DetectionSignal
from app.models.siem import SiemEvent, SiemEventLink
from app.siem.correlation import KIND_DETECTION, KIND_NDR_ANOMALY, KIND_NDR_FLOW, link_row
from app.siem.identity import ROLE_DESTINATION, ROLE_SOURCE, candidates_of
from app.siem.ingest import IngestedSiem

MAX_SIGNALS_PER_BATCH = 200
SIGNAL_SEVERITIES = ("low", "medium", "high", "critical")
# Fuentes de host que solapan con las detecciones nativas del agente de Sentra.
NATIVE_OVERLAP_SOURCES = frozenset({"wazuh_alerts"})
NATIVE_MATCH_WINDOW = timedelta(minutes=15)
# Grupos de reglas de Wazuh → categoría de las reglas nativas (tema común). Corto a
# propósito: solo grupos cuyo significado coincide sin ambigüedad.
WAZUH_GROUP_CATEGORIES = {
    "authentication_failed": "authentication",
    "authentication_failures": "authentication",
    "authentication_success": "authentication",
    "win_authentication_failed": "authentication",
    "adduser": "account",
    "account_changed": "account",
    "group_changed": "account",
    "sudo": "account",
    "service_installed": "persistence",
    "powershell": "scripting",
}


def _peer(event: SiemEvent, role: str) -> str:
    if role == ROLE_DESTINATION:
        return event.src_ip or "-"
    if role == ROLE_SOURCE:
        return event.dst_ip or "-"
    return event.src_ip or event.dst_ip or "-"


def _technique(value: str | None) -> str | None:
    # T1110.001 y T1110 hablan de la misma técnica: se compara la técnica padre.
    return value.split(".", 1)[0].upper() if value else None


def topic_of(event: SiemEvent) -> tuple[set[str], set[str]]:
    """Técnicas MITRE padre y categorías nativas equivalentes que describen el evento."""
    techniques = {t for t in (_technique(x) for x in event.mitre_techniques or []) if t}
    groups = (event.data or {}).get("rule_groups") or []
    categories = {WAZUH_GROUP_CATEGORIES[g] for g in groups if g in WAZUH_GROUP_CATEGORIES}
    return techniques, categories


def native_match(session: Session, event: SiemEvent, asset_id: int) -> Detection | None:
    """Detección nativa de Sentra que probablemente describe el mismo hecho que `event`.

    Mismo activo, ventana de ±15 min solapando la vida de la detección, y además la misma
    técnica MITRE o el mismo tema (categoría). Una coincidencia solo de tiempo no basta.
    """
    techniques, categories = topic_of(event)
    if not techniques and not categories:
        return None
    conditions = []
    if techniques:
        conditions.append(Detection.mitre_technique.in_(sorted(techniques)))
        conditions.append(
            Detection.mitre_subtechnique.in_(sorted(t.upper() for t in event.mitre_techniques))
        )
    if categories:
        conditions.append(Detection.rule_category.in_(sorted(categories)))
    return session.scalars(
        select(Detection)
        .where(
            Detection.asset_id == asset_id,
            ~Detection.rule_id.startswith("SIEM-"),
            Detection.first_seen_at <= event.observed_at + NATIVE_MATCH_WINDOW,
            Detection.last_seen_at >= event.observed_at - NATIVE_MATCH_WINDOW,
            or_(*conditions),
        )
        .order_by(Detection.last_seen_at.desc())
        .limit(1)
    ).first()


def _set_origin(event: SiemEvent, origin: str) -> None:
    # Se reasigna el dict entero para que SQLAlchemy detecte el cambio en la columna JSONB.
    event.attribution = {**(event.attribution or {}), "origin": origin}


def signal_analyzer(session: Session, settings: Settings, ingested: IngestedSiem) -> None:
    if not ingested.event_ids:
        return
    events = list(
        session.scalars(
            select(SiemEvent)
            .where(
                SiemEvent.id.in_(ingested.event_ids),
                SiemEvent.category == "detection",
                SiemEvent.severity.in_(SIGNAL_SEVERITIES),
            )
            .order_by(SiemEvent.id)
        )
    )
    if not events:
        return
    links: dict[int, list[SiemEventLink]] = {}
    for link in session.scalars(
        select(SiemEventLink).where(
            SiemEventLink.event_id.in_([e.id for e in events]),
            SiemEventLink.kind.in_((KIND_NDR_FLOW, KIND_NDR_ANOMALY)),
        )
    ):
        links.setdefault(link.event_id, []).append(link)
    emitted = 0
    now = datetime.now(UTC)
    match_rows: list[dict[str, Any]] = []
    for event in events:
        # El nombre de host es una pista, no identidad: no basta para una detección.
        candidates = [c for c in candidates_of(event) if c.get("method") != "hostname_match"]
        if not candidates:
            _set_origin(event, "insufficient_evidence")
            continue
        related = links.get(event.id, [])
        flow_uids = [link.target_ref for link in related if link.kind == KIND_NDR_FLOW]
        anomaly_ids = [link.target_ref for link in related if link.kind == KIND_NDR_ANOMALY]
        origin = "correlated" if flow_uids else "imported"
        if event.source_type in NATIVE_OVERLAP_SOURCES:
            matched = False
            for candidate in candidates:
                native = native_match(session, event, int(candidate["asset_id"]))
                if native is None:
                    continue
                matched = True
                link_row(
                    match_rows,
                    event,
                    KIND_DETECTION,
                    native.id,
                    str(native.public_id),
                    "same_asset_topic_time",
                    "medium",
                    "Detección nativa de Sentra del mismo activo, en la misma ventana de"
                    " ±15 min y con la misma técnica MITRE o el mismo tema. Probablemente el"
                    " mismo hecho visto por Wazuh: no se crea otra detección.",
                    native_rule_id=native.rule_id,
                )
            if matched:
                _set_origin(event, "probable_match")
                continue
        _set_origin(event, origin)
        seen_assets: set[int] = set()
        for candidate in candidates:
            asset_id = int(candidate["asset_id"])
            if asset_id in seen_assets:
                continue
            seen_assets.add(asset_id)
            if emitted >= MAX_SIGNALS_PER_BATCH:
                break
            role = str(candidate.get("role"))
            signature = event.signature_id or event.rule_id or event.event_type
            data: dict[str, Any] = {
                "event_id": str(event.event_id),
                "source_type": event.source_type,
                "source_name": ingested.source.name,
                "event_type": event.event_type,
                "severity": event.severity,
                "source_severity": event.source_severity,
                "signature_id": event.signature_id,
                "rule_id": event.rule_id,
                "message": (event.message or "")[:300],
                "role": role,
                "attribution_method": candidate.get("method"),
                "attribution_confidence": candidate.get("confidence"),
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "dst_port": event.dst_port,
                "protocol": event.protocol,
                "mitre_techniques": list(event.mitre_techniques or [])[:4],
                "mitre_tactic": (event.data or {}).get("mitre_tactic"),
                "ndr_flow_uids": flow_uids[:5],
                "ndr_anomaly_ids": anomaly_ids[:5],
                "origin": origin,
            }
            session.add(
                DetectionSignal(
                    asset_id=asset_id,
                    kind=SignalKind.SIEM_ALERT.value,
                    subject=(f"siem:{event.source_type}:{signature}:{role}:{_peer(event, role)}")[
                        :255
                    ],
                    occurred_at=event.observed_at,
                    source_type=SourceType.SIEM.value,
                    source_id=str(event.event_id),
                    data=data,
                    created_at=now,
                )
            )
            emitted += 1
    if match_rows:
        session.execute(
            pg_insert(SiemEventLink)
            .values(match_rows)
            .on_conflict_do_nothing(constraint="uq_siem_event_links_target")
        )
    session.flush()
