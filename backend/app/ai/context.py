"""Context builder de AI Security Insights (Fase 4J).

Única capa que lee la base de datos para la IA. Ofrece un conjunto CERRADO de lecturas
(`asset`, `detection`, `fleet`) que la aplicación elige; el modelo nunca decide qué consultar
ni recibe SQL, y no hay forma de pedir otras tablas (usuarios, sesiones, auditoría, tokens).

Qué hace con los datos:
- consume los resultados de los motores deterministas (detecciones 4H, riesgo 4I, alertas,
  exposición): la IA interpreta, no recalcula;
- acota todo: elementos por análisis (AI_MAX_CONTEXT_ITEMS), longitud de cada texto, claves
  de los diccionarios, ventana temporal. Prioriza correlaciones, detecciones críticas/altas,
  contribuciones de riesgo y cambios recientes de exposición; el resto se resume en
  contadores ("omitted") para que el modelo sepa que hay más y lo diga;
- asigna a cada elemento citable un identificador corto ("D1", "C2", "E3"). El modelo solo
  puede citar esos identificadores; el servidor los traduce a referencias reales (tipo e id
  público) y descarta cualquier otro. Así un ID inventado nunca llega a la UI;
- sanea el texto no confiable (sin caracteres de control, acotado) y aplica la
  seudonimización configurada (AI_REDACT) antes de que nada salga del servidor.
"""

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.ai.redaction import Redactor
from app.core.exceptions import NotFoundError
from app.detection.rules import RULES_BY_ID
from app.detection.text import clean
from app.incidents.workflow import incident_key
from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset
from app.models.asset_context import AssetBusinessContext, AssetRole
from app.models.change import AssetChange
from app.models.detection import (
    SEVERITY_RANK,
    Detection,
    DetectionEvidence,
    DetectionSeverity,
    DetectionStatus,
)
from app.models.event import SystemEvent
from app.models.exposure import AssetPort, PortStateValue
from app.models.incident import (
    Incident,
    IncidentActivity,
    IncidentAlert,
    IncidentAsset,
    IncidentDetection,
    IncidentNote,
    IncidentThreatMatch,
)
from app.models.risk import RiskSnapshot
from app.models.threat_intel import ThreatIndicator, ThreatIntelMatch, ThreatIntelSource
from app.models.vulnerability import Vulnerability, VulnerabilityFinding
from app.risk.config import RiskConfig
from app.services.asset_context_service import (
    COMPLETENESS_FIELDS,
    ContextValues,
    role_suggestion,
    tags_by_asset,
)
from app.services.asset_service import effective_status
from app.services.detection_rule_service import rule_text
from app.services.incident_service import family_ids
from app.services.risk_service import RiskService
from app.threat_intel.lookup import load_exploitation

RefType = Literal[
    "asset",
    "detection",
    "event",
    "evidence",
    "exposure",
    "risk_contribution",
    "risk_snapshot",
    "alert",
    "change",
    "incident",
    "note",
    "vulnerability",
    "threat_match",
]

# Prefijo del identificador corto de cada tipo (lo que ve el modelo).
_PREFIX: dict[str, str] = {
    "asset": "A",
    "detection": "D",
    "event": "E",
    "evidence": "V",
    "exposure": "X",
    "risk_contribution": "C",
    "risk_snapshot": "S",
    "alert": "L",
    "change": "H",
    # Fase 4K: el incidente y sus notas (texto del analista, no confiable).
    "incident": "I",
    "note": "N",
    # Fase 5B: finding de vulnerabilidad (la V ya es evidencia).
    "vulnerability": "F",
    # Fase 5C: match de inteligencia de amenazas con un dato local.
    "threat_match": "T",
}

# Claves de diccionarios no confiables que se seudonimizan como campo estructurado.
_KEY_FIELDS: dict[str, str] = {
    "account": "usernames",
    "user": "usernames",
    "username": "usernames",
    "actor": "usernames",
    "member": "usernames",
    "target_user": "usernames",
    "subject_user": "usernames",
    "workstation": "hostnames",
    "computer": "hostnames",
    "hostname": "hostnames",
    "host": "hostnames",
    "domain": "hostnames",
    "source_ip": "ips",
    "ip": "ips",
    "ip_address": "ips",
    "address": "ips",
    "success_source": "ips",
    "path": "paths",
    "image_path": "paths",
    "process": "paths",
    "command_line": "paths",
}

TEXT_LIMIT = 300
SHORT_LIMIT = 120
MAX_KEYS = 16
MAX_LIST = 10
MAX_DEPTH = 3

WINDOWS: dict[str, timedelta] = {
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}


@dataclass(frozen=True)
class EvidenceRef:
    """Referencia interna navegable a la que puede apuntar un hallazgo."""

    type: str
    id: str
    label: str
    # Activo al que pertenece (para enlazar en la UI); None en referencias de flota.
    asset_id: str | None = None

    def as_dict(self) -> dict[str, str | None]:
        return {"type": self.type, "id": self.id, "label": self.label, "asset_id": self.asset_id}


@dataclass
class AIContext:
    """Contexto acotado listo para el prompt, con el mapa de referencias citables."""

    scope: str
    data: dict[str, Any]
    refs: dict[str, EvidenceRef]
    redactor: Redactor
    # Elementos con referencia incluidos (métrica técnica y límite de tamaño).
    items: int = 0
    asset_pk: int | None = None
    detection_pk: int | None = None
    risk_snapshot_pk: int | None = None
    incident_pk: int | None = None
    vulnerability_pk: int | None = None
    # Hay datos sustantivos sobre los que razonar (si no, no se llama al modelo).
    has_data: bool = True
    omitted: dict[str, int] = field(default_factory=dict)

    def input_refs(self) -> list[dict[str, str]]:
        """Referencias de entrada que se guardan con el insight (sin el contenido)."""
        return [{"ref": key, "type": ref.type, "id": ref.id} for key, ref in self.refs.items()]


class ContextBuilder:
    def __init__(
        self,
        session: Session,
        risk_config: RiskConfig,
        heartbeat_timeout: timedelta,
        max_items: int,
        redactor: Redactor,
        now: datetime | None = None,
    ) -> None:
        self._session = session
        self._risk = RiskService(session, risk_config, heartbeat_timeout)
        self._timeout = heartbeat_timeout
        self._max_items = max_items
        self._r = redactor
        self._now = now or datetime.now(UTC)
        self._refs: dict[str, EvidenceRef] = {}
        self._by_target: dict[tuple[str, str], str] = {}
        self._counters: dict[str, int] = {}
        self._omitted: dict[str, int] = {}

    # --- Referencias y presupuesto ------------------------------------------------------------

    def _budget_left(self) -> int:
        return self._max_items - len(self._refs)

    def _ref(self, type_: str, id_: str, label: str, asset_id: str | None) -> str | None:
        """Identificador corto para un elemento citable; None si se agotó el presupuesto."""
        existing = self._by_target.get((type_, id_))
        if existing is not None:
            return existing
        if self._budget_left() <= 0:
            self._omitted[type_] = self._omitted.get(type_, 0) + 1
            return None
        prefix = _PREFIX[type_]
        self._counters[prefix] = self._counters.get(prefix, 0) + 1
        key = f"{prefix}{self._counters[prefix]}"
        self._refs[key] = EvidenceRef(type_, id_, clean(label, 160), asset_id)
        self._by_target[(type_, id_)] = key
        return key

    def _omit(self, type_: str, count: int) -> None:
        if count > 0:
            self._omitted[type_] = self._omitted.get(type_, 0) + count

    def _finish(
        self,
        scope: str,
        data: dict[str, Any],
        asset_pk: int | None = None,
        detection_pk: int | None = None,
        risk_snapshot_pk: int | None = None,
        incident_pk: int | None = None,
        vulnerability_pk: int | None = None,
    ) -> AIContext:
        if self._omitted:
            # El modelo debe saber que hay más datos de los que ve (y decirlo).
            data["omitted_for_size"] = dict(self._omitted)
        # Última pasada: seudonimiza en el texto libre los valores ya registrados.
        redacted = _redact_tree(data, self._r) if self._r.active else data
        return AIContext(
            scope=scope,
            data=redacted,
            refs=dict(self._refs),
            redactor=self._r,
            items=len(self._refs),
            omitted=dict(self._omitted),
            asset_pk=asset_pk,
            detection_pk=detection_pk,
            risk_snapshot_pk=risk_snapshot_pk,
            incident_pk=incident_pk,
            vulnerability_pk=vulnerability_pk,
        )

    # --- Saneado de datos no confiables ------------------------------------------------------

    def _text(self, value: object, limit: int = TEXT_LIMIT) -> str | None:
        if value is None:
            return None
        text = clean(value, limit)
        return text or None

    def _safe(self, value: Any, depth: int = 0, key: str | None = None) -> Any:
        """Copia acotada de datos no confiables: escalares limpios, profundidad limitada."""
        if value is None or isinstance(value, bool | int | float):
            return value
        if isinstance(value, dict):
            if depth >= MAX_DEPTH:
                return "[estructura omitida]"
            result: dict[str, Any] = {}
            for k, v in list(value.items())[:MAX_KEYS]:
                safe_key = clean(k, 48)
                result[safe_key] = self._safe(v, depth + 1, safe_key.lower())
            return result
        if isinstance(value, list | tuple):
            return [self._safe(v, depth + 1, key) for v in list(value)[:MAX_LIST]]
        text = clean(value, 200)
        field_name = _KEY_FIELDS.get(key or "")
        if field_name:
            return self._r.value(field_name, text)
        return text

    # --- Lecturas cerradas ------------------------------------------------------------------

    def _asset_by_public_id(self, public_id: UUID) -> Asset:
        asset = self._session.scalar(select(Asset).where(Asset.public_id == public_id))
        if asset is None:
            raise NotFoundError("Asset not found")
        return asset

    def _asset_item(self, asset: Asset) -> dict[str, Any]:
        public = str(asset.public_id)
        name = self._r.value("hostnames", clean(asset.display_name, SHORT_LIMIT))
        return {
            "ref": self._ref("asset", public, asset.display_name, public),
            "name": name,
            "hostname": self._r.value("hostnames", self._text(asset.hostname, SHORT_LIMIT)),
            "ip": self._r.value("ips", asset.primary_ip),
            "device_type": asset.device_type,
            "os": self._text(" ".join(filter(None, [asset.os_name, asset.os_version])), 80),
            "monitoring_method": asset.monitoring_method.value,
            "status": effective_status(asset, self._now, self._timeout).value,
            "criticality": asset.criticality.value,
            "last_seen_at": asset.last_seen_at or asset.last_network_seen_at,
            "business_context": self._business_context(asset),
        }

    def _business_context(self, asset: Asset) -> dict[str, Any]:
        """Asset Context (Fase 4L) con procedencia, para que la IA explique el impacto.

        Solo lo CONFIRMADO va en `confirmed`; lo desconocido se lista en `unknown` para que
        el modelo no lo suponga, y la sugerencia de rol de la identificación va aparte como
        inferencia. Responsable y departamento se seudonimizan como "owners" (siempre con
        proveedor no local; con local, según AI_REDACT).
        """
        ctx = self._session.get(AssetBusinessContext, asset.id)
        values = ContextValues.of(asset, ctx)
        provenance = (ctx.provenance if ctx else None) or {}
        confirmed: dict[str, Any] = {}
        unknown: list[str] = []
        for name in COMPLETENESS_FIELDS:
            if not values.known(name):
                unknown.append(name)
                continue
            raw = getattr(values, name)
            value: Any = getattr(raw, "value", raw)
            if name in ("owner", "department"):
                value = self._r.value("owners", clean(value, SHORT_LIMIT))
            source = provenance.get(name, {}).get("source") if name in provenance else None
            confirmed[name] = {"value": value, "source": source or "manual"}
        data: dict[str, Any] = {"confirmed": confirmed, "unknown": unknown}
        tags = tags_by_asset(self._session, [asset.id]).get(asset.id, [])
        if tags:
            data["tags"] = tags[:MAX_LIST]
        suggestion = role_suggestion(asset, values.role)
        if suggestion is not None and values.role == AssetRole.UNKNOWN:
            data["suggested_role"] = {
                "value": suggestion.value.value,
                "kind": "inferred",
                "source": suggestion.source,
                "confidence": suggestion.confidence.value if suggestion.confidence else None,
            }
        return data

    def _detection_item(self, d: Detection, asset: Asset) -> dict[str, Any] | None:
        public = str(d.public_id)
        key = self._ref("detection", public, f"{d.rule_id}: {d.title}", str(asset.public_id))
        if key is None:
            return None
        rule = RULES_BY_ID.get(d.rule_id)
        meta = rule.meta if rule else None
        return {
            "ref": key,
            "rule_id": d.rule_id,
            "rule_source": d.rule_source,
            "kind": d.kind,
            "category": d.rule_category or (meta.category if meta else None),
            "title": self._text(d.title, 200),
            "summary": self._text(d.summary),
            "severity": d.severity.value,
            "confidence": d.confidence.value,
            "status": d.status.value,
            "occurrences": d.occurrence_count,
            "first_seen_at": d.first_seen_at,
            "last_seen_at": d.last_seen_at,
            "mitre_technique": d.mitre_subtechnique or d.mitre_technique,
            "asset": self._by_target.get(("asset", str(asset.public_id))),
        }

    def _risk_block(self, asset: Asset, contributions_limit: int = 12) -> dict[str, Any]:
        """Riesgo determinista del activo (4I): score, nivel, confianza, factores e historial."""
        detail = self._risk.detail(asset.public_id)
        public = str(asset.public_id)
        if not detail.evaluated:
            return {"evaluated": False, "note": "El Risk Engine aún no evaluó este activo."}
        contributions = []
        relevant = [c for c in detail.contributions if c.points != 0]
        for index, c in enumerate(relevant[:contributions_limit]):
            key = self._ref("risk_contribution", f"{public}#{index}", c.label, public)
            if key is None:
                break
            contributions.append(
                {
                    "ref": key,
                    "factor": c.factor,
                    "category": c.category,
                    "label": self._text(c.label, 200),
                    "points": round(c.points, 1),
                    "detection": (
                        self._by_target.get(("detection", str(c.detection_id)))
                        if c.detection_id
                        else None
                    ),
                    "port": c.port,
                }
            )
        self._omit("risk_contribution", len(relevant) - len(contributions))
        changes = []
        for s in detail.recent_changes[:5]:
            key = self._ref(
                "risk_snapshot", str(s.snapshot_id), f"Riesgo {s.score} ({s.level})", public
            )
            if key is None:
                break
            changes.append(
                {
                    "ref": key,
                    "at": s.calculated_at,
                    "score": s.score,
                    "level": s.level.value,
                    "previous_score": s.previous_score,
                    "transition": s.transition,
                    "reason": s.reason,
                }
            )
        return {
            "evaluated": True,
            "score": detail.score,
            "level": detail.level.value if detail.level else None,
            "confidence": detail.confidence.value if detail.confidence else None,
            "trend_24h": detail.trend_24h,
            "calculated_at": detail.calculated_at,
            "pending_recalculation": detail.pending_recalculation,
            # Explicación determinista ya calculada por 4I (texto de plantillas).
            "headline": self._text(detail.explanation.headline, 200),
            "reasons": [self._text(r, 200) for r in detail.explanation.reasons[:6]],
            "confidence_factors": [
                f"{f.effect} {self._text(f.label, 160)}"
                for f in detail.explanation.confidence_factors[:6]
            ],
            "contributions": contributions,
            "recent_changes": changes,
        }

    def _latest_snapshot_pk(self, asset: Asset) -> int | None:
        return self._session.scalar(
            select(RiskSnapshot.id)
            .where(RiskSnapshot.asset_id == asset.id)
            .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
            .limit(1)
        )

    def _active_detections(self, asset: Asset, limit: int) -> list[dict[str, Any]]:
        where = (Detection.asset_id == asset.id, Detection.status != DetectionStatus.RESOLVED)
        rows = self._session.scalars(
            select(Detection)
            .where(*where)
            # Correlaciones primero, luego severidad (orden del enum) y actividad reciente.
            .order_by(
                (Detection.kind == "correlation").desc(),
                Detection.severity.desc(),
                Detection.last_seen_at.desc(),
                Detection.id,
            )
            .limit(limit)
        ).all()
        total = self._session.scalar(select(func.count()).select_from(Detection).where(*where)) or 0
        items = [i for d in rows if (i := self._detection_item(d, asset)) is not None]
        self._omit("detection", total - len(items))
        return items

    def _exposure(self, asset: Asset, recent: timedelta) -> dict[str, Any]:
        ports = self._session.scalars(
            select(AssetPort)
            .where(
                AssetPort.asset_id == asset.id,
                (AssetPort.state == PortStateValue.OPEN)
                | (AssetPort.closed_at >= self._now - recent),
            )
            # Aperturas recientes primero: son el cambio de exposición relevante.
            .order_by(AssetPort.opened_at.desc())
            .limit(20)
        ).all()
        public = str(asset.public_id)
        items = []
        for p in ports:
            key = self._ref("exposure", f"{public}:{p.protocol}/{p.port}", f"{p.port}/tcp", public)
            if key is None:
                break
            items.append(
                {
                    "ref": key,
                    "port": p.port,
                    "service_hint": p.service_hint,
                    "state": p.state.value,
                    "opened_at": p.opened_at,
                    "closed_at": p.closed_at,
                    "recently_opened": p.opened_at >= self._now - recent,
                }
            )
        return {"ports": items, "note": "Puertos alcanzables desde el servidor de Sentra."}

    def _changes(self, asset: Asset, since: datetime, limit: int) -> list[dict[str, Any]]:
        rows = self._session.scalars(
            select(AssetChange)
            .where(AssetChange.asset_id == asset.id, AssetChange.detected_at >= since)
            .order_by(AssetChange.detected_at.desc())
            .limit(limit)
        ).all()
        public = str(asset.public_id)
        items = []
        for c in rows:
            key = self._ref("change", str(c.public_id), f"{c.category}: {c.item}", public)
            if key is None:
                break
            items.append(
                {
                    "ref": key,
                    "category": c.category.value,
                    "kind": c.kind.value,
                    # Nombre de software/servicio/cuenta: dato no confiable del host.
                    "item": self._safe(
                        c.item, key="account" if c.category.value == "account" else None
                    ),
                    "detected_at": c.detected_at,
                }
            )
        return items

    def _alerts(self, asset: Asset | None, limit: int) -> list[dict[str, Any]]:
        stmt = select(Alert, Asset).join(Asset, Asset.id == Alert.asset_id)
        stmt = stmt.where(Alert.status != AlertStatus.RESOLVED)
        if asset is not None:
            stmt = stmt.where(Alert.asset_id == asset.id)
        rows = self._session.execute(
            stmt.order_by(Alert.opened_at.desc(), Alert.id.desc()).limit(limit)
        ).all()
        items = []
        for alert, owner in rows:
            label = f"{alert.rule}: {alert.message}"
            key = self._ref("alert", str(alert.public_id), label, str(owner.public_id))
            if key is None:
                break
            items.append(
                {
                    "ref": key,
                    "rule": alert.rule.value,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "message": self._text(alert.message, 200),
                    "opened_at": alert.opened_at,
                    "asset": self._by_target.get(("asset", str(owner.public_id))),
                }
            )
        return items

    # --- Contextos por tipo de insight ------------------------------------------------------

    def asset(
        self,
        public_id: UUID,
        *,
        detection_limit: int = 12,
        include_inventory_changes: bool = True,
    ) -> AIContext:
        """Activo: estado, detecciones activas, riesgo, exposición, cambios y alertas."""
        asset = self._asset_by_public_id(public_id)
        data: dict[str, Any] = {"generated_for": "asset", "now": self._now}
        data["asset"] = self._asset_item(asset)
        # Orden = prioridad dentro del presupuesto: detecciones (correlaciones y graves
        # primero) antes que contribuciones, exposición, cambios y alertas.
        data["active_detections"] = self._active_detections(asset, limit=detection_limit)
        data["risk"] = self._risk_block(asset)
        data["exposure"] = self._exposure(asset, timedelta(hours=24))
        if include_inventory_changes:
            data["recent_changes_24h"] = self._changes(asset, self._now - timedelta(hours=24), 8)
            data["active_alerts"] = self._alerts(asset, 5)
        data["threat_intel_matches"] = self._threat_matches([asset.id], 6)
        return self._finish(
            "asset",
            data,
            asset_pk=asset.id,
            risk_snapshot_pk=self._latest_snapshot_pk(asset),
        )

    def detection(self, public_id: UUID) -> AIContext:
        """Detección con su evidencia, la regla, el activo y detecciones cercanas."""
        row = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.public_id == public_id)
        ).first()
        if row is None:
            raise NotFoundError("Detection not found")
        detection, asset = row[0], row[1]
        data: dict[str, Any] = {"generated_for": "detection", "now": self._now}
        data["asset"] = self._asset_item(asset)
        item = self._detection_item(detection, asset) or {}
        rule = RULES_BY_ID.get(detection.rule_id)
        meta = rule.meta if rule else None
        if meta is not None:
            # Catálogo built-in: texto fijo de Sentra (confiable), no datos del host.
            item["rule"] = {
                "description": meta.description,
                "why_it_matters": meta.why,
                "rule_recommendations": list(meta.recommendations),
            }
        else:
            # Fase 5A: los textos de reglas custom/Sigma los escribe un admin o vienen de un
            # YAML importado: son contenido NO confiable y pasan por el mismo saneado que los
            # datos del host (_text), nunca como instrucciones del sistema.
            texts = rule_text(self._session, detection.rule_id, detection.rule_version)
            item["rule"] = (
                {
                    "source": texts.source,
                    "description": self._text(texts.description, 400),
                    "why_it_matters": self._text(texts.why, 400),
                    "rule_recommendations": [
                        t for r in texts.recommendations[:5] if (t := self._text(r, 200))
                    ],
                }
                if texts
                else None
            )
        item["details"] = self._safe(detection.details or {})
        item["acknowledged"] = detection.acknowledged_at is not None
        item["resolution_note"] = self._text(detection.resolution_note, 200)
        data["detection"] = item
        data["evidence"] = self._evidence(detection, asset)
        # Detecciones del mismo activo en ±24 h: base para "¿qué parece relacionado?".
        window = timedelta(hours=24)
        related = self._session.scalars(
            select(Detection)
            .where(
                Detection.asset_id == asset.id,
                Detection.id != detection.id,
                Detection.last_seen_at >= detection.first_seen_at - window,
                Detection.first_seen_at <= detection.last_seen_at + window,
            )
            .order_by(Detection.severity.desc(), Detection.last_seen_at.desc())
            .limit(6)
        ).all()
        data["nearby_detections_same_asset_24h"] = [
            i for d in related if (i := self._detection_item(d, asset)) is not None
        ]
        risk = self._risk_block(asset, contributions_limit=5)
        risk.pop("recent_changes", None)
        data["asset_risk"] = risk
        return self._finish("detection", data, asset_pk=asset.id, detection_pk=detection.id)

    def _evidence(self, detection: Detection, asset: Asset) -> list[dict[str, Any]]:
        total = (
            self._session.scalar(
                select(func.count())
                .select_from(DetectionEvidence)
                .where(DetectionEvidence.detection_id == detection.id)
            )
            or 0
        )
        # Las más recientes (la detección ya resume las anteriores con contadores).
        rows = list(
            reversed(
                self._session.scalars(
                    select(DetectionEvidence)
                    .where(DetectionEvidence.detection_id == detection.id)
                    .order_by(DetectionEvidence.occurred_at.desc(), DetectionEvidence.id.desc())
                    .limit(15)
                ).all()
            )
        )
        # Un evento solo es referencia "event" si sigue existiendo (la retención lo purga).
        event_ids = {
            UUID(r.source_id)
            for r in rows
            if r.source_type == "system_event" and r.source_id and _is_uuid(r.source_id)
        }
        existing = (
            {
                str(e)
                for e in self._session.scalars(
                    select(SystemEvent.public_id).where(SystemEvent.public_id.in_(event_ids))
                )
            }
            if event_ids
            else set()
        )
        public = str(asset.public_id)
        items = []
        for index, r in enumerate(rows):
            if r.source_id in existing:
                key = self._ref("event", str(r.source_id), r.summary, public)
            else:
                key = self._ref("evidence", f"{detection.public_id}#{r.id}", r.summary, public)
            if key is None:
                break
            items.append(
                {
                    "ref": key,
                    "signal": r.signal_kind,
                    "role": r.role,
                    "source_type": r.source_type,
                    "occurred_at": r.occurred_at,
                    "summary": self._text(r.summary),
                    "data": self._safe(r.data or {}),
                    "order": index + 1,
                }
            )
        self._omit("evidence", total - len(items))
        return items

    def incident(self, public_id: UUID) -> AIContext:
        """Incidente (Fase 4K): el caso, sus detecciones, evidencia, alertas, riesgo y notas.

        Mismas garantías que el resto de lecturas: solo datos ya relacionados con el caso por
        el servidor, acotados y seudonimizados. El título, la descripción y las notas son
        texto de analistas (no confiable): viajan como datos, nunca como instrucciones.
        """
        incident = self._session.scalar(select(Incident).where(Incident.public_id == public_id))
        if incident is None:
            raise NotFoundError("Incident not found")
        family = family_ids(self._session, incident.id)
        data: dict[str, Any] = {"generated_for": "incident", "now": self._now}
        key = incident_key(incident.number)
        data["incident"] = {
            "ref": self._ref("incident", str(incident.public_id), key, None),
            "key": key,
            "title": self._text(incident.title, 200),
            "description": self._text(incident.description, 600),
            "status": incident.status.value,
            "severity": incident.severity.value,
            "priority": incident.priority.value,
            "confidence": incident.confidence.value if incident.confidence else None,
            "assigned": incident.owner_user_id is not None,
            "created_at": incident.created_at,
            "first_seen_at": incident.first_seen_at,
            "last_seen_at": incident.last_seen_at,
            "resolution_category": (
                incident.resolution_category.value if incident.resolution_category else None
            ),
            "risk_snapshot": {
                "score": incident.risk_score_snapshot,
                "level": incident.risk_level_snapshot,
                "taken_at": incident.risk_snapshot_at,
            },
        }
        assets = list(
            self._session.scalars(
                select(Asset)
                .join(IncidentAsset, IncidentAsset.asset_id == Asset.id)
                .where(IncidentAsset.incident_id == incident.id)
                .order_by(IncidentAsset.id)
                .limit(5)
            )
        )
        data["assets"] = [self._asset_item(a) for a in assets]
        # Detecciones del caso: correlaciones y graves primero (prioridad dentro del límite).
        linked = select(IncidentDetection.detection_id).where(
            IncidentDetection.incident_id.in_(family)
        )
        rows = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(Detection.id.in_(linked))
            .order_by(
                (Detection.kind == "correlation").desc(),
                Detection.severity.desc(),
                Detection.last_seen_at.desc(),
            )
            .limit(12)
        ).all()
        total = (
            self._session.scalar(
                select(func.count()).select_from(Detection).where(Detection.id.in_(linked))
            )
            or 0
        )
        data["incident_detections"] = [
            i for d, a in rows if (i := self._detection_item(d, a)) is not None
        ]
        self._omit("detection", total - len(data["incident_detections"]))
        # Evidencia de las dos detecciones principales (la del resto se resume en contadores).
        data["evidence"] = [item for d, a in rows[:2] for item in self._evidence(d, a)]
        alert_rows = self._session.execute(
            select(Alert, Asset)
            .join(Asset, Asset.id == Alert.asset_id)
            .where(
                Alert.id.in_(
                    select(IncidentAlert.alert_id).where(IncidentAlert.incident_id.in_(family))
                )
            )
            .order_by(Alert.opened_at.desc())
            .limit(5)
        ).all()
        data["incident_alerts"] = []
        for alert, owner in alert_rows:
            ref = self._ref(
                "alert",
                str(alert.public_id),
                f"{alert.rule}: {alert.message}",
                str(owner.public_id),
            )
            if ref is None:
                break
            data["incident_alerts"].append(
                {
                    "ref": ref,
                    "rule": alert.rule.value,
                    "severity": alert.severity.value,
                    "status": alert.status.value,
                    "message": self._text(alert.message, 200),
                    "opened_at": alert.opened_at,
                }
            )
        if assets:
            risk = self._risk_block(assets[0], contributions_limit=5)
            data["primary_asset_risk"] = risk
        data["threat_intel_matches"] = self._threat_matches(
            [],
            6,
            match_ids=select(IncidentThreatMatch.match_id).where(
                IncidentThreatMatch.incident_id.in_(family)
            ),
        )
        notes = self._session.scalars(
            select(IncidentNote)
            .where(IncidentNote.incident_id.in_(family))
            .order_by(IncidentNote.created_at.desc(), IncidentNote.id.desc())
            .limit(8)
        ).all()
        data["analyst_notes"] = []
        for note in reversed(notes):
            ref = self._ref("note", str(note.public_id), _note_label(note.body), None)
            if ref is None:
                break
            data["analyst_notes"].append(
                {
                    "ref": ref,
                    "author": self._r.value("usernames", note.author),
                    "at": note.created_at,
                    "text": self._text(note.body),
                }
            )
        activity = self._session.scalars(
            select(IncidentActivity)
            .where(IncidentActivity.incident_id.in_(family))
            .order_by(IncidentActivity.occurred_at.desc(), IncidentActivity.id.desc())
            .limit(15)
        ).all()
        # Actividad del caso como contexto cronológico (sin refs: ya la generó Sentra).
        data["case_activity"] = [
            {"at": a.occurred_at, "action": a.action, "summary": self._text(a.summary, 200)}
            for a in reversed(activity)
        ]
        ctx = self._finish("incident", data, incident_pk=incident.id)
        return ctx

    def vulnerability(self, public_id: UUID) -> AIContext:
        """Finding de vulnerabilidad (Fase 5B): qué dice el catálogo, qué se comparó y con qué
        resultado, la exposición observada y el riesgo del activo.

        Solo datos ya guardados por Sentra. Las referencias externas del catálogo (URLs) no se
        envían: el modelo no puede abrirlas y no debe presentarlas como verificadas.
        """
        row = self._session.execute(
            select(VulnerabilityFinding, Vulnerability, Asset)
            .join(Vulnerability, Vulnerability.id == VulnerabilityFinding.vulnerability_id)
            .join(Asset, Asset.id == VulnerabilityFinding.asset_id)
            .where(VulnerabilityFinding.public_id == public_id)
        ).first()
        if row is None:
            raise NotFoundError("Vulnerability finding not found")
        finding, vuln, asset = row
        public = str(asset.public_id)
        data: dict[str, Any] = {"generated_for": "vulnerability", "now": self._now}
        data["asset"] = self._asset_item(asset)
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        data["vulnerability_finding"] = {
            "ref": self._ref(
                "vulnerability",
                str(finding.public_id),
                f"{finding.vuln_external_id}: {finding.title}",
                public,
            ),
            "id": self._text(finding.vuln_external_id, 64),
            "title": self._text(finding.title, 200),
            # Texto del catálogo importado (no confiable): dato, nunca instrucción.
            "catalog_description": self._text(vuln.description, 600),
            "severity": finding.severity,
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else None,
            "cvss_version": vuln.cvss_version,
            "match_state": finding.match_state,
            "match_confidence": finding.confidence,
            "rationale": self._text(finding.rationale, 500),
            "status": finding.status,
            "status_reason": self._text(finding.status_reason, 300),
            "component": {
                "type": finding.component_type,
                "name": self._text(finding.component_name, 160),
                "vendor": self._text(finding.component_vendor, 120),
                "installed_version": self._text(finding.installed_version, 64),
                "affected_range": self._text(finding.affected_range, 200),
                "fixed_version": self._text(finding.fixed_version, 64),
            },
            "evidence": self._safe(
                {
                    "source": evidence.get("source"),
                    "collected_at": evidence.get("collected_at"),
                    "instances": evidence.get("instances"),
                    "checks": evidence.get("checks"),
                }
            ),
            "exposure": self._safe(finding.exposure),
            "priority": {"score": finding.priority_score, "level": finding.priority_level},
            "first_seen_at": finding.first_seen_at,
            "last_seen_at": finding.last_seen_at,
            "inventory_observed_at": finding.inventory_observed_at,
            "remediation": self._text(vuln.remediation, 400),
            # Fase 5C: inteligencia EXTERNA del CVE (no es evidencia del activo).
            "external_intelligence": self._exploitation(finding.intel_cve),
            "note": (
                "match_state lo decidió el matcher determinista de Sentra: confirmed y "
                "probable tienen evidencia de versión; potential y unknown NO confirman que "
                "el activo sea vulnerable."
            ),
        }
        data["exposure"] = self._exposure(asset, timedelta(hours=24))
        data["risk"] = self._risk_block(asset, contributions_limit=6)
        return self._finish(
            "vulnerability",
            data,
            asset_pk=asset.id,
            risk_snapshot_pk=self._latest_snapshot_pk(asset),
            vulnerability_pk=finding.id,
        )

    def _exploitation(self, cve: str | None) -> dict[str, Any]:
        """KEV/EPSS del CVE con su procedencia, separado de la evidencia local."""
        intel = load_exploitation(self._session, [cve], self._now).get(cve) if cve else None
        if intel is None:
            return {
                "available": False,
                "note": "Sin inteligencia de explotación configurada o sin datos para este CVE.",
            }
        data = intel.as_context()
        kev = data.get("kev") or {}
        if kev:
            kev["required_action"] = self._text((intel.kev or {}).get("required_action"), 300)
        return {
            "available": True,
            **self._safe(data),
            "note": (
                "Inteligencia externa. KEV significa que se ha reportado explotación de esta"
                " vulnerabilidad en algún lugar, NO que este activo haya sido atacado. EPSS es"
                " una probabilidad estadística de explotación en 30 días según FIRST, NO la"
                " probabilidad de que este activo esté comprometido. known_ransomware_use"
                " 'unknown' no significa que sea seguro."
            ),
        }

    def _threat_matches(
        self, asset_ids: Sequence[int], limit: int, match_ids: Any = None
    ) -> list[dict[str, Any]]:
        """Matches de IOCs: lo observado localmente separado de lo que dice la fuente."""
        stmt = (
            select(ThreatIntelMatch, ThreatIndicator, ThreatIntelSource, Asset)
            .join(ThreatIndicator, ThreatIndicator.id == ThreatIntelMatch.indicator_id)
            .join(ThreatIntelSource, ThreatIntelSource.id == ThreatIndicator.source_id)
            .join(Asset, Asset.id == ThreatIntelMatch.asset_id)
            .where(ThreatIntelMatch.status != "dismissed")
            .order_by(ThreatIntelMatch.last_observed_at.desc(), ThreatIntelMatch.id)
            .limit(limit)
        )
        stmt = (
            stmt.where(ThreatIntelMatch.id.in_(match_ids))
            if match_ids is not None
            else stmt.where(ThreatIntelMatch.asset_id.in_(asset_ids))
        )
        result: list[dict[str, Any]] = []
        for match, indicator, source, owner in self._session.execute(stmt):
            ref = self._ref(
                "threat_match",
                str(match.public_id),
                f"IOC {indicator.value_normalized} en {owner.display_name}",
                str(owner.public_id),
            )
            if ref is None:
                break
            result.append(
                {
                    "ref": ref,
                    "status": match.status,
                    "observed_locally": {
                        "observation_type": match.observation_type,
                        "value": self._text(match.observed_value, 120),
                        "first_observed_at": match.first_observed_at,
                        "last_observed_at": match.last_observed_at,
                        "count": match.observation_count,
                        "details": self._safe(match.evidence),
                    },
                    "external_intelligence": {
                        "indicator_type": indicator.indicator_type,
                        "indicator_value": self._text(indicator.value_normalized, 120),
                        "classification": indicator.classification,
                        "confidence": indicator.confidence,
                        "match_confidence": match.match_confidence,
                        "source": self._text(source.name, 100),
                        "source_trust": source.trust,
                        "revoked": indicator.revoked,
                        "valid_until": indicator.valid_until,
                        "tags": [self._text(t, 40) for t in (indicator.tags or [])[:5]],
                    },
                }
            )
        if result:
            # Recordatorio en los propios datos: la IA debe distinguir ambos bloques.
            result[0]["note"] = (
                "observed_locally es evidencia de Sentra; external_intelligence es lo que"
                " declara una fuente externa y no confirma un compromiso."
            )
        return result

    def fleet(
        self,
        window: str = "24h",
        min_severity: DetectionSeverity = DetectionSeverity.HIGH,
        *,
        focus_risk: bool = True,
    ) -> AIContext:
        """Visión SOC: detecciones graves de la ventana, activos con más riesgo y cambios."""
        since = self._now - WINDOWS[window]
        data: dict[str, Any] = {"generated_for": "fleet", "now": self._now, "window": window}
        total_assets = self._session.scalar(select(func.count()).select_from(Asset)) or 0
        active_counts = {s.value: 0 for s in DetectionSeverity}
        for severity, count in self._session.execute(
            select(Detection.severity, func.count())
            .where(Detection.status != DetectionStatus.RESOLVED)
            .group_by(Detection.severity)
        ):
            active_counts[severity.value] = count
        data["totals"] = {
            "assets": total_assets,
            "active_detections_by_severity": active_counts,
        }
        rank = SEVERITY_RANK[min_severity]
        severities = [s for s in DetectionSeverity if SEVERITY_RANK[s] >= rank]
        where = (Detection.severity.in_(severities), Detection.last_seen_at >= since)
        rows = self._session.execute(
            select(Detection, Asset)
            .join(Asset, Asset.id == Detection.asset_id)
            .where(*where)
            .order_by(
                (Detection.kind == "correlation").desc(),
                Detection.severity.desc(),
                Detection.last_seen_at.desc(),
            )
            .limit(15)
        ).all()
        in_window = (
            self._session.scalar(select(func.count()).select_from(Detection).where(*where)) or 0
        )
        assets_seen: dict[int, Asset] = {}
        detections = []
        for d, asset in rows:
            if asset.id not in assets_seen:
                assets_seen[asset.id] = asset
                # El activo como referencia mínima (nombre), sin cargar su detalle.
                self._ref("asset", str(asset.public_id), asset.display_name, str(asset.public_id))
            item = self._detection_item(d, asset)
            if item is not None:
                item["asset_name"] = self._r.value("hostnames", clean(asset.display_name, 120))
                detections.append(item)
        self._omit("detection", in_window - len(detections))
        data["detections_in_window"] = {
            "min_severity": min_severity.value,
            "total": in_window,
            "items": detections,
        }
        overview = self._risk.overview()
        top = []
        for a in overview.top_assets[: 10 if focus_risk else 5]:
            key = self._ref("asset", str(a.asset_id), a.display_name, str(a.asset_id))
            if key is None:
                break
            top.append(
                {
                    "ref": key,
                    "name": self._r.value("hostnames", clean(a.display_name, 120)),
                    "score": a.score,
                    "level": a.level.value if a.level else None,
                    "confidence": a.confidence.value if a.confidence else None,
                    "criticality": a.criticality.value,
                    "status": a.status.value,
                    "top_factor": self._text(a.top_factor, 160),
                }
            )
        transitions = []
        for t in overview.recent_transitions:
            if t.calculated_at < since:
                continue
            key = self._ref(
                "risk_snapshot",
                str(t.snapshot_id),
                f"{t.display_name}: {t.previous_level} -> {t.level}",
                str(t.asset_id),
            )
            if key is None:
                break
            transitions.append(
                {
                    "ref": key,
                    "asset": self._by_target.get(("asset", str(t.asset_id))),
                    "asset_name": self._r.value("hostnames", clean(t.display_name, 120)),
                    "at": t.calculated_at,
                    "previous_level": t.previous_level.value if t.previous_level else None,
                    "level": t.level.value,
                    "score": t.score,
                    "transition": t.transition,
                }
            )
        data["risk"] = {
            "evaluated_assets": overview.evaluated,
            "by_level": {k.value: v for k, v in overview.by_level.items()},
            "by_confidence": {k.value: v for k, v in overview.by_confidence.items()},
            "top_factors": [
                {"category": f.category, "label": f.label, "assets": f.assets, "points": f.points}
                for f in overview.top_factors[:6]
            ],
            "top_risky_assets": top,
            "level_transitions_in_window": transitions,
        }
        data["active_alerts"] = self._alerts(None, 8)
        ctx = self._finish("fleet", data)
        # Sin activos no hay nada que analizar: se responde sin llamar al modelo.
        ctx.has_data = total_assets > 0
        return ctx


def _note_label(body: str) -> str:
    return "Nota: " + clean(body, 80)


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
    except ValueError:
        return False
    return True


def _redact_tree(value: Any, redactor: Redactor) -> Any:
    if isinstance(value, dict):
        return {k: _redact_tree(v, redactor) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_tree(v, redactor) for v in value]
    if isinstance(value, str):
        return redactor.text(value)
    return value
