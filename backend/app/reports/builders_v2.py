"""Datos adicionales del snapshot para la plantilla v2 (Fase 6D.5).

Se ejecutan en la MISMA transacción REPEATABLE READ de solo lectura que los builders v1
(app/reports/builders.py), con el mismo `BuildContext` y la misma hora de corte, y su
resultado se guarda en `snapshot["extended"]`. Las gráficas v2 salen SOLO de aquí y del resto
del snapshot: el render nunca consulta la base de datos.

Reglas (las mismas de los builders v1):
- consultas agregadas y acotadas (GROUP BY, LIMIT), nada de SELECT * de tablas grandes;
- el Risk Engine y el Detection Engine son la única fuente: se leen sus resultados guardados;
- todo texto libre pasa por la redacción (app/reports/redaction.py), también las etiquetas
  que acabarán en una gráfica o en el diagrama de topología;
- se distingue "no medido" de "cero": cada serie dice si hay fuente que la mida (p. ej. los
  eventos del sistema solo existen en activos con agente).

Los informes v1 no llevan `extended` y siguen renderizándose igual que antes.
"""

import logging
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import Float, String, and_, case, cast, func, or_, select, true
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Session
from sqlalchemy.sql import column

from app.models.asset import Asset, AssetCriticality, MonitoringMethod
from app.models.detection import Detection
from app.models.event import SystemEvent
from app.models.exposure import AssetPort, PortStateValue
from app.models.response import ResponseExecution
from app.models.risk import AssetRisk, RiskSnapshot
from app.reports.builders import (
    BuildContext,
    _detection_conditions,
    _enum,
    _execution_conditions,
    _in_range,
    _ordered,
    _single_asset,
    _text,
    asset_conditions,
    iso,
    scoped_asset_ids,
)
from app.reports.redaction import redact_text

logger = logging.getLogger(__name__)

SEVERITIES = ("critical", "high", "medium", "low", "informational")
DETECTION_STATUSES = ("open", "acknowledged", "resolved")
LEVELS = ("critical", "high", "medium", "low", "informational")
CRITICALITIES = tuple(c.value for c in reversed(list(AssetCriticality)))
# Series de evolución del riesgo (una por activo) y puntos por serie.
RISK_HISTORY_ASSETS = 6
RISK_HISTORY_POINTS = 200
RISK_TRACE_ASSETS = 10
RISK_TRACE_CONTRIBUTIONS = 12
TOP_RULES = 15
TOP_PORTS = 15
TOPOLOGY_MAX_NODES = 60
TOPOLOGY_MAX_SITES = 3
# Cubos diarios hasta 92 días; por encima, semanales (lo mismo que las tendencias v1).
DAILY_MAX_DAYS = 92
# Claves numéricas que se copian del desglose del Risk Engine (nada de texto libre).
TRACE_KEYS = (
    "base_points",
    "criticality_factor",
    "type_factor",
    "context_factor",
    "raw_points",
    "saturation_knee",
    "saturated_points",
    "score",
    "formula_version",
)
NOMINAL_KEYS = ("severity_points", "confidence_factor", "occurrence_factor", "correlation_factor")
CHAIN_KEYS = ("recency_factor", "status_factor", "position_factor", "occurrence_count")


def _number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    return float(value)


# --- Series temporales ------------------------------------------------------------------------


def _unit(ctx: BuildContext) -> str | None:
    if ctx.start is None:
        return None
    return "day" if ctx.end - ctx.start <= timedelta(days=DAILY_MAX_DAYS) else "week"


def _bucket_start(moment: datetime, unit: str) -> datetime:
    moment = moment.astimezone(UTC)
    day = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    if unit == "week":
        # date_trunc('week') de PostgreSQL: lunes a las 00:00.
        day -= timedelta(days=day.weekday())
    return day


def _buckets(ctx: BuildContext, unit: str) -> list[datetime]:
    assert ctx.start is not None  # noqa: S101  (solo se llama con rango)
    step = timedelta(days=7 if unit == "week" else 1)
    current = _bucket_start(ctx.start, unit)
    out: list[datetime] = []
    while current <= ctx.end and len(out) < 400:
        out.append(current)
        current += step
    return out


def _series(ctx: BuildContext, unit: str, column_: Any, *conditions: Any) -> list[dict[str, Any]]:
    """Recuento por cubo con TODOS los cubos del periodo (los vacíos con 0): un día sin
    detecciones es un cero medido, no un hueco."""
    bucket = func.date_trunc(unit, column_)
    counts = {
        b.astimezone(UTC): int(c)
        for b, c in ctx.session.execute(
            select(bucket, func.count())
            .where(_in_range(column_, ctx), *conditions)
            .group_by(bucket)
            .order_by(bucket)
        ).all()
        if b is not None
    }
    return [{"bucket": iso(b), "count": counts.get(b, 0)} for b in _buckets(ctx, unit)]


def _agents_in_scope(ctx: BuildContext) -> int:
    managed = or_(
        Asset.agent_id.is_not(None),
        Asset.ever_managed,
        Asset.monitoring_method == MonitoringMethod.AGENT,
    )
    return int(ctx.session.scalar(select(func.count()).where(*asset_conditions(ctx), managed)) or 0)


def activity_trend(ctx: BuildContext, events: bool = True) -> dict[str, Any] | None:
    """Eventos del sistema y detecciones nuevas por día (o semana) en el periodo."""
    unit = _unit(ctx)
    if unit is None:
        return None
    detections = _series(
        ctx,
        unit,
        Detection.first_seen_at,
        Detection.asset_id.in_(scoped_asset_ids(ctx)),
        Detection.created_at <= ctx.cutoff,
    )
    out: dict[str, Any] = {
        "unit": unit,
        "start": iso(ctx.start),
        "end": iso(ctx.end),
        "detections": detections,
    }
    if events:
        agents = _agents_in_scope(ctx)
        out["agents_in_scope"] = agents
        # Sin ningún activo con agente, los eventos del sistema NO se miden: la serie se
        # omite (la plantilla dice "No medido") en lugar de dibujar ceros engañosos.
        out["events"] = (
            _series(
                ctx,
                unit,
                SystemEvent.occurred_at,
                SystemEvent.asset_id.in_(scoped_asset_ids(ctx)),
                SystemEvent.received_at <= ctx.cutoff,
            )
            if agents
            else None
        )
    return out


def execution_trend(ctx: BuildContext) -> dict[str, Any] | None:
    unit = _unit(ctx)
    if unit is None:
        return None
    conditions = _execution_conditions(ctx)
    return {
        "unit": unit,
        "start": iso(ctx.start),
        "end": iso(ctx.end),
        "executions": _series(ctx, unit, ResponseExecution.created_at, *conditions),
        "failed": _series(
            ctx,
            unit,
            ResponseExecution.created_at,
            *conditions,
            ResponseExecution.status.in_(("failed", "timed_out")),
        ),
    }


def new_assets_trend(ctx: BuildContext) -> dict[str, Any] | None:
    unit = _unit(ctx)
    if unit is None:
        return None
    return {
        "unit": unit,
        "start": iso(ctx.start),
        "end": iso(ctx.end),
        "new_assets": _series(ctx, unit, Asset.first_seen_at, *asset_conditions(ctx)),
    }


# --- Detecciones --------------------------------------------------------------------------


def detection_matrix(ctx: BuildContext) -> dict[str, dict[str, int]]:
    """Detecciones del alcance por severidad y estado (todas las celdas, con ceros)."""
    rows = ctx.session.execute(
        select(cast(Detection.severity, String), cast(Detection.status, String), func.count())
        .where(*_detection_conditions(ctx))
        .group_by(Detection.severity, Detection.status)
    ).all()
    counts: dict[str, dict[str, int]] = {}
    for severity, status, count in rows:
        counts.setdefault(str(severity), {})[str(status)] = int(count)
    return {
        severity: _ordered(counts.get(severity, {}), DETECTION_STATUSES)
        for severity in [*SEVERITIES, *sorted(set(counts) - set(SEVERITIES))]
    }


# --- Riesgo -------------------------------------------------------------------------------


def _scored_conditions(ctx: BuildContext) -> list[Any]:
    conditions = [
        AssetRisk.asset_id.in_(scoped_asset_ids(ctx)),
        AssetRisk.calculated_at.is_not(None),
    ]
    if ctx.filters.get("risk_levels"):
        conditions.append(cast(AssetRisk.level, String).in_(ctx.filters["risk_levels"]))
    return conditions


def risk_history(ctx: BuildContext, asset_ids: list[int] | None = None) -> dict[str, Any]:
    """Evolución del score (snapshots del Risk Engine) de los activos más riesgosos.

    Cada serie lleva también el último valor ANTERIOR al periodo (`baseline`), para que la
    línea empiece en el borde izquierdo con el valor que el activo ya tenía.
    """
    session = ctx.session
    if asset_ids is None:
        asset_ids = [
            asset_id
            for (asset_id,) in session.execute(
                select(AssetRisk.asset_id)
                .join(Asset, Asset.id == AssetRisk.asset_id)
                .where(*_scored_conditions(ctx))
                .order_by(AssetRisk.score.desc(), Asset.id)
                .limit(RISK_HISTORY_ASSETS)
            ).all()
        ]
    series = []
    for asset_id in asset_ids:
        asset = session.get(Asset, asset_id)
        if asset is None:
            continue
        points = [
            {"at": iso(at), "score": int(score)}
            for at, score in session.execute(
                select(RiskSnapshot.calculated_at, RiskSnapshot.score)
                .where(
                    RiskSnapshot.asset_id == asset_id, _in_range(RiskSnapshot.calculated_at, ctx)
                )
                .order_by(RiskSnapshot.calculated_at, RiskSnapshot.id)
                .limit(RISK_HISTORY_POINTS)
            ).all()
        ]
        baseline = None
        if ctx.start is not None:
            baseline = session.scalar(
                select(RiskSnapshot.score)
                .where(RiskSnapshot.asset_id == asset_id, RiskSnapshot.calculated_at < ctx.start)
                .order_by(RiskSnapshot.calculated_at.desc(), RiskSnapshot.id.desc())
                .limit(1)
            )
        series.append(
            {
                "asset_id": str(asset.public_id),
                "asset": _text(asset.display_name, 120),
                "baseline": int(baseline) if baseline is not None else None,
                "points": points,
            }
        )
    return {"start": iso(ctx.start), "end": iso(ctx.end), "series": series}


def risk_contributions(ctx: BuildContext) -> dict[str, Any]:
    """Aportes vigentes del Risk Engine agregados por categoría y por regla (solo lectura
    de asset_risk.contributions; no se recalcula nada)."""
    elements = (
        func.jsonb_array_elements(AssetRisk.contributions)
        .table_valued(column("value", JSONB))
        .alias("c")
    )
    value = elements.c.value
    points = cast(value["points"].astext, Float)
    base = (
        select()
        .select_from(AssetRisk)
        .join(elements, true())
        .where(
            *_scored_conditions(ctx),
            func.jsonb_typeof(AssetRisk.contributions) == "array",
            func.jsonb_typeof(value["points"]) == "number",
        )
    )
    category = value["category"].astext
    by_category = [
        {
            "category": _text(name, 32) or "unknown",
            "points": round(float(total or 0), 2),
            "count": int(count),
        }
        for name, total, count in ctx.session.execute(
            base.add_columns(category, func.sum(points), func.count())
            .where(points > 0)
            .group_by(category)
            .order_by(func.sum(points).desc(), category)
        ).all()
    ]
    rule = value["rule_id"].astext
    rule_rows = ctx.session.execute(
        base.add_columns(rule, func.min(value["label"].astext), func.sum(points), func.count())
        .where(points > 0, rule.is_not(None))
        .group_by(rule)
        .order_by(func.sum(points).desc(), rule)
    ).all()
    by_rule = [
        {
            "rule_id": _text(rule_id, 32),
            "label": _text(label, 160),
            "points": round(float(total or 0), 2),
            "count": int(count),
        }
        for rule_id, label, total, count in rule_rows[:TOP_RULES]
    ]
    assets = int(ctx.session.scalar(select(func.count()).where(*_scored_conditions(ctx))) or 0)
    return {
        "assets_scored": assets,
        "by_category": by_category,
        "by_rule": by_rule,
        "rules_total": len(rule_rows),
    }


def _trace(breakdown: Any) -> dict[str, float] | None:
    if not isinstance(breakdown, dict) or not isinstance(breakdown.get("trace"), dict):
        return None
    trace = breakdown["trace"]
    out = {key: _number(trace.get(key)) for key in TRACE_KEYS}
    clean = {key: value for key, value in out.items() if value is not None}
    return clean or None


def _chain(contributions: Any) -> list[dict[str, Any]]:
    if not isinstance(contributions, list):
        return []
    out = []
    for entry in contributions:
        if not isinstance(entry, dict) or entry.get("factor") != "detection":
            continue
        details = entry.get("details")
        if not isinstance(details, dict) or not isinstance(details.get("nominal_breakdown"), dict):
            continue
        nominal = details["nominal_breakdown"]
        item: dict[str, Any] = {
            "label": _text(entry.get("label"), 160),
            "rule_id": _text(entry.get("rule_id"), 32),
            "points": _number(entry.get("points")),
            "nominal_points": _number(entry.get("nominal_points")),
        }
        for key in NOMINAL_KEYS:
            item[key] = _number(nominal.get(key))
        for key in CHAIN_KEYS:
            item[key] = _number(details.get(key))
        out.append(item)
        if len(out) >= RISK_TRACE_CONTRIBUTIONS:
            break
    return out


def risk_traces(ctx: BuildContext, asset_ids: list[int] | None = None) -> list[dict[str, Any]]:
    """Cadena del cálculo de riesgo (breakdown.trace y details.nominal_breakdown) cuando el
    Risk Engine la guardó. Los cálculos antiguos no la tienen: entonces no se incluye nada."""
    query = select(AssetRisk, Asset).join(Asset, Asset.id == AssetRisk.asset_id)
    if asset_ids is not None:
        query = query.where(AssetRisk.asset_id.in_(asset_ids), AssetRisk.calculated_at.is_not(None))
    else:
        query = query.where(*_scored_conditions(ctx))
    rows = ctx.session.execute(
        query.order_by(AssetRisk.score.desc(), Asset.id).limit(RISK_TRACE_ASSETS)
    ).all()
    out = []
    for risk, asset in rows:
        trace = _trace(risk.breakdown)
        chain = _chain(risk.contributions)
        if trace is None and not chain:
            continue
        out.append(
            {
                "asset_id": str(asset.public_id),
                "asset": _text(asset.display_name, 120),
                "score": risk.score,
                "level": _enum(risk.level),
                "trace": trace,
                "chain": chain,
            }
        )
    return out


def criticality_comparison(ctx: BuildContext) -> dict[str, Any]:
    """Activos por criticidad y nivel de riesgo; los no puntuados aparte (no son "0")."""
    scored = and_(AssetRisk.asset_id.is_not(None), AssetRisk.calculated_at.is_not(None))
    bucket = case((scored, cast(AssetRisk.level, String)), else_="unscored")
    rows = ctx.session.execute(
        select(cast(Asset.criticality, String), bucket, func.count())
        .outerjoin(AssetRisk, AssetRisk.asset_id == Asset.id)
        .where(*asset_conditions(ctx))
        .group_by(Asset.criticality, bucket)
    ).all()
    stats = ctx.session.execute(
        select(
            cast(Asset.criticality, String),
            func.avg(AssetRisk.score),
            func.max(AssetRisk.score),
            func.count(AssetRisk.asset_id),
        )
        .join(AssetRisk, AssetRisk.asset_id == Asset.id)
        .where(*asset_conditions(ctx), AssetRisk.calculated_at.is_not(None))
        .group_by(Asset.criticality)
    ).all()
    counts: dict[str, dict[str, int]] = {}
    for criticality, bucket_value, count in rows:
        counts.setdefault(str(criticality), {})[str(bucket_value)] = int(count)
    summary = {
        str(c): {"avg_score": round(float(avg), 1), "max_score": int(mx), "scored": int(n)}
        for c, avg, mx, n in stats
        if avg is not None
    }
    return {
        "order": list(CRITICALITIES),
        "by_criticality": {
            c: _ordered(counts.get(c, {}), (*LEVELS, "unscored")) for c in CRITICALITIES
        },
        "scores": {c: summary.get(c) for c in CRITICALITIES},
    }


# --- Exposición ---------------------------------------------------------------------------


def exposure(ctx: BuildContext) -> dict[str, Any]:
    """Puertos abiertos vistos por discovery. Un activo sin ningún registro de puertos no se
    ha escaneado: cuenta como "no medido", no como "0 puertos abiertos"."""
    in_scope = AssetPort.asset_id.in_(scoped_asset_ids(ctx))
    observed = AssetPort.first_seen_at <= ctx.cutoff
    open_now = and_(AssetPort.state == PortStateValue.OPEN, AssetPort.opened_at <= ctx.cutoff)
    total_assets = int(ctx.session.scalar(select(func.count()).where(*asset_conditions(ctx))) or 0)
    scanned = int(
        ctx.session.scalar(
            select(func.count(func.distinct(AssetPort.asset_id))).where(in_scope, observed)
        )
        or 0
    )
    with_open = int(
        ctx.session.scalar(
            select(func.count(func.distinct(AssetPort.asset_id))).where(in_scope, open_now)
        )
        or 0
    )
    open_ports = int(ctx.session.scalar(select(func.count()).where(in_scope, open_now)) or 0)
    rows = ctx.session.execute(
        select(
            AssetPort.port,
            AssetPort.protocol,
            func.min(AssetPort.service_hint),
            func.count(func.distinct(AssetPort.asset_id)),
        )
        .where(in_scope, open_now)
        .group_by(AssetPort.port, AssetPort.protocol)
        .order_by(func.count(func.distinct(AssetPort.asset_id)).desc(), AssetPort.port)
    ).all()
    return {
        "assets_in_scope": total_assets,
        "assets_scanned": scanned,
        "assets_with_open_ports": with_open,
        "open_ports": open_ports,
        "top_ports": [
            {
                "port": int(port),
                "protocol": _text(protocol, 8),
                "service": _text(service, 32),
                "assets": int(count),
            }
            for port, protocol, service, count in rows[:TOP_PORTS]
        ],
        "distinct_ports": len(rows),
    }


# --- Topología ----------------------------------------------------------------------------


def _clean_topology(raw: Any) -> dict[str, Any]:
    """Copia acotada y redactada del resultado de report_topology: solo enlaces verificados
    (physical, logical u observed) entre nodos presentes; nunca se inventa ninguno."""
    nodes_in = raw.get("nodes") if isinstance(raw, dict) else None
    links_in = raw.get("links") if isinstance(raw, dict) else None
    nodes = []
    keys: set[str] = set()
    for node in (nodes_in or [])[:TOPOLOGY_MAX_NODES]:
        if not isinstance(node, dict) or node.get("id") is None:
            continue
        key = str(node["id"])[:120]
        if key in keys:
            continue
        keys.add(key)
        nodes.append(
            {
                "id": key,
                "label": redact_text(str(node.get("label") or key), 80),
                "kind": _text(node.get("kind"), 32),
                "device_type": _text(node.get("device_type"), 32),
                "role": _text(node.get("role"), 32),
            }
        )
    links = []
    for link in links_in or []:
        if not isinstance(link, dict):
            continue
        kind = str(link.get("kind") or "")
        source, target = str(link.get("source") or ""), str(link.get("target") or "")
        if kind not in ("physical", "logical", "observed") or source == target:
            continue
        if source not in keys or target not in keys:
            continue
        links.append(
            {
                "source": source,
                "target": target,
                "kind": kind,
                "relation": _text(link.get("relation"), 32),
                "confidence": _text(link.get("confidence"), 16),
            }
        )
        if len(links) >= 400:
            break
    links.sort(key=lambda x: (x["source"], x["target"], x["kind"], x["relation"] or ""))
    return {
        "status": "ok",
        "nodes": sorted(nodes, key=lambda n: n["id"]),
        "links": links,
        "truncated": bool(raw.get("truncated")) if isinstance(raw, dict) else False,
        "built_at": _text(raw.get("built_at"), 40) if isinstance(raw, dict) else None,
    }


def topology(
    session: Session, site_ids: list[int], asset_ids: list[int] | None
) -> list[dict[str, Any]]:
    """Topología verificada por site (docs/topology-engine.md, "Integración con informes v2").

    Importación diferida: el motor de topología es un módulo aparte; si no está disponible o
    falla, el informe lo dice explícitamente ("no disponible") en lugar de fallar entero o de
    dibujar nada inventado. Cada llamada va en un SAVEPOINT para que un error SQL no deje
    abortada la transacción de lectura del snapshot.
    """
    try:
        from app.topology.service import report_topology
    except ImportError:
        return [{"status": "unavailable", "site_id": None}]
    from app.models.site import Site

    out = []
    for site_id in site_ids[:TOPOLOGY_MAX_SITES]:
        site_name = session.scalar(select(Site.name).where(Site.id == site_id))
        try:
            with session.begin_nested():
                raw = report_topology(
                    session, site_id, asset_ids=asset_ids, max_nodes=TOPOLOGY_MAX_NODES
                )
            item = _clean_topology(raw)
        except Exception:  # el informe sigue; la sección dice que no se pudo obtener
            logger.warning("report topology failed", extra={"site_id": site_id}, exc_info=True)
            item = {"status": "error"}
        item["site"] = _text(site_name, 120)
        out.append(item)
    return out


def _topology_for_scope(ctx: BuildContext) -> list[dict[str, Any]]:
    site_ids = sorted(
        int(s)
        for (s,) in ctx.session.execute(
            select(Asset.site_id).where(*asset_conditions(ctx)).group_by(Asset.site_id)
        ).all()
    )
    asset_ids = None
    if ctx.filters.get("asset_ids"):
        asset_ids = [
            int(i) for (i,) in ctx.session.execute(select(Asset.id).where(*asset_conditions(ctx)))
        ]
    if not site_ids:
        return []
    return topology(ctx.session, site_ids, asset_ids)


# --- Por tipo -----------------------------------------------------------------------------


def _executive(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return {
        "activity": activity_trend(ctx),
        "criticality": criticality_comparison(ctx),
        "exposure": exposure(ctx),
        "risk_history": risk_history(ctx),
    }


def _technical(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "activity": activity_trend(ctx),
        "detection_matrix": detection_matrix(ctx),
        "criticality": criticality_comparison(ctx),
        "exposure": exposure(ctx),
    }
    ctx.checkpoint()
    out["risk_history"] = risk_history(ctx)
    out["risk_contributions"] = risk_contributions(ctx)
    out["risk_traces"] = risk_traces(ctx)
    ctx.checkpoint()
    out["topology"] = _topology_for_scope(ctx)
    return out


def _asset(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    asset = _single_asset(ctx)
    out: dict[str, Any] = {
        "activity": activity_trend(ctx),
        "detection_matrix": detection_matrix(ctx),
        "exposure": exposure(ctx),
        "risk_traces": risk_traces(ctx, [asset.id]),
    }
    ctx.checkpoint()
    out["topology"] = topology(ctx.session, [asset.site_id], [asset.id])
    return out


def _vulnerability(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return {"exposure": exposure(ctx)}


def _risk(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {
        "risk_history": risk_history(ctx),
        "risk_contributions": risk_contributions(ctx),
    }
    ctx.checkpoint()
    out["risk_traces"] = risk_traces(ctx)
    out["criticality"] = criticality_comparison(ctx)
    return out


def _detection(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return {"activity": activity_trend(ctx), "detection_matrix": detection_matrix(ctx)}


def _response(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return {"executions": execution_trend(ctx)}


def _lifecycle(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return {"new_assets": new_assets_trend(ctx)}


def _incident(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    # El informe de incidente no usa rango: sus gráficas salen de las filas del propio
    # snapshot (línea de tiempo, detecciones vinculadas).
    return {}


EXTENDED: dict[str, Callable[[BuildContext, dict[str, Any]], dict[str, Any]]] = {
    "executive_summary": _executive,
    "technical": _technical,
    "incident": _incident,
    "asset": _asset,
    "vulnerability": _vulnerability,
    "risk": _risk,
    "detection": _detection,
    "response_activity": _response,
    "lifecycle_change": _lifecycle,
}


def build_extended(ctx: BuildContext, result: dict[str, Any]) -> dict[str, Any]:
    return EXTENDED[ctx.definition.id](ctx, result)
