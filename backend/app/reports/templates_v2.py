# ruff: noqa: RUF001, RUF002, RUF003
# (Este módulo trabaja a propósito con símbolos Unicode parecidos a ASCII: ×, –, comillas.)
"""Plantilla v2 de los informes (Fase 6D.5): snapshot → DocumentV2.

Mismo principio que v1 (app/reports/templates.py, que no cambia): código Python con bloques
cerrados, sin motor de plantillas ni eval, y sin acceso a nada fuera del snapshot recibido.
Mismo snapshot → mismo documento → mismos bytes.

Estructura común de todos los tipos:
portada técnica (renderer) → índice → resumen ejecutivo con indicadores y hora de corte →
hallazgos prioritarios → metodología y alcance → análisis gráfico → secciones de detalle
(las tablas técnicas de v1, con estados legibles) → topología y trazabilidad del riesgo
cuando existen → evidencias y referencias → recomendaciones → conclusiones → anexo técnico.

Reglas de contenido:
- hallazgos, recomendaciones y conclusiones son frases fijas construidas con cifras del
  snapshot (nada de IA ni adjetivos que el dato no respalde); cada recomendación nombra el
  dato que la motiva;
- se distingue siempre dato ausente ("Sin datos en el periodo"), no medido ("No medido: ..."
  con el motivo), desconocido ("Desconocido") y cero ("0");
- toda etiqueta que acaba en una gráfica o en el diagrama pasa otra vez por la redacción
  (defensa en profundidad: el builder ya la aplicó);
- el resumen ejecutivo sigue minimizando datos: sin IDs, IPs ni evidencia técnica, y sin
  topología ni trazas de cálculo.
"""

import copy
import math
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from app.reports.document import (
    CATEGORICAL,
    SEVERITY_COLORS,
    BarChart,
    BlockV2,
    Bullets,
    Diagram,
    DiagramEdge,
    DiagramNode,
    DocumentV2,
    KeyValues,
    LineChart,
    LineSeries,
    Metric,
    Metrics,
    Notice,
    Paragraph,
    SectionV2,
    StackedBarChart,
    Subheading,
    Table,
    fmt,
)
from app.reports.redaction import redact_text
from app.reports.summary import count_phrase
from app.reports.templates import (
    CLASSIFICATION_LABELS,
    LEVEL_LABELS,
    SEVERITY_LABELS,
    SOURCE_LABELS,
    STATUS_LABELS,
    TEMPLATES,
    _meta,
)

TEMPLATE_VERSION = 2
NO_DATA = "Sin datos en el periodo."
UNKNOWN = "Desconocido"
UNSCORED = "Sin calcular"
NOT_MEASURED_EVENTS = (
    "No medido: ningún activo del alcance tiene agente (los eventos del sistema los envía el"
    " agente)."
)
# Topes de las gráficas: lo que no cabe se cuenta ("y N más") y está en las tablas.
MAX_BARS = 15
MAX_REFERENCES = 200
MAX_DIAGRAM_PER_ROW = 8
DETECTION_STATUS_LABELS = {"open": "Abierta", "acknowledged": "Reconocida", "resolved": "Resuelta"}
DETECTION_STATUS_COLORS = ("#c53030", "#b7791f", "#2f855a")
EVIDENCE_LABELS = {"confirmed": "Confirmada", "probable": "Probable", "potential": "Potencial"}
EVIDENCE_COLORS = ("#9b1c1c", "#d9480f", "#a0aec0")
CRITICALITY_LABELS = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja"}
LEVEL_COLORS = {**SEVERITY_COLORS, "unscored": "#cbd5e0"}
LINK_LABELS = {
    "physical": "Física (LLDP/CDP)",
    "logical": "Lógica (gateway, gestión)",
    "observed": "Observada (MAC/cliente)",
}
CATEGORY_LABELS = {
    "exposure": "Exposición",
    "context": "Contexto del activo",
    "vulnerability": "Vulnerabilidades",
    "threat_intel": "Threat intelligence",
}
STATE_LEGEND = (
    ("0", "Medido y cero: la fuente existe y no registró ningún caso."),
    ("Sin datos en el periodo", "La fuente existe pero no hay registros en el rango pedido."),
    ("No medido", "No hay fuente que lo mida para ese activo (p. ej. sin agente o sin escaneo)."),
    ("Desconocido", "La fuente informa de que el valor no se conoce."),
    ("Sin calcular", "El Risk Engine todavía no ha puntuado el activo."),
    ("—", "Campo sin valor registrado en el origen."),
)
SOURCES = {
    "executive_summary": (
        "Inventario de activos y política de ciclo de vida.",
        "Risk Engine (scores, niveles e historial de snapshots).",
        "Detection Engine, incidentes, vulnerabilidades y Response.",
        "Eventos del sistema enviados por los agentes y escaneo de puertos de discovery.",
    ),
    "technical": (
        "Inventario, ciclo de vida, Risk Engine, Detection Engine, alertas e incidentes.",
        "Vulnerabilidades, threat intelligence, Response y cambios de discovery.",
        "Eventos del sistema de los agentes, puertos abiertos y topología verificada.",
    ),
    "incident": (
        "El incidente con sus activos, detecciones, alertas, vulnerabilidades, threat"
        " intelligence, notas, línea de tiempo y ejecuciones de Response.",
    ),
    "asset": (
        "Identidad e inventario del activo, agente y linaje.",
        "Risk Engine (score actual, contribuciones e historial), detecciones, vulnerabilidades,"
        " incidentes, threat intelligence y Response.",
        "Eventos del sistema, puertos abiertos y topología verificada del site del activo.",
    ),
    "vulnerability": (
        "Findings de vulnerabilidad (confirmados, probables, potenciales y resueltos).",
        "Puertos abiertos registrados por discovery (exposición).",
    ),
    "risk": (
        "Risk Engine: score vigente, contribuciones guardadas y snapshots históricos.",
        "Criticidad asignada a cada activo.",
    ),
    "detection": ("Detection Engine: detecciones, evidencia guardada e incidentes asociados.",),
    "response_activity": ("Ejecuciones de acciones y de playbooks de Response.",),
    "lifecycle_change": (
        "Inventario, política de ciclo de vida, auditoría de archivado/restauración,"
        " reconciliaciones de agente y cambios de discovery.",
    ),
}


# --- Utilidades ---------------------------------------------------------------------------


def _get(data: Any, *path: str, default: Any = None) -> Any:
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return default
        data = data[key]
    return default if data is None else data


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int | float) and math.isfinite(value):
        return int(value)
    return 0


def _label(text: Any, limit: int = 80) -> str:
    """Etiqueta de gráfica o de diagrama: texto plano redactado y acotado."""
    if text is None or text == "":
        return UNKNOWN
    return redact_text(str(text), limit)


def _parse(value: Any) -> datetime | None:
    if not isinstance(value, str) or len(value) < 10:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _date(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _sum_counts(counts: Any) -> int:
    if not isinstance(counts, dict):
        return 0
    return sum(_int(v) for v in counts.values())


def _bounded(
    items: list[tuple[str, float]], limit: int = MAX_BARS
) -> tuple[tuple[tuple[str, float], ...], int]:
    """Las `limit` categorías de más valor (orden estable) y cuántas quedan fuera."""
    if len(items) <= limit:
        return tuple(items), 0
    ranked = sorted(items, key=lambda item: (-item[1], item[0]))
    return tuple(ranked[:limit]), len(items) - limit


class _Axis:
    """Eje temporal del periodo del informe: fecha → fracción en [0, 1] y marcas."""

    def __init__(self, start: datetime, end: datetime) -> None:
        self.start = start
        self.end = end if end > start else start + timedelta(days=1)

    def x(self, moment: datetime) -> float:
        span = (self.end - self.start).total_seconds()
        return min(max((moment - self.start).total_seconds() / span, 0.0), 1.0)

    def ticks(self) -> tuple[tuple[float, str], ...]:
        return tuple(
            (i / 4, _date(self.start + (self.end - self.start) * (i / 4))) for i in range(5)
        )


def _axis_for(start: Any, end: Any) -> _Axis | None:
    first, last = _parse(start), _parse(end)
    if first is None or last is None:
        return None
    return _Axis(first, last)


# --- Gráficas -----------------------------------------------------------------------------


def _upgrade_bar(chart: BarChart) -> BarChart:
    """Barras v1 reutilizadas en las secciones de detalle: con unidad explícita."""
    return BarChart(chart.title, chart.items, unit="recuento")


def _counts_chart(
    title: str,
    counts: Any,
    labels: dict[str, str] | None = None,
    unit: str = "recuento",
    colors: dict[str, str] | None = None,
    empty: str = NO_DATA,
) -> BarChart:
    counts = counts if isinstance(counts, dict) else {}
    labels = labels or {}
    # Orden fijo e independiente del dict (JSONB lo reordena): primero el de las etiquetas
    # (critical → informational), después el resto alfabético.
    keys = [k for k in labels if k in counts] + sorted(k for k in counts if k not in labels)
    entries = [(k, _label(labels.get(k, k)), float(_int(counts[k]))) for k in keys]
    more = 0
    if len(entries) > MAX_BARS:
        entries = sorted(entries, key=lambda e: (-e[2], e[1]))
        more = len(entries) - MAX_BARS
        entries = entries[:MAX_BARS]
    return BarChart(
        title,
        tuple((label, value) for _, label, value in entries),
        unit=unit,
        more=more,
        colors=tuple(colors.get(k, CATEGORICAL[0]) for k, _, _ in entries) if colors else (),
        empty_text=empty,
    )


def trend_chart(activity: Any, title: str) -> BlockV2 | None:
    """Eventos del sistema y detecciones nuevas por día (o semana) del periodo."""
    if not isinstance(activity, dict):
        return None
    axis = _axis_for(activity.get("start"), activity.get("end"))
    if axis is None:
        return None
    unit_name = "día" if activity.get("unit") == "day" else "semana"
    series = []
    missing: list[tuple[str, str]] = []
    total = 0
    for key, label, color in (
        ("detections", "Detecciones nuevas", CATEGORICAL[1]),
        ("events", "Eventos del sistema", CATEGORICAL[0]),
    ):
        if key not in activity:
            continue
        points_raw = activity.get(key)
        if points_raw is None:
            missing.append((label, NOT_MEASURED_EVENTS))
            continue
        points = []
        for point in points_raw:
            moment = _parse(point.get("bucket"))
            if moment is None:
                continue
            points.append((axis.x(moment), float(_int(point.get("count")))))
            total += _int(point.get("count"))
        series.append(LineSeries(label, tuple(points), color))
    note = None
    if series and total == 0:
        note = "Todas las series medidas valen 0 en el periodo (medido y cero, no ausencia)."
    return LineChart(
        title,
        tuple(series),
        axis.ticks(),
        unit=f"elementos por {unit_name} (UTC)",
        x_label=f"Cubos de un {unit_name}, de {_date(axis.start)} a {_date(axis.end)}",
        note=note,
        missing=tuple(missing),
    )


def trend_table(activity: Any) -> Table | None:
    if not isinstance(activity, dict) or not isinstance(activity.get("detections"), list):
        return None
    events = activity.get("events")
    events_by_bucket = (
        {p.get("bucket"): _int(p.get("count")) for p in events}
        if isinstance(events, list)
        else None
    )
    rows = []
    for point in activity["detections"]:
        bucket = point.get("bucket")
        rows.append(
            (
                fmt(bucket)[:10],
                str(_int(point.get("count"))),
                str(events_by_bucket.get(bucket, 0))
                if events_by_bucket is not None
                else "No medido",
            )
        )
    if not rows:
        return None
    return Table(
        ("Inicio del cubo (UTC)", "Detecciones nuevas", "Eventos del sistema"), tuple(rows)
    )


def simple_trend_chart(
    data: Any, keys: tuple[tuple[str, str], ...], title: str, unit_label: str
) -> BlockV2 | None:
    if not isinstance(data, dict):
        return None
    axis = _axis_for(data.get("start"), data.get("end"))
    if axis is None:
        return None
    unit_name = "día" if data.get("unit") == "day" else "semana"
    series = []
    total = 0
    for index, (key, label) in enumerate(keys):
        points = []
        for point in data.get(key) or []:
            moment = _parse(point.get("bucket"))
            if moment is not None:
                points.append((axis.x(moment), float(_int(point.get("count")))))
                total += _int(point.get("count"))
        series.append(LineSeries(label, tuple(points), CATEGORICAL[index % len(CATEGORICAL)]))
    return LineChart(
        title,
        tuple(series),
        axis.ticks(),
        unit=f"{unit_label} por {unit_name} (UTC)",
        x_label=f"Cubos de un {unit_name}, de {_date(axis.start)} a {_date(axis.end)}",
        note="Todas las series valen 0 en el periodo (medido y cero)." if total == 0 else None,
    )


def risk_history_chart(history: Any, title: str = "Evolución del riesgo por activo") -> BlockV2:
    """Una línea por activo con el score de cada snapshot del Risk Engine (0-100)."""
    series_raw = _get(history, "series", default=[])
    axis = _axis_for(_get(history, "start"), _get(history, "end"))
    if axis is None:
        return Paragraph("Evolución del riesgo: el informe no tiene periodo (sin eje temporal).")
    series = []
    missing = []
    for index, item in enumerate(series_raw):
        label = _label(item.get("asset"), 48)
        points: list[tuple[float, float]] = []
        if item.get("baseline") is not None:
            points.append((0.0, float(_int(item["baseline"]))))
        for point in item.get("points") or []:
            moment = _parse(point.get("at"))
            if moment is not None:
                points.append((axis.x(moment), float(_int(point.get("score")))))
        if not points:
            missing.append((label, "Sin snapshots de riesgo en el periodo ni antes de él."))
            continue
        if len(points) == 1 or points[-1][0] < 1.0:
            # El score se mantiene hasta el siguiente snapshot: la línea llega a la hora de corte.
            points.append((1.0, points[-1][1]))
        series.append(LineSeries(label, tuple(points), CATEGORICAL[index % len(CATEGORICAL)]))
    return LineChart(
        title,
        tuple(series),
        axis.ticks(),
        unit="score de riesgo (0-100)",
        y_max=100.0,
        x_label=(
            "Cada punto es un snapshot guardado por el Risk Engine; entre snapshots el score se"
            " mantiene. El primer punto es el último valor anterior al periodo, si existe."
        ),
        missing=tuple(missing),
        empty_text="Sin activos puntuados por el Risk Engine en el alcance.",
    )


def severity_status_chart(matrix: Any) -> BlockV2:
    if not isinstance(matrix, dict) or not matrix:
        return BarChart("Detecciones por severidad y estado", (), unit="detecciones")
    statuses = tuple(DETECTION_STATUS_LABELS)
    rows = []
    # Orden fijo (crítica → informativa y después el resto alfabético): JSONB no conserva el
    # orden de las claves y el documento debe ser idéntico al re-renderizar.
    known = [k for k in SEVERITY_LABELS if k in matrix]
    for severity in known + sorted(k for k in matrix if k not in SEVERITY_LABELS):
        counts = matrix[severity]
        values = tuple(float(_int(_get(counts, status, default=0))) for status in statuses)
        if severity not in SEVERITY_LABELS and not any(values):
            continue
        rows.append((_label(SEVERITY_LABELS.get(severity, severity)), values))
    total = sum(sum(values) for _, values in rows)
    return StackedBarChart(
        "Detecciones por severidad y estado",
        tuple(DETECTION_STATUS_LABELS.values()),
        tuple(rows),
        DETECTION_STATUS_COLORS,
        unit="detecciones del periodo",
        note="Ninguna detección en el periodo: todas las celdas valen 0." if total == 0 else None,
    )


def vulnerability_chart(groups: dict[str, Any]) -> BlockV2:
    """Severidad × evidencia (confirmada, probable, potencial): nunca se mezclan."""
    severities = ("critical", "high", "medium", "low", "informational")
    rows = []
    for severity in severities:
        values = tuple(
            float(_int(_get(groups, kind, severity, default=0))) for kind in EVIDENCE_LABELS
        )
        rows.append((SEVERITY_LABELS.get(severity, severity), values))
    total = sum(sum(v) for _, v in rows)
    return StackedBarChart(
        "Vulnerabilidades activas por severidad y evidencia",
        tuple(EVIDENCE_LABELS.values()),
        tuple(rows),
        EVIDENCE_COLORS,
        unit="findings activos",
        note=(
            "Sin findings activos en el alcance: todas las celdas valen 0."
            if total == 0
            else "Potencial = no confirmado por la evidencia del inventario."
        ),
    )


def exposure_blocks(data: Any) -> list[BlockV2]:
    if not isinstance(data, dict):
        return []
    scanned = _int(data.get("assets_scanned"))
    in_scope = _int(data.get("assets_in_scope"))
    unscanned = max(in_scope - scanned, 0)
    blocks: list[BlockV2] = [
        KeyValues(
            (
                ("Activos en el alcance", str(in_scope)),
                ("Con escaneo de puertos registrado", str(scanned)),
                (
                    "Sin escaneo de puertos (exposición no medida)",
                    str(unscanned),
                ),
                ("Con algún puerto abierto", str(_int(data.get("assets_with_open_ports")))),
                ("Puertos abiertos (total)", str(_int(data.get("open_ports")))),
            )
        )
    ]
    if scanned == 0:
        blocks.append(
            BarChart(
                "Puertos abiertos más frecuentes",
                (),
                unit="activos con el puerto abierto",
                empty_text=(
                    "No medido: ningún activo del alcance tiene escaneo de puertos registrado."
                ),
            )
        )
        return blocks
    items = [
        (
            _label(
                f"{p.get('port')}/{p.get('protocol') or 'tcp'}"
                + (f" ({p['service']})" if p.get("service") else ""),
                40,
            ),
            float(_int(p.get("assets"))),
        )
        for p in data.get("top_ports") or []
    ]
    more = max(_int(data.get("distinct_ports")) - len(items), 0)
    blocks.append(
        BarChart(
            "Puertos abiertos más frecuentes",
            tuple(items),
            unit="activos con el puerto abierto",
            more=more,
            empty_text="0 puertos abiertos en los activos escaneados (medido y cero).",
            note=(
                f"{unscanned} activos sin escaneo de puertos no se cuentan (no medidos)."
                if unscanned
                else None
            ),
        )
    )
    return blocks


def contribution_charts(data: Any, scope_text: str) -> list[BlockV2]:
    if not isinstance(data, dict):
        return []
    if _int(data.get("assets_scored")) == 0:
        return [
            BarChart(
                "Aportes al riesgo por categoría",
                (),
                unit="puntos de riesgo",
                empty_text="Sin activos puntuados por el Risk Engine en el alcance.",
            )
        ]
    categories = [
        (
            _label(CATEGORY_LABELS.get(str(c.get("category")), c.get("category")), 40),
            float(c.get("points") or 0),
        )
        for c in data.get("by_category") or []
    ]
    bounded, more = _bounded(categories)
    rules = [
        (_label(f"{r.get('rule_id')}", 40), float(r.get("points") or 0))
        for r in data.get("by_rule") or []
    ]
    return [
        BarChart(
            "Aportes al riesgo por categoría",
            bounded,
            unit="puntos de riesgo vigentes (suma)",
            more=more,
            empty_text="0 puntos: ningún aporte positivo vigente (medido y cero).",
            note=f"Suma de los aportes positivos vigentes de {scope_text}. Las reducciones"
            " (saturación, decaimiento) se ven en la trazabilidad del cálculo.",
        ),
        BarChart(
            "Aportes al riesgo por regla de detección",
            tuple(rules),
            unit="puntos de riesgo vigentes (suma)",
            more=max(_int(data.get("rules_total")) - len(rules), 0),
            empty_text="Ninguna regla de detección aporta riesgo vigente (medido y cero).",
        ),
    ]


def asset_contribution_chart(contributions: Any) -> BlockV2:
    totals: dict[str, float] = {}
    for item in contributions or []:
        points = item.get("points")
        if isinstance(points, int | float) and points > 0:
            key = str(item.get("category") or "unknown")
            totals[key] = totals.get(key, 0.0) + float(points)
    items = sorted(
        ((_label(CATEGORY_LABELS.get(k, k), 40), round(v, 2)) for k, v in totals.items()),
        key=lambda item: (-item[1], item[0]),
    )
    bounded, more = _bounded(items)
    return BarChart(
        "Aportes al riesgo del activo por categoría",
        bounded,
        unit="puntos de riesgo vigentes",
        more=more,
        empty_text="Sin aportes positivos vigentes (riesgo sin calcular o sin evidencia).",
    )


def criticality_blocks(data: Any) -> list[BlockV2]:
    if not isinstance(data, dict):
        return []
    series_keys = ("critical", "high", "medium", "low", "informational", "unscored")
    series_labels = tuple(
        UNSCORED if key == "unscored" else LEVEL_LABELS.get(key, key) for key in series_keys
    )
    rows = []
    table_rows = []
    for criticality in data.get("order") or []:
        counts = _get(data, "by_criticality", criticality, default={})
        values = tuple(float(_int(counts.get(key))) for key in series_keys)
        label = CRITICALITY_LABELS.get(criticality, criticality)
        rows.append((label, values))
        scores = _get(data, "scores", criticality)
        total = int(sum(values))
        table_rows.append(
            (
                label,
                str(total),
                str(_int(_get(scores, "scored", default=0))),
                fmt(scores["avg_score"]) if scores else (UNSCORED if total else "Sin activos"),
                fmt(scores["max_score"]) if scores else (UNSCORED if total else "Sin activos"),
            )
        )
    total_assets = sum(sum(v) for _, v in rows)
    return [
        StackedBarChart(
            "Comparativa de activos por criticidad y nivel de riesgo",
            series_labels,
            tuple(rows),
            tuple(LEVEL_COLORS[key] for key in series_keys),
            unit="activos",
            note=(
                "Sin activos en el alcance: todas las celdas valen 0."
                if total_assets == 0
                else "Sin calcular = el Risk Engine aún no puntuó el activo (no es riesgo 0)."
            ),
        ),
        Table(
            ("Criticidad", "Activos", "Puntuados", "Score medio", "Score máximo"),
            tuple(table_rows),
        ),
    ]


# --- Topología ----------------------------------------------------------------------------


def layout_topology(
    nodes: list[dict[str, Any]], links: list[dict[str, Any]]
) -> tuple[tuple[DiagramNode, ...], tuple[DiagramEdge, ...], int, int]:
    """Disposición determinista por capas (sin aleatoriedad ni dependencia del orden de
    entrada): raíz de cada componente = nodo de infraestructura con más enlaces; capas por
    distancia (BFS); dentro de cada capa, orden por baricentro de los vecinos de la capa
    anterior y, a igualdad, por etiqueta e id. Las capas anchas se pliegan en varias filas.

    Devuelve nodos posicionados, aristas, número de filas y nodos sin enlaces (no se dibujan:
    sin relación verificada no hay nada que unir).
    """
    by_key = {n["id"]: n for n in nodes}
    adjacency: dict[str, set[str]] = {}
    edges = []
    seen_edges: set[tuple[str, str, str]] = set()
    for link in links:
        a, b, kind = link["source"], link["target"], link["kind"]
        if a not in by_key or b not in by_key or a == b:
            continue
        ident = (min(a, b), max(a, b), kind)
        if ident in seen_edges:
            continue
        seen_edges.add(ident)
        adjacency.setdefault(a, set()).add(b)
        adjacency.setdefault(b, set()).add(a)
        edges.append(DiagramEdge(a, b, kind))
    connected = sorted(adjacency)
    isolated = len(nodes) - len(connected)

    def sort_key(key: str) -> tuple[int, int, str, str]:
        # Raíz preferente: equipos de borde (router, firewall), luego infraestructura y, a
        # igualdad, el nodo con más enlaces.
        node = by_key[key]
        if node.get("device_type") in ("router", "firewall", "gateway"):
            rank = 0
        elif node.get("role") == "infrastructure":
            rank = 1
        else:
            rank = 2
        return (rank, -len(adjacency[key]), str(node.get("label")), key)

    depth: dict[str, int] = {}
    component: dict[str, int] = {}
    roots: list[str] = []
    for key in sorted(connected, key=sort_key):
        if key in depth:
            continue
        index = len(roots)
        roots.append(key)
        depth[key], component[key] = 0, index
        frontier = [key]
        while frontier:
            following = []
            for current in frontier:
                for neighbour in sorted(adjacency[current], key=sort_key):
                    if neighbour not in depth:
                        depth[neighbour] = depth[current] + 1
                        component[neighbour] = index
                        following.append(neighbour)
            frontier = following
    layers: dict[int, list[str]] = {}
    for key in connected:
        layers.setdefault(depth[key], []).append(key)
    order: dict[str, float] = {}
    rows: list[list[str]] = []
    for level in sorted(layers):
        members = layers[level]

        def barycenter(key: str, level: int = level) -> float:
            parents = [order[n] for n in adjacency[key] if depth.get(n) == level - 1 and n in order]
            return sum(parents) / len(parents) if parents else 0.0

        members.sort(key=lambda k: (component[k], barycenter(k), str(by_key[k].get("label")), k))
        for position, key in enumerate(members):
            order[key] = position / max(len(members) - 1, 1)
        for start in range(0, len(members), MAX_DIAGRAM_PER_ROW):
            rows.append(members[start : start + MAX_DIAGRAM_PER_ROW])
    positioned = []
    for row_index, row in enumerate(rows):
        y = row_index / (len(rows) - 1) if len(rows) > 1 else 0.5
        for col, key in enumerate(row):
            node = by_key[key]
            positioned.append(
                DiagramNode(
                    key=key,
                    label=_label(node.get("label"), 60),
                    x=(col + 0.5) / len(row),
                    y=y,
                    role=str(node.get("role") or ""),
                )
            )
    return tuple(positioned), tuple(edges), len(rows), isolated


def topology_blocks(items: Any) -> list[BlockV2]:
    if not isinstance(items, list) or not items:
        return [Paragraph("Sin activos en el alcance: no hay topología que representar.")]
    blocks: list[BlockV2] = []
    for item in items:
        site = _label(item.get("site") or "site", 80)
        status = item.get("status")
        if len(items) > 1 or item.get("site"):
            blocks.append(Subheading(f"Site: {site}"))
        if status == "unavailable":
            blocks.append(
                Notice(
                    "Topología no disponible en esta instalación: el informe no dibuja ninguna"
                    " relación entre activos."
                )
            )
            continue
        if status != "ok":
            blocks.append(
                Notice(
                    "No se pudo obtener la topología verificada al generar el informe: no se"
                    " dibuja ninguna relación."
                )
            )
            continue
        nodes = [n for n in item.get("nodes") or [] if isinstance(n, dict) and n.get("id")]
        links = [
            link
            for link in item.get("links") or []
            if isinstance(link, dict) and link.get("kind") in LINK_LABELS
        ]
        positioned, edges, rows, isolated = layout_topology(nodes, links)
        if not edges:
            blocks.append(
                Paragraph(
                    "No hay relaciones verificadas (físicas, lógicas u observadas) en el alcance:"
                    " no se dibuja ningún enlace. Compartir subred o gateway no se considera una"
                    " relación verificada."
                )
            )
            continue
        notes = [
            "Solo enlaces presentes y no rechazados de clase física, lógica u observada; los"
            " candidatos y desconocidos no se dibujan."
        ]
        if isolated:
            notes.append(
                f"{count_phrase(isolated, 'nodo', 'nodos')} sin relaciones verificadas no se"
                " dibuja(n)."
            )
        if item.get("truncated"):
            notes.append("La topología del site supera el tope de nodos del informe (truncada).")
        if item.get("built_at"):
            notes.append(f"Última reconstrucción de la topología: {fmt(item['built_at'])}.")
        kinds = sorted({edge.kind for edge in edges}, key=list(LINK_LABELS).index)
        blocks.append(
            Diagram(
                f"Topología verificada ({site})",
                positioned,
                edges,
                rows,
                tuple((kind, LINK_LABELS[kind]) for kind in kinds),
                note=" ".join(notes),
            )
        )
        labels = {n["id"]: _label(n.get("label"), 80) for n in nodes}
        blocks.append(
            Table(
                ("Origen", "Destino", "Clase", "Relación", "Confianza"),
                tuple(
                    (
                        labels.get(link["source"], UNKNOWN),
                        labels.get(link["target"], UNKNOWN),
                        LINK_LABELS[link["kind"]],
                        fmt(link.get("relation")),
                        fmt(link.get("confidence")),
                    )
                    for link in links
                    if link["source"] in labels and link["target"] in labels
                ),
            )
        )
    return blocks


# --- Trazabilidad del riesgo --------------------------------------------------------------


def _factor(value: Any) -> str:
    return fmt(value) if isinstance(value, int | float) else "—"


def trace_blocks(traces: Any) -> list[BlockV2]:
    """Cadena del cálculo de riesgo cuando el Risk Engine la guardó (breakdown.trace y
    details.nominal_breakdown). Sin esos campos no se muestra nada."""
    if not isinstance(traces, list) or not traces:
        return []
    blocks: list[BlockV2] = [
        Paragraph(
            "Cadena guardada por el Risk Engine en su último cálculo (no se recalcula): puntos de"
            " severidad × confianza × ocurrencias × correlación × vigencia × estado × posición ="
            " aporte; suma de aportes = base; base × criticidad × tipo × contexto = bruto;"
            " saturación → score."
        )
    ]
    for item in traces:
        blocks.append(
            Subheading(f"{_label(item.get('asset'), 80)}: score {fmt(item.get('score'))}")
        )
        trace = item.get("trace")
        if isinstance(trace, dict):
            parts = []
            if "base_points" in trace:
                parts.append(f"base {_factor(trace.get('base_points'))} pts")
            for key, name in (
                ("criticality_factor", "criticidad"),
                ("type_factor", "tipo"),
                ("context_factor", "contexto"),
            ):
                if key in trace:
                    parts.append(f"× {name} {_factor(trace[key])}")
            text = " ".join(parts)
            if "raw_points" in trace:
                text += f" = bruto {_factor(trace['raw_points'])} pts"
            if "saturated_points" in trace:
                knee = (
                    f" (rodilla {_factor(trace['saturation_knee'])})"
                    if "saturation_knee" in trace
                    else ""
                )
                text += f"; saturación{knee} → {_factor(trace['saturated_points'])} pts"
            if "score" in trace:
                text += f"; score {_factor(trace['score'])}"
            if "formula_version" in trace:
                text += f" (fórmula v{_factor(trace['formula_version'])})"
            blocks.append(Paragraph(text.strip() + "."))
        chain = item.get("chain") or []
        if chain:
            blocks.append(
                Table(
                    (
                        "Aporte",
                        "Severidad (pts)",
                        "× Confianza",
                        "× Ocurrencias",
                        "× Correlación",
                        "× Vigencia",
                        "× Estado",
                        "× Posición",
                        "= Puntos",
                    ),
                    tuple(
                        (
                            _label(c.get("label"), 160),
                            _factor(c.get("severity_points")),
                            _factor(c.get("confidence_factor")),
                            _factor(c.get("occurrence_factor")),
                            _factor(c.get("correlation_factor")),
                            _factor(c.get("recency_factor")),
                            _factor(c.get("status_factor")),
                            _factor(c.get("position_factor")),
                            _factor(c.get("points")),
                        )
                        for c in chain
                    ),
                )
            )
    return blocks


# --- Hechos: hallazgos, recomendaciones y KPIs ----------------------------------------------


def _facts(snapshot: dict[str, Any]) -> list[tuple[int, str, str]]:
    """(prioridad, hallazgo, recomendación) a partir de cifras del snapshot.

    Funciona con la forma de datos de cualquier tipo: cada regla solo se aplica si el dato
    existe. Las frases solo llevan recuentos (aptas también para el resumen ejecutivo).
    """
    rtype = snapshot["meta"]["report_type"]
    d = snapshot.get("data") or {}
    ext = snapshot.get("extended") or {}
    facts: list[tuple[int, str, str]] = []

    def add(priority: int, finding: str, recommendation: str) -> None:
        facts.append((priority, finding, recommendation))

    by_level = _get(d, "risk", "by_level") or _get(d, "by_level") if rtype != "asset" else None
    if isinstance(by_level, dict):
        critical, high = _int(by_level.get("critical")), _int(by_level.get("high"))
        if critical:
            add(
                0,
                f"{count_phrase(critical, 'activo', 'activos')} en nivel de riesgo crítico"
                " (Risk Engine).",
                f"Mitigar los factores principales de {count_phrase(critical, 'activo', 'activos')}"
                " en riesgo crítico (ver contribuciones y trazabilidad del riesgo).",
            )
        if high:
            add(
                2,
                f"{count_phrase(high, 'activo', 'activos')} en nivel de riesgo alto.",
                f"Planificar la reducción del riesgo de {count_phrase(high, 'activo', 'activos')}"
                " en nivel alto.",
            )
    unscored = _get(d, "risk", "unscored") if rtype != "risk" else _get(d, "unscored")
    if isinstance(unscored, int) and unscored > 0:
        add(
            3,
            f"{count_phrase(unscored, 'activo', 'activos')} sin riesgo calculado por el Risk"
            " Engine.",
            f"Comprobar por qué {count_phrase(unscored, 'activo', 'activos')} no tiene(n) riesgo"
            " calculado: sin score no se pueden priorizar.",
        )
    if rtype == "asset":
        level = _get(d, "risk", "level")
        if level in ("critical", "high"):
            add(
                0 if level == "critical" else 2,
                f"El activo está en nivel de riesgo {LEVEL_LABELS.get(level, level).lower()}"
                f" (score {fmt(_get(d, 'risk', 'score'))}).",
                "Actuar sobre el factor principal del riesgo del activo:"
                f" {fmt(_get(d, 'risk', 'top_factor'))}.",
            )
        elif level is None:
            add(
                3,
                "El riesgo del activo aún no está calculado por el Risk Engine.",
                "Verificar que el Risk Engine procesa el activo (sin score no se puede priorizar).",
            )
    severity = (
        _get(d, "detections", "by_severity")
        if rtype in ("executive_summary", "technical")
        else _get(d, "by_severity")
        if rtype == "detection"
        else None
    )
    if isinstance(severity, dict) and _int(severity.get("critical")):
        n = _int(severity["critical"])
        add(
            0,
            f"{count_phrase(n, 'detección', 'detecciones')} de severidad crítica en el periodo.",
            f"Investigar y cerrar {count_phrase(n, 'detección crítica', 'detecciones críticas')}"
            " del periodo.",
        )
    status = (
        _get(d, "detections", "by_status")
        if rtype == "technical"
        else (_get(d, "by_status") if rtype == "detection" else None)
    )
    if isinstance(status, dict) and _int(status.get("open")):
        n = _int(status["open"])
        add(
            2,
            f"{count_phrase(n, 'detección abierta', 'detecciones abiertas')} sin triar.",
            f"Triar {count_phrase(n, 'detección abierta', 'detecciones abiertas')}"
            " (reconocer o resolver con justificación).",
        )
    incidents = _get(d, "incidents", "active_by_severity")
    if isinstance(incidents, dict) and _int(incidents.get("critical")):
        n = _int(incidents["critical"])
        add(
            0,
            f"{count_phrase(n, 'incidente crítico abierto', 'incidentes críticos abiertos')}.",
            "Asignar responsable y plan de cierre a"
            f" {count_phrase(n, 'incidente crítico', 'incidentes críticos')}.",
        )
    groups = _vuln_groups(snapshot)
    if groups:
        critical_vulns = _int(_get(groups, "confirmed", "critical")) + _int(
            _get(groups, "probable", "critical")
        )
        potential = _sum_counts(groups.get("potential"))
        if critical_vulns:
            add(
                1,
                count_phrase(
                    critical_vulns,
                    "vulnerabilidad crítica confirmada o probable",
                    "vulnerabilidades críticas confirmadas o probables",
                )
                + " activas.",
                "Priorizar la corrección de "
                + count_phrase(
                    critical_vulns, "vulnerabilidad crítica", "vulnerabilidades críticas"
                )
                + " confirmadas o probables.",
            )
        if potential:
            add(
                4,
                count_phrase(potential, "finding potencial", "findings potenciales")
                + " sin confirmar.",
                "Confirmar o descartar"
                f" {count_phrase(potential, 'finding potencial', 'findings potenciales')}"
                " con un inventario actualizado del activo.",
            )
    stale_evidence = _get(d, "stale_evidence", "table", "total")
    if isinstance(stale_evidence, int) and stale_evidence:
        add(
            4,
            f"{count_phrase(stale_evidence, 'finding activo', 'findings activos')} con evidencia de"
            " inventario antigua.",
            "Actualizar el inventario de los activos con evidencia antigua para confirmar su"
            " estado.",
        )
    failed = _get(d, "response", "failed") if rtype != "response_activity" else _get(d, "failed")
    if isinstance(failed, int) and failed:
        add(
            3,
            count_phrase(
                failed, "ejecución de Response terminó", "ejecuciones de Response terminaron"
            )
            + " en fallo o timeout.",
            "Revisar el motivo de"
            f" {count_phrase(failed, 'ejecución fallida', 'ejecuciones fallidas')}"
            " de Response y repetirlas si procede.",
        )
    stale = _get(d, "assets", "stale")
    if (
        isinstance(stale, int)
        and stale
        and rtype in ("technical", "lifecycle_change", "executive_summary")
    ):
        add(
            4,
            f"{count_phrase(stale, 'activo stale', 'activos stale')} (sin actividad reciente).",
            f"Revisar {count_phrase(stale, 'activo stale', 'activos stale')}: archivar los"
            " retirados o recuperar su monitorización.",
        )
    duplicates = _get(snapshot, "tables", "duplicates", "total")
    if isinstance(duplicates, int) and duplicates:
        add(
            3,
            f"{count_phrase(duplicates, 'posible duplicado', 'posibles duplicados')} de activo.",
            "Revisar los posibles duplicados y reconciliarlos cuando la evidencia lo confirme.",
        )
    activity = ext.get("activity")
    if isinstance(activity, dict) and "events" in activity and activity.get("events") is None:
        add(
            5,
            "Eventos del sistema no medidos: ningún activo del alcance tiene agente.",
            "Desplegar el agente de Sentra en los activos críticos para medir sus eventos.",
        )
    exposure = ext.get("exposure")
    if isinstance(exposure, dict):
        unscanned = max(
            _int(exposure.get("assets_in_scope")) - _int(exposure.get("assets_scanned")), 0
        )
        if unscanned:
            add(
                5,
                f"{count_phrase(unscanned, 'activo', 'activos')} sin escaneo de puertos"
                " (exposición no medida).",
                f"Incluir {count_phrase(unscanned, 'activo', 'activos')} en el escaneo de"
                " discovery para medir su exposición.",
            )
    case = _get(d, "case")
    if isinstance(case, dict) and case.get("status") not in ("resolved", "closed", "merged"):
        add(
            1 if case.get("severity") in ("critical", "high") else 3,
            f"{case.get('number')} sigue abierto (estado {fmt(case.get('status'))}, severidad"
            f" {fmt(case.get('severity'))}).",
            f"Completar la investigación de {case.get('number')} y documentar su resolución.",
        )
    return sorted(facts, key=lambda fact: fact[0])


def _vuln_groups(snapshot: dict[str, Any]) -> dict[str, Any] | None:
    rtype = snapshot["meta"]["report_type"]
    d = snapshot.get("data") or {}
    if rtype == "executive_summary":
        v = d.get("vulnerabilities") or {}
        return {"confirmed": v.get("confirmed"), "probable": v.get("probable"), "potential": {}}
    if rtype == "technical":
        v = d.get("vulnerabilities") or {}
        return {k: _get(v, k, "by_severity", default={}) for k in EVIDENCE_LABELS}
    if rtype == "vulnerability":
        return {k: _get(d, k, "by_severity", default={}) for k in EVIDENCE_LABELS}
    if rtype == "asset":
        groups = d.get("vulnerability_groups") or {}
        return {k: groups.get(k) or {} for k in EVIDENCE_LABELS}
    return None


def _kpis(snapshot: dict[str, Any]) -> tuple[Metric, ...]:
    rtype = snapshot["meta"]["report_type"]
    d = snapshot.get("data") or {}
    t = snapshot.get("tables") or {}

    def m(label: str, value: Any, detail: str = "") -> Metric:
        return Metric(label, fmt(value) if value is not None else UNKNOWN, detail)

    if rtype in ("executive_summary", "technical"):
        groups = _vuln_groups(snapshot) or {}
        vulns = _sum_counts(groups.get("confirmed")) + _sum_counts(groups.get("probable"))
        return (
            m("Activos", _get(d, "assets", "total", default=0), "en el alcance"),
            m("Riesgo crítico", _get(d, "risk", "by_level", "critical", default=0), "activos"),
            m("Sin riesgo calculado", _get(d, "risk", "unscored", default=0), "activos"),
            m(
                "Incidentes abiertos",
                _get(d, "incidents", "open_now", default=0),
                "a la hora de corte",
            ),
            m("Detecciones", _get(d, "detections", "total", default=0), "en el periodo"),
            m("Vulnerabilidades", vulns, "confirmadas o probables activas"),
        )
    if rtype == "incident":
        c = d.get("case") or {}
        return (
            m("Incidente", c.get("number")),
            m("Severidad", SEVERITY_LABELS.get(str(c.get("severity")), c.get("severity"))),
            m("Estado", c.get("status")),
            m("Activos", _get(d, "assets", "total", default=0)),
            m("Detecciones", _get(d, "detections", "total", default=0), "vinculadas"),
            m("Response", _get(d, "executions", "total", default=0), "ejecuciones"),
        )
    if rtype == "asset":
        risk = d.get("risk") or {}
        groups = _vuln_groups(snapshot) or {}
        agent = _get(d, "agent", "agent_version")
        return (
            Metric("Score de riesgo", fmt(risk.get("score")) if risk.get("level") else UNSCORED),
            Metric(
                "Nivel",
                LEVEL_LABELS.get(str(risk.get("level")), UNSCORED)
                if risk.get("level")
                else UNSCORED,
            ),
            m("Detecciones", _get(t, "detections", "total", default=0), "en el periodo"),
            m(
                "Vulnerabilidades",
                _sum_counts(groups.get("confirmed")) + _sum_counts(groups.get("probable")),
                "confirmadas o probables",
            ),
            m("Incidentes", _get(d, "incidents", "total", default=0)),
            Metric("Agente", fmt(agent) if agent else "Sin agente", "versión" if agent else ""),
        )
    if rtype == "vulnerability":
        return (
            m("Confirmadas", _get(d, "confirmed", "table", "total", default=0)),
            m("Probables", _get(d, "probable", "table", "total", default=0)),
            m("Potenciales", _get(d, "potential", "table", "total", default=0), "sin confirmar"),
            m("Resueltas", _get(d, "resolved", "table", "total", default=0), "en el periodo"),
            m(
                "Activos afectados",
                _get(d, "assets_affected", default=0),
                "confirmadas o probables",
            ),
            m("Evidencia antigua", _get(d, "stale_evidence", "table", "total", default=0)),
        )
    if rtype == "risk":
        return (
            m("Activos", _get(d, "assets_in_scope", default=0), "en el alcance"),
            m("Riesgo crítico", _get(d, "by_level", "critical", default=0)),
            m("Riesgo alto", _get(d, "by_level", "high", default=0)),
            Metric(
                "Sin calcular",
                fmt(d.get("unscored")) if d.get("unscored") is not None else "No aplica",
                "con filtro de nivel" if d.get("unscored") is None else "activos",
            ),
            m("Subidas de nivel", _get(d, "transitions", "up", default=0), "en el periodo"),
            m("Bajadas de nivel", _get(d, "transitions", "down", default=0), "en el periodo"),
        )
    if rtype == "detection":
        rules = d.get("top_rules") or []
        return (
            m("Detecciones", d.get("total", 0), "en el periodo"),
            m("Críticas", _get(d, "by_severity", "critical", default=0)),
            m("Abiertas", _get(d, "by_status", "open", default=0)),
            m("Reconocidas", _get(d, "by_status", "acknowledged", default=0)),
            m("Resueltas", _get(d, "by_status", "resolved", default=0)),
            Metric("Regla más frecuente", fmt(rules[0].get("rule_id")) if rules else NO_DATA),
        )
    if rtype == "response_activity":
        return (
            m("Ejecuciones", d.get("total", 0), "en el periodo"),
            m("Fallidas o timeout", d.get("failed", 0)),
            m("Playbooks", _get(t, "playbook_runs", "total", default=0), "ejecuciones"),
        )
    return (
        m("Activos nuevos", _get(t, "new_assets", "total", default=0), "en el periodo"),
        m("Stale", _get(d, "assets", "stale", default=0), "a la hora de corte"),
        m("Candidatos a limpieza", _get(d, "assets", "cleanup_candidates", default=0)),
        m("Archivados", _get(d, "events_by_action", "asset_archived", default=0), "en el periodo"),
        m("Restaurados", _get(d, "events_by_action", "asset_restored", default=0), "en el periodo"),
        m("Posibles duplicados", _get(t, "duplicates", "total", default=0)),
    )


# --- Gráficas por tipo ----------------------------------------------------------------------


def _charts(snapshot: dict[str, Any]) -> list[BlockV2]:
    rtype = snapshot["meta"]["report_type"]
    d = snapshot.get("data") or {}
    ext = snapshot.get("extended") or {}
    blocks: list[BlockV2] = []

    def sub(title: str, *items: BlockV2 | None) -> None:
        present = [item for item in items if item is not None]
        if present:
            blocks.append(Subheading(title))
            blocks.extend(present)

    if rtype in ("executive_summary", "technical"):
        risk = d.get("risk") or {}
        sub(
            "Riesgo",
            _counts_chart(
                "Activos por nivel de riesgo",
                risk.get("by_level"),
                LEVEL_LABELS,
                "activos",
                SEVERITY_COLORS,
            ),
            risk_history_chart(ext.get("risk_history")) if ext.get("risk_history") else None,
        )
        if ext.get("criticality"):
            sub("Comparativa por criticidad", *criticality_blocks(ext["criticality"]))
        sub(
            "Detecciones y actividad",
            severity_status_chart(ext["detection_matrix"])
            if ext.get("detection_matrix")
            else _counts_chart(
                "Detecciones del periodo por severidad",
                _get(d, "detections", "by_severity"),
                SEVERITY_LABELS,
                "detecciones",
                SEVERITY_COLORS,
            ),
            trend_chart(ext.get("activity"), "Tendencia de eventos y detecciones"),
        )
        if rtype == "technical" and ext.get("risk_contributions"):
            sub(
                "Contribuciones al Risk Engine",
                *contribution_charts(
                    ext["risk_contributions"], "los activos puntuados del alcance"
                ),
            )
        sub(
            "Vulnerabilidades y exposición",
            vulnerability_chart(_vuln_groups(snapshot) or {}),
            *exposure_blocks(ext.get("exposure")),
        )
    elif rtype == "asset":
        risk = d.get("risk") or {}
        history = {
            "start": snapshot["meta"].get("time_from"),
            "end": snapshot["meta"].get("time_to") or snapshot["meta"].get("cutoff_at"),
            "series": [
                {
                    "asset": _get(d, "identity", "name"),
                    "baseline": None,
                    "points": risk.get("history") or [],
                }
            ],
        }
        sub(
            "Riesgo",
            risk_history_chart(history, "Evolución del riesgo del activo"),
            asset_contribution_chart(risk.get("contributions")),
        )
        sub(
            "Detecciones y actividad",
            severity_status_chart(ext.get("detection_matrix")),
            trend_chart(ext.get("activity"), "Tendencia de eventos y detecciones del activo"),
        )
        sub(
            "Vulnerabilidades y exposición",
            vulnerability_chart(_vuln_groups(snapshot) or {}),
            *exposure_blocks(ext.get("exposure")),
        )
    elif rtype == "vulnerability":
        sub(
            "Vulnerabilidades y exposición",
            vulnerability_chart(_vuln_groups(snapshot) or {}),
            _counts_chart(
                "Resueltas en el periodo por severidad",
                _get(d, "resolved", "by_severity"),
                SEVERITY_LABELS,
                "findings",
                SEVERITY_COLORS,
            ),
            *exposure_blocks(ext.get("exposure")),
        )
    elif rtype == "risk":
        sub(
            "Distribución y evolución",
            _counts_chart(
                "Activos por nivel de riesgo",
                d.get("by_level"),
                LEVEL_LABELS,
                "activos",
                SEVERITY_COLORS,
            ),
            risk_history_chart(ext.get("risk_history")) if ext.get("risk_history") else None,
        )
        if ext.get("risk_contributions"):
            sub(
                "Contribuciones al Risk Engine",
                *contribution_charts(
                    ext["risk_contributions"], "los activos puntuados del alcance"
                ),
            )
        if ext.get("criticality"):
            sub("Comparativa por criticidad", *criticality_blocks(ext["criticality"]))
    elif rtype == "detection":
        sub(
            "Detecciones",
            severity_status_chart(ext.get("detection_matrix")),
            trend_chart(ext.get("activity"), "Tendencia de eventos y detecciones"),
            _rules_chart(d.get("top_rules")),
        )
    elif rtype == "incident":
        sub("Actividad del incidente", *_incident_charts(d))
    elif rtype == "response_activity":
        sub(
            "Ejecuciones",
            simple_trend_chart(
                ext.get("executions"),
                (("executions", "Ejecuciones"), ("failed", "Fallidas o timeout")),
                "Tendencia de ejecuciones de Response",
                "ejecuciones",
            ),
            _counts_chart("Ejecuciones por estado", d.get("by_status"), unit="ejecuciones"),
            _counts_chart("Ejecuciones por acción", d.get("by_action"), unit="ejecuciones"),
        )
    elif rtype == "lifecycle_change":
        sub(
            "Ciclo de vida",
            simple_trend_chart(
                ext.get("new_assets"),
                (("new_assets", "Activos nuevos"),),
                "Activos nuevos en el periodo",
                "activos",
            ),
            _counts_chart(
                "Origen de los activos", _get(d, "assets", "by_source"), SOURCE_LABELS, "activos"
            ),
            _counts_chart("Eventos de ciclo de vida", d.get("events_by_action"), unit="eventos"),
        )
    if not blocks:
        blocks.append(Paragraph("Este tipo de informe no tiene gráficas con datos disponibles."))
    return blocks


def _rules_chart(rules: Any) -> BlockV2:
    items = [
        (_label(r.get("rule_id"), 40), float(_int(r.get("count"))))
        for r in rules or []
        if isinstance(r, dict)
    ]
    return BarChart(
        "Reglas con más detecciones",
        tuple(items),
        unit="detecciones",
        empty_text="Sin detecciones en el periodo.",
        note="Las 10 reglas con más detecciones del alcance." if items else None,
    )


def _incident_charts(d: dict[str, Any]) -> list[BlockV2]:
    per_day: dict[str, int] = {}
    for row in _get(d, "timeline", "rows", default=[]):
        moment = _parse(row.get("at"))
        if moment is not None:
            per_day[_date(moment)] = per_day.get(_date(moment), 0) + 1
    days = sorted(per_day)
    items = [(day, float(per_day[day])) for day in days]
    shown = tuple(items[-MAX_BARS:])
    timeline = BarChart(
        "Actividad de la línea de tiempo por día",
        shown,
        unit="entradas de la línea de tiempo",
        more=len(items) - len(shown),
        empty_text="Sin entradas en la línea de tiempo.",
        note="Se muestran los días más recientes." if len(items) > len(shown) else None,
    )
    severities: dict[str, int] = {}
    for row in _get(d, "detections", "rows", default=[]):
        key = str(row.get("severity") or "unknown")
        severities[key] = severities.get(key, 0) + 1
    detections = _counts_chart(
        "Detecciones vinculadas por severidad",
        severities,
        {**SEVERITY_LABELS, "unknown": UNKNOWN},
        "detecciones",
        SEVERITY_COLORS,
        empty="Sin detecciones vinculadas.",
    )
    return [timeline, detections]


# --- Secciones de detalle (tablas v1 con estados legibles) ----------------------------------

# Secciones v1 que v2 sustituye por las suyas (resumen, hallazgos y tendencias).
_REPLACED = {
    "executive_summary": {"Estado general", "Hallazgos prioritarios", "Tendencias"},
}


def _readable(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Copia del snapshot con estados legibles en las tablas de detalle (el original, que se
    hashea, no se toca): "Sin calcular" en vez de un score vacío, "Desconocido" en vez de
    "unknown", etc."""
    data = copy.deepcopy(snapshot)
    for row in _get(data, "tables", "assets", "rows", default=[]):
        row["status"] = STATUS_LABELS.get(str(row.get("status")), row.get("status"))
        if row.get("risk_score") is None:
            row["risk_score"] = UNSCORED
            row["risk_level"] = UNSCORED
        if row.get("last_activity_at") is None:
            row["last_activity_at"] = "Sin actividad registrada"
    for name in ("detections",):
        for row in _get(data, "tables", name, "rows", default=[]):
            if row.get("risk_points") is None:
                row["risk_points"] = "Sin aporte vigente"
    identity = _get(data, "data", "identity")
    if isinstance(identity, dict) and identity.get("status") == "unknown":
        identity["status"] = UNKNOWN
    risk = _get(data, "data", "risk")
    if (
        snapshot["meta"]["report_type"] == "asset"
        and isinstance(risk, dict)
        and risk.get("level") is None
    ):
        risk["score"] = UNSCORED
        risk["level"] = UNSCORED
    return data


def _detail_sections(snapshot: dict[str, Any]) -> list[SectionV2]:
    rtype = snapshot["meta"]["report_type"]
    readable = _readable(snapshot)
    summary = tuple(snapshot.get("summary") or ())
    out = []
    for section in TEMPLATES[rtype](readable):
        if section.title in _REPLACED.get(rtype, set()):
            continue
        blocks: list[BlockV2] = []
        for block in section.blocks:
            if isinstance(block, Bullets) and block.items == summary:
                continue  # ya está en el resumen ejecutivo
            blocks.append(_upgrade_bar(block) if isinstance(block, BarChart) else block)
        if blocks:
            out.append(SectionV2(f"Detalle: {section.title}", tuple(blocks)))
    return out


# --- Referencias, metodología y anexo -------------------------------------------------------


def _references(snapshot: dict[str, Any]) -> list[BlockV2]:
    rtype = snapshot["meta"]["report_type"]
    if rtype == "executive_summary":
        return [
            Paragraph(
                "El resumen ejecutivo no incluye identificadores, direcciones IP ni evidencia"
                " técnica por diseño (minimización de datos). Fuentes de las cifras:"
            ),
            Bullets(SOURCES[rtype]),
        ]
    if rtype == "incident":
        return [
            Paragraph(
                "Las referencias de evidencia del incidente están en la sección de detalle"
                ' "Referencias de evidencia".'
            )
        ]
    t = snapshot.get("tables") or {}
    rows: list[tuple[str, str, str]] = []
    for row in _get(t, "detections", "rows", default=[]):
        rows.append(
            (
                "Detección",
                fmt(row.get("id")),
                f"{fmt(row.get('rule_id'))} · {fmt(row.get('title'))}",
            )
        )
    for row in _get(t, "incidents", "rows", default=[]):
        rows.append(("Incidente", fmt(row.get("number")), fmt(row.get("title"))))
    for row in _get(t, "vulnerabilities", "rows", default=[]):
        rows.append(
            (
                "Vulnerabilidad",
                fmt(row.get("cve") or row.get("vulnerability")),
                f"{fmt(row.get('component'))} {fmt(row.get('installed_version'))} · finding"
                f" {fmt(row.get('id'))}",
            )
        )
    for row in _get(t, "executions", "rows", default=[]):
        rows.append(("Ejecución de Response", fmt(row.get("id")), fmt(row.get("action"))))
    for row in (
        _get(snapshot, "data", "risk", "changes", "rows", default=[]) if rtype == "risk" else []
    ):
        rows.append(("Cambio de riesgo", fmt(row.get("asset_id")), fmt(row.get("at"))))
    if not rows:
        return [Paragraph("Sin referencias: el alcance no contiene objetos referenciables.")]
    shown = tuple(rows[:MAX_REFERENCES])
    note = (
        f"Mostrando {len(shown)} de {len(rows)} referencias (tope de la sección)."
        if len(rows) > len(shown)
        else None
    )
    return [Table(("Tipo", "Referencia", "Detalle"), shown, note)]


def _scope_pairs(meta: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    pairs = [
        ("Datos a fecha de (hora de corte)", fmt(meta.get("cutoff_at"))),
        (
            "Periodo",
            f"{fmt(meta.get('time_from'))} a {fmt(meta.get('time_to'))}"
            if meta.get("time_from") or meta.get("time_to")
            else "Todo el objeto hasta la hora de corte",
        ),
        ("Zona horaria", str(meta.get("timezone") or "UTC")),
        ("Filtros", fmt(meta.get("filters")) if meta.get("filters") else "ninguno"),
    ]
    scope = meta.get("scope") or {}
    for key, label in (("assets", "Activos"), ("incidents", "Incidentes")):
        if scope.get(key):
            pairs.append((label, ", ".join(str(item.get("name")) for item in scope[key])))
    return tuple(pairs)


def _truncations(snapshot: dict[str, Any]) -> list[str]:
    notes = []

    def visit(name: str, value: Any) -> None:
        if isinstance(value, dict):
            if "rows" in value and "total" in value:
                total = _int(value.get("total"))
                rows = len(value.get("rows") or [])
                if value.get("truncated") or total > rows:
                    notes.append(f"{name}: {rows} de {total} filas (límite REPORT_MAX_ROWS).")
                return
            for key in sorted(value):
                visit(f"{name}.{key}" if name else key, value[key])

    visit("", {"data": snapshot.get("data"), "tables": snapshot.get("tables")})
    return notes


def _methodology(snapshot: dict[str, Any]) -> list[BlockV2]:
    meta = snapshot["meta"]
    rtype = meta["report_type"]
    return [
        Paragraph(
            "Todos los datos se leyeron en una sola transacción de solo lectura (REPEATABLE READ):"
            " todas las secciones ven la misma foto de la base de datos a la hora de corte. El"
            " informe se renderiza solo desde ese snapshot guardado; las gráficas no consultan"
            " nada al dibujarse. El Risk Engine y el Detection Engine son la única fuente de sus"
            " valores: el informe no recalcula ningún score."
        ),
        Subheading("Fuentes"),
        Bullets(SOURCES.get(rtype, ())),
        Subheading("Alcance"),
        KeyValues(_scope_pairs(meta)),
        Subheading("Cómo leer los datos"),
        KeyValues(STATE_LEGEND),
        Paragraph(
            "Las tablas muestran como máximo REPORT_MAX_ROWS filas por tabla (el resto se cuenta"
            " y se avisa). Las gráficas muestran como máximo 15 categorías y dicen cuántas quedan"
            " fuera. En el PDF, los caracteres que las fuentes estándar no pueden mostrar se"
            " transliteran o se marcan como [U+XXXX]; el HTML conserva el texto original."
        ),
    ]


def _annex(snapshot: dict[str, Any]) -> list[BlockV2]:
    meta = snapshot["meta"]
    ext = snapshot.get("extended") or {}
    blocks: list[BlockV2] = [
        Subheading("Metadatos del informe"),
        KeyValues(_meta(meta)),
        Subheading("Versiones"),
        KeyValues(
            (
                ("Plantilla", f"v{meta.get('template_version')}"),
                ("Formato del snapshot", "meta, summary, data, tables, extended"),
                ("Renderer PDF", "Sentra v2 (fuentes estándar, WinAnsiEncoding)"),
            )
        ),
    ]
    truncations = _truncations(snapshot)
    blocks.append(Subheading("Límites aplicados"))
    blocks.append(
        Bullets(tuple(truncations)) if truncations else Paragraph("Ninguna tabla truncada.")
    )
    table = trend_table(ext.get("activity"))
    if table is not None:
        blocks.append(Subheading("Serie temporal de eventos y detecciones"))
        blocks.append(table)
    blocks.append(Subheading("Glosario"))
    blocks.append(
        KeyValues(
            (
                ("Hora de corte", "Instante de la foto de datos; nada posterior aparece."),
                ("Confirmada / probable / potencial", "Grado de evidencia de una vulnerabilidad."),
                ("Stale", "Activo sin actividad durante más tiempo del que fija la política."),
                ("Score", "Riesgo 0-100 calculado por el Risk Engine."),
                ("Relación verificada", "Enlace de topología físico, lógico u observado."),
            )
        )
    )
    return blocks


def _conclusions(snapshot: dict[str, Any], facts: list[tuple[int, str, str]]) -> tuple[str, ...]:
    meta = snapshot["meta"]
    urgent = sum(1 for priority, _, _ in facts if priority <= 1)
    lines = []
    if urgent:
        lines.append(
            f"A la hora de corte ({fmt(meta.get('cutoff_at'))}) el alcance requiere atención:"
            f" {count_phrase(urgent, 'hallazgo prioritario', 'hallazgos prioritarios')} de"
            " máxima prioridad."
        )
    elif facts:
        lines.append(
            f"A la hora de corte ({fmt(meta.get('cutoff_at'))}) no hay hallazgos de máxima"
            f" prioridad; quedan {count_phrase(len(facts), 'punto', 'puntos')} de mejora."
        )
    else:
        lines.append(
            f"A la hora de corte ({fmt(meta.get('cutoff_at'))}) no hay hallazgos prioritarios"
            " en el alcance del informe."
        )
    lines.append(
        "Las cifras proceden de un snapshot inmutable y no se recalculan: un informe nuevo con"
        " los mismos filtros reflejará los cambios posteriores."
    )
    if _truncations(snapshot):
        lines.append(
            "Algunas tablas están truncadas por REPORT_MAX_ROWS (ver anexo): las cifras"
            " agregadas sí cuentan todos los registros."
        )
    return tuple(lines)


def render_document_v2(snapshot: dict[str, Any]) -> DocumentV2:
    meta = snapshot["meta"]
    rtype = meta["report_type"]
    facts = _facts(snapshot)
    cutoff = fmt(meta.get("cutoff_at"))
    sections: list[SectionV2] = [
        SectionV2(
            "Resumen ejecutivo",
            (
                Metrics(_kpis(snapshot), note=f"Indicadores con datos a fecha de {cutoff}."),
                Bullets(tuple(snapshot.get("summary") or ())),
            ),
            new_page=True,
        ),
        SectionV2(
            "Hallazgos prioritarios",
            (Bullets(tuple(f for _, f, _ in facts)),)
            if facts
            else (Paragraph("Sin hallazgos prioritarios a la hora de corte."),),
        ),
        SectionV2("Metodología y alcance", tuple(_methodology(snapshot))),
        SectionV2("Análisis gráfico", tuple(_charts(snapshot)), new_page=True),
    ]
    sections.extend(_detail_sections(snapshot))
    ext = snapshot.get("extended") or {}
    if rtype in ("technical", "asset") and "topology" in ext:
        sections.append(SectionV2("Topología verificada", tuple(topology_blocks(ext["topology"]))))
    traces = trace_blocks(ext.get("risk_traces")) if rtype != "executive_summary" else []
    if traces:
        sections.append(SectionV2("Trazabilidad del cálculo de riesgo", tuple(traces)))
    sections.append(SectionV2("Evidencias y referencias", tuple(_references(snapshot))))
    recommendations = tuple(dict.fromkeys(r for _, _, r in facts))
    sections.append(
        SectionV2(
            "Recomendaciones",
            (
                Paragraph("Cada recomendación procede de un hallazgo con cifras del snapshot."),
                Bullets(recommendations),
            )
            if recommendations
            else (
                Paragraph(
                    "Sin recomendaciones derivadas de los datos del periodo: mantener la"
                    " monitorización y revisar de nuevo en el siguiente periodo."
                ),
            ),
        )
    )
    sections.append(SectionV2("Conclusiones", (Bullets(_conclusions(snapshot, facts)),)))
    sections.append(SectionV2("Anexo técnico", tuple(_annex(snapshot)), new_page=True))
    classification = CLASSIFICATION_LABELS.get(meta["classification"], "INTERNAL")
    period = (
        f"{fmt(meta.get('time_from'))} a {fmt(meta.get('time_to'))}"
        if meta.get("time_from") or meta.get("time_to")
        else "Todo el objeto hasta la hora de corte"
    )
    cover = (
        ("ID del informe", str(meta["report_id"])),
        ("Tipo", f"{meta['report_name']} ({rtype})"),
        ("Plantilla", f"v{meta['template_version']}"),
        ("Clasificación", classification),
        ("Datos a fecha de", cutoff),
        ("Periodo", period),
        ("Zona horaria", str(meta.get("timezone") or "UTC")),
        ("Generado", fmt(meta.get("generated_at"))),
        ("Solicitado por", str(meta.get("requested_by"))),
    )
    return DocumentV2(
        title=meta["title"],
        report_name=meta["report_name"],
        report_id=meta["report_id"],
        generated_at=fmt(meta["generated_at"]),
        cutoff_at=cutoff,
        classification=classification,
        cover=cover,
        sections=tuple(sections),
        template_version=_int(meta.get("template_version")) or TEMPLATE_VERSION,
    )


RENDERERS: dict[int, Callable[[dict[str, Any]], DocumentV2]] = {2: render_document_v2}
