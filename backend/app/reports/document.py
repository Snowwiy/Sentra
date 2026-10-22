"""Documento neutro de un informe (Fase 5E) y utilidades de formato.

Las plantillas (app/reports/templates.py) convierten el snapshot en este documento, y cada
renderer (HTML, PDF) lo dibuja. Así:
- el contenido de un informe se define una sola vez y todos los formatos dicen lo mismo;
- los renderers solo conocen bloques cerrados (párrafo, lista, clave-valor, tabla, barras,
  aviso): no hay plantillas con lógica, expresiones ni HTML del usuario. Todo el texto es
  texto plano que cada renderer escapa a su manera.
"""

from dataclasses import dataclass, field
from typing import Any

EMPTY = "—"


@dataclass(frozen=True)
class Paragraph:
    text: str


@dataclass(frozen=True)
class Bullets:
    items: tuple[str, ...]


@dataclass(frozen=True)
class KeyValues:
    pairs: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Table:
    columns: tuple[str, ...]
    rows: tuple[tuple[str, ...], ...]
    # Pie de tabla (p. ej. "Mostrando 500 de 1200 filas").
    note: str | None = None


@dataclass(frozen=True)
class BarChart:
    title: str
    items: tuple[tuple[str, float], ...]
    # Campos de la plantilla v2 (Fase 6D.5). Los renderers v1 no los leen y las plantillas
    # v1 nunca los rellenan, así que la salida v1 no cambia.
    # Unidad del eje de valores ("detecciones", "puntos de riesgo"...).
    unit: str = ""
    note: str | None = None
    # Categorías sin valor numérico y el motivo, que se muestra en lugar de una barra: así un
    # dato no medido o desconocido nunca se dibuja como 0.
    missing: tuple[tuple[str, str], ...] = ()
    # Categorías que no se dibujan por el tope de la gráfica ("y N más").
    more: int = 0
    # Color de cada barra (hex "#rrggbb" de las paletas de este módulo); vacío = color base.
    colors: tuple[str, ...] = ()
    empty_text: str = "Sin datos en el periodo."


@dataclass(frozen=True)
class Notice:
    text: str


Block = Paragraph | Bullets | KeyValues | Table | BarChart | Notice


@dataclass(frozen=True)
class Section:
    title: str
    blocks: tuple[Block, ...]


@dataclass(frozen=True)
class Document:
    title: str
    report_name: str
    report_id: str
    generated_at: str
    classification: str
    meta: tuple[tuple[str, str], ...]
    summary: tuple[str, ...]
    sections: tuple[Section, ...] = field(default_factory=tuple)


def fmt(value: Any) -> str:
    """Valor de una celda como texto plano estable."""
    if value is None or value == "" or value == []:
        return EMPTY
    if isinstance(value, bool):
        return "sí" if value else "no"
    if isinstance(value, float):
        return f"{value:.2f}".rstrip("0").rstrip(".")
    if isinstance(value, list | tuple):
        return ", ".join(fmt(v) for v in value) or EMPTY
    if isinstance(value, dict):
        # Claves ordenadas: PostgreSQL (JSONB) no conserva el orden de inserción y el
        # documento debe salir idéntico al re-renderizarlo desde el snapshot guardado.
        return "; ".join(f"{k}={fmt(value[k])}" for k in sorted(value)) or EMPTY
    text = str(value)
    if len(text) >= 20 and text[4:5] == "-" and text[10:11] == "T":
        # ISO 8601 de los builders (UTC, sufijo Z): legible y explícito en la zona.
        return text.replace("T", " ").replace("Z", "")[:19] + " UTC"
    return text


def table(
    columns: tuple[tuple[str, str], ...], data: dict[str, Any] | None, empty: str = "Sin datos."
) -> Block:
    """Tabla a partir de una tabla del snapshot ({"rows", "total", "truncated"})."""
    rows = list((data or {}).get("rows") or [])
    if not rows:
        return Paragraph(empty)
    body = tuple(tuple(fmt(row.get(key)) for key, _ in columns) for row in rows)
    note = None
    total = int((data or {}).get("total") or len(rows))
    if (data or {}).get("truncated") or total > len(rows):
        note = f"Mostrando {len(rows)} de {total} filas (límite REPORT_MAX_ROWS del informe)."
    return Table(tuple(label for _, label in columns), body, note)


def bars(title: str, counts: dict[str, Any] | None, labels: dict[str, str] | None = None) -> Block:
    counts = counts or {}
    labels = labels or {}
    # Orden fijo e independiente del orden del dict (JSONB lo reordena): primero el de las
    # etiquetas (critical → informational), después el resto alfabético.
    keys = [k for k in labels if k in counts] + sorted(k for k in counts if k not in labels)
    items = tuple((labels.get(key, key), float(counts[key] or 0)) for key in keys)
    if not items:
        return Paragraph(f"{title}: sin datos.")
    return BarChart(title, items)


# --- Documento v2 (Fase 6D.5) ----------------------------------------------------------------
#
# La plantilla v2 añade bloques nuevos (gráficas apiladas, de líneas, diagrama de topología,
# indicadores, subtítulos y saltos de página) sin tocar los de v1: los renderers v1 siguen
# recibiendo solo `Document` con bloques v1, y los v2 reciben `DocumentV2`. Todo bloque v2 es
# un dato ya resuelto (posiciones, colores de una paleta cerrada, textos planos): los
# renderers no consultan nada ni toman decisiones que dependan de otra cosa que el bloque.

# Paletas cerradas. Los renderers solo aceptan colores con forma "#rrggbb" y las plantillas
# solo usan estos valores.
BRAND = "#1f4e79"
SEVERITY_COLORS = {
    "critical": "#9b1c1c",
    "high": "#d9480f",
    "medium": "#e8a317",
    "low": "#2b6cb0",
    "informational": "#718096",
}
CATEGORICAL = (
    "#1f4e79",
    "#d9480f",
    "#2f855a",
    "#805ad5",
    "#b7791f",
    "#c53030",
    "#319795",
    "#4a5568",
)
LINK_STYLES = {"physical": "solid", "logical": "dashed", "observed": "dotted"}


@dataclass(frozen=True)
class StackedBarChart:
    """Barras horizontales apiladas: una fila por categoría y un tramo por serie."""

    title: str
    series: tuple[str, ...]
    rows: tuple[tuple[str, tuple[float, ...]], ...]
    colors: tuple[str, ...]
    unit: str = ""
    note: str | None = None
    missing: tuple[tuple[str, str], ...] = ()
    more: int = 0
    empty_text: str = "Sin datos en el periodo."


@dataclass(frozen=True)
class LineSeries:
    label: str
    # (x en [0, 1] sobre el eje temporal, valor). La posición se calcula en la plantilla a
    # partir de las fechas del snapshot: el renderer solo escala.
    points: tuple[tuple[float, float], ...]
    color: str


@dataclass(frozen=True)
class LineChart:
    title: str
    series: tuple[LineSeries, ...]
    x_ticks: tuple[tuple[float, str], ...]
    unit: str
    # Máximo fijo del eje (p. ej. 100 en el score de riesgo); None = automático.
    y_max: float | None = None
    x_label: str = ""
    note: str | None = None
    missing: tuple[tuple[str, str], ...] = ()
    more: int = 0
    empty_text: str = "Sin datos en el periodo."


@dataclass(frozen=True)
class DiagramNode:
    key: str
    label: str
    # Posición normalizada (0..1) calculada al construir el documento (disposición
    # determinista por capas); el renderer solo la escala a su lienzo.
    x: float
    y: float
    role: str


@dataclass(frozen=True)
class DiagramEdge:
    source: str
    target: str
    kind: str


@dataclass(frozen=True)
class Diagram:
    title: str
    nodes: tuple[DiagramNode, ...]
    edges: tuple[DiagramEdge, ...]
    # Filas de nodos (para que el renderer reserve la altura adecuada).
    rows: int
    legend: tuple[tuple[str, str], ...]
    note: str | None = None


@dataclass(frozen=True)
class Metric:
    label: str
    value: str
    detail: str = ""


@dataclass(frozen=True)
class Metrics:
    items: tuple[Metric, ...]
    note: str | None = None


@dataclass(frozen=True)
class Subheading:
    text: str


@dataclass(frozen=True)
class PageBreak:
    pass


BlockV2 = (
    Paragraph
    | Bullets
    | KeyValues
    | Table
    | BarChart
    | Notice
    | StackedBarChart
    | LineChart
    | Diagram
    | Metrics
    | Subheading
    | PageBreak
)


@dataclass(frozen=True)
class SectionV2:
    title: str
    blocks: tuple[BlockV2, ...]
    # Las secciones principales (resumen, anexo) empiezan en página nueva en PDF e impresión.
    new_page: bool = False


@dataclass(frozen=True)
class DocumentV2:
    title: str
    report_name: str
    report_id: str
    generated_at: str
    cutoff_at: str
    classification: str
    # Datos de la portada técnica (pares etiqueta-valor ya formateados).
    cover: tuple[tuple[str, str], ...]
    sections: tuple[SectionV2, ...]
    template_version: int = 2


AnyDocument = Document | DocumentV2
