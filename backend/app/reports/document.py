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
