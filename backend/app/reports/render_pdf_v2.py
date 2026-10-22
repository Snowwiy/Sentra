# ruff: noqa: RUF001, RUF002, RUF003
# (Este módulo trabaja a propósito con símbolos Unicode parecidos a ASCII: ×, –, comillas.)
"""Renderer PDF de la plantilla v2 (Fase 6D.5): propio, determinista y sin dependencias.

Mantiene todas las garantías del renderer v1 (app/reports/render_pdf.py, que no cambia):
solo las fuentes estándar Helvetica (sin incrustar ni cargar fuentes), sin anotaciones,
enlaces, acciones, formularios, imágenes ni ficheros incrustados; todo texto como cadena
hexadecimal; misma entrada → mismos bytes (/ID derivado del id del informe, zlib con nivel
fijo, sin fecha de reloj).

Lo que añade v2:
- portada técnica con identidad SENTRA dibujada con operadores vectoriales (sin imágenes);
- índice con el número de página de cada sección (dos pasadas de maquetación: el índice
  ocupa siempre lo mismo, así la segunda pasada pagina igual que la primera);
- cabecera y pie en cada página con "Página X de Y", id del informe, hora de corte y
  clasificación;
- tablas con cabecera repetida en cada página, filas que nunca se parten entre páginas y
  rótulo "(continuación)"; las celdas muy largas se acotan a MAX_CELL_LINES líneas;
- gráficas vectoriales con ejes, unidades, leyenda, valores y motivo explícito de los datos
  no medidos o desconocidos; diagrama de topología con la disposición calculada en la
  plantilla;
- transliteración de símbolos y marcador "[U+XXXX]" en lugar de "?" (app/reports/charset.py).
"""

import hashlib
import math
import re
import unicodedata
import zlib

from app.reports.charset import encode_winansi
from app.reports.document import (
    BRAND,
    LINK_STYLES,
    BarChart,
    BlockV2,
    Bullets,
    Diagram,
    DocumentV2,
    KeyValues,
    LineChart,
    Metrics,
    Notice,
    PageBreak,
    Paragraph,
    StackedBarChart,
    Subheading,
    Table,
)
from app.reports.render_pdf import _BOLD, _REGULAR

PAGE_W, PAGE_H = 595.0, 842.0  # A4 vertical en puntos
MARGIN = 42.0
TOP = PAGE_H - 70.0  # bajo la cabecera de página
BOTTOM = 58.0  # sobre el pie de página
CONTENT_W = PAGE_W - 2 * MARGIN
MAX_CELL_LINES = 10
# Tope de filas de una gráfica de barras: las plantillas ya acotan, esto es la red de
# seguridad para que una gráfica nunca necesite más de una página.
MAX_CHART_ROWS = 30

_TEXT = (0.11, 0.14, 0.19)
_GREY = (0.36, 0.40, 0.45)
_LIGHT = (0.55, 0.58, 0.62)
_LINE = (0.79, 0.83, 0.87)
_GRID = (0.90, 0.92, 0.94)
_HEAD_BG = (0.91, 0.94, 0.97)
_ZEBRA = (0.97, 0.98, 0.99)
_NOTICE_BG = (1.0, 0.97, 0.90)
_NOTICE = (0.72, 0.47, 0.12)
_WHITE = (1.0, 1.0, 1.0)
_RED = (0.61, 0.11, 0.11)
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")

Color = tuple[float, float, float]

# Anchos AFM de los caracteres no ASCII más habituales de cp1252 que no son una letra con
# diacrítico (las letras acentuadas miden lo mismo que su base en Helvetica).
_EXTRA_WIDTHS = {
    "€": 556,
    "•": 350,
    "—": 1000,
    "–": 556,
    "…": 1000,
    "«": 556,
    "»": 556,
    "‹": 333,
    "›": 333,
    "“": 333,
    "”": 333,
    "‘": 222,
    "’": 222,
    "°": 400,
    " ": 278,
    "¿": 611,
    "¡": 333,
    "×": 584,
    "±": 584,
    "·": 278,
    "º": 365,
    "ª": 370,
}
_FALLBACK_WIDTH = 667


def _byte_width(byte: int, bold: bool) -> int:
    table = _BOLD if bold else _REGULAR
    if 32 <= byte <= 126:
        return table[byte - 32]
    char = bytes([byte]).decode("cp1252", errors="replace")
    if char in _EXTRA_WIDTHS:
        return _EXTRA_WIDTHS[char]
    base = "".join(c for c in unicodedata.normalize("NFKD", char) if not unicodedata.combining(c))
    if len(base) == 1 and 32 <= ord(base) <= 126:
        return table[ord(base) - 32]
    # Sobreestimar solo deja algo más de margen, nunca texto que se sale de su caja.
    return _FALLBACK_WIDTH


_WIDTHS = {
    bold: [_byte_width(b, bold) if b >= 32 else 0 for b in range(256)] for bold in (False, True)
}


def text_width(data: bytes, size: float, bold: bool = False) -> float:
    widths = _WIDTHS[bold]
    return sum(widths[b] for b in data) * size / 1000.0


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[bytes]:
    """Parte el texto en líneas que caben en `width`; corta palabras largas (ids, hashes)."""
    lines: list[bytes] = []
    for paragraph in text.split("\n"):
        current = b""
        for word in encode_winansi(paragraph).split(b" "):
            candidate = word if not current else current + b" " + word
            if text_width(candidate, size, bold) <= width:
                current = candidate
                continue
            if current:
                lines.append(current)
                current = b""
            while text_width(word, size, bold) > width and len(word) > 1:
                cut = len(word)
                while cut > 1 and text_width(word[:cut], size, bold) > width:
                    cut -= 1
                lines.append(word[:cut])
                word = word[cut:]
            current = word
        lines.append(current)
    return lines or [b""]


def clip(lines: list[bytes], limit: int, width: float, size: float, bold: bool) -> list[bytes]:
    """Acota a `limit` líneas; la última termina en "…" (0x85 en cp1252) si se cortó."""
    if len(lines) <= limit:
        return lines
    last = lines[limit - 1]
    while last and text_width(last + b"\x85", size, bold) > width:
        last = last[:-1]
    return [*lines[: limit - 1], last + b"\x85"]


def one_line(text: str, width: float, size: float, bold: bool = False) -> bytes:
    return clip(wrap(text, width, size, bold), 1, width, size, bold)[0]


def _num(value: float) -> str:
    if not math.isfinite(value):
        value = 0.0
    return f"{value:.2f}".rstrip("0").rstrip(".") or "0"


def rgb(color: str) -> Color:
    if not _HEX.match(color):
        return _TEXT
    return (int(color[1:3], 16) / 255.0, int(color[3:5], 16) / 255.0, int(color[5:7], 16) / 255.0)


def fmt_value(value: float) -> str:
    """Número legible y estable: enteros con separador de miles (espacio fino), decimales
    con dos cifras como máximo."""
    if not math.isfinite(value):
        return "?"
    if float(value).is_integer() and abs(value) < 1e15:
        return f"{int(value):,}".replace(",", " ")
    if abs(value) >= 1e15:
        return f"{value:.3g}"
    return f"{value:,.2f}".rstrip("0").rstrip(".").replace(",", " ")


def fmt_chart(value: float) -> str:
    """Número de una gráfica: igual que fmt_value hasta el millón y compacto por encima
    (M = millones, mil M = miles de millones, B = billones), para que la etiqueta quepa."""
    if not math.isfinite(value):
        return "?"
    magnitude = abs(value)
    for limit, suffix in ((1e12, "B"), (1e9, "mil M"), (1e6, "M")):
        if magnitude >= limit:
            return f"{value / limit:,.1f}".replace(",", "\u00a0") + f"\u00a0{suffix}"
    return fmt_value(value)


def nice_max(value: float) -> float:
    """Máximo "redondo" del eje (1, 2, 2.5, 5 × 10^n) para marcas legibles."""
    if not math.isfinite(value) or value <= 0:
        return 1.0
    exponent = math.floor(math.log10(value))
    for step in (1.0, 2.0, 2.5, 5.0, 10.0):
        candidate = float(step * 10.0**exponent)
        if candidate >= value:
            return candidate
    return float(10.0 ** (exponent + 1))  # pragma: no cover - el bucle siempre devuelve


def axis_max(values: list[float]) -> float:
    """Máximo del eje. Con datos enteros (recuentos) las 4 divisiones son enteras: nunca un
    eje de "detecciones" con marcas 0,25 o 0,5."""
    top = max(values, default=0.0)
    nice = nice_max(top)
    if all(float(v).is_integer() for v in values) and nice < 1e15:
        return float(max(math.ceil(nice / 4), 1) * 4)
    return nice


def safe(value: float) -> float:
    """Valor dibujable: no finito o negativo → 0 (las plantillas ya lo marcan aparte)."""
    return value if math.isfinite(value) and value > 0 else 0.0


class _Layout:
    """Maquetación por bloques: llena páginas y salta cuando un bloque no cabe."""

    def __init__(self, document: DocumentV2, toc_numbers: list[int]) -> None:
        self.document = document
        self.toc_numbers = toc_numbers
        self.pages: list[list[str]] = [[]]
        self.y = TOP
        self.section_pages: list[int] = []

    # --- Primitivas ------------------------------------------------------------------------

    @property
    def ops(self) -> list[str]:
        return self.pages[-1]

    def new_page(self) -> None:
        self.pages.append([])
        self.y = TOP

    def ensure(self, height: float) -> None:
        if self.y - height < BOTTOM and self.y < TOP:
            self.new_page()

    def text(
        self,
        x: float,
        y: float,
        data: bytes,
        size: float,
        font: str = "F1",
        color: Color = _TEXT,
    ) -> None:
        r, g, b = color
        self.ops.append(
            f"BT {_num(r)} {_num(g)} {_num(b)} rg /{font} {_num(size)} Tf"
            f" {_num(x)} {_num(y)} Td <{data.hex()}> Tj ET"
        )

    def rect(
        self,
        x: float,
        y: float,
        w: float,
        h: float,
        fill: Color | None = None,
        stroke: Color | None = None,
        width: float = 0.5,
    ) -> None:
        parts = []
        if fill:
            parts.append(f"{_num(fill[0])} {_num(fill[1])} {_num(fill[2])} rg")
        if stroke:
            parts.append(
                f"{_num(stroke[0])} {_num(stroke[1])} {_num(stroke[2])} RG {_num(width)} w"
            )
        op = "B" if fill and stroke else "f" if fill else "S"
        parts.append(f"{_num(x)} {_num(y)} {_num(w)} {_num(h)} re {op}")
        self.ops.append("q " + " ".join(parts) + " Q")

    def line(
        self,
        points: list[tuple[float, float]],
        color: Color,
        width: float = 0.6,
        dash: str = "solid",
    ) -> None:
        if len(points) < 2:
            return
        pattern = {"dashed": "[4 2] 0 d", "dotted": "[1 2] 0 d"}.get(dash, "[] 0 d")
        path = " ".join(
            f"{_num(x)} {_num(y)} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(points)
        )
        self.ops.append(
            f"q {_num(color[0])} {_num(color[1])} {_num(color[2])} RG {_num(width)} w"
            f" 1 J 1 j {pattern} {path} S Q"
        )

    def polygon(self, points: list[tuple[float, float]], fill: Color) -> None:
        path = " ".join(
            f"{_num(x)} {_num(y)} {'m' if i == 0 else 'l'}" for i, (x, y) in enumerate(points)
        )
        self.ops.append(f"q {_num(fill[0])} {_num(fill[1])} {_num(fill[2])} rg {path} h f Q")

    def logo(self, x: float, y: float, scale: float, body: Color, mark: Color) -> None:
        """Escudo SENTRA: contorno de escudo y un trazo de pulso, solo vectores."""
        s = scale
        shield = [
            (x, y + 9 * s),
            (x + 8 * s, y + 12 * s),
            (x + 16 * s, y + 9 * s),
            (x + 16 * s, y + 4 * s),
            (x + 8 * s, y - 4 * s),
            (x, y + 4 * s),
        ]
        self.polygon(shield, body)
        pulse = [
            (x + 2.5 * s, y + 4.5 * s),
            (x + 5.5 * s, y + 4.5 * s),
            (x + 7 * s, y + 8 * s),
            (x + 9 * s, y + 1 * s),
            (x + 10.5 * s, y + 4.5 * s),
            (x + 13.5 * s, y + 4.5 * s),
        ]
        self.line(pulse, mark, width=max(0.8, 1.1 * s))

    # --- Texto ------------------------------------------------------------------------------

    def paragraph(
        self,
        text: str,
        size: float = 9.0,
        font: str = "F1",
        indent: float = 0,
        color: Color = _TEXT,
        after: float = 4,
    ) -> None:
        leading = size * 1.35
        for line in wrap(text, CONTENT_W - indent, size, font == "F2"):
            self.ensure(leading)
            self.text(MARGIN + indent, self.y - size, line, size, font, color)
            self.y -= leading
        self.y -= after

    def bullets(self, items: tuple[str, ...]) -> None:
        size, leading = 9.0, 9.0 * 1.35
        for item in items:
            lines = wrap(item, CONTENT_W - 14, size)
            self.ensure(leading * min(len(lines), 3))
            for n, line in enumerate(lines):
                self.ensure(leading)
                if n == 0:
                    self.text(MARGIN + 3, self.y - size, encode_winansi("•"), size, "F1", BRAND_RGB)
                self.text(MARGIN + 14, self.y - size, line, size)
                self.y -= leading
            self.y -= 1.5
        self.y -= 3

    def notice(self, text: str) -> None:
        size = 8.5
        leading = size * 1.35
        lines = wrap(text, CONTENT_W - 20, size, True)
        height = len(lines) * leading + 10
        self.ensure(height + 4)
        top = self.y
        self.rect(MARGIN, top - height, CONTENT_W, height, fill=_NOTICE_BG)
        self.rect(MARGIN, top - height, 3, height, fill=_NOTICE)
        for n, line in enumerate(lines):
            self.text(MARGIN + 12, top - 5 - size - n * leading + 1, line, size, "F2", _NOTICE)
        self.y = top - height - 8

    def subheading(self, text: str, lead: float = 40) -> None:
        # Mantener con el siguiente bloque: un subtítulo nunca queda solo al pie de página.
        self.ensure(22 + lead)
        self.y -= 4
        self.text(MARGIN, self.y - 10.5, one_line(text, CONTENT_W, 10.5, True), 10.5, "F2", _TEXT)
        self.y -= 18

    def heading(self, number: int, title: str, lead: float = 40) -> None:
        self.ensure(46 + lead)
        self.section_pages.append(len(self.pages))
        self.y -= 6
        label = one_line(f"{number}. {title}", CONTENT_W, 15, True)
        self.text(MARGIN, self.y - 15, label, 15, "F2", BRAND_RGB)
        self.y -= 22
        self.rect(MARGIN, self.y, CONTENT_W, 1.2, fill=BRAND_RGB)
        self.y -= 12

    # --- Tablas -----------------------------------------------------------------------------

    def table(
        self,
        columns: tuple[str, ...],
        rows: tuple[tuple[str, ...], ...],
        widths: list[float] | None = None,
        key_values: bool = False,
    ) -> None:
        count = len(columns)
        size = 8.0 if count <= 5 else 7.2 if count <= 8 else 6.4 if count <= 11 else 5.8
        leading = size * 1.28
        pad = 3.0
        if widths is None:
            widths = _column_widths(columns, rows, size)

        def cells(values: tuple[str, ...], bold_all: bool) -> list[list[bytes]]:
            out = []
            for i, value in enumerate(values):
                bold = bold_all or (key_values and i == 0)
                inner = widths[i] - 2 * pad
                out.append(clip(wrap(value, inner, size, bold), MAX_CELL_LINES, inner, size, bold))
            return out

        def height_of(wrapped: list[list[bytes]]) -> float:
            return max(len(c) for c in wrapped) * leading + 2 * pad

        def draw(wrapped: list[list[bytes]], kind: str, stripe: bool) -> None:
            height = height_of(wrapped)
            x = MARGIN
            for i, lines in enumerate(wrapped):
                fill = (
                    _HEAD_BG
                    if kind == "header" or (key_values and i == 0)
                    else _ZEBRA
                    if stripe
                    else None
                )
                self.rect(x, self.y - height, widths[i], height, fill=fill, stroke=_LINE)
                bold = kind == "header" or (key_values and i == 0)
                for n, line in enumerate(lines):
                    self.text(
                        x + pad,
                        self.y - pad - size - n * leading + 1.2,
                        line,
                        size,
                        "F2" if bold else "F1",
                    )
                x += widths[i]
            self.y -= height

        header = None if key_values else cells(columns, True)
        header_h = height_of(header) if header else 0.0
        first = cells(rows[0], False) if rows else None
        # Nunca una cabecera huérfana al pie de página: cabecera + primera fila juntas.
        self.ensure(header_h + (height_of(first) if first else 0) + 2)
        if header:
            draw(header, "header", False)
        for index, row in enumerate(rows):
            wrapped = first if index == 0 and first is not None else cells(row, False)
            height = height_of(wrapped)
            if self.y - height < BOTTOM:
                # Salto controlado: la fila entera pasa a la página siguiente, precedida de un
                # rótulo y de la cabecera repetida.
                self.new_page()
                if header:
                    self.text(MARGIN, self.y - 7, encode_winansi("(continuación)"), 7, "F3", _GREY)
                    self.y -= 11
                    draw(header, "header", False)
            draw(wrapped, "row", index % 2 == 1)
        self.y -= 7

    # --- Indicadores ------------------------------------------------------------------------

    def metrics(self, block: Metrics) -> None:
        per_row = 3
        gap = 8.0
        tile_w = (CONTENT_W - gap * (per_row - 1)) / per_row
        tile_h = 54.0
        items = block.items
        for start in range(0, len(items), per_row):
            self.ensure(tile_h + gap)
            top = self.y
            for col, metric in enumerate(items[start : start + per_row]):
                x = MARGIN + col * (tile_w + gap)
                self.rect(x, top - tile_h, tile_w, tile_h, fill=_ZEBRA, stroke=_LINE)
                self.rect(x, top - tile_h, 3, tile_h, fill=BRAND_RGB)
                self.text(
                    x + 10, top - 13, one_line(metric.label, tile_w - 16, 7.5, True), 7.5, "F2",
                    _GREY,
                )  # fmt: skip
                self.text(
                    x + 10, top - 33, one_line(metric.value, tile_w - 16, 15, True), 15, "F2",
                    BRAND_RGB,
                )  # fmt: skip
                if metric.detail:
                    self.text(
                        x + 10, top - 46, one_line(metric.detail, tile_w - 16, 6.8), 6.8, "F1",
                        _GREY,
                    )  # fmt: skip
            self.y = top - tile_h - gap
        if block.note:
            self.paragraph(block.note, size=7.5, font="F3", color=_GREY)
        self.y -= 2

    # --- Gráficas ---------------------------------------------------------------------------

    def _chart_title(self, title: str, unit: str) -> None:
        self.text(MARGIN, self.y - 10, one_line(title, CONTENT_W, 9.5, True), 9.5, "F2", _TEXT)
        self.y -= 14
        if unit:
            self.text(MARGIN, self.y - 7, one_line(f"Unidad: {unit}", CONTENT_W, 7), 7, "F3", _GREY)
            self.y -= 11

    def _empty_chart(self, title: str, unit: str, text: str, note: str | None) -> None:
        self.ensure(66)
        self._chart_title(title, unit)
        self.rect(MARGIN, self.y - 30, CONTENT_W, 30, fill=_ZEBRA, stroke=_LINE)
        data = one_line(text, CONTENT_W - 20, 8.5)
        self.text(MARGIN + 10, self.y - 18, data, 8.5, "F3", _GREY)
        self.y -= 38
        self._chart_notes(note, (), 0)

    def _chart_notes(
        self, note: str | None, missing: tuple[tuple[str, str], ...], more: int
    ) -> None:
        for label, reason in missing:
            self.paragraph(f"{label}: {reason}", size=7.5, font="F3", color=_GREY, after=0)
        if more:
            self.paragraph(
                f"Y {more} categorías más no dibujadas (tope de la gráfica).",
                size=7.5,
                font="F3",
                color=_GREY,
                after=0,
            )
        if note:
            self.paragraph(note, size=7.5, font="F3", color=_GREY, after=0)
        self.y -= 8

    def _axis(self, x0: float, width: float, top: float, bottom: float, maximum: float) -> None:
        for i in range(5):
            value = maximum * i / 4
            x = x0 + width * i / 4
            self.line([(x, top), (x, bottom)], _GRID, 0.4)
            label = encode_winansi(fmt_chart(value))
            self.text(x - text_width(label, 6.5) / 2, bottom - 8, label, 6.5, "F1", _GREY)

    def bar_chart(self, chart: BarChart) -> None:
        items = chart.items[:MAX_CHART_ROWS]
        if not items and not chart.missing:
            self._empty_chart(chart.title, chart.unit, chart.empty_text, chart.note)
            return
        row_h, label_w, value_w = 14.0, 150.0, 58.0
        rows = len(items) + len(chart.missing)
        extra = 12 * (len(chart.missing) + (1 if chart.more else 0) + (2 if chart.note else 0))
        self.ensure(30 + rows * row_h + 18 + extra)
        self._chart_title(chart.title, chart.unit)
        bar_x = MARGIN + label_w
        bar_w = CONTENT_W - label_w - value_w
        maximum = axis_max([safe(v) for _, v in items])
        top = self.y
        bottom = top - rows * row_h - 2
        self._axis(bar_x, bar_w, top, bottom, maximum)
        for index, (label, value) in enumerate(items):
            y = top - index * row_h
            self.text(MARGIN, y - 10, one_line(label, label_w - 8, 7.5), 7.5)
            length = bar_w * safe(value) / maximum
            color = rgb(chart.colors[index]) if index < len(chart.colors) else BRAND_RGB
            if length > 0:
                self.rect(bar_x, y - row_h + 3, max(length, 0.8), row_h - 6, fill=color)
            shown = encode_winansi(fmt_chart(value))
            self.text(bar_x + length + 4, y - 10, shown, 7.5, "F2")
        for offset, (label, reason) in enumerate(chart.missing):
            y = top - (len(items) + offset) * row_h
            self.text(MARGIN, y - 10, one_line(label, label_w - 8, 7.5), 7.5)
            self.text(bar_x + 2, y - 10, one_line(reason, bar_w + value_w - 4, 7), 7, "F3", _GREY)
        self.line([(bar_x, top), (bar_x, bottom)], _LIGHT, 0.6)
        self.y = bottom - 14
        self._chart_notes(chart.note, (), chart.more)

    def stacked_chart(self, chart: StackedBarChart) -> None:
        rows_data = chart.rows[:MAX_CHART_ROWS]
        if not rows_data and not chart.missing:
            self._empty_chart(chart.title, chart.unit, chart.empty_text, chart.note)
            return
        row_h, label_w, value_w = 15.0, 130.0, 58.0
        rows = len(rows_data) + len(chart.missing)
        extra = 12 * (len(chart.missing) + (1 if chart.more else 0) + (2 if chart.note else 0))
        self.ensure(46 + rows * row_h + 18 + extra)
        self._chart_title(chart.title, chart.unit)
        self._legend(list(zip(chart.series, chart.colors, strict=False)))
        bar_x = MARGIN + label_w
        bar_w = CONTENT_W - label_w - value_w
        totals = [sum(safe(v) for v in values) for _, values in rows_data]
        maximum = axis_max(totals)
        top = self.y
        bottom = top - rows * row_h - 2
        self._axis(bar_x, bar_w, top, bottom, maximum)
        for index, (label, values) in enumerate(rows_data):
            y = top - index * row_h
            self.text(MARGIN, y - 10, one_line(label, label_w - 8, 7.5), 7.5)
            x = bar_x
            for series_index, value in enumerate(values):
                length = bar_w * safe(value) / maximum
                if length > 0:
                    color = (
                        rgb(chart.colors[series_index])
                        if series_index < len(chart.colors)
                        else BRAND_RGB
                    )
                    self.rect(x, y - row_h + 3, length, row_h - 6, fill=color)
                x += length
            shown = encode_winansi(fmt_chart(totals[index]))
            self.text(x + 4, y - 10, shown, 7.5, "F2")
        for offset, (label, reason) in enumerate(chart.missing):
            y = top - (len(rows_data) + offset) * row_h
            self.text(MARGIN, y - 10, one_line(label, label_w - 8, 7.5), 7.5)
            self.text(bar_x + 2, y - 10, one_line(reason, bar_w + value_w - 4, 7), 7, "F3", _GREY)
        self.line([(bar_x, top), (bar_x, bottom)], _LIGHT, 0.6)
        self.y = bottom - 14
        self._chart_notes(chart.note, (), chart.more)

    def _legend(self, entries: list[tuple[str, str]], dashes: list[str] | None = None) -> None:
        x = MARGIN
        size = 7.0
        for index, (label, color) in enumerate(entries):
            data = one_line(label, 150, size)
            needed = 16 + text_width(data, size) + 12
            if x + needed > MARGIN + CONTENT_W:
                x = MARGIN
                self.y -= 11
            if dashes is not None:
                self.line(
                    [(x, self.y - 4.5), (x + 12, self.y - 4.5)], rgb(color), 1.4, dashes[index]
                )
            else:
                self.rect(x, self.y - 7.5, 8, 7, fill=rgb(color))
            self.text(x + 15, self.y - 7, data, size, "F1", _TEXT)
            x += needed
        self.y -= 15

    def line_chart(self, chart: LineChart) -> None:
        series = [s for s in chart.series if s.points]
        if not series and not chart.missing:
            self._empty_chart(chart.title, chart.unit, chart.empty_text, chart.note)
            return
        plot_h = 150.0
        axis_w = 44.0
        extra = 12 * (len(chart.missing) + (1 if chart.more else 0) + (2 if chart.note else 0))
        legend_rows = 1 + len(chart.series) // 4
        self.ensure(30 + plot_h + 28 + legend_rows * 12 + extra)
        self._chart_title(chart.title, chart.unit)
        values = [safe(v) for s in series for _, v in s.points]
        maximum = chart.y_max if chart.y_max else axis_max(values)
        x0 = MARGIN + axis_w
        width = CONTENT_W - axis_w - 8
        top = self.y - 4
        bottom = top - plot_h
        for i in range(5):
            value = maximum * i / 4
            y = bottom + plot_h * i / 4
            self.line([(x0, y), (x0 + width, y)], _GRID, 0.4)
            tick = encode_winansi(fmt_chart(value))
            self.text(x0 - 4 - text_width(tick, 6.5), y - 2.2, tick, 6.5, "F1", _GREY)
        self.line([(x0, top), (x0, bottom), (x0 + width, bottom)], _LIGHT, 0.7)
        for fraction, label in chart.x_ticks:
            x = x0 + width * min(max(fraction, 0.0), 1.0)
            self.line([(x, bottom), (x, bottom - 3)], _LIGHT, 0.6)
            data = one_line(label, 70, 6.3)
            left = min(
                max(x - text_width(data, 6.3) / 2, x0 - 10), x0 + width - text_width(data, 6.3)
            )
            self.text(left, bottom - 11, data, 6.3, "F1", _GREY)
        for item in series:
            color = rgb(item.color)
            points = [
                (
                    x0 + width * min(max(px, 0.0), 1.0),
                    bottom + plot_h * min(safe(py), maximum) / maximum,
                )
                for px, py in item.points
            ]
            self.line(points, color, 1.3)
            if len(points) <= 62:
                for px, py in points:
                    self.rect(px - 1.6, py - 1.6, 3.2, 3.2, fill=color)
        self.y = bottom - 20
        if chart.x_label:
            for line in wrap(chart.x_label, width, 6.8)[:3]:
                self.text(x0, self.y, line, 6.8, "F3", _GREY)
                self.y -= 9
            self.y -= 2
        self._legend([(s.label, s.color) for s in chart.series if s.points])
        self._chart_notes(chart.note, chart.missing, chart.more)

    def diagram(self, block: Diagram) -> None:
        if not block.nodes:
            self._empty_chart(block.title, "", "Sin nodos que dibujar.", block.note)
            return
        height = _diagram_height(block.rows)
        self.ensure(height + 74)
        self._chart_title(block.title, "")
        top = self.y
        self.rect(MARGIN, top - height, CONTENT_W, height, fill=_ZEBRA, stroke=_LINE)
        per_row = max(
            (sum(1 for n in block.nodes if abs(n.y - m.y) < 1e-6) for m in block.nodes), default=1
        )
        box_w = min(110.0, (CONTENT_W - 16) / per_row - 6)
        box_h = 20.0
        inner_x, inner_w = MARGIN + 8 + box_w / 2, CONTENT_W - 16 - box_w
        inner_top, inner_h = top - 8 - box_h / 2, height - 16 - box_h

        def pos(x: float, y: float) -> tuple[float, float]:
            return inner_x + inner_w * x, inner_top - inner_h * y

        where = {node.key: pos(node.x, node.y) for node in block.nodes}
        for edge in block.edges:
            if edge.source in where and edge.target in where:
                self.line(
                    [where[edge.source], where[edge.target]],
                    _GREY,
                    0.9,
                    LINK_STYLES.get(edge.kind, "solid"),
                )
        size = 6.2 if box_w > 60 else 5.4
        for node in block.nodes:
            cx, cy = where[node.key]
            color = BRAND_RGB if node.role == "infrastructure" else _GREY
            self.rect(
                cx - box_w / 2, cy - box_h / 2, box_w, box_h, fill=_WHITE, stroke=color, width=0.9
            )
            self.rect(cx - box_w / 2, cy - box_h / 2, 2.5, box_h, fill=color)
            data = one_line(node.label, box_w - 8, size)
            self.text(cx - box_w / 2 + 5, cy - size / 2 + 0.6, data, size)
        self.y = top - height - 8
        legend = [(label, "#5c6673") for _, label in block.legend]
        self._legend(legend, dashes=[LINK_STYLES.get(kind, "solid") for kind, _ in block.legend])
        self._chart_notes(block.note, (), 0)

    # --- Documento --------------------------------------------------------------------------

    def block(self, block: BlockV2) -> None:
        if isinstance(block, Paragraph):
            self.paragraph(block.text)
        elif isinstance(block, Notice):
            self.notice(block.text)
        elif isinstance(block, Bullets):
            self.bullets(block.items)
        elif isinstance(block, KeyValues):
            widths = [CONTENT_W * 0.32, CONTENT_W * 0.68]
            self.table(("", ""), block.pairs, widths=widths, key_values=True)
        elif isinstance(block, Table):
            if not block.rows:
                self.paragraph("Sin filas.")
            else:
                self.table(block.columns, block.rows)
            if block.note:
                self.paragraph(block.note, size=7.2, font="F3", color=_GREY)
        elif isinstance(block, Metrics):
            self.metrics(block)
        elif isinstance(block, Subheading):
            self.subheading(block.text, 40)
        elif isinstance(block, PageBreak):
            if self.y < TOP:
                self.new_page()
        elif isinstance(block, StackedBarChart):
            self.stacked_chart(block)
        elif isinstance(block, LineChart):
            self.line_chart(block)
        elif isinstance(block, Diagram):
            self.diagram(block)
        else:
            self.bar_chart(block)

    def cover(self) -> None:
        doc = self.document
        band = 190.0
        self.rect(0, PAGE_H - band, PAGE_W, band, fill=BRAND_RGB)
        self.logo(MARGIN, PAGE_H - 92, 3.2, _WHITE, BRAND_RGB)
        self.text(MARGIN + 66, PAGE_H - 78, b"SENTRA", 30, "F2", _WHITE)
        self.text(
            MARGIN + 67,
            PAGE_H - 96,
            encode_winansi("Plataforma de monitorización y operaciones de seguridad"),
            9,
            "F1",
            (0.85, 0.90, 0.95),
        )
        label = encode_winansi(doc.classification)
        lw = text_width(label, 9, True) + 16
        self.rect(PAGE_W - MARGIN - lw, PAGE_H - 150, lw, 18, fill=_WHITE)
        self.text(PAGE_W - MARGIN - lw + 8, PAGE_H - 144, label, 9, "F2", _RED)
        self.y = PAGE_H - band - 36
        for line in wrap(doc.title, CONTENT_W, 20, True)[:3]:
            self.text(MARGIN, self.y - 20, line, 20, "F2", _TEXT)
            self.y -= 26
        self.text(MARGIN, self.y - 11, one_line(doc.report_name, CONTENT_W, 11), 11, "F1", _GREY)
        self.y -= 30
        self.table(
            ("", ""), doc.cover, widths=[CONTENT_W * 0.32, CONTENT_W * 0.68], key_values=True
        )
        self.y -= 6
        self.paragraph(
            "Documento generado por Sentra a partir de un snapshot inmutable de los datos a la"
            " hora de corte indicada. Volver a renderizar el mismo snapshot produce exactamente"
            " los mismos bytes (SHA-256 reproducible). Todas las horas en UTC.",
            size=7.5,
            font="F3",
            color=_GREY,
        )

    def toc(self) -> None:
        self.new_page()
        self.text(MARGIN, self.y - 15, encode_winansi("Contenido"), 15, "F2", BRAND_RGB)
        self.y -= 22
        self.rect(MARGIN, self.y, CONTENT_W, 1.2, fill=BRAND_RGB)
        self.y -= 14
        for index, section in enumerate(self.document.sections):
            number = self.toc_numbers[index] if index < len(self.toc_numbers) else 0
            page = encode_winansi(str(number))
            title = one_line(f"{index + 1}. {section.title}", CONTENT_W - 60, 9.5)
            self.ensure(15)
            self.text(MARGIN, self.y - 10, title, 9.5)
            start = MARGIN + text_width(title, 9.5) + 6
            end = PAGE_W - MARGIN - text_width(page, 9.5) - 6
            if end > start:
                self.line([(start, self.y - 10), (end, self.y - 10)], _LINE, 0.6, "dotted")
            self.text(PAGE_W - MARGIN - text_width(page, 9.5), self.y - 10, page, 9.5)
            self.y -= 15

    def run(self) -> None:
        self.cover()
        self.toc()
        self.new_page()
        for number, section in enumerate(self.document.sections, start=1):
            if section.new_page and self.y < TOP:
                self.new_page()
            blocks = section.blocks
            lead = _lead(blocks[0]) if blocks else 20
            if blocks and isinstance(blocks[0], Subheading) and len(blocks) > 1:
                lead = 22 + _lead(blocks[1])
            self.heading(number, section.title, lead)
            for index, block in enumerate(blocks):
                if isinstance(block, Subheading):
                    following = blocks[index + 1] if index + 1 < len(blocks) else None
                    self.subheading(block.text, _lead(following) if following else 20)
                else:
                    self.block(block)


def _diagram_height(rows: int) -> float:
    return min(max(rows, 1) * 58.0 + 10, TOP - BOTTOM - 120)


def _lead(block: BlockV2) -> float:
    """Altura mínima del comienzo de un bloque, para que un título no quede huérfano: una
    gráfica no se parte (cuenta entera), una tabla necesita cabecera y una fila."""
    if isinstance(block, BarChart | StackedBarChart):
        rows = (len(block.items) if isinstance(block, BarChart) else len(block.rows)) + len(
            block.missing
        )
        return min(48 + min(rows, MAX_CHART_ROWS) * 15 + 30, 520) if rows else 80
    if isinstance(block, LineChart):
        return 240
    if isinstance(block, Diagram):
        return _diagram_height(block.rows) + 74
    if isinstance(block, Metrics):
        return 62
    if isinstance(block, Table | KeyValues):
        return 50
    if isinstance(block, Subheading):
        return 80
    return 30


BRAND_RGB = rgb(BRAND)


def _column_widths(
    columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...], size: float
) -> list[float]:
    """Ancho "natural" de cada columna (cabecera y celdas, con tope) escalado al ancho útil,
    sin bajar del ancho de la palabra más larga de la cabecera: así un título de columna no se
    parte por la mitad aunque la tabla tenga muchas columnas."""
    natural, minimum = [], []
    for i, column in enumerate(columns):
        header = encode_winansi(column)
        longest = text_width(header, size, True)
        for row in rows[:200]:
            if i < len(row):
                longest = max(longest, min(text_width(encode_winansi(row[i]), size), 190))
        natural.append(max(longest + 8, 30))
        word = max((text_width(w, size, True) for w in header.split(b" ")), default=0.0)
        minimum.append(min(word + 8, 90))
    total = sum(natural)
    widths = [CONTENT_W * w / total for w in natural]
    if sum(minimum) >= CONTENT_W:
        return [CONTENT_W * m / sum(minimum) for m in minimum]
    # Las columnas por debajo de su mínimo lo reciben; el exceso sale de las demás en
    # proporción a lo que les sobra sobre su propio mínimo.
    for _ in range(len(columns)):
        short = [i for i, w in enumerate(widths) if w < minimum[i] - 1e-6]
        if not short:
            break
        deficit = sum(minimum[i] - widths[i] for i in short)
        for i in short:
            widths[i] = minimum[i]
        spare = [(i, widths[i] - minimum[i]) for i in range(len(widths)) if i not in short]
        room = sum(extra for _, extra in spare)
        if room <= 0:
            break
        for i, extra in spare:
            widths[i] -= deficit * extra / room
    return widths


def _decorate(document: DocumentV2, pages: list[list[str]]) -> None:
    total = len(pages)
    for number, ops in enumerate(pages, start=1):
        w = _Layout(document, [])
        w.pages = [ops]
        if number > 1:
            # Cabecera: escudo, marca, título y clasificación en cada página salvo la portada.
            w.logo(MARGIN, PAGE_H - 36, 0.9, BRAND_RGB, _WHITE)
            w.text(MARGIN + 20, PAGE_H - 34, b"SENTRA", 10, "F2", BRAND_RGB)
            label = encode_winansi(document.classification)
            label_w = text_width(label, 8.5, True)
            title = one_line(document.title, CONTENT_W - 100 - label_w, 8)
            w.text(MARGIN + 82, PAGE_H - 34, title, 8, "F1", _GREY)
            w.text(PAGE_W - MARGIN - label_w, PAGE_H - 34, label, 8.5, "F2", _RED)
            w.rect(MARGIN, PAGE_H - 44, CONTENT_W, 0.8, fill=BRAND_RGB)
        w.rect(MARGIN, 42, CONTENT_W, 0.5, fill=_LINE)
        pages_label = encode_winansi(f"Página {number} de {total}")
        footer = one_line(
            f"Sentra • Informe {document.report_id} • Datos a fecha de {document.cutoff_at}"
            f" • {document.classification}",
            CONTENT_W - text_width(pages_label, 7) - 12,
            7,
        )
        w.text(MARGIN, 30, footer, 7, "F1", _GREY)
        w.text(PAGE_W - MARGIN - text_width(pages_label, 7), 30, pages_label, 7, "F1", _GREY)


def _pdf_string(text: str) -> str:
    return f"<{encode_winansi(text).hex()}>"


def _pdf_date(iso_text: str) -> str:
    digits = "".join(ch for ch in iso_text if ch.isdigit())[:14].ljust(14, "0")
    return f"D:{digits}Z"


def layout(document: DocumentV2) -> list[list[str]]:
    """Dos pasadas: la primera averigua en qué página empieza cada sección y la segunda
    escribe esos números en el índice. El índice ocupa lo mismo en las dos (una línea por
    sección), así que la paginación no cambia entre pasadas."""
    first = _Layout(document, [0] * len(document.sections))
    first.run()
    second = _Layout(document, first.section_pages)
    second.run()
    _decorate(document, second.pages)
    return second.pages


def render_pdf_v2(document: DocumentV2, generated_iso: str) -> bytes:
    pages = layout(document)
    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # se rellena al final (necesita el id de /Pages)
    pages_id = add(b"")
    fonts = [
        add(
            (
                f"<< /Type /Font /Subtype /Type1 /BaseFont /{name} /Encoding /WinAnsiEncoding >>"
            ).encode("ascii")
        )
        for name in ("Helvetica", "Helvetica-Bold", "Helvetica-Oblique")
    ]
    font_refs = " ".join(f"/F{i + 1} {ref} 0 R" for i, ref in enumerate(fonts))
    kids = []
    for ops in pages:
        stream = zlib.compress("\n".join(ops).encode("latin-1"), 6)
        content = add(
            b"<< /Length %d /Filter /FlateDecode >>\nstream\n" % len(stream)
            + stream
            + b"\nendstream"
        )
        kids.append(
            add(
                (
                    f"<< /Type /Page /Parent {pages_id} 0 R"
                    f" /MediaBox [0 0 {_num(PAGE_W)} {_num(PAGE_H)}]"
                    f" /Resources << /Font << {font_refs} >> >>"
                    f" /Contents {content} 0 R >>"
                ).encode("ascii")
            )
        )
    objects[pages_id - 1] = (
        f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>"
    ).encode("ascii")
    objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
    info = add(
        (
            f"<< /Title {_pdf_string(document.title)} /Subject {_pdf_string(document.report_name)}"
            " /Producer (Sentra Reporting v2) /Creator (Sentra)"
            f" /CreationDate ({_pdf_date(generated_iso)}) >>"
        ).encode("ascii")
    )
    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for number, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % number + body + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for offset in offsets:
        out += b"%010d 00000 n \n" % offset
    file_id = hashlib.sha256(document.report_id.encode("ascii", "replace")).hexdigest()[:32]
    out += (
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R"
        f" /ID [<{file_id}> <{file_id}>] >>\nstartxref\n{xref}\n%%EOF\n"
    ).encode("ascii")
    return bytes(out)
