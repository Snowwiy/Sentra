"""Generador PDF propio y determinista (Fase 5E), sin dependencias ni navegador.

Por qué no HTML→PDF (wkhtmltopdf, WeasyPrint, Chromium): todos cargan recursos (file://,
http://, fuentes del sistema) mientras renderizan, lo que abre SSRF y lectura de ficheros
locales, y añaden binarios nativos frágiles en Windows. Aquí el PDF se escribe directamente
desde el documento neutro (app/reports/document.py):

- solo las 2 fuentes estándar Helvetica/Helvetica-Bold (no se incrusta ni se carga ninguna
  fuente) con WinAnsiEncoding: cubre español; lo que no entra en cp1252 se sustituye por "?"
  (solo v1: la plantilla v2 translitera y marca "[U+XXXX]", ver render_pdf_v2.py);
- sin anotaciones, enlaces (/URI), acciones (/Launch, /JavaScript), formularios ni imágenes:
  el fichero no puede abrir nada al visualizarse;
- todo texto va como cadena hexadecimal: ningún carácter del dato puede cerrar la cadena
  ni inyectar operadores PDF;
- determinista: misma entrada → mismos bytes (fechas del snapshot, /ID derivado del id del
  informe, zlib con nivel fijo). El SHA-256 del artefacto es por tanto reproducible.
"""

import hashlib
import zlib
from dataclasses import dataclass, field

from app.reports.document import (
    AnyDocument,
    BarChart,
    Block,
    Bullets,
    Document,
    DocumentV2,
    KeyValues,
    Notice,
    Paragraph,
    Table,
)

PAGE_W, PAGE_H = 595.0, 842.0  # A4 vertical en puntos
MARGIN = 40.0
TOP = PAGE_H - 62.0  # bajo la cabecera de página
BOTTOM = 52.0  # sobre el pie de página
CONTENT_W = PAGE_W - 2 * MARGIN
MAX_CELL_LINES = 8

# Anchos AFM (1/1000 em) de Helvetica y Helvetica-Bold para ASCII 32..126.
_REGULAR = [
    278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
    1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
    333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
    556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
]  # fmt: skip
_BOLD = [
    278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
    556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
    975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
    667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
    333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
    611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584,
]  # fmt: skip
# Fuera de ASCII (acentos, ñ, guiones largos...): ancho conservador (sobreestimar solo deja
# algo más de margen, nunca texto que se sale de la celda).
_WIDE = {0x85: 1000, 0x97: 1000, 0x96: 556, 0x95: 350}
_DEFAULT_WIDE = 667
_REPLACE = {"→": "->", "←": "<-", "✓": "v", "\t": " ", "\r": " "}

_BLUE = (0.12, 0.31, 0.47)
_GREY = (0.36, 0.40, 0.45)
_LINE = (0.79, 0.83, 0.87)
_HEAD_BG = (0.93, 0.95, 0.97)
_NOTICE = (0.72, 0.47, 0.12)


def encode(text: str) -> bytes:
    for old, new in _REPLACE.items():
        text = text.replace(old, new)
    return text.encode("cp1252", errors="replace")


def text_width(data: bytes, size: float, bold: bool = False) -> float:
    table = _BOLD if bold else _REGULAR
    total = 0
    for byte in data:
        if 32 <= byte <= 126:
            total += table[byte - 32]
        else:
            total += _WIDE.get(byte, _DEFAULT_WIDE)
    return total * size / 1000.0


def wrap(text: str, width: float, size: float, bold: bool = False) -> list[bytes]:
    """Parte el texto en líneas que caben en `width`; corta palabras largas (ids, hashes)."""
    lines: list[bytes] = []
    for paragraph in text.split("\n"):
        current = b""
        for word in encode(paragraph).split(b" "):
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


def _clip(lines: list[bytes], limit: int) -> list[bytes]:
    if len(lines) <= limit:
        return lines
    return [*lines[: limit - 1], lines[limit - 1][:-1] + b"\x85"]


def _num(value: float) -> str:
    return f"{value:.2f}".rstrip("0").rstrip(".")


@dataclass
class _Page:
    ops: list[str] = field(default_factory=list)


class _Writer:
    """Maquetación por bloques: va llenando páginas y salta de página cuando no cabe."""

    def __init__(self) -> None:
        self.pages: list[_Page] = [_Page()]
        self.y = TOP

    @property
    def ops(self) -> list[str]:
        return self.pages[-1].ops

    def new_page(self) -> None:
        self.pages.append(_Page())
        self.y = TOP

    def ensure(self, height: float) -> None:
        if self.y - height < BOTTOM:
            self.new_page()

    def text(
        self,
        x: float,
        y: float,
        data: bytes,
        size: float,
        bold: bool = False,
        color: tuple[float, float, float] = (0, 0, 0),
    ) -> None:
        font = "F2" if bold else "F1"
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
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
    ) -> None:
        parts = []
        if fill:
            parts.append(f"{_num(fill[0])} {_num(fill[1])} {_num(fill[2])} rg")
        if stroke:
            parts.append(f"{_num(stroke[0])} {_num(stroke[1])} {_num(stroke[2])} RG 0.5 w")
        op = "B" if fill and stroke else "f" if fill else "S"
        parts.append(f"{_num(x)} {_num(y)} {_num(w)} {_num(h)} re {op}")
        self.ops.append("q " + " ".join(parts) + " Q")

    def paragraph(
        self,
        text: str,
        size: float = 9,
        bold: bool = False,
        indent: float = 0,
        color: tuple[float, float, float] = (0, 0, 0),
    ) -> None:
        leading = size * 1.3
        for line in wrap(text, CONTENT_W - indent, size, bold):
            self.ensure(leading)
            self.text(MARGIN + indent, self.y - size, line, size, bold, color)
            self.y -= leading
        self.y -= 3

    def heading(self, text: str) -> None:
        self.ensure(40)
        self.y -= 8
        self.text(MARGIN, self.y - 12, encode(text), 12, True, _BLUE)
        self.y -= 16
        self.rect(MARGIN, self.y, CONTENT_W, 0.6, fill=_LINE)
        self.y -= 8

    def table(
        self,
        columns: tuple[str, ...],
        rows: tuple[tuple[str, ...], ...],
        widths: list[float] | None = None,
        bold_first: bool = False,
        header: bool = True,
    ) -> None:
        count = len(columns)
        size = 8.0 if count <= 6 else 7.0 if count <= 10 else 6.0
        leading = size * 1.25
        pad = 2.5
        if widths is None:
            widths = _column_widths(columns, rows, size)

        def cells(values: tuple[str, ...], is_header: bool) -> list[list[bytes]]:
            return [
                _clip(
                    wrap(value, widths[i] - 2 * pad, size, is_header or (bold_first and i == 0)),
                    MAX_CELL_LINES,
                )
                for i, value in enumerate(values)
            ]

        def draw(values: tuple[str, ...], is_header: bool) -> None:
            wrapped = cells(values, is_header)
            height = max(len(c) for c in wrapped) * leading + 2 * pad
            if self.y - height < BOTTOM:
                self.new_page()
                if header and not is_header:
                    draw(columns, True)
            x = MARGIN
            for i, lines in enumerate(wrapped):
                self.rect(
                    x, self.y - height, widths[i], height,
                    fill=_HEAD_BG if is_header else None, stroke=_LINE,
                )  # fmt: skip
                for n, line in enumerate(lines):
                    self.text(
                        x + pad,
                        self.y - pad - size - n * leading + 1,
                        line,
                        size,
                        is_header or (bold_first and i == 0),
                    )
                x += widths[i]
            self.y -= height

        if header:
            draw(columns, True)
        for row in rows:
            draw(row, False)
        self.y -= 6

    def chart(self, chart: BarChart) -> None:
        size, row_h, label_w = 8.0, 13.0, 150.0
        self.ensure(row_h * min(len(chart.items), 6) + 20)
        self.text(MARGIN, self.y - 10, encode(chart.title), 9, True)
        self.y -= 16
        top = max((value for _, value in chart.items), default=0) or 1
        bar_space = CONTENT_W - label_w - 50
        for label, value in chart.items:
            self.ensure(row_h)
            self.text(MARGIN, self.y - size - 1, _clip(wrap(label, label_w - 6, size), 1)[0], size)
            length = bar_space * (value / top)
            if length > 0:
                self.rect(MARGIN + label_w, self.y - row_h + 3, length, row_h - 5, fill=_BLUE)
            shown = str(int(value)) if float(value).is_integer() else _num(round(value, 1))
            self.text(MARGIN + label_w + length + 4, self.y - size - 1, encode(shown), size)
            self.y -= row_h
        self.y -= 6


def _column_widths(
    columns: tuple[str, ...], rows: tuple[tuple[str, ...], ...], size: float
) -> list[float]:
    # Ancho "natural" de cada columna (cabecera y celdas, con tope), escalado al ancho útil.
    natural = []
    for i, column in enumerate(columns):
        longest = text_width(encode(column), size, True)
        for row in rows[:200]:
            longest = max(longest, min(text_width(encode(row[i]), size), 180))
        natural.append(max(longest + 6, 28))
    total = sum(natural)
    return [CONTENT_W * w / total for w in natural]


def _block(writer: _Writer, block: Block) -> None:
    if isinstance(block, Paragraph):
        writer.paragraph(block.text)
    elif isinstance(block, Notice):
        writer.paragraph("Aviso: " + block.text, bold=True, color=_NOTICE)
    elif isinstance(block, Bullets):
        for item in block.items:
            writer.paragraph("\x95 " + item, indent=6)
    elif isinstance(block, KeyValues):
        widths = [CONTENT_W * 0.3, CONTENT_W * 0.7]
        writer.table(("", ""), block.pairs, widths=widths, bold_first=True, header=False)
    elif isinstance(block, Table):
        writer.table(block.columns, block.rows)
        if block.note:
            writer.paragraph(block.note, size=7, color=_GREY)
    else:
        writer.chart(block)


def _header_footer(document: Document, page: _Page, number: int, total: int) -> None:
    w = _Writer()
    w.pages = [page]
    # Cabecera: marca, título y clasificación en cada página; pie con id, fecha y página.
    w.text(MARGIN, PAGE_H - 34, b"SENTRA", 10, True, _BLUE)
    title = _clip(wrap(document.title, CONTENT_W - 160, 8), 1)[0]
    w.text(MARGIN + 60, PAGE_H - 34, title, 8, False, _GREY)
    label = encode(document.classification)
    w.text(
        PAGE_W - MARGIN - text_width(label, 9, True),
        PAGE_H - 34,
        label,
        9,
        True,
        (0.61, 0.11, 0.11),
    )
    w.rect(MARGIN, PAGE_H - 42, CONTENT_W, 0.8, fill=_BLUE)
    footer = encode(
        f"Sentra \x95 Informe {document.report_id} \x95 Generado {document.generated_at}"
        f" \x95 {document.classification}"
    )
    w.rect(MARGIN, 40, CONTENT_W, 0.5, fill=_LINE)
    w.text(MARGIN, 28, footer, 7, False, _GREY)
    pages = encode(f"Página {number} de {total}")
    w.text(PAGE_W - MARGIN - text_width(pages, 7), 28, pages, 7, False, _GREY)


def _pdf_string(text: str) -> str:
    return f"<{encode(text).hex()}>"


def _pdf_date(iso_text: str) -> str:
    digits = "".join(ch for ch in iso_text if ch.isdigit())[:14].ljust(14, "0")
    return f"D:{digits}Z"


def render_pdf(document: AnyDocument, generated_iso: str) -> bytes:
    # Fase 6D.5: la plantilla v2 tiene su propio renderer (importación diferida: el módulo
    # v2 reutiliza las tablas de anchos de este). El camino v1 no cambia.
    if isinstance(document, DocumentV2):
        from app.reports.render_pdf_v2 import render_pdf_v2

        return render_pdf_v2(document, generated_iso)
    writer = _Writer()
    writer.paragraph(document.title, size=16, bold=True, color=_BLUE)
    writer.paragraph(document.report_name, size=10, color=_GREY)
    writer.heading("Metadatos del informe")
    _block(writer, KeyValues(document.meta))
    for section in document.sections:
        writer.heading(section.title)
        for block in section.blocks:
            _block(writer, block)
    total = len(writer.pages)
    for number, page in enumerate(writer.pages, start=1):
        _header_footer(document, page, number, total)

    objects: list[bytes] = []

    def add(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog = add(b"")  # se rellena al final (necesita el id de /Pages)
    pages_id = add(b"")
    regular = add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    bold = add(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>"
    )
    kids = []
    for page in writer.pages:
        stream = zlib.compress("\n".join(page.ops).encode("latin-1"), 6)
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
                    f" /Resources << /Font << /F1 {regular} 0 R /F2 {bold} 0 R >> >>"
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
            f"<< /Title {_pdf_string(document.title)} /Producer (Sentra Reporting)"
            f" /Creator (Sentra) /CreationDate ({_pdf_date(generated_iso)}) >>"
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
