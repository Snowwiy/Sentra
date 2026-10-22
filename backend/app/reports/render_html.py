"""Render HTML autocontenido de un informe (Fase 5E).

Seguridad (docs/report-security.md):
- Todo texto pasa por html.escape (también comillas): hostnames, títulos de incidentes,
  notas o nombres de regla hostiles se muestran como texto, nunca como marcado.
- Sin JavaScript, sin recursos externos: ni <script>, ni src/href a URLs, ni @import, ni
  url(). Los gráficos son SVG en línea generado aquí. La CSP del propio documento lo
  refuerza aunque alguien lo abra fuera de Sentra: default-src 'none'.
- Imprimible: CSS de impresión, cabeceras de tabla repetidas y sin cortes dentro de filas.
"""

from html import escape

from app.reports.document import (
    AnyDocument,
    BarChart,
    Block,
    Bullets,
    DocumentV2,
    KeyValues,
    Notice,
    Paragraph,
    Table,
)
from app.reports.render_html_v2 import render_html_v2

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none';"
    " form-action 'none'"
)
_CSS = """
:root{color-scheme:light}
body{font-family:Helvetica,Arial,sans-serif;font-size:12px;color:#1b2430;margin:24px;line-height:1.4}
header{border-bottom:3px solid #1f4e79;margin-bottom:16px;padding-bottom:8px}
.brand{font-weight:bold;color:#1f4e79;letter-spacing:.08em}
.classification{float:right;font-weight:bold;border:1px solid #9b1c1c;color:#9b1c1c;padding:2px 8px}
h1{font-size:20px;margin:8px 0 4px}
h2{font-size:15px;color:#1f4e79;border-bottom:1px solid #c9d3df;margin-top:24px;padding-bottom:2px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #c9d3df;padding:3px 5px;text-align:left;vertical-align:top;
 word-break:break-word}
th{background:#eef2f7}
tr{page-break-inside:avoid}
thead{display:table-header-group}
table.kv th{width:28%}
.note{color:#5b6573;font-size:11px}
.notice{border-left:4px solid #b7791f;background:#fff8e6;padding:6px 8px;margin:8px 0}
.chart{margin:8px 0}
footer{margin-top:32px;border-top:1px solid #c9d3df;padding-top:6px;color:#5b6573;font-size:11px}
@media print{body{margin:0}h2{page-break-after:avoid}}
"""
_BAR_COLOR = "#1f4e79"


def _e(text: str) -> str:
    return escape(text, quote=True)


def _chart(chart: BarChart) -> str:
    width, row_h, label_w = 640, 20, 200
    height = row_h * len(chart.items) + 24
    top = max((value for _, value in chart.items), default=0) or 1
    parts = [
        f'<svg class="chart" width="{width}" height="{height}"'
        f' viewBox="0 0 {width} {height}" role="img" aria-label="{_e(chart.title)}">',
        f'<text x="0" y="14" font-size="12" font-weight="bold">{_e(chart.title)}</text>',
    ]
    for index, (label, value) in enumerate(chart.items):
        y = 24 + index * row_h
        bar = int((width - label_w - 60) * (value / top))
        parts.append(f'<text x="0" y="{y + 13}" font-size="11">{_e(label)}</text>')
        parts.append(
            f'<rect x="{label_w}" y="{y + 3}" width="{bar}" height="{row_h - 6}"'
            f' fill="{_BAR_COLOR}"/>'
        )
        shown = int(value) if float(value).is_integer() else round(value, 1)
        parts.append(f'<text x="{label_w + bar + 6}" y="{y + 13}" font-size="11">{shown}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _block(block: Block) -> str:
    if isinstance(block, Paragraph):
        return f"<p>{_e(block.text)}</p>"
    if isinstance(block, Notice):
        return f'<div class="notice">{_e(block.text)}</div>'
    if isinstance(block, Bullets):
        items = "".join(f"<li>{_e(item)}</li>" for item in block.items)
        return f"<ul>{items}</ul>"
    if isinstance(block, KeyValues):
        rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in block.pairs)
        return f'<table class="kv"><tbody>{rows}</tbody></table>'
    if isinstance(block, Table):
        head = "".join(f"<th>{_e(c)}</th>" for c in block.columns)
        body = "".join(
            "<tr>" + "".join(f"<td>{_e(cell)}</td>" for cell in row) + "</tr>" for row in block.rows
        )
        note = f'<p class="note">{_e(block.note)}</p>' if block.note else ""
        return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>{note}"
    return _chart(block)


def render_html(document: AnyDocument) -> bytes:
    # Fase 6D.5: la plantilla v2 tiene su propio renderer; el camino v1 no cambia (mismo
    # snapshot v1 → mismos bytes que antes).
    if isinstance(document, DocumentV2):
        return render_html_v2(document)
    sections = "".join(
        f"<section><h2>{_e(section.title)}</h2>{''.join(_block(b) for b in section.blocks)}"
        "</section>"
        for section in document.sections
    )
    meta = _block(KeyValues(document.meta))
    html = (
        "<!DOCTYPE html>\n"
        '<html lang="es"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        '<meta name="referrer" content="no-referrer">'
        f"<title>{_e(document.title)}</title><style>{_CSS}</style></head><body>"
        f'<header><span class="classification">{_e(document.classification)}</span>'
        f'<div class="brand">SENTRA</div><h1>{_e(document.title)}</h1>'
        f"<div>{_e(document.report_name)}</div></header>"
        f"<section><h2>Metadatos del informe</h2>{meta}</section>"
        f"{sections}"
        f"<footer>Sentra · Informe {_e(document.report_id)} · Generado {_e(document.generated_at)}"
        f" · {_e(document.classification)}</footer>"
        "</body></html>\n"
    )
    return html.encode("utf-8")
