"""Renderer HTML de la plantilla v2 (Fase 6D.5): autocontenido, imprimible y sin scripts.

Mismas garantías que v1 (app/reports/render_html.py, que no cambia) y la misma CSP:
- todo texto pasa por html.escape (también comillas); los SVG se construyen aquí solo con
  números, colores de la paleta cerrada de app/reports/document.py y texto escapado;
- sin <script>, sin manejadores on*, sin recursos externos (ni src/href a URLs, ni @import,
  ni url()); los únicos enlaces son anclas internas del índice ("#s-3");
- el HTML conserva el Unicode completo (la transliteración solo existe en el PDF).

Impresión: @page A4 con márgenes, saltos de página antes de las secciones principales,
cabeceras de tabla repetidas (thead), filas que no se parten y gráficas que no se cortan.
"""

import math
import re
from html import escape

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
from app.reports.render_pdf_v2 import axis_max, fmt_chart, safe

_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none';"
    " form-action 'none'"
)
_HEX = re.compile(r"^#[0-9a-fA-F]{6}$")
_CSS = """
:root{color-scheme:light;--brand:#1f4e79;--text:#1b2430;--muted:#5b6573;--line:#c9d3df;
 --head:#e8eef5;--zebra:#f7f9fb}
*{box-sizing:border-box}
body{font-family:Helvetica,Arial,sans-serif;font-size:12px;color:var(--text);margin:0;
 background:#fff;line-height:1.45}
main{max-width:900px;margin:0 auto;padding:24px}
.cover{background:var(--brand);color:#fff;padding:28px 32px;border-radius:4px}
.cover .brand{display:flex;align-items:center;gap:14px}
.cover .word{font-size:32px;font-weight:bold;letter-spacing:.08em}
.cover .tag{font-size:12px;opacity:.85}
.cover .classification{float:right;background:#fff;color:#9b1c1c;font-weight:bold;
 padding:3px 10px;border-radius:3px}
h1{font-size:24px;margin:22px 0 4px}
.subtitle{color:var(--muted);font-size:14px;margin-bottom:12px}
h2{font-size:17px;color:var(--brand);border-bottom:2px solid var(--brand);margin-top:30px;
 padding-bottom:3px}
h3{font-size:13px;margin:18px 0 6px}
nav ol{padding-left:22px}
nav a{color:var(--brand);text-decoration:none}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid var(--line);padding:3px 6px;text-align:left;vertical-align:top;
 word-break:break-word}
th{background:var(--head)}
tbody tr:nth-child(even) td{background:var(--zebra)}
tr{break-inside:avoid;page-break-inside:avoid}
thead{display:table-header-group}
table.kv th{width:32%}
.note{color:var(--muted);font-size:11px;font-style:italic}
.notice{border-left:4px solid #b7791f;background:#fff8e6;padding:6px 10px;margin:8px 0;
 font-weight:bold;color:#7a4f0e}
.chart{margin:12px 0;break-inside:avoid;page-break-inside:avoid}
.chart h4{margin:0 0 2px;font-size:12px}
.chart .unit{color:var(--muted);font-size:10px;font-style:italic}
.chart svg{width:100%;height:auto;display:block}
.empty{border:1px solid var(--line);background:var(--zebra);padding:10px;color:var(--muted);
 font-style:italic}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:8px 0}
.metric{border:1px solid var(--line);border-left:4px solid var(--brand);background:var(--zebra);
 padding:6px 10px;break-inside:avoid}
.metric .label{color:var(--muted);font-size:10px;font-weight:bold;text-transform:uppercase}
.metric .value{color:var(--brand);font-size:20px;font-weight:bold}
.metric .detail{color:var(--muted);font-size:10px}
.legend{font-size:10px;color:var(--text);margin:4px 0}
.legend span{display:inline-block;margin-right:12px}
.legend i{display:inline-block;width:10px;height:10px;margin-right:4px;vertical-align:-1px}
footer{margin-top:32px;border-top:1px solid var(--line);padding-top:6px;color:var(--muted);
 font-size:11px}
.pb{break-before:page;page-break-before:always}
@page{size:A4;margin:16mm 14mm}
@media print{main{padding:0;max-width:none}h2,h3{break-after:avoid;page-break-after:avoid}
 .cover{break-after:page;page-break-after:always}}
@media (max-width:640px){.metrics{grid-template-columns:1fr}}
"""


def _e(text: str) -> str:
    return escape(text, quote=True)


def _color(value: str) -> str:
    return value if _HEX.match(value) else BRAND


def _n(value: float) -> str:
    if not math.isfinite(value):
        value = 0.0
    return f"{value:.1f}".rstrip("0").rstrip(".") or "0"


def _logo(size: int, body: str, mark: str) -> str:
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 16 17" role="img" aria-label="SENTRA">'
        f'<path d="M8 0.5 L16 3.5 L16 8.5 L8 16.5 L0 8.5 L0 3.5 Z" fill="{body}"/>'
        f'<path d="M2.5 8 L5.5 8 L7 4.5 L9 11.5 L10.5 8 L13.5 8" fill="none" stroke="{mark}"'
        ' stroke-width="1.2" stroke-linejoin="round" stroke-linecap="round"/></svg>'
    )


def _chart_head(title: str, unit: str) -> str:
    unit_html = f'<div class="unit">Unidad: {_e(unit)}</div>' if unit else ""
    return f"<h4>{_e(title)}</h4>{unit_html}"


def _notes(note: str | None, missing: tuple[tuple[str, str], ...], more: int) -> str:
    parts = [f'<p class="note">{_e(label)}: {_e(reason)}</p>' for label, reason in missing]
    if more:
        parts.append(
            f'<p class="note">Y {more} categorías más no dibujadas (tope de la gráfica).</p>'
        )
    if note:
        parts.append(f'<p class="note">{_e(note)}</p>')
    return "".join(parts)


def _empty(title: str, unit: str, text: str, note: str | None) -> str:
    return (
        f'<div class="chart">{_chart_head(title, unit)}<div class="empty">{_e(text)}</div>'
        f"{_notes(note, (), 0)}</div>"
    )


def _axis(x0: float, width: float, top: float, bottom: float, maximum: float) -> list[str]:
    parts = []
    for i in range(5):
        x = x0 + width * i / 4
        parts.append(
            f'<line x1="{_n(x)}" y1="{_n(top)}" x2="{_n(x)}" y2="{_n(bottom)}"'
            ' stroke="#e5e9ee" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{_n(x)}" y="{_n(bottom + 12)}" font-size="9" text-anchor="middle"'
            f' fill="#5b6573">{_e(fmt_chart(maximum * i / 4))}</text>'
        )
    return parts


def _bars(chart: BarChart) -> str:
    items = chart.items
    if not items and not chart.missing:
        return _empty(chart.title, chart.unit, chart.empty_text, chart.note)
    width, row_h, label_w, value_w = 760, 20, 220, 80
    rows = len(items) + len(chart.missing)
    bar_w = width - label_w - value_w
    height = rows * row_h + 22
    maximum = axis_max([safe(v) for _, v in items])
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_e(chart.title)}">',
        *_axis(label_w, bar_w, 0, rows * row_h, maximum),
    ]
    for index, (label, value) in enumerate(items):
        y = index * row_h
        length = bar_w * safe(value) / maximum
        color = _color(chart.colors[index]) if index < len(chart.colors) else BRAND
        parts.append(f'<text x="0" y="{y + 14}" font-size="11">{_e(label)}</text>')
        if length > 0:
            parts.append(
                f'<rect x="{label_w}" y="{y + 4}" width="{_n(max(length, 1))}"'
                f' height="{row_h - 8}" fill="{color}"/>'
            )
        parts.append(
            f'<text x="{_n(label_w + length + 5)}" y="{y + 14}" font-size="11"'
            f' font-weight="bold">{_e(fmt_chart(value))}</text>'
        )
    for offset, (label, reason) in enumerate(chart.missing):
        y = (len(items) + offset) * row_h
        parts.append(f'<text x="0" y="{y + 14}" font-size="11">{_e(label)}</text>')
        parts.append(
            f'<text x="{label_w + 4}" y="{y + 14}" font-size="10" font-style="italic"'
            f' fill="#5b6573">{_e(reason)}</text>'
        )
    parts.append("</svg>")
    return (
        f'<div class="chart">{_chart_head(chart.title, chart.unit)}{"".join(parts)}'
        f"{_notes(chart.note, (), chart.more)}</div>"
    )


def _legend(entries: list[tuple[str, str]], dashes: list[str] | None = None) -> str:
    spans = []
    for index, (label, color) in enumerate(entries):
        if dashes is not None:
            dash = {"dashed": "6 3", "dotted": "1.5 3"}.get(dashes[index], "")
            dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
            swatch = (
                f'<svg width="22" height="10" viewBox="0 0 22 10"><line x1="0" y1="5" x2="22"'
                f' y2="5" stroke="{_color(color)}" stroke-width="2"{dash_attr}/></svg> '
            )
        else:
            swatch = f'<i style="background:{_color(color)}"></i>'
        spans.append(f"<span>{swatch}{_e(label)}</span>")
    return f'<div class="legend">{"".join(spans)}</div>'


def _stacked(chart: StackedBarChart) -> str:
    rows_data = chart.rows
    if not rows_data and not chart.missing:
        return _empty(chart.title, chart.unit, chart.empty_text, chart.note)
    width, row_h, label_w, value_w = 760, 22, 200, 80
    rows = len(rows_data) + len(chart.missing)
    bar_w = width - label_w - value_w
    height = rows * row_h + 22
    totals = [sum(safe(v) for v in values) for _, values in rows_data]
    maximum = axis_max(totals)
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_e(chart.title)}">',
        *_axis(label_w, bar_w, 0, rows * row_h, maximum),
    ]
    for index, (label, values) in enumerate(rows_data):
        y = index * row_h
        parts.append(f'<text x="0" y="{y + 15}" font-size="11">{_e(label)}</text>')
        x = float(label_w)
        for series_index, value in enumerate(values):
            length = bar_w * safe(value) / maximum
            if length > 0:
                color = (
                    _color(chart.colors[series_index])
                    if series_index < len(chart.colors)
                    else BRAND
                )
                parts.append(
                    f'<rect x="{_n(x)}" y="{y + 4}" width="{_n(length)}" height="{row_h - 8}"'
                    f' fill="{color}"/>'
                )
            x += length
        parts.append(
            f'<text x="{_n(x + 5)}" y="{y + 15}" font-size="11" font-weight="bold">'
            f"{_e(fmt_chart(totals[index]))}</text>"
        )
    for offset, (label, reason) in enumerate(chart.missing):
        y = (len(rows_data) + offset) * row_h
        parts.append(f'<text x="0" y="{y + 15}" font-size="11">{_e(label)}</text>')
        parts.append(
            f'<text x="{label_w + 4}" y="{y + 15}" font-size="10" font-style="italic"'
            f' fill="#5b6573">{_e(reason)}</text>'
        )
    parts.append("</svg>")
    legend = _legend(list(zip(chart.series, chart.colors, strict=False)))
    return (
        f'<div class="chart">{_chart_head(chart.title, chart.unit)}{legend}{"".join(parts)}'
        f"{_notes(chart.note, (), chart.more)}</div>"
    )


def _lines(chart: LineChart) -> str:
    series = [s for s in chart.series if s.points]
    if not series and not chart.missing:
        return _empty(chart.title, chart.unit, chart.empty_text, chart.note)
    width, plot_h, axis_w, pad = 760, 220, 56, 10
    height = plot_h + 40
    values = [safe(v) for s in series for _, v in s.points]
    maximum = chart.y_max if chart.y_max else axis_max(values)
    x0, plot_w = axis_w, width - axis_w - pad
    top, bottom = 8, 8 + plot_h
    parts = [f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_e(chart.title)}">']
    for i in range(5):
        y = bottom - plot_h * i / 4
        parts.append(
            f'<line x1="{x0}" y1="{_n(y)}" x2="{x0 + plot_w}" y2="{_n(y)}" stroke="#e5e9ee"/>'
        )
        parts.append(
            f'<text x="{x0 - 6}" y="{_n(y + 3)}" font-size="9" text-anchor="end"'
            f' fill="#5b6573">{_e(fmt_chart(maximum * i / 4))}</text>'
        )
    parts.append(
        f'<polyline points="{x0},{top} {x0},{bottom} {x0 + plot_w},{bottom}" fill="none"'
        ' stroke="#8c949e"/>'
    )
    for fraction, label in chart.x_ticks:
        x = x0 + plot_w * min(max(fraction, 0.0), 1.0)
        parts.append(
            f'<line x1="{_n(x)}" y1="{bottom}" x2="{_n(x)}" y2="{bottom + 4}" stroke="#8c949e"/>'
        )
        parts.append(
            f'<text x="{_n(x)}" y="{bottom + 16}" font-size="9" text-anchor="middle"'
            f' fill="#5b6573">{_e(label)}</text>'
        )
    for item in series:
        color = _color(item.color)
        points = [
            (
                x0 + plot_w * min(max(px, 0.0), 1.0),
                bottom - plot_h * min(safe(py), maximum) / maximum,
            )
            for px, py in item.points
        ]
        coords = " ".join(f"{_n(x)},{_n(y)}" for x, y in points)
        parts.append(
            f'<polyline points="{coords}" fill="none" stroke="{color}" stroke-width="2"'
            ' stroke-linejoin="round"/>'
        )
        if len(points) <= 62:
            parts.extend(
                f'<circle cx="{_n(x)}" cy="{_n(y)}" r="2.6" fill="{color}"/>' for x, y in points
            )
    parts.append("</svg>")
    x_label = f'<p class="note">{_e(chart.x_label)}</p>' if chart.x_label else ""
    legend = _legend([(s.label, s.color) for s in series])
    return (
        f'<div class="chart">{_chart_head(chart.title, chart.unit)}{"".join(parts)}{x_label}'
        f"{legend}{_notes(chart.note, chart.missing, chart.more)}</div>"
    )


def _diagram(block: Diagram) -> str:
    if not block.nodes:
        return _empty(block.title, "", "Sin nodos que dibujar.", block.note)
    width = 760
    rows = max(block.rows, 1)
    height = rows * 80 + 20
    per_row = max(
        (sum(1 for n in block.nodes if abs(n.y - m.y) < 1e-6) for m in block.nodes), default=1
    )
    box_w = min(150.0, (width - 20) / per_row - 8)
    box_h = 26.0
    inner_x, inner_w = 10 + box_w / 2, width - 20 - box_w
    inner_y, inner_h = 10 + box_h / 2, height - 20 - box_h
    where = {
        node.key: (inner_x + inner_w * node.x, inner_y + inner_h * node.y) for node in block.nodes
    }
    parts = [
        f'<svg viewBox="0 0 {width} {height}" role="img" aria-label="{_e(block.title)}">',
        f'<rect x="0" y="0" width="{width}" height="{height}" fill="#f7f9fb" stroke="#c9d3df"/>',
    ]
    for edge in block.edges:
        if edge.source not in where or edge.target not in where:
            continue
        (x1, y1), (x2, y2) = where[edge.source], where[edge.target]
        dash = {"dashed": "6 3", "dotted": "1.5 3"}.get(LINK_STYLES.get(edge.kind, "solid"), "")
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        parts.append(
            f'<line x1="{_n(x1)}" y1="{_n(y1)}" x2="{_n(x2)}" y2="{_n(y2)}" stroke="#5c6673"'
            f' stroke-width="1.4"{dash_attr}/>'
        )
    font = 10 if box_w > 90 else 8
    for node in block.nodes:
        cx, cy = where[node.key]
        color = BRAND if node.role == "infrastructure" else "#5c6673"
        parts.append(
            f"<g><title>{_e(node.label)}</title>"
            f'<rect x="{_n(cx - box_w / 2)}" y="{_n(cy - box_h / 2)}"'
            f' width="{_n(box_w)}" height="{_n(box_h)}" rx="3" fill="#fff" stroke="{color}"'
            f' stroke-width="1.4"/>'
        )
        # La etiqueta se recorta en el propio SVG (clipPath no hace falta: se acorta el texto
        # a lo que cabe aproximadamente y el título conserva el nombre completo).
        limit = max(4, int(box_w / (font * 0.56)))
        label = node.label if len(node.label) <= limit else node.label[: limit - 1] + "…"
        parts.append(
            f'<text x="{_n(cx)}" y="{_n(cy + font / 3)}" font-size="{font}" text-anchor="middle">'
            f"{_e(label)}</text></g>"
        )
    parts.append("</svg>")
    legend = _legend(
        [(label, "#5c6673") for _, label in block.legend],
        dashes=[LINK_STYLES.get(kind, "solid") for kind, _ in block.legend],
    )
    return (
        f'<div class="chart">{_chart_head(block.title, "")}{"".join(parts)}{legend}'
        f"{_notes(block.note, (), 0)}</div>"
    )


def _metrics(block: Metrics) -> str:
    tiles = "".join(
        f'<div class="metric"><div class="label">{_e(m.label)}</div>'
        f'<div class="value">{_e(m.value)}</div>'
        + (f'<div class="detail">{_e(m.detail)}</div>' if m.detail else "")
        + "</div>"
        for m in block.items
    )
    note = f'<p class="note">{_e(block.note)}</p>' if block.note else ""
    return f'<div class="metrics">{tiles}</div>{note}'


def _block(block: BlockV2) -> str:
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
    if isinstance(block, Metrics):
        return _metrics(block)
    if isinstance(block, Subheading):
        return f"<h3>{_e(block.text)}</h3>"
    if isinstance(block, PageBreak):
        return '<div class="pb"></div>'
    if isinstance(block, StackedBarChart):
        return _stacked(block)
    if isinstance(block, LineChart):
        return _lines(block)
    if isinstance(block, Diagram):
        return _diagram(block)
    return _bars(block)


def render_html_v2(document: DocumentV2) -> bytes:
    cover_rows = "".join(f"<tr><th>{_e(k)}</th><td>{_e(v)}</td></tr>" for k, v in document.cover)
    toc = "".join(
        f'<li><a href="#s-{n}">{_e(section.title)}</a></li>'
        for n, section in enumerate(document.sections, start=1)
    )
    sections = "".join(
        f'<section id="s-{n}"{" class=" + chr(34) + "pb" + chr(34) if section.new_page else ""}>'
        f"<h2>{n}. {_e(section.title)}</h2>{''.join(_block(b) for b in section.blocks)}</section>"
        for n, section in enumerate(document.sections, start=1)
    )
    html = (
        "<!DOCTYPE html>\n"
        '<html lang="es"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        '<meta name="referrer" content="no-referrer">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>{_e(document.title)}</title><style>{_CSS}</style></head><body><main>"
        '<header class="cover">'
        f'<span class="classification">{_e(document.classification)}</span>'
        f'<div class="brand">{_logo(56, "#ffffff", BRAND)}<div><div class="word">SENTRA</div>'
        '<div class="tag">Plataforma de monitorización y operaciones de seguridad</div></div>'
        "</div></header>"
        f"<h1>{_e(document.title)}</h1>"
        f'<div class="subtitle">{_e(document.report_name)}</div>'
        f'<table class="kv"><tbody>{cover_rows}</tbody></table>'
        '<p class="note">Documento generado por Sentra a partir de un snapshot inmutable de los'
        " datos a la hora de corte indicada. Volver a renderizar el mismo snapshot produce"
        " exactamente los mismos bytes (SHA-256 reproducible). Todas las horas en UTC.</p>"
        f'<nav class="pb"><h2>Contenido</h2><ol>{toc}</ol></nav>'
        f"{sections}"
        f"<footer>Sentra · Informe {_e(document.report_id)} · Datos a fecha de"
        f" {_e(document.cutoff_at)} · Generado {_e(document.generated_at)} ·"
        f" {_e(document.classification)}</footer>"
        "</main></body></html>\n"
    )
    return html.encode("utf-8")
