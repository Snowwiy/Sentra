"""Fase 7C.5: plantilla v3 de informes con panel visual de anillos.

v3 es v2 más un panel de anillos en el resumen ejecutivo. Lo que no puede cambiar: un
snapshot v2 ya guardado se sigue renderizando con v2 (mismos bytes) y el mismo snapshot v3
produce siempre los mismos bytes en HTML y PDF.
"""

import copy
import re
import zlib
from typing import Any

import pytest

from app.reports.document import DocumentV2, DonutChart, DonutPanel, SectionV2, Subheading
from app.reports.render_html import render_html
from app.reports.render_pdf import render_pdf
from app.reports.render_pdf_v2 import donut_angles, share
from app.reports.templates import render_document
from app.reports.templates_v2 import (
    MAX_DONUT_SLICES,
    _donut,
    executive_panel,
    render_document_v2,
)
from tests.test_reports_v2 import (
    GENERATED,
    _check_html_v2,
    _pdf_pages_text,
    v1_response_snapshot,
    v1_risk_snapshot,
)


def _with_version(snapshot: dict[str, Any], version: int) -> dict[str, Any]:
    data = copy.deepcopy(snapshot)
    data["meta"]["template_version"] = version
    return data


def _panel(document: DocumentV2) -> DonutPanel | None:
    for block in document.sections[0].blocks:
        if isinstance(block, DonutPanel):
            return block
    return None


def test_v2_snapshot_keeps_v2_output_without_panel() -> None:
    snapshot = _with_version(v1_risk_snapshot(), 2)
    document = render_document(snapshot)
    assert isinstance(document, DocumentV2) and _panel(document) is None
    assert render_html(document) == render_html(render_document_v2(snapshot))
    html = render_html(document).decode()
    assert "Panel visual" not in html and ".donuts" not in html


def test_v3_adds_panel_after_kpis_and_is_deterministic() -> None:
    snapshot = _with_version(v1_risk_snapshot(), 3)
    document = render_document(snapshot)
    assert isinstance(document, DocumentV2) and document.template_version == 3
    blocks = document.sections[0].blocks
    assert isinstance(blocks[1], Subheading) and blocks[1].text == "Panel visual"
    panel = _panel(document)
    assert panel is not None
    risk = panel.charts[0]
    assert risk.title == "Activos por nivel de riesgo"
    # Sin ceros y en el orden fijo de los niveles; "unscored" None no añade porción.
    assert [label for label, _, _ in risk.slices] == ["Crítico", "Medio"]
    html = render_html(document)
    pdf = render_pdf(document, GENERATED)
    assert render_html(render_document(copy.deepcopy(snapshot))) == html
    assert render_pdf(render_document(copy.deepcopy(snapshot)), GENERATED) == pdf
    text = html.decode()
    _check_html_v2(text)
    assert 'class="donuts"' in text and "stroke-dasharray" in text
    # Accesible: el SVG lleva el desglose completo como texto.
    assert 'aria-label="Activos por nivel de riesgo: Crítico: 2 (67%); Medio: 1 (33%)"' in text
    pages = "\n".join(_pdf_pages_text(pdf))
    assert "Panel visual" in pages and "2 · 67%" in pages


def test_response_activity_panel_and_pdf_draws_curves() -> None:
    snapshot = _with_version(v1_response_snapshot(), 3)
    document = render_document(snapshot)
    assert isinstance(document, DocumentV2)
    panel = _panel(document)
    assert panel is not None
    assert {c.title for c in panel.charts} <= {"Ejecuciones por estado", "Ejecuciones por acción"}
    pdf = render_pdf(document, GENERATED)
    streams = re.findall(rb"stream\r?\n(.*?)\r?\nendstream", pdf, re.S)
    content = b"".join(zlib.decompress(s) for s in streams if s[:1] == b"x")
    # Las porciones son trazados con curvas Bézier (operador "c"), sin imágenes.
    assert re.search(rb"\d c ", content) is not None
    assert b"/Image" not in pdf


def test_unknown_future_version_uses_latest_renderer() -> None:
    document = render_document(_with_version(v1_risk_snapshot(), 9))
    assert isinstance(document, DocumentV2) and _panel(document) is not None


def test_donut_slices_order_zero_others_and_absent() -> None:
    assert _donut("x", None) is None
    empty = _donut("x", {"a": 0, "b": 0})
    assert empty is not None and empty.slices == ()
    many = _donut("x", {f"k{i:02d}": i + 1 for i in range(10)})
    assert many is not None and len(many.slices) == MAX_DONUT_SLICES
    assert many.slices[-1][0] == "Otros"
    assert sum(v for _, v, _ in many.slices) == sum(range(1, 11))


@pytest.mark.parametrize(
    ("value", "total", "expected"),
    [(0, 10, "0%"), (1, 1000, "<1%"), (1, 3, "33%"), (2, 3, "67%"), (5, 0, "0%")],
)
def test_share_never_shows_a_real_slice_as_zero(value: float, total: float, expected: str) -> None:
    assert share(value, total) == expected


def test_donut_angles_cover_full_circle_and_empty_chart_renders() -> None:
    chart = DonutChart("t", (("a", 1.0, "#1f4e79"), ("b", 3.0, "#d9480f")))
    angles = donut_angles(chart)
    assert angles[0][:2] == (0.0, 90.0) and angles[-1][1] == pytest.approx(360.0)
    empty = DonutPanel((DonutChart("Vacío", ()),))
    document = DocumentV2(
        title="t",
        report_name="r",
        report_id="00000000-0000-4000-8000-0000000000aa",
        generated_at="g",
        cutoff_at="c",
        classification="INTERNAL",
        cover=(),
        sections=(SectionV2("Resumen ejecutivo", (empty,)),),
        template_version=3,
    )
    assert "Sin datos en el periodo." in render_html(document).decode()
    assert "Sin datos en el periodo." in "\n".join(_pdf_pages_text(render_pdf(document, GENERATED)))


def test_executive_panel_minimizes_data() -> None:
    snapshot = {
        "meta": {"report_type": "executive_summary"},
        "data": {
            "risk": {"by_level": {"critical": 1, "low": 4}, "unscored": 2},
            "detections": {"by_severity": {"high": 3}},
            "vulnerabilities": {"confirmed": {"critical": 1}, "probable": {"critical": 2}},
            "assets": {"by_status": {"online": 5, "offline": 2}},
        },
    }
    panel = executive_panel(snapshot)
    assert panel is not None
    titles = [c.title for c in panel.charts]
    assert titles == [
        "Activos por nivel de riesgo",
        "Detecciones del periodo por severidad",
        "Vulnerabilidades activas por severidad",
        "Activos por estado",
    ]
    assert panel.charts[0].slices[-1][:2] == ("Sin calcular", 2.0)
    assert panel.charts[2].slices == (("Crítica", 3.0, "#9b1c1c"),)
    # Solo recuentos y etiquetas fijas: ningún identificador ni dirección.
    labels = [label for chart in panel.charts for label, _, _ in chart.slices]
    assert all(not re.search(r"\d+\.\d+\.\d+\.\d+|[0-9a-f]{8}-", label) for label in labels)
