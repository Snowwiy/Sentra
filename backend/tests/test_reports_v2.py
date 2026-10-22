# ruff: noqa: RUF001
# (Las pruebas de transliteración usan a propósito símbolos Unicode parecidos a ASCII.)
"""Reporting Engine v2 (Fase 6D.5): plantilla v2, gráficas, PDF v2 y compatibilidad con v1.

Dos grupos de pruebas:
- unitarias, sin base de datos: snapshots y documentos sintéticos para los casos límite
  (gráficas vacías, un solo valor, valores enormes, cientos de categorías, tablas de cientos
  de filas, caracteres fuera de cp1252, redacción, topología, HTML seguro);
- de integración con PostgreSQL real: generación de todos los tipos con v2, versión guardada,
  etiqueta personalizada, trazabilidad del riesgo y re-render de un snapshot v1.

Los valores de referencia de v1 (hashes) se obtuvieron con el código de reporting anterior a
la Fase 6D.5: si cambian, la salida v1 ha cambiado y eso no está permitido.
"""

import copy
import hashlib
import json
import random
import re
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings
from app.models.exposure import AssetPort, PortStateValue
from app.models.report import Report
from app.models.risk import AssetRisk, RiskLevel, RiskSnapshot
from app.reports import builders_v2
from app.reports.charset import encode_winansi, marker, to_winansi
from app.reports.document import (
    BarChart,
    Diagram,
    Document,
    DocumentV2,
    LineChart,
    LineSeries,
    SectionV2,
    StackedBarChart,
    Table,
)
from app.reports.render_html import render_html
from app.reports.render_pdf import encode as encode_v1
from app.reports.render_pdf import render_pdf
from app.reports.templates import render_document
from app.reports.templates_v2 import (
    _counts_chart,
    criticality_blocks,
    exposure_blocks,
    layout_topology,
    risk_history_chart,
    severity_status_chart,
    topology_blocks,
    trace_blocks,
    trend_chart,
)
from tests.test_reports import (
    API,
    R,
    _all_requests,
    _check_html,
    _check_pdf,
    _create,
    _download,
    _generate,
    _ok,
    _pdf_streams,
    _seed,
    _worker,
)
from tests.test_risk import _detection, _discovered

GENERATED = "2026-10-01T10:00:05Z"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


# --- Utilidades -----------------------------------------------------------------------------


def _pdf_pages_text(data: bytes) -> list[str]:
    """Texto de cada página del PDF (cadenas hexadecimales de los operadores Tj)."""
    pages = []
    for stream in _pdf_streams(data):
        if b" Tj" not in stream:
            continue
        chunks = re.findall(rb"<([0-9a-f]*)> Tj", stream)
        pages.append("\n".join(bytes.fromhex(c.decode()).decode("cp1252") for c in chunks))
    return pages


def _pdf_raw_strings(data: bytes) -> list[bytes]:
    return [
        bytes.fromhex(c.decode())
        for stream in _pdf_streams(data)
        for c in re.findall(rb"<([0-9a-f]*)> Tj", stream)
    ]


def _doc(*sections: SectionV2, title: str = "Informe de prueba") -> DocumentV2:
    return DocumentV2(
        title=title,
        report_name="Informe técnico de seguridad",
        report_id="00000000-0000-4000-8000-0000000000aa",
        generated_at="2026-10-01 10:00:05 UTC",
        cutoff_at="2026-10-01 10:00:04 UTC",
        classification="CONFIDENTIAL",
        cover=(("ID del informe", "00000000-0000-4000-8000-0000000000aa"), ("Plantilla", "v2")),
        sections=sections,
    )


def _render_both(document: DocumentV2, hostile: bool = False) -> tuple[str, bytes]:
    html = render_html(document)
    pdf = render_pdf(document, GENERATED)
    if not hostile:
        # La comprobación v1 busca subcadenas en todo el documento; con texto hostil
        # (escapado, pero presente como texto) se usa solo la comprobación por etiquetas.
        _check_html(html)
    _check_html_v2(html.decode("utf-8"))
    _check_pdf(pdf)
    return html.decode("utf-8"), pdf


def _check_html_v2(text: str) -> None:
    lowered = text.lower()
    assert "<script" not in lowered
    assert "url(" not in lowered and "@import" not in lowered
    assert "http://" not in lowered and "https://" not in lowered
    assert "Content-Security-Policy" in text and "default-src 'none'" in text
    for tag in re.findall(r"<[^>]*>", text):
        # Ninguna etiqueta lleva manejadores on*, src ni enlaces que no sean anclas internas.
        assert re.search(r"\son[a-z]+\s*=", tag.lower()) is None, tag
        assert re.search(r"\ssrc\s*=", tag.lower()) is None, tag
        for href in re.findall(r'href="([^"]*)"', tag):
            assert href.startswith("#s-"), href


# --- Snapshots v1 sintéticos (referencia de compatibilidad) --------------------------------

V1_META = {
    "report_id": "00000000-0000-4000-8000-000000000001",
    "report_name": "Informe de riesgo",
    "report_type": "risk",
    "title": "Informe de riesgo → «prod» ≥ ☃",
    "template_version": 1,
    "requested_by": "admin",
    "requested_at": "2026-10-01T10:00:00Z",
    "generated_at": "2026-10-01T10:00:05Z",
    "cutoff_at": "2026-10-01T10:00:04Z",
    "time_from": "2026-09-01T10:00:00Z",
    "time_to": "2026-10-01T10:00:04Z",
    "timezone": "UTC",
    "classification": "confidential",
    "format": "pdf",
    "filters": {"risk_levels": ["critical", "high"]},
    "scope": {},
}


def v1_risk_snapshot() -> dict[str, Any]:
    rows = [
        {
            "asset_id": f"00000000-0000-4000-8000-{i:012d}",
            "asset": f"SRV-{i:03d} ✓ Łódź",
            "at": "2026-09-15T08:00:00Z",
            "previous_level": "high",
            "level": "critical",
            "previous_score": 60 + i % 10,
            "score": 80 + i % 10,
            "transition": "up",
            "reason": "level_change",
            "top_factor": "DEF-001 · Fuerza bruta",
        }
        for i in range(60)
    ]
    return {
        "meta": dict(V1_META),
        "summary": [
            "2 activos presentan nivel de riesgo crítico.",
            "Ningún activo presenta nivel de riesgo alto.",
        ],
        "data": {
            "assets_in_scope": 3,
            "by_level": {"critical": 2, "high": 0, "medium": 1, "low": 0, "informational": 0},
            "unscored": None,
            "top_assets": [
                {
                    "asset_id": "00000000-0000-4000-8000-000000000001",
                    "asset": "SRV-001",
                    "score": 91,
                    "level": "critical",
                    "confidence": "high",
                    "top_factor": "DEF-001 · Fuerza bruta",
                    "formula_version": 2,
                    "calculated_at": "2026-09-30T10:00:00Z",
                    "contributions": [
                        {
                            "category": "authentication",
                            "label": "DEF-001 · Fuerza bruta",
                            "points": 40.5,
                            "rule_id": "DEF-001",
                        },
                        {
                            "category": "context",
                            "label": "Criticidad",
                            "points": 10,
                            "rule_id": None,
                        },
                    ],
                }
            ],
            "transitions": {"up": 60, "down": 0},
            "changes": {"total": 75, "truncated": True, "rows": rows},
            "evolution": [
                {
                    "bucket": "2026-09-01T00:00:00Z",
                    "avg_score": 50.5,
                    "max_score": 70,
                    "samples": 4,
                },
                {
                    "bucket": "2026-09-02T00:00:00Z",
                    "avg_score": 55.0,
                    "max_score": 91,
                    "samples": 2,
                },
            ],
            "trend_unit": "day",
        },
        "tables": {"changes": {"total": 75, "truncated": True, "rows": rows}},
    }


def v1_response_snapshot() -> dict[str, Any]:
    meta = dict(
        V1_META,
        report_type="response_activity",
        report_name="Informe de actividad de Response",
        title="Actividad de Response",
        classification="internal",
        filters={},
    )
    executions = [
        {
            "id": f"00000000-0000-4000-9000-{i:012d}",
            "created_at": "2026-09-10T10:00:00Z",
            "action": "isolate_host",
            "risk_level": "high",
            "status": "failed" if i % 3 == 0 else "succeeded",
            "target": f"PC-{i:02d} <script>alert(1)</script>",
            "actor": "ana",
            "playbook": None,
            "incident": None,
            "confirmed": True,
            "result_summary": "ok " * 40,
            "error_code": None,
            "error_message": None,
            "duration_seconds": 12.5,
        }
        for i in range(25)
    ]
    return {
        "meta": meta,
        "summary": ["25 ejecuciones de Response en el período; 9 terminaron en fallo o timeout."],
        "data": {
            "total": 25,
            "failed": 9,
            "by_status": {"failed": 9, "succeeded": 16},
            "by_action": {"isolate_host": 25},
        },
        "tables": {
            "executions": {"total": 25, "truncated": False, "rows": executions},
            "playbook_runs": {"total": 0, "truncated": False, "rows": []},
        },
    }


# HTML: bytes exactos. PDF: contenido de las páginas descomprimido (el byte a byte del PDF
# depende de la versión de zlib de cada plataforma; el contenido no).
V1_GOLDEN = {
    "risk": (
        "6fbdd0ad99a90ec85da3f9a2fa5c50b6ddf1115f54ac290d6e3502f59e078792",
        "5ec7dd4c8284f4a3c1ec2af73f4fbf893253cc4c0e001d512daf83a25455d19c",
    ),
    "response_activity": (
        "c177f6c74b5a83ea13e5b9c9aa5b6a8be5d359b5a9e1df6423e4feb8460f5337",
        "d6dab39464a77c4ceeed0e251c159fb0ad05241f265512cff6aad4fdbe042345",
    ),
}


@pytest.mark.parametrize("factory", [v1_risk_snapshot, v1_response_snapshot])
def test_v1_output_is_unchanged(factory: Any) -> None:
    snapshot = factory()
    document = render_document(snapshot)
    assert isinstance(document, Document) and not isinstance(document, DocumentV2)
    html = render_html(document)
    pdf = render_pdf(document, snapshot["meta"]["generated_at"])
    streams = [
        zlib.decompress(m.group(1))
        for m in re.finditer(rb"stream\n(.*?)\nendstream", pdf, re.DOTALL)
    ]
    html_sha, pdf_sha = V1_GOLDEN[snapshot["meta"]["report_type"]]
    assert hashlib.sha256(html).hexdigest() == html_sha
    assert hashlib.sha256(b"\n--\n".join(streams)).hexdigest() == pdf_sha
    # v1 conserva su comportamiento con los caracteres fuera de cp1252 ("?").
    assert encode_v1("☃") == b"?"
    assert render_pdf(document, snapshot["meta"]["generated_at"]) == pdf


def _as_v2(snapshot: dict[str, Any]) -> dict[str, Any]:
    data = copy.deepcopy(snapshot)
    data["meta"]["template_version"] = 2
    return data


def _shuffled(value: Any, rng: random.Random) -> Any:
    """Misma estructura con las claves de los dicts en otro orden (como al leer de JSONB)."""
    if isinstance(value, dict):
        keys = list(value)
        rng.shuffle(keys)
        return {k: _shuffled(value[k], rng) for k in keys}
    if isinstance(value, list):
        return [_shuffled(v, rng) for v in value]
    return value


@pytest.mark.parametrize("factory", [v1_risk_snapshot, v1_response_snapshot])
def test_v2_is_deterministic_and_independent_of_key_order(factory: Any) -> None:
    snapshot = _as_v2(factory())
    document = render_document(snapshot)
    assert isinstance(document, DocumentV2)
    pdf = render_pdf(document, GENERATED)
    html = render_html(document)
    again = render_document(json.loads(json.dumps(_shuffled(snapshot, random.Random(7)))))  # noqa: S311
    assert render_pdf(again, GENERATED) == pdf
    assert render_html(again) == html
    assert hashlib.sha256(render_pdf(render_document(snapshot), GENERATED)).hexdigest() == (
        hashlib.sha256(pdf).hexdigest()
    )
    _check_pdf(pdf)
    _check_html(html)
    _check_html_v2(html.decode())


def test_v2_pdf_structure_pagination_and_page_numbers() -> None:
    snapshot = _as_v2(v1_risk_snapshot())
    pdf = render_pdf(render_document(snapshot), GENERATED)
    _check_pdf(pdf)
    assert pdf.count(b"/Type /Page ") == len(_pdf_pages_text(pdf))
    for font in re.findall(rb"/BaseFont /([A-Za-z-]+)", pdf):
        assert font in (b"Helvetica", b"Helvetica-Bold", b"Helvetica-Oblique")
    assert b"/FontFile" not in pdf and b"/Image" not in pdf and b"/Annots" not in pdf
    pages = _pdf_pages_text(pdf)
    total = len(pages)
    for number, text in enumerate(pages, start=1):
        assert f"Página {number} de {total}" in text
        assert "Datos a fecha de 2026-10-01 10:00:04 UTC" in text
    # Portada con identidad SENTRA, índice con número de página y secciones v2.
    assert "SENTRA" in pages[0] and "Plantilla" in pages[0] and "v2" in pages[0]
    assert "Contenido" in pages[1]
    joined = "\n".join(pages)
    for title in (
        "Resumen ejecutivo",
        "Hallazgos prioritarios",
        "Metodología y alcance",
        "Análisis gráfico",
        "Evidencias y referencias",
        "Recomendaciones",
        "Conclusiones",
        "Anexo técnico",
    ):
        assert title in joined
    # El índice apunta a la página real de cada sección.
    toc = dict(re.findall(r"(\d+\. [^\n]+)\n(\d+)", pages[1]))
    for heading, page in toc.items():
        assert heading in pages[int(page) - 1], (heading, page)


# --- Caracteres fuera de cp1252 ------------------------------------------------------------


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("a → b", "a -> b"),
        ("x ≥ 3 y ≤ 5, ≠ 0", "x >= 3 y <= 5, != 0"),
        ("✓ hecho ✗ fallo", "[OK] hecho [X] fallo"),
        ("Łódź", "Lódz"),
        ("Ștefan ā", "Stefan a"),
        ("x⁴ y²", "x^4 y²"),
        ("a b​c", "a bc"),
        ("‐‑−", "---"),
        ("〈tag〉", "<tag>"),
        ("«ñandú» – “ok” … € •", "«ñandú» – “ok” … € •"),
        ("muñeco ☃", "muñeco [U+2603]"),
        ("emoji 😀️", "emoji [U+1F600]"),
        ("é", "é"),
        ("ctl\x07", "ctl[U+0007]"),
    ],
)
def test_transliteration(text: str, expected: str) -> None:
    assert to_winansi(text) == expected
    assert b"?" not in encode_winansi(text)


def test_marker_format_is_stable() -> None:
    assert marker("☃") == "[U+2603]"
    assert marker("😀") == "[U+1F600]"


def test_pdf_v2_has_no_replacement_question_marks() -> None:
    hostile = "Servidor → «prod» ≥ 5 ✓ ☃ 😀 Łódź ≠ x⁴  fin"
    document = _doc(
        SectionV2(
            "Caracteres",
            (
                Table(("Nombre", "Valor"), ((hostile, "1"),)),
                BarChart("Etiquetas ☃", ((hostile, 3.0),), unit="recuento"),
            ),
        ),
        title=hostile,
    )
    html, pdf = _render_both(document)
    for raw in _pdf_raw_strings(pdf):
        assert b"?" not in raw, raw
    text = "\n".join(_pdf_pages_text(pdf))
    assert "Servidor -> «prod» >= 5 [OK] [U+2603] [U+1F600] Lódz != x^4" in text
    # El HTML conserva el Unicode completo.
    assert hostile in html.replace("&#x27;", "'")


# --- Gráficas: casos límite -----------------------------------------------------------------


def test_charts_empty_single_huge_and_many_categories() -> None:
    many = {f"cat{i:03d}": i for i in range(300)}
    blocks = (
        BarChart("Vacía", (), unit="detecciones"),
        BarChart("Un valor", (("Único", 1.0),), unit="detecciones"),
        BarChart(
            "Enormes",
            (("a", 1e15), ("b", 3.5e12), ("c", float("inf")), ("d", float("nan")), ("e", -5.0)),
            unit="puntos",
        ),
        _counts_chart("Cientos", many, unit="activos"),
        StackedBarChart("Apilada vacía", ("A", "B"), (), ("#1f4e79", "#d9480f")),
        StackedBarChart(
            "Apilada", ("A", "B"), (("x", (1e9, 2.0)), ("y", (0.0, 0.0))), ("#1f4e79", "#d9480f")
        ),
        LineChart("Línea vacía", (), (), unit="score"),
        LineChart(
            "Un punto",
            (LineSeries("s", ((0.5, 42.0),), "#1f4e79"),),
            ((0.0, "2026-09-01"), (1.0, "2026-10-01")),
            unit="score",
            y_max=100.0,
        ),
    )
    html, pdf = _render_both(_doc(SectionV2("Gráficas", blocks)))
    _check_html_v2(html)
    text = "\n".join(_pdf_pages_text(pdf))
    assert "Sin datos en el periodo." in text and "Sin datos en el periodo." in html
    assert "Y 285 categorías más no dibujadas" in text
    assert "Y 285 categorías más no dibujadas" in html
    assert "1 000.0 B" in text  # 1e15 en formato compacto, sin desbordar
    assert "nan" not in html.lower() and "inf" not in re.sub(r"informe|info", "", html.lower())
    chart = _counts_chart("Cientos", many, unit="activos")
    assert len(chart.items) == 15 and chart.more == 285
    assert chart.items[0] == ("cat299", 299.0)
    # Determinista.
    assert render_pdf(_doc(SectionV2("Gráficas", blocks)), GENERATED) == pdf


def test_table_with_hundreds_of_rows_repeats_header_and_never_splits_rows() -> None:
    rows = tuple(
        (f"ROW-{i:04d}", f"valor {i} " + "texto largo " * (i % 7), str(i)) for i in range(400)
    )
    document = _doc(SectionV2("Tabla", (Table(("Clave", "Descripción", "Número"), rows),)))
    _, pdf = _render_both(document)
    pages = _pdf_pages_text(pdf)
    table_pages = [p for p in pages if "ROW-" in p]
    assert len(table_pages) > 5
    for index, page in enumerate(table_pages):
        assert "Clave" in page and "Descripción" in page and "Número" in page
        if index > 0:
            assert "(continuación)" in page
    for i in range(400):
        key = f"ROW-{i:04d}"
        holders = [n for n, p in enumerate(pages) if re.search(rf"^{key}$", p, re.M)]
        assert len(holders) == 1, key
        # La fila entera (todas sus celdas) está en la misma página.
        assert re.search(rf"^valor {i}( |$)", pages[holders[0]], re.M), key


# --- Distinción ausente / no medido / desconocido / cero -------------------------------------


def _activity(events: list[int] | None, detections: list[int]) -> dict[str, Any]:
    start = datetime(2026, 9, 1, tzinfo=UTC)

    def series(values: list[int]) -> list[dict[str, Any]]:
        return [
            {"bucket": (start + timedelta(days=i)).isoformat().replace("+00:00", "Z"), "count": v}
            for i, v in enumerate(values)
        ]

    return {
        "unit": "day",
        "start": "2026-09-01T00:00:00Z",
        "end": "2026-09-05T00:00:00Z",
        "detections": series(detections),
        "events": series(events) if events is not None else None,
        "agents_in_scope": 0 if events is None else 1,
    }


def test_absent_not_measured_unknown_and_zero_are_distinct() -> None:
    not_measured = trend_chart(_activity(None, [0, 1, 0, 0, 2]), "Tendencia")
    zeros = trend_chart(_activity([0, 0, 0, 0, 0], [0, 0, 0, 0, 0]), "Tendencia")
    assert isinstance(not_measured, LineChart) and isinstance(zeros, LineChart)
    assert [label for label, _ in not_measured.missing] == ["Eventos del sistema"]
    assert "No medido" in not_measured.missing[0][1]
    assert not zeros.missing and zeros.note and "medido y cero" in zeros.note
    criticality = criticality_blocks(
        {
            "order": ["critical", "high", "medium", "low"],
            "by_criticality": {
                "critical": {"critical": 2, "unscored": 0},
                "high": {"unscored": 3},
                "medium": {},
                "low": {},
            },
            "scores": {
                "critical": {"avg_score": 88.5, "max_score": 95, "scored": 2},
                "high": None,
                "medium": None,
                "low": None,
            },
        }
    )
    unscanned = exposure_blocks({"assets_in_scope": 4, "assets_scanned": 0})
    scanned_zero = exposure_blocks(
        {"assets_in_scope": 4, "assets_scanned": 4, "top_ports": [], "distinct_ports": 0}
    )
    matrix = severity_status_chart({"critical": {"open": 0, "acknowledged": 0, "resolved": 0}})
    unknown = _counts_chart("Estado", {"unknown": 2, "online": 0}, {"online": "En línea"})
    html, pdf = _render_both(
        _doc(
            SectionV2(
                "Estados",
                (
                    not_measured,
                    zeros,
                    *criticality,
                    *unscanned,
                    *scanned_zero,
                    matrix,
                    unknown,
                    BarChart("Sin nada", (), unit="activos"),
                ),
            )
        )
    )
    text = "\n".join(_pdf_pages_text(pdf))
    for expected in (
        "No medido: ningún activo del alcance tiene agente",
        "Todas las series medidas valen 0",
        "Sin calcular",
        "Sin activos",
        "88.5",
        "No medido: ningún activo del alcance tiene escaneo de puertos registrado.",
        "0 puertos abiertos en los activos escaneados (medido y cero).",
        "Ninguna detección en el periodo: todas las celdas valen 0.",
        "Sin datos en el periodo.",
    ):
        assert expected in text, expected
        assert expected in html, expected


# --- Topología --------------------------------------------------------------------------------


def _topology(links: list[dict[str, Any]], label: str = "core") -> list[dict[str, Any]]:
    nodes = [
        {"id": "n:router", "label": label, "device_type": "router", "role": "infrastructure"},
        {"id": "n:switch", "label": "sw-1", "device_type": "switch", "role": "infrastructure"},
        {"id": "n:pc1", "label": "pc-1", "device_type": "workstation", "role": "endpoint"},
        {"id": "n:pc2", "label": "pc-2", "device_type": "workstation", "role": "endpoint"},
        {"id": "n:lonely", "label": "isla", "device_type": "server", "role": "endpoint"},
    ]
    return [{"status": "ok", "site": "Sede", "nodes": nodes, "links": links, "truncated": False}]


_LINKS = [
    {"source": "n:router", "target": "n:switch", "kind": "physical", "relation": "lldp"},
    {"source": "n:switch", "target": "n:pc1", "kind": "observed", "relation": "mac"},
    {"source": "n:switch", "target": "n:pc2", "kind": "logical", "relation": "gateway"},
    {"source": "n:pc2", "target": "n:lonely", "kind": "candidate", "relation": "mac"},
]


def test_topology_diagram_is_deterministic_and_only_draws_verified_links() -> None:
    blocks = topology_blocks(_topology(_LINKS))
    diagram = next(b for b in blocks if isinstance(b, Diagram))
    assert {(e.source, e.target, e.kind) for e in diagram.edges} == {
        ("n:router", "n:switch", "physical"),
        ("n:switch", "n:pc1", "observed"),
        ("n:switch", "n:pc2", "logical"),
    }
    keys = {n.key for n in diagram.nodes}
    assert "n:lonely" not in keys  # solo tenía un enlace candidato
    router = next(n for n in diagram.nodes if n.key == "n:router")
    assert router.y == 0.0  # el router es la raíz de la disposición por capas
    # Mismo resultado con la entrada en otro orden.
    shuffled = _topology(list(reversed(_LINKS)))
    shuffled[0]["nodes"].reverse()
    again = next(b for b in topology_blocks(shuffled) if isinstance(b, Diagram))
    assert sorted(again.nodes, key=lambda n: n.key) == sorted(diagram.nodes, key=lambda n: n.key)
    assert diagram.note and "1 nodo sin relaciones verificadas" in diagram.note
    html, _pdf = _render_both(_doc(SectionV2("Topología", tuple(blocks))))
    assert "Física (LLDP/CDP)" in html


def test_topology_without_verified_links_says_so_explicitly() -> None:
    candidate_only = [{"source": "n:pc1", "target": "n:pc2", "kind": "candidate"}]
    blocks = topology_blocks(_topology(candidate_only))
    assert not any(isinstance(b, Diagram) for b in blocks)
    _, pdf = _render_both(_doc(SectionV2("Topología", tuple(blocks))))
    assert "No hay relaciones verificadas" in "\n".join(_pdf_pages_text(pdf))
    unavailable = topology_blocks([{"status": "unavailable", "site_id": None}])
    assert "Topología no disponible" in str(unavailable)
    failed = topology_blocks([{"status": "error", "site": "Sede"}])
    assert "No se pudo obtener la topología" in str(failed)
    assert "Sin activos en el alcance" in str(topology_blocks([]))
    nodes, edges, rows, isolated = layout_topology([], [])
    assert nodes == () and edges == () and rows == 0 and isolated == 0


def test_redaction_applies_to_chart_labels_and_topology() -> None:
    secret = "hunter2-very-secret"
    blocks = [
        *topology_blocks(_topology(_LINKS, label=f"router password={secret}")),
        _counts_chart("Reglas", {f"token={secret}": 3}),
        risk_history_chart(
            {
                "start": "2026-09-01T00:00:00Z",
                "end": "2026-10-01T00:00:00Z",
                "series": [{"asset": f"api_key: {secret}", "baseline": 10, "points": []}],
            }
        ),
    ]
    html, pdf = _render_both(_doc(SectionV2("Redacción", tuple(blocks))))
    assert secret not in html
    assert secret.encode() not in b"".join(_pdf_raw_strings(pdf))
    assert "[redacted]" in html
    # También en el builder (antes de entrar en el snapshot).
    clean = builders_v2._clean_topology(
        {"nodes": [{"id": "a", "label": f"Bearer {secret}xyz"}, {"id": "b"}], "links": []}
    )
    assert secret not in json.dumps(clean)


def test_hostile_text_in_v2_html_is_escaped() -> None:
    hostile = '<script>alert(1)</script><img src=x onerror=alert(2)>"onload="x'
    blocks = (
        _counts_chart("Hostil", {hostile: 2}),
        *topology_blocks(_topology(_LINKS, label=hostile)),
        Table(("A",), ((hostile,),)),
    )
    html, _ = _render_both(_doc(SectionV2(hostile, blocks), title=hostile), hostile=True)
    assert "&lt;script&gt;" in html


# --- Trazabilidad del riesgo -------------------------------------------------------------------


def test_risk_trace_is_shown_only_when_present() -> None:
    assert trace_blocks([]) == []
    assert trace_blocks(None) == []
    blocks = trace_blocks(
        [
            {
                "asset": "SRV-01",
                "score": 87,
                "trace": {
                    "base_points": 70.5,
                    "criticality_factor": 1.3,
                    "type_factor": 1.0,
                    "context_factor": 1.1,
                    "raw_points": 100.8,
                    "saturation_knee": 80,
                    "saturated_points": 87.2,
                    "score": 87,
                    "formula_version": 3,
                },
                "chain": [
                    {
                        "label": "DEF-001 · Fuerza bruta",
                        "points": 30.1,
                        "severity_points": 40,
                        "confidence_factor": 0.9,
                        "occurrence_factor": 1.2,
                        "correlation_factor": 1.0,
                        "recency_factor": 0.95,
                        "status_factor": 1.0,
                        "position_factor": 1.0,
                    }
                ],
            }
        ]
    )
    html, _ = _render_both(_doc(SectionV2("Riesgo", tuple(blocks))))
    assert "base 70.5 pts × criticidad 1.3 × tipo 1 × contexto 1.1 = bruto 100.8 pts" in html
    assert "saturación (rodilla 80) → 87.2 pts; score 87 (fórmula v3)" in html
    assert "× Confianza" in html and "0.95" in html
    # El builder copia solo números de las claves conocidas y omite cálculos antiguos.
    assert builders_v2._trace({"base_points": 1}) is None
    assert builders_v2._trace({"trace": {"score": 5, "evil": "x"}}) == {"score": 5.0}
    assert builders_v2._chain([{"factor": "detection", "details": {}}]) == []


# --- Integración con PostgreSQL ----------------------------------------------------------------


def test_all_types_generate_v2_with_label_and_extended_data(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = _seed(db)
    asset = seed["asset"]
    asset.custom_label = "Etiqueta Manual → Ficheros"
    db.add(
        AssetPort(
            asset_id=asset.id,
            protocol="tcp",
            port=443,
            state=PortStateValue.OPEN,
            service_hint="https",
            first_seen_at=datetime.now(UTC) - timedelta(days=2),
            opened_at=datetime.now(UTC) - timedelta(days=2),
            last_seen_at=datetime.now(UTC),
        )
    )
    now = datetime.now(UTC)
    db.add(
        AssetRisk(
            asset_id=asset.id,
            score=87,
            level=RiskLevel.CRITICAL,
            calculated_at=now - timedelta(minutes=1),
            contributions=[
                {
                    "factor": "detection",
                    "category": "authentication",
                    "label": "DEF-001 · Detección",
                    "points": 30.1,
                    "nominal_points": 40.0,
                    "rule_id": "DEF-001",
                    "details": {
                        "recency_factor": 0.95,
                        "status_factor": 1.0,
                        "position_factor": 1.0,
                        "occurrence_count": 1,
                        "nominal_breakdown": {
                            "severity_points": 40,
                            "confidence_factor": 0.9,
                            "occurrence_factor": 1.0,
                            "correlation_factor": 1.0,
                        },
                    },
                }
            ],
            breakdown={
                "trace": {
                    "base_points": 30.1,
                    "criticality_factor": 1.0,
                    "type_factor": 1.0,
                    "context_factor": 1.0,
                    "raw_points": 30.1,
                    "saturation_knee": 80,
                    "saturated_points": 30.1,
                    "score": 87,
                    "formula_version": 3,
                }
            },
        )
    )
    for days, score in ((10, 40), (3, 87)):
        db.add(
            RiskSnapshot(
                asset_id=asset.id,
                calculated_at=now - timedelta(days=days),
                score=score,
                level=RiskLevel.CRITICAL if score > 80 else RiskLevel.MEDIUM,
                confidence="high",
                reason="material_change",
                formula_version=3,
            )
        )
    db.commit()
    incident = _ok(
        client.post(
            f"{API}/incidents",
            json={
                "title": "Fuerza bruta",
                "severity": "high",
                "priority": "high",
                "asset_ids": [str(asset.public_id)],
            },
        ),
        201,
    )
    monkeypatch.setattr(get_settings(), "report_max_concurrent", 50)
    monkeypatch.setattr(get_settings(), "report_max_queued_total", 50)
    created = []
    seen: set[tuple[str, str]] = set()
    for rtype, fmt, filters in _all_requests(seed, incident["incident_id"]):
        if fmt in ("csv", "evidence") or (rtype, fmt) in seen:
            continue
        seen.add((rtype, fmt))
        created.append((rtype, fmt, _create(client, rtype, fmt, filters=filters)["id"]))
    worker = _worker(engine)
    while worker.run_once(max_jobs=50)["generated"]:
        pass
    for rtype, fmt, report_id in created:
        report = _ok(client.get(f"{R}/{report_id}"))
        assert report["status"] == "succeeded", (rtype, fmt, report)
        assert report["template_version"] == 2
        stored = db.scalar(select(Report).where(Report.public_id == UUID(report_id)))
        assert stored is not None and stored.snapshot is not None
        assert stored.template_version == 2
        assert stored.snapshot["meta"]["template_version"] == 2
        assert "extended" in stored.snapshot
        data = _download(client, report_id)
        if fmt == "html":
            text = data.decode()
            _check_html_v2(text)
            assert "SENTRA" in text and "Análisis gráfico" in text
        else:
            _check_pdf(data)
            text = "\n".join(_pdf_pages_text(data))
            for raw in _pdf_raw_strings(data):
                assert b"?" not in raw, (rtype, raw)
        # Mismo snapshot → mismos bytes (re-render desde el JSONB guardado).
        document = render_document(stored.snapshot)
        again = (
            render_html(document)
            if fmt == "html"
            else render_pdf(document, stored.snapshot["meta"]["generated_at"])
        )
        assert again == data, (rtype, fmt)
        if rtype in ("asset", "technical", "risk") and fmt == "html":
            # Etiqueta manual visible y cadena del cálculo del Risk Engine.
            assert "Etiqueta Manual → Ficheros" in text, rtype
            assert "Trazabilidad del cálculo de riesgo" in text, rtype
            assert "base 30.1 pts" in text, rtype
        if rtype == "asset" and fmt == "pdf":
            assert "Etiqueta Manual -> Ficheros" in text
        if rtype in ("technical", "asset"):
            assert isinstance(stored.snapshot["extended"]["topology"], list)
        if rtype == "executive_summary":
            # El resumen ejecutivo v2 sigue minimizando datos: ni IPs ni ids de activos.
            assert asset.primary_ip and asset.primary_ip not in text
            assert str(asset.public_id) not in text
            assert "Trazabilidad del cálculo de riesgo" not in text
        if rtype == "asset":
            ext = stored.snapshot["extended"]
            assert ext["exposure"]["assets_scanned"] == 1
            assert ext["exposure"]["top_ports"][0]["port"] == 443
            assert ext["risk_traces"][0]["chain"][0]["severity_points"] == 40.0


def test_v1_snapshot_stored_in_db_still_renders_with_v1(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _seed(db)
    report = _generate(client, engine, "detection", "html")
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    legacy = copy.deepcopy(stored.snapshot)
    legacy["meta"]["template_version"] = 1
    legacy.pop("extended")
    document = render_document(legacy)
    assert isinstance(document, Document) and not isinstance(document, DocumentV2)
    html = render_html(document).decode()
    assert "Plantilla" in html and "v1" in html and "Análisis gráfico" not in html


def test_risk_history_builder_reads_snapshots_with_baseline(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="SRV-HIST")
    _detection(db, asset)
    now = datetime.now(UTC)
    db.add(AssetRisk(asset_id=asset.id, score=50, level=RiskLevel.MEDIUM, calculated_at=now))
    for days, score in ((60, 20), (5, 50)):
        db.add(
            RiskSnapshot(
                asset_id=asset.id,
                calculated_at=now - timedelta(days=days),
                score=score,
                level=RiskLevel.MEDIUM,
                confidence="medium",
                reason="interval",
                formula_version=3,
            )
        )
    db.commit()
    report = _generate(client, engine, "risk", "pdf")
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    series = stored.snapshot["extended"]["risk_history"]["series"]
    mine = next(s for s in series if s["asset"] == "SRV-HIST")
    assert mine["baseline"] == 20  # último snapshot ANTERIOR al periodo (30 días)
    assert [p["score"] for p in mine["points"]] == [50]
