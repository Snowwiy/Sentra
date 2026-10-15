"""Reporting, exportación de evidencias e informes auditables (Fase 5E), con PostgreSQL real.

Datos sintéticos (activos, detecciones, incidentes y agentes de test). La generación se
dispara a mano con ReportWorker.run_once(): los jobs en segundo plano están apagados en los
tests (conftest), así cada test decide cuándo se genera y qué cambia entre medias.
"""

import csv
import hashlib
import io
import json
import re
import socket
import threading
import zipfile
import zlib
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, get_settings
from app.core.permissions import Permission, permissions_for
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.detection import DetectionEvidence, DetectionSeverity
from app.models.report import Report, ReportArtifact
from app.reports import summary as phrases
from app.reports.catalog import DEFINITIONS
from app.reports.exports import neutralize, render_csv
from app.reports.redaction import redact, redact_text
from app.reports.storage import ArtifactStorage, StorageError, new_key, validate_key
from app.services.report_service import ReportWorker
from tests.conftest import authenticate
from tests.test_risk import _detection, _discovered

API = "/api/v1"
R = f"{API}/reports"
SECRET = "sup3r-s3cret-value-123456"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _ok(response: Any, status: int = 200) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    return body


def _error(response: Any, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()["error"]
    assert body["code"] == code, body
    return body


def _as(client: TestClient, engine: Engine, role: str) -> TestClient:
    other = TestClient(client.app)
    authenticate(other, engine, role)
    return other


def _worker(engine: Engine, settings: Settings | None = None, **kw: Any) -> ReportWorker:
    return ReportWorker(engine, settings or get_settings(), **kw)


def _create(client: TestClient, report_type: str, fmt: str, **body: Any) -> dict[str, Any]:
    payload = {"report_type": report_type, "format": fmt, **body}
    return _ok(client.post(R, json=payload), 202)


def _generate(
    client: TestClient, engine: Engine, report_type: str, fmt: str, **body: Any
) -> dict[str, Any]:
    created = _create(client, report_type, fmt, **body)
    _worker(engine).run_once()
    report = _ok(client.get(f"{R}/{created['id']}"))
    assert report["status"] == "succeeded", report
    return report


def _download(client: TestClient, report_id: str) -> bytes:
    response = client.get(f"{R}/{report_id}/artifact")
    assert response.status_code == 200, response.text
    return response.content


def _audit(db: Session, action: str) -> list[AuditEvent]:
    db.expire_all()
    return list(
        db.scalars(select(AuditEvent).where(AuditEvent.action == action).order_by(AuditEvent.id))
    )


def _seed(db: Session) -> dict[str, Any]:
    """Un activo crítico con detección y evidencia (con un secreto que nunca debe salir)."""
    asset = _discovered(db, name="SRV-FICHEROS")
    detection = _detection(db, asset, severity=DetectionSeverity.CRITICAL)
    db.add(
        DetectionEvidence(
            detection_id=detection.id,
            signal_kind="logon_failure",
            role="trigger",
            source_type="event",
            source_id="4625",
            occurred_at=datetime.now(UTC) - timedelta(minutes=3),
            created_at=datetime.now(UTC),
            summary=f"Fallo de inicio de sesión password={SECRET}",
            data={"user": "ana", "password": SECRET, "api_token": SECRET, "ip": "10.0.0.9"},
        )
    )
    db.commit()
    return {"asset": asset, "detection": detection}


# --- A. Catálogo y RBAC ---------------------------------------------------------------------


def test_a_catalog_lists_closed_types_by_role(client: TestClient, engine: Engine) -> None:
    catalog = _ok(client.get(f"{R}/catalog"))
    ids = [item["id"] for item in catalog["items"]]
    assert ids == [d.id for d in DEFINITIONS]
    assert catalog["enabled"] is True
    assert catalog["classifications"] == ["internal", "confidential", "restricted"]
    assert all(item["can_generate"] for item in catalog["items"])
    viewer = _as(client, engine, "viewer")
    items = {i["id"]: i for i in _ok(viewer.get(f"{R}/catalog"))["items"]}
    # El viewer ve los tipos cuyos datos ya puede leer, pero no puede generar ninguno.
    assert "lifecycle_change" not in items
    assert items and not any(i["can_generate"] for i in items.values())
    analyst = _as(client, engine, "analyst")
    items = {i["id"]: i for i in _ok(analyst.get(f"{R}/catalog"))["items"]}
    assert items["executive_summary"]["can_generate"] is False
    assert items["incident"]["can_generate"] is True


def test_b_viewer_reads_but_cannot_generate_cancel_or_delete(
    client: TestClient, engine: Engine, db: Session
) -> None:
    report = _generate(client, engine, "risk", "html")
    viewer = _as(client, engine, "viewer")
    assert _ok(viewer.get(f"{R}/{report['id']}"))["status"] == "succeeded"
    assert _download(viewer, report["id"])
    for response in (
        viewer.post(R, json={"report_type": "risk", "format": "html"}),
        viewer.post(f"{R}/preview", json={"report_type": "risk", "format": "html"}),
        viewer.post(f"{R}/{report['id']}/cancel"),
        viewer.delete(f"{R}/{report['id']}"),
    ):
        _error(response, 403, "permission_denied")


def test_c_analyst_generates_technical_but_not_executive_or_global(
    client: TestClient, engine: Engine, db: Session
) -> None:
    seed = _seed(db)
    analyst = _as(client, engine, "analyst")
    _error(
        analyst.post(R, json={"report_type": "executive_summary", "format": "pdf"}),
        403,
        "permission_denied",
    )
    # Técnico global (sin activos ni incidentes concretos): solo admin.
    _error(
        analyst.post(R, json={"report_type": "technical", "format": "pdf"}),
        403,
        "permission_denied",
    )
    scoped = {"asset_ids": [str(seed["asset"].public_id)]}
    created = _create(analyst, "technical", "pdf", filters=scoped)
    assert created["status"] == "pending" and created["can_cancel"] is True
    assert created["can_delete"] is False
    _error(analyst.delete(f"{R}/{created['id']}"), 403, "permission_denied")


def test_d_report_of_a_type_the_role_cannot_read_is_404(client: TestClient, engine: Engine) -> None:
    report = _generate(client, engine, "lifecycle_change", "html")
    viewer = _as(client, engine, "viewer")
    # Sin assets:duplicates_read el viewer no ve informes de ciclo de vida: igual que
    # inexistente (sin IDOR), también en el historial.
    _error(viewer.get(f"{R}/{report['id']}"), 404, "not_found")
    _error(viewer.get(f"{R}/{report['id']}/artifact"), 404, "not_found")
    listed = _ok(viewer.get(R))
    assert report["id"] not in {r["id"] for r in listed["items"]}
    _error(client.get(f"{R}/{uuid4()}"), 404, "not_found")


# --- E. Validación --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("body", "code"),
    [
        ({"report_type": "nope", "format": "pdf"}, "report_type_unknown"),
        ({"report_type": "risk", "format": "csv"}, "report_format_unsupported"),
        ({"report_type": "risk", "format": "pdf", "filters": {"incident_ids": [str(uuid4())]}},
         "report_filter_not_supported"),
        ({"report_type": "incident", "format": "pdf"}, "report_filter_required"),
        ({"report_type": "risk", "format": "pdf", "filters": {"risk_levels": ["huge"]}},
         "report_filter_invalid"),
        ({"report_type": "risk", "format": "pdf", "range": {"preset": "custom"}},
         "report_range_invalid"),
        ({"report_type": "risk", "format": "pdf",
          "range": {"preset": "custom", "from": "2026-10-10T00:00:00Z",
                    "to": "2026-10-01T00:00:00Z"}}, "report_range_invalid"),
        ({"report_type": "risk", "format": "pdf",
          "range": {"preset": "custom", "from": "2020-01-01T00:00:00Z",
                    "to": "2026-01-01T00:00:00Z"}}, "report_range_too_large"),
        ({"report_type": "risk", "format": "pdf",
          "range": {"preset": "custom", "from": "2099-01-01T00:00:00Z",
                    "to": "2099-01-02T00:00:00Z"}}, "report_range_invalid"),
        ({"report_type": "asset", "format": "pdf", "filters": {"asset_ids": [str(uuid4())]}},
         "report_target_not_found"),
    ],
)  # fmt: skip
def test_e_validation_errors_are_explicit(
    client: TestClient, body: dict[str, Any], code: str
) -> None:
    _error(client.post(f"{R}/preview", json=body), 422, code)
    _error(client.post(R, json=body), 422, code)


def test_e_unknown_fields_and_paths_are_rejected(client: TestClient) -> None:
    for body in (
        {"report_type": "risk", "format": "pdf", "path": "../../etc/passwd"},
        {"report_type": "risk", "format": "pdf", "filters": {"query": "SELECT 1"}},
        {"report_type": "risk", "format": "pdf", "template": "<script>"},
    ):
        _error(client.post(R, json=body), 422, "validation_error")


def test_e_scope_limit_uses_report_max_assets(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "report_max_assets", 2)
    ids = [str(uuid4()) for _ in range(3)]
    body = {"report_type": "risk", "format": "pdf", "filters": {"asset_ids": ids}}
    _error(client.post(R, json=body), 422, "report_scope_too_large")


def test_e_archived_asset_needs_explicit_opt_in(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="VIEJO")
    db.execute(update(Asset).where(Asset.id == asset.id).values(archived_at=datetime.now(UTC)))
    db.commit()
    filters: dict[str, Any] = {"asset_ids": [str(asset.public_id)]}
    _error(
        client.post(R, json={"report_type": "asset", "format": "html", "filters": filters}),
        422,
        "report_asset_archived",
    )
    report = _generate(
        client, engine, "asset", "html", filters={**filters, "include_archived": True}
    )
    assert report["scope"]["assets"][0]["archived"] is True


def test_e_preview_has_no_side_effects(client: TestClient, db: Session) -> None:
    _seed(db)
    preview = _ok(client.post(f"{R}/preview", json={"report_type": "detection", "format": "csv"}))
    assert preview["scope"]["detections"] == 1
    assert preview["timezone"] == "UTC" and preview["sections"]
    assert db.scalar(select(Report.id).limit(1)) is None
    exec_preview = _ok(
        client.post(f"{R}/preview", json={"report_type": "executive_summary", "format": "pdf"})
    )
    assert "executive_minimized" in {w["code"] for w in exec_preview["warnings"]}


def test_e_disabled_reporting_answers_409(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(get_settings(), "report_enabled", False)
    _error(client.post(R, json={"report_type": "risk", "format": "pdf"}), 409, "reports_disabled")
    assert _ok(client.get(f"{R}/catalog"))["enabled"] is False


# --- F. Generación de todos los tipos y formatos -------------------------------------------


def _all_requests(seed: dict[str, Any], incident_id: str) -> list[tuple[str, str, dict[str, Any]]]:
    asset = {"asset_ids": [str(seed["asset"].public_id)]}
    out: list[tuple[str, str, dict[str, Any]]] = []
    for definition in DEFINITIONS:
        filters: dict[str, Any] = {}
        if definition.id == "incident":
            filters = {"incident_ids": [incident_id]}
        elif definition.id == "asset":
            filters = asset
        for fmt in definition.supported_formats:
            out.append((definition.id, fmt, filters))
    return out


def test_f_every_type_and_format_generates_offline(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    seed = _seed(db)
    incident = _ok(
        client.post(
            f"{API}/incidents",
            json={
                "title": "Fuerza bruta",
                "severity": "high",
                "priority": "high",
                "asset_ids": [str(seed["asset"].public_id)],
            },
        ),
        201,
    )
    requests = _all_requests(seed, incident["incident_id"])
    monkeypatch.setattr(get_settings(), "report_max_concurrent", 50)
    monkeypatch.setattr(get_settings(), "report_max_queued_total", 50)
    created = [
        (rtype, fmt, _create(client, rtype, fmt, filters=filters)["id"])
        for rtype, fmt, filters in requests
    ]

    # Sin red: cualquier intento de abrir un socket durante la generación hace fallar el test.
    real_connect = socket.socket.connect

    def guarded(sock: socket.socket, address: Any) -> Any:
        if sock.family in (socket.AF_INET, socket.AF_INET6):
            host = address[0]
            if host not in ("127.0.0.1", "::1", "localhost"):
                raise AssertionError(f"network access during report generation: {host}")
        return real_connect(sock, address)

    monkeypatch.setattr(socket.socket, "connect", guarded)
    worker = _worker(engine)
    while worker.run_once(max_jobs=50)["generated"]:
        pass
    monkeypatch.setattr(socket.socket, "connect", real_connect)

    for rtype, fmt, report_id in created:
        report = _ok(client.get(f"{R}/{report_id}"))
        assert report["status"] == "succeeded", (rtype, fmt, report)
        data = _download(client, report_id)
        assert hashlib.sha256(data).hexdigest() == report["artifact"]["sha256"]
        assert report["artifact"]["size_bytes"] == len(data)
        assert re.fullmatch(r"sentra-[a-z-]+-\d{8}-\d{6}-[0-9a-f]{8}\.(html|pdf|csv|zip)",
                            report["artifact"]["filename"])  # fmt: skip
        assert report["cutoff_at"] and report["snapshot_sha256"] and report["summary"]
        _check_format(fmt, data)
        # Ningún formato filtra el secreto de la evidencia.
        assert SECRET.encode() not in data, (rtype, fmt)
        if fmt == "evidence":
            with zipfile.ZipFile(io.BytesIO(data)) as bundle:
                for name in bundle.namelist():
                    assert SECRET.encode() not in bundle.read(name), (rtype, name)


def _check_format(fmt: str, data: bytes) -> None:
    if fmt == "html":
        _check_html(data)
    elif fmt == "pdf":
        _check_pdf(data)
    elif fmt == "csv":
        assert data.startswith("﻿".encode())
        assert next(csv.reader(io.StringIO(data.decode("utf-8-sig"))))
    else:
        _check_bundle(data)


def _check_html(data: bytes) -> None:
    text = data.decode("utf-8")
    assert text.startswith("<!DOCTYPE html>")
    assert "Content-Security-Policy" in text and "default-src 'none'" in text
    lowered = text.lower()
    assert "<script" not in lowered and "javascript:" not in lowered
    assert "http://" not in lowered and "https://" not in lowered
    assert " on" + "error=" not in lowered and " on" + "load=" not in lowered


def _pdf_streams(data: bytes) -> list[bytes]:
    out = []
    for match in re.finditer(rb"stream\r?\n(.*?)\r?\nendstream", data, re.DOTALL):
        try:
            out.append(zlib.decompress(match.group(1)))
        except zlib.error:
            out.append(match.group(1))
    return out


def _check_pdf(data: bytes) -> None:
    assert data.startswith(b"%PDF-1.") and data.rstrip().endswith(b"%%EOF")
    for forbidden in (
        b"/URI",
        b"/JavaScript",
        b"/JS",
        b"/Launch",
        b"/EmbeddedFile",
        b"/OpenAction",
    ):
        assert forbidden not in data
    # xref válida: cada desplazamiento apunta al comienzo de su objeto.
    startxref = int(re.findall(rb"startxref\s+(\d+)", data)[-1])
    assert data[startxref:].startswith(b"xref")
    lines = data[startxref:].split(b"\n")
    count = int(lines[1].split()[1])
    for number in range(1, count):
        offset = int(lines[2 + number].split()[0])
        assert data[offset:].startswith(f"{number} 0 obj".encode()), number
    assert b"/ID [" in data
    for stream in _pdf_streams(data):
        assert b"http" not in stream.lower()


def _check_bundle(data: bytes) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as bundle:
        names = bundle.namelist()
        assert names[0] == "manifest.json"
        assert {"report.html", "report.pdf", "snapshot.json"} <= set(names)
        for name in names:
            assert not name.startswith("/") and ".." not in name and "\\" not in name
            info = bundle.getinfo(name)
            assert (info.external_attr >> 16) == 0o100644
        manifest = json.loads(bundle.read("manifest.json"))
        assert manifest["format"] == "sentra-evidence-bundle/1"
        listed = {f["name"]: f for f in manifest["files"]}
        assert set(listed) == set(names) - {"manifest.json"}
        for name, entry in listed.items():
            content = bundle.read(name)
            assert hashlib.sha256(content).hexdigest() == entry["sha256"]
            assert len(content) == entry["size_bytes"]
        _check_html(bundle.read("report.html"))
        _check_pdf(bundle.read("report.pdf"))


# --- G. Snapshot, determinismo e inmutabilidad ---------------------------------------------


def test_g_snapshot_is_immutable_after_data_changes(
    client: TestClient, engine: Engine, db: Session
) -> None:
    seed = _seed(db)
    report = _generate(client, engine, "detection", "csv")
    first = _download(client, report["id"])
    assert seed["detection"].public_id.hex[:8] in first.decode("utf-8-sig").replace("-", "")
    # Los datos cambian después: el informe y su fichero no.
    _detection(db, seed["asset"], rule_id="DEF-002")
    assert _download(client, report["id"]) == first
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    assert len(stored.snapshot["tables"]["detections"]["rows"]) == 1
    # Uno nuevo sí ve la segunda detección.
    again = _generate(client, engine, "detection", "csv", classification="confidential")
    assert len(_download(client, again["id"]).decode("utf-8-sig").strip().splitlines()) == 3


def test_g_cutoff_excludes_data_created_after_it(
    client: TestClient, engine: Engine, db: Session
) -> None:
    seed = _seed(db)
    report = _generate(client, engine, "risk", "html")
    cutoff = datetime.fromisoformat(report["cutoff_at"])
    assert cutoff <= datetime.now(UTC)
    assert report["time_to"] is not None
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    meta = stored.snapshot["meta"]
    assert meta["cutoff_at"] and meta["template_version"] == 1 and meta["timezone"] == "UTC"
    assert seed["asset"]


def test_g_rendering_is_deterministic_from_the_snapshot(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from app.reports.exports import build_bundle
    from app.reports.render_html import render_html
    from app.reports.render_pdf import render_pdf
    from app.reports.templates import render_document

    _seed(db)
    report = _generate(client, engine, "technical", "pdf")
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    snapshot = stored.snapshot
    generated = snapshot["meta"]["generated_at"]
    document = render_document(snapshot)
    assert render_pdf(document, generated) == _download(client, report["id"])
    assert render_html(document) == render_html(render_document(snapshot))
    stamp = datetime.fromisoformat(snapshot["meta"]["cutoff_at"])
    html, pdf = render_html(document), render_pdf(document, generated)
    assert build_bundle(snapshot, html, pdf, ("assets",), stamp) == build_bundle(
        snapshot, html, pdf, ("assets",), stamp
    )


# --- H. Idempotencia, colas y concurrencia --------------------------------------------------


def test_h_idempotency_key_returns_the_same_report(client: TestClient) -> None:
    body = {"report_type": "risk", "format": "pdf", "idempotency_key": "abc12345-dialog"}
    first = _ok(client.post(R, json=body), 202)
    second = _ok(client.post(R, json=body), 202)
    assert second["id"] == first["id"] and second["deduplicated"] is True
    _error(
        client.post(R, json={**body, "format": "html"}),
        409,
        "report_conflict",
    )


def test_h_identical_live_request_is_deduplicated(client: TestClient) -> None:
    first = _create(client, "risk", "pdf")
    second = _create(client, "risk", "pdf")
    assert second["id"] == first["id"] and second["deduplicated"] is True
    other = _create(client, "risk", "html")
    assert other["id"] != first["id"]


def test_h_concurrent_double_click_creates_one_report(
    client: TestClient, engine: Engine, db: Session
) -> None:
    body = {"report_type": "risk", "format": "pdf", "idempotency_key": "double-click-1"}
    results: list[int] = []

    def post() -> None:
        results.append(client.post(R, json=body).status_code)

    threads = [threading.Thread(target=post) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [202] * 4
    db.expire_all()
    assert len(list(db.scalars(select(Report)))) == 1


def test_h_queue_limits(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(get_settings(), "report_max_concurrent", 2)
    _create(client, "risk", "pdf")
    _create(client, "risk", "html")
    response = client.post(R, json={"report_type": "detection", "format": "csv"})
    _error(response, 429, "report_queue_full")
    assert int(response.headers["Retry-After"]) >= 1
    monkeypatch.setattr(get_settings(), "report_max_concurrent", 10)
    monkeypatch.setattr(get_settings(), "report_max_queued_total", 2)
    _error(client.post(R, json={"report_type": "detection", "format": "csv"}), 429,
           "report_queue_full")  # fmt: skip


def test_h_two_workers_never_generate_the_same_report(
    client: TestClient, engine: Engine, db: Session
) -> None:
    for fmt in ("html", "pdf"):
        _create(client, "risk", fmt)
    counts: list[int] = []

    def run() -> None:
        counts.append(_worker(engine).run_once()["generated"])

    threads = [threading.Thread(target=run) for _ in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sum(counts) == 2
    db.expire_all()
    assert len(list(db.scalars(select(ReportArtifact)))) == 2
    assert {r.attempts for r in db.scalars(select(Report))} == {1}


# --- I. Cancelación, fallos, plazos y huérfanos ---------------------------------------------


def test_i_cancel_pending_and_running(client: TestClient, engine: Engine, db: Session) -> None:
    pending = _create(client, "risk", "pdf")
    cancelled = _ok(client.post(f"{R}/{pending['id']}/cancel"))
    assert cancelled["status"] == "cancelled" and cancelled["cancel_requested"] is True
    _error(client.post(f"{R}/{pending['id']}/cancel"), 409, "report_invalid_state")
    _error(client.get(f"{R}/{pending['id']}/artifact"), 409, "report_not_ready")

    running = _create(client, "risk", "html")
    worker = _worker(engine)
    report_id = worker._claim()
    assert report_id is not None
    assert _ok(client.post(f"{R}/{running['id']}/cancel"))["cancel_requested"] is True
    worker.generate(report_id)
    final = _ok(client.get(f"{R}/{running['id']}"))
    assert final["status"] == "cancelled" and final["artifact"] is None
    assert db.scalar(select(ReportArtifact.id).limit(1)) is None


def test_i_cancel_of_someone_elses_report_needs_admin(client: TestClient, engine: Engine) -> None:
    analyst = _as(client, engine, "analyst")
    created = _create(analyst, "risk", "pdf")
    other = _as(client, engine, "analyst")
    _error(other.post(f"{R}/{created['id']}/cancel"), 403, "permission_denied")
    assert _ok(client.post(f"{R}/{created['id']}/cancel"))["status"] == "cancelled"


def test_i_cancel_during_finalize_never_succeeds(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = _create(client, "risk", "pdf")
    worker = _worker(engine)
    report_id = worker._claim()
    assert report_id is not None
    original = worker.storage.write_atomic
    written: list[Path] = []

    def write_then_cancel(key: str, data: bytes) -> Path:
        path = original(key, data)
        written.append(path)
        # Llega la cancelación justo después de escribir el fichero y antes de finalizar.
        client.post(f"{R}/{created['id']}/cancel")
        return path

    monkeypatch.setattr(worker.storage, "write_atomic", write_then_cancel)
    worker.generate(report_id)
    final = _ok(client.get(f"{R}/{created['id']}"))
    assert final["status"] == "cancelled" and final["artifact"] is None
    # El fichero ya escrito se borra: no queda un artefacto huérfano en disco ni en la BD.
    assert len(written) == 1 and not written[0].exists()
    assert db.scalar(select(ReportArtifact.id).limit(1)) is None


def test_i_failure_is_recorded_without_partial_artifact(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.reports import builders

    def boom(ctx: Any) -> dict[str, Any]:
        raise RuntimeError(f"database exploded {SECRET}")

    monkeypatch.setitem(builders.BUILDERS, "risk", boom)
    created = _create(client, "risk", "pdf")
    _worker(engine).run_once()
    failed = _ok(client.get(f"{R}/{created['id']}"))
    assert failed["status"] == "failed" and failed["error_code"] == "report_generation_failed"
    # El mensaje es genérico: ni trazas ni datos internos llegan a la API o a la auditoría.
    assert SECRET not in json.dumps(failed)
    assert failed["artifact"] is None
    [event] = _audit(db, "report_failed")
    assert SECRET not in json.dumps(event.details) and event.result == "failure"


def test_i_timeout_marks_failed(
    client: TestClient, engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    ticks = iter([0.0, *[10_000.0] * 50])
    created = _create(client, "risk", "html")
    _worker(engine, clock=lambda: next(ticks)).run_once()
    report = _ok(client.get(f"{R}/{created['id']}"))
    assert report["status"] == "failed" and report["error_code"] == "report_timeout"


def test_i_stale_running_job_is_recovered(client: TestClient, engine: Engine, db: Session) -> None:
    created = _create(client, "risk", "html")
    worker = _worker(engine)
    report_id = worker._claim()
    assert report_id is not None
    # El proceso "murió": nadie renueva el lease.
    db.execute(
        update(Report)
        .where(Report.id == report_id)
        .values(lease_until=datetime.now(UTC) - timedelta(minutes=1))
    )
    db.commit()
    assert worker.recover_stale() == 1
    report = _ok(client.get(f"{R}/{created['id']}"))
    assert report["status"] == "failed" and report["error_code"] == "report_interrupted"
    # Un trabajo nuevo idéntico ya no está bloqueado por el muerto.
    assert _create(client, "risk", "html")["id"] != created["id"]


def test_i_artifact_size_limit(
    client: TestClient, engine: Engine, db: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    created = _create(client, "risk", "pdf")
    settings = get_settings().model_copy(update={"report_max_artifact_mb": 1})
    monkeypatch.setattr("app.services.report_service.render_pdf", lambda *a: b"x" * (2 << 20))
    _worker(engine, settings=settings).run_once()
    report = _ok(client.get(f"{R}/{created['id']}"))
    assert report["status"] == "failed" and report["error_code"] == "report_artifact_too_large"
    assert db.scalar(select(ReportArtifact.id).limit(1)) is None


def test_i_rows_are_truncated_to_report_max_rows(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db, name="RUIDOSO")
    for i in range(5):
        _detection(db, asset, rule_id=f"DEF-{i:03d}")
    settings = get_settings().model_copy(update={"report_max_rows": 2})
    created = _create(client, "detection", "csv")
    _worker(engine, settings=settings).run_once()
    stored = db.scalar(select(Report).where(Report.public_id == UUID(created["id"])))
    assert stored is not None and stored.snapshot is not None
    table = stored.snapshot["tables"]["detections"]
    assert table["total"] == 5 and len(table["rows"]) == 2 and table["truncated"] is True


# --- J. Descarga, integridad, borrado y retención ------------------------------------------


def test_j_download_headers_and_integrity(client: TestClient, engine: Engine, db: Session) -> None:
    report = _generate(client, engine, "risk", "html")
    response = client.get(f"{R}/{report['id']}/artifact")
    assert response.headers["content-type"].startswith("text/html")
    assert response.headers["x-sentra-sha256"] == report["artifact"]["sha256"]
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["content-security-policy"].startswith("sandbox")
    disposition = response.headers["content-disposition"]
    assert disposition == f'attachment; filename="{report["artifact"]["filename"]}"'
    assert _audit(db, "report_downloaded")

    # Alguien modifica el fichero en disco: no se entrega y queda en la auditoría.
    artifact = db.scalar(select(ReportArtifact))
    assert artifact is not None
    path = ArtifactStorage(get_settings().report_output_dir).path_for(artifact.storage_key)
    path.write_bytes(path.read_bytes() + b"<!-- tampered -->")
    _error(client.get(f"{R}/{report['id']}/artifact"), 409, "report_integrity_failed")
    assert _audit(db, "report_integrity_failed")
    path.unlink()
    _error(client.get(f"{R}/{report['id']}/artifact"), 410, "report_artifact_unavailable")


def test_j_delete_expires_and_removes_the_file(
    client: TestClient, engine: Engine, db: Session
) -> None:
    report = _generate(client, engine, "risk", "pdf")
    artifact = db.scalar(select(ReportArtifact))
    assert artifact is not None
    path = ArtifactStorage(get_settings().report_output_dir).path_for(artifact.storage_key)
    assert path.exists()
    deleted = _ok(client.delete(f"{R}/{report['id']}"))
    assert deleted["status"] == "expired" and deleted["artifact"] is None
    assert not path.exists()
    _error(client.get(f"{R}/{report['id']}/artifact"), 410, "report_artifact_unavailable")
    _error(client.delete(f"{R}/{report['id']}"), 409, "report_invalid_state")
    # La fila queda como rastro: metadata, resumen y checksum en la auditoría.
    assert _ok(client.get(f"{R}/{report['id']}"))["summary"]
    [event] = _audit(db, "report_deleted")
    assert event.details is not None and event.details["sha256"] == artifact.sha256
    pending = _create(client, "risk", "html")
    _error(client.delete(f"{R}/{pending['id']}"), 409, "report_invalid_state")


def test_j_retention_unset_keeps_everything_and_set_expires_old(
    client: TestClient, engine: Engine, db: Session
) -> None:
    report = _generate(client, engine, "risk", "html")
    db.execute(update(Report).values(finished_at=datetime.now(UTC) - timedelta(days=400)))
    db.commit()
    assert _worker(engine).purge_expired() == 0
    settings = get_settings().model_copy(update={"report_retention_days": 30})
    assert _worker(engine, settings=settings).purge_expired() == 1
    assert _ok(client.get(f"{R}/{report['id']}"))["status"] == "expired"
    [event] = _audit(db, "report_expired")
    assert event.details is not None and event.details["retention_days"] == 30


def test_j_list_filters_and_pagination(client: TestClient, engine: Engine) -> None:
    _generate(client, engine, "risk", "html")
    _create(client, "risk", "pdf")
    listed = _ok(client.get(R, params={"limit": 1}))
    assert listed["total"] == 2 and len(listed["items"]) == 1
    assert _ok(client.get(R, params={"status": "succeeded"}))["total"] == 1
    assert _ok(client.get(R, params={"report_type": "detection"}))["total"] == 0
    _error(client.get(R, params={"status": "bogus"}), 422, "validation_error")


# --- K. Auditoría sin secretos --------------------------------------------------------------


def test_k_audit_trail_has_no_secrets(client: TestClient, engine: Engine, db: Session) -> None:
    seed = _seed(db)
    report = _generate(
        client, engine, "detection", "evidence",
        filters={"asset_ids": [str(seed["asset"].public_id)]},
    )  # fmt: skip
    _download(client, report["id"])
    actions = [
        "report_requested", "report_generated", "evidence_bundle_generated", "report_downloaded",
    ]  # fmt: skip
    for action in actions:
        [event] = _audit(db, action)
        assert event.target_type == "report" and event.target_id == report["id"]
        dumped = json.dumps(event.details)
        assert SECRET not in dumped and "password" not in dumped
    [generated] = _audit(db, "report_generated")
    assert generated.details is not None
    assert generated.details["sha256"] == report["artifact"]["sha256"]
    assert generated.details["report_type"] == "detection"


# --- L. Seguridad de contenido: XSS, CSV injection y redacción ------------------------------


def test_l_hostile_names_are_escaped_and_csv_is_neutralized(
    client: TestClient, engine: Engine, db: Session
) -> None:
    hostile = '<script>alert(1)</script><img src=x onerror=alert(2)>=HYPERLINK("http://x")'
    asset = _discovered(db, name=hostile)
    _detection(db, asset)
    html = _download(client, _generate(client, engine, "technical", "html")["id"]).decode()
    assert "<script>alert" not in html and "<img src=x" not in html
    assert "&lt;script&gt;" in html
    csv_report = _generate(client, engine, "lifecycle_change", "csv")
    rows = list(csv.reader(io.StringIO(_download(client, csv_report["id"]).decode("utf-8-sig"))))
    cells = [cell for row in rows[1:] for cell in row]
    assert not any(cell.startswith(("=", "+", "-", "@")) for cell in cells)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("-2+3", "'-2+3"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\tTAB", "'\tTAB"),
        ("normal", "normal"),
        (-3, -3),
        (None, ""),
        (True, "true"),
    ],
)
def test_l_csv_formula_neutralization(value: Any, expected: Any) -> None:
    assert neutralize(value) == expected


def test_l_csv_has_fixed_columns_and_bom() -> None:
    data = render_csv("executions", {"rows": [{"action": "=cmd|' /C calc'!A0", "extra": "x"}]})
    text = data.decode("utf-8-sig")
    header, row = list(csv.reader(io.StringIO(text)))
    assert "extra" not in header and row[header.index("action")].startswith("'=")


def test_l_redaction_removes_credentials() -> None:
    data = redact(
        {
            "user": "ana",
            "password": "x",
            "nested": {"Authorization": "Bearer abc", "list": [{"api_key": "k"}]},
            "note": f"token={SECRET} y Bearer abcdefghijklmnop",
        }
    )
    dumped = json.dumps(data)
    assert SECRET not in dumped and "abcdefghijklmnop" not in dumped
    assert data["user"] == "ana" and data["password"] == "[redacted]"
    assert data["nested"]["Authorization"] == "[redacted]"
    assert redact_text("password: hunter2 ok").startswith("[redacted]")
    deep: dict[str, Any] = {}
    cursor = deep
    for _ in range(20):
        cursor["a"] = {}
        cursor = cursor["a"]
    assert "[truncated]" in json.dumps(redact(deep))


# --- M. Almacenamiento ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "key",
    [
        "../2026/10/" + "a" * 32 + ".pdf",
        "/etc/passwd",
        "2026/10/../../" + "a" * 32 + ".pdf",
        "2026\\10\\" + "a" * 32 + ".pdf",
        "2026/10/" + "a" * 32 + ".exe",
        "2026/10/con.pdf",
        "C:/Windows/" + "a" * 32 + ".pdf",
        "//server/share/" + "a" * 32 + ".pdf",
        "2026/10/" + "a" * 32 + ".pdf\x00",
        "",
    ],
)
def test_m_storage_keys_reject_traversal(key: str) -> None:
    with pytest.raises(StorageError):
        validate_key(key)


def test_m_storage_atomic_write_symlinks_and_repo(tmp_path: Path) -> None:
    storage = ArtifactStorage(str(tmp_path / "reports"))
    key = new_key(datetime(2026, 10, 14, tzinfo=UTC), uuid4(), "pdf")
    storage.write_atomic(key, b"%PDF-1.4 data")
    assert storage.read(key, 1024) == b"%PDF-1.4 data"
    assert not list((tmp_path / "reports" / ".tmp").iterdir())
    with pytest.raises(StorageError):
        storage.read(key, 4)
    # Un enlace simbólico en lugar del fichero no se sigue.
    outside = tmp_path / "secret.txt"
    outside.write_text("secreto")
    link_key = new_key(datetime(2026, 10, 14, tzinfo=UTC), uuid4(), "pdf")
    link = storage.path_for(link_key)
    link.parent.mkdir(parents=True, exist_ok=True)
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symlinks not available")
    with pytest.raises(StorageError):
        storage.read(link_key, 1024)
    assert storage.delete(link_key) is True
    assert outside.exists()
    # La raíz nunca puede estar dentro del repositorio.
    repo = Path(__file__).resolve().parents[2]
    with pytest.raises(StorageError):
        ArtifactStorage(str(repo / "reports-out")).ensure_root()
    with pytest.raises(StorageError):
        ArtifactStorage("relative/dir").ensure_root()


def test_m_orphan_temp_files_are_purged(tmp_path: Path) -> None:
    storage = ArtifactStorage(str(tmp_path / "r"))
    tmp = storage.ensure_root() / ".tmp"
    (tmp / "old.part").write_bytes(b"x")
    (tmp / "keep.txt").write_bytes(b"x")
    import time

    assert storage.purge_temp(0, time.time() + 10) == 1
    assert (tmp / "keep.txt").exists()


def test_m_report_output_dir_must_be_absolute(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@127.0.0.1:5433/x")
    monkeypatch.setenv("REPORT_OUTPUT_DIR", "reports")
    with pytest.raises(ValueError, match="REPORT_OUTPUT_DIR"):
        Settings(_env_file=None)
    monkeypatch.setenv("REPORT_OUTPUT_DIR", "")
    monkeypatch.setenv("REPORT_RETENTION_DAYS", "")
    settings = Settings(_env_file=None)
    assert settings.report_output_dir is None and settings.report_retention_days is None


# --- N. Resumen determinista ---------------------------------------------------------------


def test_n_deterministic_summary_phrases() -> None:
    assert phrases.risk_level_sentence(3, "critical") == (
        "3 activos presentan nivel de riesgo crítico."
    )
    assert phrases.risk_level_sentence(1, "critical") == (
        "1 activo presenta nivel de riesgo crítico."
    )
    assert phrases.risk_level_sentence(0, "critical").startswith("Ningún activo")
    assert phrases.count_phrase(1, "detección", "detecciones") == "1 detección"
    assert phrases.count_phrase(2, "detección", "detecciones") == "2 detecciones"
    assert phrases.response_sentence(0, 0) == phrases.response_sentence(0, 0)


def test_n_summary_reflects_data_without_ai(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _seed(db)
    report = _generate(client, engine, "executive_summary", "pdf")
    joined = " ".join(report["summary"])
    assert "crítica" in joined or "crítico" in joined
    # El ejecutivo omite IDs, IPs y evidencia técnica.
    stored = db.scalar(select(Report).where(Report.public_id == UUID(report["id"])))
    assert stored is not None and stored.snapshot is not None
    dumped = json.dumps(stored.snapshot["data"])
    assert "10.20.0." not in dumped and "logon_failure" not in dumped


# --- O. Permisos del worker y alcance --------------------------------------------------------


def test_o_worker_uses_the_requesters_current_permissions(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from app.models.user import User

    analyst_client = TestClient(client.app)
    user = authenticate(analyst_client, engine, "analyst")
    created = _create(analyst_client, "risk", "html")
    # Le quitan la cuenta antes de generarse: el informe no se genera con más permisos.
    db.execute(update(User).where(User.id == user.id).values(is_active=False))
    db.commit()
    _worker(engine).run_once()
    report = db.scalar(select(Report).where(Report.public_id == UUID(created["id"])))
    assert report is not None and report.status == "failed"
    assert report.error_code == "report_forbidden"


def test_o_permission_sets() -> None:
    assert Permission.REPORTS_READ in permissions_for("viewer")
    assert Permission.REPORTS_GENERATE not in permissions_for("viewer")
    assert Permission.REPORTS_GENERATE in permissions_for("analyst")
    assert Permission.REPORTS_ADMIN not in permissions_for("analyst")
    assert Permission.REPORTS_ADMIN in permissions_for("admin")


# --- P. Herramientas de la Analyst Console --------------------------------------------------


def test_p_console_tools_share_rbac_and_validation(
    client: TestClient, engine: Engine, db: Session
) -> None:
    from app.core.exceptions import PermissionDeniedError
    from app.reports import tools
    from app.services.audit_service import Actor
    from app.services.report_service import ReportService, Requester

    assert set(tools.TOOLS) == {
        "reports.catalog", "reports.preview", "reports.generate", "reports.status",
        "reports.list", "reports.download_metadata",
    }  # fmt: skip
    service = ReportService(db, get_settings())
    viewer = Requester(None, Actor("viewer-tool"), permissions_for("viewer"))
    admin = Requester(None, Actor("admin-tool"), permissions_for("admin"))
    assert tools.call(service, viewer, "reports.catalog", {})["items"]
    with pytest.raises(PermissionDeniedError):
        tools.call(service, viewer, "reports.generate", {"report_type": "risk", "format": "pdf"})
    with pytest.raises(KeyError):
        tools.call(service, admin, "reports.sql", {})
    created = tools.call(
        service, admin, "reports.generate", {"report_type": "risk", "format": "pdf"}
    )
    _worker(engine).run_once()
    meta = tools.call(service, viewer, "reports.download_metadata", {"report_id": created["id"]})
    assert meta["download_path"] == f"/api/v1/reports/{created['id']}/artifact"
    assert len(meta["sha256"]) == 64 and "storage_key" not in meta
    listed = tools.call(service, viewer, "reports.list", {"status": "succeeded"})
    assert listed["total"] == 1
