"""Fase 7B.0: auditoría de solo lectura (`python -m app.cli audit-7b`).

Reproduce con eventos sintéticos el caso ravenslg (instalación del agente: 4104 + 7045) y
comprueba que el informe:
- clasifica cada detección por su evidencia, nunca por el nombre SENTRA: sin operación
  aprobada, CORR-002 queda suspicious_unverified; con ella, verified_benign;
- dice qué evidencia falta y cómo obtenerla;
- no escribe nada (transacción READ ONLY) y compara los registros que comparten una IP.
"""

from collections.abc import Iterator
from datetime import timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select
from sqlalchemy.orm import Session, sessionmaker

from app import cli
from app.models.asset import Asset
from app.models.attribution import DetectionAttributionEvent
from app.models.detection import Detection
from app.services import audit_7b
from tests.test_attribution import (
    _approved_ago,
    _asset_public_id,
    _create_and_approve,
    _install,
    _operation_body,
)
from tests.test_device_identity import RANDOM_MAC, UNIVERSAL_MAC, _discovered
from tests.test_powershell_detections import _agent, _run

TIMEOUT = timedelta(seconds=90)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _report(engine: Engine, refs: list[str], ip: str | None = None) -> dict[str, Any]:
    with sessionmaker(bind=engine)() as session:
        return audit_7b.collect(session, refs, ip, 30, TIMEOUT)


def _counts(db: Session) -> tuple[int, int]:
    db.expire_all()
    events = db.scalar(select(func.count()).select_from(DetectionAttributionEvent)) or 0
    resolved = db.scalar(
        select(func.count()).select_from(Detection).where(Detection.resolved_at.is_not(None))
    )
    return int(events), int(resolved or 0)


def test_install_without_operation_is_suspicious_with_missing_evidence(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    _install(client, agent)
    _run(engine)
    asset = db.get(Asset, asset_id)
    assert asset is not None
    before = _counts(db)

    report = _report(engine, [str(asset.public_id)])
    (item,) = report["assets"]
    by_rule = {d["rule_id"]: d for d in item["detections"]}
    # El script se llama install-sentra-agent.ps1, pero el nombre no lo hace legítimo.
    assert by_rule["CORR-002"]["classification"] == "suspicious_unverified"
    assert by_rule["SCR-001"]["classification"] == "suspicious_unverified"
    assert item["agent_context"] == {"events_4104": 1, "events_4104_with_context": 1}
    assert {e["event_code"] for e in item["events"]} == {4104, 7045}
    assert report["read_only"] is True and _counts(db) == before
    lines = audit_7b.summary_lines(report)
    assert any("CORR-002" in line and "suspicious_unverified" in line for line in lines)


def test_approved_operation_turns_the_case_verified(
    client: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    op = _create_and_approve(client, _operation_body(_asset_public_id(db, asset_id)))
    _approved_ago(db, op, 60)
    _install(client, agent)
    _run(engine)
    asset = db.get(Asset, asset_id)
    assert asset is not None
    (item,) = _report(engine, [asset.hostname or ""])["assets"]
    by_rule = {d["rule_id"]: d for d in item["detections"]}
    assert by_rule["CORR-002"]["classification"] == "verified_benign"
    assert by_rule["CORR-002"]["operation"] is not None


def test_ip_analysis_classifies_the_duplicate(
    client: TestClient, engine: Engine, db: Session
) -> None:
    _discovered(db, mac_address=RANDOM_MAC)
    _discovered(db, mac_address=UNIVERSAL_MAC)
    report = _report(engine, [], "192.168.50.66")
    analysis = report["ip_analysis"]
    assert len(analysis["records"]) == 2
    assert [c["classification"] for c in analysis["comparisons"]] == ["ip_reuse"]
    assert {r["state"] for r in analysis["records"]} == {"identity_unresolved", "probable"}


def test_cli_requires_a_target() -> None:
    assert cli.main(["audit-7b"]) == 2
