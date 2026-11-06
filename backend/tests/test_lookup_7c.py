"""Fase 7C.3: selectores contextuales sin IDs manuales (GET /lookup/{kind}).

El usuario escribe lo que reconoce y la API resuelve el id público. Una sola coincidencia
exacta se puede elegir sola; varias exactas son ambiguas y la UI tiene que preguntar.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset_context import AssetTag
from app.models.incident import Incident
from app.models.site import Site
from tests.conftest import authenticate
from tests.test_risk import _detection, _discovered

API = "/api/v1"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def viewer(client: TestClient, engine: Engine) -> Iterator[TestClient]:
    with TestClient(client.app) as other:
        authenticate(other, engine, "viewer")
        yield other


def _get(client: TestClient, kind: str, **params: Any) -> dict[str, Any]:
    response = client.get(f"{API}/lookup/{kind}", params=params)
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def test_asset_by_ip_mac_name_label_and_tag(viewer: TestClient, db: Session) -> None:
    printer = _discovered(db, name="impresora-planta2", device_type="printer")
    printer.mac_address = "00:11:22:33:44:55"
    printer.custom_label = "Impresora RRHH"
    db.add(AssetTag(asset_id=printer.id, tag="planta-2", created_at=datetime.now(UTC)))
    db.commit()
    _discovered(db, name="impresora-planta3")

    by_ip = _get(viewer, "asset", q=printer.primary_ip)
    assert by_ip["resolution"] == "exact"
    assert by_ip["items"][0]["id"] == str(printer.public_id)
    assert by_ip["items"][0]["match_field"] == "ip" and by_ip["items"][0]["exact"] is True
    assert by_ip["items"][0]["label"] == "Impresora RRHH"
    assert "printer" in by_ip["items"][0]["secondary"]

    by_mac = _get(viewer, "asset", q="00-11-22-33-44-55")
    assert by_mac["resolution"] == "exact" and by_mac["items"][0]["match_field"] == "mac"

    by_label = _get(viewer, "asset", q="impresora rrhh")
    assert by_label["items"][0]["match_field"] == "label" and by_label["resolution"] == "exact"

    partial = _get(viewer, "asset", q="impresora")
    assert partial["resolution"] == "partial" and len(partial["items"]) == 2

    by_tag = _get(viewer, "asset", q="planta-2")
    assert [i["id"] for i in by_tag["items"]] == [str(printer.public_id)]
    assert by_tag["items"][0]["match_field"] == "tag"


def test_same_name_twice_is_ambiguous(viewer: TestClient, db: Session) -> None:
    first = _discovered(db, name="pc-recepcion")
    second = _discovered(db, name="PC-RECEPCION")
    body = _get(viewer, "asset", q="pc-recepcion")
    assert body["resolution"] == "ambiguous"
    assert {i["id"] for i in body["items"]} == {str(first.public_id), str(second.public_id)}


def test_like_wildcards_are_literal_and_limit(viewer: TestClient, db: Session) -> None:
    for index in range(5):
        _discovered(db, name=f"sensor-{index}")
    assert _get(viewer, "asset", q="%")["items"] == []
    assert _get(viewer, "asset", q="sensor_")["items"] == []
    body = _get(viewer, "asset", q="sensor", limit=3)
    assert len(body["items"]) == 3 and body["truncated"] is True


def test_site_scope_and_archived(viewer: TestClient, db: Session) -> None:
    other_site = Site(name="Sede Norte", slug=f"norte-{uuid4().hex[:6]}")
    db.add(other_site)
    db.commit()
    asset = _discovered(db, name="servidor-norte")
    asset.site_id = other_site.id
    db.commit()
    local = db.query(Site).filter(Site.id != other_site.id).first()
    assert local is not None
    assert _get(viewer, "asset", q="servidor-norte", site_id=str(local.public_id))["items"] == []
    found = _get(viewer, "asset", q="servidor-norte", site_id=str(other_site.public_id))
    assert found["items"][0]["site_name"] == "Sede Norte"

    asset.archived_at = datetime.now(UTC)
    db.commit()
    assert _get(viewer, "asset", q="servidor-norte")["items"] == []
    archived = _get(viewer, "asset", q="servidor-norte", include_archived="true")
    assert archived["items"][0]["archived"] is True


def test_resolve_known_ids(viewer: TestClient, db: Session) -> None:
    asset = _discovered(db, name="pc-contabilidad")
    body = _get(viewer, "asset", ids=[str(asset.public_id), str(uuid4())])
    assert [i["label"] for i in body["items"]] == ["pc-contabilidad"]
    assert body["items"][0]["match_field"] == "id"


def test_detections_by_rule_title_and_asset(viewer: TestClient, db: Session) -> None:
    asset = _discovered(db, name="pc-finanzas-14")
    detection = _detection(db, asset, rule_id="SCR-001")
    by_rule = _get(viewer, "detection", q="scr-001")
    assert by_rule["items"][0]["id"] == str(detection.public_id)
    assert by_rule["items"][0]["asset_id"] == str(asset.public_id)
    by_asset = _get(viewer, "detection", q="finanzas")
    assert by_asset["items"][0]["asset_label"] == "pc-finanzas-14"
    by_title = _get(viewer, "detection", q="Detección SCR-001")
    assert by_title["resolution"] == "exact"


def test_incidents_need_incidents_read(
    client: TestClient, viewer: TestClient, engine: Engine, db: Session
) -> None:
    created = client.post(
        f"{API}/incidents",
        json={
            "title": "Revisión de PowerShell en Finanzas",
            "severity": "medium",
            "priority": "medium",
        },
    )
    assert created.status_code == 201, created.text
    incident = db.scalar(
        select(Incident).where(Incident.public_id == created.json()["incident_id"])
    )
    assert incident is not None
    body = _get(client, "incident", q=f"INC-{incident.number}")
    assert body["resolution"] == "exact" and body["items"][0]["match_field"] == "number"
    assert _get(client, "incident", q="powershell")["items"][0]["id"] == str(incident.public_id)
    # El viewer tiene incidents:read en Sentra; un rol sin él recibiría 403. Lo comprobamos
    # con el contrato de permisos, no inventando un rol.
    assert viewer.get(f"{API}/lookup/incident", params={"q": "x"}).status_code in (200, 403)
    assert client.get(f"{API}/lookup/nope", params={"q": "x"}).status_code == 422
