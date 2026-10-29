"""Fase 7B.4: Analyst Console sobre el motor 7A (búsqueda global y herramientas nuevas).

- búsqueda: entiende IP, MAC, SHA-256, id de regla, número de caso y texto, sin ser un
  lenguaje de consulta (un comodín LIKE se busca literal) y respetando el site;
- attribution.explain, detections.related e identity.candidates: lectura pura (el motor las
  ejecuta en una transacción READ ONLY), con RBAC y alcance de site del motor 7A.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset
from app.models.risk import AssetRisk, RiskLevel
from app.models.site import Site
from app.services.console_search import classify_query
from tests.conftest import authenticate
from tests.test_analyst_tools import _error, _ok, _run
from tests.test_attribution import _asset_public_id, _create_and_approve, _install
from tests.test_attribution import _operation_body as operation_body
from tests.test_device_identity import RANDOM_MAC, _discovered, _wifi_report
from tests.test_device_identity import _agent as register_agent
from tests.test_powershell_detections import SHA, _agent, _detections
from tests.test_powershell_detections import _run as run_engine

API = "/api/v1"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.fixture
def analyst(client: TestClient, engine: Engine) -> Iterator[TestClient]:
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst")
        yield other


@pytest.mark.parametrize(
    ("text", "kind"),
    [
        ("192.168.50.66", "ip"),
        ("da:a1:19:00:00:66", "mac"),
        ("DA-A1-19-00-00-66", "mac"),
        (SHA, "sha256"),
        ("scr-001", "rule"),
        ("INC-12", "case"),
        ("ravenslg", "text"),
    ],
)
def test_query_kinds(text: str, kind: str) -> None:
    assert classify_query(text) == kind


def test_search_by_hash_finds_detections_and_operations(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    agent, asset_id = _agent(client, db)
    _create_and_approve(client, operation_body(_asset_public_id(db, asset_id)))
    _install(client, agent)
    run_engine(engine)
    body = _ok(analyst.get(f"{API}/search", params={"q": SHA.upper()}))
    assert body["kind"] == "sha256"
    assert {d["rule_id"] for d in body["detections"]} >= {"SCR-001", "CORR-002"}
    assert len(body["operations"]) == 1 and body["operations"][0]["status"] == "approved"
    by_rule = _ok(analyst.get(f"{API}/search", params={"q": "per-001"}))
    assert {d["rule_id"] for d in by_rule["detections"]} == {"PER-001"}


def test_search_assets_wildcards_and_site_scope(analyst: TestClient, db: Session) -> None:
    phone = _discovered(db, mac_address=RANDOM_MAC)
    body = _ok(analyst.get(f"{API}/search", params={"q": "192.168.50.66"}))
    assert [a["asset_id"] for a in body["assets"]] == [str(phone.public_id)]
    body = _ok(analyst.get(f"{API}/search", params={"q": RANDOM_MAC.upper()}))
    assert body["kind"] == "mac" and len(body["assets"]) == 1
    # "%" no es un comodín: no devuelve todo.
    assert _ok(analyst.get(f"{API}/search", params={"q": "%%"}))["assets"] == []
    suffix = uuid4().hex[:6]
    other = Site(name=f"Sede {suffix}", slug=f"sede-{suffix}")
    db.add(other)
    db.commit()
    scoped = _ok(
        analyst.get(f"{API}/search", params={"q": "192.168.50.66", "site_id": str(other.public_id)})
    )
    assert scoped["assets"] == []
    assert analyst.get(f"{API}/search", params={"q": "x"}).status_code == 422


def test_attribution_and_related_tools(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    first, _ = _agent(client, db)
    second, _ = _agent(client, db)
    _install(client, first)
    _install(client, second)
    run_engine(engine)
    scr = [d for d in _detections(client, "SCR-001")]
    assert len(scr) == 2
    body = _ok(_run(analyst, "attribution.explain", {"detection_id": scr[0]["detection_id"]}))
    assert body["status"] == "succeeded"
    assert body["output"]["verdict"] == "suspicious_unverified"
    related = _ok(_run(analyst, "detections.related", {"detection_id": scr[0]["detection_id"]}))
    output = related["output"]
    assert output["keys"] == [f"script:{SHA}"]
    # El mismo script en el otro equipo (SCR-001) y las dos correlaciones que lo incluyen.
    assert {i["rule_id"] for i in output["items"]} == {"SCR-001", "CORR-002"}
    assert len({i["asset_id"] for i in output["items"]}) == 2
    assert all(i["shared"] == [f"script:{SHA}"] for i in output["items"])
    _error(_run(analyst, "attribution.explain", {"detection_id": str(uuid4())}), 404, "not_found")


def test_identity_candidates_tool(
    client: TestClient, analyst: TestClient, engine: Engine, db: Session
) -> None:
    laptop = register_agent(client, db, hostname="portatil", primary_ip="192.168.50.20")
    _wifi_report(db, laptop, RANDOM_MAC)
    seen = _discovered(db, mac_address=RANDOM_MAC)
    body = _ok(_run(analyst, "identity.candidates", {"asset_id": str(seen.public_id)}))
    assert body["output"]["profile"]["state"] == "identity_unresolved"
    assert [c["asset"]["asset_id"] for c in body["output"]["candidates"]] == [str(laptop.public_id)]
    # Ninguna herramienta nueva escribe: el activo sigue igual.
    db.expire_all()
    assert db.get(Asset, seen.id).archived_at is None  # type: ignore[union-attr]


def test_search_users_only_for_case_managers(
    client: TestClient, analyst: TestClient, engine: Engine
) -> None:
    """7B.4: la consola busca usuarios de Sentra para asignar trabajo, nunca a un viewer."""
    suffix = uuid4().hex[:6]
    with TestClient(client.app) as other:
        authenticate(other, engine, "analyst", username=f"turno-{suffix}")
    body = _ok(analyst.get(f"{API}/search", params={"q": f"TURNO-{suffix}"}))
    assert body["users_visible"] is True
    assert [(u["username"], u["role"], u["active"], u["open_cases"]) for u in body["users"]] == [
        (f"turno-{suffix}", "analyst", True, 0)
    ]
    # "_" no es un comodín de LIKE.
    assert _ok(analyst.get(f"{API}/search", params={"q": "turno_"}))["users"] == []
    # Una IP o un hash no buscan usuarios.
    assert _ok(analyst.get(f"{API}/search", params={"q": "192.168.50.1"}))["users"] == []
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        hidden = _ok(viewer.get(f"{API}/search", params={"q": f"turno-{suffix}"}))
        assert hidden["users"] == [] and hidden["users_visible"] is False


def test_viewer_cannot_run_tools_but_can_search(
    client: TestClient, engine: Engine, db: Session
) -> None:
    asset = _discovered(db)
    with TestClient(client.app) as viewer:
        authenticate(viewer, engine, "viewer")
        assert viewer.get(f"{API}/search", params={"q": "192.168"}).status_code == 200
        _error(
            _run(viewer, "identity.candidates", {"asset_id": str(asset.public_id)}),
            403,
            "permission_denied",
        )


def test_devices_sort_by_risk_server_side(analyst: TestClient, db: Session) -> None:
    """7B.3: la columna Riesgo se ordena en el servidor; sin cálculo va al final."""
    low = _discovered(db, ip="10.70.0.1")
    high = _discovered(db, ip="10.70.0.2")
    none = _discovered(db, ip="10.70.0.3")
    now = datetime.now(UTC)
    for asset, score, level in ((low, 10, RiskLevel.LOW), (high, 80, RiskLevel.HIGH)):
        db.add(AssetRisk(asset_id=asset.id, score=score, level=level, calculated_at=now))
    db.commit()
    ids = {str(a.public_id): a for a in (low, high, none)}

    def order(direction: str) -> list[str]:
        body = _ok(
            analyst.get(
                f"{API}/assets", params={"q": "10.70.0.", "sort": "risk", "order": direction}
            )
        )
        return [i["asset_id"] for i in body["items"] if i["asset_id"] in ids]

    assert order("desc") == [str(high.public_id), str(low.public_id), str(none.public_id)]
    assert order("asc") == [str(low.public_id), str(high.public_id), str(none.public_id)]
