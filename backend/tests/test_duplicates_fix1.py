"""Fase 7B-Fix1: dos "Ravenslg Linux" (192.168.50.66, b4:2e:99:e0:ee:fb).

El listado global no comparaba la MAC: dos registros del mismo equipo con la misma MAC
universal y distinto nombre no aparecían. Ahora aparecen con su hipótesis (reinstalación,
reenrolado, registro descubierto...), la reconciliación sigue siendo manual y nada se borra.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, func, select, update
from sqlalchemy.orm import Session, sessionmaker

from app.models.asset import Asset
from tests.test_asset_lifecycle import ASSETS, _discovered, _register, _revoke

MAC = "b4:2e:99:e0:ee:fb"
PRIVATE = "da:a1:19:00:00:01"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _set(db: Session, asset_id: str, **values: Any) -> None:
    db.execute(update(Asset).where(Asset.public_id == asset_id).values(**values))
    db.commit()


def _pairs(client: TestClient, **params: Any) -> list[dict[str, Any]]:
    response = client.get(f"{ASSETS}/duplicates", params=params)
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def test_same_universal_mac_is_listed_as_a_reinstall(client: TestClient, db: Session) -> None:
    host = {"os_name": "Linux", "os_version": "Ubuntu 24.04", "primary_ip": "192.168.50.66"}
    old = _register(client, hostname="ravenslg", **host)
    _revoke(client, old["asset_id"])
    new = _register(client, hostname="ravenslg-linux", **host)
    for item in (old, new):
        _set(db, item["asset_id"], mac_address=MAC)

    (pair,) = _pairs(client)
    assert {pair["asset"]["asset_id"], pair["candidate"]["asset_id"]} == {
        old["asset_id"],
        new["asset_id"],
    }
    assert "same_mac" in pair["reasons"] and pair["confidence"] == "medium"
    assert pair["hypothesis"] == "reinstall"
    # Solo sugiere: los dos registros siguen ahí.
    assert db.scalar(select(func.count()).select_from(Asset)) == 2


def test_private_mac_never_makes_a_listed_duplicate(client: TestClient, db: Session) -> None:
    host = {"os_name": "Linux", "primary_ip": "192.168.50.66"}
    old = _register(client, hostname="a", **host)
    _revoke(client, old["asset_id"])
    new = _register(client, hostname="b", **host)
    for item in (old, new):
        _set(db, item["asset_id"], mac_address=PRIVATE)
    assert _pairs(client) == []
    (low,) = _pairs(client, min_confidence="low")
    assert "same_random_mac" in low["reasons"] and low["confidence"] == "low"


def test_discovered_record_of_a_managed_host_is_explained(client: TestClient, db: Session) -> None:
    agent = _register(client, hostname="ravenslg", os_name="Linux", primary_ip="192.168.50.66")
    _set(db, agent["asset_id"], mac_address=MAC)
    _discovered(db, primary_ip="192.168.50.66", mac_address=MAC)
    (pair,) = _pairs(client)
    assert pair["hypothesis"] == "discovered_record"
    assert pair["reconcilable"] is False
    # El descubierto no tiene agente que mover: se resuelve con la fusión de discovery o
    # archivándolo, nunca con una reconciliación de agentes.
    assert {"source_without_agent", "target_never_managed"} & set(pair["reconcile_blockers"])


def test_same_machine_id_with_a_new_agent_is_a_re_enrollment(client: TestClient) -> None:
    old = _register(client, hostname="x", primary_ip="10.9.0.1", machine_id_hash="c" * 64)
    _revoke(client, old["asset_id"])
    new = _register(client, hostname="y", primary_ip="10.9.0.2", machine_id_hash="c" * 64)
    (candidate,) = client.get(f"{ASSETS}/{new['asset_id']}/duplicate-candidates").json()["items"]
    assert candidate["confidence"] == "high"
    assert candidate["hypothesis"] == "re_enrollment"
