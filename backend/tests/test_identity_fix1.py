"""Fase 7B-Fix1: identidad de los dispositivos de la red doméstica de la auditoría.

.69 "MNA LX9" (Huawei, MAC privada), .71 "MRO W09" (tableta), .108 "REALTEKSEMI..." (dock de
la Switch con adaptador Realtek), nombres asignados por un admin y lo que falta para
identificar cada equipo. Sin red: el motor de clasificación y la ficha por niveles.
"""

from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from tests.test_device_identity import RANDOM_MAC, UNIVERSAL_MAC, _discovered
from tests.test_identification import HUAWEI, REALTEK, ident

API = "/api/v1"


@pytest.mark.parametrize("name", ["MNA-LX9", "MNA LX9", "mna_lx9"])
def test_huawei_phone_codes_with_any_separator(name: str) -> None:
    result = ident(reverse_dns=name, mac_vendor=HUAWEI)
    assert result.device_type == "mobile" and result.device_vendor == "Huawei"
    assert result.device_model == "MNA-LX9"


def test_huawei_w_codes_are_tablets() -> None:
    result = ident(reverse_dns="MRO-W09", mac_vendor=HUAWEI)
    assert result.device_type == "tablet" and result.device_model == "MRO-W09"
    # Con MAC privada solo hay una pista: tipo probable, modelo sin afirmar.
    private = ident(reverse_dns="MRO W09", mac="da:a1:19:00:00:02", mac_random=True)
    assert private.device_type == "tablet" and private.device_model is None


@pytest.mark.parametrize("name", ["REALTEKSEMICONDUCTOR", "realteksemi-0a1b", "Realtek"])
def test_nic_chip_names_do_not_identify_the_device(name: str) -> None:
    result = ident(reverse_dns=name, mac_vendor=REALTEK)
    assert result.name is None or result.name.lower() != name.lower()
    assert result.device_vendor != "Realtek"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _profile(client: TestClient, asset: Any) -> dict[str, Any]:
    response = client.get(f"{API}/assets/{asset.public_id}/identity/profile")
    assert response.status_code == 200, response.text
    body: dict[str, Any] = response.json()
    return body


def test_admin_name_is_confirmed_and_wins(client: TestClient, db: Session) -> None:
    phone = _discovered(
        db,
        mac_address=RANDOM_MAC,
        custom_label="Rabanito",
        custom_label_updated_by="admin",
        observed_names=[{"source": "dhcp_lease", "value": "android-1", "kind": "generic"}],
    )
    body = _profile(client, phone)
    assert body["display_name"] == "Rabanito"
    assert body["assigned_name"]["state"] == "confirmed"
    assert body["assigned_name"]["source"] == "admin"
    gaps = {gap["field"]: gap for gap in body["missing"]}
    # La MAC privada sigue sin servir de identidad estable aunque tenga nombre.
    assert gaps["stable_identity"]["code"] == "private_mac"
    assert "name" not in gaps
    assert gaps["vendor"]["code"] == "private_mac"


def test_nic_vendor_is_separate_and_missing_info_is_listed(client: TestClient, db: Session) -> None:
    dock = _discovered(db, mac_address=UNIVERSAL_MAC, vendor="Realtek Semiconductor Corp.")
    body = _profile(client, dock)
    assert body["model"]["state"] == "unresolved"
    gaps = {gap["field"]: gap["code"] for gap in body["missing"]}
    assert gaps["model"] == "no_model_evidence"
    assert gaps["device_type"] == "no_type_evidence"
    assert "stable_identity" not in gaps


def test_announced_model_is_probable(client: TestClient, db: Session) -> None:
    tv = _discovered(
        db,
        mac_address=UNIVERSAL_MAC,
        device_vendor="Samsung",
        device_model="QE55Q60",
        classification_evidence=[{"source": "upnp", "value": "modelo QE55Q60"}],
    )
    body = _profile(client, tv)
    assert body["model"] == {
        "value": "QE55Q60",
        "source": "upnp",
        "state": "probable",
        "reasons": ["device_announced"],
        "alternatives": [],
    }
