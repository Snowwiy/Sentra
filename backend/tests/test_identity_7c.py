"""Fase 7C.6: identidad de dispositivos sin SNMP.

- nombres de marcas de consumo (Huawei, Samsung, Lenovo, Motorola, OPPO, realme, Xiaomi,
  Hisense, TCL, Philips, docks, cámaras y domótica) que los equipos publican por DHCP/mDNS;
- correlación de MACs privadas sin inventar identidades: el mismo client id DHCP es una
  señal media; dos MACs privadas que nunca coincidieron en el tiempo solo apoyan (débil) y
  necesitan además el mismo nombre propio para sugerir un candidato.
"""

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.discovery.classify import IdentityInput, identify
from app.discovery.device_types import DeviceType as T
from app.models.asset import Asset
from app.models.dhcp import DhcpLease, DhcpSource
from app.services.site_service import default_site_id
from tests.test_device_identity import _discovered

API = "/api/v1"


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


@pytest.mark.parametrize(
    ("name", "device_type", "vendor"),
    [
        ("MatePad-11", T.TABLET, "Huawei"),
        ("nova-9", T.MOBILE, "Huawei"),
        ("MateBook-D14", T.LAPTOP, "Huawei"),
        ("TB-X606F", T.TABLET, "Lenovo"),
        ("moto-g54", T.MOBILE, "Motorola"),
        ("CPH2591", T.MOBILE, "OPPO"),
        ("RMX3771", T.MOBILE, "realme"),
        ("Galaxy-S23", T.MOBILE, "Samsung"),
        ("galaxy-book3", T.LAPTOP, "Samsung"),
        ("QE55Q80A", T.SMART_TV, "Samsung"),
        ("redmi-pad-se", T.TABLET, "Xiaomi"),
        ("Mi-Box-S", T.SMART_TV, "Xiaomi"),
        ("xiaomi-tv", T.SMART_TV, "Xiaomi"),
        ("hisense-tv", T.SMART_TV, "Hisense"),
        ("Philips-TV", T.SMART_TV, "Philips"),
        ("Kindle-Paperwhite", T.TABLET, "Amazon"),
        ("apple-tv", T.SMART_TV, "Apple"),
        ("switch-dock", T.CONSOLE, "Nintendo"),
        ("tapo-c200", T.IP_CAMERA, "TP-Link"),
        ("roborock-s7", T.IOT, None),
    ],
)
def test_consumer_names_without_snmp(name: str, device_type: T, vendor: str | None) -> None:
    result = identify(IdentityInput(dhcp_hostname=name))
    assert result.device_type == device_type, result.evidence
    assert result.device_vendor == vendor


@pytest.mark.parametrize("name", ["shield", "mate", "vivo", "pad", "dock", "tcl"])
def test_ambiguous_words_do_not_invent_a_type(name: str) -> None:
    assert identify(IdentityInput(dhcp_hostname=name)).device_type is None


def test_laptop_dock_is_only_a_weak_hint_without_brand() -> None:
    result = identify(IdentityInput(dhcp_hostname="WD19TB"))
    assert result.device_type == T.LAPTOP and result.device_vendor is None
    assert result.confidence is not None and result.confidence.value == "low"


def _lease(db: Session, asset: Asset, client_id: str, source: DhcpSource) -> None:
    now = datetime.now(UTC)
    db.add(
        DhcpLease(
            site_id=asset.site_id,
            source_id=source.id,
            ip=asset.primary_ip,
            mac=asset.mac_address or "da:00:00:00:00:00",
            client_id=client_id,
            state="active",
            asset_id=asset.id,
            match="randomized_mac",
            first_seen_at=now,
            last_seen_at=now,
        )
    )
    db.commit()


def _source(db: Session) -> DhcpSource:
    source = DhcpSource(
        site_id=default_site_id(db),
        name="router",
        kind="lease_import",
        format="dnsmasq",
        created_by="admin",
    )
    db.add(source)
    db.commit()
    return source


def _candidates(client: TestClient, asset: Asset) -> list[dict[str, Any]]:
    response = client.get(f"{API}/assets/{asset.public_id}/identity/candidates")
    assert response.status_code == 200, response.text
    items: list[dict[str, Any]] = response.json()["items"]
    return items


def test_same_dhcp_client_id_is_medium_evidence(client: TestClient, db: Session) -> None:
    source = _source(db)
    first = _discovered(db, ip="192.168.50.40", mac_address="da:00:00:00:00:40")
    second = _discovered(db, ip="192.168.50.41", mac_address="da:00:00:00:00:41")
    other = _discovered(db, ip="192.168.50.42", mac_address="da:00:00:00:00:42")
    _lease(db, first, "sha256:00112233aabbccdd", source)
    _lease(db, second, "sha256:00112233aabbccdd", source)
    _lease(db, other, "sha256:ffffffffffffffff", source)
    items = _candidates(client, second)
    assert [i["asset"]["asset_id"] for i in items] == [str(first.public_id)]
    assert items[0]["strength"] == "medium"
    assert items[0]["evidence"][0]["code"] == "same_dhcp_client_id"


def test_private_mac_rotation_needs_the_same_name(client: TestClient, db: Session) -> None:
    now = datetime.now(UTC)
    names = [{"source": "dhcp_lease", "value": "MNA-LX9", "kind": "dhcp", "selected": True}]
    old = _discovered(
        db,
        ip="192.168.50.50",
        mac_address="da:00:00:00:00:50",
        first_seen_at=now - timedelta(days=10),
        last_seen_at=now - timedelta(days=3),
        device_name="MNA-LX9",
        observed_names=names,
    )
    new = _discovered(
        db,
        ip="192.168.50.51",
        mac_address="da:00:00:00:00:51",
        first_seen_at=now - timedelta(days=2),
        last_seen_at=now,
        device_name="MNA-LX9",
        observed_names=names,
    )
    items = _candidates(client, new)
    assert [i["asset"]["asset_id"] for i in items] == [str(old.public_id)]
    assert items[0]["strength"] == "weak"
    codes = {e["code"] for e in items[0]["evidence"]}
    assert {"private_mac_rotation", "same_device_name"} <= codes

    # Activos a la vez: dos equipos distintos con el mismo nombre, nunca una rotación.
    old.last_seen_at = now
    db.commit()
    items = _candidates(client, new)
    assert all("private_mac_rotation" not in {e["code"] for e in i["evidence"]} for i in items)
