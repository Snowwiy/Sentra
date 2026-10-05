"""Identificación de extremo a extremo: discovery → base de datos → API, y fusión con el agente.

Red simulada con Lab (tests/test_discovery_service.py) más un doble de las sondas de nombre;
la base OUI es un fichero de prueba en memoria. Sin Internet ni UDP real.
"""

from collections.abc import Collection, Iterator
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from app.discovery import names
from app.discovery.oui import OuiDatabase
from app.discovery.scanner import ScanConfig
from app.discovery.targets import DiscoveryScope
from app.models.alert import Alert
from app.models.asset import Asset
from app.models.change import AssetChange
from app.services import discovery_service, identification
from app.services.alert_service import AlertThresholds
from app.services.discovery_service import DiscoveryConfig, DiscoveryService
from tests.conftest import agent_payload
from tests.test_discovery_service import Host, Lab

NETWORK = "192.168.50.0/27"
# Prefijos de prueba (no son asignaciones reales del IEEE).
OUI = OuiDatabase(
    {
        "A40001": "HUAWEI TECHNOLOGIES CO.,LTD",
        "A40002": "Amazon Technologies Inc.",
        "A40003": "Realtek Semiconductor Corp.",
        "A40004": "ASUSTek COMPUTER INC.",
        "A40005": "Intel Corporate",
    }
)


def home() -> dict[str, Host]:
    return {
        "192.168.50.1": Host({53, 80, 443}, mac="a4:00:04:00:00:01"),
        "192.168.50.20": Host({22}, mac="a4:00:05:00:00:20"),
        "192.168.50.12": Host(set(), mac="a4:00:03:00:00:12"),
        "192.168.50.13": Host(set(), mac="a4:00:03:00:00:13", name="Nintendo-Switch.lan"),
        "192.168.50.14": Host(set(), mac="02:00:00:00:00:14"),
        "192.168.50.21": Host(set(), mac="a4:00:01:00:00:21", name="MNA-LX9.lan"),
        "192.168.50.28": Host(set(), mac="a4:00:02:00:00:28", name="Alexa.lan"),
    }


class Names:
    """Sondas de nombre simuladas: el .20 publica nombre por mDNS y NetBIOS."""

    async def mdns_name(self, address: str, timeout: float) -> str | None:
        return "ravenslg" if address == "192.168.50.20" else None

    async def netbios_name(self, address: str, timeout: float) -> str | None:
        return "RAVENSLG" if address == "192.168.50.20" else None

    async def ssdp_search(
        self, addresses: Collection[str], window: float
    ) -> dict[str, names.SsdpResponse]:
        return {}

    async def upnp_description(
        self, response: names.SsdpResponse, timeout: float
    ) -> names.UpnpDescription | None:
        return None


@pytest.fixture(autouse=True)
def oui(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(identification, "oui_database", lambda: OUI)
    monkeypatch.setattr(discovery_service, "oui_database", lambda: OUI)


@pytest.fixture
def db(engine: Engine, client: TestClient) -> Iterator[Session]:
    with sessionmaker(bind=engine, expire_on_commit=False)() as session:
        yield session


def _service(engine: Engine, lab: Lab) -> DiscoveryService:
    config = DiscoveryConfig(
        scope=DiscoveryScope.parse(NETWORK),
        scan=ScanConfig(ports=(22, 53, 80, 443), timeout=0.5, concurrency=16, max_rate=5000),
        offline_after_misses=2,
        heartbeat_timeout=timedelta(seconds=90),
    )
    thresholds = AlertThresholds(
        cpu_percent=90, ram_percent=90, disk_percent=90, sustained_samples=3,
        offline_after=timedelta(seconds=90),
    )  # fmt: skip
    return DiscoveryService(
        sessionmaker(bind=engine, expire_on_commit=False),
        config,
        thresholds,
        prober_factory=lambda: lab,
        identity_factory=Names,
        gateways=lambda: {"192.168.50.1"},
    )


def _by_ip(client: TestClient) -> dict[str, dict[str, Any]]:
    response = client.get("/api/v1/assets")
    assert response.status_code == 200, response.text
    return {a["primary_ip"]: a for a in response.json()["items"]}


def test_discovery_presents_devices_usefully(client: TestClient, engine: Engine) -> None:
    _service(engine, Lab(home())).run()
    assets = _by_ip(client)

    phone = assets["192.168.50.21"]
    assert (phone["device_name"], phone["device_type"], phone["device_vendor"]) == (
        "MNA-LX9",
        "mobile",
        "Huawei",
    )
    assert phone["classification_confidence"] == "high" and phone["display_name"] == "MNA-LX9"
    assert phone["network_adapter_vendor"] == "Huawei"
    assert {"source": "mac_vendor", "value": "Huawei"} in phone["classification_evidence"]

    alexa = assets["192.168.50.28"]
    assert (alexa["device_name"], alexa["device_type"], alexa["device_vendor"]) == (
        "Alexa",
        "voice_assistant",
        "Amazon",
    )

    console = assets["192.168.50.13"]
    assert console["device_type"] == "console" and console["classification_confidence"] == "medium"
    assert console["network_adapter_vendor"] == "Realtek"
    assert console["vendor"] == "Realtek Semiconductor Corp."  # nombre OUI completo

    unknown = assets["192.168.50.12"]
    assert unknown["device_name"] is None and unknown["device_type"] is None
    assert unknown["device_vendor"] is None and unknown["network_adapter_vendor"] == "Realtek"

    random_mac = assets["192.168.50.14"]
    assert random_mac["vendor"] is None and random_mac["classification_confidence"] is None
    assert random_mac["classification_evidence"] == [
        {"source": "mac_random", "value": "MAC aleatoria (privacidad): sin fabricante"}
    ]

    router = assets["192.168.50.1"]
    assert router["device_type"] == "router" and router["device_vendor"] == "ASUS"
    assert router["classification_confidence"] == "high"

    # Nombre por mDNS (no hay DNS inverso) y NetBIOS como evidencia adicional.
    linux = assets["192.168.50.20"]
    assert linux["device_name"] == "ravenslg" and linux["name_source"] == "mdns"
    assert {"source": "netbios", "value": "RAVENSLG"} in linux["classification_evidence"]

    # Búsqueda por nombre resuelto y por fabricante.
    found = client.get("/api/v1/assets", params={"q": "huawei"}).json()["items"]
    assert [a["primary_ip"] for a in found] == ["192.168.50.21"]
    by_type = client.get("/api/v1/assets", params={"device_type": "voice_assistant"}).json()
    assert [a["primary_ip"] for a in by_type["items"]] == ["192.168.50.28"]


def test_reclassification_is_history_not_an_alert(engine: Engine, db: Session) -> None:
    lab = Lab(home())
    service = _service(engine, lab)
    service.run()
    alerts_before = len(list(db.scalars(select(Alert))))
    # El dispositivo .12 publica ahora un nombre de móvil Android.
    lab.hosts["192.168.50.12"].name = "android-5f3a9c1d.lan"
    service.run()  # sin tipo antes (sin confianza): no es un cambio todavía
    lab.hosts["192.168.50.12"].name = "nintendo-switch.lan"
    service.run()

    db.expire_all()
    asset = db.scalar(select(Asset).where(Asset.primary_ip == "192.168.50.12"))
    assert asset is not None and asset.device_type == "console"
    changes = list(db.scalars(select(AssetChange).where(AssetChange.asset_id == asset.id)))
    kinds = [(c.category.value, c.kind.value, c.item) for c in changes]
    assert kinds == [("identity", "reclassified", "mobile -> console")]
    assert changes[0].details is not None and changes[0].details["to"] == "console"
    assert "discovery_job_id" in changes[0].details
    assert len(list(db.scalars(select(Alert)))) == alerts_before  # ninguna alerta nueva


def test_agent_becomes_authoritative_after_reconciliation(
    client: TestClient, engine: Engine, db: Session
) -> None:
    service = _service(engine, Lab(home()))
    service.run()
    discovered = db.scalar(select(Asset).where(Asset.primary_ip == "192.168.50.20"))
    assert discovered is not None and discovered.name_source == "mdns"
    discovered_id, discovered_at = discovered.id, discovered.discovered_at

    payload = agent_payload(
        hostname="Ravenslg", os_name="Linux", os_version="Ubuntu 24.04", primary_ip="192.168.50.20"
    )
    assert client.post("/api/v1/agents/register", json=payload).status_code == 201
    inventory = {
        "agent_id": payload["agent_id"],
        "collected_at": datetime.now(UTC).isoformat(),
        "interfaces": [
            {
                "name": "eth0",
                "mac": "a4:00:05:00:00:20",
                "addresses": ["192.168.50.20"],
                "is_up": True,
            }
        ],
    }
    assert client.post("/api/v1/inventory", json=inventory).status_code == 201

    db.expire_all()
    [managed] = db.scalars(select(Asset).where(Asset.primary_ip == "192.168.50.20")).all()
    assert db.get(Asset, discovered_id) is None
    assert managed.agent_id is not None and managed.discovered_at == discovered_at
    assert (managed.device_name, managed.name_source) == ("Ravenslg", "agent_hostname")
    assert managed.device_type == "pc" and managed.classification_confidence == "high"
    assert managed.probable_os is None and managed.os_name == "Linux"
    # Lo observado en la red se conserva como dato (no se pierde con la fusión).
    assert (managed.identity_observations or {}).get("mdns_name") == "ravenslg"
    assert managed.vendor == "Intel Corporate"

    # Un scan posterior no degrada al activo MANAGED a la inferencia de red.
    service.run()
    db.expire_all()
    db.refresh(managed)
    assert managed.device_name == "Ravenslg" and managed.device_type == "pc"


def test_heartbeat_updates_identity_without_extra_writes(client: TestClient, db: Session) -> None:
    payload = agent_payload(hostname="LAPTOP-AB12CD34", os_name="Windows", os_version="11 Pro")
    assert client.post("/api/v1/agents/register", json=payload).status_code == 201
    db.expire_all()
    asset = db.scalar(select(Asset).where(Asset.hostname == "LAPTOP-AB12CD34"))
    assert asset is not None and asset.device_type == "laptop"
    assert asset.device_name == "LAPTOP-AB12CD34" and asset.classification_confidence == "high"


def test_asset_list_has_no_n_plus_one(client: TestClient, engine: Engine) -> None:
    def count_queries(size: int) -> int:
        hosts = {
            f"192.168.50.{i}": Host({80}, mac=f"a4:00:01:00:00:{i:02x}") for i in range(1, size)
        }
        _service(engine, Lab(hosts)).run()
        statements: list[str] = []

        def record(*args: Any) -> None:
            statements.append(str(args[2]))

        event.listen(engine, "before_cursor_execute", record)
        try:
            assert client.get("/api/v1/assets").status_code == 200
        finally:
            event.remove(engine, "before_cursor_execute", record)
        return len(statements)

    small = count_queries(4)
    large = count_queries(24)
    assert small == large
