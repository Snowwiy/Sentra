"""Fase 7B-Fix1: topología doméstica (Archer GX90 sin SNMP) con evidencia incompleta.

12 nodos y 3 enlaces en 192.168.50.0/24: el builder solo enlaza con evidencia (LLDP/CDP,
FDB, asociación Wi-Fi, gateway del agente). Aquí se comprueba que una asociación Wi-Fi
verificada sin AP inventariado se dibuja hacia un nodo BSS externo y que nunca se inventan
enlaces al gateway por compartir subred.
"""

from app.topology.builder import AccessPointIn, ClientIn, GatewayIn, Snapshot, derive_links
from tests.test_topology_builder import T0, _uuid, asset, node

BSSID = "50:91:e3:00:00:01"


def _home(*clients: ClientIn, gateways: tuple[GatewayIn, ...] = ()) -> Snapshot:
    return Snapshot(
        assets=[asset(n, f"192.168.50.{n}") for n in (1, 66, 67, 69, 71, 201)],
        clients=list(clients),
        gateways=list(gateways),
    )


def test_agent_association_without_ap_links_to_an_external_bss() -> None:
    laptop = ClientIn(1, "confirmed", T0, asset_id=201, ssid="Casa", bssid=BSSID)
    pc = ClientIn(2, "confirmed", T0, asset_id=66, ssid="Casa", bssid=BSSID.upper())
    result = derive_links(_home(laptop, pc))
    assert len(result.links) == 2
    targets = {link.target.node for link in result.links}
    assert len(targets) == 1 and next(iter(targets)).startswith("external:")
    link = result.links[0]
    assert (link.kind, link.medium, link.relation, link.confidence) == (
        "observed",
        "wireless",
        "wlan_association",
        "high",
    )
    assert link.target_external == {"protocol": "wlan", "bssid": BSSID, "ssid": "Casa"}
    assert link.target_external_label == "Wi-Fi Casa"
    assert result.external_nodes == sorted(targets)


def test_unverified_or_private_mac_clients_get_no_link() -> None:
    # Cliente visto por un controlador con MAC privada sin correlacionar: sin identidad.
    phone = ClientIn(3, "observation_only", T0, asset_id=67, ssid="Casa", bssid=BSSID)
    no_bssid = ClientIn(4, "confirmed", T0, asset_id=69, ssid="Casa")
    assert derive_links(_home(phone, no_bssid)).links == []


def test_same_subnet_never_creates_gateway_links() -> None:
    result = derive_links(_home())
    assert result.links == []
    # Solo el gateway que informa un agente crea la relación lógica.
    report = GatewayIn(asset_id=201, gateways=("192.168.50.1",), collected_at=T0)
    (link,) = derive_links(_home(gateways=(report,))).links
    assert (link.relation, link.source.node, link.target.node) == (
        "default_gateway",
        node("asset", 201),
        node("asset", 1),
    )


def test_mixed_topology_prefers_the_inventoried_ap() -> None:
    ap = AccessPointIn(1, _uuid(3001), "archer", T0)
    snap = Snapshot(
        assets=[asset(201, "192.168.50.201"), asset(66, "192.168.50.66")],
        access_points=[ap],
        clients=[
            ClientIn(1, "confirmed", T0, asset_id=201, access_point_id=1, bssid=BSSID),
            ClientIn(2, "probable", T0, asset_id=66, bssid="aa:bb:cc:00:00:02"),
        ],
    )
    links = {link.target.kind: link for link in derive_links(snap).links}
    assert links["asset"].source.node == node("wlan_ap", 1)
    assert links["external"].confidence == "medium"
