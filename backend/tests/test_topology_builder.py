"""Fase 6D: reglas de derivación del motor de topología SIN base de datos.

El constructor (app/topology/builder.py) es una función pura sobre filas ya leídas: estas
pruebas fijan cada regla del contrato (docs/topology-engine.md) de forma aislada y
determinista. Las pruebas con PostgreSQL y la API están en test_topology.py.
"""

import random
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.topology.builder import (
    AccessPointIn,
    AssetIn,
    ClientIn,
    DerivedLink,
    DeriveResult,
    DeviceIn,
    GatewayIn,
    InterfaceIn,
    MacIn,
    NeighborIn,
    Snapshot,
    derive_links,
    external_key,
    interface_names,
    link_key,
)

T0 = datetime(2026, 10, 21, 10, 0, tzinfo=UTC)
SW1, SW2 = 1, 2


def _uuid(n: int) -> UUID:
    return UUID(int=n)


def asset(n: int, ip: str | None = None, mac: str | None = None, archived: bool = False) -> AssetIn:
    return AssetIn(n, _uuid(1000 + n), ip, mac, archived)


def device(n: int, address: str, **kw: object) -> DeviceIn:
    return DeviceIn(n, _uuid(2000 + n), address, f"sw{n}", **kw)  # type: ignore[arg-type]


def iface(n: int, dev: int, name: str) -> InterfaceIn:
    return InterfaceIn(n, dev, name, interface_names(name))


def neighbor(n: int, dev: int, **kw: object) -> NeighborIn:
    return NeighborIn(n, dev, str(kw.pop("protocol", "lldp")), T0, **kw)  # type: ignore[arg-type]


def mac(n: int, dev: int, value: str, location: str, interface: int | None = 10) -> MacIn:
    return MacIn(n, dev, value, location, T0, interface_id=interface)


def node(kind: str, n: int) -> str:
    base = {"asset": 1000, "network_device": 2000, "wlan_ap": 3000}[kind]
    return f"{kind}:{_uuid(base + n)}"


def only(result: DeriveResult) -> DerivedLink:
    assert len(result.links) == 1, [(x.kind, x.relation) for x in result.links]
    return result.links[0]


def two_switches(**extra: object) -> Snapshot:
    """sw1 Gi1/0/1 <-> sw2 Gi0/24 vistos por LLDP desde los dos lados."""
    rows: dict[str, object] = {
        "devices": [device(SW1, "10.0.0.1"), device(SW2, "10.0.0.2")],
        "interfaces": [iface(10, SW1, "Gi1/0/1"), iface(20, SW2, "Gi0/24")],
        "neighbors": [
            neighbor(
                1,
                SW1,
                local_port="Gi1/0/1",
                interface_id=10,
                remote_device_id=SW2,
                remote_port="Gi0/24",
                reciprocal=True,
            ),
            neighbor(
                2,
                SW2,
                local_port="Gi0/24",
                interface_id=20,
                remote_device_id=SW1,
                remote_port="Gi1/0/1",
                reciprocal=True,
            ),
        ],
    }
    rows.update(extra)
    return Snapshot(**rows)  # type: ignore[arg-type]


# --- sin SNMP / sin LLDP ------------------------------------------------------------------------


def test_without_snmp_only_agent_gateways_and_wlan() -> None:
    # Sin equipos SNMP: el grafo muestra gateways de agentes y asociaciones WLAN, nunca un
    # enlace físico inventado por compartir red.
    host, router, phone = (
        asset(1, "192.168.1.20"),
        asset(2, "192.168.1.1"),
        asset(3, "192.168.1.30"),
    )
    ap = AccessPointIn(1, _uuid(3001), "ap-hall", T0)
    snap = Snapshot(
        assets=[host, router, phone],
        access_points=[ap],
        clients=[ClientIn(1, "confirmed", T0, asset_id=3, access_point_id=1, ssid="Corp")],
        gateways=[GatewayIn(1, ("192.168.1.1",), T0), GatewayIn(3, ("192.168.1.1",), T0)],
    )
    result = derive_links(snap)
    kinds = sorted((x.kind, x.relation, x.confidence) for x in result.links)
    assert kinds == [
        ("logical", "default_gateway", "medium"),
        ("logical", "default_gateway", "medium"),
        ("observed", "wlan_association", "high"),
    ]
    assert not [x for x in result.links if x.kind == "physical"]
    wlan = next(x for x in result.links if x.relation == "wlan_association")
    assert (wlan.source.node, wlan.target.node, wlan.medium) == (
        node("wlan_ap", 1),
        node("asset", 3),
        "wireless",
    )


def test_same_subnet_never_creates_links() -> None:
    snap = Snapshot(
        assets=[asset(i, f"10.1.0.{i}", f"00:11:22:33:44:{i:02x}") for i in range(1, 9)]
    )
    result = derive_links(snap)
    assert result.links == [] and result.nodes == 8


def test_without_lldp_fdb_edge_shared_uplink() -> None:
    pc, printer, tv, laptop = (
        asset(1, mac="00:aa:00:00:00:01"),
        asset(2, mac="00:aa:00:00:00:02"),
        asset(3, mac="00:aa:00:00:00:03"),
        asset(4, mac="00:aa:00:00:00:04"),
    )
    snap = Snapshot(
        assets=[pc, printer, tv, laptop],
        devices=[device(SW1, "10.0.0.1")],
        interfaces=[iface(10, SW1, "Gi1/0/3"), iface(11, SW1, "Gi1/0/4"), iface(12, SW1, "Te1/1")],
        macs=[
            mac(1, SW1, "00:aa:00:00:00:01", "edge_candidate", 10),
            mac(2, SW1, "00:aa:00:00:00:02", "edge_candidate", 11),
            mac(3, SW1, "00:aa:00:00:00:03", "edge_candidate", 11),
            mac(4, SW1, "00:aa:00:00:00:04", "uplink_or_shared", 12),
        ],
    )
    result = derive_links(snap)
    by_target = {x.target.node: x for x in result.links}
    assert set(by_target) == {node("asset", 1), node("asset", 2), node("asset", 3)}
    edge = by_target[node("asset", 1)]
    assert (edge.kind, edge.relation, edge.confidence, edge.source_port) == (
        "observed",
        "fdb_edge",
        "medium",
        "Gi1/0/3",
    )
    shared = by_target[node("asset", 2)]
    assert (shared.kind, shared.relation, shared.confidence) == ("candidate", "fdb_shared", "low")
    # El uplink ve todo lo de detrás: ningún enlace para el portátil.
    assert node("asset", 4) not in by_target


def test_fdb_unmapped_only_without_other_links() -> None:
    lone, gw_host = (
        asset(1, "10.0.0.50", "00:aa:00:00:00:01"),
        asset(2, "10.0.0.51", "00:aa:00:00:00:02"),
    )
    router = asset(3, "10.0.0.254")
    snap = Snapshot(
        assets=[lone, gw_host, router],
        devices=[device(SW1, "10.0.0.1")],
        macs=[
            mac(1, SW1, "00:aa:00:00:00:01", "unknown", None),
            mac(2, SW1, "00:aa:00:00:00:02", "unknown", None),
        ],
        gateways=[GatewayIn(2, ("10.0.0.254",), T0)],
    )
    result = derive_links(snap)
    unmapped = [x for x in result.links if x.relation == "fdb_unmapped"]
    assert [x.target.node for x in unmapped] == [node("asset", 1)]
    assert (unmapped[0].kind, unmapped[0].confidence) == ("unknown", "low")


# --- LLDP / CDP ----------------------------------------------------------------------------------


def test_lldp_reciprocal_is_one_high_link() -> None:
    link = only(derive_links(two_switches()))
    assert (link.kind, link.relation, link.confidence, link.medium) == (
        "physical",
        "lldp",
        "high",
        "wired",
    )
    ports = {link.source.node: link.source_port, link.target.node: link.target_port}
    assert ports == {node("network_device", 1): "Gi1/0/1", node("network_device", 2): "Gi0/24"}
    assert len(link.link_key) == 64 and len(link.evidence) == 2


def test_link_key_is_order_independent() -> None:
    a, b = ("asset:x", "gi1"), ("asset:y", "gi2")
    assert link_key("physical", "link_layer", a, b) == link_key("physical", "link_layer", b, a)
    assert link_key("physical", "link_layer", a, b) != link_key("observed", "link_layer", a, b)


def test_lldp_unilateral() -> None:
    snap = two_switches()
    resolved = Snapshot(
        devices=snap.devices, interfaces=snap.interfaces, neighbors=[snap.neighbors[0]]
    )
    link = only(derive_links(resolved))
    # El colector marcó reciprocidad (lo vio en otra consulta): high aunque falte la fila.
    assert link.confidence == "high"
    one_way = Snapshot(
        devices=snap.devices,
        interfaces=snap.interfaces,
        neighbors=[
            neighbor(1, SW1, local_port="Gi1/0/1", remote_device_id=SW2, remote_port="Gi0/24")
        ],
    )
    link = only(derive_links(one_way))
    assert (link.kind, link.confidence, link.source.node) == (
        "physical",
        "medium",
        node("network_device", 1),
    )


def test_lldp_resolves_assets_by_management_address_and_chassis() -> None:
    server = asset(1, "10.0.0.10", "00:bb:00:00:00:10")
    nas = asset(2, "10.0.0.11", "00:bb:00:00:00:11")
    snap = Snapshot(
        assets=[server, nas],
        devices=[device(SW1, "10.0.0.1")],
        neighbors=[
            neighbor(1, SW1, local_port="1", remote_mgmt_address="10.0.0.10", remote_port="eth0"),
            neighbor(2, SW1, local_port="2", remote_chassis_id="00-BB-00-00-00-11"),
        ],
    )
    targets = sorted((x.target.node, x.confidence) for x in derive_links(snap).links)
    assert targets == sorted([(node("asset", 1), "medium"), (node("asset", 2), "medium")])


def test_external_neighbor() -> None:
    snap = Snapshot(
        devices=[device(SW1, "10.0.0.1")],
        neighbors=[
            neighbor(
                1,
                SW1,
                local_port="Gi1/0/48",
                remote_chassis_id="00:cc:00:00:00:01",
                remote_sys_name="isp-cpe",
                remote_port="ge-0/0/0",
                remote_platform="Juniper",
            )
        ],
    )
    link = only(derive_links(snap))
    assert link.target.kind == "external" and link.target.ref_id is None
    assert link.target.node == external_key("00:cc:00:00:00:01", "isp-cpe", "x")
    assert link.target.node.startswith("external:") and len(link.target.node) == 25
    assert (link.confidence, link.target_external_label) == ("medium", "isp-cpe")
    assert link.target_external and link.target_external["platform"] == "Juniper"
    # Sin chasis, la clave sale del sysName; con ambos, el chasis manda.
    assert external_key(None, "ISP-CPE", "x") == external_key(" ", "isp-cpe", "y")
    assert external_key("00:cc:00:00:00:01", "a", "x") == external_key(
        "00:CC:00:00:00:01", "b", "x"
    )


def test_lldp_and_cdp_of_the_same_cable_merge() -> None:
    snap = two_switches()
    cdp = neighbor(
        3, SW1, protocol="cdp", local_port="Gi1/0/1", remote_device_id=SW2, remote_port="Gi0/24"
    )
    snap = Snapshot(
        devices=snap.devices, interfaces=snap.interfaces, neighbors=[*snap.neighbors, cdp]
    )
    link = only(derive_links(snap))
    assert link.relation == "lldp" and link.evidence_sources == ["cdp", "lldp"]
    assert link.confidence == "high"


# --- evidencias parciales, contradictorias y ambiguas --------------------------------------------


def test_lldp_wins_over_fdb_between_the_same_nodes() -> None:
    # Contradicción aparente: el switch ve la MAC del servidor en un puerto de acceso y LLDP
    # informa del cable. Solo queda el enlace físico (el de la tabla MAC sería redundante).
    server = asset(1, "10.0.0.10", "00:bb:00:00:00:10")
    snap = Snapshot(
        assets=[server],
        devices=[device(SW1, "10.0.0.1")],
        interfaces=[iface(10, SW1, "Gi1/0/5")],
        neighbors=[neighbor(1, SW1, local_port="Gi1/0/5", remote_mgmt_address="10.0.0.10")],
        macs=[mac(1, SW1, "00:bb:00:00:00:10", "edge_candidate", 10)],
    )
    link = only(derive_links(snap))
    assert link.kind == "physical"


def test_partial_wlan_identity_creates_nothing() -> None:
    snap = Snapshot(
        assets=[asset(1)],
        access_points=[AccessPointIn(1, _uuid(3001), "ap", T0)],
        clients=[
            ClientIn(1, "observation_only", T0, asset_id=1, access_point_id=1),
            ClientIn(2, "confirmed", T0, asset_id=1, access_point_id=None),
            ClientIn(3, "probable", T0, asset_id=None, access_point_id=1),
        ],
    )
    assert derive_links(snap).links == []


def test_duplicate_mac_in_site_creates_no_link() -> None:
    twin_a, twin_b = asset(1, mac="00:dd:00:00:00:01"), asset(2, mac="00:dd:00:00:00:01")
    snap = Snapshot(
        assets=[twin_a, twin_b],
        devices=[device(SW1, "10.0.0.1")],
        neighbors=[neighbor(1, SW1, local_port="7", remote_chassis_id="00:dd:00:00:00:01")],
        macs=[mac(1, SW1, "00:dd:00:00:00:01", "edge_candidate")],
    )
    result = derive_links(snap)
    assert result.ambiguous_macs == 1
    # Sin fusión ni elección: el vecino LLDP queda como identidad externa.
    assert [x.target.kind for x in result.links] == ["external"]


def test_gateway_ip_shared_by_two_assets_is_ignored() -> None:
    snap = Snapshot(
        assets=[asset(1, "10.0.0.20"), asset(2, "10.0.0.1"), asset(3, "10.0.0.1")],
        gateways=[GatewayIn(1, ("10.0.0.1",), T0)],
    )
    assert derive_links(snap).links == []


def test_gateway_with_ip_forwarding_is_high_and_device_with_asset_is_one_node() -> None:
    router = asset(2, "10.0.0.1")
    snap = Snapshot(
        assets=[asset(1, "10.0.0.20"), router],
        devices=[device(SW1, "10.0.0.1", asset_id=2, ip_forwarding=True)],
        gateways=[GatewayIn(1, ("10.0.0.1", "not-an-ip"), T0)],
    )
    link = only(derive_links(snap))
    assert link.target.node == node("asset", 2) and link.target.kind == "asset"
    assert (link.kind, link.confidence, link.evidence_sources) == (
        "logical",
        "high",
        ["agent", "snmp"],
    )
    assert derive_links(snap).nodes == 2


def test_wlan_managed_by_controller() -> None:
    snap = Snapshot(
        devices=[device(SW1, "10.0.0.5")],
        access_points=[
            AccessPointIn(1, _uuid(3001), "ap-1", T0, source_device_id=SW1),
            # AP autónomo consultado directamente: es el propio equipo, sin relación.
            AccessPointIn(2, _uuid(3002), "ap-2", T0, source_device_id=SW1, network_device_id=SW1),
            AccessPointIn(3, _uuid(3003), "ap-3", T0, present=False, source_device_id=SW1),
        ],
    )
    link = only(derive_links(snap))
    assert (link.kind, link.relation, link.confidence) == ("logical", "wlan_managed_by", "high")
    assert (link.source.node, link.target.node) == (node("network_device", 1), node("wlan_ap", 1))


# --- sites y archivados -------------------------------------------------------------------------


def test_reference_to_another_site_is_never_resolved() -> None:
    # remote_device_id de un equipo que no está en la entrada (es de otro site).
    snap = Snapshot(
        devices=[device(SW1, "10.0.0.1")],
        neighbors=[neighbor(1, SW1, local_port="1", remote_device_id=999, remote_sys_name="b")],
        access_points=[AccessPointIn(1, _uuid(3001), "ap", T0)],
        clients=[ClientIn(1, "confirmed", T0, asset_id=777, access_point_id=1)],
    )
    result = derive_links(snap)
    assert result.skipped_cross_site == 2
    assert [x.target.kind for x in result.links] == ["external"]


def test_archived_assets_and_devices_are_not_nodes() -> None:
    snap = Snapshot(
        assets=[asset(1, "10.0.0.20", "00:aa:00:00:00:01", archived=True), asset(2, "10.0.0.1")],
        devices=[device(SW1, "10.0.0.2"), device(SW2, "10.0.0.3", archived=True)],
        macs=[
            mac(1, SW1, "00:aa:00:00:00:01", "edge_candidate"),
            mac(2, SW2, "00:aa:00:00:00:09", "edge_candidate"),
        ],
        gateways=[GatewayIn(1, ("10.0.0.1",), T0)],
        access_points=[AccessPointIn(1, _uuid(3001), "ap", T0)],
        clients=[ClientIn(1, "confirmed", T0, asset_id=1, access_point_id=1)],
    )
    result = derive_links(snap)
    assert result.links == [] and result.skipped_cross_site == 0
    assert result.nodes == 3  # activo 2, sw1 y el AP


# --- determinismo y límites ---------------------------------------------------------------------


def _big_snapshot(seed: int) -> Snapshot:
    rng = random.Random(seed)  # noqa: S311 - orden reproducible, no criptografía
    assets = [
        asset(i, f"10.2.{i // 250}.{i % 250 + 1}", f"02:00:00:00:{i // 256:02x}:{i % 256:02x}")
        for i in range(1, 300)
    ]
    macs = [
        mac(
            i,
            SW1,
            a.mac or "",
            rng.choice(["edge_candidate", "unknown", "uplink_or_shared"]),
            10 + i % 40,
        )
        for i, a in enumerate(assets, start=1)
    ]
    base = two_switches()
    rows = Snapshot(
        assets=assets,
        devices=base.devices,
        interfaces=[iface(10 + i, SW1, f"Gi1/0/{i}") for i in range(40)],
        neighbors=base.neighbors,
        macs=macs,
        gateways=[
            GatewayIn(a.id, ("10.2.0.1",), T0 + timedelta(minutes=a.id)) for a in assets[1:50]
        ],
    )
    return rows


def _shuffled(snap: Snapshot, seed: int) -> Snapshot:
    rng = random.Random(seed)  # noqa: S311 - orden reproducible, no criptografía

    def mix[V](values: Sequence[V]) -> list[V]:
        out = list(values)
        rng.shuffle(out)
        return out

    return Snapshot(
        assets=mix(snap.assets),
        devices=mix(snap.devices),
        interfaces=mix(snap.interfaces),
        neighbors=mix(snap.neighbors),
        macs=mix(snap.macs),
        gateways=mix(snap.gateways),
    )


def test_derivation_is_deterministic() -> None:
    snap = _big_snapshot(7)
    first = derive_links(snap)
    second = derive_links(_shuffled(snap, 3))
    assert [(x.link_key, x.confidence, x.source.node, x.target.node) for x in first.links] == [
        (x.link_key, x.confidence, x.source.node, x.target.node) for x in second.links
    ]
    assert len({x.link_key for x in first.links}) == len(first.links)


def test_max_links_keeps_the_strongest_classes() -> None:
    snap = _big_snapshot(11)
    full = derive_links(snap)
    capped = derive_links(snap, max_links=5)
    assert len(capped.links) == 5 and capped.links_dropped == len(full.links) - 5
    assert capped.links[0].kind == "physical"
    assert capped.links == full.links[:5]


def test_random_uuid_nodes_do_not_collide() -> None:
    # Dos activos con la misma IP en distinto site nunca llegan juntos al constructor; aquí
    # se comprueba que dos claves distintas no se confunden aunque el resto coincida.
    one, two = AssetIn(1, uuid4(), "10.0.0.1", None), AssetIn(2, uuid4(), "10.0.0.2", None)
    assert derive_links(Snapshot(assets=[one, two])).nodes == 2
