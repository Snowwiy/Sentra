"""Fase 7E.1: decodificación, flujos, agregación, pipeline, configuración y runner de NDR."""

import io
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor.config import ConfigError, LocalConfig, load_config
from sentra_sensor.ndr import NDR_CAPABILITY
from sentra_sensor.ndr.capture import (
    ERR_NO_INTERFACE,
    ERR_PERMISSION,
    AfPacketBackend,
    CaptureError,
    DropCounters,
    LibpcapBackend,
    PcapFileBackend,
    RawFrame,
    load_libpcap,
    write_pcap,
)
from sentra_sensor.ndr.config import (
    NdrConfigError,
    NdrInterface,
    NdrLocalConfig,
    NdrServerConfig,
    parse_local_ndr,
)
from sentra_sensor.ndr.decode import DLT_EN10MB, DLT_NULL, decode_packet
from sentra_sensor.ndr.flows import FlowTable, ObservationAggregator
from sentra_sensor.ndr.pipeline import InterfaceCapture, NdrManager, split_batch
from sentra_sensor.ndr.tools import ndr_check, replay_pcap
from sentra_sensor.protocol import ServerConfig
from sentra_sensor.runner import SensorRunner
from sentra_sensor.spool import Spool
from tests import ndr_packets as pk
from tests.conftest import FakeServer, enroll_identity, server_config, track_resource

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08
T0 = 1_800_000_000.0


def dec(frame: bytes, ts: float = T0, linktype: int = DLT_EN10MB) -> Any:
    return decode_packet(frame, ts, len(frame), linktype)


# --- decodificación --------------------------------------------------------------------------


def test_decode_tcp_ipv4_with_vlan() -> None:
    frame = pk.ethernet(
        pk.MAC_A,
        pk.MAC_B,
        0x0800,
        pk.ipv4("10.0.0.5", "10.0.0.9", 6, pk.tcp(50000, 443, SYN)),
        vlan=20,
    )
    pkt = dec(frame)
    assert (pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port) == (
        "10.0.0.5",
        "10.0.0.9",
        50000,
        443,
    )
    assert pkt.vlan == 20 and pkt.tcp_flags == SYN and pkt.protocol == 6
    assert pkt.src_mac == pk.MAC_A and not pkt.malformed


def test_decode_ipv6_extension_header_and_icmpv6() -> None:
    payload = pk.icmp(128)
    frame = pk.ethernet(
        pk.MAC_A, pk.MAC_B, 0x86DD, pk.ipv6("fd00::1", "fd00::2", 58, payload, pk.hop_by_hop(58))
    )
    pkt = dec(frame)
    assert pkt.ip_version == 6 and pkt.protocol == 58 and pkt.icmp_type == 128
    assert pkt.src_ip == "fd00::1"


def test_decode_ipv4_non_first_fragment_has_no_ports() -> None:
    frame = pk.ethernet(
        pk.MAC_A,
        pk.MAC_B,
        0x0800,
        pk.ipv4("10.0.0.1", "10.0.0.2", 17, b"x" * 16, flags_fragment=10),
    )
    pkt = dec(frame)
    assert pkt.fragment and not pkt.first_fragment and pkt.src_port is None
    table = FlowTable(10, 60, 300)
    table.add(pkt)
    assert len(table) == 0 and table.stats.unattributed_fragments == 1


def test_decode_loopback_null_link() -> None:
    raw = (2).to_bytes(4, "little") + pk.ipv4("127.0.0.1", "127.0.0.1", 17, pk.udp(1, 2, b"hi"))
    pkt = dec(raw, linktype=DLT_NULL)
    assert pkt.src_ip == "127.0.0.1" and pkt.dst_port == 2


@pytest.mark.parametrize(
    "frame",
    [
        b"",
        b"\x00" * 10,
        pk.ethernet(pk.MAC_A, pk.MAC_B, 0x0800, b"\x45\x00"),
        pk.ethernet(pk.MAC_A, pk.MAC_B, 0x0800, b"\x4f" + b"\x00" * 19),
        pk.ethernet(pk.MAC_A, pk.MAC_B, 0x86DD, b"\x60" + b"\x00" * 10),
    ],
)
def test_malformed_frames_never_raise(frame: bytes) -> None:
    pkt = dec(frame)
    assert pkt.malformed or pkt.truncated or pkt.unsupported


def test_random_garbage_never_raises() -> None:
    rng = __import__("random").Random(7)
    for _ in range(2000):
        size = rng.randint(0, 200)
        data = bytes(rng.getrandbits(8) for _ in range(size))
        for linktype in (DLT_EN10MB, DLT_NULL, 101, 113):
            decode_packet(data, T0, size, linktype)


def test_truncated_tcp_header_keeps_addresses() -> None:
    frame = pk.ethernet(pk.MAC_A, pk.MAC_B, 0x0800, pk.ipv4("10.0.0.1", "10.0.0.2", 6, b"\x01\x02"))
    pkt = dec(frame)
    assert pkt.src_ip == "10.0.0.1" and pkt.truncated and not pkt.malformed


def test_dns_query_and_response_metadata() -> None:
    query = dec(pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("Example.COM")))
    assert query.dns is not None and query.dns.qname == "example.com" and not query.dns.is_response
    response = dec(
        pk.udp_frame(
            "10.0.0.53",
            "10.0.0.5",
            53,
            40000,
            pk.dns_response("example.com", ["93.184.216.34", "2606:2800::1"]),
        )
    )
    assert response.dns is not None and response.dns.rcode == "noerror"
    assert response.dns.answers == ("93.184.216.34", "2606:2800::1")
    nx = dec(
        pk.udp_frame(
            "10.0.0.53", "10.0.0.5", 53, 40000, pk.dns_response("nope.example", [], rcode=3)
        )
    )
    assert nx.dns is not None and nx.dns.rcode == "nxdomain"


def test_dns_pointer_loop_and_hostile_names_are_contained() -> None:
    loop = b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + b"\xc0\x0c" + b"\x00\x01\x00\x01"
    pkt = dec(pk.udp_frame("10.0.0.53", "10.0.0.5", 53, 40000, loop))
    assert pkt.dns is None and (pkt.truncated or pkt.malformed)
    hostile = dec(pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("<script>.evil")))
    assert hostile.dns is not None
    assert "<" not in hostile.dns.qname and ">" not in hostile.dns.qname


def test_dns_answers_are_bounded() -> None:
    addresses = [f"10.1.0.{i}" for i in range(1, 30)]
    pkt = dec(
        pk.udp_frame("10.0.0.53", "10.0.0.5", 53, 40000, pk.dns_response("many.example", addresses))
    )
    assert pkt.dns is not None and len(pkt.dns.answers) == 8


def test_dhcp_offer_metadata_ignores_hostname() -> None:
    frame = pk.udp_frame(
        "10.0.0.1",
        "255.255.255.255",
        67,
        68,
        pk.dhcp(2, pk.MAC_A, "10.0.0.50", "10.0.0.1", ["10.0.0.1"], ["10.0.0.53", "1.1.1.1"]),
        src_mac=pk.MAC_GW,
    )
    pkt = dec(frame)
    assert pkt.dhcp is not None and pkt.dhcp.message_type == "offer"
    assert pkt.dhcp.routers == ("10.0.0.1",) and pkt.dhcp.dns_servers == ("10.0.0.53", "1.1.1.1")
    assert "laptop" not in repr(pkt)


def test_tls_sni_extracted_without_payload() -> None:
    pkt = dec(
        pk.tcp_frame(
            "10.0.0.5",
            "203.0.113.7",
            50001,
            443,
            PSH | ACK,
            pk.tls_client_hello("Login.Example.org"),
        )
    )
    assert pkt.tls_sni == "login.example.org"


def test_arp_decoding_and_gratuitous() -> None:
    pkt = dec(pk.arp_frame(2, pk.MAC_GW, "10.0.0.1", "10.0.0.1", "ff:ff:ff:ff:ff:ff"))
    assert pkt.arp is not None and pkt.arp.gratuitous and pkt.arp.operation == 2


# --- flujos ----------------------------------------------------------------------------------


def _tcp(
    src: str,
    dst: str,
    sport: int,
    dport: int,
    flags: int,
    ts: float,
    payload: bytes = b"",
    seq: int = 1,
) -> Any:
    return dec(pk.tcp_frame(src, dst, sport, dport, flags, payload, seq), ts)


def test_bidirectional_flow_and_close() -> None:
    table = FlowTable(100, idle_timeout=60, active_timeout=300)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, SYN, T0))
    table.add(_tcp("10.0.0.9", "10.0.0.5", 80, 50000, SYN | ACK, T0 + 0.01))
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, ACK | PSH, T0 + 0.02, b"GET /", seq=2))
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, FIN | ACK, T0 + 0.03))
    table.add(_tcp("10.0.0.9", "10.0.0.5", 80, 50000, FIN | ACK, T0 + 0.04))
    assert len(table) == 1
    assert table.expire(T0 + 1) == []  # todavía en la espera de cierre
    [flow] = table.expire(T0 + 3)
    assert (flow["src_ip"], flow["dst_port"], flow["state"], flow["final"]) == (
        "10.0.0.5",
        80,
        "closed",
        True,
    )
    assert flow["packets_out"] == 3 and flow["packets_in"] == 2
    assert "midstream" not in flow["flags"] and "asymmetric" not in flow["flags"]


def test_synack_first_infers_client_correctly() -> None:
    table = FlowTable(100, 60, 300)
    table.add(_tcp("10.0.0.9", "10.0.0.5", 443, 50000, SYN | ACK, T0))
    [flow] = table.drain()
    assert flow["src_ip"] == "10.0.0.5" and flow["dst_port"] == 443


def test_midstream_and_asymmetric_are_flagged() -> None:
    table = FlowTable(100, 60, 300)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 22, ACK | PSH, T0, b"x"))
    [flow] = table.expire(T0 + 61)
    assert flow["state"] == "timeout" and {"midstream", "asymmetric"} <= set(flow["flags"])
    assert flow["dst_port"] == 22  # servicio inferido por el puerto


def test_reset_and_unanswered_syn() -> None:
    table = FlowTable(100, 60, 300)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 23, SYN, T0))
    table.add(_tcp("10.0.0.9", "10.0.0.5", 23, 50000, RST | ACK, T0 + 0.001))
    [flow] = table.expire(T0 + 5)
    assert flow["state"] == "reset" and "no_handshake_reply" in flow["flags"]


def test_active_timeout_segments_share_uid_and_cumulative_counters() -> None:
    table = FlowTable(100, idle_timeout=600, active_timeout=60)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 443, SYN, T0))
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 443, ACK, T0 + 30))
    first = table.expire(T0 + 61)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 443, ACK, T0 + 90))
    second = table.expire(T0 + 130)
    assert len(first) == len(second) == 1
    assert first[0]["uid"] == second[0]["uid"]
    assert (first[0]["segment"], second[0]["segment"]) == (0, 1)
    assert second[0]["packets_out"] == 3 and not second[0]["final"]


def test_eviction_when_table_is_full() -> None:
    table = FlowTable(2, 60, 300)
    for index in range(3):
        table.add(_tcp("10.0.0.5", "10.0.0.9", 50000 + index, 80, SYN, T0 + index))
    assert len(table) == 2 and table.stats.flows_evicted == 1
    exported = table.expire(T0 + 3)
    assert [f["state"] for f in exported] == ["evicted"]


def test_tuple_reuse_after_close_is_a_new_flow() -> None:
    table = FlowTable(10, 60, 300)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, SYN, T0))
    table.add(_tcp("10.0.0.9", "10.0.0.5", 80, 50000, RST, T0 + 0.1))
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, SYN, T0 + 0.2))
    exported = table.expire(T0 + 0.3)
    assert len(exported) == 1 and exported[0]["state"] == "reset"
    assert len(table) == 1


def test_retransmission_counter() -> None:
    table = FlowTable(10, 60, 300)
    table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, SYN, T0))
    for _ in range(3):
        table.add(_tcp("10.0.0.5", "10.0.0.9", 50000, 80, ACK | PSH, T0 + 1, b"data", seq=100))
    [flow] = table.drain()
    assert flow["retransmissions"] == 2 and "retransmissions" in flow["flags"]


def test_uid_differs_between_runs() -> None:
    a, b = FlowTable(10, 60, 300), FlowTable(10, 60, 300)
    pkt = _tcp("10.0.0.5", "10.0.0.9", 50000, 80, ACK, T0)
    a.add(pkt)
    b.add(pkt)
    assert a.drain()[0]["uid"] != b.drain()[0]["uid"]


# --- observaciones ---------------------------------------------------------------------------


def test_arp_unsolicited_reply_counted() -> None:
    agg = ObservationAggregator(arp=True, dns=False, dhcp=False, tls=False)
    agg.add(dec(pk.arp_frame(1, pk.MAC_A, "10.0.0.5", "10.0.0.1"), T0))
    agg.add(dec(pk.arp_frame(2, pk.MAC_GW, "10.0.0.1", "10.0.0.5", pk.MAC_A), T0 + 0.1))
    agg.add(dec(pk.arp_frame(2, pk.MAC_EVIL, "10.0.0.1", "10.0.0.5", pk.MAC_A), T0 + 30))
    replies = [e for e in agg.collect()["arp"] if e["operation"] == "reply"]
    by_mac = {e["sender_mac"]: e for e in replies}
    assert by_mac[pk.MAC_GW]["unsolicited"] == 0
    assert by_mac[pk.MAC_EVIL]["unsolicited"] == 1


def test_dns_aggregation_and_privacy_switch() -> None:
    agg = ObservationAggregator(arp=False, dns=True, dhcp=False, tls=False)
    agg.add(dec(pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("a.example")), T0))
    agg.add(
        dec(
            pk.udp_frame(
                "10.0.0.53", "10.0.0.5", 53, 40000, pk.dns_response("a.example", [], rcode=3)
            ),
            T0 + 0.1,
        )
    )
    [entry] = agg.collect()["dns"]
    assert entry["queries"] == 1 and entry["responses"] == 1 and entry["rcodes"] == {"nxdomain": 1}
    off = ObservationAggregator(arp=False, dns=False, dhcp=False, tls=False)
    off.add(
        dec(pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("secret.example")), T0)
    )
    assert off.collect()["dns"] == []


def test_dhcp_aggregation() -> None:
    agg = ObservationAggregator(arp=False, dns=False, dhcp=True, tls=False)
    frame = pk.udp_frame(
        "10.0.0.99",
        "255.255.255.255",
        67,
        68,
        pk.dhcp(2, pk.MAC_A, "10.0.0.50", "10.0.0.99", ["10.0.0.99"], ["10.0.0.99"]),
        src_mac=pk.MAC_EVIL,
    )
    agg.add(dec(frame, T0))
    [entry] = agg.collect()["dhcp"]
    assert entry["server_ip"] == "10.0.0.99" and entry["server_mac"] == pk.MAC_EVIL
    assert entry["routers"] == ["10.0.0.99"]


def test_observation_tables_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sentra_sensor.ndr.flows.MAX_DNS_ENTRIES", 5)
    agg = ObservationAggregator(arp=False, dns=True, dhcp=False, tls=False)
    for i in range(20):
        agg.add(
            dec(pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query(f"h{i}.example")), T0)
        )
    assert len(agg.collect()["dns"]) == 5 and agg.stats.overflow == 15


# --- pipeline --------------------------------------------------------------------------------


class FakeBackend:
    name = "fake"
    linktype = DLT_EN10MB

    def __init__(self, frames: list[bytes], fail: CaptureError | None = None) -> None:
        self.frames = frames
        self.fail = fail
        self.closed = False

    def open(self) -> None:
        if self.fail is not None:
            raise self.fail

    def read(self, timeout: float) -> list[RawFrame]:
        out = [RawFrame(T0 + i * 0.001, f, len(f)) for i, f in enumerate(self.frames)]
        self.frames = []
        return out

    def drops(self) -> DropCounters:
        return DropCounters(kernel=7)

    def close(self) -> None:
        self.closed = True


def _server_ndr(**overrides: Any) -> NdrServerConfig:
    data: dict[str, Any] = {
        "enabled": True,
        "revision": 1,
        "interfaces": ["lan"],
        "arp_metadata": True,
        "dns_metadata": True,
        "dhcp_metadata": True,
        "export_interval_seconds": 10,
    }
    data.update(overrides)
    parsed = NdrServerConfig.parse(data)
    assert parsed is not None
    return parsed


def test_capture_exports_batch_with_quality_stats() -> None:
    frames = [
        pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000, 80, SYN),
        pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("x.example")),
        b"\x00" * 5,  # malformado
    ]
    batches: list[dict[str, Any]] = []
    capture = InterfaceCapture(
        NdrInterface("lan", "eth9"),
        _server_ndr(),
        lambda _i, _c: FakeBackend(frames),
        lambda _n, b: batches.append(b),
    )
    capture.run_once(0.1)
    capture.stop()
    [batch] = batches
    stats = batch["stats"]
    assert stats["packets_seen"] == 3 and stats["malformed"] == 1
    assert stats["kernel_dropped"] == 7 and batch["interface"] == "lan"
    assert len(batch["flows"]) == 2 and len(batch["dns"]) == 1
    assert "eth9" not in json.dumps(batch)  # el nombre del dispositivo no sale del host


def test_packet_budget_drops_and_reports_degraded() -> None:
    frames = [pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000 + i, 80, SYN) for i in range(400)]
    batches: list[dict[str, Any]] = []
    capture = InterfaceCapture(
        NdrInterface("lan", "eth9"),
        _server_ndr(max_packets_per_second=100),
        lambda _i, _c: FakeBackend(frames),
        lambda _n, b: batches.append(b),
    )
    capture.run_once(0.1)
    capture.stop()
    stats = batches[0]["stats"]
    assert stats["budget_dropped"] >= 250
    assert "packet_budget" in stats["degraded_reasons"]


def test_capture_error_is_reported_not_raised() -> None:
    capture = InterfaceCapture(
        NdrInterface("lan", "eth9"),
        _server_ndr(),
        lambda _i, _c: FakeBackend([], CaptureError(ERR_PERMISSION, "needs CAP_NET_RAW")),
        lambda _n, _b: None,
    )
    capture.run_once(0.1)
    assert capture.status.state == "error" and capture.status.error_code == ERR_PERMISSION


def test_split_batch_respects_record_limit() -> None:
    batch = {
        "interface": "lan",
        "flows": [{"i": i} for i in range(5)],
        "dns": [{"d": 1}],
        "stats": {"a": 1},
    }
    parts = split_batch(batch, 2)
    assert len(parts) == 3 and sum(len(p["flows"]) + len(p["dns"]) for p in parts) == 6
    assert parts[0]["stats"] == {"a": 1} and parts[1]["stats"] is None


def test_split_batch_respects_byte_budget() -> None:
    big = "x" * 900
    batch = {"interface": "lan", "flows": [{"pad": big} for _ in range(40)], "stats": {}}
    parts = split_batch(batch, 1000, max_bytes=16 * 1024)
    assert len(parts) > 1 and sum(len(p["flows"]) for p in parts) == 40
    for part in parts:
        assert len(json.dumps(part)) < 16 * 1024


def test_manager_requires_local_declaration_and_revision() -> None:
    queued: list[tuple[str, dict[str, Any]]] = []
    local = NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lan", "eth9"),))
    manager = NdrManager(
        local, lambda n, b: queued.append((n, b)), lambda _i, _c: FakeBackend([]), threaded=False
    )
    manager.apply(_server_ndr(interfaces=["lan", "dmz"]))
    assert set(manager.captures) == {"lan"} and manager.unknown_interfaces == ["dmz"]
    health = manager.health()
    assert {i["name"] for i in health["interfaces"]} == {"lan", "dmz"}
    first = manager.captures["lan"]
    manager.apply(_server_ndr(interfaces=["lan", "dmz"]))
    assert manager.captures["lan"] is first  # misma revisión: no reinicia
    manager.apply(None)
    assert manager.captures == {} and manager.health()["state"] == "not_configured"
    off = NdrManager(NdrLocalConfig(), lambda n, b: None, threaded=False)
    off.apply(_server_ndr())
    assert off.captures == {} and off.health()["state"] == "disabled"


def test_batch_ids_are_stable_per_envelope() -> None:
    queued: list[dict[str, Any]] = []
    local = NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lan", "eth9"),))
    manager = NdrManager(local, lambda _n, b: queued.append(b), threaded=False)
    manager.server = _server_ndr(max_records_per_batch=50)
    manager._emit("lan", {"interface": "lan", "flows": [{"i": i} for i in range(120)], "stats": {}})
    ids = [b["batch_id"] for b in queued]
    assert len(ids) == 3 and len(set(ids)) == 3


# --- configuración ---------------------------------------------------------------------------


def test_local_ndr_section_parsing(tmp_path: Path) -> None:
    toml = tmp_path / "sensor.toml"
    toml.write_text(
        '[sensor]\nserver_url = "https://sentra.example"\n'
        f'data_dir = "{(tmp_path / "data").as_posix()}"\n'
        '[ndr]\nenabled = true\n[[ndr.interfaces]]\nname = "lan-span"\ndevice = "eth1"\n'
    )
    config = load_config(toml)
    assert config.ndr.enabled and config.ndr.interface("lan-span") == NdrInterface(
        "lan-span", "eth1"
    )


@pytest.mark.parametrize(
    "raw",
    [
        {"enabled": True},
        {"enabled": "yes", "interfaces": []},
        {"interfaces": [{"name": "LAN", "device": "eth0"}]},
        {"interfaces": [{"name": "a", "device": "eth0; rm -rf /"}]},
        {"interfaces": [{"name": "a", "device": "eth0", "filter": "tcp"}]},
        {"backend": "raw"},
        {"unknown": 1},
    ],
)
def test_local_ndr_section_rejects_invalid(raw: dict[str, Any]) -> None:
    with pytest.raises(NdrConfigError):
        parse_local_ndr(raw)


def test_server_ndr_block_is_clamped_and_filtered() -> None:
    parsed = NdrServerConfig.parse(
        {
            "enabled": True,
            "revision": 3,
            "interfaces": ["lan", "../etc", "\\Device\\NPF_x"],
            "max_flows": 10**9,
            "snaplen": 1,
            "bpf_filter": "anything",
        }
    )
    assert parsed is not None
    assert parsed.interfaces == ("lan",) and parsed.max_flows == 500_000 and parsed.snaplen == 96
    assert NdrServerConfig.parse({"enabled": True}) is None
    config = ServerConfig.parse(server_config())
    assert config.ndr is None


# --- backends ---------------------------------------------------------------------------------


def test_pcap_file_roundtrip_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "synthetic.pcap"
    write_pcap(
        path,
        [
            (T0, pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000, 80, SYN)),
            (T0 + 1, pk.arp_frame(1, pk.MAC_A, "10.0.0.5", "10.0.0.1")),
        ],
    )
    backend = PcapFileBackend(path)
    backend.open()
    frames = backend.read(0.1)
    assert len(frames) == 2 and backend.exhausted and frames[0].timestamp == pytest.approx(T0)
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)  # pcapng
    with pytest.raises(CaptureError):
        PcapFileBackend(bad).open()


def test_af_packet_unknown_interface() -> None:
    if not sys.platform.startswith("linux"):
        pytest.skip("AF_PACKET solo existe en Linux")
    with pytest.raises(CaptureError) as info:
        AfPacketBackend("sentra-no-such0", 256, False).open()
    assert info.value.code == ERR_NO_INTERFACE


def _loopback_capture(backend: Any) -> list[Any]:
    """Abre la captura en lo, envía datagramas UDP a 127.0.0.1 y devuelve lo decodificado."""
    try:
        backend.open()
    except CaptureError as exc:
        pytest.skip(f"capture not available here: {exc.code}")
    marker_port = 47_000 + os.getpid() % 1000
    stop = threading.Event()

    def sender() -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            while not stop.is_set():
                sock.sendto(b"sentra-ndr-test", ("127.0.0.1", marker_port))
                time.sleep(0.05)

    thread = threading.Thread(target=sender, daemon=True)
    thread.start()
    found: list[Any] = []
    deadline = time.monotonic() + 5
    try:
        while time.monotonic() < deadline and not found:
            for frame in backend.read(0.3):
                pkt = decode_packet(
                    frame.data, frame.timestamp, frame.wire_length, backend.linktype
                )
                if pkt.dst_port == marker_port:
                    found.append(pkt)
    finally:
        stop.set()
        thread.join()
        backend.close()
    return found


def test_af_packet_real_loopback_capture() -> None:
    """Captura REAL en Linux (no sintética): necesita CAP_NET_RAW; si no, se omite."""
    if not sys.platform.startswith("linux"):
        pytest.skip("AF_PACKET solo existe en Linux")
    found = _loopback_capture(AfPacketBackend("lo", 256, False))
    assert found and found[0].src_ip == "127.0.0.1" and found[0].protocol == 17


def test_libpcap_real_loopback_capture() -> None:
    """Captura REAL con libpcap por ctypes (Linux/macOS con libpcap instalada)."""
    if sys.platform == "win32":
        pytest.skip("en Windows se prueba con Npcap en la QA física")
    try:
        load_libpcap()
    except CaptureError:
        pytest.skip("libpcap no instalada")
    device = "lo" if sys.platform.startswith("linux") else "lo0"
    found = _loopback_capture(LibpcapBackend(device, 256, False))
    assert found and found[0].dst_ip == "127.0.0.1"


def test_npcap_missing_is_reported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", str(tmp_path))
    with pytest.raises(CaptureError) as info:
        load_libpcap("win32")
    assert info.value.code == "npcap_missing"


# --- runner ----------------------------------------------------------------------------------


def _ndr_config(data_dir: Path) -> LocalConfig:
    return LocalConfig(
        server_url="http://127.0.0.1:8000",
        data_dir=data_dir,
        ndr=NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lan", "eth9"),)),
    ).validate()


def _ndr_runner(config: LocalConfig, server: FakeServer, frames: list[bytes]) -> SensorRunner:
    store = enroll_identity(config)
    runner = track_resource(SensorRunner(config, server, store=store, threaded_jobs=False))
    # Sustituye el gestor real por uno con un backend falso: nunca se abre una interfaz real.
    if runner.ndr is not None:
        runner.ndr.stop()
    runner.ndr = NdrManager(
        config.ndr, runner._enqueue_ndr, lambda _i, _c: FakeBackend(frames), threaded=False
    )
    return runner


def test_runner_reports_ndr_only_when_server_supports_it(data_dir: Path) -> None:
    config = _ndr_config(data_dir)
    server = FakeServer()
    runner = _ndr_runner(config, server, [])
    runner.tick()
    first = server.requests[0][2]
    assert NDR_CAPABILITY in first["capabilities"] and "ndr" not in first
    server.config = server_config(ndr={"enabled": True, "revision": 1, "interfaces": ["lan"]})
    runner.next_heartbeat_at = 0
    runner.tick()
    runner.next_heartbeat_at = 0
    runner.tick()
    last = [b for p, _h, b in server.requests if p == "/sensor/heartbeat"][-1]
    assert last["ndr"]["state"] in ("running", "starting") and last["ndr"]["config_revision"] == 1
    assert "eth9" not in json.dumps(last)


def test_runner_sends_ndr_batches_and_discards_unauthorized(data_dir: Path) -> None:
    config = _ndr_config(data_dir)
    server = FakeServer()
    server.config = server_config(ndr={"enabled": True, "revision": 1, "interfaces": ["lan"]})
    frames = [pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000, 80, SYN)]
    runner = _ndr_runner(config, server, frames)
    runner.tick()
    capture = runner.ndr.captures["lan"]
    capture.run_once(0.1)
    capture._export(final=True)
    runner.flush()
    assert len(server.ndr_batches) == 1
    batch = next(iter(server.ndr_batches.values()))
    assert batch["flows"][0]["dst_port"] == 80
    capture._export(final=False)
    server.fail_next.append(("/sensor/ndr/batches", 403, "ndr_not_authorized"))
    runner.flush()
    assert runner.ndr_spool is not None and runner.ndr_spool.stats().items == 0
    assert len(server.ndr_batches) == 1


def test_disabled_sensor_stops_capture(data_dir: Path) -> None:
    config = _ndr_config(data_dir)
    server = FakeServer()
    server.config = server_config(ndr={"enabled": True, "revision": 1, "interfaces": ["lan"]})
    runner = _ndr_runner(config, server, [])
    runner.tick()
    assert runner.ndr.captures
    server.status = "disabled"
    runner.next_heartbeat_at = 0
    runner.tick()
    assert runner.ndr.captures == {}


def test_ndr_spool_is_separate_and_private(data_dir: Path) -> None:
    config = _ndr_config(data_dir)
    runner = _ndr_runner(config, FakeServer(), [])
    assert runner.ndr_spool is not None and runner.ndr_spool.path != runner.spool.path
    assert isinstance(runner.ndr_spool, Spool)
    plain = LocalConfig(server_url="http://127.0.0.1:8000", data_dir=data_dir / "plain").validate()
    plain.ensure_data_dir()
    assert not plain.ndr_spool_file().exists()


def test_invalid_toml_ndr_raises_config_error(tmp_path: Path) -> None:
    toml = tmp_path / "sensor.toml"
    toml.write_text("[ndr]\nenabled = true\n")
    with pytest.raises(ConfigError):
        load_config(toml)


# --- Herramientas locales: ndr-check y ndr-replay -------------------------------------------


def test_ndr_check_reports_missing_interface_and_backend() -> None:
    local = NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lan", "nope-iface0"),))
    report = ndr_check(local)
    assert report["enabled"] is True
    assert report["interfaces"] == [
        {"name": "lan", "device": "nope-iface0", "present": False, "up": None}
    ]
    assert report["ok"] is False
    lo = NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lo", "lo"),))
    if sys.platform.startswith("linux"):
        assert ndr_check(lo)["interfaces"][0]["present"] is True
    assert ndr_check(NdrLocalConfig())["ok"] is True


def test_ndr_check_without_npcap_on_windows(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SystemRoot", str(tmp_path))
    local = NdrLocalConfig(enabled=True, interfaces=(NdrInterface("lan", "eth0"),))
    report = ndr_check(local, platform="win32")
    assert report["backend"]["ok"] is False
    assert report["backend"]["code"] == "npcap_missing"
    assert report["ok"] is False


def test_ndr_replay_processes_pcap_without_network(tmp_path: Path) -> None:
    path = tmp_path / "lab.pcap"
    write_pcap(
        path,
        [
            (T0, pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000, 443, SYN)),
            (T0 + 0.1, pk.tcp_frame("10.0.0.9", "10.0.0.5", 443, 50000, SYN | ACK)),
            (T0 + 0.2, pk.udp_frame("10.0.0.5", "10.0.0.53", 40000, 53, pk.dns_query("a.example"))),
            (T0 + 0.3, b"\x00" * 7),
        ],
    )
    result = replay_pcap(path)
    summary = result["summary"]
    assert summary["packets_seen"] == 4 and summary["malformed"] == 1
    assert summary["flows"] == 2 and summary["dns"] == 1
    assert {f["dst_port"] for f in result["batches"][0]["flows"]} == {443, 53}


def test_ndr_replay_rejects_pcapng(tmp_path: Path) -> None:
    path = tmp_path / "x.pcapng"
    path.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 40)
    with pytest.raises(CaptureError) as info:
        replay_pcap(path)
    assert info.value.code == "unsupported_link_type"


def test_cli_ndr_commands(tmp_path: Path) -> None:
    from sentra_sensor.cli import main

    pcap = tmp_path / "lab.pcap"
    write_pcap(pcap, [(T0, pk.tcp_frame("10.0.0.5", "10.0.0.9", 50000, 80, SYN))])
    out = io.StringIO()
    assert main(["--data-dir", str(tmp_path / "d"), "ndr-replay", str(pcap)], out=out) == 0
    assert json.loads(out.getvalue())["flows"] == 1
    out = io.StringIO()
    assert main(["--data-dir", str(tmp_path / "d"), "ndr-check"], out=out) == 0
    assert "NDR enabled:    no" in out.getvalue()
    out = io.StringIO()
    assert main(["--data-dir", str(tmp_path / "d"), "status"], out=out) == 0
    assert "NDR:            disabled" in out.getvalue()


def test_example_config_ndr_block_parses(tmp_path: Path) -> None:
    example = Path(__file__).resolve().parents[1] / "sensor.example.toml"
    text = example.read_text(encoding="utf-8")
    # Hasta la sección siguiente del ejemplo (7F, receptores SIEM).
    block = text[text.index("# [ndr]") : text.index("# --- Fase 7F")]
    uncommented = "\n".join(
        line[2:] if line.startswith("# ") and not line.startswith("# Requisitos") else ""
        for line in block.splitlines()
    )
    cfg = tmp_path / "sensor.toml"
    cfg.write_text(f'[sensor]\ndata_dir = "{tmp_path.as_posix()}/d"\n\n{uncommented}\n')
    config = load_config(cfg, {})
    assert config.ndr.enabled and config.ndr.interfaces == (NdrInterface("lan", "eth1"),)
