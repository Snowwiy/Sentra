import ipaddress
import json
import sys
from datetime import datetime
from pathlib import Path

import pytest

from sentra_agent.collectors import collect_host_info, collect_metrics
from sentra_agent.config import load_config
from sentra_agent.identity import IdentityStore
from sentra_agent.inventory import collect_inventory


def test_config_precedence_file_env_cli(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file = tmp_path / "agent.toml"
    config_file.write_text('api_url = "http://file:8000"\ninterval_seconds = 60\nbuffer_size = 7\n')
    monkeypatch.setenv("SENTRA_AGENT_INTERVAL_SECONDS", "45")

    config = load_config(config_file, {"api_url": "http://cli:8000"})

    assert config.api_url == "http://cli:8000"
    assert config.interval_seconds == 45
    assert config.buffer_size == 7


@pytest.mark.parametrize(
    "content",
    ['api_url = "ftp://x"', "interval_seconds = 1", "buffer_size = 0", 'unknown_key = "x"'],
)
def test_invalid_config_is_rejected(tmp_path: Path, content: str) -> None:
    config_file = tmp_path / "agent.toml"
    config_file.write_text(content)

    with pytest.raises(ValueError):
        load_config(config_file)


def test_identity_is_created_once_and_persisted(tmp_path: Path) -> None:
    store = IdentityStore(tmp_path / "state")

    first = store.load_or_create()
    second = IdentityStore(tmp_path / "state").load_or_create()

    assert first.agent_id == second.agent_id
    assert json.loads(store.path.read_text())["agent_id"] == str(first.agent_id)
    assert list(store.path.parent.glob(".identity-*")) == []  # no temp files left behind


def test_host_info_is_valid_for_registration() -> None:
    info = collect_host_info()

    assert info.hostname
    assert info.os_name
    assert len(info.architecture) <= 32
    ipaddress.ip_address(info.primary_ip)


def test_metrics_are_real_and_within_bounds() -> None:
    metrics = collect_metrics()

    for key in ("cpu_percent", "ram_percent", "disk_percent"):
        assert 0 <= metrics[key] <= 100
    assert metrics["ram_percent"] > 0  # a running machine always uses some memory
    assert metrics["uptime_seconds"] > 0
    assert datetime.fromisoformat(metrics["timestamp"]).utcoffset() is not None


def test_inventory_snapshot_is_real_and_bounded() -> None:
    snapshot = collect_inventory()

    assert datetime.fromisoformat(snapshot["collected_at"]).utcoffset() is not None
    assert snapshot["interfaces"], "every host has at least a loopback interface"
    for interface in snapshot["interfaces"]:
        for address in interface["addresses"]:
            ipaddress.ip_address(address)  # zone suffixes stripped
    assert snapshot["processes"], "the test process itself is running"
    assert len(snapshot["processes"]) <= 100
    memory = [p["memory_bytes"] for p in snapshot["processes"]]
    assert memory == sorted(memory, reverse=True)
    if sys.platform == "win32":
        assert snapshot["services"], "Windows always has services"
        assert all(s["status"] for s in snapshot["services"])


def test_real_disks_and_connections_are_reported() -> None:
    snapshot = collect_inventory()

    assert snapshot["disks"], "the system drive is always mounted"
    for disk in snapshot["disks"]:
        assert disk["total_bytes"] >= disk["used_bytes"] >= 0
        assert 0 <= disk["percent"] <= 100
    assert len(snapshot["connections"]) <= 1000
    for conn in snapshot["connections"]:
        assert conn["protocol"] in ("tcp", "udp")
        assert conn["status"] in ("listen", "established")
        if conn["local_address"]:
            ipaddress.ip_address(conn["local_address"])
    statuses = [c["status"] for c in snapshot["connections"]]
    assert statuses == sorted(statuses, key=lambda s: s != "listen"), "listeners first"
