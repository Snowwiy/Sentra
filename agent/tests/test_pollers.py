"""Fase 6E.3: sondeos con diff y lectores de estado del equipo (fixtures, sin el sistema)."""

import json
import os
import sys
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import endpoint
from sentra_agent.activity import ACTIVE, ERROR, PERMISSION_DENIED, UNAVAILABLE
from sentra_agent.endpoint import (
    CollectorUnavailableError,
    parse_defender,
    parse_firewall_profiles,
    parse_schtasks_csv,
    parse_socketfilterfw,
    parse_timer_unit_files,
    parse_ufw_conf,
    read_firewall,
    read_persistence,
    read_scheduled_tasks,
)
from sentra_agent.pollers import DiffPoller, StatePoller
from sentra_agent.syscmd import CommandOutput


def service(status: str = "running", start: str = "auto") -> dict[str, Any]:
    return {"name": "svc", "display_name": "Svc", "start_type": start, "status": status,
            "exe": None, "username": None}  # fmt: skip


def test_diff_poller_baseline_then_changes(tmp_path: Path) -> None:
    state: dict[str, dict[str, Any]] = {"svc": service()}
    poller = DiffPoller("service", "service_poll", lambda: dict(state), tmp_path / "b.json")

    assert poller.poll(1000.0) == []  # primera vez en este equipo: solo línea base

    state["svc"] = service(status="stopped")
    state["new"] = {**service(), "name": "new"}
    events = poller.poll(1001.0)
    assert sorted(e["action"] for e in events) == ["created", "stopped"]

    state["svc"] = service(status="stopped", start="disabled")
    del state["new"]
    events = poller.poll(1002.0)
    assert sorted(e["action"] for e in events) == ["deleted", "modified"]
    deleted = next(e for e in events if e["action"] == "deleted")
    assert deleted["data"]["name"] == "new" and deleted["category"] == "service"


def test_baseline_survives_restart(tmp_path: Path) -> None:
    state = {"a": {"mechanism": "cron", "location": "/etc/cron.d/a", "name": "a",
                   "target": None, "_fp": "1"}}  # fmt: skip
    path = tmp_path / "baseline.json"
    DiffPoller("persistence", "persistence_poll", lambda: dict(state), path).poll(1.0)

    state["b"] = {**state["a"], "location": "/etc/cron.d/b", "name": "b"}
    restarted = DiffPoller("persistence", "persistence_poll", lambda: dict(state), path)
    [created] = restarted.poll(2.0)
    assert created["action"] == "created" and created["data"]["name"] == "b"
    assert "_fp" not in created["data"]  # huellas internas nunca salen


def test_reader_failures_set_status_and_keep_baseline(tmp_path: Path) -> None:
    outcome: dict[str, Any] = {"records": {"svc": service()}}

    def reader() -> dict[str, dict[str, Any]]:
        if isinstance(outcome["records"], Exception):
            raise outcome["records"]
        return dict(outcome["records"])

    poller = DiffPoller("service", "service_poll", reader, tmp_path / "b.json")
    poller.poll(1.0)
    for error, status in (
        (PermissionError("no"), PERMISSION_DENIED),
        (CollectorUnavailableError("no"), UNAVAILABLE),
        (RuntimeError("boom"), ERROR),
    ):
        outcome["records"] = error
        assert poller.poll(2.0) == []
        assert poller.status == status
    # Tras el fallo, la línea base sigue: no aparece un "deleted" masivo ni un "created".
    outcome["records"] = {"svc": service()}
    assert poller.poll(3.0) == []
    assert poller.status == ACTIVE


def test_state_poller_emits_on_first_read_and_on_change() -> None:
    value = {"domain": {"profile": "domain", "enabled": True, "default_inbound": "block",
                        "default_outbound": "allow"}}  # fmt: skip
    poller = StatePoller("firewall", "firewall_poll", lambda: json.loads(json.dumps(value)))
    assert [e["action"] for e in poller.poll(1.0)] == ["state"]
    assert poller.poll(2.0) == []
    value["domain"]["enabled"] = False
    [changed] = poller.poll(3.0)
    assert changed["data"]["enabled"] is False and changed["category"] == "firewall"


SCHTASKS = (
    '"PC","\\Microsoft\\Windows\\Defrag\\ScheduledDefrag","N/A","Ready","Interactive","x","0",'
    '"Microsoft","%windir%\\system32\\defrag.exe -c -h -o","N/A","Optimiza","Enabled","x","x",'
    '"SYSTEM","x","x","Weekly","Weekly","1:00:00","1/1/2026","N/A","SUN","x","x"\r\n'
    '"PC","\\Updater","N/A","Ready","Interactive","x","0","Me",'
    '"C:\\Tools\\upd.exe --token abc","N/A","","Deshabilitado","x","x","Me","x","x","Diario",'
    '"Diario","9:00","1/1/2026","N/A","x","x","x"\r\n'
)


def test_parse_schtasks_csv_redacts_and_reads_state() -> None:
    records = parse_schtasks_csv(SCHTASKS)
    defrag = records["\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"]
    assert defrag["name"] == "ScheduledDefrag" and defrag["enabled"] is True
    updater = records["\\Updater"]
    assert updater["enabled"] is False
    assert "abc" not in updater["exe"]


def test_parse_timers_defender_firewall_and_macos() -> None:
    timers = parse_timer_unit_files("apt-daily.timer enabled enabled\nfoo.timer disabled enabled\n")
    assert timers["apt-daily.timer"]["enabled"] is True and timers["foo.timer"]["enabled"] is False

    defender = parse_defender('{"realtime":true,"antivirus":true,"tamper":false,"age":2}')
    assert defender["defender"]["signature_age_days"] == 2
    assert defender["defender"]["realtime_enabled"] is True

    profiles = parse_firewall_profiles(
        '[{"name":"Domain","enabled":"True","inbound":"Block","outbound":"Allow"},'
        '{"name":"Public","enabled":"False","inbound":"NotConfigured","outbound":"Allow"}]'
    )
    assert (
        profiles["domain"]["enabled"] is True and profiles["domain"]["default_inbound"] == "block"
    )
    assert profiles["public"]["enabled"] is False and profiles["public"]["default_inbound"] is None

    assert (
        parse_socketfilterfw("Firewall is disabled. (State = 0)")["application_firewall"]["enabled"]
        is False
    )
    assert (
        parse_socketfilterfw("Firewall is enabled. (State = 1)")["application_firewall"]["enabled"]
        is True
    )
    assert parse_ufw_conf("# x\nENABLED=yes\n") is True
    assert parse_ufw_conf("ENABLED=no") is False


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_linux_persistence_reads_names_not_contents(tmp_path: Path) -> None:
    root = str(tmp_path)
    (tmp_path / "etc" / "cron.d").mkdir(parents=True)
    (tmp_path / "etc" / "crontab").write_text("SECRET_CONTENT=1\n")
    (tmp_path / "etc" / "cron.d" / "backup").write_text("* * * * * root /x\n")
    units = tmp_path / "etc" / "systemd" / "system"
    (units / "multi-user.target.wants").mkdir(parents=True)
    (units / "evil.service").write_text("[Service]\n")
    os.symlink("/lib/systemd/system/ssh.service", units / "multi-user.target.wants" / "ssh.service")
    (units / "README").write_text("ignored")

    records = read_persistence("linux", root=root)

    names = sorted((r["mechanism"], r["name"]) for r in records.values())
    assert names == [
        ("cron", "backup"),
        ("cron", "crontab"),
        ("systemd_unit", "evil.service"),
        ("systemd_unit", "ssh.service"),
    ]
    ssh = next(r for r in records.values() if r["name"] == "ssh.service")
    assert ssh["target"] == "/lib/systemd/system/ssh.service"
    assert "SECRET_CONTENT" not in json.dumps(records)


def test_macos_persistence_lists_system_launchd_plists(tmp_path: Path) -> None:
    (tmp_path / "Library" / "LaunchDaemons").mkdir(parents=True)
    (tmp_path / "Library" / "LaunchDaemons" / "com.x.plist").write_bytes(b"<plist/>")
    (tmp_path / "Library" / "LaunchDaemons" / "notes.txt").write_text("x")
    records = read_persistence("darwin", root=str(tmp_path))
    assert [(r["mechanism"], r["name"]) for r in records.values()] == [
        ("launch_daemon", "com.x.plist")
    ]


def test_unsupported_platform_sources() -> None:
    with pytest.raises(CollectorUnavailableError):
        read_scheduled_tasks("darwin")
    with pytest.raises(CollectorUnavailableError):
        read_persistence("freebsd14")
    with pytest.raises(CollectorUnavailableError):
        endpoint.read_protection("linux")


def test_linux_firewall_without_ufw_or_firewalld_is_permission_denied(tmp_path: Path) -> None:
    def runner(argv: list[str], **_: Any) -> CommandOutput:
        raise AssertionError(f"no command expected: {argv}")

    with pytest.raises(PermissionError):
        read_firewall("linux", runner, root=str(tmp_path))
    (tmp_path / "etc" / "ufw").mkdir(parents=True)
    (tmp_path / "etc" / "ufw" / "ufw.conf").write_text("ENABLED=yes\n")
    records = read_firewall("linux", runner, root=str(tmp_path))
    assert records["ufw"]["enabled"] is True


def test_powershell_errors_map_to_collector_states(monkeypatch: pytest.MonkeyPatch) -> None:
    def denied(argv: list[str], **_: Any) -> CommandOutput:
        return CommandOutput(b"", "Access is denied", 1)

    def missing(argv: list[str], **_: Any) -> CommandOutput:
        return CommandOutput(b"", "Get-MpComputerStatus : not recognized", 1)

    with pytest.raises(PermissionError):
        endpoint.read_protection("win32", denied)
    with pytest.raises(CollectorUnavailableError):
        endpoint.read_protection("win32", missing)
