import logging
import sys
from datetime import datetime
from pathlib import Path

import pytest

from sentra_agent import events as events_module
from sentra_agent.events import (
    CHANNELS,
    CURSOR_FILE,
    Channel,
    EventCollector,
    EventLogError,
    build_query,
    parse_events,
)

# Shape of real `wevtutil qe ... /f:RenderedXml` output: several <Event> roots back to back.
SAMPLE = (
    "﻿<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Service Control Manager'/><EventID Qualifiers='49152'>7034</EventID>"
    "<Level>2</Level><TimeCreated SystemTime='2026-10-04T01:09:40.4690635Z'/>"
    "<EventRecordID>72912</EventRecordID><Channel>System</Channel></System>"
    "<RenderingInfo Culture='es-MX'><Message>El servicio &#13;&#10; terminó   inesperadamente."
    "</Message></RenderingInfo></Event>"
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='DCOM'/><EventID>10016</EventID><Level>3</Level>"
    "<TimeCreated SystemTime='2026-10-04T01:08:00Z'/><EventRecordID>72911</EventRecordID>"
    "</System></Event>"
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Info'/><EventID>1</EventID><Level>4</Level>"
    "<TimeCreated SystemTime='2026-10-04T01:07:00Z'/><EventRecordID>72910</EventRecordID>"
    "</System></Event>"
)


def test_parse_events_maps_levels_times_and_messages() -> None:
    events = parse_events(SAMPLE, "System")

    assert [e["record_id"] for e in events] == [72911, 72912]  # info dropped, sorted
    error = events[1]
    assert error["level"] == "error"
    assert error["event_code"] == 7034
    assert error["provider"] == "Service Control Manager"
    assert error["message"] == "El servicio terminó inesperadamente."
    assert datetime.fromisoformat(error["occurred_at"]).microsecond == 469063
    assert events[0]["level"] == "warning"
    assert events[0]["message"] == ""


@pytest.mark.skipif(sys.platform != "win32", reason="reads the real Windows Event Log")
def test_real_event_log_reads_and_cursor_prevents_resending(tmp_path: Path) -> None:
    collector = EventCollector(tmp_path)

    events, cursor = collector.pending()
    collector.commit(cursor)
    again, _ = collector.pending()

    for event in events:
        assert event["level"] in {"warning", "error", "critical"}
        assert datetime.fromisoformat(event["occurred_at"]).utcoffset() is not None
        assert len(event["message"]) <= 4000
    # Record ids are per channel: the identity of an event is (channel, record id).
    assert {(e["channel"], e["record_id"]) for e in again}.isdisjoint(
        {(e["channel"], e["record_id"]) for e in events}
    )


@pytest.mark.parametrize(
    "content", ["{broken", "[1, 2]", "null", '{"System": "x"}', '{"System": null}']
)
def test_corrupt_cursor_starts_over_instead_of_failing(tmp_path: Path, content: str) -> None:
    (tmp_path / CURSOR_FILE).write_text(content)

    # Starting over re-reads only recent events, which the server deduplicates.
    assert EventCollector(tmp_path)._load() == {}


def test_valid_cursor_is_loaded(tmp_path: Path) -> None:
    (tmp_path / CURSOR_FILE).write_text('{"System": 72912, "Application": 10}')

    assert EventCollector(tmp_path)._load() == {"System": 72912, "Application": 10}


def _event_xml(event_id: int, level: int, record: int, message: str = "text") -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{event_id}</EventID>"
        f"<Level>{level}</Level><TimeCreated SystemTime='2026-10-04T01:00:00.1234567Z'/>"
        f"<EventRecordID>{record}</EventRecordID><Computer>PC-ADMIN-01</Computer></System>"
        f"<RenderingInfo Culture='es-ES'><Message>{message}</Message></RenderingInfo></Event>"
    )


def test_security_events_are_selected_by_id_not_by_level() -> None:
    # Security events are "Information" (level 0); the level filter alone would drop them.
    xml = _event_xml(4625, 0, 10, "Error de inicio de sesión") + _event_xml(4688, 0, 11)

    (failed_logon,) = parse_events(xml, "Security")

    assert failed_logon["event_code"] == 4625  # 4688 (process created) is not collected
    assert failed_logon["level"] == "warning"
    assert failed_logon["computer"] == "PC-ADMIN-01"
    assert parse_events(_event_xml(1102, 4, 12), "Security")[0]["level"] == "critical"


def test_powershell_events_are_kept_without_their_content() -> None:
    xml = _event_xml(4104, 3, 7, "Invoke-Thing -Password hunter2")

    (event,) = parse_events(xml, "Microsoft-Windows-PowerShell/Operational")

    assert "hunter2" not in event["message"]
    assert event["message"].endswith("event 4104 (content not collected)")


def test_queries_per_channel_and_cursor() -> None:
    by_name: dict[str, Channel] = {}
    for channel in CHANNELS:
        by_name.setdefault(channel.key, channel)

    first, extra = build_query(by_name["Security"], None)
    assert "EventID=4625" in first and "EventID=1102" in first and "Level" not in first
    assert extra[0] == "/rd:true"  # newest first, limited, on the first run
    system, _ = build_query(by_name["System"], 500)
    assert "Level=1 or Level=2 or Level=3" in system and "EventID=7045" in system
    assert system.endswith("and EventRecordID>500]]")
    # 4624 va en su propia consulta (filtrada por tipo de logon) y no en la general.
    assert "EventID=4624" not in first
    logons, extra = build_query(by_name["Security:4624"], None)
    assert "Data[@Name='LogonType']='10'" in logons and extra[0] == "/rd:true"
    assert "LogonType']='3'" not in logons  # logons de red: demasiado volumen
    later, _ = build_query(by_name["Security:4624"], 77)
    assert later.endswith("and *[System[EventRecordID>77]]")
    defender, _ = build_query(by_name["Microsoft-Windows-Windows Defender/Operational"], None)
    assert "EventID=1116" in defender and "EventID=5001" in defender


def test_unreadable_channel_is_reported_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")  # the module reads sys.platform at call time

    def fake_query(channel: object, after: object) -> list[dict[str, object]]:
        if getattr(channel, "name", "") == "Security":
            raise EventLogError("wevtutil failed on Security (5): Access is denied.")
        return []

    monkeypatch.setattr(events_module, "_query", fake_query)
    collector = EventCollector(tmp_path)
    with caplog.at_level(logging.DEBUG, logger="sentra_agent"):
        collector.pending()
        collector.pending()

    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    # Una vez por consulta del canal (general y logons correctos), no en cada lectura.
    assert len(warnings) == 2
    assert {getattr(r, "channel", None) for r in warnings} == {"Security", "Security:4624"}
    assert all("requires administrator rights" in r.getMessage() for r in warnings)


def _event_with_data(event_id: int, record: int, data: str, channel: str = "Security") -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>{event_id}</EventID>"
        f"<Level>0</Level><TimeCreated SystemTime='2026-10-04T01:00:00Z'/>"
        f"<EventRecordID>{record}</EventRecordID><Channel>{channel}</Channel></System>"
        f"{data}<RenderingInfo Culture='es-ES'><Message>m</Message></RenderingInfo></Event>"
    )


def test_structured_fields_are_sent_from_an_allowlist_only() -> None:
    data = (
        "<EventData><Data Name='TargetUserName'>  alice </Data>"
        "<Data Name='TargetDomainName'>PC-01</Data><Data Name='LogonType'>3</Data>"
        "<Data Name='IpAddress'>-</Data><Data Name='SubjectLogonId'>0x3e7</Data>"
        "<Data Name='Status'>0xc000006d</Data></EventData>"
    )

    (event,) = parse_events(_event_with_data(4625, 5, data), "Security")

    # SubjectLogonId no está en la lista; "-" (valor vacío de Windows) no se envía.
    assert event["data"] == {
        "TargetUserName": "alice",
        "TargetDomainName": "PC-01",
        "LogonType": "3",
        "Status": "0xc000006d",
    }


def test_user_data_fields_and_events_without_fields() -> None:
    cleared = (
        "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/"
        "windows/eventlog'><SubjectUserSid>S-1-5-21-1-1001</SubjectUserSid>"
        "<SubjectUserName>bob</SubjectUserName></LogFileCleared></UserData>"
    )

    (event,) = parse_events(_event_with_data(1102, 9, cleared), "Security")
    (plain,) = parse_events(_event_xml(4740, 0, 10), "Security")

    assert event["data"] == {"SubjectUserSid": "S-1-5-21-1-1001", "SubjectUserName": "bob"}
    assert "data" not in plain  # sin EventData: el evento sale como antes


def test_script_block_content_is_never_sent_as_data() -> None:
    data = "<EventData><Data Name='ScriptBlockText'>$p='hunter2'</Data></EventData>"
    xml = _event_with_data(4104, 3, data, "Microsoft-Windows-PowerShell/Operational").replace(
        "<Level>0</Level>", "<Level>3</Level>"
    )

    (event,) = parse_events(xml, "Microsoft-Windows-PowerShell/Operational")

    assert "data" not in event and "hunter2" not in str(event)


def test_defender_detection_keeps_threat_fields() -> None:
    data = (
        "<EventData><Data Name='Threat Name'>Trojan:Win32/Test</Data>"
        "<Data Name='Severity Name'>Severe</Data><Data Name='Path'>file:_C:\\x.exe</Data>"
        "<Data Name='FWLink'>https://example.invalid</Data></EventData>"
    )
    channel = "Microsoft-Windows-Windows Defender/Operational"

    (event,) = parse_events(_event_with_data(1116, 4, data, channel), channel)

    assert event["level"] == "warning"
    assert event["data"]["Threat Name"] == "Trojan:Win32/Test"
    assert "FWLink" not in event["data"]
