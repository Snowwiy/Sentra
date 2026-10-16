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


# Contrato de niveles (docs/agent-protocol.md): los canales filtrados por nivel de Windows
# solo aportan warning/error/critical (Level 1-3); "info" existe en el contrato del servidor
# (EventLevel.INFO) pero el agente solo lo asigna a Security 4624 de logons interactivos (2),
# RDP (10) y con credenciales en caché (11), que el motor de detección necesita para CORR-001.
# No basta con aceptar "info": un "info" de otro canal, de otro evento o de otro tipo de logon
# indicaría que el filtro de la consulta ha dejado pasar ruido informativo.
_WINDOWS_LEVELS = {"warning", "error", "critical"}
_INTERACTIVE_LOGON_TYPES = {"2", "10", "11"}


def _assert_level_contract(event: dict[str, object]) -> None:
    if event["level"] == "info":
        assert (event["channel"], event["event_code"]) == ("Security", 4624), event
        data = event.get("data")
        assert isinstance(data, dict), event
        assert data.get("LogonType") in _INTERACTIVE_LOGON_TYPES, event
    else:
        assert event["level"] in _WINDOWS_LEVELS, event


@pytest.mark.skipif(sys.platform != "win32", reason="reads the real Windows Event Log")
def test_real_event_log_reads_and_cursor_prevents_resending(tmp_path: Path) -> None:
    # Prueba de integración con el registro real: el equipo puede tener cualquier evento
    # legítimo (también logons correctos), así que se comprueba el contrato, no una lista fija.
    collector = EventCollector(tmp_path)

    events, cursor = collector.pending()
    collector.commit(cursor)
    again, _ = collector.pending()

    for event in [*events, *again]:
        _assert_level_contract(event)
        assert datetime.fromisoformat(str(event["occurred_at"])).utcoffset() is not None
        assert len(str(event["message"])) <= 4000
    # Record ids are per channel: the identity of an event is (channel, record id).
    assert {(e["channel"], e["record_id"]) for e in again}.isdisjoint(
        {(e["channel"], e["record_id"]) for e in events}
    )
    # Lo que llega en la segunda lectura es posterior al cursor confirmado de su consulta.
    for event in again:
        keys = [c.key for c in CHANNELS if c.name == event["channel"]]
        assert any(event["record_id"] > cursor.get(key, -1) for key in keys), event


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


def _logon_xml(record: int, logon_type: str, level: int = 0) -> str:
    data = (
        "<EventData><Data Name='TargetUserName'>alice</Data>"
        f"<Data Name='LogonType'>{logon_type}</Data></EventData>"
    )
    return _event_with_data(4624, record, data).replace(
        "<Level>0</Level>", f"<Level>{level}</Level>"
    )


def test_level_contract_with_simulated_events_per_channel() -> None:
    # Eventos informativos (Level 4 o 0) de canales filtrados por nivel: nunca se envían.
    for channel in ("System", "Application", "Microsoft-Windows-PowerShell/Operational"):
        assert parse_events(_event_xml(1, 4, 1) + _event_xml(2, 0, 2), channel) == []
    # Excepciones por id del System: informativos en Windows, con nivel propio en Sentra.
    system = parse_events(_event_xml(104, 4, 3) + _event_xml(7045, 4, 4), "System")
    assert [(e["event_code"], e["level"]) for e in system] == [(104, "critical"), (7045, "warning")]
    # 4624 interactivo/RDP/caché: "info", con el tipo de logon como dato estructurado.
    logons = parse_events(
        _logon_xml(5, "2") + _logon_xml(6, "10") + _logon_xml(7, "11"), "Security"
    )
    assert {e["level"] for e in logons} == {"info"}
    for event in logons:
        _assert_level_contract(event)
    # Ids informativos que no están en la lista del canal: descartados (la consulta ya los
    # excluye por id; el parser no los convierte en "info" si llegaran).
    assert parse_events(_event_xml(4688, 0, 8), "Security") == []
    defender = "Microsoft-Windows-Windows Defender/Operational"
    assert parse_events(_event_xml(1150, 4, 9), defender) == []
    assert parse_events(_event_xml(5001, 4, 10), defender)[0]["level"] == "warning"
    # El nivel de Windows nunca convierte en "info" un evento de canal filtrado por nivel.
    for level, expected in ((1, "critical"), (2, "error"), (3, "warning")):
        (event,) = parse_events(_event_xml(999, level, 20 + level), "Application")
        assert event["level"] == expected
        _assert_level_contract(event)


def test_info_level_is_only_assigned_to_interactive_logons() -> None:
    # Guarda de la especificación: si alguien añade otro evento "info" o quita el filtro por
    # tipo de logon, esta prueba obliga a revisar el contrato y la documentación.
    info_ids = {
        (channel.name, event_id)
        for channel in CHANNELS
        for event_id, level in channel.levels_by_id.items()
        if level == "info"
    }
    assert info_ids == {("Security", 4624)}
    logon_queries = [c for c in CHANNELS if c.name == "Security" and "4624" in build_query(c, 1)[0]]
    assert [c.key for c in logon_queries] == ["Security:4624"]
    query = build_query(logon_queries[0], None)[0]
    for logon_type in _INTERACTIVE_LOGON_TYPES:
        assert f"Data[@Name='LogonType']='{logon_type}'" in query
    for noisy in ("3", "4", "5", "8", "9"):  # red, batch, servicio, cleartext, newcredentials
        assert f"Data[@Name='LogonType']='{noisy}'" not in query


class _FakeEventLog:
    """Registro simulado por consulta (cursor key): devuelve lo que pediría wevtutil."""

    def __init__(self) -> None:
        self.records: dict[str, list[int]] = {channel.key: [] for channel in CHANNELS}
        self.calls: list[tuple[str, int | None]] = []

    def add(self, key: str, *records: int) -> None:
        self.records[key].extend(records)

    def query(self, channel: Channel, after: int | None) -> list[dict[str, object]]:
        self.calls.append((channel.key, after))
        stored = sorted(self.records[channel.key])
        if after is None:
            chosen = stored[-events_module.FIRST_RUN_MAX :]
        else:
            chosen = [r for r in stored if r > after][: events_module.BATCH_MAX]
        return [{"channel": channel.name, "record_id": r, "level": "warning"} for r in chosen]


@pytest.fixture
def fake_log(monkeypatch: pytest.MonkeyPatch) -> _FakeEventLog:
    monkeypatch.setattr(sys, "platform", "win32")
    log = _FakeEventLog()
    monkeypatch.setattr(events_module, "_query", log.query)
    return log


def test_cursor_only_advances_after_commit(tmp_path: Path, fake_log: _FakeEventLog) -> None:
    fake_log.add("System", 10, 11, 12)
    collector = EventCollector(tmp_path)

    first, cursor = collector.pending()
    # Sin commit (la API rechazó el lote o no respondió) se vuelve a leer lo mismo.
    retry, _ = collector.pending()
    assert [e["record_id"] for e in first] == [e["record_id"] for e in retry] == [10, 11, 12]
    assert cursor["System"] == 12

    collector.commit(cursor)
    after_commit, _ = collector.pending()
    assert after_commit == []

    fake_log.add("System", 13)
    newer, _ = collector.pending()
    assert [e["record_id"] for e in newer] == [13]
    assert ("System", 12) in fake_log.calls


def test_cursor_survives_restart_and_first_run_is_limited(
    tmp_path: Path, fake_log: _FakeEventLog
) -> None:
    fake_log.add("Application", *range(1, 301))
    collector = EventCollector(tmp_path)

    first, cursor = collector.pending()
    # Primera ejecución: solo los más recientes, no todo el histórico.
    assert len(first) == events_module.FIRST_RUN_MAX
    assert first[-1]["record_id"] == 300
    collector.commit(cursor)

    fake_log.add("Application", 301)
    restarted = EventCollector(tmp_path)  # reinicio del servicio: lee el cursor del disco
    events, _ = restarted.pending()
    assert [e["record_id"] for e in events] == [301]


def test_security_queries_keep_independent_cursors(tmp_path: Path, fake_log: _FakeEventLog) -> None:
    fake_log.add("Security", 500, 501)
    fake_log.add("Security:4624", 480, 502)
    collector = EventCollector(tmp_path)

    events, cursor = collector.pending()
    collector.commit(cursor)

    # Mismo canal, dos consultas: cada una conserva su propio último record id, así la
    # consulta de logons no salta eventos de la general (ni al revés).
    assert cursor["Security"] == 501 and cursor["Security:4624"] == 502
    assert sorted(e["record_id"] for e in events if e["channel"] == "Security") == [
        480,
        500,
        501,
        502,
    ]
    fake_log.add("Security", 503)
    again, _ = collector.pending()
    assert [e["record_id"] for e in again] == [503]


def test_failed_query_keeps_its_cursor_and_others_advance(
    tmp_path: Path, fake_log: _FakeEventLog, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / CURSOR_FILE).write_text('{"System": 5, "Security": 40}')
    fake_log.add("System", 5, 6)
    fake_log.add("Security", 41)

    def flaky(channel: Channel, after: int | None) -> list[dict[str, object]]:
        if channel.key == "Security":
            raise EventLogError("wevtutil failed on Security (15007): channel not found")
        return fake_log.query(channel, after)

    monkeypatch.setattr(events_module, "_query", flaky)
    collector = EventCollector(tmp_path)
    events, cursor = collector.pending()

    assert [e["record_id"] for e in events] == [6]
    # El cursor de la consulta que falló no se toca: cuando vuelva, se lee desde 40.
    assert cursor["Security"] == 40 and cursor["System"] == 6
