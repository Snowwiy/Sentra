"""Fase 6E.3: evento 1 de Sysmon convertido en process/start (XML de ejemplo, sin wevtutil)."""

from pathlib import Path

from sentra_agent.activity import ACTIVE, PERMISSION_DENIED, UNAVAILABLE, instance_key
from sentra_agent.events import Channel
from sentra_agent.sysmon import SysmonQueryError, SysmonReader, parse_sysmon

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def sysmon_event(
    record: int, pid: int, event_id: int = 1, utc: str = "2026-10-22 10:00:00.123"
) -> str:
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/>'
        f"<EventID>{event_id}</EventID><Level>4</Level>"
        f'<TimeCreated SystemTime="2026-10-22T10:00:00.2000000Z"/>'
        f"<EventRecordID>{record}</EventRecordID><Computer>PC</Computer></System>"
        "<EventData>"
        f'<Data Name="UtcTime">{utc}</Data>'
        f'<Data Name="ProcessId">{pid}</Data>'
        '<Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>'
        '<Data Name="CommandLine">cmd.exe /c net use x: \\\\srv\\s /p:Secret1</Data>'
        '<Data Name="User">PC\\ana</Data>'
        '<Data Name="IntegrityLevel">Medium</Data>'
        '<Data Name="Hashes">MD5=00,SHA256=' + "A" * 64 + "</Data>"
        '<Data Name="ParentProcessId">500</Data>'
        "</EventData></Event>"
    )


def test_parse_sysmon_process_creation() -> None:
    xml = sysmon_event(10, 4242) + sysmon_event(11, 1, event_id=3)
    events, last = parse_sysmon(xml, "boot-x", "redacted", parent_key=lambda pid: "p" * 32)

    assert last == 11
    [start] = events
    assert start["source"] == "sysmon" and start["action"] == "start"
    data = start["data"]
    assert data["pid"] == 4242 and data["ppid"] == 500
    assert data["name"] == "cmd.exe"
    assert data["parent_relation"] == "inferred" and data["parent_instance_key"] == "p" * 32
    assert "Secret1" not in data["cmdline"]
    assert data["sha256"] == "a" * 64
    assert data["integrity"] == "Medium"
    # Misma clave que calcularía el tracker con el create_time de psutil (ms truncados).
    import datetime as dt

    ts = dt.datetime(2026, 10, 22, 10, 0, 0, 123000, tzinfo=dt.UTC).timestamp()
    assert start["instance_key"] == instance_key("boot-x", 4242, int(ts * 1000))


class FakeQuery:
    def __init__(self) -> None:
        self.calls: list[tuple[int | None, bool]] = []
        self.xml = ""
        self.error: Exception | None = None

    def __call__(self, channel: Channel, after: int | None, newest_only: bool) -> str:
        self.calls.append((after, newest_only))
        if self.error:
            raise self.error
        return self.xml


def test_reader_sets_cursor_first_then_reads_new_events(tmp_path: Path) -> None:
    query = FakeQuery()
    query.xml = sysmon_event(100, 7)
    reader = SysmonReader(tmp_path, "boot", "redacted", query=query)

    assert reader.poll() == []  # primera vez: no se reenvía la historia
    assert reader.status == ACTIVE
    query.xml = sysmon_event(101, 8) + sysmon_event(102, 9)
    assert [e["data"]["pid"] for e in reader.poll()] == [8, 9]
    assert query.calls == [(None, True), (100, False)]

    # El cursor persiste entre reinicios.
    again = SysmonReader(tmp_path, "boot", "redacted", query=query)
    query.xml = ""
    again.poll()
    assert query.calls[-1] == (102, False)


def test_reader_reports_denied_and_missing_channel(tmp_path: Path) -> None:
    query = FakeQuery()
    reader = SysmonReader(tmp_path, "boot", "redacted", query=query)
    query.error = SysmonQueryError("Access is denied", denied=True)
    assert reader.poll() == [] and reader.status == PERMISSION_DENIED
    query.error = SysmonQueryError("channel not found (15007)", denied=False)
    assert reader.poll() == [] and reader.status == UNAVAILABLE
