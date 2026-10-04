import sys
from datetime import datetime
from pathlib import Path

import pytest

from sentra_agent.events import EventCollector, parse_events

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
    assert {e["record_id"] for e in again}.isdisjoint({e["record_id"] for e in events})
