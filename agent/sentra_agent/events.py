"""Windows Event Log collection (warnings, errors and critical events).

Uses the built-in `wevtutil.exe` instead of a third-party binding (pywin32): no extra
dependency, nothing to compile, and it ships with every Windows version we support. The
Security channel needs administrator rights; channels we cannot read are skipped.

A per-channel cursor (last EventRecordID sent) is persisted so each event is sent once and a
restart resumes where it left off. The cursor only advances after the API accepted a batch.
"""

import json
import logging
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentra_agent")

CHANNELS = ("System", "Application")
# On first run only recent events are sent, not years of history.
FIRST_RUN_MAX = 50
BATCH_MAX = 200
MESSAGE_MAX = 4000
CURSOR_FILE = "events_cursor.json"

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
# Windows levels: 1 critical, 2 error, 3 warning, 4/0 information.
_LEVELS = {1: "critical", 2: "error", 3: "warning"}
_LEVEL_FILTER = "(Level=1 or Level=2 or Level=3)"


class EventLogError(Exception):
    pass


def _wevtutil() -> str:
    # Absolute path so a wevtutil.exe planted in the working directory or PATH is never run.
    return str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "wevtutil.exe")


def _parse_time(value: str) -> str:
    # Windows emits 7 fractional digits ("...40.4690635Z"); Python accepts at most 6.
    head, _, frac = value.rstrip("Z").partition(".")
    stamp = f"{head}.{frac[:6]}" if frac else head
    return datetime.fromisoformat(stamp).replace(tzinfo=UTC).isoformat()


def parse_events(xml_text: str, channel: str) -> list[dict[str, Any]]:
    """Parse wevtutil RenderedXml output (a sequence of <Event> roots) into API events."""
    root = ET.fromstring(f"<Events>{xml_text.lstrip(chr(0xFEFF))}</Events>")  # noqa: S314
    events = []
    for node in root.findall("e:Event", _NS):
        system = node.find("e:System", _NS)
        if system is None:
            continue
        level = _LEVELS.get(int(system.findtext("e:Level", "4", _NS) or 4))
        record = system.findtext("e:EventRecordID", None, _NS)
        created = system.find("e:TimeCreated", _NS)
        if level is None or record is None or created is None:
            continue
        provider = system.find("e:Provider", _NS)
        message = node.findtext("e:RenderingInfo/e:Message", "", _NS) or ""
        events.append(
            {
                "source": "windows_eventlog",
                "channel": channel,
                "record_id": int(record),
                "event_code": int(system.findtext("e:EventID", "0", _NS) or 0) & 0xFFFF,
                "provider": (provider.get("Name") if provider is not None else None) or "unknown",
                "level": level,
                "message": " ".join(message.split())[:MESSAGE_MAX],
                "occurred_at": _parse_time(created.get("SystemTime", "")),
            }
        )
    return sorted(events, key=lambda event: event["record_id"])


def _query(channel: str, after: int | None) -> list[dict[str, Any]]:
    if after is None:
        query, extra = f"*[System[{_LEVEL_FILTER}]]", ["/rd:true", f"/c:{FIRST_RUN_MAX}"]
    else:
        query = f"*[System[{_LEVEL_FILTER} and EventRecordID>{after}]]"
        extra = [f"/c:{BATCH_MAX}"]
    result = subprocess.run(  # noqa: S603  (fixed executable, no shell, validated arguments)
        [_wevtutil(), "qe", channel, f"/q:{query}", "/f:RenderedXml", "/uni:true", *extra],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        # /uni:true makes output UTF-16 regardless of the console code page.
        error = result.stderr.decode("utf-16-le", "replace").strip()
        raise EventLogError(f"wevtutil failed on {channel} ({result.returncode}): {error}")
    return parse_events(result.stdout.decode("utf-16-le", "replace"), channel)


class EventCollector:
    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / CURSOR_FILE

    def _load(self) -> dict[str, int]:
        if not self._path.exists():
            return {}
        data = json.loads(self._path.read_text(encoding="utf-8"))
        return {str(k): int(v) for k, v in data.items()}

    def pending(self) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Return new events and the cursor to commit once the API accepted them."""
        if sys.platform != "win32":
            return [], {}  # journald: future Linux support
        cursor = self._load()
        events: list[dict[str, Any]] = []
        for channel in CHANNELS:
            try:
                found = _query(channel, cursor.get(channel))
            except (EventLogError, subprocess.TimeoutExpired, ET.ParseError) as exc:
                logger.warning(
                    "event log channel skipped", extra={"channel": channel, "error": str(exc)}
                )
                continue
            if found:
                events.extend(found)
                cursor[channel] = found[-1]["record_id"]
        return events, cursor

    def commit(self, cursor: dict[str, int]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cursor), encoding="utf-8")
        os.replace(tmp, self._path)
