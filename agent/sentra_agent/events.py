"""Windows Event Log collection: warnings, errors, critical events and selected security events.

Uses the built-in `wevtutil.exe` instead of a third-party binding (pywin32): no extra
dependency, nothing to compile, and it ships with every Windows version we support.

Not everything is collected: each channel has its own filter (see CHANNELS). The Security
channel needs administrator rights: as a standard user it is reported once as unavailable
and skipped, never worked around (no privilege changes). PowerShell events are collected
without their text, which can contain script code and credentials.

🪟 VALIDACIÓN LOCAL EN WINDOWS: the queries, the Security/PowerShell channels and the
<Computer> field can only be exercised on a real Windows host.

A per-channel cursor (last EventRecordID sent) is persisted so each event is sent once and a
restart resumes where it left off. The cursor only advances after the API accepted a batch.
"""

import json
import logging
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentra_agent")

# On first run only recent events are sent, not years of history.
FIRST_RUN_MAX = 50
BATCH_MAX = 200
MESSAGE_MAX = 4000
CURSOR_FILE = "events_cursor.json"

_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
# Windows levels: 1 critical, 2 error, 3 warning, 4/0 information.
_LEVELS = {1: "critical", 2: "error", 3: "warning"}
_LEVEL_FILTER = "Level=1 or Level=2 or Level=3"

# Informational events worth collecting anyway, with the level Sentra gives them.
_SYSTEM_EXTRA = {104: "critical", 7045: "warning"}  # System log cleared, service installed
_SECURITY_EVENTS = {
    1102: "critical",  # Security log cleared
    4719: "warning",  # audit policy changed
    4625: "warning",  # failed logon
    4740: "warning",  # account locked out
    4720: "warning",  # user created
    4722: "warning",  # user enabled
    4725: "warning",  # user disabled
    4726: "warning",  # user deleted
    4728: "warning",  # member added to a global security group
    4729: "warning",  # member removed from a global security group
    4732: "warning",  # member added to a local group (e.g. Administrators)
    4733: "warning",  # member removed from a local group
    4756: "warning",  # member added to a universal security group
    4757: "warning",  # member removed from a universal security group
}


def _ids(events: dict[int, str]) -> str:
    return " or ".join(f"EventID={event_id}" for event_id in sorted(events))


@dataclass(frozen=True)
class Channel:
    name: str
    # XPath condition inside System[...]; the record cursor is added to it.
    condition: str
    # Event id -> level for events selected by id rather than by their Windows level.
    levels_by_id: dict[int, str] = field(default_factory=dict)
    # False: the message text is replaced (may hold script code or secrets).
    collect_message: bool = True

    def level(self, windows_level: int, event_id: int) -> str | None:
        return self.levels_by_id.get(event_id) or _LEVELS.get(windows_level)


CHANNELS = (
    Channel("System", f"({_LEVEL_FILTER} or {_ids(_SYSTEM_EXTRA)})", _SYSTEM_EXTRA),
    Channel("Application", f"({_LEVEL_FILTER})"),
    Channel("Security", f"({_ids(_SECURITY_EVENTS)})", _SECURITY_EVENTS),
    Channel(
        "Microsoft-Windows-PowerShell/Operational", f"({_LEVEL_FILTER})", collect_message=False
    ),
)
_BY_NAME = {channel.name: channel for channel in CHANNELS}


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


def parse_events(xml_text: str, channel: str | Channel) -> list[dict[str, Any]]:
    """Parse wevtutil RenderedXml output (a sequence of <Event> roots) into API events."""
    spec = channel if isinstance(channel, Channel) else _BY_NAME.get(channel, Channel(channel, ""))
    root = ET.fromstring(f"<Events>{xml_text.lstrip(chr(0xFEFF))}</Events>")  # noqa: S314
    events = []
    for node in root.findall("e:Event", _NS):
        system = node.find("e:System", _NS)
        if system is None:
            continue
        event_code = int(system.findtext("e:EventID", "0", _NS) or 0) & 0xFFFF
        level = spec.level(int(system.findtext("e:Level", "4", _NS) or 4), event_code)
        record = system.findtext("e:EventRecordID", None, _NS)
        created = system.find("e:TimeCreated", _NS)
        if level is None or record is None or created is None:
            continue
        provider = system.find("e:Provider", _NS)
        provider_name = (provider.get("Name") if provider is not None else None) or "unknown"
        if spec.collect_message:
            message = node.findtext("e:RenderingInfo/e:Message", "", _NS) or ""
        else:
            message = f"{provider_name} event {event_code} (content not collected)"
        computer = (system.findtext("e:Computer", "", _NS) or "").strip()
        events.append(
            {
                "source": "windows_eventlog",
                "channel": spec.name,
                "record_id": int(record),
                "event_code": event_code,
                "provider": provider_name[:255],
                "level": level,
                "message": " ".join(message.split())[:MESSAGE_MAX],
                "computer": computer[:255] or None,
                "occurred_at": _parse_time(created.get("SystemTime", "")),
            }
        )
    return sorted(events, key=lambda event: event["record_id"])


def build_query(channel: Channel, after: int | None) -> tuple[str, list[str]]:
    """XPath query and extra wevtutil arguments for one read of a channel."""
    if after is None:
        # First run: only the most recent matching events, newest first, not years of logs.
        return f"*[System[{channel.condition}]]", ["/rd:true", f"/c:{FIRST_RUN_MAX}"]
    return f"*[System[{channel.condition} and EventRecordID>{after}]]", [f"/c:{BATCH_MAX}"]


def _query(channel: Channel, after: int | None) -> list[dict[str, Any]]:
    query, extra = build_query(channel, after)
    result = subprocess.run(  # noqa: S603  (fixed executable, no shell, validated arguments)
        [_wevtutil(), "qe", channel.name, f"/q:{query}", "/f:RenderedXml", "/uni:true", *extra],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        # /uni:true makes output UTF-16 regardless of the console code page.
        error = result.stderr.decode("utf-16-le", "replace").strip()
        raise EventLogError(f"wevtutil failed on {channel.name} ({result.returncode}): {error}")
    return parse_events(result.stdout.decode("utf-16-le", "replace"), channel)


class EventCollector:
    def __init__(self, state_dir: Path) -> None:
        self._path = state_dir / CURSOR_FILE
        # Channels that failed last time: reported once, not on every read.
        self._unavailable: set[str] = set()

    def _load(self) -> dict[str, int]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            return {str(k): int(v) for k, v in data.items()}
        except (ValueError, TypeError, AttributeError) as exc:
            # A corrupt cursor must not break every cycle. Starting over only re-reads the
            # most recent events (first-run limit), and the server ignores the ones it already
            # has (unique per channel + record id), so nothing is duplicated.
            logger.warning("event cursor unreadable, starting over", extra={"error": str(exc)})
            return {}

    def pending(self) -> tuple[list[dict[str, Any]], dict[str, int]]:
        """Return new events and the cursor to commit once the API accepted them."""
        if sys.platform != "win32":
            return [], {}  # journald: future Linux support
        cursor = self._load()
        events: list[dict[str, Any]] = []
        for channel in CHANNELS:
            try:
                found = _query(channel, cursor.get(channel.name))
            except (EventLogError, subprocess.TimeoutExpired, ET.ParseError) as exc:
                self._report_unavailable(channel.name, exc)
                continue
            if channel.name in self._unavailable:
                self._unavailable.discard(channel.name)
                logger.info("event log channel available again", extra={"channel": channel.name})
            if found:
                events.extend(found)
                cursor[channel.name] = found[-1]["record_id"]
        return events, cursor

    def _report_unavailable(self, channel: str, exc: Exception) -> None:
        if channel in self._unavailable:
            logger.debug("event log channel still unavailable", extra={"channel": channel})
            return
        self._unavailable.add(channel)
        # Access denied (5) is what a standard user gets for Security: say why, plainly.
        denied = "access is denied" in str(exc).lower() or "(5)" in str(exc)
        logger.warning(
            "event log channel not readable"
            + (": requires administrator rights; skipped" if denied else "; skipped"),
            extra={"channel": channel, "error": str(exc)},
        )

    def commit(self, cursor: dict[str, int]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(cursor), encoding="utf-8")
        os.replace(tmp, self._path)
