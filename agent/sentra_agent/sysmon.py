"""Inicio de procesos desde Sysmon (Fase 6E.3, solo Windows).

Si el equipo YA tiene Sysmon instalado y el canal Microsoft-Windows-Sysmon/Operational es
legible por la cuenta del agente (miembro de Event Log Readers), el evento 1 (creación de
proceso) se convierte en `process/start` con `source = sysmon`: llega orientado a eventos y
no se pierde un proceso que vive menos que el intervalo de sondeo. El agente nunca instala
Sysmon ni cambia su configuración ni la política de auditoría.

Reutiliza la infraestructura de events.py (wevtutil con ruta absoluta, XPath con cursor por
EventRecordID, extracción de EventData por lista cerrada de campos).
"""

import json
import logging
import ntpath
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentra_agent.activity import (
    ACTIVE,
    DISABLED,
    ERROR,
    PERMISSION_DENIED,
    UNAVAILABLE,
    clip,
    create_time_ms,
    instance_key,
    iso,
    make_event,
    redact_cmdline,
)
from sentra_agent.events import _NS, Channel, _event_data, _wevtutil, build_query
from sentra_agent.identity import write_atomic
from sentra_agent.syscmd import run_bounded

logger = logging.getLogger("sentra_agent")

CHANNEL = Channel(
    "Microsoft-Windows-Sysmon/Operational", "EventID=1", {1: "info"}, cursor_key="sysmon"
)
CURSOR_FILE = "sysmon_cursor.json"
FIELDS = (
    "UtcTime",
    "ProcessId",
    "Image",
    "CommandLine",
    "User",
    "IntegrityLevel",
    "Hashes",
    "ParentProcessId",
)
# Errores de wevtutil: 5 acceso denegado, 15007 canal inexistente.
_ACCESS_DENIED = ("access is denied", "(5)")


class SysmonQueryError(Exception):
    def __init__(self, message: str, denied: bool) -> None:
        super().__init__(message)
        self.denied = denied


QueryFn = Callable[[Channel, int | None, bool], str]


def wevtutil_query(channel: Channel, after: int | None, newest_only: bool) -> str:
    """XML de wevtutil (RenderedXml). `newest_only`: solo el último evento (fijar cursor)."""
    if newest_only:
        query, extra = f"*[System[{channel.condition}]]", ["/rd:true", "/c:1"]
    else:
        query, extra = build_query(channel, after)
    result = run_bounded(
        [_wevtutil(), "qe", channel.name, f"/q:{query}", "/f:RenderedXml", "/uni:true", *extra],
        timeout=60,
        max_bytes=16 * 1024 * 1024,
    )
    if result.returncode != 0:
        error = result.stdout.decode("utf-16-le", "replace") + result.stderr
        lowered = error.lower()
        raise SysmonQueryError(error.strip()[:200], any(m in lowered for m in _ACCESS_DENIED))
    return result.stdout.decode("utf-16-le", "replace")


def _utc_ms(value: str) -> int | None:
    # Sysmon: "2026-10-22 10:00:00.123" en UTC.
    try:
        moment = datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)
    except ValueError:
        return None
    return create_time_ms(moment.timestamp())


def _sha256(hashes: str | None) -> str | None:
    for part in (hashes or "").split(","):
        name, _, value = part.partition("=")
        if name.strip().upper() == "SHA256" and len(value.strip()) == 64:
            return value.strip().lower()
    return None


def parse_sysmon(
    xml_text: str,
    boot_id: str,
    cmdline_policy: str,
    parent_key: Callable[[int], str | None] | None = None,
) -> tuple[list[dict[str, Any]], int | None]:
    """Eventos process/start y el último EventRecordID visto."""
    root = ET.fromstring(f"<Events>{xml_text.lstrip(chr(0xFEFF))}</Events>")  # noqa: S314
    events: list[dict[str, Any]] = []
    last: int | None = None
    for node in root.findall("e:Event", _NS):
        system = node.find("e:System", _NS)
        if system is None:
            continue
        record = system.findtext("e:EventRecordID", None, _NS)
        if record is None:
            continue
        last = max(last or 0, int(record))
        if int(system.findtext("e:EventID", "0", _NS) or 0) != 1:
            continue
        data = _event_data(node, FIELDS)
        try:
            pid = int(data.get("ProcessId", ""))
        except ValueError:
            continue
        started_ms = _utc_ms(data.get("UtcTime", ""))
        if started_ms is None:
            continue
        try:
            ppid: int | None = int(data.get("ParentProcessId", ""))
        except ValueError:
            ppid = None
        parent = parent_key(ppid) if parent_key and ppid else None
        image = data.get("Image")
        started = iso(started_ms / 1000)
        payload = {
            "pid": pid,
            "ppid": ppid,
            "parent_instance_key": parent,
            # Sysmon da el PID del padre pero no su hora de inicio: el enlace se deduce del
            # padre vivo que conoce el tracker, por eso es "inferred" y no "observed".
            "parent_relation": "inferred" if parent else "missing",
            "name": clip(ntpath.basename(image), 255) if image else None,
            "exe": clip(image, 1024),
            "cmdline": redact_cmdline(
                [data["CommandLine"]] if data.get("CommandLine") else None, cmdline_policy
            ),
            "username": clip(data.get("User"), 255),
            "started_at": started,
            "sha256": _sha256(data.get("Hashes")),
            "signer": None,
            "integrity": clip(data.get("IntegrityLevel"), 32),
        }
        key = instance_key(boot_id, pid, started_ms)
        events.append(make_event("process", "start", "sysmon", payload, started, key))
    return events, last


class SysmonReader:
    def __init__(
        self,
        state_dir: Path,
        boot_id: str,
        cmdline_policy: str,
        query: QueryFn = wevtutil_query,
        parent_key: Callable[[int], str | None] | None = None,
        enabled: bool = True,
    ) -> None:
        self._path = state_dir / CURSOR_FILE
        self.boot_id = boot_id
        self.cmdline_policy = cmdline_policy
        self._query = query
        self._parent_key = parent_key
        self.status = UNAVAILABLE if enabled else DISABLED
        self._enabled = enabled
        self._cursor = self._load()

    def _load(self) -> int | None:
        try:
            value = json.loads(self._path.read_text(encoding="utf-8")).get("after")
            return int(value) if value is not None else None
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _save(self) -> None:
        try:
            write_atomic(self._path, json.dumps({"after": self._cursor}), private=False)
        except OSError as exc:
            logger.warning("could not save sysmon cursor", extra={"error": str(exc)})

    def poll(self) -> list[dict[str, Any]]:
        if not self._enabled:
            return []
        try:
            if self._cursor is None:
                # Primera vez: no se reenvía la historia del canal, solo se fija el cursor.
                _, last = parse_sysmon(
                    self._query(CHANNEL, None, True), self.boot_id, self.cmdline_policy
                )
                self._cursor = last or 0
                self._save()
                self._set(ACTIVE)
                return []
            events, last = parse_sysmon(
                self._query(CHANNEL, self._cursor, False),
                self.boot_id,
                self.cmdline_policy,
                self._parent_key,
            )
        except SysmonQueryError as exc:
            self._set(PERMISSION_DENIED if exc.denied else UNAVAILABLE)
            return []
        except (OSError, ET.ParseError):
            self._set(ERROR)
            return []
        self._set(ACTIVE)
        if last is not None and last != self._cursor:
            self._cursor = last
            self._save()
        return events

    def _set(self, status: str) -> None:
        if status != self.status:
            logger.info("sysmon collector status", extra={"status": status})
        self.status = status
