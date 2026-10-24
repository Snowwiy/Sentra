"""Sondeos con diff de servicios, tareas, persistencia, protección y firewall (Fase 6E.3).

Cambian poco y leerlos cuesta (herramientas del sistema, PowerShell), así que se sondean con
intervalos largos y solo se envía lo que cambió:

- `DiffPoller` (servicios, tareas programadas, persistencia): compara con la última lectura y
  emite `created`, `modified`, `deleted` (y `started`/`stopped` en servicios). La línea base
  se guarda en disco: un cambio hecho con el agente parado se detecta al volver. La primera
  lectura de un equipo nuevo solo fija la línea base (enviar cientos de `created` no aporta;
  el inventario completo está en las acciones forenses).
- `StatePoller` (protección, firewall): emite `state` en la primera lectura de cada ejecución
  y cuando algo cambia.

Un lector que falla deja el estado del colector en `permission_denied`, `unavailable` o
`error` y no toca la línea base (un fallo no debe parecer un borrado masivo).
"""

import hashlib
import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentra_agent.activity import (
    ACTIVE,
    ERROR,
    PERMISSION_DENIED,
    UNAVAILABLE,
    iso,
    make_event,
)
from sentra_agent.endpoint import CollectorUnavailableError, Records, public
from sentra_agent.identity import write_atomic

logger = logging.getLogger("sentra_agent")

Reader = Callable[[], Records]


def _fingerprint(record: dict[str, Any]) -> str:
    raw = json.dumps(record, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


class _Base:
    def __init__(self, category: str, source: str, reader: Reader) -> None:
        self.category = category
        self.source = source
        self.reader = reader
        self.status = ACTIVE

    def _read(self) -> Records | None:
        try:
            records = self.reader()
        except PermissionError:
            self._set_status(PERMISSION_DENIED)
            return None
        except CollectorUnavailableError:
            self._set_status(UNAVAILABLE)
            return None
        except Exception:
            logger.warning("collector failed", extra={"collector": self.category}, exc_info=True)
            self._set_status(ERROR)
            return None
        self._set_status(ACTIVE)
        return records

    def _set_status(self, status: str) -> None:
        if status != self.status:
            logger.info(
                "collector status changed",
                extra={"collector": self.category, "status": status},
            )
        self.status = status


class DiffPoller(_Base):
    def __init__(
        self,
        category: str,
        source: str,
        reader: Reader,
        baseline_path: Path | None = None,
    ) -> None:
        super().__init__(category, source, reader)
        self._path = baseline_path
        self._baseline: dict[str, dict[str, Any]] | None = self._load()

    def _load(self) -> dict[str, dict[str, Any]] | None:
        if self._path is None:
            return None
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None

    def _save(self, baseline: dict[str, dict[str, Any]]) -> None:
        if self._path is None:
            return
        try:
            write_atomic(self._path, json.dumps(baseline), private=False)
        except OSError as exc:
            logger.warning("could not save collector baseline", extra={"error": str(exc)})

    def poll(self, now: float) -> list[dict[str, Any]]:
        records = self._read()
        if records is None:
            return []
        current: dict[str, dict[str, Any]] = {
            key: {"fp": _fingerprint(rec), "record": rec} for key, rec in records.items()
        }
        previous = self._baseline
        self._baseline = current
        events: list[dict[str, Any]] = []
        if previous is not None:
            when = iso(now)
            for key, item in current.items():
                before = previous.get(key)
                if before is None:
                    events.append(self._event("created", item["record"], when))
                elif before.get("fp") != item["fp"]:
                    action = self._change_action(before.get("record") or {}, item["record"])
                    events.append(self._event(action, item["record"], when))
            for key in previous.keys() - current.keys():
                events.append(self._event("deleted", previous[key].get("record") or {}, when))
        if previous != current:
            self._save(current)
        return events

    def _change_action(self, before: dict[str, Any], after: dict[str, Any]) -> str:
        if self.category == "service":
            same = {k: v for k, v in before.items() if k != "status"} == {
                k: v for k, v in after.items() if k != "status"
            }
            if same and before.get("status") != after.get("status"):
                return "started" if after.get("status") == "running" else "stopped"
        return "modified"

    def _event(self, action: str, record: dict[str, Any], when: str) -> dict[str, Any]:
        return make_event(self.category, action, self.source, public(record), when)


class StatePoller(_Base):
    def __init__(self, category: str, source: str, reader: Reader) -> None:
        super().__init__(category, source, reader)
        self._last: dict[str, str] = {}

    def poll(self, now: float) -> list[dict[str, Any]]:
        records = self._read()
        if records is None:
            return []
        events = []
        for key, record in records.items():
            fingerprint = _fingerprint(record)
            if self._last.get(key) != fingerprint:
                events.append(
                    make_event(self.category, "state", self.source, public(record), iso(now))
                )
            self._last[key] = fingerprint
        return events
