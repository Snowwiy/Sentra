"""Lado del agente del aislamiento: estado del helper y peticiones (Fase 6E.7).

El agente no tiene privilegios y no toca el firewall. Solo:
- lee `status.json` para el heartbeat y para decidir si anuncia `isolate_host` y
  `release_isolation` (helper instalado, habilitado y sano: estado `ready` reciente);
- valida de nuevo los parámetros del servidor (`expires_at` en el futuro y dentro de
  `max_minutes` de la política local);
- escribe `request.json` y espera, con tope, a que el helper informe del resultado.
"""

import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

from sentra_agent.config import IsolationSettings
from sentra_agent.isolation import (
    HELPER_ABSENT,
    HELPER_DISABLED,
    HELPER_ERROR,
    HELPER_READY,
    STATE_FAILED,
    STATE_ISOLATED,
    STATE_NONE,
    IsolationError,
)
from sentra_agent.isolation.exchange import (
    STATUS_FILE,
    create_request,
    parse_iso,
    read_json,
    request_payload,
)
from sentra_agent.isolation.policy import DEFAULT_MAX_MINUTES, PolicyError, load_policy

logger = logging.getLogger("sentra_agent")

HEARTBEAT_FIELDS = (
    "helper",
    "state",
    "session_id",
    "applied_at",
    "expires_at",
    "method",
    "verified",
    "error_code",
)
_HELPER_VALUES = {HELPER_ABSENT, HELPER_DISABLED, HELPER_READY, HELPER_ERROR}
_STATE_VALUES = {"none", "applying", "isolated", "reverting", "failed"}
_METHODS = {"windows_firewall", "nftables"}


def _absent() -> dict[str, Any]:
    return {
        "helper": HELPER_ABSENT,
        "state": STATE_NONE,
        "session_id": None,
        "applied_at": None,
        "expires_at": None,
        "method": None,
        "verified": False,
        "error_code": None,
    }


class IsolationClient:
    def __init__(
        self,
        settings: IsolationSettings,
        wall: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self._wall = wall
        self._sleep = sleep

    @property
    def directory(self) -> Path | None:
        return self.settings.exchange_dir

    def _raw_status(self) -> dict[str, Any] | None:
        if self.directory is None:
            return None
        return read_json(self.directory / STATUS_FILE)

    def status(self) -> dict[str, Any]:
        """heartbeat.isolation: solo los campos del contrato, con valores saneados."""
        raw = self._raw_status()
        if raw is None:
            return _absent()
        result = _absent()
        helper = raw.get("helper")
        result["helper"] = helper if helper in _HELPER_VALUES else HELPER_ERROR
        state = raw.get("state")
        result["state"] = state if state in _STATE_VALUES else STATE_NONE
        for key in ("applied_at", "expires_at"):
            try:
                result[key] = parse_iso(raw.get(key)).isoformat() if raw.get(key) else None
            except ValueError:
                result[key] = None
        try:
            result["session_id"] = (
                str(UUID(str(raw["session_id"]))) if raw.get("session_id") else None
            )
        except ValueError:
            result["session_id"] = None
        result["method"] = raw.get("method") if raw.get("method") in _METHODS else None
        result["verified"] = raw.get("verified") is True
        code = raw.get("error_code")
        result["error_code"] = str(code)[:64] if code else None
        if not self._fresh(raw):
            # Helper parado: su último estado ya no es fiable.
            result["helper"] = HELPER_ERROR
            result["error_code"] = result["error_code"] or "helper_stale"
        return result

    def _fresh(self, raw: dict[str, Any]) -> bool:
        try:
            updated = parse_iso(raw.get("updated_at"))
        except ValueError:
            return False
        age = self._wall() - updated.timestamp()
        return -60 <= age <= self.settings.status_max_age_seconds

    def ready(self) -> bool:
        return bool(self.status()["helper"] == HELPER_READY)

    def max_minutes(self) -> int:
        """max_minutes de la política local; si no se puede leer, el valor por defecto."""
        path = self.settings.policy_file
        if path is None:
            return DEFAULT_MAX_MINUTES
        try:
            return load_policy(path).max_minutes
        except PolicyError:
            return DEFAULT_MAX_MINUTES

    def request(
        self, action: str, session_id: UUID, expires_at: datetime | None
    ) -> tuple[str, str, dict[str, Any], str | None]:
        """(status, summary, data, error_code) del resultado del comando."""
        current = self.status()
        if current["helper"] != HELPER_READY:
            code = {
                HELPER_ABSENT: "helper_absent",
                HELPER_DISABLED: "helper_disabled",
            }.get(current["helper"], current.get("error_code") or "helper_error")
            return "failed", "Isolation helper not available", self._data(None, session_id), code
        now = datetime.fromtimestamp(self._wall(), UTC)
        if action == "isolate":
            if expires_at is None or expires_at <= now:
                return (
                    "failed",
                    "Expiry is in the past",
                    self._data(None, session_id),
                    "invalid_params",
                )
            if expires_at - now > timedelta(minutes=self.max_minutes()):
                return (
                    "failed",
                    "Duration exceeds the local isolation policy",
                    self._data(None, session_id),
                    "duration_exceeds_policy",
                )
        assert self.directory is not None  # noqa: S101  (ready() implica directorio)
        payload = request_payload(session_id, action, expires_at, now)
        try:
            create_request(self.directory, payload)
        except IsolationError as exc:
            return (
                "failed",
                "Could not hand the request to the helper",
                self._data(None, session_id),
                exc.code,
            )
        deadline = self._wall() + self.settings.wait_seconds
        while self._wall() < deadline:
            self._sleep(1.0)
            raw = self._raw_status()
            last = (raw or {}).get("last_action") or {}
            if (
                isinstance(last, dict)
                and last.get("session_id") == str(session_id)
                and last.get("action") == action
                and _not_before(last.get("at"), now)
            ):
                return self._outcome(action, session_id, raw or {}, last)
        return (
            "failed",
            "The isolation helper did not answer in time",
            self._data(None, session_id),
            "helper_timeout",
        )

    def _outcome(
        self, action: str, session_id: UUID, raw: dict[str, Any], last: dict[str, Any]
    ) -> tuple[str, str, dict[str, Any], str | None]:
        code = last.get("error_code")
        succeeded = last.get("outcome") == "succeeded"
        if action == "isolate":
            state = STATE_ISOLATED if succeeded else STATE_FAILED
            summary = "Host isolated" if succeeded else "Isolation failed"
        else:
            state = "restored" if succeeded else STATE_FAILED
            summary = "Isolation released" if succeeded else "Release failed"
        data = self._data(raw, session_id, state=state, error_code=None if succeeded else code)
        return (
            ("succeeded" if succeeded else "failed"),
            summary,
            data,
            (None if succeeded else code),
        )

    def _data(
        self,
        raw: dict[str, Any] | None,
        session_id: UUID,
        state: str = STATE_FAILED,
        error_code: str | None = None,
    ) -> dict[str, Any]:
        raw = raw or {}
        allowed_raw, rules_raw = raw.get("allowed"), raw.get("rules")
        allowed: list[Any] = allowed_raw if isinstance(allowed_raw, list) else []
        rules: list[Any] = rules_raw if isinstance(rules_raw, list) else []
        return {
            "isolation": {
                "state": state,
                "session_id": str(session_id),
                "applied_at": raw.get("applied_at"),
                "expires_at": raw.get("expires_at"),
                "method": raw.get("method") if raw.get("method") in _METHODS else None,
                "allowed": [str(a)[:64] for a in allowed][:64],
                "rules": [r for r in rules if isinstance(r, dict)][:16],
                "verified": raw.get("verified") is True,
                "error_code": error_code,
            }
        }


def _not_before(value: object, moment: datetime) -> bool:
    try:
        # Margen de 1 s: el helper redondea a segundos en algunos sistemas de ficheros.
        return parse_iso(value) >= moment - timedelta(seconds=1)
    except ValueError:
        return False
