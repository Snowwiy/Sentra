"""Ejecución de un job snmp_inventory: módulos en orden, límites y resumen (Fase 6B).

Interfaz equivalente a la del Scanner de discovery (run / request_cancel) para que el runner
los trate igual: un hilo por job, cancelable desde el heartbeat o la respuesta de un lote, y
cada módulo terminado va al spool en cuanto acaba (durable aunque el proceso muera).

La credencial llega en memoria (respuesta de start) y solo la usa el transporte. Nunca se
pasa a los registros, al resumen ni a los logs.
"""

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentra_sensor.snmp.mibs import READERS, Record
from sentra_sensor.snmp.transport import SnmpError, SnmpMalformedError, SnmpTransport
from sentra_sensor.snmp.walker import Budget, StopWalkError, Walker

logger = logging.getLogger("sentra_sensor.snmp")

# Errores que significan "el equipo ya no responde o no nos acepta": seguir con más módulos
# solo acumularía esperas de timeout x reintentos.
_FATAL = ("timeout", "host_unreachable", "auth_failed", "unsupported_version")


@dataclass(frozen=True)
class SnmpCredentials:
    """Secretos de un job. repr oculta los valores: nunca acaban en un log por accidente."""

    snmp_version: str
    username: str | None = None
    auth_protocol: str | None = None
    priv_protocol: str | None = None
    auth_password: str | None = field(default=None, repr=False)
    priv_password: str | None = field(default=None, repr=False)
    community: str | None = field(default=None, repr=False)


@dataclass
class SnmpReport:
    modules: dict[str, str]
    records: int
    requests: int
    varbinds: int
    truncated: bool
    error_code: str | None
    errors: list[str]
    outcome: str  # completed | cancelled | timed_out | failed

    def summary(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "modules": dict(self.modules),
            "requests": self.requests,
            "varbinds": self.varbinds,
            "truncated": self.truncated,
        }
        if self.error_code is not None:
            out["error_code"] = self.error_code
        return out


class SnmpCollector:
    def __init__(
        self,
        modules: tuple[str, ...],
        transport_factory: Callable[[], SnmpTransport],
        emit: Callable[[list[Record]], None],
        *,
        max_varbinds: int,
        max_rows: int,
        max_repetitions: int,
        deadline_seconds: int,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._modules = modules
        self._factory = transport_factory
        self._emit = emit
        self._cancel = threading.Event()
        self._max_repetitions = max_repetitions
        self._budget = Budget(
            max_varbinds=max_varbinds,
            max_rows=max_rows,
            deadline=clock() + deadline_seconds,
            cancel=self._cancel,
            clock=clock,
        )

    def request_cancel(self) -> None:
        self._cancel.set()

    def run(self) -> SnmpReport:
        statuses = dict.fromkeys(self._modules, "skipped")
        errors: list[str] = []
        error_code: str | None = None
        outcome = "completed"
        records = 0
        try:
            transport = self._factory()
        except SnmpError as exc:
            return self._report(statuses, 0, exc.code, [exc.code], "failed")
        walker = Walker(transport, self._budget, self._max_repetitions)
        try:
            for name in self._modules:
                try:
                    result = READERS[name](walker)
                except StopWalkError as stop:
                    statuses[name] = "partial"
                    if stop.reason == "cancelled":
                        outcome, error_code = "cancelled", "cancelled"
                    elif stop.reason == "deadline":
                        outcome, error_code = "timed_out", "timeout"
                    else:
                        error_code = "limit_exceeded"
                    break
                except SnmpMalformedError:
                    # Una tabla mal formada no invalida el resto del equipo.
                    statuses[name] = "failed"
                    error_code = error_code or "malformed_response"
                    errors.append(f"{name}: malformed_response")
                    continue
                except SnmpError as exc:
                    statuses[name] = "failed"
                    errors.append(f"{name}: {exc.code}")
                    if name == "system":
                        # Sin system no hay equipo que inventariar: el job falla con el motivo.
                        return self._report(statuses, records, exc.code, errors, "failed")
                    error_code = exc.code if exc.code in _FATAL else error_code or exc.code
                    if exc.code in _FATAL:
                        break
                    continue
                except Exception as exc:
                    logger.warning(
                        "snmp module crashed", extra={"module": name, "error": type(exc).__name__}
                    )
                    statuses[name] = "failed"
                    error_code = error_code or "internal"
                    errors.append(f"{name}: internal")
                    continue
                statuses[name] = result.status
                if result.records:
                    self._emit(result.records)
                    records += len(result.records)
        finally:
            transport.close()
        if error_code is None and self._budget.truncated:
            error_code = "limit_exceeded"
        if error_code is None and any(s in ("partial", "failed") for s in statuses.values()):
            error_code = "partial"
        return self._report(statuses, records, error_code, errors, outcome)

    def _report(
        self,
        statuses: dict[str, str],
        records: int,
        error_code: str | None,
        errors: list[str],
        outcome: str,
    ) -> SnmpReport:
        return SnmpReport(
            modules=statuses,
            records=records,
            requests=self._budget.requests,
            varbinds=self._budget.varbinds,
            truncated=self._budget.truncated,
            error_code=error_code,
            errors=errors[:50],
            outcome=outcome,
        )
