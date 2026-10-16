"""Recorrido acotado de columnas SNMP (Fase 6B).

Garantías frente a equipos defectuosos o maliciosos:
- solo OIDs del catálogo (catalog.allowed) y nunca fuera del subárbol pedido;
- OIDs estrictamente crecientes: un agente que repite o retrocede (bucle) corta la columna
  como "malformada" en lugar de girar para siempre;
- presupuesto global de varbinds y de peticiones, tope de filas por columna, plazo del job y
  cancelación comprobados antes de cada petición.
"""

import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from sentra_sensor.snmp import catalog
from sentra_sensor.snmp.transport import (
    Oid,
    SnmpMalformedError,
    SnmpTransport,
    Value,
    VarBind,
)

# Tope de seguridad de peticiones por job aunque el presupuesto de varbinds no se agote
# (p. ej. un agente que responde con un solo varbind por GETBULK).
MAX_REQUESTS = 20_000
MAX_GET_OIDS = 16


class StopWalkError(Exception):
    """Fin anticipado del job: cancelación, plazo o presupuesto agotado."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason  # "cancelled" | "deadline" | "limit_exceeded"


@dataclass
class Budget:
    max_varbinds: int
    max_rows: int
    deadline: float
    cancel: threading.Event
    clock: Callable[[], float] = time.monotonic
    requests: int = 0
    varbinds: int = 0
    truncated: bool = False
    malformed: list[str] = field(default_factory=list)

    def check(self) -> None:
        if self.cancel.is_set():
            raise StopWalkError("cancelled")
        if self.clock() >= self.deadline:
            raise StopWalkError("deadline")
        if self.varbinds >= self.max_varbinds or self.requests >= MAX_REQUESTS:
            self.truncated = True
            raise StopWalkError("limit_exceeded")


@dataclass
class Column:
    rows: dict[tuple[int, ...], Value] = field(default_factory=dict)
    # El agente no tiene esta columna (noSuchObject o el GETBULK salió del subárbol de
    # inmediato): se distingue de "existe pero vacía" solo por exists.
    exists: bool = False
    truncated: bool = False
    malformed: bool = False


class Walker:
    def __init__(self, transport: SnmpTransport, budget: Budget, max_repetitions: int) -> None:
        self._transport = transport
        self._budget = budget
        self._max_repetitions = max_repetitions

    def get(self, oids: Sequence[Oid]) -> dict[Oid, Value]:
        out: dict[Oid, Value] = {}
        for start in range(0, len(oids), MAX_GET_OIDS):
            chunk = list(oids[start : start + MAX_GET_OIDS])
            for item in chunk:
                if not catalog.allowed(item):
                    raise SnmpMalformedError("OID outside the read-only catalog")
            self._budget.check()
            self._budget.requests += 1
            response = self._transport.get(chunk)
            self._budget.varbinds += len(response)
            wanted = set(chunk)
            for name, value in response:
                if name in wanted:
                    out[name] = value
        return out

    def column(self, base: Oid) -> Column:
        if not catalog.allowed(base):
            raise SnmpMalformedError("OID outside the read-only catalog")
        result = Column()
        current = base
        while True:
            self._budget.check()
            self._budget.requests += 1
            response = self._transport.get_bulk(current, self._max_repetitions)
            self._budget.varbinds += len(response)
            if not response:
                return result
            for name, value in response:
                if name[: len(base)] != base or len(name) == len(base):
                    return result
                if name <= current:
                    # Agente defectuoso: OID repetido o hacia atrás.
                    result.malformed = True
                    self._budget.malformed.append(catalog.dotted(base))
                    return result
                current = name
                if value is None:
                    continue
                result.exists = True
                result.rows[name[len(base) :]] = value
                if len(result.rows) >= self._budget.max_rows:
                    result.truncated = True
                    self._budget.truncated = True
                    return result

    def table(self, entry: Oid, columns: dict[str, int]) -> dict[str, Column]:
        return {name: self.column((*entry, number)) for name, number in columns.items()}


def rows_by_index(columns: dict[str, Column]) -> dict[tuple[int, ...], dict[str, Value]]:
    rows: dict[tuple[int, ...], dict[str, Value]] = {}
    for name, column in columns.items():
        for index, value in column.rows.items():
            rows.setdefault(index, {})[name] = value
    return rows


def first(varbinds: Sequence[VarBind]) -> Value:
    return varbinds[0][1] if varbinds else None
