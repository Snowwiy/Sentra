"""Interfaz mínima entre el colector y la biblioteca SNMP (Fase 6B).

Solo dos operaciones de lectura: GET y GETBULK. El colector y los tests trabajan contra esta
interfaz; el adaptador real (pysnmp_adapter.py) es el único módulo que importa pysnmp. Los
valores se entregan ya convertidos a tipos de Python simples para que nada de pysnmp se
filtre al resto del sensor.
"""

from collections.abc import Sequence
from typing import Protocol

Oid = tuple[int, ...]


class ObjectId(str):
    """Valor OBJECT IDENTIFIER (p. ej. sysObjectID) en forma punteada."""


# int (Integer32, Counter, Gauge, TimeTicks), bytes (OCTET STRING, IpAddress), ObjectId o
# None (noSuchObject / noSuchInstance: el objeto no existe en este equipo).
Value = int | bytes | ObjectId | None
VarBind = tuple[Oid, Value]


class SnmpError(Exception):
    """Error de consulta con su código de la taxonomía del contrato (SnmpJobSummary)."""

    code = "internal"

    def __init__(self, detail: str = "") -> None:
        super().__init__(detail or self.code)
        self.detail = detail


class SnmpTimeoutError(SnmpError):
    code = "timeout"


class SnmpUnreachableError(SnmpError):
    code = "host_unreachable"


class SnmpAuthError(SnmpError):
    """Usuario desconocido, clave errónea o comunidad rechazada (en v2c suele ser timeout)."""

    code = "auth_failed"


class SnmpUnsupportedVersionError(SnmpError):
    code = "unsupported_version"


class SnmpMalformedError(SnmpError):
    code = "malformed_response"


class SnmpTransport(Protocol):
    def get(self, oids: Sequence[Oid]) -> list[VarBind]:
        """Una petición GET. Devuelve un varbind por OID pedido (None si no existe)."""
        ...

    def get_bulk(self, start: Oid, max_repetitions: int) -> list[VarBind]:
        """Una petición GETBULK desde `start`. Lista vacía = fin de la MIB (endOfMibView)."""
        ...

    def close(self) -> None: ...
