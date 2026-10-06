"""Seudonimización opcional de datos antes de enviarlos al proveedor (AI_REDACT).

No se borran los valores: se sustituyen por seudónimos estables dentro de un mismo análisis
("[user-1]", "[host-2]", "[ip-3]", "[path-4]"). Así el modelo sigue viendo que dos
evidencias hablan de la misma cuenta o del mismo equipo (la correlación se conserva) sin
recibir el nombre real. Al volver, el servidor restaura los valores reales en el texto que
ve el analista: la seudonimización solo existe en el tramo servidor -> proveedor.

Limitación documentada: el texto libre (resúmenes de evidencia) solo se seudonimiza para los
valores que también aparecen en campos estructurados, más IPv4 y rutas por patrón.
"""

import re
from collections.abc import Iterable

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# Rutas Windows (C:\..., \\servidor\...) y Unix absolutas con al menos dos segmentos.
_PATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)[^\s\"'<>|]+|(?<![\w/])/(?:[\w.\-]+/)+[\w.\-]+")
_PREFIX = {
    "usernames": "user",
    "hostnames": "host",
    "ips": "ip",
    "paths": "path",
    # Fase 4L: responsable y departamento del Asset Context (texto administrativo que puede
    # nombrar a personas o equipos internos).
    "owners": "owner",
}


class Redactor:
    def __init__(self, fields: Iterable[str]) -> None:
        self.fields = frozenset(fields)
        self._forward: dict[tuple[str, str], str] = {}
        self._reverse: dict[str, str] = {}
        self._counter = 0

    @property
    def active(self) -> bool:
        return bool(self.fields)

    def _alias(self, field: str, value: str) -> str:
        key = (field, value.lower())
        alias = self._forward.get(key)
        if alias is None:
            self._counter += 1
            alias = f"[{_PREFIX[field]}-{self._counter}]"
            self._forward[key] = alias
            self._reverse[alias] = value
        return alias

    def value(self, field: str, value: str | None) -> str | None:
        """Seudónimo de un campo estructurado de ese tipo (o el valor si no se redacta)."""
        if value is None or field not in self.fields or not value.strip():
            return value
        return self._alias(field, value)

    def text(self, value: str | None) -> str | None:
        """Texto libre: sustituye los valores ya conocidos y, si procede, IPv4 y rutas."""
        if value is None or not self.fields:
            return value
        result = value
        # Una sola pasada con todos los valores conocidos (los más largos primero, para que
        # "admin" no rompa "administrator"): un seudónimo ya insertado nunca se reprocesa.
        # Valores muy cortos se omiten: "1" o "pc" destrozarían el texto sin proteger nada.
        known = sorted({o for (_, o) in self._forward if len(o) >= 3}, key=len, reverse=True)
        if known:
            pattern = re.compile(
                r"(?<![\w-])(?:" + "|".join(re.escape(o) for o in known) + r")(?![\w-])",
                re.IGNORECASE,
            )
            lookup = {o: alias for (_, o), alias in self._forward.items()}
            result = pattern.sub(lambda m: lookup.get(m.group(0).lower(), m.group(0)), result)
        if "ips" in self.fields:
            result = _IPV4.sub(lambda m: self._alias("ips", m.group(0)), result)
        if "paths" in self.fields:
            result = _PATH.sub(lambda m: self._alias("paths", m.group(0)), result)
        return result

    def restore(self, value: str) -> str:
        """Devuelve los valores reales en la respuesta del modelo (solo para el analista)."""
        if not self._reverse:
            return value
        return re.sub(
            r"\[(?:user|host|ip|path|owner)-\d+\]",
            lambda m: self._reverse.get(m.group(0), m.group(0)),
            value,
        )
