"""Catálogo cerrado de conectores SIEM (Fase 7F.1).

Cada conector declara un identificador estable (`source_type`), su versión, cómo pueden llegar
sus registros (`sensor` y/o `upload`), qué tipo de entrada local necesita en el sensor
(`syslog` o `file`), su normalizador y su POLÍTICA DE SEVERIDAD por defecto: la traducción de
la severidad del producto externo a la de Sentra es explícita, versionada y visible en la API,
y un admin puede ajustarla por fuente. Una fuente de un tipo que no está aquí no se puede
registrar; añadir un producto es añadir un conector con sus pruebas, nunca un campo libre.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.siem.contract import SEVERITIES, NormalizedEvent, RawRecord

TRANSPORT_SENSOR = "sensor"
TRANSPORT_UPLOAD = "upload"
INPUT_SYSLOG = "syslog"
INPUT_FILE = "file"


@dataclass(frozen=True)
class NormalizeContext:
    """Lo que un normalizador puede usar además del registro: la configuración aprobada de la
    fuente (ya validada) y los límites del servidor."""

    config: dict[str, Any]
    raw_store_bytes: int

    def severity_policy(self, default: dict[str, str]) -> dict[str, str]:
        override = self.config.get("severity_policy") or {}
        return {**default, **{k: v for k, v in override.items() if k in default}}

    def allows(self, event_type: str) -> bool:
        allowed = self.config.get("event_types")
        return not allowed or event_type in allowed


Normalizer = Callable[[RawRecord, NormalizeContext], NormalizedEvent]


@dataclass(frozen=True)
class Connector:
    source_type: str
    title: str
    version: str
    transports: tuple[str, ...]
    sensor_input: str | None
    description: str
    normalize: Normalizer
    # Clave del valor de origen → severidad de Sentra. Las claves son las que el
    # normalizador busca (p. ej. "1", "2", "3" para Suricata; "0-3"... para Wazuh).
    severity_policy: dict[str, str]
    severity_policy_doc: str
    # Tipos de evento que el conector sabe normalizar (para el filtro `event_types`).
    event_types: tuple[str, ...] = ()
    # Campos con datos potencialmente sensibles (solo visibles con siem:evidence).
    sensitive_fields: tuple[str, ...] = ()
    # Qué se ha validado de verdad: los fixtures son sintéticos salvo que se diga lo contrario.
    validation: str = "Fixtures sintéticos documentados; sin validación con el producto real."
    formats: tuple[str, ...] = field(default_factory=tuple)


CONNECTORS: dict[str, Connector] = {}


def register(connector: Connector) -> Connector:
    for value in connector.severity_policy.values():
        if value not in SEVERITIES:
            raise ValueError(f"invalid severity {value!r} in {connector.source_type}")
    CONNECTORS[connector.source_type] = connector
    return connector


def get_connector(source_type: str) -> Connector | None:
    _load()
    return CONNECTORS.get(source_type)


def connectors() -> list[Connector]:
    _load()
    return sorted(CONNECTORS.values(), key=lambda c: c.source_type)


_LOADED: list[bool] = []


def _load() -> None:
    """Importa los conectores (cada módulo se registra al importarse). Perezoso para evitar
    ciclos de importación con los modelos."""
    if _LOADED:
        return
    from app.siem.normalizers import sentra_json, suricata, syslog, wazuh, zeek  # noqa: F401

    _LOADED.append(True)
