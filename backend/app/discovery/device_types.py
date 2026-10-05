"""Tipos de dispositivo y nivel de confianza de la clasificación.

Los identificadores son estables (se guardan en assets.device_type y viajan en la API); la
UI los traduce al español. "Desconocido" no es un valor: se guarda null, que el filtro de
la API y la UI tratan como "unknown". Así un activo nunca aparece con un tipo inventado.
"""

from enum import StrEnum


class DeviceType(StrEnum):
    PC = "pc"
    LAPTOP = "laptop"
    SERVER = "server"
    MOBILE = "mobile"
    TABLET = "tablet"
    CONSOLE = "console"
    PRINTER = "printer"
    ROUTER = "router"
    NETWORK_SWITCH = "network_switch"
    ACCESS_POINT = "access_point"
    IOT = "iot"
    # Asistentes de voz (Echo/Alexa, Google Home/Nest): un IoT concreto que interesa
    # distinguir porque escucha permanentemente en la red doméstica.
    VOICE_ASSISTANT = "voice_assistant"
    SMART_TV = "smart_tv"
    NAS = "nas"
    VIRTUAL_MACHINE = "virtual_machine"


class ClassificationConfidence(StrEnum):
    """Cuánto respaldan las evidencias la clasificación (tipo y fabricante) del activo.

    - low: una sola pista débil; la UI lo presenta como "probable".
    - medium: una pista clara o varias débiles coherentes; también "probable".
    - high: fuente autoritativa (agente, gateway) o evidencias independientes que se
      confirman entre sí (p. ej. nombre con código de modelo Huawei + OUI Huawei).
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# Tipos que no se contradicen entre sí: una pista "IoT" no resta confianza a "asistente de
# voz", ni "PC" a "portátil". Solo una pista de otra familia es un conflicto real.
FAMILIES: tuple[frozenset[DeviceType], ...] = (
    frozenset({DeviceType.PC, DeviceType.LAPTOP, DeviceType.SERVER, DeviceType.VIRTUAL_MACHINE}),
    frozenset({DeviceType.MOBILE, DeviceType.TABLET}),
    frozenset({DeviceType.ROUTER, DeviceType.NETWORK_SWITCH, DeviceType.ACCESS_POINT}),
    frozenset({DeviceType.IOT, DeviceType.VOICE_ASSISTANT, DeviceType.SMART_TV}),
)


def compatible(a: DeviceType, b: DeviceType) -> bool:
    return a == b or any(a in family and b in family for family in FAMILIES)
