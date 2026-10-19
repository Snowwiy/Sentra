"""Inventario SNMP de solo lectura (Fase 6B; módulo wlan en la Fase 6C.3).

El sensor solo hace GET y GETBULK sobre un catálogo cerrado de MIBs (catalog.py). No existe
en este paquete ninguna operación SET ni forma de pedir un OID arbitrario: el servidor envía
nombres de módulo y el sensor decide qué OIDs consultar.

pysnmp es una dependencia OPCIONAL (extra `snmp`). Sin ella el sensor sigue funcionando para
discovery y simplemente no declara capacidades snmp.*, así que el servidor nunca le envía un
job snmp_inventory.
"""

from importlib.util import find_spec

# Fase 6C.3: "wlan" (APs, BSS, WLANs y clientes; IEEE802dot11-MIB, AIRESPACE y UniFi). El
# servidor solo lo pide a sensores que declaran snmp.wlan (0.4.0+); un 0.3.0 nunca lo recibe.
MODULES: tuple[str, ...] = (
    "system",
    "entity",
    "interfaces",
    "lldp",
    "cdp",
    "bridge",
    "vlan",
    "wlan",
)


def snmp_available() -> bool:
    """pysnmp instalado (y por tanto pyasn1)."""
    return find_spec("pysnmp") is not None


def v3_available() -> bool:
    """SNMPv3 authPriv necesita además `cryptography` para AES."""
    return snmp_available() and find_spec("cryptography") is not None


def capabilities() -> tuple[str, ...]:
    """Capacidades SNMP que este sensor puede cumplir de verdad en esta máquina."""
    if not snmp_available():
        return ()
    caps = [f"snmp.{name}" for name in MODULES]
    caps.append("snmp.v2c")
    if v3_available():
        caps.append("snmp.v3")
    return tuple(caps)
