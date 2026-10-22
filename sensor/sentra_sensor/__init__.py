"""Sentra Sensor: runtime del sensor distribuido de un Site (5F; 6A discovery avanzado; 6B SNMP;
6C.3 módulo SNMP wlan; Corrección 6C sondas de nombre)."""

from sentra_sensor import snmp as _snmp

__version__ = "0.5.1"

# Capacidades realmente implementadas. Se declaran al servidor en enroll y heartbeat; no se
# anuncia nada que el sensor no sepa hacer. Wi-Fi (6C.3) solo como inventario SNMP de lectura
# (snmp.wlan) de APs y controladoras: el sensor no escanea radio ni usa una tarjeta Wi-Fi.
# Las snmp.* solo aparecen si el extra `snmp` (pysnmp, y cryptography para v3) está
# instalado en esta máquina.
CAPABILITIES: tuple[str, ...] = (
    "network.discovery.basic",
    # Fase 6A: jobs discovery_advanced (perfiles quick/standard/deep, reintentos acotados,
    # RTT medido y DNS directo para confirmar el inverso).
    "network.discovery.advanced",
    # Corrección 6C: sondas de nombre (mDNS, NetBIOS, SSDP/UPnP) en discovery_advanced v2,
    # las mismas que el discovery local del servidor.
    "network.discovery.names",
    "network.dns",
    "network.tcp",
    "network.icmp",
    "network.arp",
    *_snmp.capabilities(),
)
