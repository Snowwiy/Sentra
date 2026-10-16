"""Sentra Sensor: runtime del sensor distribuido de un Site (5F; 6A discovery avanzado; 6B SNMP)."""

from sentra_sensor import snmp as _snmp

__version__ = "0.3.0"

# Capacidades realmente implementadas. Se declaran al servidor en enroll y heartbeat; no se
# anuncia nada que el sensor no sepa hacer (sin Wi-Fi). Las snmp.* solo aparecen si el extra
# `snmp` (pysnmp, y cryptography para v3) está instalado en esta máquina.
CAPABILITIES: tuple[str, ...] = (
    "network.discovery.basic",
    # Fase 6A: jobs discovery_advanced (perfiles quick/standard/deep, reintentos acotados,
    # RTT medido y DNS directo para confirmar el inverso).
    "network.discovery.advanced",
    "network.dns",
    "network.tcp",
    "network.icmp",
    "network.arp",
    *_snmp.capabilities(),
)
