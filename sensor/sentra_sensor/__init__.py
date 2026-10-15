"""Sentra Sensor: runtime del sensor distribuido de un Site (Fase 5F; 6A discovery avanzado)."""

__version__ = "0.2.0"

# Capacidades realmente implementadas. Se declaran al servidor en enroll y heartbeat; no se
# anuncia nada que el sensor no sepa hacer (sin SNMP/LLDP/CDP/WiFi).
CAPABILITIES: tuple[str, ...] = (
    "network.discovery.basic",
    # Fase 6A: jobs discovery_advanced (perfiles quick/standard/deep, reintentos acotados,
    # RTT medido y DNS directo para confirmar el inverso).
    "network.discovery.advanced",
    "network.dns",
    "network.tcp",
    "network.icmp",
    "network.arp",
)
