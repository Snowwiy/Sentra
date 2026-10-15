"""Sentra Sensor: runtime del sensor distribuido de un Site (Fase 5F)."""

__version__ = "0.1.0"

# Capacidades realmente implementadas. Se declaran al servidor en enroll y heartbeat; no se
# anuncia nada que el sensor no sepa hacer (sin SNMP/LLDP/CDP/WiFi).
CAPABILITIES: tuple[str, ...] = (
    "network.discovery.basic",
    "network.tcp",
    "network.icmp",
    "network.arp",
)
