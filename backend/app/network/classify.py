"""Clasificación de equipos de infraestructura a partir de evidencia SNMP (Fase 6B).

Reglas (docs/snmp-network-intelligence.md, sección Switch intelligence):
- Solo evidencia que el propio equipo informa por SNMP: capacidades LLDP habilitadas,
  sysServices, ipForwarding, BRIDGE-MIB y tipos de interfaz. Nunca un puerto TCP abierto ni
  el texto libre de sysDescr (cualquiera puede escribir "switch" ahí).
- Cada conclusión lleva su nivel de confianza y la lista de evidencias que la sostienen.
  Sin evidencia suficiente el resultado es "unclassified" con confianza "none": no se adivina.
- Fabricante, modelo y versión no se inventan: el fabricante sale del número de empresa
  IANA de sysObjectID (o del fabricante que declara ENTITY-MIB) y el modelo, la versión y el
  número de serie solo de ENTITY-MIB (componente chassis o stack).
"""

from dataclasses import dataclass, field
from typing import Any

from app.network.catalog import ENTERPRISE_VENDORS, FIREWALL_ENTERPRISES, enterprise_number

MAX_EVIDENCE = 8
# sysServices (RFC 3418): suma de 2^(capa-1). Capa 2 = 2 (datalink/bridge), capa 3 = 4.
SYS_SERVICES_L2 = 0x02
SYS_SERVICES_L3 = 0x04
# Con menos puertos de bridge, un BRIDGE-MIB presente no basta para hablar de "switch":
# muchos routers domésticos y APs exponen un bridge de 2-3 puertos internos.
MIN_SWITCH_BRIDGE_PORTS = 4
# PhysicalClass de ENTITY-MIB.
ENTITY_CHASSIS = 3
ENTITY_STACK = 11


@dataclass
class DeviceEvidence:
    sys_object_id: str | None = None
    sys_services: int | None = None
    ip_forwarding: bool | None = None
    lldp_capabilities: list[str] = field(default_factory=list)
    bridge_ports: int | None = None
    physical_ports: int = 0
    wireless_ports: int = 0
    entities: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class Classification:
    classification: str
    confidence: str
    evidence: list[dict[str, str]]
    layer3: bool | None
    enterprise_number: int | None
    vendor: str | None
    vendor_source: str | None
    model: str | None
    firmware: str | None
    serial_number: str | None


def _primary_entity(entities: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Chassis (o stack) con el índice más bajo: el que describe al equipo completo."""
    candidates = [e for e in entities if e.get("phys_class") in (ENTITY_CHASSIS, ENTITY_STACK)]
    if not candidates:
        return None
    # Un stack describe el conjunto; si no hay, el primer chassis.
    candidates.sort(key=lambda e: (e.get("phys_class") != ENTITY_STACK, int(e.get("index", 0))))
    return candidates[0]


def _clean(value: object, limit: int = 128) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    return text[:limit] if text else None


def classify(ev: DeviceEvidence) -> Classification:
    evidence: list[dict[str, str]] = []

    def add(source: str, detail: str) -> None:
        if len(evidence) < MAX_EVIDENCE:
            evidence.append({"source": source, "detail": detail[:200]})

    pen = enterprise_number(ev.sys_object_id)
    vendor = ENTERPRISE_VENDORS.get(pen) if pen is not None else None
    vendor_source = "sys_object_id" if vendor else None
    entity = _primary_entity(ev.entities)
    model = firmware = serial = None
    if entity is not None:
        model = _clean(entity.get("model_name"))
        firmware = _clean(entity.get("software_rev")) or _clean(entity.get("firmware_rev"))
        serial = _clean(entity.get("serial"))
        if vendor is None and _clean(entity.get("mfg_name")):
            vendor = _clean(entity.get("mfg_name"))
            vendor_source = "entity_mib"

    caps = set(ev.lldp_capabilities)
    l2_services = ev.sys_services is not None and bool(ev.sys_services & SYS_SERVICES_L2)
    l3_services = ev.sys_services is not None and bool(ev.sys_services & SYS_SERVICES_L3)
    routes = ev.ip_forwarding is True
    layer3: bool | None = None
    if "router" in caps or routes or l3_services:
        layer3 = True
    elif ev.ip_forwarding is False and ev.sys_services is not None and not l3_services:
        layer3 = False
    big_bridge = (ev.bridge_ports or 0) >= MIN_SWITCH_BRIDGE_PORTS

    result = "unclassified"
    confidence = "none"
    # 1. Capacidades LLDP habilitadas: el equipo declara qué hace. Es la mejor evidencia
    #    disponible por SNMP, aunque sigue siendo autodeclarada.
    if "wlan_access_point" in caps:
        result, confidence = "access_point", "high"
        add("lldp_capabilities", "LLDP enabled capability: wlanAccessPoint")
    elif "bridge" in caps:
        result, confidence = "managed_switch", "high"
        add("lldp_capabilities", "LLDP enabled capability: bridge")
        if "router" in caps:
            add("lldp_capabilities", "LLDP enabled capability: router (layer 3 switch)")
    elif "router" in caps:
        result, confidence = "router", "high"
        add("lldp_capabilities", "LLDP enabled capability: router")
    # 2. Sin LLDP: tabla de bridge con suficientes puertos o reenvío IP.
    elif big_bridge:
        result, confidence = "managed_switch", "medium"
        add("bridge_mib", f"BRIDGE-MIB reports {ev.bridge_ports} bridge ports")
    elif routes and l3_services:
        result, confidence = "router", "medium"
        add("ip_forwarding", "IP-MIB ipForwarding = forwarding")
        add("sys_services", "sysServices includes layer 3")
    elif ev.wireless_ports > 0:
        result, confidence = "access_point", "low"
        add("if_type", f"{ev.wireless_ports} IEEE 802.11 interface(s)")
    elif routes:
        result, confidence = "router", "low"
        add("ip_forwarding", "IP-MIB ipForwarding = forwarding")
    # 3. Fabricante de cortafuegos: solo si nada más fuerte lo contradice (también venden
    #    switches y APs, de ahí que no pase de confianza media).
    if pen in FIREWALL_ENTERPRISES and confidence in ("none", "low"):
        result, confidence = "firewall", "medium"
        add("sys_object_id", f"enterprise {pen} ({vendor or 'unknown'}) builds firewalls")
    # Evidencia complementaria que no decide por sí sola pero ayuda a revisar el resultado.
    if l2_services and result == "managed_switch":
        add("sys_services", "sysServices includes layer 2 (bridging)")
    if result != "unclassified" and vendor_source == "sys_object_id":
        add("sys_object_id", f"enterprise number {pen} ({vendor})")
    return Classification(
        classification=result,
        confidence=confidence,
        evidence=evidence,
        layer3=layer3,
        enterprise_number=pen,
        vendor=vendor,
        vendor_source=vendor_source,
        model=model,
        firmware=firmware,
        serial_number=serial,
    )
