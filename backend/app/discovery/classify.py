"""Identificación de un activo: nombre, tipo, fabricante, modelo y SO probable, con evidencias.

Función pura (sin red ni base de datos): recibe lo que Sentra ya sabe de un activo y
devuelve la conclusión y el porqué. Se recalcula cada vez que llega información nueva
(discovery, agente, fusión), así que una regla mejorada se aplica sin migrar datos.

Principios, en orden de importancia:

1. No inventar. Cada conclusión sale de una evidencia concreta que se guarda junto a ella
   (classification_evidence). Sin evidencia el tipo queda desconocido (None).
2. El agente es autoritativo. Un activo MANAGED se identifica con lo que reporta su agente
   (hostname, SO); las inferencias de red solo completan lo que el agente no dice
   (fabricante de la NIC, máquina virtual).
3. El fabricante de la NIC no es el del dispositivo (ver vendors.py). Solo un fabricante
   de dispositivos completos en la tabla de marcas cuenta como fabricante del equipo.
4. La confianza sube cuando fuentes independientes se confirman entre sí, no por repetir
   la misma pista. Un nombre puede ser cualquier cosa que el usuario escribió; un nombre
   con código de modelo Huawei confirmado por un OUI Huawei ya no es casualidad.
5. Nunca versiones de SO (Android 14, Windows 11 23H2...) para activos sin agente: desde la
   red no se pueden demostrar.

Puntuación: cada pista tiene una fuerza (1 débil, 2 media, 3 fuerte, 4 autoritativa). Se
suma por tipo; la confianza depende del total, de cuántas fuentes distintas la apoyan y del
margen frente al mejor tipo incompatible (ver _confidence).
"""

import re
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from app.discovery.device_types import ClassificationConfidence, DeviceType, compatible
from app.discovery.vendors import VendorKind, display_vendor, profile_for

T = DeviceType
Confidence = ClassificationConfidence

AUTHORITATIVE = 4
MAX_EVIDENCE = 16
MAX_VALUE = 128

# --- Fuentes de evidencia (identificadores estables, la UI los traduce) -------------------
AGENT_HOSTNAME = "agent_hostname"
AGENT_OS = "agent_os"
REVERSE_DNS = "reverse_dns"
# Fase 6E.2: hostname de un lease DHCP de una fuente autorizada, asociado al activo con
# coincidencia alta (misma MAC e IP; ver app/dhcp/matching.py). Es lo que el equipo pidió
# llamarse al servidor DHCP, así que va justo detrás del agente.
DHCP_LEASE = "dhcp_lease"
MDNS = "mdns"
NETBIOS = "netbios"
UPNP = "upnp"
SSDP = "ssdp"
MAC_VENDOR = "mac_vendor"
MAC_RANDOM = "mac_random"
PORTS = "ports"
GATEWAY = "gateway"
# Corrección 6C: dos pistas que se contradicen (fabricante o tipo). Se guardan como evidencia
# para que la UI las enseñe; nunca se resuelven eligiendo una al azar.
CONFLICT = "conflict"

# Prioridad del nombre automático. El hostname del agente es lo que el propio equipo dice
# llamarse; después, lo que la red publica sobre él, de más a menos fiable. La etiqueta
# personalizada (assets.custom_label) NO es una fuente de este motor: la escribe una persona,
# va en otra columna y ninguna identificación automática la toca.
NAME_SOURCES = (AGENT_HOSTNAME, DHCP_LEASE, REVERSE_DNS, MDNS, NETBIOS, UPNP, "vendor_model")

# Clase de cada nombre observado (Corrección 6C). Sirve para que la UI distinga lo que el
# equipo dice de sí mismo de lo que dice la infraestructura, y para no presentar como nombre
# del dispositivo algo que solo es un valor por defecto:
# - agent: hostname reportado por el agente (autoritativo).
# - device: publicado por el propio equipo (mDNS, NetBIOS, nombre UPnP, o un nombre .local
#   que devuelve el resolvedor del sistema).
# - dhcp: nombre del DNS local del router (sufijo .lan, .home...). Casi siempre es el
#   hostname que el equipo dio por DHCP, pero eso es una inferencia: el router también puede
#   publicar una etiqueta puesta por su administrador y desde la red no se distinguen.
# - dns: nombre de un DNS de dominio (FQDN), gestionado por alguien.
# - generic: nombre por defecto de un sistema operativo ("linux", "android"): no identifica
#   al equipo, así que nunca es el nombre mostrado ni vota tipo o SO.
NAME_KIND_AGENT = "agent"
NAME_KIND_DEVICE = "device"
NAME_KIND_DHCP = "dhcp"
NAME_KIND_DNS = "dns"
NAME_KIND_GENERIC = "generic"


@dataclass(frozen=True)
class IdentityInput:
    managed: bool = False
    hostname: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    reverse_dns: str | None = None
    # Fase 6E.2: solo llega si el lease se asoció con coincidencia alta.
    dhcp_hostname: str | None = None
    mdns_name: str | None = None
    netbios_name: str | None = None
    upnp_friendly_name: str | None = None
    upnp_manufacturer: str | None = None
    upnp_model_name: str | None = None
    upnp_model_number: str | None = None
    upnp_device_type: str | None = None
    ssdp_server: str | None = None
    mac: str | None = None
    # Organización registrada del prefijo de la MAC (oui.py), tal cual o ya abreviada.
    mac_vendor: str | None = None
    mac_random: bool = False
    open_ports: frozenset[int] = frozenset()
    is_gateway: bool = False
    # Corrección 6C. Resultado de confirmar el DNS inverso con una consulta directa (FCrDNS):
    # True confirmado, False el nombre no resuelve a esta IP, None sin comprobar.
    reverse_dns_confirmed: bool | None = None
    # Fuentes de nombre cuyo último dato es antiguo (ver identification.NAME_STALE_DAYS): se
    # conservan como evidencia, pero un nombre reciente de otra fuente pasa por delante.
    stale_sources: frozenset[str] = frozenset()


@dataclass
class Identification:
    name: str | None = None
    name_source: str | None = None
    device_type: DeviceType | None = None
    device_vendor: str | None = None
    device_model: str | None = None
    network_adapter_vendor: str | None = None
    # Solo para activos sin agente; los MANAGED tienen os_name/os_version reales.
    probable_os: str | None = None
    confidence: ClassificationConfidence | None = None
    evidence: list[dict[str, str]] = field(default_factory=list)
    # Resumen legible del porqué del tipo (assets.device_type_reason).
    reason: str | None = None
    # Corrección 6C: todos los nombres observados con su procedencia y clase
    # ({"source", "value", "kind", "selected", "confirmed", "stale"}), el elegido incluido.
    # Se guardan en assets.observed_names para que la UI muestre la evidencia original
    # aunque haya una etiqueta personalizada.
    names: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class _Hint:
    """Lo que sugiere un patrón de nombre: tipo, marca, SO y si el nombre es un modelo."""

    type: DeviceType | None = None
    strength: int = 2
    vendor: str | None = None
    os: str | None = None
    # El propio nombre es un código de modelo de ese fabricante (p. ej. "MNA-LX9").
    model_code: bool = False


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Patrones sobre nombres (hostname de red, mDNS, NetBIOS, nombre UPnP). Anclados para no
# disparar con subcadenas casuales: "switch" solo cuenta junto a "nintendo".
_NAME_HINTS: tuple[tuple[re.Pattern[str], _Hint], ...] = (
    # Códigos de modelo de Huawei/Honor que el móvil usa como hostname DHCP:
    # tres letras, guion, prefijo de región/red y dígitos (MNA-LX9, VOG-L29, ANE-LX1, ELS-NX9).
    (
        _rx(r"^[a-z]{3}-(l|lx|nx|al|tl|an|cl|dl|w)\d{1,2}[a-z]?$"),
        _Hint(T.MOBILE, 2, "Huawei", None, True),
    ),
    (_rx(r"^(huawei|honor)[-_ ]"), _Hint(T.MOBILE, 2, "Huawei")),
    (_rx(r"^android[-_ ]?[0-9a-f]{0,16}$"), _Hint(T.MOBILE, 2, None, "Android")),
    (_rx(r"\biphone\b|^iphone"), _Hint(T.MOBILE, 3, "Apple", "iOS")),
    (_rx(r"\bipad\b|^ipad"), _Hint(T.TABLET, 3, "Apple", "iPadOS")),
    (_rx(r"^galaxy[-_ ]?tab|^sm-[tx]\d{3}"), _Hint(T.TABLET, 2, "Samsung", "Android")),
    (_rx(r"^galaxy"), _Hint(T.MOBILE, 2, "Samsung", "Android")),
    (_rx(r"^sm-[afgmns]\d{3}"), _Hint(T.MOBILE, 2, "Samsung", "Android", True)),
    (_rx(r"^(redmi|poco|xiaomi|mi-?\d)"), _Hint(T.MOBILE, 2, "Xiaomi", "Android")),
    (_rx(r"^oneplus"), _Hint(T.MOBILE, 2, "OnePlus", "Android")),
    (_rx(r"^pixel[-_ ]?\d"), _Hint(T.MOBILE, 2, "Google", "Android")),
    (
        _rx(r"\balexa\b|^echo[-_ ]?(dot|show|studio|pop|spot|plus)\b|^amazon[-_][0-9a-f]{6,}$"),
        _Hint(T.VOICE_ASSISTANT, 2, "Amazon"),
    ),
    (
        _rx(r"^google[-_ ]?(home|nest)|^nest[-_ ](mini|hub|audio)"),
        _Hint(T.VOICE_ASSISTANT, 2, "Google"),
    ),
    (_rx(r"^chromecast|^google[-_ ]?tv"), _Hint(T.SMART_TV, 2, "Google")),
    (_rx(r"^(fire[-_ ]?tv|firetv|aft[a-z]{1,4}$)"), _Hint(T.SMART_TV, 2, "Amazon")),
    (_rx(r"^roku"), _Hint(T.SMART_TV, 3, "Roku")),
    (_rx(r"^(lgwebostv|lg[-_ ]?webos|webos[-_ ]?tv)"), _Hint(T.SMART_TV, 3, "LG")),
    (_rx(r"^(bravia|kd-\d{2})"), _Hint(T.SMART_TV, 3, "Sony")),
    (_rx(r"^(samsung[-_ ]?tv|\[tv\] ?samsung)|^\[tv\]"), _Hint(T.SMART_TV, 3, "Samsung")),
    (_rx(r"^(nintendo|switch[-_ ]?nintendo)"), _Hint(T.CONSOLE, 2, "Nintendo")),
    (_rx(r"^(ps[345]|playstation)([-_ ]|$)"), _Hint(T.CONSOLE, 2, "Sony")),
    (_rx(r"^xbox"), _Hint(T.CONSOLE, 2, "Microsoft")),
    # Nombres por defecto de impresoras: HP + 6 hex de la MAC, Brother BRW/BRN + MAC.
    (_rx(r"^hp[0-9a-f]{6}$|^npi[0-9a-f]{6}$"), _Hint(T.PRINTER, 3, "HP")),
    (_rx(r"^br[wn][0-9a-f]{12}$"), _Hint(T.PRINTER, 3, "Brother")),
    (_rx(r"^(epson|et-\d{4})"), _Hint(T.PRINTER, 2, "Epson")),
    (_rx(r"^canon"), _Hint(T.PRINTER, 2, "Canon")),
    (_rx(r"printer|^prn[-_]|impresora"), _Hint(T.PRINTER, 2)),
    # Routers domésticos: nombres por defecto conocidos.
    (_rx(r"^(rt-[a-z]{2}\d|gt-[a-z]{2}\d|zenwifi|router\.asus)"), _Hint(T.ROUTER, 2, "ASUS")),
    (_rx(r"^(fritz\.?box)"), _Hint(T.ROUTER, 3, "AVM")),
    (_rx(r"^(tplinkwifi|archer[-_ ])"), _Hint(T.ROUTER, 2, "TP-Link")),
    (
        _rx(r"^(openwrt|pfsense|opnsense|mikrotik|edgerouter|unifi[-_ ]?gateway|udm)"),
        _Hint(T.ROUTER, 2),
    ),
    (_rx(r"^(router|gateway|gw)([-_.\d]|$)"), _Hint(T.ROUTER, 1)),
    (_rx(r"^(uap|u6|unifi[-_ ]?ap|ap)[-_]"), _Hint(T.ACCESS_POINT, 2)),
    (_rx(r"^(diskstation|ds\d{3,4}|synology)"), _Hint(T.NAS, 3, "Synology")),
    (_rx(r"^(qnap|ts-\d{3})"), _Hint(T.NAS, 3, "QNAP")),
    (_rx(r"^(truenas|freenas|nas)([-_\d]|$)"), _Hint(T.NAS, 2)),
    # Windows nombra los equipos según el chasis en la instalación: DESKTOP-XXXXXXX en
    # sobremesa y LAPTOP-XXXXXXXX en portátiles; WIN-XXXXXXXXXXX en Windows Server.
    (_rx(r"^desktop-[a-z0-9]{7}$"), _Hint(T.PC, 2, None, "Windows")),
    (_rx(r"^laptop-[a-z0-9]{8}$"), _Hint(T.LAPTOP, 2, None, "Windows")),
    (_rx(r"^win-[a-z0-9]{11}$"), _Hint(T.SERVER, 2, None, "Windows")),
    (_rx(r"macbook"), _Hint(T.LAPTOP, 3, "Apple", "macOS")),
    (_rx(r"^imac|mac-?mini|mac-?studio"), _Hint(T.PC, 3, "Apple", "macOS")),
    (
        _rx(r"^(esp[-_]?[0-9a-f]{4,}|esp32|esp8266|tasmota|shelly|tuya|smartplug|wled)"),
        _Hint(T.IOT, 2),
    ),
    (_rx(r"^(hue[-_ ]?bridge|philips[-_ ]?hue)"), _Hint(T.IOT, 3, "Philips Hue")),
)

# deviceType UPnP (urn:schemas-upnp-org:device:<Tipo>:<versión>) → tipo de Sentra. Lo
# declara el propio dispositivo; un MediaRenderer puede ser TV o altavoz, por eso es débil.
_UPNP_TYPES: tuple[tuple[re.Pattern[str], DeviceType, int], ...] = (
    (_rx(r":device:InternetGatewayDevice:"), T.ROUTER, 3),
    (_rx(r":device:WLANAccessPointDevice:"), T.ACCESS_POINT, 2),
    (_rx(r":device:Printer:"), T.PRINTER, 3),
    (_rx(r":device:MediaServer:"), T.NAS, 1),
    (_rx(r":device:MediaRenderer:"), T.SMART_TV, 1),
    (_rx(r"dial-multiscreen-org:device:dial"), T.SMART_TV, 2),
)

_PRINTER_PORTS = {9100: "jetdirect", 515: "lpd", 631: "ipp"}
_WINDOWS_PORTS = {135: "msrpc", 139: "netbios-ssn", 445: "smb", 3389: "rdp", 5985: "winrm"}
# Sufijos de dominio local que el router añade a los nombres DHCP. Se quitan del nombre
# mostrado ("mna-lx9.lan" → "mna-lx9"); un FQDN corporativo se muestra completo.
_LOCAL_SUFFIXES = (".lan", ".local", ".home", ".localdomain", ".home.arpa", ".internal")
# Nombres de relleno que algunos routers devuelven para clientes sin nombre: no identifican
# y ni siquiera se guardan como evidencia de nombre.
_GENERIC_NAMES = _rx(r"^(localhost|unknown|\*|dhcp[-_.]?\d.*|host[-_]?\d.*|client[-_]?\d.*)$")
# Corrección 6C: hostnames por defecto de sistemas operativos y firmwares. Muchos equipos
# (asistentes de voz, cámaras, TV) usan un Linux embebido que se anuncia como "linux": el
# nombre es real (se guarda como observado), pero no identifica al equipo ni demuestra que
# sea un PC con Linux. Por eso no se muestra como nombre ni vota tipo ni SO.
_DEFAULT_OS_NAMES = _rx(
    r"^(linux|android|ubuntu|debian|fedora|centos|rhel|raspberrypi|kali|archlinux|alpine|"
    r"espressif|esp|busybox|openembedded|poky|yocto|buildroot|localdomain|none|null|default|"
    r"device|my-?device|generic)$"
)
# Puertos que solo apoyan un tipo que ya sugiere otra fuente: un puerto suelto no basta para
# deducir el tipo (RTSP lo abren cámaras, pero también NAS y PCs con software de vídeo).
_SUPPORT_PORTS: dict[int, tuple[DeviceType, str]] = {
    554: (T.IOT, "rtsp"),
    1883: (T.IOT, "mqtt"),
    8008: (T.SMART_TV, "cast"),
    8009: (T.SMART_TV, "cast"),
    5000: (T.NAS, "nas-http"),
    5001: (T.NAS, "nas-https"),
}


@dataclass
class _Score:
    total: int = 0
    sources: set[str] = field(default_factory=set)
    reasons: list[str] = field(default_factory=list)
    # Marcas que implican las pistas de nombre que votaron este tipo (para _corroborate).
    implied: set[str] = field(default_factory=set)


class _Evidence:
    def __init__(self) -> None:
        self.items: list[dict[str, str]] = []

    def add(self, source: str, value: str) -> None:
        item = {"source": source, "value": _clip(value)}
        if item not in self.items and len(self.items) < MAX_EVIDENCE:
            self.items.append(item)


def identify(data: IdentityInput) -> Identification:
    evidence = _Evidence()
    result = Identification()
    types: dict[DeviceType, _Score] = defaultdict(_Score)
    vendors: dict[str, _Score] = defaultdict(_Score)
    oses: dict[str, _Score] = defaultdict(_Score)
    model_codes: list[tuple[str, str]] = []  # (código, fabricante que lo respalda)

    def vote_type(t: DeviceType, strength: int, source: str, reason: str) -> None:
        score = types[t]
        score.total += strength
        score.sources.add(source)
        score.reasons.append(reason)

    def vote(table: dict[str, _Score], value: str, strength: int, source: str) -> None:
        table[value].total += strength
        table[value].sources.add(source)

    # --- Fabricante de la NIC (OUI) ------------------------------------------------------
    adapter_profile = profile_for(data.mac_vendor)
    result.network_adapter_vendor = display_vendor(data.mac_vendor)
    if data.mac_random:
        evidence.add(MAC_RANDOM, "MAC aleatoria (privacidad): sin fabricante")
    elif result.network_adapter_vendor:
        evidence.add(MAC_VENDOR, result.network_adapter_vendor)
        if adapter_profile is not None:
            if adapter_profile.kind == VendorKind.DEVICE:
                vote(vendors, adapter_profile.brand, 2, MAC_VENDOR)
            if adapter_profile.type_hint is not None:
                vote_type(
                    adapter_profile.type_hint,
                    adapter_profile.hint_strength,
                    MAC_VENDOR,
                    f"MAC {adapter_profile.brand}",
                )

    candidates = _name_candidates(data)
    if data.managed:
        _identify_managed(data, result, evidence, types, adapter_profile)
        # Los nombres de red de un equipo con agente se conservan como observados (no
        # elegidos): el nombre lo da el agente.
        observed = _names_view(candidates, None)
        result.names = [_agent_name(data.hostname), *observed] if data.hostname else observed
        return result

    # --- Nombres publicados en la red ------------------------------------------------------
    chosen = _choose_name(candidates)
    if chosen is not None:
        result.name, result.name_source = chosen.value, chosen.source
    result.names = _names_view(candidates, chosen)
    for candidate in candidates:
        source, name = candidate.source, candidate.value
        evidence.add(source, name)
        if candidate.kind == NAME_KIND_GENERIC:
            # Un nombre por defecto ("linux") no dice qué equipo es: ni tipo ni SO.
            continue
        for hint in _name_hints(name):
            vendor = hint.vendor
            # Honor usa los mismos códigos de modelo que Huawei (ANY-LX1...): si la NIC dice
            # Honor, el código no contradice al OUI, lo confirma.
            if vendor == "Huawei" and adapter_profile and adapter_profile.brand == "Honor":
                vendor = "Honor"
            if hint.type is not None:
                vote_type(hint.type, hint.strength, source, f"nombre {name}")
                if vendor:
                    types[hint.type].implied.add(vendor)
            if vendor:
                vote(vendors, vendor, 2, source)
            if hint.os:
                vote(oses, hint.os, 2, source)
            if hint.model_code and vendor:
                model_codes.append((name.upper(), vendor))
    if data.netbios_name:
        # NetBIOS lo anuncian Windows y Samba: insinúa Windows, no lo demuestra.
        vote(oses, "Windows", 1, NETBIOS)
    if data.reverse_dns_confirmed is False and data.reverse_dns:
        evidence.add(REVERSE_DNS, "no confirmado: el nombre no resuelve a esta IP")

    # --- UPnP / SSDP: lo que el dispositivo declara de sí mismo ----------------------------
    upnp_vendor = profile_for(data.upnp_manufacturer)
    if data.upnp_manufacturer:
        evidence.add(UPNP, f"fabricante {data.upnp_manufacturer}")
        brand = upnp_vendor.brand if upnp_vendor else _clip(data.upnp_manufacturer, 64)
        vote(vendors, brand, 3, UPNP)
        if upnp_vendor and upnp_vendor.type_hint is not None:
            vote_type(upnp_vendor.type_hint, upnp_vendor.hint_strength, UPNP, f"UPnP {brand}")
    if data.upnp_model_name:
        evidence.add(UPNP, f"modelo {data.upnp_model_name}")
        for hint in _name_hints(data.upnp_model_name):
            if hint.type is not None:
                vote_type(hint.type, hint.strength, UPNP, f"modelo {data.upnp_model_name}")
    if data.upnp_device_type:
        for pattern, device_type, strength in _UPNP_TYPES:
            if pattern.search(data.upnp_device_type):
                evidence.add(UPNP, data.upnp_device_type)
                vote_type(device_type, strength, UPNP, f"UPnP {data.upnp_device_type}")
                break
    if data.ssdp_server:
        evidence.add(SSDP, data.ssdp_server)
        for hint in _name_hints(data.ssdp_server.split("/")[0]):
            if hint.type is not None:
                vote_type(hint.type, 1, SSDP, f"SSDP {data.ssdp_server}")

    # --- Puertos y posición en la red -----------------------------------------------------
    # Corrección 6C: un único puerto nunca decide el tipo por sí solo. Con un solo servicio
    # el puerto solo refuerza un tipo que ya sugiere otra fuente (nombre, fabricante, UPnP).
    ports = data.open_ports
    printer = sorted(f"{p}/{label}" for p, label in _PRINTER_PORTS.items() if p in ports)
    if printer:
        evidence.add(PORTS, ", ".join(printer))
        # 631 (IPP) solo también lo abre CUPS en un Linux cualquiera: débil sin 9100/515.
        strong = 9100 in ports or 515 in ports
        reason = "puertos de impresión " + ", ".join(printer)
        if len(printer) >= 2 or types[T.PRINTER].total > 0:
            vote_type(T.PRINTER, 2 if strong else 1, PORTS, reason)
    windows = sorted(f"{p}/{label}" for p, label in _WINDOWS_PORTS.items() if p in ports)
    if windows:
        evidence.add(PORTS, ", ".join(windows))
        vote(oses, "Windows", 2 if len(windows) >= 2 else 1, PORTS)
        # Servicios de Windows: casi siempre un equipo, pero no se sabe si PC o servidor.
        if len(windows) >= 2 or _has_family_vote(types, T.PC):
            vote_type(T.PC, 1, PORTS, "servicios Windows " + ", ".join(windows))
    for port, (support_type, label) in sorted(_SUPPORT_PORTS.items()):
        if port in ports and _has_family_vote(types, support_type):
            evidence.add(PORTS, f"{port}/{label}")
            vote_type(support_type, 1, PORTS, f"servicio {port}/{label}")
    if data.is_gateway:
        evidence.add(GATEWAY, "gateway por defecto del servidor Sentra")
        vote_type(T.ROUTER, AUTHORITATIVE, GATEWAY, "gateway por defecto del servidor Sentra")

    # --- Conclusiones ---------------------------------------------------------------------
    _corroborate(types, vendors)
    result.device_vendor = _pick(vendors)
    _vendor_conflicts(vendors, evidence)
    winner, confidence, score = _pick_type(types)
    result.device_type = winner
    result.confidence = confidence
    _type_conflicts(types, winner, evidence)
    if score is not None:
        result.reason = _clip("; ".join(dict.fromkeys(score.reasons)), 255)
    # El modelo solo se afirma si lo declara el dispositivo (UPnP) o si un código de modelo
    # del nombre está respaldado por el fabricante deducido por otra vía.
    if data.upnp_model_name:
        model = data.upnp_model_name
        if data.upnp_model_number and data.upnp_model_number not in model:
            model = f"{model} {data.upnp_model_number}"
        result.device_model = _clip(model)
    else:
        for code, vendor in model_codes:
            if result.device_vendor == vendor and len(vendors[vendor].sources) >= 2:
                result.device_model = code
                break
    os_name = _pick(oses, minimum=2)
    result.probable_os = os_name
    if result.device_vendor and result.confidence is None:
        # Fabricante conocido pero tipo no: es una identificación parcial y débil.
        result.confidence = Confidence.LOW
    if result.name is None and result.device_model:
        result.name, result.name_source = (
            f"{result.device_vendor or ''} {result.device_model}".strip(),
            "vendor_model",
        )
    result.evidence = evidence.items
    return result


def _identify_managed(
    data: IdentityInput,
    result: Identification,
    evidence: _Evidence,
    types: dict[DeviceType, _Score],
    adapter_profile: Any,
) -> None:
    """Activo con agente: lo que reporta el agente manda sobre cualquier inferencia de red.

    El agente demuestra que es un ordenador de propósito general (Windows o Linux con
    Sentra Agent). Solo se afina el subtipo con pistas fiables: interfaz de hipervisor →
    máquina virtual; SO servidor o nombre WIN-XXXX → servidor; LAPTOP-XXXX → portátil.
    """
    if data.hostname:
        result.name, result.name_source = _clip(data.hostname, 255), AGENT_HOSTNAME
        evidence.add(AGENT_HOSTNAME, data.hostname)
    os_text = " ".join(filter(None, (data.os_name, data.os_version)))
    if os_text:
        evidence.add(AGENT_OS, os_text)
    host = (data.hostname or "").lower()
    if adapter_profile is not None and adapter_profile.kind == VendorKind.VIRTUAL:
        device_type, reason = T.VIRTUAL_MACHINE, f"interfaz virtual {adapter_profile.brand}"
    elif "server" in os_text.lower() or re.match(r"^win-[a-z0-9]{11}$", host):
        device_type, reason = T.SERVER, f"agente Sentra ({os_text or host})"
    elif re.match(r"^laptop-[a-z0-9]{8}$", host):
        device_type, reason = T.LAPTOP, f"agente Sentra, nombre {data.hostname}"
    else:
        device_type, reason = T.PC, f"agente Sentra ({os_text or 'equipo con agente'})"
    result.device_type = device_type
    result.confidence = Confidence.HIGH
    result.reason = _clip(reason, 255)
    if adapter_profile is not None and adapter_profile.kind == VendorKind.DEVICE:
        result.device_vendor = adapter_profile.brand
    result.evidence = evidence.items


@dataclass(frozen=True)
class _Name:
    source: str
    value: str
    kind: str
    stale: bool = False
    confirmed: bool | None = None


def is_default_name(value: str | None) -> bool:
    """¿Es un hostname por defecto de un SO o firmware ("linux", "android")?"""
    return bool(value) and _DEFAULT_OS_NAMES.match((value or "").strip()) is not None


def _name_kind(source: str, raw: str, value: str) -> str:
    if _DEFAULT_OS_NAMES.match(value):
        return NAME_KIND_GENERIC
    if source == DHCP_LEASE:
        return NAME_KIND_DHCP
    if source != REVERSE_DNS:
        return NAME_KIND_DEVICE
    lowered = raw.strip().rstrip(".").lower()
    # El resolvedor del sistema (Windows, systemd-resolved) contesta con mDNS/LLMNR cuando el
    # DNS no conoce la IP: un nombre .local lo publica el propio equipo.
    if lowered.endswith(".local"):
        return NAME_KIND_DEVICE
    if "." not in lowered or any(lowered.endswith(suffix) for suffix in _LOCAL_SUFFIXES):
        return NAME_KIND_DHCP
    return NAME_KIND_DNS


def _name_candidates(data: IdentityInput) -> list[_Name]:
    raw_names = (
        (DHCP_LEASE, data.dhcp_hostname, _short_name(data.dhcp_hostname)),
        (REVERSE_DNS, data.reverse_dns, _short_name(data.reverse_dns)),
        (MDNS, data.mdns_name, _short_name(data.mdns_name)),
        (NETBIOS, data.netbios_name, _clean_name(data.netbios_name)),
        (UPNP, data.upnp_friendly_name, _clean_name(data.upnp_friendly_name)),
    )
    found: list[_Name] = []
    for source, raw, name in raw_names:
        if not raw or not name:
            continue
        found.append(
            _Name(
                source=source,
                value=name,
                kind=_name_kind(source, raw, name),
                stale=source in data.stale_sources,
                confirmed=data.reverse_dns_confirmed if source == REVERSE_DNS else None,
            )
        )
    return found


def _choose_name(candidates: list[_Name]) -> _Name | None:
    """Nombre automático: el mejor por procedencia, confirmación y vigencia.

    Orden: primero los nombres recientes, después los no desmentidos (un DNS inverso que no
    resuelve a esta IP pasa al final) y, a igualdad, el orden de NAME_SOURCES. Un nombre
    genérico nunca se elige: es preferible "IoT probable" a mostrar "linux" como si fuera el
    nombre del equipo.
    """
    usable = [c for c in candidates if c.kind != NAME_KIND_GENERIC]
    if not usable:
        return None
    return min(
        usable,
        key=lambda c: (c.stale, c.confirmed is False, NAME_SOURCES.index(c.source)),
    )


def _names_view(candidates: list[_Name], chosen: _Name | None) -> list[dict[str, Any]]:
    return [
        {
            "source": c.source,
            "value": c.value,
            "kind": c.kind,
            "selected": c is chosen,
            "confirmed": c.confirmed,
            "stale": c.stale,
        }
        for c in candidates
    ]


def _agent_name(hostname: str) -> dict[str, Any]:
    return {
        "source": AGENT_HOSTNAME,
        "value": _clip(hostname, 255),
        "kind": NAME_KIND_AGENT,
        "selected": True,
        "confirmed": None,
        "stale": False,
    }


def _has_family_vote(types: dict[DeviceType, _Score], device_type: DeviceType) -> bool:
    """¿Alguna fuente que no sean los puertos sugiere ya este tipo (o uno compatible)?"""
    return any(
        score.total > 0 and score.sources - {PORTS} and compatible(t, device_type)
        for t, score in types.items()
    )


def _vendor_conflicts(vendors: dict[str, _Score], evidence: _Evidence) -> None:
    """Deja constancia de fabricantes distintos que declaran fuentes independientes.

    Ejemplo: OUI Amazon y fabricante UPnP Sonos. El que gana (o ninguno, si empatan) sale
    de _pick; aquí solo se conserva la contradicción para que nadie la tome por certeza.
    """
    declared = [
        (brand, score) for brand, score in vendors.items() if score.sources & {MAC_VENDOR, UPNP}
    ]
    if len(declared) < 2:
        return
    parts = sorted(f"{brand} ({', '.join(sorted(s.sources))})" for brand, s in declared)
    evidence.add(CONFLICT, "fabricantes distintos: " + " / ".join(parts))


def _type_conflicts(
    types: dict[DeviceType, _Score], winner: DeviceType | None, evidence: _Evidence
) -> None:
    contenders = sorted(
        (
            t
            for t, s in types.items()
            if s.total > 0 and (winner is None or not compatible(t, winner))
        ),
        key=lambda t: t.value,
    )
    if winner is not None and contenders:
        evidence.add(CONFLICT, "también apunta a: " + ", ".join(t.value for t in contenders))
    elif winner is None and len(contenders) >= 2:
        evidence.add(CONFLICT, "pistas incompatibles: " + ", ".join(t.value for t in contenders))


def _corroborate(types: dict[DeviceType, _Score], vendors: dict[str, _Score]) -> None:
    """Sube la puntuación de un tipo cuando su marca la confirma una fuente independiente.

    "MNA-LX9" solo es un nombre que alguien pudo escribir; con un OUI Huawei (o un fabricante
    UPnP Huawei) deja de ser una coincidencia. Solo cuentan como confirmación las fuentes
    que no son nombres: otro nombre del mismo equipo repetiría la misma pista.
    """
    for score in types.values():
        for vendor in sorted(score.implied):
            backing = vendors[vendor].sources & {MAC_VENDOR, UPNP} if vendor in vendors else set()
            if backing:
                score.total += 2
                score.sources |= backing
                score.reasons.append(f"confirmado por fabricante {vendor}")
                break


def _pick_type(
    types: dict[DeviceType, _Score],
) -> tuple[DeviceType | None, ClassificationConfidence | None, _Score | None]:
    ranked = sorted(types.items(), key=lambda item: item[1].total, reverse=True)
    if not ranked or ranked[0][1].total <= 0:
        return None, None, None
    winner, score = ranked[0]
    rival = max((s.total for t, s in ranked[1:] if not compatible(t, winner)), default=0)
    margin = score.total - rival
    # Empate con un tipo incompatible: no se elige al azar, se deja desconocido.
    if margin <= 0:
        return None, None, None
    return winner, _confidence(score, margin), score


def _confidence(score: _Score, margin: int) -> ClassificationConfidence:
    if score.total >= AUTHORITATIVE and margin >= 2:
        return Confidence.HIGH
    if score.total >= 2 and margin >= 2:
        return Confidence.MEDIUM
    return Confidence.LOW


def _pick(table: dict[str, _Score], minimum: int = 1) -> str | None:
    ranked = sorted(table.items(), key=lambda item: item[1].total, reverse=True)
    if not ranked or ranked[0][1].total < minimum:
        return None
    # Dos candidatos igual de respaldados se contradicen: mejor no afirmar ninguno.
    if len(ranked) > 1 and ranked[1][1].total == ranked[0][1].total:
        return None
    return ranked[0][0]


def _name_hints(name: str) -> Iterable[_Hint]:
    for pattern, hint in _NAME_HINTS:
        if pattern.search(name):
            yield hint


def _clean_name(value: str | None) -> str | None:
    if not value:
        return None
    text = "".join(ch for ch in value if ch.isprintable()).strip()
    if not text or _GENERIC_NAMES.match(text):
        return None
    return _clip(text, 255)


def _short_name(value: str | None) -> str | None:
    """Nombre DNS/mDNS para mostrar: sin el dominio local que añade el router."""
    name = _clean_name(value)
    if name is None:
        return None
    name = name.rstrip(".")
    lowered = name.lower()
    for suffix in _LOCAL_SUFFIXES:
        if lowered.endswith(suffix) and "." not in name[: -len(suffix)]:
            name = name[: -len(suffix)]
            break
    # Algunos routers devuelven la propia IP con guiones ("192-168-1-20"): no es un nombre.
    if re.fullmatch(r"(ip-)?\d{1,3}([-.]\d{1,3}){3}", name, re.IGNORECASE):
        return None
    return _clean_name(name)


def _clip(value: str, limit: int = MAX_VALUE) -> str:
    return value if len(value) <= limit else value[: limit - 1] + "…"
