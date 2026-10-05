"""Qué dice (y qué NO dice) un nombre de fabricante sobre el dispositivo.

El registro OUI devuelve organizaciones como "HUAWEI TECHNOLOGIES CO.,LTD" o "Realtek
Semiconductor Corp.". Esta tabla las reduce a una marca corta y, sobre todo, distingue:

- DEVICE: fabricantes de dispositivos completos. Su OUI en la interfaz principal suele
  coincidir con el fabricante del equipo (Huawei, Apple, Nintendo...).
- COMPONENT: fabricantes de chips, NICs o módulos que acaban dentro de equipos de cualquier
  marca (Realtek, Intel, Broadcom...). Solo dicen quién hizo la tarjeta de red: un
  "Realtek" puede ser un PC, una consola con adaptador USB o una Smart TV.
- VIRTUAL: interfaces de hipervisores. Indican máquina virtual con bastante seguridad.

Las pistas de tipo son débiles a propósito (fuerza 1-2): Samsung fabrica móviles y
televisores, TP-Link routers y enchufes inteligentes. Una marca nunca decide el tipo sola
salvo casos casi unívocos (Nintendo, Roku, Synology...). Un fabricante que no está en la
tabla no se usa como fabricante del dispositivo: no sabemos si hizo el equipo o solo la NIC.
"""

import re
from dataclasses import dataclass
from enum import StrEnum

from app.discovery.device_types import DeviceType


class VendorKind(StrEnum):
    DEVICE = "device"
    COMPONENT = "component"
    VIRTUAL = "virtual"


@dataclass(frozen=True)
class VendorProfile:
    brand: str
    kind: VendorKind
    type_hint: DeviceType | None = None
    # 1 = débil (la marca hace muchos tipos de producto), 2 = media (casi siempre ese tipo).
    hint_strength: int = 0


def _p(
    pattern: str,
    brand: str,
    kind: VendorKind = VendorKind.DEVICE,
    hint: DeviceType | None = None,
    strength: int = 0,
) -> tuple[re.Pattern[str], VendorProfile]:
    return re.compile(pattern, re.IGNORECASE), VendorProfile(brand, kind, hint, strength)


D, C, V = VendorKind.DEVICE, VendorKind.COMPONENT, VendorKind.VIRTUAL
T = DeviceType

# El orden importa: la primera coincidencia gana (p. ej. "Sony Interactive" antes que "Sony").
_PROFILES: tuple[tuple[re.Pattern[str], VendorProfile], ...] = (
    # --- Virtualización -----------------------------------------------------------------
    _p(r"\bvmware\b", "VMware", V, T.VIRTUAL_MACHINE, 2),
    _p(r"qemu/kvm", "QEMU/KVM", V, T.VIRTUAL_MACHINE, 2),
    _p(r"\bpcs systemtechnik\b|\bvirtualbox\b", "VirtualBox", V, T.VIRTUAL_MACHINE, 2),
    _p(r"\bxensource\b", "Xen", V, T.VIRTUAL_MACHINE, 2),
    _p(r"\bparallels\b", "Parallels", V, T.VIRTUAL_MACHINE, 2),
    _p(r"\bproxmox\b", "Proxmox", V, T.VIRTUAL_MACHINE, 2),
    # --- Chips, NICs y módulos: dicen quién hizo la tarjeta, no el equipo --------------
    _p(r"\brealtek\b", "Realtek", C),
    _p(r"\bintel\b", "Intel", C),
    _p(r"\bbroadcom\b", "Broadcom", C),
    _p(r"\bqualcomm\b|\batheros\b", "Qualcomm", C),
    _p(r"\bmediatek\b|\bralink\b", "MediaTek", C),
    _p(r"\bmarvell\b", "Marvell", C),
    _p(r"\bazurewave\b", "AzureWave", C),
    _p(r"\bhon hai\b|\bfoxconn\b", "Foxconn", C),
    _p(r"\blite-?on\b", "Lite-On", C),
    _p(r"\bmurata\b", "Murata", C),
    _p(r"\basix\b", "ASIX", C),
    _p(r"\bmicrochip\b", "Microchip", C),
    _p(r"\bcypress\b", "Cypress", C),
    _p(r"\btexas instruments\b", "Texas Instruments", C),
    _p(r"\bwistron\b", "Wistron", C),
    _p(r"\bquanta\b", "Quanta", C),
    _p(r"\bcompal\b", "Compal", C),
    _p(r"\buniversal global scientific\b", "USI", C),
    _p(r"\bsilicon labs?\b|\bsilicon laboratories\b", "Silicon Labs", C, T.IOT, 1),
    # Los módulos Wi-Fi de Espressif (ESP8266/ESP32) van casi siempre en dispositivos IoT,
    # pero el fabricante del producto final es otro: pista de tipo sí, marca no.
    _p(r"\bespressif\b", "Espressif", C, T.IOT, 2),
    _p(r"\btuya\b", "Tuya", C, T.IOT, 2),
    # --- Consolas -----------------------------------------------------------------------
    _p(r"\bnintendo\b", "Nintendo", D, T.CONSOLE, 2),
    _p(r"\bsony interactive\b|\bsony computer entertainment\b", "Sony", D, T.CONSOLE, 2),
    # --- Móviles y fabricantes de electrónica de consumo -------------------------------
    _p(r"\bhuawei\b", "Huawei", D),
    _p(r"\bhonor device\b", "Honor", D, T.MOBILE, 1),
    _p(r"\bapple\b", "Apple", D),
    _p(r"\bsamsung\b", "Samsung", D),
    _p(r"\bxiaomi\b|\bbeijing xiaomi\b", "Xiaomi", D),
    _p(r"\boneplus\b", "OnePlus", D, T.MOBILE, 2),
    _p(r"\bguangdong oppo\b|\boppo\b", "OPPO", D, T.MOBILE, 2),
    _p(r"\bvivo mobile\b", "vivo", D, T.MOBILE, 2),
    _p(r"\bmotorola mobility\b", "Motorola", D, T.MOBILE, 2),
    _p(r"\bgoogle\b", "Google", D),
    _p(r"\bamazon\b", "Amazon", D, T.IOT, 1),
    _p(r"\bsony\b", "Sony", D),
    _p(r"\blg electronics\b|\blg innotek\b", "LG", D),
    _p(r"\broku\b", "Roku", D, T.SMART_TV, 2),
    _p(r"\bvizio\b", "Vizio", D, T.SMART_TV, 2),
    _p(r"\bhisense\b", "Hisense", D, T.SMART_TV, 2),
    _p(r"\btcl\b", "TCL", D),
    _p(r"\bsonos\b", "Sonos", D, T.IOT, 2),
    _p(r"\bmicrosoft\b", "Microsoft", D),
    _p(r"\blenovo\b", "Lenovo", D),
    _p(r"\bdell\b", "Dell", D),
    _p(r"\bhewlett[ -]packard\b|\bhp inc\b", "HP", D),
    _p(r"\bmicro-star\b|\bmsi\b", "MSI", D),
    _p(r"\bgigabyte\b|\bgiga-byte\b", "Gigabyte", D),
    _p(r"\braspberry pi\b", "Raspberry Pi", D),
    # --- Red ----------------------------------------------------------------------------
    _p(r"\basustek\b|\basus\b", "ASUS", D),
    _p(r"\btp-?link\b", "TP-Link", D),
    _p(r"\bnetgear\b", "Netgear", D),
    _p(r"\bd-link\b", "D-Link", D),
    _p(r"\bzyxel\b", "Zyxel", D),
    _p(r"\blinksys\b|\bbelkin\b", "Linksys", D),
    _p(r"\bubiquiti\b", "Ubiquiti", D, T.ACCESS_POINT, 1),
    _p(r"\brouterboard\b|\bmikrotik\b", "MikroTik", D, T.ROUTER, 2),
    _p(r"\bcisco\b|\bmeraki\b", "Cisco", D),
    _p(r"\baruba\b", "Aruba", D, T.ACCESS_POINT, 1),
    _p(r"\bjuniper\b", "Juniper", D),
    _p(r"\bfortinet\b", "Fortinet", D, T.ROUTER, 1),
    _p(r"\bavm\b", "AVM", D, T.ROUTER, 2),
    _p(r"\bsagemcom\b", "Sagemcom", D, T.ROUTER, 2),
    _p(r"\barcadyan\b", "Arcadyan", D, T.ROUTER, 2),
    _p(r"\bmitrastar\b", "MitraStar", D, T.ROUTER, 2),
    # --- Impresoras ----------------------------------------------------------------------
    _p(r"\bbrother\b", "Brother", D, T.PRINTER, 2),
    _p(r"\bseiko epson\b|\bepson\b", "Epson", D, T.PRINTER, 2),
    _p(r"\bcanon\b", "Canon", D, T.PRINTER, 1),
    _p(r"\blexmark\b", "Lexmark", D, T.PRINTER, 2),
    _p(r"\bxerox\b", "Xerox", D, T.PRINTER, 2),
    _p(r"\bkyocera\b", "Kyocera", D, T.PRINTER, 2),
    _p(r"\bricoh\b", "Ricoh", D, T.PRINTER, 2),
    # --- NAS ------------------------------------------------------------------------------
    _p(r"\bsynology\b", "Synology", D, T.NAS, 2),
    _p(r"\bqnap\b", "QNAP", D, T.NAS, 2),
    _p(r"\bwestern digital\b", "Western Digital", D),
    # --- IoT -----------------------------------------------------------------------------
    _p(r"\bsignify\b|\bphilips lighting\b", "Philips Hue", D, T.IOT, 2),
    _p(r"\bnest labs\b", "Google Nest", D, T.IOT, 2),
    _p(r"\becobee\b", "ecobee", D, T.IOT, 2),
    _p(r"\bshelly\b|\ballterco\b", "Shelly", D, T.IOT, 2),
    _p(r"\bhikvision\b", "Hikvision", D, T.IOT, 2),
    _p(r"\bdahua\b", "Dahua", D, T.IOT, 2),
)

# Sufijos societarios que no aportan nada a la marca mostrada.
_LEGAL_SUFFIX = re.compile(
    r"[,.\s]*\b(co\.?,?\s*ltd|ltd|limited|inc|incorporated|corp|corporation|gmbh|s\.?a|"
    r"llc|ag|b\.?v|technologies|technology|electronics)\b\.?$",
    re.IGNORECASE,
)


def profile_for(organization: str | None) -> VendorProfile | None:
    """Perfil conocido de una organización (OUI o fabricante UPnP), o None."""
    if not organization:
        return None
    for pattern, profile in _PROFILES:
        if pattern.search(organization):
            return profile
    return None


def display_vendor(organization: str | None) -> str | None:
    """Marca corta si se conoce; si no, el nombre registrado sin sufijos societarios."""
    if not organization:
        return None
    profile = profile_for(organization)
    if profile is not None:
        return profile.brand
    name = organization.strip()
    for _ in range(3):  # "Foo Technologies Co., Ltd." tiene varios sufijos encadenados
        stripped = _LEGAL_SUFFIX.sub("", name).strip(" ,.")
        if not stripped or stripped == name:
            break
        name = stripped
    return name[:128] or None
