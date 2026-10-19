"""Interpretación de la evidencia Wi-Fi (Fase 6C.3, docs/wlan-discovery.md).

Tablas cerradas por fuente: lo que no está aquí se deja en None ("no disponible"), nunca se
adivina. En particular la banda solo se deduce cuando la evidencia la fija sin ambigüedad (el
canal 1 existe en 2,4 GHz y en 6 GHz, así que un canal suelto no basta).
"""

import re

# Fuentes (columna `source`) y su confianza.
SOURCE_DOT11 = "snmp_ieee802dot11"
SOURCE_AIRESPACE = "snmp_airespace"
SOURCE_UNIFI = "snmp_unifi"
SOURCE_AGENT = "agent"
SNMP_SOURCES = {"ieee802dot11": SOURCE_DOT11, "airespace": SOURCE_AIRESPACE, "unifi": SOURCE_UNIFI}
ALL_SOURCES = (SOURCE_DOT11, SOURCE_AIRESPACE, SOURCE_UNIFI, SOURCE_AGENT)
# Lo que informa la propia infraestructura gestionada (controladora o AP consultado).
REPORTED = "reported_by_device"
# Lo que un agente ve por radio: no prueba que el AP pertenezca a la organización.
OBSERVED = "observed"

# Fabricante implícito en la MIB propietaria (la MIB solo existe en ese fabricante).
SOURCE_VENDOR = {SOURCE_AIRESPACE: "Cisco", SOURCE_UNIFI: "Ubiquiti"}

# IEEE802dot11-MIB dot11PHYType → estándar.
DOT11_PHY_STANDARD = {
    1: "802.11",  # fhss
    2: "802.11",  # dsss
    3: "802.11",  # irbaseband
    4: "802.11a",  # ofdm
    5: "802.11b",  # hrdsss
    6: "802.11g",  # erp
    7: "802.11n",  # ht
    8: "802.11ad",  # dmg
    9: "802.11ac",  # vht
    10: "802.11af",  # tvht
    11: "802.11ah",  # s1g
    14: "802.11ax",  # he
}
# PHYs que solo existen en una banda.
DOT11_PHY_BAND = {2: "2.4", 5: "2.4", 6: "2.4", 4: "5", 9: "5"}

# AIRESPACE-WIRELESS-MIB.
AIRESPACE_AP_STATUS = {1: "up", 2: "transitional", 3: "transitional"}
AIRESPACE_RADIO_BAND = {1: "2.4", 2: "5"}
AIRESPACE_RADIO_STATUS = {1: "down", 2: "up"}
AIRESPACE_STATION_STATE = {
    0: "idle",
    1: "pending",
    2: "authenticated",
    3: "associated",
    4: "power_save",
    5: "disassociated",
    6: "disassociated",
    7: "probing",
    8: "excluded",
}
AIRESPACE_STATION_PROTOCOL = {
    1: ("802.11a", "5"),
    2: ("802.11b", "2.4"),
    3: ("802.11g", "2.4"),
    6: ("802.11n", "2.4"),
    7: ("802.11n", "5"),
}
# UBNT-UniFi-MIB unifiVapRadio.
UNIFI_RADIO_BAND = {"ng": "2.4", "na": "5"}

# Protecciones normalizadas. Las inseguras producen una observación técnica en la API, pero
# NO contribuyen al Risk Engine (no hay política aprobada para ello).
PROTECTIONS = (
    "open",
    "owe",
    "wep",
    "wpa",
    "wpa_wpa2",
    "wpa2",
    "wpa2_wpa3",
    "wpa3",
    "rsn",
    "legacy",
    "unknown",
)
INSECURE_PROTECTIONS = {
    "open": "open_network",
    "wep": "wep",
    "wpa": "wpa1",
    "wpa_wpa2": "wpa1_allowed",
    "legacy": "legacy_privacy",
}

_STANDARD = re.compile(r"802\.11\s*([a-z]{1,2})\b")


def mac_randomized(mac: str | None) -> bool:
    """Bit "localmente administrado" (0x02 del primer octeto): MAC aleatoria o asignada por
    software. Nunca identifica por sí sola un dispositivo físico."""
    if not mac:
        return False
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def band_from_frequency(mhz: int | None) -> str | None:
    if mhz is None:
        return None
    if 2400 <= mhz <= 2500:
        return "2.4"
    if 4900 <= mhz <= 5895:
        return "5"
    if 5925 <= mhz <= 7125:
        return "6"
    return None


def frequency_from_channel(band: str | None, channel: int | None) -> int | None:
    """Frecuencia central de un canal de 20 MHz cuando la banda es conocida."""
    if band is None or channel is None:
        return None
    if band == "2.4":
        if channel == 14:
            return 2484
        return 2407 + 5 * channel if 1 <= channel <= 13 else None
    if band == "5":
        return 5000 + 5 * channel if 32 <= channel <= 177 else None
    if band == "6":
        return 5950 + 5 * channel if 1 <= channel <= 233 else None
    return None


def dot11_band(phy_type: int | None, channel: int | None) -> str | None:
    if phy_type in DOT11_PHY_BAND:
        return DOT11_PHY_BAND[phy_type]
    if phy_type == 7 and channel is not None:
        # HT solo existe en 2,4 y 5 GHz: ahí el canal sí desambigua.
        if 1 <= channel <= 14:
            return "2.4"
        if channel >= 32:
            return "5"
    return None


def dot11_protection(privacy: int | None, rsna: int | None) -> str | None:
    """dot11PrivacyInvoked y dot11RSNAEnabled (TruthValue 1/2).

    Sin privacidad la red es abierta. Con privacidad y RSNA es RSN (WPA2 o WPA3: la MIB no
    dice cuál sin tablas de suites que no se leen). Con privacidad sin RSNA es WEP o WPA1
    ("legacy"). Sin la columna RSNA (MIB antigua) no se puede saber: "unknown".
    """
    if privacy is None:
        return None
    if privacy == 2:
        return "open"
    if rsna == 1:
        return "rsn"
    if rsna == 2:
        return "legacy"
    return "unknown"


def normalize_security(reported: str | None) -> str | None:
    """Texto de seguridad que da el sistema operativo (system_profiler, netsh, nmcli) →
    protección normalizada. Las variantes conocidas de cada herramienta están en los tests."""
    if reported is None:
        return None
    text = reported.lower().replace("-", " ").replace("_", " ").strip()
    if text in ("", "none", "open", "open none", "spairport security mode none"):
        return "open"
    if "owe" in text.split() or "enhanced open" in text:
        return "owe"
    if "wep" in text:
        return "wep"
    has_wpa3 = "wpa3" in text or "sae" in text.split()
    has_wpa2 = "wpa2" in text or "rsn" in text.split()
    tokens = text.replace("/", " ").split()
    has_wpa1 = "wpa" in tokens or "wpa1" in tokens
    if has_wpa3 and has_wpa2:
        return "wpa2_wpa3"
    if has_wpa3:
        return "wpa3"
    if has_wpa2 and has_wpa1:
        return "wpa_wpa2"
    if has_wpa2:
        return "wpa2"
    if has_wpa1:
        return "wpa"
    if text.startswith("open"):
        return "open"
    return "unknown"


def normalize_standard(phy_mode: str | None) -> str | None:
    if not phy_mode:
        return None
    match = _STANDARD.search(phy_mode.lower())
    return f"802.11{match.group(1)}" if match else None


def insecure_finding(protection: str | None, reported: str | None) -> str | None:
    """Código de la observación técnica de configuración insegura (o None)."""
    if protection in INSECURE_PROTECTIONS:
        return INSECURE_PROTECTIONS[protection]
    if reported and "tkip" in reported.lower():
        return "tkip_allowed"
    return None
