"""Colector Wi-Fi pasivo (Fase 6C.5) para Windows, Linux y macOS.

Qué hace: lee lo que el sistema operativo YA sabe de sus redes inalámbricas (la red a la que
está conectado y la lista de redes que el propio sistema mantiene de su último escaneo) y lo
envía como campo opcional `wireless` del inventario. Qué no hace, nunca:

- escanear: no se fuerza ningún escaneo (nmcli `--rescan no`; netsh y system_profiler solo
  devuelven resultados cacheados por el sistema);
- leer credenciales: ni `netsh wlan show profile ... key=clear`, ni el llavero, ni ficheros
  de NetworkManager. Ninguna orden de este módulo devuelve claves;
- inventar datos: un campo que el sistema no da (o que oculta por privacidad, como el SSID
  sin permiso de Localización en macOS 14.4+) se envía como null y el estado lo explica.

Fuentes (rutas absolutas, sin shell, con plazo y cupo de salida, vía syscmd.run_bounded):
- macOS: `/usr/sbin/system_profiler SPAirPortDataType -json`;
- Windows: `netsh wlan show interfaces` y `netsh wlan show networks mode=bssid`;
- Linux: `nmcli -t -f ... dev wifi list --rescan no` y `nmcli -t -f ... dev status`.

Estados: ok, no_adapter (sin adaptador Wi-Fi), permission_limited (el sistema oculta parte
de los datos por privacidad/permisos), unsupported (falta la herramienta) y error.

Idioma (Windows): netsh traduce las etiquetas al idioma del sistema. El parser reconoce por
la forma del valor lo que no depende del idioma (SSID n, BSSID n, señal en %, tipo de radio
802.11, banda en GHz, Rssi, direcciones MAC) y por una tabla de etiquetas en inglés,
español, francés, alemán, italiano y portugués el canal, la autenticación y el cifrado. En
otro idioma esos tres campos llegan como null (limitación documentada, sin inventar).

VALIDACIÓN REAL PENDIENTE: los parsers se prueban con salidas reales guardadas como
fixtures; falta probarlos con hardware Wi-Fi real en las tres plataformas.
"""

import json
import logging
import os
import re
import sys
import time
import unicodedata
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import psutil

from sentra_agent.syscmd import (
    CommandOutput,
    CommandTimeoutError,
    CommandUnavailableError,
    run_bounded,
)

logger = logging.getLogger("sentra_agent")

STATUS_OK = "ok"
STATUS_NO_ADAPTER = "no_adapter"
STATUS_PERMISSION_LIMITED = "permission_limited"
STATUS_UNSUPPORTED = "unsupported"
STATUS_ERROR = "error"

SOURCE_MACOS = "macos_system_profiler"
SOURCE_WINDOWS = "windows_netsh"
SOURCE_LINUX = "linux_nmcli"

MAX_INTERFACES = 8
MAX_NETWORKS = 256
# Un SSID son como mucho 32 bytes; 64 caracteres cubren SSID no ASCII decodificados.
SSID_MAX = 64
NAME_MAX = 64
SECURITY_MAX = 64
PHY_MODE_MAX = 32

SYSTEM_PROFILER = "/usr/sbin/system_profiler"
NMCLI_PATHS = ("/usr/bin/nmcli", "/bin/nmcli")
# system_profiler tarda varios segundos en Macs con muchas redes alrededor.
TIMEOUT_SECONDS = 60.0
MAX_OUTPUT_BYTES = 4 * 1024 * 1024
# Salida de nmcli sin traducir: los valores (Infra, MHz) no dependen del idioma del equipo.
_LINUX_ENV = {"LC_ALL": "C", "LANG": "C", "PATH": "/usr/bin:/bin"}

CommandRunner = Callable[[list[str]], CommandOutput]


def _run(argv: list[str]) -> CommandOutput:
    env = _LINUX_ENV if sys.platform.startswith("linux") else None
    return run_bounded(argv, timeout=TIMEOUT_SECONDS, max_bytes=MAX_OUTPUT_BYTES, env=env)


# --- Normalización común --------------------------------------------------------------------

_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_MAC = re.compile(r"^[0-9A-Fa-f]{1,2}([:-])(?:[0-9A-Fa-f]{1,2}\1){4}[0-9A-Fa-f]{1,2}$")


def _text(value: object, limit: int) -> str | None:
    if value is None:
        return None
    text = _CONTROL.sub("", str(value)).strip()
    return text[:limit] or None


def normalize_mac(value: object) -> str | None:
    """Normaliza "AA-BB-CC-DD-EE-FF" o "a4:83:e7:1:2:3" (macOS sin ceros) a minúsculas."""
    text = str(value or "").strip()
    if not _MAC.match(text):
        return None
    parts = re.split(r"[:-]", text)
    mac = ":".join(part.zfill(2) for part in parts).lower()
    # Todo ceros o todo F: valores de relleno, no una dirección real.
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return None
    return mac


def band_for_frequency(frequency: int | None) -> str | None:
    if frequency is None:
        return None
    if 2400 <= frequency < 2500:
        return "2.4"
    if 5150 <= frequency < 5925:
        return "5"
    if 5925 <= frequency <= 7125:
        return "6"
    return None


def frequency_for_channel(channel: int | None, band: str | None) -> int | None:
    """Frecuencia central (MHz) del canal según la banda (IEEE 802.11)."""
    if channel is None or band is None:
        return None
    if band == "2.4":
        if channel == 14:
            return 2484
        return 2407 + 5 * channel if 1 <= channel <= 13 else None
    if band == "5":
        return 5000 + 5 * channel if 1 <= channel <= 196 else None
    if band == "6":
        return 5950 + 5 * channel if 1 <= channel <= 233 else None
    return None


def channel_for_frequency(frequency: int | None) -> int | None:
    if frequency is None:
        return None
    if frequency == 2484:
        return 14
    band = band_for_frequency(frequency)
    if band == "2.4":
        return (frequency - 2407) // 5
    if band == "5":
        return (frequency - 5000) // 5
    if band == "6":
        return (frequency - 5950) // 5
    return None


def _band_from_text(text: str) -> str | None:
    match = re.search(r"(\d(?:[.,]\d)?)\s*GHz", text, re.IGNORECASE)
    if not match:
        return None
    value = match.group(1).replace(",", ".")
    return {"2": "2.4", "2.4": "2.4", "5": "5", "6": "6"}.get(value)


def _int(value: object) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def make_network(
    *,
    ssid: object = None,
    bssid: object = None,
    channel: int | None = None,
    frequency_mhz: int | None = None,
    band: str | None = None,
    security: object = None,
    signal_dbm: int | None = None,
    signal_quality: int | None = None,
    phy_mode: object = None,
    connected: bool = False,
) -> dict[str, Any]:
    """Red con el contrato exacto; deduce banda/frecuencia/canal solo por la norma 802.11."""
    if band is None:
        band = band_for_frequency(frequency_mhz)
    if band is None and channel is not None:
        # Sin banda informada (netsh de Windows 10): 1-14 solo existe en 2,4 GHz; el resto
        # se asume 5 GHz porque esas versiones no soportan 6 GHz.
        band = "2.4" if 1 <= channel <= 14 else "5"
    if frequency_mhz is None:
        frequency_mhz = frequency_for_channel(channel, band)
    if channel is None:
        channel = channel_for_frequency(frequency_mhz)
    if signal_dbm is not None and not -120 <= signal_dbm <= 0:
        signal_dbm = None
    if signal_quality is not None and not 0 <= signal_quality <= 100:
        signal_quality = None
    return {
        "ssid": _text(ssid, SSID_MAX),
        "bssid": normalize_mac(bssid),
        "channel": channel if channel is not None and 0 < channel <= 233 else None,
        "frequency_mhz": frequency_mhz,
        "band": band,
        "security": _text(security, SECURITY_MAX),
        "signal_dbm": signal_dbm,
        "signal_quality": signal_quality,
        "phy_mode": _text(phy_mode, PHY_MODE_MAX),
        "connected": bool(connected),
    }


def make_interface(
    name: object, mac: object = None, ssid: object = None, bssid: object = None
) -> dict[str, Any]:
    return {
        "name": _text(name, NAME_MAX) or "unknown",
        "mac": normalize_mac(mac),
        "connected_ssid": _text(ssid, SSID_MAX),
        "connected_bssid": normalize_mac(bssid),
    }


def _finish_networks(networks: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sin duplicados (por BSSID, o SSID+canal si no hay BSSID), conectadas y fuertes antes."""
    unique: dict[tuple[Any, ...], dict[str, Any]] = {}
    for network in networks:
        key: tuple[Any, ...] = (
            ("bssid", network["bssid"])
            if network["bssid"]
            else ("ssid", network["ssid"], network["channel"], network["security"])
        )
        current = unique.get(key)
        if current is None or (network["connected"] and not current["connected"]):
            unique[key] = network
    ordered = sorted(
        unique.values(),
        key=lambda n: (
            not n["connected"],
            -(n["signal_dbm"] if n["signal_dbm"] is not None else -200),
            -(n["signal_quality"] if n["signal_quality"] is not None else -1),
        ),
    )
    return ordered[:MAX_NETWORKS]


def result(
    status: str,
    source: str,
    interfaces: list[dict[str, Any]] | None = None,
    networks: list[dict[str, Any]] | None = None,
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "source": source,
        "collected_at": (collected_at or datetime.now(UTC)).isoformat(),
        "interfaces": (interfaces or [])[:MAX_INTERFACES],
        "networks": _finish_networks(networks or []),
    }


# --- macOS: system_profiler -----------------------------------------------------------------

# macOS 14.4+ sin permiso de Localización: el SSID (y el BSSID) se sustituyen por esto.
_REDACTED = ("<redacted>", "<private>", "<hidden>")
# Interfaces de Apple sin redes de usuario (AirDrop/AWDL y su enlace de baja latencia).
_MAC_SKIP = ("awdl", "llw")


def _redacted(value: object) -> bool:
    return isinstance(value, str) and value.strip().lower() in _REDACTED


def _mac_security(value: object) -> str | None:
    text = str(value or "")
    # "spairport_security_mode_wpa2_personal" -> "wpa2_personal"; algunos macOS escriben
    # el prefijo sin la "s" inicial.
    marker = "security_mode_"
    return text.split(marker, 1)[1] if marker in text else (text or None)


def _mac_network(entry: dict[str, Any], connected: bool) -> tuple[dict[str, Any], bool]:
    """Red de system_profiler y si sus identificadores venían ocultos."""
    name = entry.get("_name")
    hidden = _redacted(name) or _redacted(entry.get("spairport_network_bssid"))
    channel_text = str(entry.get("spairport_network_channel") or "")
    channel_match = re.match(r"^\s*(\d+)", channel_text)
    signal_match = re.match(r"^\s*(-?\d+)\s*dBm", str(entry.get("spairport_signal_noise") or ""))
    network = make_network(
        ssid=None if _redacted(name) else name,
        bssid=None if hidden else entry.get("spairport_network_bssid"),
        channel=int(channel_match.group(1)) if channel_match else None,
        band=_band_from_text(channel_text),
        security=_mac_security(entry.get("spairport_security_mode")),
        signal_dbm=int(signal_match.group(1)) if signal_match else None,
        phy_mode=entry.get("spairport_network_phymode"),
        connected=connected,
    )
    return network, hidden


def parse_system_profiler(data: Any) -> tuple[str, list[dict[str, Any]], list[dict[str, Any]]]:
    """Salida JSON de `system_profiler SPAirPortDataType -json` -> (estado, interfaces, redes)."""
    if not isinstance(data, dict):
        raise ValueError("unexpected system_profiler output")
    interfaces: list[dict[str, Any]] = []
    networks: list[dict[str, Any]] = []
    limited = False
    for section in data.get("SPAirPortDataType") or []:
        if not isinstance(section, dict):
            continue
        for item in section.get("spairport_airport_interfaces") or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("_name") or "")
            if not name or name.startswith(_MAC_SKIP):
                continue
            current = item.get("spairport_current_network_information")
            connected_ssid = connected_bssid = None
            if isinstance(current, dict) and current:
                network, hidden = _mac_network(current, connected=True)
                limited = limited or hidden or network["ssid"] is None
                networks.append(network)
                connected_ssid, connected_bssid = network["ssid"], network["bssid"]
            others = item.get("spairport_airport_other_local_wireless_networks") or []
            for other in others if isinstance(others, list) else []:
                if isinstance(other, dict):
                    network, hidden = _mac_network(other, connected=False)
                    limited = limited or hidden
                    networks.append(network)
            interfaces.append(
                make_interface(
                    name, item.get("spairport_wireless_mac_address"), connected_ssid,
                    connected_bssid,
                )
            )  # fmt: skip
    if not interfaces:
        return STATUS_NO_ADAPTER, [], []
    return (STATUS_PERMISSION_LIMITED if limited else STATUS_OK), interfaces, networks


def collect_macos(runner: CommandRunner = _run) -> dict[str, Any]:
    output = runner([SYSTEM_PROFILER, "SPAirPortDataType", "-json"])
    if output.truncated:
        raise ValueError("system_profiler output exceeded the size limit")
    if output.returncode != 0:
        raise OSError(f"system_profiler failed ({output.returncode}): {output.stderr[:200]}")
    status, interfaces, networks = parse_system_profiler(json.loads(output.text() or "{}"))
    return result(status, SOURCE_MACOS, interfaces, networks)


# --- Windows: netsh -------------------------------------------------------------------------

_LINE = re.compile(r"^\s*(?P<label>[^:\r\n]*?\S)\s+:\s?(?P<value>.*?)\s*$")
_SSID_HEADER = re.compile(r"^\s*SSID\s+\d+\s*:\s?(?P<value>.*?)\s*$")
_BSSID_HEADER = re.compile(r"^\s*BSSID\s+\d+\s*:\s?(?P<value>.*?)\s*$")
_PERCENT = re.compile(r"^(\d{1,3})\s*%$")
# Etiquetas traducidas que no se pueden reconocer por la forma del valor (sin acentos y en
# minúsculas, ver _fold).
_CHANNEL_LABELS = frozenset({"channel", "canal", "kanal", "canale"})
_AUTH_LABELS = frozenset(
    {"authentication", "autenticacion", "authentification", "authentifizierung",
     "autenticazione", "autenticacao"}
)  # fmt: skip
_CIPHER_LABELS = frozenset(
    {"encryption", "cipher", "cifrado", "chiffrement", "verschlusselung", "crittografia",
     "criptografia", "codificacion"}
)  # fmt: skip
# Marcas de error de netsh que no dependen del idioma: el servicio wlansvc (sin él no hay
# Wi-Fi gestionado por Windows) y el URI de los ajustes de Localización (Windows 11 24H2
# exige ese permiso para leer la información WLAN).
_LOCATION_MARKERS = ("ms-settings:privacy-location", "location permission", "permiso de ubicaci")
_NO_ADAPTER_MARKERS = (
    "wlansvc",
    "there is no wireless interface",
    "no hay ninguna interfaz inal",
)


def _fold(label: str) -> str:
    decomposed = unicodedata.normalize("NFKD", label)
    return "".join(c for c in decomposed if not unicodedata.combining(c)).strip().lower()


def netsh_status(text: str) -> str | None:
    """Estado deducido de un mensaje de error de netsh, o None si no es un error conocido."""
    lowered = text.lower()
    if any(marker in lowered for marker in _LOCATION_MARKERS):
        return STATUS_PERMISSION_LIMITED
    if any(marker in lowered for marker in _NO_ADAPTER_MARKERS):
        return STATUS_NO_ADAPTER
    return None


def _security(auth: str | None, cipher: str | None) -> str | None:
    if auth and cipher:
        return f"{auth} ({cipher})"
    return auth or cipher


def parse_netsh_interfaces(text: str) -> list[dict[str, Any]]:
    """`netsh wlan show interfaces` -> interfaces con datos de su conexión actual.

    Cada interfaz empieza por la misma etiqueta (Name/Nombre...): la primera etiqueta de la
    salida marca el inicio de bloque, sea cual sea el idioma.
    """
    blocks: list[dict[str, Any]] = []
    first_label: str | None = None
    current: dict[str, Any] | None = None
    for line in text.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        label, value = _fold(match["label"]), match["value"].strip()
        if first_label is None:
            first_label = label
        if label == first_label:
            current = {"name": value}
            blocks.append(current)
            continue
        if current is None:
            continue
        if label == "ssid":
            current["ssid"] = value
        elif "bssid" in label:
            current["bssid"] = value
        elif normalize_mac(value) and "mac" not in current:
            current["mac"] = value
        elif label == "rssi":
            current["rssi"] = _int(value)
        elif percent := _PERCENT.match(value):
            current["quality"] = int(percent.group(1))
        elif value.lower().startswith("802.11"):
            current["phy"] = value
        elif _band_from_text(value) and re.fullmatch(r"[\d.,]+\s*GHz", value, re.IGNORECASE):
            current["band"] = _band_from_text(value)
        elif label in _CHANNEL_LABELS:
            current["channel"] = _int(value)
        elif label in _AUTH_LABELS:
            current["auth"] = value
        elif label in _CIPHER_LABELS:
            current["cipher"] = value
    return blocks[:MAX_INTERFACES]


def parse_netsh_networks(text: str) -> list[dict[str, Any]]:
    """`netsh wlan show networks mode=bssid` -> una red por BSSID visible."""
    networks: list[dict[str, Any]] = []
    ssid: str | None = None
    auth = cipher = None
    bss: dict[str, Any] | None = None

    def flush() -> None:
        if bss is not None:
            networks.append(
                make_network(
                    ssid=ssid,
                    bssid=bss.get("bssid"),
                    channel=bss.get("channel"),
                    band=bss.get("band"),
                    security=_security(auth, cipher),
                    signal_quality=bss.get("quality"),
                    phy_mode=bss.get("phy"),
                )
            )

    for line in text.splitlines():
        if header := _SSID_HEADER.match(line):
            flush()
            bss = None
            ssid = header["value"] or None  # SSID vacío = red oculta
            auth = cipher = None
            continue
        if header := _BSSID_HEADER.match(line):
            flush()
            bss = {"bssid": header["value"]}
            continue
        match = _LINE.match(line)
        if not match:
            continue
        label, value = _fold(match["label"]), match["value"].strip()
        if bss is None:
            # Campos de la red (antes del primer BSSID): autenticación y cifrado.
            if label in _AUTH_LABELS:
                auth = value or None
            elif label in _CIPHER_LABELS:
                cipher = value or None
            continue
        if percent := _PERCENT.match(value):
            bss["quality"] = int(percent.group(1))
        elif value.lower().startswith("802.11"):
            bss["phy"] = value
        elif re.fullmatch(r"[\d.,]+\s*GHz", value, re.IGNORECASE):
            bss["band"] = _band_from_text(value)
        elif label in _CHANNEL_LABELS:
            bss["channel"] = _int(value)
    flush()
    return networks


def merge_netsh(
    blocks: list[dict[str, Any]], networks: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Marca la red conectada y la añade si el listado no la incluía."""
    interfaces = []
    for block in blocks:
        ssid = block.get("ssid") or None
        bssid = normalize_mac(block.get("bssid"))
        interfaces.append(make_interface(block.get("name"), block.get("mac"), ssid, bssid))
        if ssid is None and bssid is None:
            continue
        matched = False
        for network in networks:
            if (bssid and network["bssid"] == bssid) or (
                not bssid and network["ssid"] == _text(ssid, SSID_MAX)
            ):
                network["connected"] = True
                if network["signal_dbm"] is None and block.get("rssi") is not None:
                    network["signal_dbm"] = make_network(signal_dbm=block["rssi"])["signal_dbm"]
                matched = True
        if not matched:
            networks.append(
                make_network(
                    ssid=ssid,
                    bssid=bssid,
                    channel=block.get("channel"),
                    band=block.get("band"),
                    security=_security(block.get("auth"), block.get("cipher")),
                    signal_dbm=block.get("rssi"),
                    signal_quality=block.get("quality"),
                    phy_mode=block.get("phy"),
                    connected=True,
                )
            )
    return interfaces, networks


def _netsh() -> str:
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    # Python de 32 bits en Windows de 64: Sysnative llega al netsh nativo.
    system = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    return os.path.join(root, system, "netsh.exe")


def _windows_encoding() -> str:
    """Página de códigos OEM de la consola (netsh escribe en ella, no en UTF-8)."""
    if sys.platform == "win32":
        import ctypes

        try:
            return f"cp{ctypes.windll.kernel32.GetOEMCP()}"
        except (AttributeError, OSError):
            return "utf-8"
    return "utf-8"


def _decode(output: CommandOutput) -> str:
    # Accept UTF-8 captures; fall back to the Windows OEM code page.
    try:
        return output.stdout.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return output.stdout.decode(_windows_encoding(), "replace")
        except LookupError:
            return output.text()


def collect_windows(runner: CommandRunner = _run, netsh: str | None = None) -> dict[str, Any]:
    netsh = netsh or _netsh()
    shown = runner([netsh, "wlan", "show", "interfaces"])
    text = _decode(shown)
    status = netsh_status(text + "\n" + shown.stderr)
    blocks = parse_netsh_interfaces(text) if status is None else []
    if status is not None and status != STATUS_PERMISSION_LIMITED:
        return result(status, SOURCE_WINDOWS)
    if status is None and not blocks:
        if shown.returncode != 0:
            raise OSError(f"netsh failed ({shown.returncode})")
        return result(STATUS_NO_ADAPTER, SOURCE_WINDOWS)
    listed = runner([netsh, "wlan", "show", "networks", "mode=bssid"])
    listed_text = _decode(listed)
    listed_status = netsh_status(listed_text + "\n" + listed.stderr)
    networks = parse_netsh_networks(listed_text) if listed_status is None else []
    interfaces, networks = merge_netsh(blocks, networks)
    if status == STATUS_PERMISSION_LIMITED or listed_status == STATUS_PERMISSION_LIMITED:
        return result(STATUS_PERMISSION_LIMITED, SOURCE_WINDOWS, interfaces, networks)
    return result(STATUS_OK, SOURCE_WINDOWS, interfaces, networks)


# --- Linux: nmcli ---------------------------------------------------------------------------

NMCLI_FIELDS = "IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY,DEVICE"


def split_terse(line: str) -> list[str]:
    """Campos de una línea `nmcli -t` (":" separa; "\\:" y "\\\\" son literales)."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in line:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    return fields


def parse_nmcli_devices(text: str) -> list[str]:
    """`nmcli -t -f DEVICE,TYPE,STATE dev status` -> dispositivos Wi-Fi (no wifi-p2p)."""
    devices = []
    for line in text.splitlines():
        fields = split_terse(line)
        if len(fields) >= 2 and fields[1] == "wifi" and fields[0]:
            devices.append(fields[0])
    return devices[:MAX_INTERFACES]


def parse_nmcli_wifi(text: str) -> list[tuple[str, dict[str, Any]]]:
    """`nmcli -t -f IN-USE,BSSID,SSID,CHAN,FREQ,SIGNAL,SECURITY,DEVICE dev wifi list`."""
    found = []
    for line in text.splitlines():
        fields = split_terse(line)
        if len(fields) != 8:
            continue
        in_use, bssid, ssid, chan, freq, signal, security, device = fields
        frequency = _int(re.sub(r"\s*MHz$", "", freq.strip()))
        security = security.strip()
        found.append(
            (
                device,
                make_network(
                    ssid=None if ssid in ("", "--") else ssid,
                    bssid=bssid,
                    channel=_int(chan),
                    frequency_mhz=frequency,
                    # nmcli: cadena vacía o "--" = red abierta, no "desconocida".
                    security="open" if security in ("", "--") else security,
                    signal_quality=_int(signal),
                    connected=in_use.strip() == "*",
                ),
            )
        )
    return found


def _link_mac(name: str) -> str | None:
    for address in psutil.net_if_addrs().get(name, []):
        if address.family == psutil.AF_LINK:
            return address.address
    return None


def collect_linux(
    runner: CommandRunner = _run,
    nmcli: str | None = None,
    mac_of: Callable[[str], str | None] = _link_mac,
) -> dict[str, Any]:
    nmcli = nmcli or next(
        (path for path in NMCLI_PATHS if os.path.isfile(path) and os.access(path, os.X_OK)), None
    )
    if nmcli is None:
        return result(STATUS_UNSUPPORTED, SOURCE_LINUX)
    status = runner([nmcli, "-t", "-e", "yes", "-f", "DEVICE,TYPE,STATE", "dev", "status"])
    if status.returncode != 0:
        if "not running" in (status.stderr + status.text()).lower():
            # Sin NetworkManager no hay ninguna fuente pasiva soportada en este equipo.
            return result(STATUS_UNSUPPORTED, SOURCE_LINUX)
        raise OSError(f"nmcli failed ({status.returncode}): {status.stderr[:200]}")
    devices = parse_nmcli_devices(status.text())
    if not devices:
        return result(STATUS_NO_ADAPTER, SOURCE_LINUX)
    listed = runner(
        [nmcli, "-t", "-e", "yes", "-f", NMCLI_FIELDS, "dev", "wifi", "list", "--rescan", "no"]
    )
    if listed.returncode != 0:
        raise OSError(f"nmcli failed ({listed.returncode}): {listed.stderr[:200]}")
    rows = parse_nmcli_wifi(listed.text())
    interfaces = []
    for device in devices:
        connected = next((n for d, n in rows if d == device and n["connected"]), None)
        interfaces.append(
            make_interface(
                device,
                mac_of(device),
                connected["ssid"] if connected else None,
                connected["bssid"] if connected else None,
            )
        )
    return result(STATUS_OK, SOURCE_LINUX, interfaces, [network for _, network in rows])


# --- Punto de entrada -----------------------------------------------------------------------


def source_for(platform: str) -> str | None:
    if platform == "darwin":
        return SOURCE_MACOS
    if platform == "win32":
        return SOURCE_WINDOWS
    if platform.startswith("linux"):
        return SOURCE_LINUX
    return None


def collect_wireless(platform: str | None = None) -> dict[str, Any] | None:
    """Estado Wi-Fi de este equipo según el contrato, o None en una plataforma sin fuente.

    Nunca lanza: cualquier fallo se informa como status "error" (sin detalles sensibles; el
    detalle va al log local) y el resto del inventario sigue igual.
    """
    platform = platform or sys.platform
    source = source_for(platform)
    if source is None:
        return None
    try:
        if source == SOURCE_MACOS:
            return collect_macos()
        if source == SOURCE_WINDOWS:
            return collect_windows()
        return collect_linux()
    except (FileNotFoundError, CommandUnavailableError):
        # Herramienta ausente (system_profiler, netsh o nmcli): no hay fuente soportada.
        return result(STATUS_UNSUPPORTED, source)
    except OSError as exc:
        level = logging.WARNING if isinstance(exc, CommandTimeoutError) else logging.INFO
        logger.log(level, "wireless collection failed", extra={"error": str(exc)[:300]})
        return result(STATUS_ERROR, source)
    except Exception as exc:
        logger.warning("wireless collection failed", extra={"error": repr(exc)[:300]})
        return result(STATUS_ERROR, source)


class WirelessCollector:
    """Lectura Wi-Fi con su propio intervalo mínimo (`wireless_interval_seconds`).

    Viaja dentro del inventario, así que nunca se envía más a menudo que él. Con intervalo 0
    se lee en cada inventario; con un intervalo mayor se reutiliza la última lectura hasta
    que vence (el inventario siempre lleva el último estado conocido, no un hueco que el
    servidor tomaría como "sin Wi-Fi").
    """

    def __init__(
        self,
        interval_seconds: int = 0,
        collect: Callable[[], dict[str, Any] | None] = collect_wireless,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.interval = interval_seconds
        self._collect = collect
        self._clock = clock
        self._last: dict[str, Any] | None = None
        self._at: float | None = None

    def snapshot(self, force: bool = False) -> dict[str, Any] | None:
        now = self._clock()
        if (
            not force
            and self._at is not None
            and self.interval > 0
            and now - self._at < self.interval
        ):
            return self._last
        self._last = self._collect()
        self._at = now
        return self._last
