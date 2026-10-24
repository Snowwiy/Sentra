"""Lectores de estado del equipo para la telemetría y las acciones forenses (Fase 6E).

Servicios, tareas programadas, mecanismos de persistencia, protección antivirus y firewall,
por plataforma. Reglas comunes:

- solo lectura y sin privilegios extra: lo que el sistema no deja leer a la cuenta del agente
  se informa como `PermissionError` (colector `permission_denied`), nunca se fuerza;
- lo que no existe en esta plataforma lanza `CollectorUnavailableError` (`unavailable`);
- de los ficheros de persistencia (cron, unidades systemd, plists de launchd, carpeta Inicio)
  solo se leen nombre, ruta, tamaño, fecha y destino de enlaces: nunca su contenido;
- las herramientas del sistema se ejecutan con ruta absoluta, argumentos fijos y sin shell
  (syscmd.run_bounded); los tests sustituyen `run`.

Cada lector devuelve un diccionario clave -> registro. Las claves que empiezan por "_" son
huellas internas para detectar cambios (`_fp`) y no se envían al servidor.
"""

import contextlib
import csv
import io
import json
import os
import stat
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sentra_agent.activity import clip, redact_cmdline
from sentra_agent.syscmd import CommandOutput, first_existing, run_bounded

Runner = Callable[..., CommandOutput]
Records = dict[str, dict[str, Any]]

MAX_RECORDS = 5000
_SYSTEMCTL = ("/usr/bin/systemctl", "/bin/systemctl")
SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class CollectorUnavailableError(Exception):
    """La fuente no existe en este equipo o plataforma."""


def powershell_path() -> str:
    root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    system = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    return str(root / system / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def run_powershell(script: str, run: Runner = run_bounded, timeout: float = 60.0) -> str:
    """Ejecuta un script FIJO de PowerShell (nunca con texto de fuera) y devuelve stdout.

    Acceso denegado se traduce a PermissionError; cualquier otro fallo a
    CollectorUnavailableError (módulo ausente, servicio parado, Server Core...).
    """
    argv = [powershell_path(), "-NoProfile", "-NonInteractive", "-Command", script]
    try:
        result = run(argv, timeout=timeout, max_bytes=8 * 1024 * 1024)
    except OSError as exc:
        raise CollectorUnavailableError(str(exc)) from exc
    if result.returncode != 0:
        detail = (result.stderr or result.text()).lower()
        if "denied" in detail or "0x80070005" in detail or "permission" in detail:
            raise PermissionError(detail[:200])
        raise CollectorUnavailableError(detail[:200] or "powershell failed")
    return result.text()


def decode_console(raw: bytes) -> str:
    """Salida de herramientas de consola de Windows: UTF-8 si lo es, si no la página OEM."""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp850", "replace")


def _fingerprint_file(path: str) -> tuple[str, str | None] | None:
    """Huella (tamaño, fecha, destino del enlace) sin abrir el fichero."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    target = None
    if stat.S_ISLNK(info.st_mode):
        try:
            target = os.readlink(path)
        except OSError:
            target = None
    return f"{info.st_size}:{info.st_mtime_ns}:{target}", target


def _scan_dir(
    directory: str, mechanism: str, depth: int = 1, suffixes: tuple[str, ...] = ()
) -> Records:
    records: Records = {}
    try:
        entries = list(os.scandir(directory))
    except FileNotFoundError:
        return records
    except PermissionError:
        raise
    except OSError:
        return records
    for entry in sorted(entries, key=lambda e: e.name):
        if len(records) >= MAX_RECORDS:
            break
        try:
            is_dir = entry.is_dir(follow_symlinks=False)
        except OSError:
            continue
        if is_dir:
            if depth > 1:
                try:
                    records.update(_scan_dir(entry.path, mechanism, depth - 1, suffixes))
                except PermissionError:
                    continue
            continue
        if suffixes and not entry.name.endswith(suffixes):
            continue
        found = _fingerprint_file(entry.path)
        if found is None:
            continue
        fingerprint, target = found
        records[f"{mechanism}:{entry.path}"] = {
            "mechanism": mechanism,
            "location": clip(entry.path, 1024),
            "name": clip(entry.name, 255),
            "target": clip(target, 1024),
            "_fp": fingerprint,
        }
    return records


# --- Servicios ----------------------------------------------------------------------------


def read_services(platform: str | None = None) -> Records:
    platform = platform or sys.platform
    if platform == "win32":
        return _windows_services()
    from sentra_agent.inventory import collect_services

    if platform.startswith("linux") and not os.path.isdir("/run/systemd/system"):
        raise CollectorUnavailableError("systemd not running")
    records: Records = {}
    for service in collect_services():
        name = str(service.get("name") or "")
        if not name:
            continue
        records[name] = {
            "name": clip(name, 255),
            "display_name": clip(service.get("display_name"), 512),
            "start_type": clip(service.get("start_type"), 32),
            "status": clip(service.get("status"), 32),
            "exe": None,
            "username": None,
        }
    return records


def _windows_services() -> Records:
    if sys.platform != "win32":  # mypy: win_service_iter solo existe en Windows
        raise CollectorUnavailableError("not windows")
    import psutil

    records: Records = {}
    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()
        except (psutil.Error, OSError):
            continue
        name = str(info.get("name") or "")
        if not name:
            continue
        records[name] = {
            "name": clip(name, 255),
            "display_name": clip(info.get("display_name"), 512),
            "start_type": clip(info.get("start_type"), 32),
            "status": clip(info.get("status"), 32),
            "exe": clip(info.get("binpath"), 1024),
            "username": clip(info.get("username"), 255),
        }
        if len(records) >= MAX_RECORDS:
            break
    return records


# --- Tareas programadas -------------------------------------------------------------------

# Columnas de `schtasks /query /fo csv /v /nh` (posiciones fijas; los valores van en el idioma
# del sistema). VALIDACIÓN LOCAL EN WINDOWS: comprobar en un Windows real en español.
_TASK_NAME, _TASK_RUN, _TASK_STATE, _TASK_SCHEDULE = 1, 8, 11, 18
_ENABLED_WORDS = {"enabled", "habilitado", "habilitada", "activé", "aktiviert"}
_DISABLED_WORDS = {"disabled", "deshabilitado", "deshabilitada", "désactivé", "deaktiviert"}


def parse_schtasks_csv(text: str, cmdline_policy: str = "redacted") -> Records:
    records: Records = {}
    for row in csv.reader(io.StringIO(text)):
        if len(row) <= _TASK_SCHEDULE or not row[_TASK_NAME].startswith("\\"):
            continue  # cabeceras repetidas o líneas incompletas
        name = row[_TASK_NAME]
        if name in records:
            continue  # una fila por desencadenador: basta la primera
        state = row[_TASK_STATE].strip().lower()
        enabled = True if state in _ENABLED_WORDS else False if state in _DISABLED_WORDS else None
        exe = row[_TASK_RUN].strip()
        records[name] = {
            "name": clip(name.rsplit("\\", 1)[-1], 255),
            "path": clip(name, 1024),
            "exe": redact_cmdline(exe.split(), cmdline_policy) if exe else None,
            "enabled": enabled,
            "trigger": clip(row[_TASK_SCHEDULE], 128),
        }
        if len(records) >= MAX_RECORDS:
            break
    return records


def parse_timer_unit_files(text: str) -> Records:
    records: Records = {}
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[0].endswith(".timer"):
            continue
        records[fields[0]] = {
            "name": clip(fields[0], 255),
            "path": None,
            "exe": None,
            "enabled": fields[1] == "enabled",
            "trigger": "systemd_timer",
        }
    return records


def read_scheduled_tasks(
    platform: str | None = None, run: Runner = run_bounded, cmdline_policy: str = "redacted"
) -> Records:
    platform = platform or sys.platform
    if platform == "win32":
        schtasks = str(
            Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "schtasks.exe"
        )
        try:
            result = run([schtasks, "/query", "/fo", "csv", "/v", "/nh"], timeout=60)
        except OSError as exc:
            raise CollectorUnavailableError(str(exc)) from exc
        text = decode_console(result.stdout)
        if result.returncode != 0:
            if "denied" in (result.stderr + text).lower():
                raise PermissionError("schtasks access denied")
            raise CollectorUnavailableError("schtasks failed")
        return parse_schtasks_csv(text, cmdline_policy)
    if platform.startswith("linux"):
        systemctl = first_existing(_SYSTEMCTL)
        if systemctl is None or not os.path.isdir("/run/systemd/system"):
            raise CollectorUnavailableError("systemd not running")
        result = run(
            [systemctl, "list-unit-files", "--type=timer", "--no-legend", "--no-pager", "--plain"],
            timeout=30,
        )
        if result.returncode != 0:
            raise CollectorUnavailableError("systemctl failed")
        return parse_timer_unit_files(result.text())
    raise CollectorUnavailableError("no scheduled task source on this platform")


# --- Persistencia --------------------------------------------------------------------------

LINUX_CRON = ("/etc/crontab", "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
              "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron/crontabs",
              "/var/spool/cron")  # fmt: skip
LINUX_SYSTEMD = "/etc/systemd/system"
MACOS_LAUNCH = (
    ("/Library/LaunchAgents", "launch_agent"),
    ("/Library/LaunchDaemons", "launch_daemon"),
)
WINDOWS_RUN_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
)


def read_persistence(
    platform: str | None = None, cmdline_policy: str = "redacted", root: str = ""
) -> Records:
    """Mecanismos de persistencia del SISTEMA (no de cada perfil de usuario).

    `root` antepone un prefijo a las rutas (tests con un árbol falso).
    """
    platform = platform or sys.platform
    if platform == "win32":
        return _windows_persistence(cmdline_policy)
    records: Records = {}
    denied = 0
    if platform.startswith("linux"):
        for path in LINUX_CRON:
            full = root + path
            if os.path.isfile(full):
                found = _fingerprint_file(full)
                if found:
                    records[f"cron:{full}"] = {
                        "mechanism": "cron",
                        "location": full,
                        "name": os.path.basename(full),
                        "target": found[1],
                        "_fp": found[0],
                    }
                continue
            try:
                records.update(_scan_dir(full, "cron"))
            except PermissionError:
                denied += 1  # /var/spool/cron/crontabs solo lo lee root
        try:
            records.update(
                _scan_dir(
                    root + LINUX_SYSTEMD,
                    "systemd_unit",
                    depth=2,
                    suffixes=(".service", ".timer", ".socket", ".path"),
                )
            )
        except PermissionError:
            denied += 1
    elif platform == "darwin":
        for directory, mechanism in MACOS_LAUNCH:
            try:
                records.update(_scan_dir(root + directory, mechanism, suffixes=(".plist",)))
            except PermissionError:
                denied += 1
    else:
        raise CollectorUnavailableError("no persistence source on this platform")
    if denied and not records:
        raise PermissionError("persistence locations not readable")
    return records


def _windows_persistence(cmdline_policy: str) -> Records:
    if sys.platform != "win32":
        raise CollectorUnavailableError("not windows")
    import winreg

    records: Records = {}
    for path in WINDOWS_RUN_KEYS:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                count = winreg.QueryInfoKey(key)[1]
                for index in range(min(count, MAX_RECORDS)):
                    name, value, _kind = winreg.EnumValue(key, index)
                    location = f"HKLM\\{path}"
                    target = redact_cmdline(str(value).split(), cmdline_policy)
                    records[f"run_key:{location}:{name}"] = {
                        "mechanism": "run_key",
                        "location": clip(location, 1024),
                        "name": clip(name, 255),
                        "target": clip(target, 1024),
                        "_fp": str(value),
                    }
        except FileNotFoundError:
            continue
        except PermissionError:
            continue
        except OSError:
            continue
    program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
    startup = os.path.join(
        program_data, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"
    )
    with contextlib.suppress(PermissionError):
        records.update(_scan_dir(startup, "startup_folder"))
    return records


# --- Protección y firewall -----------------------------------------------------------------

_DEFENDER_SCRIPT = (
    "$s = Get-MpComputerStatus -ErrorAction Stop; "
    "[pscustomobject]@{ realtime = [bool]$s.RealTimeProtectionEnabled; "
    "antivirus = [bool]$s.AntivirusEnabled; tamper = $s.IsTamperProtected; "
    "age = $s.AntivirusSignatureAge } | ConvertTo-Json -Compress"
)
_FIREWALL_SCRIPT = (
    "Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object { "
    "[pscustomobject]@{ name = [string]$_.Name; enabled = [string]$_.Enabled; "
    "inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction } "
    "} | ConvertTo-Json -Compress"
)


def parse_defender(text: str) -> Records:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise CollectorUnavailableError("unexpected Get-MpComputerStatus output")
    age = data.get("age")
    return {
        "defender": {
            "product": "Microsoft Defender Antivirus",
            "realtime_enabled": data.get("realtime"),
            "antivirus_enabled": data.get("antivirus"),
            "tamper_protection": data.get("tamper"),
            "signature_age_days": age if isinstance(age, int) and age >= 0 else None,
        }
    }


def read_protection(platform: str | None = None, run: Runner = run_bounded) -> Records:
    platform = platform or sys.platform
    if platform != "win32":
        raise CollectorUnavailableError("no protection source on this platform")
    return parse_defender(run_powershell(_DEFENDER_SCRIPT, run))


def _action(value: object) -> str | None:
    text = str(value or "").strip().lower()
    if text in ("block", "allow"):
        return text
    if text in ("notconfigured", "not configured", ""):
        return None
    return text[:32]


def _bool_text(value: object) -> bool | None:
    text = str(value).strip().lower()
    return True if text in ("true", "1") else False if text in ("false", "0") else None


def parse_firewall_profiles(text: str) -> Records:
    data = json.loads(text)
    items = data if isinstance(data, list) else [data]
    records: Records = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        name = str(item["name"]).lower()
        records[name] = {
            "profile": clip(name, 32),
            "enabled": _bool_text(item.get("enabled")),
            "default_inbound": _action(item.get("inbound")),
            "default_outbound": _action(item.get("outbound")),
        }
    return records


def parse_socketfilterfw(text: str) -> Records:
    lowered = text.lower()
    # "disabled" contiene "enabled": se mira primero.
    enabled = False if "disabled" in lowered else True if "enabled" in lowered else None
    return {
        "application_firewall": {
            "profile": "application_firewall",
            "enabled": enabled,
            "default_inbound": None,
            "default_outbound": None,
        }
    }


def parse_ufw_conf(text: str) -> bool | None:
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key.strip() == "ENABLED":
            return value.strip().strip("\"'").lower() == "yes"
    return None


def read_firewall(
    platform: str | None = None, run: Runner = run_bounded, root: str = ""
) -> Records:
    """Estado del firewall por perfil, solo lo que se puede leer sin privilegios."""
    platform = platform or sys.platform
    if platform == "win32":
        return parse_firewall_profiles(run_powershell(_FIREWALL_SCRIPT, run))
    if platform == "darwin":
        try:
            result = run([SOCKETFILTERFW, "--getglobalstate"], timeout=15)
        except OSError as exc:
            raise CollectorUnavailableError(str(exc)) from exc
        return parse_socketfilterfw(result.text())
    if platform.startswith("linux"):
        records: Records = {}
        try:
            text = Path(root + "/etc/ufw/ufw.conf").read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            text = None
        except PermissionError:
            raise
        if text is not None:
            records["ufw"] = {
                "profile": "ufw",
                "enabled": parse_ufw_conf(text),
                "default_inbound": None,
                "default_outbound": None,
            }
        systemctl = first_existing(_SYSTEMCTL)
        if systemctl and os.path.isfile(root + "/usr/lib/systemd/system/firewalld.service"):
            result = run([systemctl, "is-active", "firewalld"], timeout=15)
            records["firewalld"] = {
                "profile": "firewalld",
                "enabled": result.text().strip() == "active",
                "default_inbound": None,
                "default_outbound": None,
            }
        if not records:
            # nftables/iptables sin firewalld ni ufw: leer las reglas exige CAP_NET_ADMIN.
            raise PermissionError("firewall rules need CAP_NET_ADMIN to be read")
        return records
    raise CollectorUnavailableError("no firewall source on this platform")


def public(record: dict[str, Any]) -> dict[str, Any]:
    """El registro sin claves internas (las que empiezan por "_")."""
    return {key: value for key, value in record.items() if not key.startswith("_")}
