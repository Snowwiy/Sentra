"""Adaptadores de plataforma para macOS (Fase 6C.5).

El agente es el mismo en las tres plataformas: protocolo, enrolamiento, búfer, reintentos y
comandos de Response no cambian. Este módulo solo sustituye las fuentes de datos que en
Windows (registro, wevtutil) y Linux (/proc, systemctl, dpkg) no existen en macOS, con las
interfaces que Apple mantiene para ello:

- versión del sistema: `sw_vers`;
- arquitectura nativa y Rosetta 2: `sysctl hw.optional.arm64` y `sysctl.proc_translated`
  (un Python x86_64 en un Mac Apple Silicon informa `x86_64` en platform.machine());
- identidad estable: IOPlatformUUID de `ioreg`, que solo se usa como clave del HMAC por
  aplicación de machine_identity.py y nunca sale del equipo. El número de serie aparece en
  la misma salida de ioreg pero no se extrae, no se guarda y no se registra;
- servicios: `launchctl list` (dominio del sistema cuando corre como root);
- software: Info.plist de los bundles de /Applications (plistlib, tamaño acotado) y los
  recibos de paquetes de /var/db/receipts (la base que consulta `pkgutil`), sin los
  componentes de Apple (com.apple.*), que ya describe la versión del sistema;
- cuentas locales: `dscl .` (Directory Services; /etc/passwd en macOS no lista usuarios);
- red: `route -n get default` y `scutil --dns`.

Nada de esto pide permisos de TCC: no se leen carpetas de usuario (Escritorio, Documentos,
Descargas), ni la ubicación, ni el contenido de ningún fichero de usuario. Todas las
llamadas pasan por syscmd.run_bounded: ruta absoluta, sin shell, con plazo y cupo.

VALIDACIÓN EN macOS REAL PENDIENTE: los parsers se prueban con salidas reales de macOS 14 y
15 guardadas como fixtures, pero no se han ejecutado en un Mac físico.
"""

import ipaddress
import logging
import os
import plistlib
import re
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sentra_agent.syscmd import run_bounded

logger = logging.getLogger("sentra_agent")

SW_VERS = "/usr/bin/sw_vers"
IOREG = "/usr/sbin/ioreg"
SYSCTL = "/usr/sbin/sysctl"
LAUNCHCTL = "/bin/launchctl"
DSCL = "/usr/bin/dscl"
ROUTE = "/sbin/route"
SCUTIL = "/usr/sbin/scutil"

APPLICATION_ROOTS = ("/Applications",)
RECEIPTS_DIR = "/var/db/receipts"
# Límites del inventario de software: un Info.plist real ocupa unos KB; uno de varios MB no
# es un Info.plist normal y no se parsea. El plazo total protege de discos lentos o de red.
INFO_PLIST_MAX_BYTES = 1024 * 1024
RECEIPT_MAX_BYTES = 256 * 1024
MAX_RECEIPTS = 5000
SOFTWARE_DEADLINE_SECONDS = 30.0
MAX_SERVICES = 2000
MAX_SOFTWARE = 5000
MAX_ACCOUNTS = 1000

# Runner inyectable: los tests sustituyen la ejecución real por salidas guardadas.
Runner = Callable[[list[str]], str]


def run_text(argv: list[str], timeout: float = 30.0, max_bytes: int = 4 * 1024 * 1024) -> str:
    """Salida de una herramienta del sistema; OSError si falla (código distinto de 0)."""
    result = run_bounded(argv, timeout=timeout, max_bytes=max_bytes)
    if result.returncode != 0:
        raise OSError(
            f"{os.path.basename(argv[0])} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.text()


def _clip(value: object, length: int) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:length] or None


# --- Sistema y arquitectura ----------------------------------------------------------------


def parse_sw_vers(text: str) -> dict[str, str]:
    """`sw_vers`: líneas "ProductName:\tmacOS" (macOS 11+) o "Mac OS X" (antiguos)."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() in ("ProductName", "ProductVersion", "BuildVersion"):
            found[key.strip()] = value.strip()
    return found


def os_version_label(info: dict[str, str]) -> str | None:
    version = info.get("ProductVersion")
    if not version:
        return None
    build = info.get("BuildVersion")
    return f"{version} ({build})" if build else version


def native_architecture(machine: str, arm64_hardware: bool) -> str:
    """Arquitectura del hardware, no la del proceso (Rosetta informa x86_64)."""
    if arm64_hardware:
        return "arm64"
    lowered = machine.lower()
    return "x86_64" if lowered in ("x86_64", "amd64", "i386") else (lowered or "unknown")


@dataclass(frozen=True)
class MacPlatform:
    product_name: str
    product_version: str | None
    build_version: str | None
    # Arquitectura del proceso del agente (la del Python que lo ejecuta).
    process_architecture: str
    # Arquitectura del Mac: arm64 (Apple Silicon) o x86_64 (Intel).
    native_architecture: str
    # True: el agente corre traducido por Rosetta 2 (Python x86_64 en Apple Silicon).
    # None: no se pudo saber.
    rosetta: bool | None

    @property
    def os_version(self) -> str | None:
        info = {"ProductVersion": self.product_version or "", "BuildVersion": self.build_version}
        return os_version_label({k: v for k, v in info.items() if v})


def _sysctl_flag(name: str, runner: Runner) -> bool | None:
    # En Intel `hw.optional.arm64` y `sysctl.proc_translated` no existen: sysctl falla y eso
    # significa "no" para el primero y "no traducido" para el segundo.
    try:
        value = runner([SYSCTL, "-n", name]).strip()
    except OSError:
        return None
    if value in ("0", "1"):
        return value == "1"
    return None


def detect_platform(machine: str, runner: Runner = run_text) -> MacPlatform:
    try:
        info = parse_sw_vers(runner([SW_VERS]))
    except OSError as exc:
        logger.warning("sw_vers unavailable", extra={"error": str(exc)[:200]})
        info = {}
    translated = _sysctl_flag("sysctl.proc_translated", runner)
    arm64 = _sysctl_flag("hw.optional.arm64", runner)
    process_arch = (machine or "unknown").lower()
    if translated is None:
        # Intel (sin la clave) o error: solo hay traducción si el hardware es arm64 y el
        # proceso x86_64, y eso sin la clave no se puede afirmar.
        rosetta: bool | None = False if arm64 is not True else None
    else:
        rosetta = translated
    return MacPlatform(
        product_name=info.get("ProductName") or "macOS",
        product_version=info.get("ProductVersion"),
        build_version=info.get("BuildVersion"),
        process_architecture=process_arch,
        native_architecture=native_architecture(process_arch, arm64 is True or rosetta is True),
        rosetta=rosetta,
    )


_platform_cache: MacPlatform | None = None


def platform_info(machine: str) -> MacPlatform:
    """Plataforma del Mac, calculada una vez por ejecución (no cambia sin reiniciar)."""
    global _platform_cache
    if _platform_cache is None:
        _platform_cache = detect_platform(machine)
        if _platform_cache.rosetta:
            logger.warning(
                "agent runs under Rosetta 2 (x86_64 Python on Apple Silicon); install the"
                " arm64 package for native execution"
            )
    return _platform_cache


# --- Identidad del equipo ------------------------------------------------------------------

# Solo la línea del UUID: el resto de la salida (número de serie incluido) se descarta.
_PLATFORM_UUID = re.compile(r'^\s*"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"\s*$', re.MULTILINE)


def parse_ioreg_platform_uuid(text: str) -> str | None:
    match = _PLATFORM_UUID.search(text)
    return match.group(1).lower() if match else None


def platform_uuid(runner: Runner = run_text) -> str | None:
    try:
        output = runner([IOREG, "-rd1", "-c", "IOPlatformExpertDevice"])
    except OSError:
        return None
    return parse_ioreg_platform_uuid(output)


# --- Servicios de launchd -------------------------------------------------------------------


def parse_launchctl_list(text: str) -> list[dict[str, Any]]:
    """`launchctl list`: "PID<TAB>Status<TAB>Label" por línea, con cabecera.

    PID "-" = no está en ejecución; Status es el último código de salida (negativo: señal).
    """
    services: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        fields = line.split("\t")
        if len(fields) != 3 or fields[0] == "PID":
            continue
        pid_text, code_text, label = (field.strip() for field in fields)
        name = _clip(label, 255)
        if not name or name in seen:
            continue
        seen.add(name)
        pid = int(pid_text) if pid_text.isdigit() else None
        try:
            code = int(code_text)
        except ValueError:
            code = 0
        if pid:
            status = "running"
        elif code == 0:
            status = "stopped"
        elif code < 0:
            status = "signaled"  # terminado por una señal (p. ej. -9 al descargar por inactividad)
        else:
            status = "failed"
        services.append(
            {
                "name": name,
                "display_name": None,
                "status": status,
                "start_type": None,
                "pid": pid or None,
            }
        )
    return services[:MAX_SERVICES]


def collect_services(runner: Runner = run_text) -> list[dict[str, Any]]:
    return parse_launchctl_list(runner([LAUNCHCTL, "list"]))


# --- Software -------------------------------------------------------------------------------


def _read_plist(path: Path, limit: int) -> dict[str, Any] | None:
    try:
        with path.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError:
        return None
    if len(data) > limit:
        return None
    try:
        value = plistlib.loads(data)
    except (plistlib.InvalidFileException, ValueError, TypeError, OverflowError):
        return None
    except Exception:  # plistlib puede lanzar otros errores con datos corruptos
        return None
    return value if isinstance(value, dict) else None


def bundle_software(app: Path) -> dict[str, Any] | None:
    """Entrada de software de un bundle .app a partir de su Contents/Info.plist."""
    info = _read_plist(app / "Contents" / "Info.plist", INFO_PLIST_MAX_BYTES)
    if info is None:
        return None
    name = None
    for key in ("CFBundleDisplayName", "CFBundleName"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            name = value
            break
    version = None
    for key in ("CFBundleShortVersionString", "CFBundleVersion"):
        value = info.get(key)
        if isinstance(value, str) and value.strip():
            version = value
            break
    clean_name = _clip(name or app.name.removesuffix(".app"), 512)
    if not clean_name:
        return None
    # Editor, fecha de instalación y arquitectura no están en Info.plist de forma fiable: se
    # envían como desconocidos en lugar de deducirlos (la fecha de modificación no lo es).
    return {
        "name": clean_name,
        "version": _clip(version, 128),
        "publisher": None,
        "install_date": None,
        "architecture": None,
    }


def _bundles(roots: Iterable[str], deadline: float) -> Iterable[Path]:
    """Bundles .app de las raíces y de sus subcarpetas directas (p. ej. Utilities).

    No se siguen enlaces simbólicos (un enlace a otra parte del disco no es una aplicación
    instalada) ni se entra en los bundles.
    """
    for root in roots:
        stack = [(Path(root), 0)]
        while stack:
            folder, depth = stack.pop()
            try:
                entries = sorted(os.scandir(folder), key=lambda e: e.name)
            except OSError:
                continue
            for entry in entries:
                if time.monotonic() > deadline:
                    raise TimeoutError("software scan exceeded its time limit")
                try:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if entry.name.endswith(".app"):
                    yield Path(entry.path)
                elif depth < 1 and not entry.name.startswith("."):
                    stack.append((Path(entry.path), depth + 1))


def receipt_software(data: dict[str, Any]) -> dict[str, Any] | None:
    """Entrada de software de un recibo de paquete (lo que muestra `pkgutil --pkg-info`)."""
    identifier = data.get("PackageIdentifier")
    if not isinstance(identifier, str) or not identifier.strip():
        return None
    if identifier.startswith("com.apple."):
        return None  # componentes del sistema: los cubre la versión de macOS
    installed = data.get("InstallDate")
    install_date = None
    if isinstance(installed, datetime):
        moment = installed if installed.tzinfo else installed.replace(tzinfo=UTC)
        install_date = moment.astimezone(UTC).date().isoformat()
    version = data.get("PackageVersion")
    return {
        "name": _clip(identifier, 512),
        "version": _clip(version, 128) if isinstance(version, str) else None,
        "publisher": None,
        "install_date": install_date,
        "architecture": None,
    }


def _receipts(directory: str, deadline: float) -> list[dict[str, Any]]:
    try:
        names = sorted(n for n in os.listdir(directory) if n.endswith(".plist"))
    except OSError:
        return []
    found = []
    for name in names[:MAX_RECEIPTS]:
        if time.monotonic() > deadline:
            raise TimeoutError("software scan exceeded its time limit")
        data = _read_plist(Path(directory) / name, RECEIPT_MAX_BYTES)
        entry = receipt_software(data) if data else None
        if entry:
            found.append(entry)
    return found


def collect_software(
    roots: Iterable[str] = APPLICATION_ROOTS,
    receipts_dir: str = RECEIPTS_DIR,
    deadline_seconds: float = SOFTWARE_DEADLINE_SECONDS,
) -> list[dict[str, Any]]:
    """Aplicaciones de /Applications y paquetes instalados (sin los de Apple).

    Si se agota el plazo se lanza TimeoutError: una lista a medias haría creer al servidor
    que se desinstaló software; así la sección se marca como incompleta.
    """
    deadline = time.monotonic() + deadline_seconds
    seen: set[tuple[str, str | None]] = set()
    software: list[dict[str, Any]] = []
    candidates: list[dict[str, Any]] = []
    for app in _bundles(roots, deadline):
        entry = bundle_software(app)
        if entry:
            candidates.append(entry)
    candidates.extend(_receipts(receipts_dir, deadline))
    for entry in candidates:
        key = (str(entry["name"]), entry["version"])
        if key in seen:
            continue
        seen.add(key)
        software.append(entry)
    software.sort(key=lambda item: str(item["name"]).lower())
    return software[:MAX_SOFTWARE]


# --- Cuentas locales ------------------------------------------------------------------------


def parse_dscl_list(text: str) -> dict[str, str]:
    """`dscl . -list /Users <Atributo>`: "nombre<espacios>valor" por línea."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            values[parts[0]] = parts[1].strip()
    return values


def parse_group_membership(text: str) -> set[str]:
    """`dscl . -read /Groups/admin GroupMembership` -> miembros del grupo."""
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip() == "GroupMembership":
            return set(value.split())
    return set()


_NO_LOGIN_SHELLS = ("/usr/bin/false", "/bin/false", "/sbin/nologin", "/usr/sbin/nologin")


def macos_accounts(
    uids: dict[str, str], shells: dict[str, str], admins: set[str] | None
) -> list[dict[str, Any]]:
    """Cuentas de personas (root y UID >= 500), sin las de servicio (prefijo "_").

    `enabled` es False solo si la cuenta no puede iniciar sesión (shell false/nologin); que
    esté deshabilitada por política (pwpolicy) no se lee y queda desconocido (null).
    """
    accounts = []
    for name, uid_text in sorted(uids.items()):
        try:
            uid = int(uid_text)
        except ValueError:
            continue
        if name.startswith("_") or name in ("nobody", "daemon"):
            continue
        if uid != 0 and not 500 <= uid < 2**31:
            continue
        shell = shells.get(name, "")
        accounts.append(
            {
                "name": _clip(name, 255),
                "enabled": False if shell in _NO_LOGIN_SHELLS else None,
                "is_admin": None if admins is None else (uid == 0 or name in admins),
                "last_logon": None,
            }
        )
    return accounts[:MAX_ACCOUNTS]


def collect_accounts(runner: Runner = run_text) -> list[dict[str, Any]]:
    uids = parse_dscl_list(runner([DSCL, ".", "-list", "/Users", "UniqueID"]))
    try:
        shells = parse_dscl_list(runner([DSCL, ".", "-list", "/Users", "UserShell"]))
    except OSError:
        shells = {}
    try:
        admins: set[str] | None = parse_group_membership(
            runner([DSCL, ".", "-read", "/Groups/admin", "GroupMembership"])
        )
    except OSError:
        admins = None  # sin el grupo no se puede afirmar quién es administrador
    return macos_accounts(uids, shells, admins)


# --- Red ------------------------------------------------------------------------------------


def _addresses(values: Iterable[str]) -> list[str]:
    found: list[str] = []
    for value in values:
        token = value.strip().split("%", 1)[0]
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            continue
        text = str(address)
        if not address.is_unspecified and text not in found:
            found.append(text)
    return found[:16]


def parse_route_gateway(text: str) -> list[str]:
    """`route -n get default`: línea "gateway: 192.168.1.1" (IPv6 con zona fe80::1%en0)."""
    return _addresses(
        line.split(":", 1)[1] for line in text.splitlines() if line.strip().startswith("gateway:")
    )


def parse_scutil_dns(text: str) -> list[str]:
    """Servidores DNS de `scutil --dns` (la configuración general antes que la de ámbito)."""
    general, _, scoped = text.partition("(for scoped queries)")
    for section in (general, scoped):
        servers = _addresses(
            line.split(":", 1)[1]
            for line in section.splitlines()
            if line.strip().startswith("nameserver[")
        )
        if servers:
            return servers
    return []


def collect_network(runner: Runner = run_text) -> dict[str, Any]:
    gateways: list[str] = []
    for args in ([ROUTE, "-n", "get", "default"], [ROUTE, "-n", "get", "-inet6", "default"]):
        try:
            gateways += parse_route_gateway(runner(args))
        except OSError:
            continue  # sin ruta por defecto en esa familia (no es un error)
    try:
        dns = parse_scutil_dns(runner([SCUTIL, "--dns"]))
    except OSError:
        dns = []
    return {"gateways": _addresses(gateways), "dns_servers": dns}
