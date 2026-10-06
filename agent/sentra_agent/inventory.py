"""Read-only system inventory: interfaces, disks, users, processes, services, software and
network connections.

Every collector only reads what the OS already exposes to the current user. Each section is
collected independently so one failing source (e.g. access denied) does not lose the others.
Limits mirror the API's validation bounds so a busy host never produces a rejected payload.
"""

import ipaddress
import json
import logging
import os
import platform
import re
import socket
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

logger = logging.getLogger("sentra_agent")

MAX_INTERFACES = 128
MAX_USERS = 256
MAX_PROCESSES = 100  # top by memory; the full process list is noise for an inventory view
MAX_SERVICES = 2000
MAX_SOFTWARE = 5000
MAX_DISKS = 64
MAX_CONNECTIONS = 1000
MAX_ACCOUNTS = 1000


def _clip(value: object, length: int) -> str | None:
    if value is None:
        return None
    # NUL can appear in raw OS strings (e.g. a malformed registry value) and the API rejects
    # it (PostgreSQL cannot store it): drop it here so one bad entry does not cost the whole
    # snapshot.
    text = str(value).replace("\x00", "").strip()
    return text[:length] or None


def collect_interfaces() -> list[dict[str, Any]]:
    stats = psutil.net_if_stats()
    result = []
    for name, addresses in psutil.net_if_addrs().items():
        mac = None
        ips = []
        for address in addresses:
            if address.family == psutil.AF_LINK:
                mac = address.address
            elif address.family in (socket.AF_INET, socket.AF_INET6):
                # IPv6 link-local addresses carry a zone suffix ("fe80::1%12") that is local
                # to this host and not part of a valid address for the API.
                ips.append(address.address.split("%", 1)[0])
        stat = stats.get(name)
        result.append(
            {
                "name": _clip(name, 255) or "unknown",
                "mac": _clip(mac, 64),
                "addresses": ips[:64],
                "is_up": bool(stat and stat.isup),
                # psutil reports 0 when the speed is unknown (virtual adapters, Wi-Fi on some
                # drivers); send null rather than a misleading 0 Mbps.
                "speed_mbps": stat.speed if stat and stat.speed > 0 else None,
            }
        )
    return result[:MAX_INTERFACES]


def collect_disks() -> list[dict[str, Any]]:
    """Mounted volumes with capacity. Telemetry only tracks the system drive's percentage."""
    disks = []
    # all=False skips pseudo filesystems; on Windows it lists fixed, removable and network
    # drives that have a drive letter.
    for partition in psutil.disk_partitions(all=False):
        if "cdrom" in partition.opts:
            continue  # optical drives without media raise or report 0 bytes
        try:
            usage = psutil.disk_usage(partition.mountpoint)
        except (OSError, psutil.Error):
            continue  # card reader without media, disconnected network share
        disks.append(
            {
                "device": _clip(partition.device, 255) or "unknown",
                "mountpoint": _clip(partition.mountpoint, 255) or "unknown",
                "fstype": _clip(partition.fstype, 32),
                "total_bytes": usage.total,
                "used_bytes": usage.used,
                "free_bytes": usage.free,
                "percent": usage.percent,
            }
        )
    return disks[:MAX_DISKS]


def collect_users() -> list[dict[str, Any]]:
    return [
        {
            "name": _clip(user.name, 255) or "unknown",
            "terminal": _clip(user.terminal, 255),
            "host": _clip(user.host, 255),
            "started_at": datetime.fromtimestamp(user.started, UTC).isoformat()
            if user.started
            else None,
        }
        for user in psutil.users()
    ][:MAX_USERS]


def collect_processes() -> list[dict[str, Any]]:
    processes = []
    for proc in psutil.process_iter(["pid", "name", "username", "memory_info"]):
        info = proc.info
        memory = info.get("memory_info")
        processes.append(
            {
                "pid": info["pid"],
                "name": _clip(info.get("name"), 255) or f"pid {info['pid']}",
                # Other users' process owners need admin rights; psutil yields None then.
                "username": _clip(info.get("username"), 255),
                "memory_bytes": memory.rss if memory else 0,
            }
        )
    processes.sort(key=lambda item: item["memory_bytes"], reverse=True)
    return processes[:MAX_PROCESSES]


_CONNECTION_STATES = {psutil.CONN_LISTEN, psutil.CONN_ESTABLISHED, psutil.CONN_NONE}


def collect_connections() -> list[dict[str, Any]]:
    """Listening sockets and established TCP connections, with the owning process.

    Read from the OS connection tables (GetExtendedTcpTable/UdpTable on Windows), which any
    user may query: no packet capture and no admin rights. Transient states (TIME_WAIT,
    SYN_SENT...) are skipped: they churn every second and add nothing to an inventory view.
    Listeners come first because they are the host's attack surface.
    """
    names: dict[int, str] = {}
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info.get("name"):
            names[proc.info["pid"]] = proc.info["name"]

    result = []
    for conn in psutil.net_connections(kind="inet"):
        if conn.status not in _CONNECTION_STATES:
            continue
        is_tcp = conn.type == socket.SOCK_STREAM
        if is_tcp and conn.status == psutil.CONN_NONE:
            continue
        local, remote = conn.laddr, conn.raddr
        result.append(
            {
                "protocol": "tcp" if is_tcp else "udp",
                # Zone suffix stripped for the same reason as in interfaces.
                "local_address": local.ip.split("%", 1)[0] if local else None,
                "local_port": local.port if local else None,
                "remote_address": remote.ip.split("%", 1)[0] if remote else None,
                "remote_port": remote.port if remote else None,
                # UDP is connectionless; "listen" describes a bound UDP socket for the UI.
                "status": conn.status.lower() if is_tcp else "listen",
                "pid": conn.pid or None,
                "process_name": _clip(names.get(conn.pid or -1), 255),
            }
        )
    result.sort(key=lambda c: (c["status"] != "listen", c["protocol"], c["local_port"] or 0))
    return result[:MAX_CONNECTIONS]


def collect_services() -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return _systemd_services()
    services = []
    for service in psutil.win_service_iter():
        try:
            info = service.as_dict()
        except (psutil.Error, OSError):
            continue  # services can disappear or deny access while iterating
        services.append(
            {
                "name": _clip(info.get("name"), 255) or "unknown",
                "display_name": _clip(info.get("display_name"), 512),
                "status": _clip(info.get("status"), 32) or "unknown",
                "start_type": _clip(info.get("start_type"), 32),
                # 🪟 VALIDACIÓN LOCAL EN WINDOWS: psutil reports 0/None for stopped ones.
                "pid": info.get("pid") or None,
            }
        )
    return services[:MAX_SERVICES]


def collect_software() -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return _linux_packages()
    import winreg

    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    # Native and 32-bit (WOW6432Node) machine-wide installs, plus per-user installs, each
    # with the architecture its registry view implies (per-user: unknown).
    # 🪟 VALIDACIÓN LOCAL EN WINDOWS (install date and architecture).
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, uninstall, windows_architecture(platform.machine())),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
            "x86",
        ),
        (winreg.HKEY_CURRENT_USER, uninstall, None),
    ]

    def value(key: Any, name: str) -> Any:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    seen: set[tuple[str, str | None]] = set()
    software = []
    for hive, path, architecture in sources:
        try:
            root = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with root:
            for index in range(winreg.QueryInfoKey(root)[0]):
                try:
                    with winreg.OpenKey(root, winreg.EnumKey(root, index)) as entry:
                        name = _clip(value(entry, "DisplayName"), 512)
                        # SystemComponent entries are hidden parts of other products (runtimes,
                        # patches); Windows' own "Apps" list omits them too.
                        if not name or value(entry, "SystemComponent") == 1:
                            continue
                        version = _clip(value(entry, "DisplayVersion"), 128)
                        if (name, version) in seen:
                            continue
                        seen.add((name, version))
                        software.append(
                            {
                                "name": name,
                                "version": version,
                                "publisher": _clip(value(entry, "Publisher"), 512),
                                "install_date": registry_date(value(entry, "InstallDate")),
                                "architecture": architecture,
                            }
                        )
                except OSError:
                    continue
    software.sort(key=lambda item: str(item["name"]).lower())
    return software[:MAX_SOFTWARE]


def windows_architecture(machine: str) -> str | None:
    """Native architecture name for the 64-bit registry view (platform.machine())."""
    return {"amd64": "x64", "x86_64": "x64", "arm64": "arm64", "x86": "x86"}.get(machine.lower())


def registry_date(raw: object) -> str | None:
    """Uninstall InstallDate is "YYYYMMDD" by convention; anything else is dropped."""
    text = str(raw or "").strip()
    try:
        return datetime.strptime(text, "%Y%m%d").date().isoformat() if len(text) == 8 else None
    except ValueError:
        return None


# --- Linux ------------------------------------------------------------------------------
#
# Read with the distribution's own read-only query tools, through absolute paths so a binary
# planted earlier in PATH is never run (same reasoning as wevtutil.exe on Windows). No shell,
# fixed arguments, bounded run time.

_SYSTEMCTL = ("/usr/bin/systemctl", "/bin/systemctl")
_DPKG_QUERY = ("/usr/bin/dpkg-query", "/bin/dpkg-query")
_RPM = ("/usr/bin/rpm", "/bin/rpm")
# Maintainer fields look like "Ubuntu Developers <ubuntu-devel@lists.ubuntu.com>".
_EMAIL = re.compile(r"\s*<[^>]*>")


def _first_existing(candidates: tuple[str, ...]) -> str | None:
    return next((path for path in candidates if os.path.isfile(path)), None)


def _run(executable: str, *args: str) -> str:
    result = subprocess.run(  # noqa: S603  (absolute path, fixed arguments, no shell)
        [executable, *args], capture_output=True, timeout=60, check=False
    )
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", "replace").strip()
        raise OSError(f"{os.path.basename(executable)} failed ({result.returncode}): {error}")
    return result.stdout.decode("utf-8", "replace")


def parse_systemd_services(units: str, unit_files: str) -> list[dict[str, Any]]:
    """Parse `systemctl list-units --plain` and `list-unit-files` output into API services.

    `status` is the unit's sub-state (running, exited, dead, failed...), which is what the
    dashboard colors; `start_type` is the unit file state (enabled, disabled, static...).
    """
    start_types = {}
    for line in unit_files.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            start_types[fields[0]] = fields[1]
    services = []
    for line in units.splitlines():
        # UNIT LOAD ACTIVE SUB DESCRIPTION (the description may contain spaces).
        fields = line.split(None, 4)
        if len(fields) < 4 or not fields[0].endswith(".service") or fields[1] == "not-found":
            continue
        unit = fields[0]
        services.append(
            {
                "name": _clip(unit.removesuffix(".service"), 255) or "unknown",
                "display_name": _clip(fields[4] if len(fields) > 4 else None, 512),
                "status": _clip(fields[3], 32) or "unknown",
                "start_type": _clip(start_types.get(unit), 32),
            }
        )
    return services[:MAX_SERVICES]


def _systemd_services() -> list[dict[str, Any]]:
    # sd_booted(): systemd manages this host only if this directory exists. Containers and
    # other init systems have no units to report; that is not an error.
    systemctl = _first_existing(_SYSTEMCTL)
    if systemctl is None or not os.path.isdir("/run/systemd/system"):
        return []
    common = ("--type=service", "--no-legend", "--no-pager", "--plain")
    units = _run(systemctl, "list-units", "--all", *common)
    unit_files = _run(systemctl, "list-unit-files", *common)
    return parse_systemd_services(units, unit_files)


def parse_package_list(output: str) -> list[dict[str, Any]]:
    """Parse tab-separated package lines (dpkg-query or rpm output).

    Fields: name, version, publisher, then optionally architecture and install time (epoch
    seconds, rpm only; dpkg does not record one).
    """
    seen: set[tuple[str, str | None]] = set()
    software = []
    for line in output.splitlines():
        fields = line.split("\t")
        if not 3 <= len(fields) <= 5:
            continue
        fields += [""] * (5 - len(fields))
        name = _clip(fields[0], 512)
        version = _clip(fields[1], 128)
        publisher = _EMAIL.sub("", fields[2])
        if not name or (name, version) in seen:
            continue  # multi-arch packages (libc6:amd64 and :i386) report the same version
        seen.add((name, version))
        software.append(
            {
                "name": name,
                "version": version,
                # rpm prints "(none)" for packages without a vendor.
                "publisher": None if publisher == "(none)" else _clip(publisher, 512),
                "architecture": _clip(fields[3], 16) if fields[3] != "(none)" else None,
                "install_date": _epoch_date(fields[4]),
            }
        )
    software.sort(key=lambda item: str(item["name"]).lower())
    return software[:MAX_SOFTWARE]


def _installed_dpkg_lines(output: str) -> str:
    """Keep the packages dpkg reports as installed, without the status column.

    db:Status-Abbrev is three letters: desired action, package state, error flag. The second
    one is "i" for installed, whatever the first says ("ii" normal, "hi" on hold); removed
    packages with leftover configuration ("rc") are not installed software.
    """
    installed = []
    for line in output.splitlines():
        status, _, rest = line.partition("\t")
        if len(status) >= 2 and status[1] == "i":
            installed.append(rest)
    return "\n".join(installed)


def _linux_packages() -> list[dict[str, Any]]:
    dpkg_query = _first_existing(_DPKG_QUERY)
    if dpkg_query is not None:
        output = _run(
            dpkg_query,
            "--show",
            "--showformat=${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Maintainer}"
            "\\t${Architecture}\\n",
        )
        return parse_package_list(_installed_dpkg_lines(output))
    rpm = _first_existing(_RPM)
    if rpm is not None:
        return parse_package_list(
            _run(
                rpm,
                "--query",
                "--all",
                "--queryformat",
                "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{ARCH}\\t%{INSTALLTIME}\\n",
            )
        )
    return []  # other package managers: not supported yet


def software_source() -> str | None:
    """Origen del inventario de software, en el mismo orden de preferencia que la recogida.

    El servidor lo usa para saber con qué reglas comparar versiones (dpkg y rpm no ordenan
    igual) y para no confundir paquetes de la distribución con aplicaciones (Fase 5B).
    """
    if sys.platform == "win32":
        return "windows_registry"
    if _first_existing(_DPKG_QUERY) is not None:
        return "dpkg"
    if _first_existing(_RPM) is not None:
        return "rpm"
    return None


def _epoch_date(raw: str) -> str | None:
    text = raw.strip()
    if not text.isdigit():
        return None
    try:
        return datetime.fromtimestamp(int(text), UTC).date().isoformat()
    except (OverflowError, OSError, ValueError):
        return None


# --- Local accounts ------------------------------------------------------------------------
#
# Identity and state only (name, enabled, administrator, last logon). Never passwords, hashes
# or anything else secret: the collectors do not read them and the API rejects extra fields.

# Windows PowerShell 5.1 ships the LocalAccounts module. The Administrators group is found by
# its well-known SID, so the result does not depend on the Windows display language.
# Get-LocalGroupMember fails on hosts with orphaned (unresolvable) members: then membership is
# reported as unknown (null) for everyone instead of guessing.
_ACCOUNTS_SCRIPT = """
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$ErrorActionPreference = 'Stop'
$admins = $null
try {
  $admins = @(Get-LocalGroupMember -SID 'S-1-5-32-544' | ForEach-Object { [string]$_.SID.Value })
} catch { $admins = $null }
$users = @(Get-LocalUser | ForEach-Object {
  [pscustomobject]@{
    name = [string]$_.Name
    sid = [string]$_.SID.Value
    enabled = [bool]$_.Enabled
    last_logon = if ($_.LastLogon) { $_.LastLogon.ToUniversalTime().ToString('o') } else { $null }
  }
})
[pscustomobject]@{ users = $users; admins = $admins } | ConvertTo-Json -Depth 4 -Compress
"""
# Groups whose members can become root on Debian/Ubuntu (sudo, admin) and RHEL/Fedora (wheel).
_LINUX_ADMIN_GROUPS = {"sudo", "wheel", "admin"}


def _powershell() -> str:
    root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    # A 32-bit Python on 64-bit Windows is redirected to the 32-bit PowerShell, which has no
    # LocalAccounts module; Sysnative reaches the native one.
    system = "Sysnative" if os.environ.get("PROCESSOR_ARCHITEW6432") else "System32"
    return str(root / system / "WindowsPowerShell" / "v1.0" / "powershell.exe")


def parse_windows_accounts(output: str) -> list[dict[str, Any]]:
    """Parse the JSON printed by _ACCOUNTS_SCRIPT."""
    data = json.loads(output.lstrip("\ufeff") or "{}")
    users = data.get("users") or []
    if isinstance(users, dict):  # ConvertTo-Json unwraps single-element arrays
        users = [users]
    admins = data.get("admins")
    admin_sids = None if admins is None else {str(sid) for sid in _as_list(admins)}
    accounts = []
    for user in users:
        if not isinstance(user, dict) or not user.get("name"):
            continue
        accounts.append(
            {
                "name": _clip(user["name"], 255),
                "enabled": user.get("enabled") if isinstance(user.get("enabled"), bool) else None,
                "is_admin": None if admin_sids is None else str(user.get("sid")) in admin_sids,
                "last_logon": _iso_utc(user.get("last_logon")),
            }
        )
    return accounts[:MAX_ACCOUNTS]


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def _iso_utc(value: Any) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC).isoformat() if parsed.tzinfo else None


def parse_linux_accounts(passwd: str, group: str) -> list[dict[str, Any]]:
    """Human accounts (root and UID 1000-65533) from /etc/passwd and /etc/group.

    Without root the shadow file is unreadable, so a locked password cannot be seen:
    `enabled` is False only for accounts that cannot log in at all (nologin/false shell)
    and unknown (null) otherwise.
    """
    admin_gids: set[str] = set()
    admin_members: set[str] = set()
    for line in group.splitlines():
        fields = line.split(":")
        if len(fields) >= 4 and fields[0] in _LINUX_ADMIN_GROUPS:
            admin_gids.add(fields[2])
            admin_members.update(m for m in fields[3].split(",") if m)
    accounts = []
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) < 7 or not fields[2].isdigit():
            continue
        name, uid, gid, shell = fields[0], int(fields[2]), fields[3], fields[6]
        if uid != 0 and not 1000 <= uid < 65534:
            continue  # system accounts (daemons) and nobody
        no_login = shell.rstrip().endswith(("nologin", "/false"))
        accounts.append(
            {
                "name": _clip(name, 255),
                "enabled": False if no_login else None,
                "is_admin": uid == 0 or name in admin_members or gid in admin_gids,
                "last_logon": None,
            }
        )
    return accounts[:MAX_ACCOUNTS]


def collect_accounts() -> list[dict[str, Any]]:
    if sys.platform == "win32":
        # 🪟 VALIDACIÓN LOCAL EN WINDOWS: PowerShell 5.1 LocalAccounts, as a standard user.
        return parse_windows_accounts(
            _run(_powershell(), "-NoProfile", "-NonInteractive", "-Command", _ACCOUNTS_SCRIPT)
        )
    try:
        passwd = Path("/etc/passwd").read_text(encoding="utf-8", errors="replace")
        group = Path("/etc/group").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return parse_linux_accounts(passwd, group)


# --- Network summary (gateways, DNS servers) -----------------------------------------------

_MAX_ADDRESSES = 16


def ip_list(values: Any) -> list[str]:
    """Valid, distinct IP addresses from registry/text values ("a b,c" or a list of them)."""
    found: list[str] = []
    for value in _flatten(values):
        for token in re.split(r"[\s,;]+", str(value or "")):
            token = token.split("%", 1)[0]  # IPv6 zone index
            try:
                address = ipaddress.ip_address(token)
            except ValueError:
                continue
            text = str(address)
            if not address.is_unspecified and text not in found:
                found.append(text)
    return found[:_MAX_ADDRESSES]


def _flatten(values: Any) -> list[Any]:
    # REG_MULTI_SZ values are lists, collected into a list per interface.
    if not isinstance(values, list):
        return [values]
    return [item for value in values for item in _flatten(value)]


def parse_proc_route(text: str) -> list[str]:
    """Default IPv4 gateways from /proc/net/route (hex, little-endian)."""
    gateways = []
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4 or fields[1] != "00000000":
            continue
        try:
            if int(fields[3], 16) & 0x2:  # RTF_GATEWAY
                gateways.append(str(ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1])))
        except ValueError:
            continue
    return ip_list(gateways)


def parse_resolv_conf(text: str) -> list[str]:
    return ip_list(
        [
            line.split()[1]
            for line in text.splitlines()
            if line.strip().startswith("nameserver") and len(line.split()) > 1
        ]
    )


def _windows_network() -> dict[str, Any]:
    """Gateways/DNS of the interfaces that are up, from the TCP/IP registry keys.

    🪟 VALIDACIÓN LOCAL EN WINDOWS. Read-only registry access, no admin rights. Static values
    win over DHCP ones, as Windows itself does. Interfaces are matched by their friendly name
    (Connection\\Name), the same name psutil reports, so adapters that are down (whose
    last DHCP values stay in the registry) are left out.
    """
    if sys.platform != "win32":  # keeps mypy on Linux from checking winreg calls
        return {"gateways": [], "dns_servers": []}
    import winreg

    def values(key: Any, *names: str) -> Any:
        for name in names:
            try:
                value = winreg.QueryValueEx(key, name)[0]
            except OSError:
                continue
            if ip_list(value):
                return value
        return None

    def subkeys(path: str) -> list[str]:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                return [winreg.EnumKey(key, i) for i in range(winreg.QueryInfoKey(key)[0])]
        except OSError:
            return []

    network_class = (
        r"SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}"
    )
    friendly: dict[str, str] = {}
    for guid in subkeys(network_class):
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, rf"{network_class}\{guid}\Connection"
            ) as key:
                friendly[guid.lower()] = str(winreg.QueryValueEx(key, "Name")[0])
        except OSError:
            continue
    up = {name for name, stats in psutil.net_if_stats().items() if stats.isup}
    gateways: list[Any] = []
    dns: list[Any] = []
    for service in ("Tcpip", "Tcpip6"):
        base = rf"SYSTEM\CurrentControlSet\Services\{service}\Parameters\Interfaces"
        for guid in subkeys(base):
            if friendly.get(guid.lower()) not in up:
                continue
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"{base}\{guid}") as key:
                    gateways.append(values(key, "DefaultGateway", "DhcpDefaultGateway"))
                    dns.append(values(key, "NameServer", "DhcpNameServer"))
            except OSError:
                continue
    return {"gateways": ip_list(gateways), "dns_servers": ip_list(dns)}


def collect_network() -> dict[str, Any] | None:
    if sys.platform == "win32":
        return _windows_network()
    try:
        route = Path("/proc/net/route").read_text(encoding="utf-8", errors="replace")
    except OSError:
        route = ""
    try:
        resolv = Path("/etc/resolv.conf").read_text(encoding="utf-8", errors="replace")
    except OSError:
        resolv = ""
    return {"gateways": parse_proc_route(route), "dns_servers": parse_resolv_conf(resolv)}


SECTIONS: dict[str, Callable[[], Any]] = {
    "interfaces": collect_interfaces,
    "disks": collect_disks,
    "users": collect_users,
    "processes": collect_processes,
    "services": collect_services,
    "software": collect_software,
    "connections": collect_connections,
    "accounts": collect_accounts,
    "network": collect_network,
}
# What a failed section is reported as: empty list, or no summary at all.
_EMPTY: dict[str, Any] = {"network": None}


def collect_inventory() -> dict[str, Any]:
    snapshot: dict[str, Any] = {"collected_at": datetime.now(UTC).isoformat()}
    failed = []
    for section, collector in SECTIONS.items():
        try:
            snapshot[section] = collector()
        except Exception:
            logger.warning("inventory section failed", extra={"section": section}, exc_info=True)
            snapshot[section] = _EMPTY.get(section, [])
            failed.append(section)
    # Una sección fallida se envía vacía; el servidor necesita saber que está incompleta para
    # no tomar "sin software" como "el software se desinstaló" (Fase 5B).
    snapshot["incomplete_sections"] = failed
    snapshot["software_source"] = software_source()
    return snapshot
