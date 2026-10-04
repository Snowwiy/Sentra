"""Read-only system inventory: interfaces, disks, users, processes, services, software and
network connections.

Every collector only reads what the OS already exposes to the current user. Each section is
collected independently so one failing source (e.g. access denied) does not lose the others.
Limits mirror the API's validation bounds so a busy host never produces a rejected payload.
"""

import logging
import socket
import sys
from collections.abc import Callable
from datetime import UTC, datetime
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


def _clip(value: object, length: int) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
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
        return []  # systemd units: future Linux support
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
            }
        )
    return services[:MAX_SERVICES]


def collect_software() -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return []  # dpkg/rpm: future Linux support
    import winreg

    uninstall = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    # 64-bit and 32-bit (WOW6432Node) machine-wide installs, plus per-user installs.
    sources = [
        (winreg.HKEY_LOCAL_MACHINE, uninstall),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ),
        (winreg.HKEY_CURRENT_USER, uninstall),
    ]

    def value(key: Any, name: str) -> Any:
        try:
            return winreg.QueryValueEx(key, name)[0]
        except OSError:
            return None

    seen: set[tuple[str, str | None]] = set()
    software = []
    for hive, path in sources:
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
                            }
                        )
                except OSError:
                    continue
    software.sort(key=lambda item: str(item["name"]).lower())
    return software[:MAX_SOFTWARE]


SECTIONS: dict[str, Callable[[], list[dict[str, Any]]]] = {
    "interfaces": collect_interfaces,
    "disks": collect_disks,
    "users": collect_users,
    "processes": collect_processes,
    "services": collect_services,
    "software": collect_software,
    "connections": collect_connections,
}


def collect_inventory() -> dict[str, Any]:
    snapshot: dict[str, Any] = {"collected_at": datetime.now(UTC).isoformat()}
    for section, collector in SECTIONS.items():
        try:
            snapshot[section] = collector()
        except Exception:
            logger.warning("inventory section failed", extra={"section": section}, exc_info=True)
            snapshot[section] = []
    return snapshot
