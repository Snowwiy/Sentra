"""Host inventory and resource metrics, read through psutil for Windows/Linux portability."""

import platform
import socket
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from sentra_agent import __version__
from sentra_agent.machine_identity import machine_id_hash


@dataclass(frozen=True)
class HostInfo:
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    primary_ip: str
    agent_version: str
    # Fase 5C.1: hash del id del equipo (machine_identity). Solo se envía si existe: un
    # servidor anterior lo rechazaría como campo desconocido.
    machine_id_hash: str | None = None

    def as_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        if payload["machine_id_hash"] is None:
            del payload["machine_id_hash"]
        return payload


def _os_version() -> str:
    if platform.system() == "Windows":
        # release() gives the marketing version ("11"), version() the build ("10.0.26200").
        return f"{platform.release()} (build {platform.version()})"
    return platform.release()


def primary_ip() -> str:
    """Return the address of the interface used for outbound traffic.

    Connecting a UDP socket sends no packets; it only asks the OS routing table which local
    address would be used. 192.0.2.1 is a reserved documentation address, never contacted.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("192.0.2.1", 9))
            return str(sock.getsockname()[0])
        except OSError:
            return "127.0.0.1"


def collect_host_info() -> HostInfo:
    return HostInfo(
        hostname=socket.gethostname()[:255],
        os_name=platform.system() or "unknown",
        os_version=_os_version()[:128] or "unknown",
        architecture=(platform.machine() or "unknown")[:32],
        primary_ip=primary_ip(),
        agent_version=__version__,
        machine_id_hash=machine_id_hash(),
    )


def system_disk_path() -> str:
    # The system drive (C:\ on Windows, / elsewhere) is what fills up and breaks a host.
    return Path.home().anchor or "/"


def collect_metrics() -> dict[str, Any]:
    """Collect one telemetry sample. Blocks ~1 s to measure CPU over a real interval."""
    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "ram_percent": psutil.virtual_memory().percent,
        "disk_percent": psutil.disk_usage(system_disk_path()).percent,
        "uptime_seconds": max(0, int(time.time() - psutil.boot_time())),
    }
