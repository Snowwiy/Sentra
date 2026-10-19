"""Host inventory and resource metrics, read through psutil for Windows/Linux portability."""

import platform
import socket
import sys
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psutil

from sentra_agent import __version__
from sentra_agent.machine_identity import machine_id_hash
from sentra_agent.macos import platform_info


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


def _os_name() -> str:
    # Fase 6C.5: en macOS platform.system() devuelve "Darwin" (el núcleo); el servidor y el
    # panel muestran el producto, como hacen con Windows y Linux.
    if sys.platform == "darwin":
        return "macOS"
    return platform.system() or "unknown"


def _architecture() -> str:
    if sys.platform == "darwin":
        # Arquitectura del Mac, no la del proceso: bajo Rosetta 2 platform.machine() dice
        # x86_64 en un Apple Silicon. La del proceso va en el diagnóstico del agente.
        return platform_info(platform.machine()).native_architecture
    return platform.machine() or "unknown"


def _os_version() -> str:
    if sys.platform == "darwin":
        # "15.1 (24B83)" de sw_vers; si no estuviera, la versión de platform.mac_ver().
        return platform_info(platform.machine()).os_version or platform.mac_ver()[0] or "unknown"
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
        os_name=_os_name(),
        os_version=_os_version()[:128] or "unknown",
        architecture=_architecture()[:32] or "unknown",
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
