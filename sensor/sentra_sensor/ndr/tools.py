"""Herramientas locales de NDR para el operador: `ndr-check` y `ndr-replay`.

Ninguna de las dos habla con el servidor. `ndr-check` comprueba que las interfaces declaradas
en sensor.toml existen y que el backend de captura se puede cargar; `ndr-replay` procesa un
.pcap clásico con el mismo pipeline que la captura real para validar el decodificador y los
límites sin tocar la red (QA en laboratorio o análisis de una captura propia).
"""

import contextlib
import socket
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

from sentra_sensor.ndr.capture import (
    CaptureError,
    InterfaceInfo,
    PcapFileBackend,
    list_os_interfaces,
    list_pcap_interfaces,
    load_libpcap,
)
from sentra_sensor.ndr.config import NdrInterface, NdrLocalConfig, NdrServerConfig
from sentra_sensor.ndr.pipeline import InterfaceCapture

# El replay no tiene reloj real: se procesa tan rápido como se lee y el presupuesto de pps
# de la captura en vivo descartaría casi todo. Este límite solo protege de ficheros enormes.
REPLAY_MAX_PACKETS_PER_SECOND = 10_000_000


def _backend_check(kind: str, platform: str) -> dict[str, Any]:
    """Comprueba que el backend se puede usar, sin abrir ninguna interfaz."""
    effective = kind
    if kind == "auto":
        effective = "af_packet" if platform.startswith("linux") else "libpcap"
    result: dict[str, Any] = {"backend": effective, "ok": True, "code": None, "detail": None}
    if effective == "af_packet":
        family = getattr(socket, "AF_PACKET", None)
        if family is None:
            return {**result, "ok": False, "code": "backend_unavailable", "detail": "no AF_PACKET"}
        try:
            # Un socket sin bind no captura nada; solo confirma CAP_NET_RAW.
            probe = socket.socket(family, socket.SOCK_RAW, 0)
        except PermissionError:
            return {
                **result,
                "ok": False,
                "code": "permission_denied",
                "detail": "CAP_NET_RAW is required (see sentra-sensor-ndr.conf)",
            }
        except OSError as exc:
            return {**result, "ok": False, "code": "capture_failed", "detail": exc.strerror}
        probe.close()
        return result
    try:
        load_libpcap(platform)
    except CaptureError as exc:
        return {**result, "ok": False, "code": exc.code, "detail": exc.detail}
    return result


def ndr_check(local: NdrLocalConfig, platform: str | None = None) -> dict[str, Any]:
    """Estado local de NDR: backend utilizable y presencia de cada interfaz declarada."""
    platform = platform or sys.platform
    report: dict[str, Any] = {
        "enabled": local.enabled,
        "backend": _backend_check(local.backend, platform),
        "interfaces": [],
    }
    known: list[InterfaceInfo] = list_os_interfaces()
    backend = report["backend"]["backend"]
    if backend == "libpcap" and report["backend"]["ok"]:
        # En Windows los nombres de Npcap (\Device\NPF_{GUID}) no coinciden con los del
        # sistema: la lista que vale es la de la propia biblioteca.
        with contextlib.suppress(CaptureError, OSError):
            known = list_pcap_interfaces(platform)
    by_device = {info.device: info for info in known}
    for interface in local.interfaces:
        info = by_device.get(interface.device)
        report["interfaces"].append(
            {
                "name": interface.name,
                "device": interface.device,
                "present": info is not None,
                "up": info.up if info is not None else None,
            }
        )
    report["available_devices"] = [
        {"device": info.device, "description": info.description, "up": info.up} for info in known
    ]
    report["ok"] = bool(
        not local.enabled
        or (report["backend"]["ok"] and all(i["present"] for i in report["interfaces"]))
    )
    return report


def replay_pcap(
    path: Path, server: NdrServerConfig | None = None, interface: str = "replay"
) -> dict[str, Any]:
    """Procesa un .pcap clásico y devuelve los lotes que se habrían enviado (sin enviarlos)."""
    config = server or NdrServerConfig(
        enabled=True,
        revision=0,
        interfaces=(interface,),
        dns_metadata=True,
        tls_metadata=True,
    )
    config = replace(config, max_packets_per_second=REPLAY_MAX_PACKETS_PER_SECOND)
    batches: list[dict[str, Any]] = []
    backend = PcapFileBackend(path, snaplen=config.snaplen)
    capture = InterfaceCapture(
        NdrInterface(interface, str(path)),
        config,
        lambda _i, _c: backend,
        lambda _alias, batch: batches.append(batch),
    )
    try:
        while not backend.exhausted:
            capture.run_once(timeout=0)
            if capture.status.state == "error":
                raise CaptureError(
                    capture.status.error_code or "capture_failed",
                    capture.status.error_detail or "replay failed",
                )
    finally:
        capture.stop(timeout=0)
    summary = {
        "batches": len(batches),
        "flows": sum(len(b["flows"]) for b in batches),
        "arp": sum(len(b["arp"]) for b in batches),
        "dns": sum(len(b["dns"]) for b in batches),
        "dhcp": sum(len(b["dhcp"]) for b in batches),
        "tls": sum(len(b["tls"]) for b in batches),
        "packets_seen": sum(b["stats"].get("packets_seen", 0) for b in batches),
        "malformed": sum(b["stats"].get("malformed", 0) for b in batches),
    }
    return {"summary": summary, "batches": batches}
