"""`status` (solo estado local) y `diagnostics` (comprueba servidor, TLS, credencial, spool).

Ninguno muestra la credencial: como mucho, si está cargada y si sus permisos son correctos.
Tampoco el contenido de los ficheros de leases DHCP (Fase 6E): solo nombre, formato, ruta,
si existen, si se pueden abrir y su tamaño.
"""

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sentra_sensor import CAPABILITIES, __version__
from sentra_sensor.client import ApiError, SensorClient, TlsError, Transport, TransportError
from sentra_sensor.config import LocalConfig
from sentra_sensor.credentials import CredentialError, CredentialStore
from sentra_sensor.dhcp import describe_sources
from sentra_sensor.fsperm import is_private
from sentra_sensor.spool import Spool
from sentra_sensor.state import host_metadata, load_state


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def _spool_summary(path: Path, config: LocalConfig) -> dict[str, Any]:
    if not path.exists():
        return {"path": str(path), "items": 0, "bytes": 0, "dropped_total": 0}
    spool = Spool(
        path,
        max_bytes=config.spool_max_mb * 1024 * 1024,
        max_items=config.spool_max_items,
        max_age_seconds=config.spool_max_age_hours * 3600,
    )
    try:
        stats = spool.stats()
    finally:
        spool.close()
    return {
        "path": str(path),
        "items": stats.items,
        "bytes": stats.bytes,
        "dropped_total": stats.dropped_total,
    }


def local_status(config: LocalConfig) -> dict[str, Any]:
    store = CredentialStore(config.credential_file())
    status: dict[str, Any] = {"version": __version__, "enrolled": False}
    try:
        identity = store.load()
    except CredentialError as exc:
        status["credential_error"] = str(exc) if store.exists() else None
    else:
        status.update(
            enrolled=True,
            sensor_id=identity.sensor_id,
            site_id=identity.site_id,
            site_name=identity.site_name,
            server_url=config.server_url or identity.server_url,
            credential_issued_at=identity.credential_issued_at,
            enrolled_at=identity.enrolled_at,
        )
    state = load_state(config.state_file())
    status["mode"] = state.mode
    status["last_heartbeat_at"] = state.last_heartbeat_at
    status["last_successful_job_at"] = state.last_successful_job_at
    if state.server_config:
        status["allowed_networks"] = state.server_config.get("allowed_networks", [])
        status["jobs_enabled"] = state.server_config.get("jobs_enabled")
    status["spool"] = _spool_summary(config.spool_file(), config)
    status["dhcp_sources"] = describe_sources(config)
    return status


def _dhcp_checks(config: LocalConfig) -> list[Check]:
    """Una comprobación por fuente DHCP: falla si el job no podría leerla ahora mismo."""
    checks: list[Check] = []
    for source in describe_sources(config):
        if not source["exists"]:
            ok, state = False, "file missing"
        elif not source["readable"]:
            ok, state = False, "file not readable by this account"
        elif source["too_large"]:
            ok, state = False, f"{source['size_bytes']} bytes exceeds dhcp_max_file_kb"
        else:
            ok, state = True, f"readable, {source['size_bytes']} bytes"
        checks.append(
            Check(
                f"dhcp_source:{source['name']}",
                ok,
                f"{source['format']} {source['path']}: {state}",
            )
        )
    return checks


def run_diagnostics(config: LocalConfig, transport: Transport) -> list[Check]:
    checks: list[Check] = [Check("config", True, "configuration is valid")]
    data_dir = config.data_dir
    writable = data_dir.is_dir() and os.access(data_dir, os.W_OK)
    checks.append(
        Check("data_dir", writable, f"{data_dir} {'is' if writable else 'is NOT'} writable")
    )
    private = is_private(data_dir)
    checks.append(
        Check(
            "data_dir_permissions",
            private,
            "owner-only" if private else "data_dir is accessible to other accounts",
        )
    )
    # Antes de la credencial: el estado de las fuentes locales se ve aunque no esté enrolado.
    checks.extend(_dhcp_checks(config))
    store = CredentialStore(config.credential_file())
    try:
        identity = store.load()
    except CredentialError as exc:
        checks.append(Check("credential", False, str(exc)))
        return checks
    checks.append(Check("credential", True, "credential loaded (value not shown)"))
    checks.append(
        Check(
            "credential_permissions",
            store.permissions_ok(),
            "owner-only" if store.permissions_ok() else "credential file is readable by others",
        )
    )
    server_url = config.server_url or identity.server_url
    scheme = urlsplit(server_url).scheme
    client = SensorClient(
        server_url,
        transport,
        timeout=config.request_timeout_seconds,
        credential=identity.credential,
    )
    body: dict[str, Any] = {
        **host_metadata(),
        "sensor_version": __version__,
        "capabilities": list(CAPABILITIES),
    }
    body["sent_at"] = datetime.now(UTC).isoformat()
    try:
        response = client.heartbeat(body)
    except TlsError as exc:
        checks.append(Check("server_reachable", True, server_url))
        checks.append(Check("tls", False, str(exc)))
    except TransportError as exc:
        checks.append(Check("server_reachable", False, f"{server_url}: {exc}"))
    except ApiError as exc:
        checks.append(Check("server_reachable", True, server_url))
        checks.append(Check("tls", True, "verified" if scheme == "https" else "loopback http"))
        checks.append(Check("authenticated", False, f"HTTP {exc.status} {exc.code or ''}".strip()))
    else:
        checks.append(Check("server_reachable", True, server_url))
        checks.append(Check("tls", True, "verified" if scheme == "https" else "loopback http"))
        checks.append(Check("authenticated", True, f"status {response.get('status')}"))
        site_ok = str(response.get("site_id")) == identity.site_id
        checks.append(
            Check(
                "site",
                site_ok,
                f"{identity.site_name or identity.site_id}"
                + ("" if site_ok else " (server reports a different site)"),
            )
        )
    spool = _spool_summary(config.spool_file(), config)
    checks.append(Check("spool", True, f"{spool['items']} items, {spool['bytes']} bytes"))
    return checks
