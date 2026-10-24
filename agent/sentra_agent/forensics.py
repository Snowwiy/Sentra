"""Acciones forenses de solo lectura (Fase 6E.6).

Cada acción devuelve un artefacto `sentra-forensic/1` con el contenido, su SHA-256 sobre el
JSON canónico (el servidor lo recalcula: si no coincide, el artefacto queda marcado) y las
limitaciones encontradas (permisos insuficientes, no soportado en esta plataforma...).

Límites deliberados:
- nunca se lee el contenido de un fichero salvo para el hash de `forensic_file_metadata`, y
  solo hasta `forensics.hash_max_mb`;
- la única ruta que acepta una acción (`path`) se valida aquí con la configuración LOCAL
  (`forensics.allowed_roots`): absoluta, sin `..`, sin rutas de red ni flujos alternativos,
  dentro de las raíces permitidas y fuera de una lista de rutas sensibles. Un servidor
  comprometido no puede ampliar ese alcance;
- un enlace simbólico no se sigue (se informa a dónde apunta) y un directorio intermedio que
  escape de las raíces por un enlace se rechaza;
- el artefacto completo tiene tope `forensics.max_artifact_kb`: se recorta la lista y se
  marca `truncated`.
"""

import hashlib
import json
import logging
import os
import socket
import stat
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import PurePath, PurePosixPath, PureWindowsPath
from typing import Any

import psutil

from sentra_agent import __version__
from sentra_agent.activity import (
    clip,
    create_time_ms,
    file_sha256,
    instance_key,
    iso,
    redact_cmdline,
)
from sentra_agent.endpoint import (
    CollectorUnavailableError,
    Records,
    public,
    read_firewall,
    read_persistence,
    read_scheduled_tasks,
    read_services,
    run_powershell,
)
from sentra_agent.syscmd import CommandOutput, run_bounded

logger = logging.getLogger("sentra_agent")

SCHEMA = "sentra-forensic/1"
PATH_MAX = 1024

FORENSIC_PROCESSES = "forensic_processes"
FORENSIC_CONNECTIONS = "forensic_connections"
FORENSIC_SERVICES = "forensic_services"
FORENSIC_SCHEDULED_TASKS = "forensic_scheduled_tasks"
FORENSIC_PERSISTENCE = "forensic_persistence"
FORENSIC_SESSIONS = "forensic_sessions"
FORENSIC_NETWORK_CONFIG = "forensic_network_config"
FORENSIC_FIREWALL_STATE = "forensic_firewall_state"
FORENSIC_FILE_METADATA = "forensic_file_metadata"
FORENSIC_TYPES = frozenset(
    {
        FORENSIC_PROCESSES,
        FORENSIC_CONNECTIONS,
        FORENSIC_SERVICES,
        FORENSIC_SCHEDULED_TASKS,
        FORENSIC_PERSISTENCE,
        FORENSIC_SESSIONS,
        FORENSIC_NETWORK_CONFIG,
        FORENSIC_FIREWALL_STATE,
        FORENSIC_FILE_METADATA,
    }
)


def forensic_capabilities(platform: str) -> set[str]:
    """Acciones forenses que funcionan de verdad en esta plataforma."""
    if platform == "win32" or platform.startswith("linux"):
        return set(FORENSIC_TYPES)
    if platform == "darwin":
        # launchd no tiene "tareas programadas" separadas de la persistencia: no se ofrece
        # una acción que siempre volvería vacía.
        return set(FORENSIC_TYPES) - {FORENSIC_SCHEDULED_TASKS}
    return set()


# --- Rutas permitidas ----------------------------------------------------------------------


class PathRejectedError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def default_allowed_roots(platform: str | None = None) -> tuple[str, ...]:
    """Programas y sistema; nunca perfiles de usuario completos ni temporales de usuario."""
    platform = platform or sys.platform
    if platform == "win32":
        env = os.environ
        roots = [
            env.get("PROGRAMFILES") or r"C:\Program Files",
            env.get("PROGRAMFILES(X86)") or r"C:\Program Files (x86)",
            env.get("SYSTEMROOT") or r"C:\Windows",
            env.get("PROGRAMDATA") or r"C:\ProgramData",
        ]
        return tuple(dict.fromkeys(roots))
    if platform == "darwin":
        return ("/Applications", "/Library", "/System/Library", "/usr", "/opt", "/bin", "/sbin")
    return ("/usr", "/opt", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/boot", "/srv")


def _sensitive(platform: str) -> tuple[str, ...]:
    """Rutas que nunca se examinan aunque caigan dentro de una raíz permitida."""
    if platform == "win32":
        system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
        program_data = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return (
            system_root + r"\System32\config",  # SAM, SECURITY, SYSTEM
            program_data + r"\Sentra",  # estado y token cifrado del propio agente
            program_data + r"\Microsoft\Crypto",
        )
    return (
        "/etc/shadow",
        "/etc/gshadow",
        "/etc/sudoers",
        "/etc/sudoers.d",
        "/etc/ssh",
        "/etc/sentra-agent",
        "/var/lib/sentra-agent",
        "/private/etc/master.passwd",
        "/Library/Keychains",
        "/Library/Sentra",
    )


def _pure(platform: str) -> type[PurePath]:
    return PureWindowsPath if platform == "win32" else PurePosixPath


def _parts(path: PurePath, platform: str) -> tuple[str, ...]:
    if platform == "win32":
        return tuple(part.casefold() for part in path.parts)
    return path.parts


def _within(path: PurePath, root: PurePath, platform: str) -> bool:
    parts, root_parts = _parts(path, platform), _parts(root, platform)
    return len(parts) >= len(root_parts) and parts[: len(root_parts)] == root_parts


def validate_path(
    raw: object,
    allowed_roots: tuple[str, ...] | None,
    platform: str | None = None,
    extra_denied: tuple[str, ...] = (),
) -> str:
    """Valida `path` de forensic_file_metadata sin tocar el sistema de ficheros."""
    platform = platform or sys.platform
    if not isinstance(raw, str) or not 1 <= len(raw) <= PATH_MAX:
        raise PathRejectedError("invalid_params", "path must be a string of 1-1024 chars")
    if any(ord(ch) < 32 for ch in raw):
        raise PathRejectedError("invalid_params", "path contains control characters")
    pure = _pure(platform)
    path = pure(raw)
    if platform == "win32":
        # Sin UNC (\\server\share, \\?\...): la cuenta del servicio no debe salir a la red.
        if raw.startswith(("\\\\", "//")) or not path.drive or not path.root:
            raise PathRejectedError("invalid_params", "path must be an absolute local path")
        if ":" in raw[2:]:
            raise PathRejectedError("invalid_params", "alternate data streams are not allowed")
    elif not raw.startswith("/"):
        raise PathRejectedError("invalid_params", "path must be absolute")
    separators = ("\\", "/") if platform == "win32" else ("/",)
    pieces = [raw]
    for separator in separators:
        pieces = [p for piece in pieces for p in piece.split(separator)]
    if ".." in pieces:
        raise PathRejectedError("invalid_params", "path must not contain '..'")
    roots = allowed_roots if allowed_roots is not None else default_allowed_roots(platform)
    if not any(_within(path, pure(root), platform) for root in roots if root):
        raise PathRejectedError("path_not_allowed", "path is outside forensics.allowed_roots")
    for denied in (*_sensitive(platform), *extra_denied):
        if denied and _within(path, pure(denied), platform):
            raise PathRejectedError("path_not_allowed", "path is in a protected location")
    return str(path)


# --- Artefactos ----------------------------------------------------------------------------


def canonical(content: Any) -> bytes:
    return json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def build_artifact(
    kind: str,
    content: dict[str, Any],
    max_kb: int,
    platform: str | None = None,
    list_key: str = "items",
    collected_at: datetime | None = None,
) -> dict[str, Any]:
    """Artefacto del contrato con recorte por tamaño y SHA-256 del JSON canónico."""
    limit = max_kb * 1024
    truncated = False
    items = content.get(list_key)
    if len(canonical(content)) > limit and isinstance(items, list):
        # Búsqueda binaria del número de elementos que cabe: O(log n) serializaciones.
        low, high = 0, len(items)
        while low < high:
            middle = (low + high + 1) // 2
            if len(canonical({**content, list_key: items[:middle]})) <= limit:
                low = middle
            else:
                high = middle - 1
        content = {**content, list_key: items[:low]}
        truncated = True
    return {
        "schema": SCHEMA,
        "kind": kind,
        "collected_at": (collected_at or datetime.now(UTC)).isoformat(),
        "agent_version": __version__,
        "platform": _platform_name(platform or sys.platform),
        "content": content,
        "sha256": hashlib.sha256(canonical(content)).hexdigest(),
        "truncated": truncated,
    }


def _platform_name(platform: str) -> str:
    if platform == "win32":
        return "windows"
    if platform == "darwin":
        return "macos"
    return "linux" if platform.startswith("linux") else platform


def limitation(code: str, detail: str) -> dict[str, str]:
    return {"code": code, "detail": detail[:200]}


# --- Recolección ---------------------------------------------------------------------------

_SIGNATURE_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$s = Get-AuthenticodeSignature -LiteralPath $env:SENTRA_FORENSIC_PATH; "
    "$c = $s.SignerCertificate; "
    "[pscustomobject]@{ status = [string]$s.Status; signer = $c.Subject; issuer = $c.Issuer; "
    "thumbprint = $c.Thumbprint; "
    "not_after = $(if ($c) { $c.NotAfter.ToUniversalTime().ToString('o') } else { $null }) } "
    "| ConvertTo-Json -Compress"
)


def _list_result(
    reader: Callable[[], Records], label: str
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    try:
        records = reader()
    except PermissionError as exc:
        return [], [limitation("permission_denied", f"{label}: {exc}")]
    except CollectorUnavailableError as exc:
        return [], [limitation("not_supported", f"{label}: {exc}")]
    return [public(record) for _, record in sorted(records.items())], []


class ForensicCollector:
    """Ejecuta las acciones forenses. Las fuentes del sistema son inyectables (tests)."""

    def __init__(
        self,
        boot_id: str,
        cmdline_policy: str = "redacted",
        allowed_roots: tuple[str, ...] | None = None,
        max_artifact_kb: int = 2048,
        hash_max_mb: int = 100,
        platform: str | None = None,
        extra_denied: tuple[str, ...] = (),
        run: Callable[..., CommandOutput] = run_bounded,
        readers: dict[str, Callable[[], Records]] | None = None,
    ) -> None:
        self.boot_id = boot_id
        self.cmdline_policy = cmdline_policy
        self.allowed_roots = allowed_roots
        self.max_artifact_kb = max_artifact_kb
        self.hash_max_bytes = hash_max_mb * 1024 * 1024
        self.platform = platform or sys.platform
        self.extra_denied = extra_denied
        self._run = run
        self.readers = readers or {
            FORENSIC_SERVICES: lambda: read_services(self.platform),
            FORENSIC_SCHEDULED_TASKS: lambda: read_scheduled_tasks(
                self.platform, self._run, self.cmdline_policy
            ),
            FORENSIC_PERSISTENCE: lambda: read_persistence(self.platform, self.cmdline_policy),
            FORENSIC_FIREWALL_STATE: lambda: read_firewall(self.platform, self._run),
        }

    def collect(
        self, kind: str, params: dict[str, Any] | None = None
    ) -> tuple[str, dict[str, Any]]:
        """(summary, data) con data = {"artifact": ..., "limitations": [...]}."""
        handlers: dict[str, Callable[[], tuple[dict[str, Any], list[dict[str, str]]]]] = {
            FORENSIC_PROCESSES: self._processes,
            FORENSIC_CONNECTIONS: self._connections,
            FORENSIC_SESSIONS: self._sessions,
            FORENSIC_NETWORK_CONFIG: self._network_config,
        }
        if kind == FORENSIC_FILE_METADATA:
            params = params or {}
            content, limits = self.file_metadata(str(params["path"]), bool(params["hash"]))
        elif kind in handlers:
            content, limits = handlers[kind]()
        elif kind in self.readers:
            items, limits = _list_result(self.readers[kind], kind.removeprefix("forensic_"))
            content = {"items": items, "total": len(items)}
        else:
            raise ValueError(f"not a forensic action: {kind}")
        artifact = build_artifact(kind, content, self.max_artifact_kb, self.platform)
        if kind == FORENSIC_FILE_METADATA:
            summary = "file metadata" if content.get("exists") else "file not found"
        else:
            total = content.get("total", 0)
            summary = f"{total} items" + (" (truncated)" if artifact["truncated"] else "")
        return summary, {"artifact": artifact, "limitations": limits}

    def _processes(self) -> tuple[dict[str, Any], list[dict[str, str]]]:
        items = []
        hidden = 0
        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "status"]
        for proc in psutil.process_iter(attrs, ad_value=None):
            info = proc.info
            created = info.get("create_time")
            key = (
                instance_key(self.boot_id, info["pid"], create_time_ms(created))
                if created
                else None
            )
            if info.get("exe") is None and info.get("username") is None:
                hidden += 1
            items.append(
                {
                    "pid": info["pid"],
                    "ppid": info.get("ppid"),
                    "instance_key": key,
                    "name": clip(info.get("name"), 255),
                    "exe": clip(info.get("exe"), 1024),
                    "cmdline": redact_cmdline(info.get("cmdline"), self.cmdline_policy),
                    "username": clip(info.get("username"), 255),
                    "started_at": iso(created) if created else None,
                    "status": clip(info.get("status"), 32),
                }
            )
        items.sort(key=lambda item: item["pid"])
        limits = (
            [limitation("permission_denied", f"{hidden} processes without owner or path")]
            if hidden
            else []
        )
        return {"items": items, "total": len(items), "cmdline_policy": self.cmdline_policy}, limits

    def _connections(self) -> tuple[dict[str, Any], list[dict[str, str]]]:
        try:
            raw = psutil.net_connections(kind="inet")
        except psutil.AccessDenied:
            return {"items": [], "total": 0}, [
                limitation("permission_denied", "connection table needs more privileges")
            ]
        items = []
        for conn in raw:
            local, remote = conn.laddr, conn.raddr
            items.append(
                {
                    "pid": conn.pid or None,
                    "protocol": "tcp" if conn.type == socket.SOCK_STREAM else "udp",
                    "family": "ipv6" if conn.family == socket.AF_INET6 else "ipv4",
                    "local_address": local.ip if local else None,
                    "local_port": local.port if local else None,
                    "remote_address": remote.ip if remote else None,
                    "remote_port": remote.port if remote else None,
                    "state": (conn.status or "").lower() or None,
                }
            )
        items.sort(key=lambda c: (c["protocol"], c["local_port"] or 0, c["remote_port"] or 0))
        limits = []
        if any(item["pid"] is None for item in items):
            limits.append(limitation("permission_denied", "some sockets have no visible owner"))
        return {"items": items, "total": len(items)}, limits

    def _sessions(self) -> tuple[dict[str, Any], list[dict[str, str]]]:
        items = [
            {
                "user": clip(user.name, 255),
                "terminal": clip(user.terminal, 64),
                "host": clip(user.host, 255),
                "started_at": iso(user.started) if user.started else None,
                "pid": getattr(user, "pid", None),
            }
            for user in psutil.users()
        ]
        return {"items": items, "total": len(items)}, []

    def _network_config(self) -> tuple[dict[str, Any], list[dict[str, str]]]:
        from sentra_agent.inventory import collect_interfaces, collect_network

        limits = []
        interfaces = collect_interfaces()
        try:
            summary = collect_network()
        except Exception as exc:  # una fuente rota no invalida las interfaces
            summary = None
            limits.append(limitation("collector_failed", f"gateways/dns: {type(exc).__name__}"))
        return {
            "items": interfaces,
            "total": len(interfaces),
            "gateways": (summary or {}).get("gateways", []),
            "dns_servers": (summary or {}).get("dns_servers", []),
            "hostname": socket.gethostname()[:255],
        }, limits

    def file_metadata(
        self, raw_path: str, want_hash: bool
    ) -> tuple[dict[str, Any], list[dict[str, str]]]:
        path = validate_path(raw_path, self.allowed_roots, self.platform, self.extra_denied)
        limits: list[dict[str, str]] = []
        # Un directorio intermedio que sea un enlace no puede sacar la consulta de las raíces.
        parent = os.path.dirname(path)
        try:
            validate_path(
                os.path.realpath(parent) if parent else path,
                self.allowed_roots,
                self.platform,
                self.extra_denied,
            )
        except PathRejectedError as exc:
            raise PathRejectedError("path_not_allowed", "path escapes the allowed roots") from exc
        content: dict[str, Any] = {"path": path, "exists": False}
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            return content, limits
        except PermissionError:
            return content, [limitation("permission_denied", "cannot stat the path")]
        content.update(_stat_fields(info))
        content["exists"] = True
        if stat.S_ISLNK(info.st_mode):
            try:
                content["link_target"] = clip(os.readlink(path), 1024)
            except OSError:
                content["link_target"] = None
            limits.append(limitation("symlink_not_followed", "symbolic links are not followed"))
            want_hash = False
        content["sha256"] = None
        if want_hash and stat.S_ISREG(info.st_mode):
            if info.st_size > self.hash_max_bytes:
                limits.append(limitation("hash_skipped_too_large", "file exceeds hash_max_mb"))
            else:
                try:
                    with open(path, "rb"):
                        pass
                except PermissionError:
                    limits.append(limitation("permission_denied", "file not readable for hash"))
                else:
                    content["sha256"] = file_sha256(path, self.hash_max_bytes)
        content["signature"] = None
        if self.platform == "win32" and stat.S_ISREG(info.st_mode):
            content["signature"] = self._signature(path, limits)
        elif stat.S_ISREG(info.st_mode):
            limits.append(limitation("not_supported", "code signature check is Windows-only"))
        return content, limits

    def _signature(self, path: str, limits: list[dict[str, str]]) -> dict[str, Any] | None:
        # La ruta viaja como variable de entorno, separada del script: en Windows PowerShell
        # 5.1 lo que sigue a -Command se concatena al texto del script (eso sería
        # interpolar) y con -File un argumento que empiece por "-" se tomaría por parámetro.
        env = {**os.environ, "SENTRA_FORENSIC_PATH": path}

        def run_with_env(argv: list[str], **kwargs: Any) -> CommandOutput:
            return self._run(argv, env=env, **kwargs)

        try:
            data = json.loads(run_powershell(_SIGNATURE_SCRIPT, run_with_env, timeout=60))
        except PermissionError:
            limits.append(limitation("permission_denied", "signature not readable"))
            return None
        except (CollectorUnavailableError, ValueError) as exc:
            limits.append(limitation("signature_unavailable", str(exc)))
            return None
        if not isinstance(data, dict):
            return None
        return {key: clip(data.get(key), 512) for key in ("status", "signer", "issuer",
                                                          "thumbprint", "not_after")}  # fmt: skip


def _stat_fields(info: os.stat_result) -> dict[str, Any]:
    mode = info.st_mode
    kind = (
        "symlink"
        if stat.S_ISLNK(mode)
        else "directory"
        if stat.S_ISDIR(mode)
        else "file"
        if stat.S_ISREG(mode)
        else "other"
    )
    fields: dict[str, Any] = {
        "type": kind,
        "size": info.st_size,
        "mode": oct(stat.S_IMODE(mode)),
        "modified_at": iso(info.st_mtime),
        "accessed_at": iso(info.st_atime),
    }
    birth = getattr(info, "st_birthtime", None)
    if sys.platform == "win32":
        fields["created_at"] = iso(birth if birth is not None else info.st_ctime)
    else:
        fields["created_at"] = iso(birth) if birth is not None else None
        fields["changed_at"] = iso(info.st_ctime)
        fields["uid"] = info.st_uid
        fields["gid"] = info.st_gid
    return fields
