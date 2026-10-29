"""Identidad de los servicios de Windows para el inventario (agente 0.6.2, Fase 7B-Fix1).

El servidor necesita saber, sin fiarse del nombre, si un servicio que aparece es una
instancia de servicio por usuario (WpnUserService_6df11) o una instalación nueva. Para eso
el inventario envía, además del nombre y el estado:

- `binpath`: la línea de comandos del servicio tal como la guarda el SCM;
- `username`: la cuenta con la que corre;
- `service_type`: el valor `Type` del registro del servicio. Las instancias por usuario
  llevan el bit SERVICE_USERSERVICE_INSTANCE (0x80); las plantillas, SERVICE_USER_SERVICE
  (0x40);
- `image`: la ruta del ejecutable sacada de `binpath`, con las variables de entorno y el
  prefijo \\SystemRoot\\ expandidos;
- `image_signature`: estado y firmante Authenticode de ese ejecutable.

Todo es lectura. La firma se comprueba con Get-AuthenticodeSignature (el mismo cmdlet que usa
un administrador, que también resuelve las firmas de catálogo de los binarios de Windows),
en una sola llamada por inventario, solo para ejecutables que no estén ya en la caché y con
un máximo por ciclo: el primer inventario tarda algo más, los siguientes no.
"""

import json
import logging
import os
import re
import sys
from collections.abc import Callable, Iterable
from typing import Any

from sentra_agent.endpoint import CollectorUnavailableError, run_powershell
from sentra_agent.syscmd import CommandOutput, run_bounded

logger = logging.getLogger("sentra_agent")

# Bits del valor Type de un servicio (winnt.h).
SERVICE_USER_SERVICE = 0x40
SERVICE_USERSERVICE_INSTANCE = 0x80

MAX_SIGNATURES_PER_CYCLE = 32
SIGNATURE_TIMEOUT = 90.0
_SIGNATURE_FIELDS = ("status", "signer")

# Los paths viajan como JSON en una variable de entorno, nunca dentro del texto del script.
_SIGNATURE_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    "$paths = $env:SENTRA_SIGNATURE_PATHS | ConvertFrom-Json; "
    "$out = foreach ($p in $paths) { "
    "try { $s = Get-AuthenticodeSignature -LiteralPath $p; "
    "[pscustomobject]@{ path = $p; status = [string]$s.Status; "
    "signer = $(if ($s.SignerCertificate) { $s.SignerCertificate.Subject } else { $null }) } } "
    "catch { [pscustomobject]@{ path = $p; status = 'Unreadable'; signer = $null } } }; "
    "@($out) | ConvertTo-Json -Compress"
)

_QUOTED = re.compile(r'^\s*"([^"]+)"')
_UNQUOTED = re.compile(r"^\s*(\S+?\.exe)\b", re.IGNORECASE)


def image_from_binpath(binpath: str | None, environ: dict[str, str] | None = None) -> str | None:
    """Ruta del ejecutable de la línea de comandos de un servicio.

    `"C:\\Program Files\\X\\x.exe" -arg` -> la ruta entre comillas; `C:\\Windows\\system32\\
    svchost.exe -k grupo` -> hasta `.exe`. Expande %VARIABLES% y el prefijo \\SystemRoot\\
    o system32\\ que usan los controladores y algunos servicios del sistema.
    """
    if not binpath:
        return None
    env = environ if environ is not None else dict(os.environ)
    match = _QUOTED.match(binpath) or _UNQUOTED.match(binpath)
    raw = match.group(1) if match else binpath.strip().split(" ")[0]
    root = env.get("SYSTEMROOT") or env.get("SystemRoot") or r"C:\Windows"

    def expand(found: re.Match[str]) -> str:
        name = found.group(1)
        for key, value in env.items():
            if key.lower() == name.lower():
                return value
        return found.group(0)

    path = re.sub(r"%([^%]+)%", expand, raw)
    lowered = path.lower()
    if lowered.startswith("\\systemroot\\"):
        path = root + path[len("\\systemroot") :]
    elif lowered.startswith("system32\\"):
        path = root + "\\" + path
    elif lowered.startswith("\\??\\"):
        path = path[4:]
    return path[:1024] or None


def read_service_type(name: str) -> int | None:
    """Valor Type del servicio en el registro, o None si no se puede leer."""
    if sys.platform != "win32":  # mypy: winreg solo existe en Windows
        return None
    import winreg

    key = rf"SYSTEM\CurrentControlSet\Services\{name}"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as handle:
            value, kind = winreg.QueryValueEx(handle, "Type")
    except OSError:
        return None
    return int(value) if kind == winreg.REG_DWORD and isinstance(value, int) else None


def _file_key(path: str) -> tuple[str, int, int] | None:
    try:
        info = os.stat(path)
    except OSError:
        return None
    return (path.lower(), info.st_size, int(info.st_mtime))


def parse_signatures(output: str) -> dict[str, dict[str, str | None]]:
    """Resultado de _SIGNATURE_SCRIPT por ruta (en minúsculas)."""
    data = json.loads(output.lstrip("\ufeff") or "[]")
    if isinstance(data, dict):  # ConvertTo-Json desenvuelve las listas de un elemento
        data = [data]
    found: dict[str, dict[str, str | None]] = {}
    for item in data if isinstance(data, list) else ():
        if not isinstance(item, dict) or not item.get("path"):
            continue
        found[str(item["path"]).lower()] = {
            key: (str(item[key])[:512] if item.get(key) is not None else None)
            for key in _SIGNATURE_FIELDS
        }
    return found


class SignatureCache:
    """Firma Authenticode por ejecutable, recordada mientras el fichero no cambie.

    La clave es (ruta, tamaño, fecha de modificación): si el ejecutable se sustituye, la
    firma se vuelve a comprobar en el siguiente inventario.
    """

    def __init__(
        self,
        run: Callable[..., CommandOutput] = run_bounded,
        per_cycle: int = MAX_SIGNATURES_PER_CYCLE,
    ) -> None:
        self._run = run
        self._per_cycle = per_cycle
        self._known: dict[tuple[str, int, int], dict[str, str | None]] = {}

    def lookup(self, paths: Iterable[str]) -> dict[str, dict[str, str | None]]:
        keys = {path.lower(): _file_key(path) for path in paths}
        pending = sorted(p for p, k in keys.items() if k is not None and k not in self._known)
        if pending:
            self._verify(pending[: self._per_cycle], keys)
        return {
            path: self._known[key]
            for path, key in keys.items()
            if key is not None and key in self._known
        }

    def _verify(self, paths: list[str], keys: dict[str, tuple[str, int, int] | None]) -> None:
        env = {**os.environ, "SENTRA_SIGNATURE_PATHS": json.dumps(paths)}

        def run_with_env(argv: list[str], **kwargs: Any) -> CommandOutput:
            return self._run(argv, env=env, **kwargs)

        try:
            found = parse_signatures(
                run_powershell(_SIGNATURE_SCRIPT, run_with_env, timeout=SIGNATURE_TIMEOUT)
            )
        except (CollectorUnavailableError, PermissionError, ValueError):
            # Sin firma el servidor no puede verificar la instancia, pero el resto del
            # inventario sigue valiendo: se envía sin `image_signature`.
            logger.warning("service signature check failed", exc_info=True)
            return
        for path in paths:
            key = keys.get(path)
            if key is not None and path in found:
                self._known[key] = found[path]


_SIGNATURES = SignatureCache()


def enrich_windows_services(
    services: list[dict[str, Any]],
    details: dict[str, dict[str, Any]],
    type_reader: Callable[[str], int | None] = read_service_type,
    signatures: SignatureCache | None = None,
) -> None:
    """Añade binpath, cuenta, tipo, ejecutable y firma a cada servicio (in situ).

    `details` es lo que psutil devolvió por nombre (binpath, username). Un dato que no se
    puede leer se omite: el servidor lo trata como "falta", nunca como "casa".
    """
    cache = signatures if signatures is not None else _SIGNATURES
    images: dict[str, str] = {}
    for service in services:
        info = details.get(service["name"], {})
        binpath = info.get("binpath")
        if binpath:
            service["binpath"] = str(binpath)[:1024]
            image = image_from_binpath(service["binpath"])
            if image:
                service["image"] = image
                images[service["name"]] = image
        if info.get("username"):
            service["username"] = str(info["username"])[:255]
        kind = type_reader(service["name"])
        if kind is not None:
            service["service_type"] = kind
    found = cache.lookup(set(images.values()))
    for service in services:
        image = images.get(service["name"])
        signature = found.get(image.lower()) if image else None
        if signature is not None:
            service["image_signature"] = dict(signature)
