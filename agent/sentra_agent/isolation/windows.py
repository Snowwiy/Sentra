"""Aislamiento con el Firewall de Windows Defender (solo lo ejecuta el helper privilegiado).

Reglas de BLOQUEO en el grupo propio "Sentra Isolation", entrada y salida, por familia, hacia
el complemento de lo permitido (en Windows un bloqueo prevalece sobre un permiso). No se
deshabilita el firewall, no se cambian perfiles ni se tocan reglas ajenas: revertir es borrar
el grupo. Una tarea programada de respaldo (SYSTEM, a la hora de expiración) borra el grupo
aunque el helper estuviera parado.

Los scripts de PowerShell se generan solo con valores validados: direcciones producidas por
`ipaddress` (y comprobadas con una expresión regular estricta), nombres fijos, el UUID de la
sesión y una fecha formateada aquí. Nunca se interpola texto libre de una petición.

VALIDACIÓN EN WINDOWS REAL: New-NetFirewallRule, la lectura de vuelta de las reglas y la
tarea de respaldo solo pueden comprobarse en un Windows físico como administrador.
"""

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sentra_agent.endpoint import CollectorUnavailableError, run_powershell
from sentra_agent.isolation import GROUP, METHOD_WINDOWS, IsolationError
from sentra_agent.isolation.addresses import (
    Network,
    complement_ranges,
    format_range,
    normalize_tokens,
)
from sentra_agent.syscmd import CommandOutput, run_bounded

# Solo dígitos hexadecimales, puntos, dos puntos y un guion de rango.
_ADDRESS = re.compile(r"[0-9a-fA-F.:]{2,45}(-[0-9a-fA-F.:]{2,45})?")
BACKUP_TASK_PATH = "\\Sentra\\"
BACKUP_TASK_NAME = "SentraIsolationExpiry"


@dataclass(frozen=True)
class Rule:
    name: str
    direction: str  # inbound | outbound
    action: str  # block
    remote: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "direction": self.direction,
            "action": self.action,
            "remote": ",".join(self.remote),
        }


def build_rules(allowed: list[Network]) -> list[Rule]:
    rules = []
    for version in (4, 6):
        remote = tuple(
            format_range(start, end, version) for start, end in complement_ranges(allowed, version)
        )
        if not remote:
            continue
        for direction in ("outbound", "inbound"):
            name = f"{GROUP} - block {direction} IPv{version}"
            rules.append(Rule(name, direction, "block", remote))
    return rules


def _quoted_addresses(remote: tuple[str, ...]) -> str:
    for token in remote:
        if not _ADDRESS.fullmatch(token):
            # Defensa en profundidad: build_rules solo produce direcciones de ipaddress.
            raise IsolationError("invalid_rule", f"unexpected address token {token!r}")
    return "@(" + ",".join(f"'{token}'" for token in remote) + ")"


def apply_script(rules: list[Rule], session_id: UUID) -> str:
    session = str(UUID(str(session_id)))
    lines = [
        "$ErrorActionPreference = 'Stop'",
        f"Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue",
    ]
    for rule in rules:
        direction = "Outbound" if rule.direction == "outbound" else "Inbound"
        lines.append(
            f"New-NetFirewallRule -Group '{GROUP}' -DisplayName '{rule.name}'"
            f" -Description 'Sentra isolation session {session}'"
            f" -Direction {direction} -Action Block -Profile Any -Enabled True"
            f" -RemoteAddress {_quoted_addresses(rule.remote)} | Out-Null"
        )
    return "; ".join(lines)


VERIFY_SCRIPT = (
    f"@(Get-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue | ForEach-Object {{ "
    "[pscustomobject]@{ name = [string]$_.DisplayName; direction = [string]$_.Direction; "
    "action = [string]$_.Action; enabled = [string]$_.Enabled; "
    "remote = @(($_ | Get-NetFirewallAddressFilter).RemoteAddress) } }) "
    "| ConvertTo-Json -Depth 4 -Compress"
)
REVERT_SCRIPT = (
    "$ErrorActionPreference = 'Stop'; "
    f"Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue; "
    f"Unregister-ScheduledTask -TaskPath '{BACKUP_TASK_PATH}' -TaskName '{BACKUP_TASK_NAME}'"
    " -Confirm:$false -ErrorAction SilentlyContinue"
)
# Perfiles activos (los de las redes conectadas) y estado de cada perfil.
PROFILES_SCRIPT = (
    "$active = @(Get-NetConnectionProfile -ErrorAction SilentlyContinue | ForEach-Object { "
    "[string]$_.NetworkCategory }); "
    "$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore | ForEach-Object { "
    "[pscustomobject]@{ name = [string]$_.Name; enabled = [string]$_.Enabled } }); "
    "[pscustomobject]@{ active = $active; profiles = $profiles } "
    "| ConvertTo-Json -Depth 4 -Compress"
)


def backup_task_script(expires_at: datetime) -> str:
    """Tarea de respaldo como SYSTEM que solo borra las reglas del grupo a la expiración."""
    stamp = expires_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", stamp):
        raise IsolationError("invalid_request", "bad expiry timestamp")
    command = f"Remove-NetFirewallRule -Group '{GROUP}' -ErrorAction SilentlyContinue"
    return (
        "$ErrorActionPreference = 'Stop'; "
        "$at = [DateTime]::ParseExact("
        f"'{stamp}', 'yyyy-MM-ddTHH:mm:ssZ', [Globalization.CultureInfo]::InvariantCulture, "
        "[Globalization.DateTimeStyles]::AdjustToUniversal).ToLocalTime(); "
        "$ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'; "
        "$action = New-ScheduledTaskAction -Execute $ps "
        f'-Argument "-NoProfile -NonInteractive -Command {command}"; '
        "$trigger = New-ScheduledTaskTrigger -Once -At $at; "
        "$principal = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount"
        " -RunLevel Highest; "
        f"Register-ScheduledTask -TaskPath '{BACKUP_TASK_PATH}' -TaskName '{BACKUP_TASK_NAME}'"
        " -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null"
    )


def parse_rules(text: str) -> list[dict[str, Any]]:
    if not text.strip():
        return []
    data = json.loads(text)
    items = data if isinstance(data, list) else [data]
    return [item for item in items if isinstance(item, dict)]


def rules_match(found: list[dict[str, Any]], expected: list[Rule]) -> bool:
    """Las reglas leídas de vuelta son exactamente las esperadas (nombre, sentido, rangos)."""
    if len(found) != len(expected):
        return False
    by_name = {str(item.get("name")): item for item in found}
    for rule in expected:
        item = by_name.get(rule.name)
        if item is None:
            return False
        if str(item.get("direction", "")).lower() != rule.direction:
            return False
        if str(item.get("action", "")).lower() != "block":
            return False
        if str(item.get("enabled", "")).lower() not in ("true", "1"):
            return False
        remote = item.get("remote")
        tokens = [str(t) for t in remote] if isinstance(remote, list) else [str(remote)]
        try:
            if normalize_tokens(tokens) != normalize_tokens(rule.remote):
                return False
        except ValueError:
            return False
    return True


def parse_profiles(text: str) -> tuple[list[str], dict[str, bool]]:
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("unexpected profile output")
    raw_active = data.get("active") or []
    active = [str(a) for a in (raw_active if isinstance(raw_active, list) else [raw_active])]
    raw_profiles = data.get("profiles") or []
    profiles: dict[str, bool] = {}
    for item in raw_profiles if isinstance(raw_profiles, list) else [raw_profiles]:
        if isinstance(item, dict) and item.get("name"):
            profiles[str(item["name"]).lower()] = str(item.get("enabled")).lower() == "true"
    return active, profiles


def active_profiles_enabled(active: list[str], profiles: dict[str, bool]) -> bool:
    """¿Están activados los perfiles de las redes conectadas? Sin datos: todos activados."""
    names = {"domainauthenticated": "domain", "private": "private", "public": "public"}
    wanted = {names.get(category.lower(), category.lower()) for category in active}
    wanted &= set(profiles)
    if not wanted:
        wanted = set(profiles)
    return bool(wanted) and all(profiles[name] for name in wanted)


class WindowsFirewallBackend:
    method = METHOD_WINDOWS

    def __init__(self, run: Callable[..., CommandOutput] = run_bounded) -> None:
        self._run = run
        self._expected: list[Rule] = []

    def _ps(self, script: str) -> str:
        try:
            return run_powershell(script, self._run, timeout=120)
        except PermissionError as exc:
            raise IsolationError("permission_denied", str(exc)) from exc
        except CollectorUnavailableError as exc:
            raise IsolationError("firewall_command_failed", str(exc)) from exc

    def precheck(self) -> None:
        try:
            active, profiles = parse_profiles(self._ps(PROFILES_SCRIPT))
        except ValueError as exc:
            raise IsolationError("firewall_state_unknown", str(exc)) from exc
        if not active_profiles_enabled(active, profiles):
            # Con el perfil desactivado las reglas no harían nada: mejor fallar que mentir.
            raise IsolationError("firewall_disabled", "an active firewall profile is disabled")

    def apply(
        self, allowed: list[Network], session_id: UUID, expires_at: datetime
    ) -> list[dict[str, Any]]:
        rules = build_rules(allowed)
        self._expected = rules
        self._ps(apply_script(rules, session_id))
        try:
            self._ps(backup_task_script(expires_at))
        except IsolationError as exc:
            # Sin tarea de respaldo el aislamiento no se aplica: la reversión local que no
            # depende del helper es parte de la garantía.
            self.revert()
            raise IsolationError("backup_task_failed", str(exc)) from exc
        return [rule.as_dict() for rule in rules]

    def verify(self, allowed: list[Network]) -> bool:
        expected = build_rules(allowed)
        try:
            return rules_match(parse_rules(self._ps(VERIFY_SCRIPT)), expected)
        except (IsolationError, ValueError):
            return False

    def present(self) -> bool:
        try:
            return bool(parse_rules(self._ps(VERIFY_SCRIPT)))
        except (IsolationError, ValueError):
            return False

    def revert(self) -> None:
        self._ps(REVERT_SCRIPT)
