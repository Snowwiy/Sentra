"""Agent configuration: defaults < TOML file < environment variables < CLI flags."""

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sentra_agent.credentials import resolve_store

INSTALLATION_METHOD = re.compile(r"[a-z][a-z0-9_]{0,31}")
# Fase 6E: política de línea de comandos de la telemetría (gana la más restrictiva entre
# agente y servidor; el agente nunca envía más de lo que dice aquí).
CMDLINE_POLICIES = ("off", "redacted", "full")


def default_state_dir() -> Path:
    # Per-user locations so the agent runs without administrator rights (manual runs).
    # El servicio Windows no usa este valor: su agent.toml (generado por el instalador) fija
    # state_dir en %ProgramData%\Sentra\Agent\state (ver sentra_agent/winsetup.py).
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Sentra" / "Agent"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "sentra-agent"


def default_isolation_exchange_dir(platform: str | None = None) -> Path | None:
    """Directorio de intercambio con el helper de aislamiento (contrato 6E).

    macOS no tiene helper en 6E: sin directorio, el agente nunca anuncia aislamiento.
    """
    platform = platform or sys.platform
    if platform == "win32":
        base = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return Path(base) / "Sentra" / "Agent" / "isolation"
    if platform.startswith("linux"):
        return Path("/var/lib/sentra-agent/isolation")
    return None


def default_isolation_policy(platform: str | None = None) -> Path | None:
    """Política local del helper; el agente solo la lee para validar duraciones."""
    platform = platform or sys.platform
    if platform == "win32":
        base = os.environ.get("PROGRAMDATA") or r"C:\ProgramData"
        return Path(base) / "Sentra" / "Isolation" / "isolation.toml"
    if platform.startswith("linux"):
        return Path("/etc/sentra-agent/isolation.toml")
    return None


@dataclass(frozen=True)
class TelemetrySettings:
    """Sección [telemetry] (Fase 6E.3): actividad de procesos, red, servicios y estado."""

    enabled: bool = True
    # Sondeo de procesos: un proceso que vive menos que esto puede no verse (latencia
    # honesta, documentada en docs/endpoint-telemetry-agent.md).
    process_poll_seconds: int = 5
    network_enabled: bool = True
    cmdline: str = "redacted"
    # Desactivado por defecto: leer ejecutables cuesta disco y CPU. Con tope y caché.
    hash_executables: bool = False
    hash_max_mb: int = 50
    activity_queue_max_events: int = 20_000
    # Servicios y tareas cambian poco: sondeo mucho más espaciado que el de procesos.
    services_poll_seconds: int = 120
    persistence_poll_seconds: int = 300
    # Protección (antivirus) y firewall: lanzar PowerShell cuesta; una vez cada 5 min basta.
    state_poll_seconds: int = 300
    sysmon_enabled: bool = True
    sysmon_poll_seconds: int = 10
    health_seconds: int = 300

    def validate(self) -> None:
        _bounded("telemetry.process_poll_seconds", self.process_poll_seconds, 2, 300)
        if self.cmdline not in CMDLINE_POLICIES:
            raise ValueError("telemetry.cmdline must be one of off, redacted, full")
        _bounded("telemetry.hash_max_mb", self.hash_max_mb, 1, 1024)
        _bounded(
            "telemetry.activity_queue_max_events", self.activity_queue_max_events, 100, 200_000
        )
        _bounded("telemetry.services_poll_seconds", self.services_poll_seconds, 30, 3600)
        _bounded("telemetry.persistence_poll_seconds", self.persistence_poll_seconds, 60, 3600)
        _bounded("telemetry.state_poll_seconds", self.state_poll_seconds, 60, 3600)
        _bounded("telemetry.sysmon_poll_seconds", self.sysmon_poll_seconds, 2, 300)
        _bounded("telemetry.health_seconds", self.health_seconds, 60, 3600)


@dataclass(frozen=True)
class ForensicsSettings:
    """Sección [forensics] (Fase 6E.6): límites locales de las acciones forenses."""

    # None = raíces por defecto de la plataforma (programas y sistema, nunca perfiles de
    # usuario). Es la última palabra: el servidor no puede ampliarlas.
    allowed_roots: tuple[str, ...] | None = None
    max_artifact_kb: int = 2048
    hash_max_mb: int = 100

    def validate(self) -> None:
        _bounded("forensics.max_artifact_kb", self.max_artifact_kb, 64, 16_384)
        _bounded("forensics.hash_max_mb", self.hash_max_mb, 1, 4096)
        for root in self.allowed_roots or ():
            if not isinstance(root, str) or not root or "\x00" in root:
                raise ValueError("forensics.allowed_roots must be non-empty paths")


@dataclass(frozen=True)
class IsolationSettings:
    """Sección [isolation] del agente (Fase 6E.7): solo cómo hablar con el helper local.

    La política de verdad (enabled, max_minutes, extra_allow) es del helper y vive en su
    propio isolation.toml, fuera del alcance del agente.
    """

    exchange_dir: Path | None = field(default_factory=default_isolation_exchange_dir)
    policy_file: Path | None = field(default_factory=default_isolation_policy)
    # Espera máxima del resultado del helper dentro de un comando.
    wait_seconds: int = 60
    # status.json más antiguo que esto = helper parado (no se anuncia la capacidad).
    status_max_age_seconds: int = 180

    def validate(self) -> None:
        _bounded("isolation.wait_seconds", self.wait_seconds, 5, 300)
        _bounded("isolation.status_max_age_seconds", self.status_max_age_seconds, 30, 3600)


def _bounded(name: str, value: int, low: int, high: int) -> None:
    if not low <= value <= high:
        raise ValueError(f"{name} must be between {low} and {high}")


SECTIONS: dict[str, type[Any]] = {
    "telemetry": TelemetrySettings,
    "forensics": ForensicsSettings,
    "isolation": IsolationSettings,
}


@dataclass(frozen=True)
class AgentConfig:
    api_url: str = "http://127.0.0.1:8000"
    interval_seconds: int = 30
    # Inventory changes slowly and is the largest payload; send it far less often.
    inventory_interval_seconds: int = 900
    events_interval_seconds: int = 60
    # Process list: changes constantly, so sent far more often than the inventory; only the
    # latest snapshot is kept by the server.
    processes_interval_seconds: int = 60
    request_timeout_seconds: float = 10.0
    max_backoff_seconds: int = 300
    # Samples kept in memory while the API is unreachable, sent once it is back.
    buffer_size: int = 120
    state_dir: Path = field(default_factory=default_state_dir)
    log_level: str = "INFO"
    # Directory of the rotating log file (default: <state_dir>/logs). The Linux package uses
    # /var/log/sentra-agent; under systemd the console output also goes to the journal.
    log_dir: Path | None = None
    # Needed only to enroll (first start, or after the server revoked our token). Prefer the
    # SENTRA_AGENT_ENROLLMENT_KEY environment variable over writing it into a config file.
    enrollment_key: str | None = field(default=None, repr=False)
    # Recommended instead of the shared key: a one-time enrollment token created by an
    # operator (`python -m app.cli create-enrollment-token` on the server). Pass it in
    # SENTRA_AGENT_ENROLLMENT_TOKEN or, better, in a file (enrollment_token_file) that the
    # agent deletes once enrolled. It is used for enrollment only, never for other calls.
    enrollment_token: str | None = field(default=None, repr=False)
    enrollment_token_file: Path | None = None
    # Cómo se instaló este agente (p. ej. "windows_service"), lo escribe el instalador en
    # agent.toml y viaja con el registro y cada heartbeat para que el dashboard lo muestre.
    # Sin valor (ejecución manual o instalaciones anteriores) no se envía nada: los
    # servidores antiguos no conocen el campo.
    installation_method: str | None = None
    # Fase 6C.5: dónde se guarda el token propio del agente. "auto" = DPAPI en Windows,
    # Keychain en macOS (el daemon usa el keychain del sistema) y fichero 0600 en Linux.
    # En macOS "file" es una elección explícita del administrador (fichero 0600 en un
    # directorio 0700 del usuario del agente) para equipos sin Keychain utilizable; si el
    # Keychain falla con "auto"/"keychain" el agente se detiene, nunca pasa a fichero solo.
    credential_store: str = "auto"
    # Fase 6C.5: estado Wi-Fi pasivo dentro del inventario (sin escaneo ni credenciales).
    # Se puede desactivar; con intervalo 0 se lee en cada inventario y con otro valor como
    # mucho una vez por ese intervalo (viaja en el inventario: nunca más a menudo que él).
    wireless_enabled: bool = True
    wireless_interval_seconds: int = 0
    # Fase 6E: secciones [telemetry], [forensics] e [isolation] de agent.toml.
    telemetry: TelemetrySettings = field(default_factory=TelemetrySettings)
    forensics: ForensicsSettings = field(default_factory=ForensicsSettings)
    isolation: IsolationSettings = field(default_factory=IsolationSettings)

    def validate(self) -> "AgentConfig":
        parsed = urlparse(self.api_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(f"api_url must be an http(s) URL, got {self.api_url!r}")
        if not 5 <= self.interval_seconds <= 3600:
            raise ValueError("interval_seconds must be between 5 and 3600")
        if not 60 <= self.inventory_interval_seconds <= 86400:
            raise ValueError("inventory_interval_seconds must be between 60 and 86400")
        if not 10 <= self.events_interval_seconds <= 3600:
            raise ValueError("events_interval_seconds must be between 10 and 3600")
        if not 15 <= self.processes_interval_seconds <= 3600:
            raise ValueError("processes_interval_seconds must be between 15 and 3600")
        if self.request_timeout_seconds <= 0:
            raise ValueError("request_timeout_seconds must be positive")
        if self.max_backoff_seconds < self.interval_seconds:
            raise ValueError("max_backoff_seconds must be >= interval_seconds")
        # At least one slot: the current sample always goes through the buffer.
        if not 1 <= self.buffer_size <= 10_000:
            raise ValueError("buffer_size must be between 1 and 10000")
        # Mismo patrón que valida el servidor (schemas/agent.py): un valor fuera de él haría
        # que cada registro y heartbeat fuese rechazado con 422.
        if self.installation_method is not None and not INSTALLATION_METHOD.fullmatch(
            self.installation_method
        ):
            raise ValueError("installation_method must match [a-z][a-z0-9_]{0,31}")
        # Mismas reglas que credentials.resolve_store (keychain solo en macOS, Windows
        # siempre DPAPI): un valor que no aplica aquí es un error de configuración.
        resolve_store(self.credential_store)
        if self.wireless_interval_seconds != 0 and not (
            60 <= self.wireless_interval_seconds <= 86400
        ):
            raise ValueError("wireless_interval_seconds must be 0 or between 60 and 86400")
        self.telemetry.validate()
        self.forensics.validate()
        self.isolation.validate()
        return self


_ENV_PREFIX = "SENTRA_AGENT_"


def _coerce(name: str, value: Any) -> Any:
    target = {f.name: f.type for f in fields(AgentConfig)}[name]
    if target in (bool, "bool"):
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ("1", "true", "yes", "on"):
            return True
        if text in ("0", "false", "no", "off"):
            return False
        raise ValueError(f"{name} must be true or false, got {value!r}")
    if target in (int, "int"):
        return int(value)
    if target in (float, "float"):
        return float(value)
    if name in ("enrollment_key", "enrollment_token", "installation_method"):
        return str(value).strip() or None
    if name in ("enrollment_token_file", "log_dir"):
        return Path(value).expanduser() if str(value) else None
    if target in (Path, "Path"):
        return Path(value).expanduser()
    return str(value)


def _coerce_section(section: str, name: str, value: Any) -> Any:
    """Convierte un valor de una sección (TOML o variable de entorno) a su tipo."""
    cls = SECTIONS[section]
    target = {f.name: f.type for f in fields(cls)}[name]
    if name == "allowed_roots":
        if isinstance(value, str):
            # Variable de entorno: rutas separadas por el separador del sistema (; o :).
            value = [part for part in value.split(os.pathsep) if part]
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ValueError(f"{section}.{name} must be a list of paths")
        return tuple(value)
    if name in ("exchange_dir", "policy_file"):
        return Path(value).expanduser() if str(value) else None
    if target is bool:
        return _coerce_bool(f"{section}.{name}", value)
    if target is int:
        if isinstance(value, bool):
            raise ValueError(f"{section}.{name} must be an integer")
        return int(value)
    return str(value)


def _coerce_bool(name: str, value: Any) -> bool:
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in ("1", "true", "yes", "on"):
        return True
    if text in ("0", "false", "no", "off"):
        return False
    raise ValueError(f"{name} must be true or false, got {value!r}")


def _load_section(section: str, data: Any, source: str) -> Any:
    cls = SECTIONS[section]
    if not isinstance(data, dict):
        raise ValueError(f"[{section}] in {source} must be a table")
    known = {f.name for f in fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ValueError(f"Unknown keys in [{section}] of {source}: {sorted(unknown)}")
    values = {k: _coerce_section(section, k, v) for k, v in data.items()}
    for name in known:
        env_value = os.environ.get(f"{_ENV_PREFIX}{section.upper()}_{name.upper()}")
        if env_value is not None:
            values[name] = _coerce_section(section, name, env_value)
    return cls(**values)


def load_config(
    config_file: Path | None = None, overrides: dict[str, Any] | None = None
) -> AgentConfig:
    """Build the effective configuration. Unknown keys are rejected to catch typos early."""
    known = {f.name for f in fields(AgentConfig)} - set(SECTIONS)
    values: dict[str, Any] = {}
    sections: dict[str, Any] = {}

    if config_file is not None:
        data = tomllib.loads(config_file.read_text(encoding="utf-8"))
        for section in SECTIONS:
            if section in data:
                sections[section] = data.pop(section)
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config keys in {config_file}: {sorted(unknown)}")
        values.update(data)

    for name in known:
        env_value = os.environ.get(_ENV_PREFIX + name.upper())
        if env_value is not None:
            values[name] = env_value

    values.update({k: v for k, v in (overrides or {}).items() if v is not None})
    coerced = {k: _coerce(k, v) for k, v in values.items()}
    for section in SECTIONS:
        # Siempre se construye: las variables SENTRA_AGENT_<SECCION>_<CLAVE> valen sin TOML.
        coerced[section] = _load_section(section, sections.get(section, {}), str(config_file))
    config = replace(AgentConfig(), **coerced)
    return config.validate()
