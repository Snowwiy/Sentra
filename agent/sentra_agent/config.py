"""Agent configuration: defaults < TOML file < environment variables < CLI flags."""

import os
import re
import sys
import tomllib
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

INSTALLATION_METHOD = re.compile(r"[a-z][a-z0-9_]{0,31}")


def default_state_dir() -> Path:
    # Per-user locations so the agent runs without administrator rights (manual runs).
    # El servicio Windows no usa este valor: su agent.toml (generado por el instalador) fija
    # state_dir en %ProgramData%\Sentra\Agent\state (ver sentra_agent/winsetup.py).
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "Sentra" / "Agent"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "sentra-agent"


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
        return self


_ENV_PREFIX = "SENTRA_AGENT_"


def _coerce(name: str, value: Any) -> Any:
    target = {f.name: f.type for f in fields(AgentConfig)}[name]
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


def load_config(
    config_file: Path | None = None, overrides: dict[str, Any] | None = None
) -> AgentConfig:
    """Build the effective configuration. Unknown keys are rejected to catch typos early."""
    known = {f.name for f in fields(AgentConfig)}
    values: dict[str, Any] = {}

    if config_file is not None:
        data = tomllib.loads(config_file.read_text(encoding="utf-8"))
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"Unknown config keys in {config_file}: {sorted(unknown)}")
        values.update(data)

    for name in known:
        env_value = os.environ.get(_ENV_PREFIX + name.upper())
        if env_value is not None:
            values[name] = env_value

    values.update({k: v for k, v in (overrides or {}).items() if v is not None})
    config = replace(AgentConfig(), **{k: _coerce(k, v) for k, v in values.items()})
    return config.validate()
