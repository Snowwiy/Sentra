from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.discovery.ports import parse_ports
from app.discovery.targets import DiscoveryScope


def parse_name_list(value: str) -> list[str]:
    """Comma separated names, blanks dropped."""
    return [item.strip() for item in value.split(",") if item.strip()]


def parse_critical_events(value: str) -> list[tuple[str, int]]:
    """`Provider:EventID,...` into (provider, event id) pairs. Raises ValueError."""
    events = []
    for item in parse_name_list(value):
        provider, separator, code = item.rpartition(":")
        if not separator or not provider.strip() or not code.strip().isdigit():
            raise ValueError(f"expected Provider:EventID, got {item!r}")
        events.append((provider.strip(), int(code)))
    return events


class Settings(BaseSettings):
    """Application settings. Every value comes from environment variables or a `.env` file."""

    model_config = SettingsConfigDict(env_file=(".env", "../.env"), extra="ignore")

    app_name: str = "Sentra API"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"

    database_url: str = Field(description="SQLAlchemy URL, e.g. postgresql+psycopg://...")
    test_database_url: str | None = None

    # Largest accepted request body. Real inventories are well under 1 MB; the limit leaves
    # room for the inventory caps while stopping memory exhaustion by huge uploads.
    max_request_bytes: int = Field(default=4 * 1024 * 1024, ge=1024)

    # Comma separated list of origins allowed to call the API from a browser.
    cors_origins: str = ""

    # Shared secret agents must present to register. Unset means registration is disabled
    # (fail closed): an open registration endpoint would let anyone inject fake assets.
    agent_enrollment_key: SecretStr | None = Field(default=None, min_length=24)

    # One-time enrollment tokens (recommended over the shared key): lifetime when created
    # without an explicit one. See services/enrollment_token_service.py.
    enrollment_token_ttl_minutes: int = Field(default=15, ge=1, le=1440)

    # Key for the administration API (X-Admin-Key): creating, listing and revoking
    # enrollment tokens. Unset (the default) disables those endpoints; the CLI keeps working.
    # Desde la Fase 4G es un mecanismo LEGACY para automatización servidor a servidor: el
    # dashboard usa login y roles, y el navegador nunca recibe ni envía esta clave.
    admin_api_key: SecretStr | None = Field(default=None, min_length=24)

    # --- Fase 4G: login del dashboard, sesiones y RBAC (ver docs/authentication.md) ---
    # Caducidad absoluta de una sesión y caducidad por inactividad.
    session_ttl_hours: int = Field(default=12, ge=1, le=168)
    session_idle_minutes: int = Field(default=60, ge=5, le=1440)
    # Atributo Secure de la cookie de sesión. Sin valor: activo solo con
    # ENVIRONMENT=production. Con Secure el navegador solo la envía por HTTPS, así que en
    # producción la API tiene que servirse por HTTPS (reverse proxy); HTTP en la LAN es solo
    # para desarrollo y no protege las contraseñas ni la cookie frente a quien escuche la red.
    session_cookie_secure: bool | None = None
    # strict: el navegador no envía la cookie en peticiones iniciadas desde otro sitio
    # (primera barrera contra CSRF; la segunda es el token X-CSRF-Token).
    session_cookie_samesite: Literal["strict", "lax"] = "strict"
    # Login: fallos por usuario+dirección, intentos por dirección y fallos por usuario
    # (cualquier dirección) dentro de la ventana. Ver services/auth_service.py.
    login_rate_window_minutes: int = Field(default=15, ge=1, le=1440)
    login_max_failures_per_user_ip: int = Field(default=5, ge=1, le=1000)
    login_max_attempts_per_ip: int = Field(default=30, ge=1, le=10_000)
    login_max_failures_per_user: int = Field(default=50, ge=1, le=100_000)
    # POST /agents/register por dirección y minuto. No afecta a heartbeat/telemetría.
    agent_register_max_per_minute: int = Field(default=30, ge=1, le=10_000)
    # Nombres de host aceptados en la cabecera Host (TrustedHostMiddleware), separados por
    # coma, p. ej. "sentra.lan,192.168.50.201,localhost". Vacío: sin comprobación (LAN de
    # desarrollo). Recomendado en producción contra DNS rebinding y cabeceras Host falsas.
    allowed_hosts: str = ""

    # URL agents use to reach this server, shown in the dashboard's install command
    # (e.g. http://192.168.50.201:8000). Unset: suggested from this machine's addresses.
    agent_server_url: str | None = Field(
        default=None, pattern=r"^https?://[A-Za-z0-9.\-\[\]:]+(/[A-Za-z0-9._~/-]*)?$"
    )

    # An asset is reported offline when it has not been seen for this many seconds.
    heartbeat_timeout_seconds: int = Field(default=90, gt=0)

    # Alert rules. CPU and RAM must stay above the threshold for `alert_sustained_samples`
    # consecutive samples so short spikes do not page anyone; disk alerts on a single sample
    # because disk usage does not spike and fills steadily.
    alert_cpu_percent: float = Field(default=90, gt=0, le=100)
    alert_ram_percent: float = Field(default=90, gt=0, le=100)
    alert_disk_percent: float = Field(default=90, gt=0, le=100)
    alert_sustained_samples: int = Field(default=3, ge=1, le=100)

    # Services whose stop is worth an alert (comma separated service names, case
    # insensitive; empty disables the rule). Defaults: Event Log, Defender, Windows Firewall,
    # the services an attacker stops first. Evaluated on every inventory snapshot.
    alert_watched_services: str = "EventLog,WinDefend,mpssvc"
    # Host events that open an alert by themselves, as Provider:EventID (comma separated).
    # Defaults: unexpected reboot (Kernel-Power 41), unexpected shutdown (6008), Security
    # and System log cleared (1102, 104).
    alert_critical_events: str = (
        "Microsoft-Windows-Kernel-Power:41,EventLog:6008,"
        "Microsoft-Windows-Eventlog:1102,Microsoft-Windows-Eventlog:104"
    )
    # Burst of error/critical host events: at least COUNT within MINUTES on one asset.
    alert_event_burst_count: int = Field(default=10, ge=2, le=10_000)
    alert_event_burst_minutes: int = Field(default=10, ge=1, le=1440)
    # Event-based alerts (critical event, burst, admin change) have no condition that
    # clears: they resolve once nothing new fired for this long.
    alert_event_quiet_minutes: int = Field(default=60, ge=1, le=10_080)

    # Background jobs (offline detection). Disabled in tests, which drive jobs explicitly.
    background_jobs_enabled: bool = True
    offline_sweep_interval_seconds: int = Field(default=30, ge=5)

    # Data retention in days. Unset (the default) keeps everything: deleting monitoring
    # history is the operator's decision. See services/retention_service.py.
    telemetry_retention_days: int | None = Field(default=None, ge=1)
    event_retention_days: int | None = Field(default=None, ge=1)
    # Inventory change history, and resolved alerts (active alerts are never deleted).
    change_retention_days: int | None = Field(default=None, ge=1)
    alert_retention_days: int | None = Field(default=None, ge=1)
    retention_sweep_interval_seconds: int = Field(default=3600, ge=60)

    # --- Agentless network discovery (app/discovery). Off unless networks are listed. ---
    # Comma separated CIDRs/addresses Sentra may probe, e.g. "192.168.1.0/24,10.0.10.0/24".
    # Empty (the default) disables discovery entirely. Public Internet space is refused
    # unless DISCOVERY_ALLOW_PUBLIC_NETWORKS=true; 0.0.0.0/0 is always refused.
    discovery_allowed_networks: str = ""
    # Addresses/networks never probed, even inside an allowed network.
    discovery_excluded: str = ""
    discovery_allow_public_networks: bool = False
    # Largest network accepted (addresses), so a /8 typo is refused, not scanned.
    discovery_max_hosts_per_network: int = Field(default=1024, ge=1, le=65_536)
    # Port profiles (minimal, common, windows, printers, web) and/or ports and ranges.
    discovery_ports: str = "common"
    discovery_timeout_ms: int = Field(default=800, ge=50, le=10_000)
    # Probes in flight at once, and started per second, for the whole server.
    discovery_concurrency: int = Field(default=64, ge=1, le=256)
    discovery_max_probes_per_second: int = Field(default=200, ge=1, le=5000)
    discovery_icmp: bool = True
    discovery_reverse_dns: bool = True
    # Sondas de nombre de hosts vivos: mDNS, NetBIOS y SSDP/UPnP (app/discovery/names.py).
    discovery_identify: bool = True
    # Ficheros OUI del IEEE (oui.csv, mam.csv, oui36.csv) separados por coma, para resolver
    # el fabricante de la NIC sin consultar Internet. Vacío: fabricante desconocido.
    discovery_oui_file: str = ""
    # Periodic runs over every allowed network; unset = manual only (CLI `discover`).
    discovery_interval_minutes: int | None = Field(default=None, ge=5, le=10_080)
    # A run is stopped (results kept as partial) after this long.
    discovery_job_timeout_minutes: int = Field(default=30, ge=1, le=1440)
    # Complete runs without seeing a host before it is reported offline/disappeared.
    discovery_offline_after_misses: int = Field(default=3, ge=1, le=100)

    @field_validator("agent_server_url", mode="before")
    @classmethod
    def _blank_server_url(cls, value: object) -> object:
        # `AGENT_SERVER_URL=` in .env means "not set", not an invalid URL.
        if isinstance(value, str):
            value = value.strip().rstrip("/")
            return value or None
        return value

    @field_validator("cors_origins")
    @classmethod
    def _check_cors_origins(cls, value: str) -> str:
        # Las peticiones del dashboard llevan la cookie de sesión (credenciales): un comodín
        # permitiría a cualquier web leer datos con la sesión del operador. Se exige la lista
        # explícita de orígenes.
        if "*" in value:
            raise ValueError("CORS_ORIGINS must list explicit origins; '*' is not allowed")
        return value

    @field_validator("alert_critical_events")
    @classmethod
    def _check_critical_events(cls, value: str) -> str:
        # Fail at startup instead of silently ignoring a misspelled rule.
        parse_critical_events(value)
        return value

    @model_validator(mode="after")
    def _check_discovery(self) -> "Settings":
        # Same rule as for alert lists: a bad allowlist stops the API at startup, it is
        # never silently ignored or "fixed" into something that might scan more.
        self.discovery_scope()
        parse_ports(self.discovery_ports)
        return self

    def discovery_scope(self) -> DiscoveryScope:
        return DiscoveryScope.parse(
            self.discovery_allowed_networks,
            self.discovery_excluded,
            self.discovery_max_hosts_per_network,
            self.discovery_allow_public_networks,
        )

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def allowed_host_list(self) -> list[str]:
        return parse_name_list(self.allowed_hosts)

    @property
    def cookie_secure(self) -> bool:
        if self.session_cookie_secure is None:
            return self.is_production
        return self.session_cookie_secure

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
