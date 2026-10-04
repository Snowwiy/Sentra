from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    @field_validator("alert_critical_events")
    @classmethod
    def _check_critical_events(cls, value: str) -> str:
        # Fail at startup instead of silently ignoring a misspelled rule.
        parse_critical_events(value)
        return value

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
