from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    # Background jobs (offline detection). Disabled in tests, which drive jobs explicitly.
    background_jobs_enabled: bool = True
    offline_sweep_interval_seconds: int = Field(default=30, ge=5)

    @property
    def cors_origin_list(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
