"""Configuración de Threat Intelligence derivada de Settings (sin secretos)."""

from dataclasses import dataclass, field
from typing import Literal

from app.core.config import Settings, parse_lan_networks, parse_source_urls
from app.threat_intel.http import FetchPolicy, Network

MIB = 1024 * 1024
DetectionPolicy = Literal["off", "high_confidence_malicious", "malicious"]


@dataclass(frozen=True)
class ThreatIntelConfig:
    enabled: bool = True
    sync_enabled: bool = False
    default_interval_hours: int = 24
    timeout_seconds: int = 120
    max_bytes: int = 128 * MIB
    max_records: int = 1_000_000
    batch_size: int = 5000
    allowed_networks: tuple[Network, ...] = ()
    source_urls: dict[str, str] = field(default_factory=dict)
    detection_policy: DetectionPolicy = "high_confidence_malicious"
    production: bool = False

    @classmethod
    def from_settings(cls, settings: Settings) -> "ThreatIntelConfig":
        return cls(
            enabled=settings.threat_intel_enabled,
            sync_enabled=settings.threat_intel_sync_enabled,
            default_interval_hours=settings.threat_intel_default_interval_hours,
            timeout_seconds=settings.threat_intel_http_timeout_seconds,
            max_bytes=settings.threat_intel_max_download_mb * MIB,
            max_records=settings.threat_intel_max_records,
            batch_size=settings.threat_intel_batch_size,
            allowed_networks=parse_lan_networks(
                settings.threat_intel_allowed_networks, "THREAT_INTEL_ALLOWED_NETWORKS"
            ),
            source_urls=parse_source_urls(settings.threat_intel_source_urls),
            detection_policy=settings.threat_intel_detection_policy,
            production=settings.is_production,
        )

    def fetch_policy(self) -> FetchPolicy:
        return FetchPolicy(
            connect_timeout=min(10.0, float(self.timeout_seconds)),
            read_timeout=min(30.0, float(self.timeout_seconds)),
            total_timeout=float(self.timeout_seconds),
            max_bytes=self.max_bytes,
            allowed_networks=self.allowed_networks,
            # http en claro solo hacia un espejo de la LAN autorizado y nunca en producción.
            allow_http=not self.production,
        )
