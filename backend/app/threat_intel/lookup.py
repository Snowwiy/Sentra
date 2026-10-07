"""Lecturas de inteligencia de explotabilidad por CVE (KEV, EPSS) para los consumidores.

Un solo sitio decide qué inteligencia "cuenta": registros activos de fuentes activadas y no
archivadas. La prioridad 5B, el riesgo 4I, la IA y la API leen de aquí, así una fuente
desactivada deja de influir en todos a la vez (y requeue_source encola lo afectado).

Vocabulario (también en la UI): KEV = "explotación conocida reportada" (en algún sitio, no en
este activo); EPSS = "probabilidad de explotación EPSS" (modelo estadístico de FIRST, no un
porcentaje de vulnerabilidad ni de compromiso).
"""

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.threat_intel import ThreatIntelSource, VulnerabilityIntel
from app.threat_intel import epss
from app.threat_intel.freshness import is_stale

CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
# CVEs por consulta (IN acotado).
_CHUNK = 5000


def intel_cve(external_id: str, aliases: Sequence[str] | None) -> str | None:
    """CVE con el que se busca la inteligencia de un registro del catálogo 5B.

    El propio identificador si es un CVE; si no (GHSA, aviso de fabricante), el primer alias
    CVE. Sin CVE no hay enriquecimiento: no se adivina por título ni producto.
    """
    candidate = external_id.strip().upper()
    if CVE.match(candidate):
        return candidate
    for alias in aliases or ():
        if isinstance(alias, str) and CVE.match(alias.strip().upper()):
            return alias.strip().upper()
    return None


@dataclass(frozen=True)
class ExploitIntel:
    cve: str
    known_exploited: bool = False
    kev: dict[str, Any] | None = None
    kev_source: str | None = None
    kev_stale: bool = False
    epss_score: float | None = None
    epss_percentile: float | None = None
    epss_date: str | None = None
    epss_previous: dict[str, Any] | None = None
    epss_source: str | None = None
    epss_stale: bool = False

    @property
    def epss_band(self) -> str:
        return epss.band(self.epss_score)

    @property
    def stale(self) -> bool:
        """¿Alguna inteligencia que aporta viene de una fuente caducada?"""
        return (self.known_exploited and self.kev_stale) or (
            self.epss_score is not None and self.epss_stale
        )

    def as_context(self) -> dict[str, Any]:
        """Representación mínima y estable (snapshot de incidentes, contexto de IA)."""
        data: dict[str, Any] = {"cve": self.cve, "known_exploited": self.known_exploited}
        if self.known_exploited and self.kev:
            data["kev"] = {
                "source": self.kev_source,
                "date_added": self.kev.get("date_added"),
                "due_date": self.kev.get("due_date"),
                "known_ransomware_use": self.kev.get("known_ransomware_use") or "unknown",
                "stale": self.kev_stale,
            }
        if self.epss_score is not None:
            data["epss"] = {
                "source": self.epss_source,
                "score": self.epss_score,
                "percentile": self.epss_percentile,
                "band": self.epss_band,
                "score_date": self.epss_date,
                "stale": self.epss_stale,
            }
        return data


def load_exploitation(
    session: Session, cves: Iterable[str | None], now: datetime
) -> dict[str, ExploitIntel]:
    """Inteligencia vigente por CVE en pocas consultas (nunca una por finding)."""
    wanted = sorted({cve for cve in cves if cve})
    found: dict[str, dict[str, Any]] = {}
    for start in range(0, len(wanted), _CHUNK):
        chunk = wanted[start : start + _CHUNK]
        rows = session.execute(
            select(VulnerabilityIntel, ThreatIntelSource)
            .join(ThreatIntelSource, ThreatIntelSource.id == VulnerabilityIntel.source_id)
            .where(
                VulnerabilityIntel.cve_id.in_(chunk),
                VulnerabilityIntel.active,
                ThreatIntelSource.enabled,
                ThreatIntelSource.archived_at.is_(None),
            )
            .order_by(VulnerabilityIntel.cve_id, VulnerabilityIntel.id)
        ).all()
        for intel, source in rows:
            entry = found.setdefault(intel.cve_id, {"cve": intel.cve_id})
            stale = is_stale(source, now)
            if intel.kind == "kev" and not entry.get("known_exploited"):
                entry.update(
                    known_exploited=True,
                    kev=dict(intel.data or {}),
                    kev_source=source.name,
                    kev_stale=stale,
                )
            elif (
                intel.kind == "epss"
                and intel.epss_score is not None
                # Con dos fuentes EPSS (espejo y oficial) gana la que no está caducada.
                and (entry.get("epss_score") is None or not stale)
            ):
                data = intel.data or {}
                entry.update(
                    epss_score=intel.epss_score,
                    epss_percentile=intel.epss_percentile,
                    epss_date=data.get("score_date"),
                    epss_previous=data.get("previous"),
                    epss_source=source.name,
                    epss_stale=stale,
                )
    return {cve: ExploitIntel(**values) for cve, values in found.items()}
