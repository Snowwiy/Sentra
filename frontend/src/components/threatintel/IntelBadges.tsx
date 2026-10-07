import type {
  IndicatorClassification,
  IntelSourceState,
  IntelTrust,
  ThreatMatchStatus,
} from "../../api/types";
import {
  CLASSIFICATION_LABELS,
  EPSS_BAND_LABELS,
  epssBand,
  formatEpss,
  MATCH_STATUS_LABELS,
  SOURCE_STATE_LABELS,
  TRUST_LABELS,
} from "../../lib/threatIntel";

/** Explotación conocida reportada (CISA KEV): en algún sitio, no en este activo. */
export function KevBadge({ stale = false }: { stale?: boolean }) {
  return (
    <span
      className={`badge badge--crit${stale ? " badge--muted" : ""}`}
      title="Explotación conocida reportada por CISA KEV (en algún sitio; no indica compromiso de este activo)"
    >
      KEV{stale ? " (fuente desactualizada)" : ""}
    </span>
  );
}

/** Probabilidad de explotación EPSS: modelo estadístico, no porcentaje de vulnerabilidad. */
export function EpssBadge({ score }: { score: number | null | undefined }) {
  if (score == null) return null;
  const band = epssBand(score);
  const tone = band === "high" ? "badge--warn" : band === "elevated" ? "badge--info" : "";
  return (
    <span
      className={`badge ${tone}`.trim()}
      title={`Probabilidad de explotación EPSS (próximos 30 días, modelo de FIRST): banda ${(EPSS_BAND_LABELS[band] ?? band).toLowerCase()}`}
    >
      EPSS {formatEpss(score)}
    </span>
  );
}

export function TrustBadge({ trust }: { trust: IntelTrust }) {
  return <span className={`tibadge tibadge--trust-${trust}`}>{TRUST_LABELS[trust] ?? trust}</span>;
}

export function SourceStateBadge({ state }: { state: IntelSourceState }) {
  const tone = state === "fresh" ? "badge--ok" : state === "stale" ? "badge--warn" : "";
  return <span className={`badge ${tone}`.trim()}>{SOURCE_STATE_LABELS[state] ?? state}</span>;
}

export function ClassificationBadge({ value }: { value: IndicatorClassification }) {
  const tone = value === "malicious" ? "badge--crit" : value === "suspicious" ? "badge--warn" : "";
  return (
    <span className={`badge ${tone}`.trim()} title="Clasificación declarada por la fuente">
      {CLASSIFICATION_LABELS[value] ?? value}
    </span>
  );
}

export function MatchStatusBadge({ status }: { status: ThreatMatchStatus }) {
  return <span className={`vstatus vstatus--${status}`}>{MATCH_STATUS_LABELS[status] ?? status}</span>;
}
