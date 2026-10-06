import type { ExposureState, FindingStatus, MatchConfidence, MatchState, VulnSeverity } from "../../api/types";
import {
  CONFIDENCE_LABELS,
  EXPOSURE_LABELS,
  MATCH_HINTS,
  MATCH_LABELS,
  SEVERITY_LABELS,
  STATUS_LABELS,
} from "../../lib/vulnerabilities";

/** Severidad del catálogo (impacto); la prioridad se muestra aparte. */
export function VulnSeverityBadge({ severity }: { severity: VulnSeverity }) {
  return (
    <span className={`dseverity dseverity--${severity}`} title="Severidad (catálogo)">
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

/** Estado técnico + confianza: una potencial se distingue siempre de una confirmada. */
export function MatchBadge({ state, confidence }: { state: MatchState; confidence?: MatchConfidence }) {
  return (
    <span className={`vmatch vmatch--${state}`} title={MATCH_HINTS[state]}>
      {MATCH_LABELS[state]}
      {confidence && <span className="vmatch__confidence"> · confianza {CONFIDENCE_LABELS[confidence].toLowerCase()}</span>}
    </span>
  );
}

export function FindingStatusBadge({ status }: { status: FindingStatus }) {
  return <span className={`vstatus vstatus--${status}`}>{STATUS_LABELS[status]}</span>;
}

export function ExposureBadge({ state }: { state: ExposureState }) {
  return <span className={`vexposure vexposure--${state}`}>{EXPOSURE_LABELS[state]}</span>;
}

/** Prioridad de trabajo (0-100) calculada por Sentra, no por el catálogo. */
export function PriorityBadge({ score, level }: { score: number; level: string }) {
  const known = ["critical", "high", "medium", "low"].includes(level) ? level : "low";
  return (
    <span className={`ipriority ipriority--${known}`} title="Prioridad Sentra (urgencia de trabajo)">
      {score}
    </span>
  );
}
