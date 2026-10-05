import type { AssetCriticality, RiskConfidence, RiskLevel } from "../../api/types";
import { CRITICALITY_LABELS, RISK_CONFIDENCE_LABELS, RISK_LEVEL_LABELS } from "../../lib/risk";

/** Score y nivel juntos ("78 · Alto"): nunca un número sin su nivel. */
export function RiskBadge({ score, level }: { score: number; level: RiskLevel }) {
  return (
    <span className={`risk risk--${level}`} title="Riesgo (0-100)">
      <span className="risk__score">{score}</span>
      <span className="risk__level">{RISK_LEVEL_LABELS[level]}</span>
    </span>
  );
}

/** Solo el nivel, para tablas donde el score va en su propia columna. */
export function RiskLevelBadge({ level }: { level: RiskLevel }) {
  return <span className={`risk-level risk-level--${level}`}>{RISK_LEVEL_LABELS[level]}</span>;
}

/** Confianza de la evaluación, separada del score: baja = verificar antes de actuar. */
export function RiskConfidenceBadge({ confidence }: { confidence: RiskConfidence }) {
  return (
    <span className={`dconfidence dconfidence--${confidence}`} title="Confianza de la evaluación">
      conf. {RISK_CONFIDENCE_LABELS[confidence]}
    </span>
  );
}

/** Celda compacta para tablas: badge y confianza, o "pendiente" si aún no se evaluó. */
export function RiskCell({
  score,
  level,
  confidence,
}: {
  score: number | null;
  level: RiskLevel | null;
  confidence: RiskConfidence | null;
}) {
  if (score === null || level === null) {
    return <span className="muted small">Pendiente</span>;
  }
  return (
    <span className="risk-cell">
      <RiskBadge score={score} level={level} />
      {confidence && <RiskConfidenceBadge confidence={confidence} />}
    </span>
  );
}

export function CriticalityBadge({ criticality }: { criticality: AssetCriticality }) {
  return (
    <span className={`criticality criticality--${criticality}`} title="Criticidad del activo">
      {CRITICALITY_LABELS[criticality]}
    </span>
  );
}
