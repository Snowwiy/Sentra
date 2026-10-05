import type { IncidentLevel, IncidentStatus } from "../../api/types";
import { LEVEL_LABELS, STATUS_LABELS } from "../../lib/incidents";

/** Severidad = impacto; prioridad = urgencia de trabajo. Se muestran por separado. */
export function LevelBadge({ level, kind }: { level: IncidentLevel; kind: "severity" | "priority" }) {
  return (
    <span
      className={kind === "severity" ? `dseverity dseverity--${level}` : `ipriority ipriority--${level}`}
      title={kind === "severity" ? "Severidad (impacto)" : "Prioridad (urgencia)"}
    >
      {LEVEL_LABELS[level]}
    </span>
  );
}

export function IncidentStatusBadge({ status }: { status: IncidentStatus }) {
  return <span className={`istatus istatus--${status}`}>{STATUS_LABELS[status]}</span>;
}
