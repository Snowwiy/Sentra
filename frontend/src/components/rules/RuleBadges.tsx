import type { CompileStatus, RuleIssue, RuleSource, RuleStatus } from "../../api/types";
import { COMPILE_LABELS, RULE_STATUS_LABELS, SOURCE_LABELS, compileTone, statusTone } from "../../lib/rules";

export function RuleSourceBadge({ source }: { source: RuleSource }) {
  return <span className={`badge${source === "builtin" ? " badge--info" : ""}`}>{SOURCE_LABELS[source]}</span>;
}

export function RuleStatusBadge({ status }: { status: RuleStatus }) {
  return <span className={`badge ${statusTone(status)}`}>{RULE_STATUS_LABELS[status]}</span>;
}

export function CompileBadge({ status }: { status: CompileStatus }) {
  return (
    <span className={`badge ${compileTone(status)}`} title="Estado de compilación">
      {COMPILE_LABELS[status]}
    </span>
  );
}

/** Lista de errores o avisos del compilador. Texto plano: nunca se interpreta como HTML. */
export function IssueList({ issues, tone }: { issues: RuleIssue[]; tone: "warn" | "crit" }) {
  if (!issues.length) return null;
  return (
    <ul className={`plain-list small ${tone === "crit" ? "text-crit" : "text-warn"}`}>
      {issues.map((issue, index) => (
        <li key={`${issue.code}-${index}`}>
          <span className="mono">{issue.code}</span>
          {issue.path && <span className="muted mono"> · {issue.path}</span>}: {issue.message}
        </li>
      ))}
    </ul>
  );
}
