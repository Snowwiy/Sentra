// Presentación de un insight de IA (Fase 4J).
//
// Separa visualmente "Datos de Sentra" (referencias validadas por el backend, enlazadas a
// sus páginas) de "Análisis de IA" (texto del modelo). Todo el texto del modelo se pinta
// como texto: React lo escapa, no se interpreta Markdown/HTML, no hay enlaces generados por
// el modelo ni botones para copiar o ejecutar comandos.
import { Link } from "react-router-dom";
import type { EvidenceRef, Insight } from "../../api/types";
import { CERTAINTY_LABELS, KIND_LABELS, REF_TYPE_LABELS, STALE_LABELS, refLink } from "../../lib/ai";
import { formatDateTime, formatRelative } from "../../lib/format";

export const AI_DISCLAIMER = "Análisis asistido por IA. Verifique la evidencia antes de tomar acciones.";

function RefChip({ item }: { item: EvidenceRef | undefined }) {
  if (!item) return null;
  const href = refLink(item);
  const text = `${REF_TYPE_LABELS[item.type] ?? item.type}: ${item.label}`;
  return (
    <span className="ai-ref" title={`${item.ref} · ${item.id}`}>
      {href ? <Link to={href}>{text}</Link> : text}
    </span>
  );
}

function Refs({ codes, refs }: { codes: string[]; refs: Map<string, EvidenceRef> }) {
  if (!codes.length) return null;
  return (
    <span className="ai-refs">
      {codes.map((code) => (
        <RefChip key={code} item={refs.get(code)} />
      ))}
    </span>
  );
}

export function InsightMeta({ insight }: { insight: Insight }) {
  return (
    <div className="ai-meta small">
      <span className="badge">{KIND_LABELS[insight.kind]}</span>
      {insight.stale ? (
        <span className="badge badge--warn" title="El análisis no refleja los datos actuales">
          Desactualizado ({insight.stale_reason ? STALE_LABELS[insight.stale_reason] : "stale"})
        </span>
      ) : (
        <span className="badge badge--ok">Actual</span>
      )}
      {insight.cached && <span className="badge">Desde caché</span>}
      <span className="muted">
        Modelo <span className="mono">{insight.model}</span> · {formatDateTime(insight.generated_at)} (
        {formatRelative(insight.generated_at)}) · alcance {insight.scope}
        {insight.asset_name ? ` (${insight.asset_name})` : ""} · {insight.evidence_count} evidencias
      </span>
    </div>
  );
}

export function InsightView({ insight }: { insight: Insight }) {
  const result = insight.result;
  const refs = new Map(result.evidence_refs.map((r) => [r.ref, r]));
  return (
    <div className="ai-insight">
      <InsightMeta insight={insight} />
      {insight.question && (
        <p className="ai-question">
          <span className="muted">Pregunta:</span> {insight.question}
        </p>
      )}
      {result.warnings.length > 0 && (
        <ul className="banner banner--warn ai-warnings" role="alert">
          {result.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}

      <section className="ai-section ai-section--model" aria-label="Análisis de IA">
        <h3>Análisis de IA</h3>
        <p className="ai-disclaimer small">{AI_DISCLAIMER}</p>
        <p className="strong">{result.summary}</p>
        {result.assessment && <p>{result.assessment}</p>}
        {result.confidence_note && <p className="muted small">Confianza: {result.confidence_note}</p>}
        {result.key_findings.length > 0 && (
          <>
            <h4>Hallazgos</h4>
            <ul className="ai-findings">
              {result.key_findings.map((f, i) => (
                <li key={i}>
                  <span className={`ai-certainty ai-certainty--${f.certainty}`}>{CERTAINTY_LABELS[f.certainty]}</span>{" "}
                  {f.text} <Refs codes={f.evidence} refs={refs} />
                </li>
              ))}
            </ul>
          </>
        )}
        {result.recommended_actions.length > 0 && (
          <>
            <h4>Qué revisar</h4>
            <ul className="recommendations">
              {result.recommended_actions.map((a, i) => (
                <li key={i}>
                  {a.text} <Refs codes={a.evidence} refs={refs} />
                </li>
              ))}
            </ul>
          </>
        )}
        {result.limitations.length > 0 && (
          <p className="muted small">Limitaciones: {result.limitations.join(" · ")}</p>
        )}
      </section>

      <section className="ai-section ai-section--data" aria-label="Datos de Sentra">
        <h3>Datos de Sentra citados</h3>
        {result.evidence_refs.length ? (
          <ul className="ai-evidence">
            {result.evidence_refs.map((r) => (
              <li key={r.ref}>
                <RefChip item={r} />
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">
            {result.insufficient_data
              ? "No hay datos suficientes en Sentra para sostener conclusiones."
              : "El análisis no citó evidencia."}
          </p>
        )}
      </section>
    </div>
  );
}
