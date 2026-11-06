import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ApiError, aiInvalidReasonText } from "../../api/client";
import { consoleAiApi } from "../../api/sentra7b";
import type {
  AIStatus,
  ConsoleContextPreview,
  ConsoleContextRequest,
  ConsoleTask,
  EvidenceRef,
  Insight,
  ToolExecutionOut,
} from "../../api/types";
import { CERTAINTY_LABELS, REF_TYPE_LABELS, refLink } from "../../lib/ai";
import { errorMessage, formatRelative } from "../../lib/format";
import { AIProviderBadge } from "../ai/AIAnalyzePanel";
import { CopyButton } from "../CopyButton";
import { Icon } from "../icons";

/**
 * Fase 7C.2: asistente de IA local de la Analyst Console.
 *
 * Trabaja solo sobre resultados de herramientas ya ejecutados (lectura o investigación) que
 * el analista marca: nunca ejecuta herramientas, no ve resultados ajenos y no cambia nada.
 * Todo lo que escribe el modelo se pinta como "Sugerencia del modelo", separado de los datos
 * de Sentra citados; las hipótesis salen siempre como "Posible" con cómo validarlas y el
 * borrador lleva la cabecera fija de texto generado por IA.
 *
 * 7C-Security-Fix1 (privacidad estricta): nada sale hacia el modelo sin que el analista vea
 * antes el documento exacto (POST /ai/console/context) y pulse «Enviar al modelo local». El
 * envío repite la huella revisada; si los datos cambiaron, el servidor no envía nada.
 */

const TASKS: { task: ConsoleTask; label: string; hint: string }[] = [
  { task: "summary", label: "Resumir", hint: "Qué muestran los resultados elegidos" },
  { task: "explain_risk", label: "Explicar riesgo", hint: "Por qué el riesgo es el que es" },
  { task: "hypotheses", label: "Hipótesis", hint: "Explicaciones posibles y cómo validarlas" },
  { task: "draft_note", label: "Borrador de nota", hint: "Texto para revisar antes de usarlo" },
];

const ERROR_TEXT: Record<string, string> = {
  ai_console_disabled: "El asistente de consola está desactivado en este servidor (AI_CONSOLE_ASSIST_ENABLED).",
  ai_not_configured: "La IA local no está configurada. El resto de la consola funciona igual.",
  ai_destination_blocked: "El destino del modelo no está autorizado: los datos no salen del servidor.",
  ai_provider_unavailable: "El servidor del modelo local no responde. No se usa ningún otro proveedor.",
  ai_timeout: "El modelo local tardó demasiado. Prueba con menos resultados o un modelo más ligero.",
  ai_provider_rate_limited: "El servidor del modelo está saturado. Inténtalo en unos segundos.",
  ai_busy: "Hay demasiados análisis en curso. Inténtalo en unos segundos.",
  ai_invalid_response: "El modelo devolvió una respuesta que no se puede usar (formato no válido).",
  ai_ungrounded_response: "El modelo no citó datos reales de Sentra: la respuesta se descartó.",
  console_execution_not_usable: "Alguno de los resultados elegidos no se puede analizar (fallido, sin salida o es una acción).",
  console_assist_invalid: "La petición no es válida: revisa los resultados elegidos.",
  ai_console_loopback_required:
    "El asistente solo usa un modelo en este mismo servidor (loopback). Pide al administrador que apunte la IA a loopback.",
  console_context_review_required: "Revisa los datos antes de enviarlos al modelo.",
  console_context_changed: "Los datos cambiaron desde la revisión: no se ha enviado nada. Revísalos de nuevo.",
};

// Fase 7C.1: de dónde sale el modelo que responde (nunca de un proveedor externo implícito).
const MODEL_SOURCE_LABELS: Record<string, string> = {
  settings: "configurado en el servidor",
  local_manager: "modelo activo del gestor local",
};

export function assistErrorText(err: unknown): string {
  if (err instanceof ApiError) {
    // 7C-Fix2: el motivo concreto (cortado, solo razonamiento, schema...) cuando lo hay.
    const reason = err.code === "ai_invalid_response" ? aiInvalidReasonText(err.details) : undefined;
    return reason ?? ERROR_TEXT[err.code] ?? err.message;
  }
  return errorMessage(err instanceof Error ? err : new Error(String(err)));
}

/** Resultados que el asistente acepta: terminados con salida y que no son acciones. */
export function usableExecutions(items: ToolExecutionOut[]): ToolExecutionOut[] {
  const seen = new Set<string>();
  return items.filter((e) => {
    if (seen.has(e.execution_id)) return false;
    seen.add(e.execution_id);
    return e.status === "succeeded" && e.category !== "action" && (e.output !== null || e.output_sha256 !== null);
  });
}

function RefChip({ item }: { item: EvidenceRef | undefined }) {
  if (!item) return null;
  const href = refLink(item);
  const text = `${REF_TYPE_LABELS[item.type] ?? item.type}: ${item.label}`;
  return (
    <span className="ai-ref" title={item.ref}>
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

function AssistResult({ insight }: { insight: Insight }) {
  const result = insight.result;
  const refs = useMemo(() => new Map(result.evidence_refs.map((r) => [r.ref, r])), [result.evidence_refs]);
  const fromModel = result.origin !== "sentra";
  return (
    <div className="assistant__result" aria-live="polite">
      <div className="assistant__origin">
        {fromModel ? (
          <span className="badge badge--warn">Sugerencia del modelo</span>
        ) : (
          <span className="badge">Respuesta de Sentra (sin modelo)</span>
        )}
        <span className="small muted">
          {fromModel && <span className="mono">{insight.model}</span>}
          {fromModel && " · "}
          {formatRelative(insight.generated_at)}
          {insight.cached && " · desde caché"}
          {insight.stale && " · desactualizado"}
        </span>
      </div>
      {fromModel && (
        <p className="assistant__disclaimer small">
          No es evidencia: es una lectura del modelo sobre los datos citados abajo. Compruébala antes de actuar.
        </p>
      )}
      {result.warnings.length > 0 && (
        <ul className="banner banner--warn small" role="note">
          {result.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      <p className="strong">{result.summary}</p>
      {result.assessment && <p className="small">{result.assessment}</p>}
      {result.key_findings.length > 0 && (
        <ul className="ai-findings small">
          {result.key_findings.map((f, i) => (
            <li key={i}>
              <span className={`ai-certainty ai-certainty--${f.certainty}`}>{CERTAINTY_LABELS[f.certainty]}</span> {f.text}{" "}
              <Refs codes={f.evidence} refs={refs} />
            </li>
          ))}
        </ul>
      )}
      {result.hypotheses.length > 0 && (
        <section aria-label="Hipótesis del modelo">
          <h4 className="small">Hipótesis (sin confirmar)</h4>
          <ol className="assistant__hypotheses small">
            {result.hypotheses.map((h, i) => (
              <li key={i}>
                <span className="ai-certainty ai-certainty--possible">Posible</span> {h.text}{" "}
                <Refs codes={h.evidence} refs={refs} />
                {h.validate_with && <div className="muted">Cómo validarla: {h.validate_with}</div>}
              </li>
            ))}
          </ol>
        </section>
      )}
      {result.draft && (
        <section aria-label="Borrador de nota">
          <div className="assistant__draft-head">
            <h4 className="small">Borrador de nota</h4>
            <CopyButton text={result.draft} label="Copiar borrador" />
          </div>
          <textarea className="input assistant__draft" readOnly rows={6} value={result.draft} />
        </section>
      )}
      {result.recommended_actions.length > 0 && (
        <>
          <h4 className="small">Qué revisar</h4>
          <ul className="small">
            {result.recommended_actions.map((a, i) => (
              <li key={i}>
                {a.text} <Refs codes={a.evidence} refs={refs} />
              </li>
            ))}
          </ul>
        </>
      )}
      <section className="assistant__data" aria-label="Datos de Sentra citados">
        <h4 className="small">Datos de Sentra citados</h4>
        {result.evidence_refs.length ? (
          <ul className="ai-evidence small">
            {result.evidence_refs.map((r) => (
              <li key={r.ref}>
                <RefChip item={r} />
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">
            {result.insufficient_data ? "No hay datos suficientes para sostener conclusiones." : "Sin citas."}
          </p>
        )}
      </section>
    </div>
  );
}

const TASK_LABELS = Object.fromEntries(TASKS.map((t) => [t.task, t.label])) as Record<ConsoleTask, string>;

/** 7C-Security-Fix1: lo que recibiría el modelo, para aceptarlo o cancelarlo. */
function ContextReview({
  preview,
  busy,
  onSend,
  onCancel,
}: {
  preview: ConsoleContextPreview;
  busy: boolean;
  onSend: () => void;
  onCancel: () => void;
}) {
  return (
    <section className="assistant__review" aria-label="Revisión de los datos a enviar">
      <h4 className="small">Revisa lo que recibirá el modelo local · {TASK_LABELS[preview.task]}</h4>
      <ul className="small assistant__review-facts">
        <li>Destino: este servidor (loopback); no sale nada del equipo.</li>
        {preview.model && (
          <li>
            Modelo: <span className="mono">{preview.model}</span>
          </li>
        )}
        <li>
          {preview.items.length} elementos de Sentra · {preview.chars} caracteres
        </li>
        <li>
          {preview.redacted_values > 0
            ? `${preview.redacted_values} valores con aspecto de secreto retirados antes de enviar`
            : "Sin valores con aspecto de secreto"}
        </li>
        <li>
          {preview.pseudonymized.length > 0
            ? `Seudonimizado: ${preview.pseudonymized.join(", ")}`
            : "Sin seudonimización (AI_REDACT vacío)"}
        </li>
        {preview.question && <li>Pregunta: «{preview.question}»</li>}
      </ul>
      <ul className="small ai-evidence" aria-label="Elementos incluidos">
        {preview.items.map((item) => (
          <li key={item.ref}>
            <span className="mono">{item.ref}</span> {REF_TYPE_LABELS[item.type] ?? item.type}: {item.label}
          </li>
        ))}
      </ul>
      <details>
        <summary className="small">Ver el documento completo</summary>
        <pre className="assistant__review-doc mono small">{JSON.stringify(preview.document, null, 2)}</pre>
      </details>
      <p className="small muted">
        Huella <span className="mono">{preview.context_sha256.slice(0, 16)}</span>: si los datos cambian antes de enviar, no se
        envía nada.
      </p>
      <div className="assistant__tasks">
        <button type="button" className="button button--small button--primary" disabled={busy} onClick={onSend}>
          {busy ? "Enviando…" : "Enviar al modelo local"}
        </button>
        <button type="button" className="button button--small" disabled={busy} onClick={onCancel}>
          Cancelar
        </button>
      </div>
    </section>
  );
}

export function ConsoleAssistant({
  status,
  statusError,
  canUse,
  executions,
  assetId,
  detectionId,
}: {
  status?: AIStatus;
  statusError?: Error;
  canUse: boolean;
  executions: ToolExecutionOut[];
  assetId?: string;
  detectionId?: string;
}) {
  const usable = usableExecutions(executions);
  const max = status?.console_max_executions ?? 6;
  const [picked, setPicked] = useState<string[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState<ConsoleTask>();
  const [insight, setInsight] = useState<Insight>();
  const [error, setError] = useState<string>();
  const [review, setReview] = useState<{ preview: ConsoleContextPreview; request: ConsoleContextRequest }>();
  // 7C-Security-Fix1 (minimización): nada va marcado por defecto; el analista elige cada
  // resultado que quiere compartir con el modelo.
  const chosen = picked.filter((id) => usable.some((e) => e.execution_id === id));
  const ready = Boolean(status?.available && status.console_assist_available);

  // Paso 1: el servidor construye el documento y lo enseña; todavía no se envía nada.
  const prepare = async (task: ConsoleTask) => {
    const request: ConsoleContextRequest = {
      task,
      execution_ids: chosen,
      asset_id: detectionId ? null : (assetId ?? null),
      detection_id: detectionId ?? null,
      question: question.trim().length >= 3 ? question.trim() : null,
    };
    setBusy(task);
    setError(undefined);
    setReview(undefined);
    try {
      setReview({ preview: await consoleAiApi.context(request), request });
    } catch (err) {
      setError(assistErrorText(err));
    } finally {
      setBusy(undefined);
    }
  };
  // Paso 2: confirmación explícita con la huella de lo revisado.
  const send = async () => {
    if (!review) return;
    setBusy(review.request.task);
    setError(undefined);
    try {
      setInsight(
        await consoleAiApi.assist({
          ...review.request,
          context_sha256: review.preview.context_sha256,
          confirm_send: true,
        }),
      );
      setReview(undefined);
    } catch (err) {
      if (err instanceof ApiError && err.code === "console_context_changed") setReview(undefined);
      setError(assistErrorText(err));
    } finally {
      setBusy(undefined);
    }
  };
  const toggle = (id: string) =>
    setPicked((current) => (current.includes(id) ? current.filter((x) => x !== id) : [...current, id].slice(-max)));

  return (
    <section className="panel panel--padded assistant" aria-label="Asistente de IA local">
      <header className="console-col__head">
        <h2>
          <Icon name="ai" size={16} /> Asistente IA local
        </h2>
        <span className="small muted">opcional</span>
      </header>
      {!canUse ? (
        <p className="small muted">Tu rol no puede compartir datos de la consola con la IA (requiere ai:use y tools:execute).</p>
      ) : statusError ? (
        <p className="small muted" role="note">
          No se pudo consultar el estado de la IA: {errorMessage(statusError)}
        </p>
      ) : !status ? (
        <p className="small muted">Comprobando la IA local…</p>
      ) : !ready ? (
        <p className="small muted" role="note">
          {status.available
            ? (status.console_assist_reason ?? "El asistente de consola está desactivado en este servidor.")
            : (status.reason ?? "IA local no configurada.")}{" "}
          La consola funciona igual sin IA.
        </p>
      ) : (
        <>
          <p className="small" aria-label="Modelo en uso">
            <AIProviderBadge status={status} />{" "}
            <span className="small muted">{MODEL_SOURCE_LABELS[status.model_source] ?? status.model_source}</span>
          </p>
          <p className="small muted">
            Analiza solo los resultados que marques, tras revisar lo que se enviará. Nunca ejecuta herramientas ni sustituye
            al motor de detección.
          </p>
          {usable.length === 0 ? (
            <p className="small muted">Ejecuta una herramienta de lectura o investigación para poder analizar su resultado.</p>
          ) : (
            <fieldset className="assistant__picks">
              <legend className="small">
                Marca los resultados que quieres compartir con el modelo ({chosen.length} de máximo {max})
              </legend>
              {usable.slice(0, 12).map((e) => (
                <label key={e.execution_id} className="checkbox small">
                  <input
                    type="checkbox"
                    checked={chosen.includes(e.execution_id)}
                    onChange={() => toggle(e.execution_id)}
                    disabled={!chosen.includes(e.execution_id) && chosen.length >= max}
                  />{" "}
                  <span className="mono">{e.tool_name}</span>
                  {e.target_label && <span className="muted"> · {e.target_label}</span>}
                </label>
              ))}
            </fieldset>
          )}
          <label className="picker">
            <span className="picker__label">Pregunta concreta (opcional)</span>
            <input
              className="input"
              value={question}
              maxLength={500}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="¿Qué debería comprobar primero?"
            />
          </label>
          <div className="assistant__tasks" role="group" aria-label="Tareas del asistente">
            {TASKS.map(({ task, label, hint }) => (
              <button
                key={task}
                type="button"
                className="button button--small"
                title={hint}
                disabled={busy !== undefined || chosen.length === 0}
                onClick={() => void prepare(task)}
              >
                {busy === task ? "Analizando…" : label}
              </button>
            ))}
          </div>
          {review && (
            <ContextReview
              preview={review.preview}
              busy={busy !== undefined}
              onSend={() => void send()}
              onCancel={() => setReview(undefined)}
            />
          )}
          {error && (
            <div className="banner banner--warn small" role="alert">
              {error}
            </div>
          )}
          {insight && <AssistResult insight={insight} />}
        </>
      )}
    </section>
  );
}
