import { useCallback, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { ApiError } from "../../api/client";
import { topologyApi } from "../../api/sentra";
import type { TopologyLink, TopologyLinkDetail, TopologyNode, TopologyReviewState } from "../../api/types";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  CONFIDENCE_LABELS,
  EVIDENCE_SOURCE_LABELS,
  inventoryPath,
  LINK_KIND_LABELS,
  MEDIUM_LABELS,
  NODE_KIND_LABELS,
  nodeTitle,
  relationLabel,
  REVIEW_LABELS,
  ROLE_LABELS,
} from "../../lib/topology";
import { usePolling } from "../../lib/usePolling";
import { ErrorState, LoadingState } from "../StateViews";

// Detalle bajo demanda: se pide al seleccionar y no se sondea (el grafo ya se refresca solo).
const DETAIL_REFRESH_MS = 3_600_000;
const NOTE_MAX = 500;

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

const none = <span className="muted">—</span>;

function When({ iso }: { iso: string | null | undefined }) {
  if (!iso) return none;
  return (
    <time dateTime={iso} title={formatDateTime(iso)}>
      {formatRelative(iso)}
    </time>
  );
}

/**
 * Panel de un nodo: lo que la topología sabe de él y sus enlaces. NO repite el inventario:
 * enlaza al detalle del activo o del equipo y a su riesgo.
 */
export function NodeDetails({
  node,
  siteId,
  names,
  onSelectLink,
  onClose,
}: {
  node: TopologyNode;
  siteId?: string;
  names: Map<string, string>;
  onSelectLink: (linkId: string) => void;
  onClose: () => void;
}) {
  const fetcher = useCallback(
    (signal: AbortSignal) => topologyApi.node(node.id, siteId, signal),
    [node.id, siteId],
  );
  const detail = usePolling(fetcher, DETAIL_REFRESH_MS);
  const current = detail.data?.node ?? node;
  const path = inventoryPath(current, detail.data?.inventory_path);
  const links: TopologyLink[] = detail.data?.links ?? [];
  return (
    <section className="panel panel--padded stack topo-details" aria-label="Detalles del nodo" aria-live="polite">
      <div className="topo-details__head">
        <h2 className="panel__title">{nodeTitle(current)}</h2>
        <button type="button" className="button button--small" onClick={onClose}>
          Cerrar
        </button>
      </div>
      <dl className="fields">
        {current.custom_label && (
          <Field label="Etiqueta">
            {current.custom_label}
            {current.automatic_name && <div className="muted small">nombre automático: {current.automatic_name}</div>}
          </Field>
        )}
        <Field label="Tipo de nodo">{NODE_KIND_LABELS[current.kind] ?? current.kind}</Field>
        <Field label="Papel">{ROLE_LABELS[current.role] ?? current.role}</Field>
        <Field label="Tipo de dispositivo">{current.device_type ?? none}</Field>
        <Field label="IP">{current.ip ? <span className="mono">{current.ip}</span> : none}</Field>
        <Field label="MAC">{current.mac ? <span className="mono">{current.mac}</span> : none}</Field>
        <Field label="Fabricante">{current.vendor ?? none}</Field>
        <Field label="Estado">{current.status ?? none}</Field>
        <Field label="Riesgo">
          {current.risk_score != null ? `${current.risk_score}${current.risk_level ? ` (${current.risk_level})` : ""}` : none}
        </Field>
        <Field label="Fuentes">{current.sources.length ? current.sources.join(", ") : none}</Field>
        <Field label="Confianza de identidad">{current.identity_confidence ?? none}</Field>
      </dl>
      <div className="actions">
        {path && (
          <Link className="button button--small" to={path}>
            Ver en el inventario
          </Link>
        )}
        {current.asset_id && (
          <Link className="button button--small" to={`/assets/${encodeURIComponent(current.asset_id)}?tab=risk`}>
            Ver riesgo
          </Link>
        )}
      </div>
      {detail.data && detail.data.observed_names.length > 0 && (
        <div>
          <h3 className="small strong">Nombres observados</h3>
          <ul className="plain-list small">
            {detail.data.observed_names.map((n) => (
              <li key={`${n.source}:${n.value}`}>
                {n.value} <span className="muted">({n.source})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <h3 className="small strong">Enlaces ({detail.data ? links.length : current.link_count})</h3>
      {detail.loading ? (
        <LoadingState label="Cargando enlaces…" />
      ) : detail.error && !detail.data ? (
        <ErrorState message={errorMessage(detail.error)} onRetry={detail.refresh} />
      ) : links.length === 0 ? (
        <p className="muted small">Sin enlaces presentes con evidencia.</p>
      ) : (
        <ul className="plain-list topo-details__links" aria-label="Enlaces del nodo">
          {links.map((link) => {
            const other = link.source === current.id ? link.target : link.source;
            return (
              <li key={link.id}>
                <button type="button" className="button button--small" onClick={() => onSelectLink(link.id)}>
                  Evidencia
                </button>{" "}
                <span>{names.get(other) ?? other}</span>{" "}
                <span className="muted small">
                  · {LINK_KIND_LABELS[link.kind]} · {relationLabel(link.relation)} · confianza{" "}
                  {CONFIDENCE_LABELS[link.confidence]}
                </span>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

/** Panel de un enlace: evidencia acotada y, para admin, revisión con nota y versión. */
export function LinkDetails({
  linkId,
  names,
  canManage,
  onReviewed,
  onClose,
}: {
  linkId: string;
  names: Map<string, string>;
  canManage: boolean;
  onReviewed: () => void;
  onClose: () => void;
}) {
  const fetcher = useCallback((signal: AbortSignal) => topologyApi.link(linkId, signal), [linkId]);
  const detail = usePolling(fetcher, DETAIL_REFRESH_MS);
  // Fuera del formulario: el formulario se vuelve a montar con cada versión nueva y el aviso
  // (sobre todo el de conflicto 409) debe seguir visible tras la recarga.
  const [message, setMessage] = useState<{ tone: "ok" | "warn"; text: string }>();
  if (detail.loading) return <LoadingState label="Cargando enlace…" />;
  if (!detail.data) {
    return (
      <section className="panel panel--padded" aria-label="Detalles del enlace">
        <ErrorState message={detail.error ? errorMessage(detail.error) : "Sin datos"} onRetry={detail.refresh} />
      </section>
    );
  }
  const link = detail.data;
  return (
    <section className="panel panel--padded stack topo-details" aria-label="Detalles del enlace" aria-live="polite">
      <div className="topo-details__head">
        <h2 className="panel__title">
          {names.get(link.source) ?? link.source} — {names.get(link.target) ?? link.target}
        </h2>
        <button type="button" className="button button--small" onClick={onClose}>
          Cerrar
        </button>
      </div>
      <dl className="fields">
        <Field label="Clase">{LINK_KIND_LABELS[link.kind]}</Field>
        <Field label="Relación">{relationLabel(link.relation)}</Field>
        <Field label="Medio">{MEDIUM_LABELS[link.medium] ?? link.medium}</Field>
        <Field label="Confianza">{CONFIDENCE_LABELS[link.confidence]}</Field>
        <Field label="Puertos">
          {link.source_port || link.target_port ? (
            <span className="mono">
              {link.source_port ?? "?"} → {link.target_port ?? "?"}
            </span>
          ) : (
            none
          )}
        </Field>
        <Field label="Presente">{link.present ? "sí" : "no (ya no se deriva de la evidencia)"}</Field>
        <Field label="Visto por primera vez">
          <When iso={link.first_seen_at} />
        </Field>
        <Field label="Última evidencia">
          <When iso={link.last_evidence_at ?? link.last_seen_at} />
        </Field>
        <Field label="Revisión">
          {REVIEW_LABELS[link.review_state]}
          {link.reviewed_by && (
            <div className="muted small">
              por {link.reviewed_by} <When iso={link.reviewed_at} />
            </div>
          )}
          {link.review_note && <div className="small">{link.review_note}</div>}
        </Field>
      </dl>
      <h3 className="small strong">Evidencia</h3>
      {link.evidence.length === 0 ? (
        <p className="muted small">El servidor no devolvió evidencia detallada.</p>
      ) : (
        <ul className="plain-list small" aria-label="Evidencia del enlace">
          {link.evidence.map((e, i) => (
            <li key={`${e.source}-${i}`}>
              <span className="strong">{EVIDENCE_SOURCE_LABELS[e.source] ?? e.source}:</span> {e.detail}{" "}
              {e.observed_at && (
                <span className="muted">
                  (<When iso={e.observed_at} />)
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
      {canManage && (
        <ReviewForm
          key={`${link.id}-${link.version}`}
          link={link}
          onMessage={setMessage}
          onDone={() => {
            detail.refresh();
            onReviewed();
          }}
        />
      )}
      {message && (
        <div className={`banner${message.tone === "warn" ? " banner--warn" : ""}`} role={message.tone === "warn" ? "alert" : "status"}>
          {message.text}
        </div>
      )}
    </section>
  );
}

/**
 * Revisión de un enlace (topology:manage). Envía la versión leída; un 409 significa que otro
 * administrador lo revisó antes: se explica, se recarga y nunca se sobrescribe en silencio.
 * La revisión no cambia la clase ni la confianza (lo deja claro el texto).
 */
function ReviewForm({
  link,
  onDone,
  onMessage,
}: {
  link: TopologyLinkDetail;
  onDone: () => void;
  onMessage: (message: { tone: "ok" | "warn"; text: string } | undefined) => void;
}) {
  const [state, setState] = useState<TopologyReviewState>(link.review_state);
  const [note, setNote] = useState(link.review_note ?? "");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    setBusy(true);
    onMessage(undefined);
    try {
      // eslint-disable-next-line no-control-regex
      const clean = note.replace(/[\u0000-\u001f\u007f]/g, " ").trim();
      await topologyApi.review(link.id, { review_state: state, note: clean || null, version: link.version });
      onMessage({ tone: "ok", text: "Revisión guardada." });
      onDone();
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      onMessage({ tone: "warn", text: errorMessage(error) });
      if (err instanceof ApiError && err.status === 409) onDone();
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      className="stack topo-review"
      aria-label="Revisar enlace"
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <h3 className="small strong">Revisar enlace</h3>
      <p className="muted small">
        La revisión deja constancia de lo que un administrador ha comprobado. No cambia la clase ni la confianza: un
        candidato aceptado sigue siendo un candidato. Un enlace rechazado se oculta del mapa por defecto.
      </p>
      <label className="small">
        Estado{" "}
        <select
          className="input input--select"
          value={state}
          onChange={(event) => setState(event.target.value as TopologyReviewState)}
          disabled={busy}
        >
          {(Object.keys(REVIEW_LABELS) as TopologyReviewState[]).map((s) => (
            <option key={s} value={s}>
              {REVIEW_LABELS[s]}
            </option>
          ))}
        </select>
      </label>
      <label className="small stack">
        Nota (opcional)
        <textarea
          className="input"
          rows={2}
          maxLength={NOTE_MAX}
          value={note}
          onChange={(event) => setNote(event.target.value)}
          disabled={busy}
        />
      </label>
      <div>
        <button type="submit" className="button button--primary button--small" disabled={busy}>
          {busy ? "Guardando…" : "Guardar revisión"}
        </button>
      </div>
    </form>
  );
}
