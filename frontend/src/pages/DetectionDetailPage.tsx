import { useCallback, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { detectionsApi } from "../api/sentra";
import type { DetectionDetail, DetectionEvidence } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import {
  CATEGORY_LABELS,
  ConfidenceBadge,
  DetectionSeverityBadge,
  DetectionStatusBadge,
} from "../components/detections/DetectionBadges";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";

/** Valor de evidencia como texto plano: React lo escapa; nunca se interpreta como HTML. */
function plain(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (Array.isArray(value)) return value.map(plain).join(", ");
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function EvidenceItem({ item }: { item: DetectionEvidence }) {
  const entries = Object.entries(item.data ?? {});
  return (
    <li className="timeline__item">
      <div className="timeline__when" title={formatDateTime(item.occurred_at)}>
        {formatDateTime(item.occurred_at)}
      </div>
      <div className="timeline__body">
        <div>
          <span className="badge">{item.signal_kind}</span>
          {item.role && <span className="badge">{item.role}</span>}
          <span className="muted small"> · {item.source_type}</span>
        </div>
        <div>{item.summary}</div>
        {entries.length > 0 && (
          <dl className="fields fields--inline evidence-data">
            {entries.map(([key, value]) => (
              <div className="field" key={key}>
                <dt>{key}</dt>
                <dd className="mono">{plain(value)}</dd>
              </div>
            ))}
          </dl>
        )}
      </div>
    </li>
  );
}

/**
 * Reconocer / resolver (detections:manage: admin y analyst). Un viewer no ve los botones y
 * el backend rechaza la acción con 403 igualmente.
 */
function DetectionActions({ detection, onChanged }: { detection: DetectionDetail; onChanged: () => void }) {
  const auth = useAuth();
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  if (!auth.can("detections:manage") || detection.status === "resolved") return null;

  async function run(action: () => Promise<unknown>) {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      setNote("");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel panel--padded">
      <h2>Gestión</h2>
      <label className="detection-note">
        <span className="muted small">Nota de resolución (opcional)</span>
        <textarea
          className="input"
          maxLength={500}
          rows={2}
          value={note}
          onChange={(e) => setNote(e.target.value)}
          aria-label="Nota de resolución"
        />
      </label>
      <div className="actions">
        {detection.status === "open" && (
          <button
            type="button"
            className="button"
            disabled={busy}
            onClick={() => void run(() => detectionsApi.acknowledge(detection.detection_id))}
          >
            Reconocer
          </button>
        )}
        <button
          type="button"
          className="button button--primary"
          disabled={busy}
          onClick={() => void run(() => detectionsApi.resolve(detection.detection_id, note))}
        >
          Resolver
        </button>
        {error && (
          <span className="banner banner--warn" role="alert">
            {error}
          </span>
        )}
      </div>
    </section>
  );
}

export function DetectionDetailPage() {
  const { detectionId = "" } = useParams();
  const fetchDetection = useCallback(
    (signal: AbortSignal) => detectionsApi.get(detectionId, signal),
    [detectionId],
  );
  const { data: d, error, loading, refresh } = usePolling(fetchDetection, config.refreshIntervalMs);

  if (loading) return <LoadingState label="Cargando detección…" />;
  if (!d) {
    return (
      <div className="page">
        <Link to="/detections" className="muted">
          ← Detecciones
        </Link>
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      </div>
    );
  }

  const mitre = [d.mitre_tactic, d.mitre_subtechnique ?? d.mitre_technique].filter(Boolean).join(" · ");
  return (
    <div className="page">
      <Link to="/detections" className="muted">
        ← Detecciones
      </Link>
      <div className="page__header">
        <h1>{d.title}</h1>
        <div className="detection-badges">
          <DetectionSeverityBadge severity={d.severity} />
          <ConfidenceBadge confidence={d.confidence} />
          <DetectionStatusBadge status={d.status} />
        </div>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="panel panel--padded">
        <h2>Qué pasó</h2>
        <p>{d.summary}</p>
        <h2>Por qué importa</h2>
        <p>{d.why || "—"}</p>
        <dl className="fields">
          <div className="field">
            <dt>Activo</dt>
            <dd>
              <Link to={`/assets/${d.asset_id}`} className="strong">
                {d.hostname}
              </Link>
            </dd>
          </div>
          <div className="field">
            <dt>Regla</dt>
            <dd>
              <span className="mono">{d.rule_id}</span> v{d.rule_version} ·{" "}
              {CATEGORY_LABELS[d.category] ?? d.category}
              {d.kind === "correlation" && " · correlación"}
            </dd>
          </div>
          <div className="field">
            <dt>Primera vez</dt>
            <dd>{formatDateTime(d.first_seen_at)}</dd>
          </div>
          <div className="field">
            <dt>Última vez</dt>
            <dd>
              {formatDateTime(d.last_seen_at)} <span className="muted">({formatRelative(d.last_seen_at)})</span>
            </dd>
          </div>
          <div className="field">
            <dt>Ocurrencias</dt>
            <dd>{d.occurrence_count}</dd>
          </div>
          <div className="field">
            <dt>MITRE ATT&amp;CK</dt>
            <dd>{mitre || "Sin mapeo"}</dd>
          </div>
          {d.alert_id && (
            <div className="field">
              <dt>Alerta</dt>
              <dd>
                <Link to="/alerts">Ver alertas</Link>
              </dd>
            </div>
          )}
          {d.acknowledged_at && (
            <div className="field">
              <dt>Reconocida</dt>
              <dd>
                {formatDateTime(d.acknowledged_at)} · {d.acknowledged_by ?? "—"}
              </dd>
            </div>
          )}
          {d.resolved_at && (
            <div className="field">
              <dt>Resuelta</dt>
              <dd>
                {formatDateTime(d.resolved_at)} · {d.resolved_by ?? "—"}
                {d.resolution_note && <div className="muted">{d.resolution_note}</div>}
              </dd>
            </div>
          )}
        </dl>
      </section>

      <section className="panel panel--padded">
        <h2>Recomendaciones</h2>
        {d.recommendations.length ? (
          <ul className="recommendations">
            {d.recommendations.map((text) => (
              <li key={text}>{text}</li>
            ))}
          </ul>
        ) : (
          <p className="muted">Sin recomendaciones para esta regla.</p>
        )}
        {d.required_data.length > 0 && (
          <p className="muted small">Datos que usa la regla: {d.required_data.join(", ")}.</p>
        )}
      </section>

      <section className="panel panel--padded">
        <h2>Evidencias</h2>
        {d.evidence_total > d.evidence.length && (
          <p className="muted small">
            Se muestran {d.evidence.length} de {d.evidence_total} evidencias.
          </p>
        )}
        {d.evidence.length ? (
          <ol className="timeline" aria-label="Timeline de evidencias">
            {d.evidence.map((item, index) => (
              <EvidenceItem key={`${item.occurred_at}-${index}`} item={item} />
            ))}
          </ol>
        ) : (
          <p className="muted">Sin evidencias registradas.</p>
        )}
      </section>

      <DetectionActions detection={d} onChanged={refresh} />
    </div>
  );
}
