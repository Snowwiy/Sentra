import { useCallback, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { threatIntelApi } from "../api/sentra";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { ClassificationBadge, MatchStatusBadge, TrustBadge } from "../components/threatintel/IntelBadges";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import {
  CONFIDENCE_LABELS,
  INDICATOR_STATE_LABELS,
  INDICATOR_TYPE_LABELS,
  isConflict,
  MATCH_ACTION_LABELS,
  OBSERVATION_LABELS,
  REASON_REQUIRED,
} from "../lib/threatIntel";
import { usePolling } from "../lib/usePolling";

const backLink = (
  <Link className="muted" to="/threat-intel?tab=matches">
    ← Coincidencias
  </Link>
);

type Action = "acknowledge" | "dismiss" | "reopen";

/**
 * Coincidencia de un indicador con un dato local. NO afirma un compromiso: dice qué dato de
 * Sentra coincide con qué indicador y qué declara la fuente. El análisis lo hace una persona.
 */
export function ThreatMatchDetailPage() {
  const { matchId = "" } = useParams();
  const auth = useAuth();
  const navigate = useNavigate();
  const fetcher = useCallback((signal: AbortSignal) => threatIntelApi.match(matchId, signal), [matchId]);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const [pending, setPending] = useState<Action>();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();

  if (loading) return <LoadingState label="Cargando coincidencia…" />;
  if (!data) {
    const missing = error instanceof ApiError && (error.status === 404 || error.status === 422);
    return (
      <div className="page">
        {backLink}
        {missing || !error ? (
          <EmptyState title="Coincidencia no encontrada" />
        ) : (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        )}
      </div>
    );
  }

  const execute = async (work: () => Promise<unknown>) => {
    setBusy(true);
    setActionError(undefined);
    try {
      await work();
      setPending(undefined);
      setReason("");
      refresh();
    } catch (err) {
      setActionError(
        isConflict(err)
          ? "Otra persona o el matching cambió esta coincidencia. Recarga y revisa antes de repetir la acción."
          : err instanceof Error
            ? errorMessage(err)
            : String(err),
      );
    } finally {
      setBusy(false);
    }
  };

  const canIncident = data.actions.includes("incident") && auth.can("incidents:manage");
  const evidence = Object.entries(data.evidence ?? {}).filter(([, value]) => value !== null && value !== "");

  return (
    <div className="page">
      {backLink}
      <div className="page__header">
        <div>
          <h1>
            Coincidencia con <span className="mono">{data.indicator_value}</span>
          </h1>
          <div className="detection-badges">
            <ClassificationBadge value={data.classification} />
            <MatchStatusBadge status={data.status} />
            <span className="muted small">
              en <Link to={`/assets/${data.asset.asset_id}`}>{data.asset.name}</Link> ({data.asset.primary_ip})
            </span>
          </div>
        </div>
      </div>
      <div className="banner" role="note">
        Un dato de Sentra coincide con un indicador que la fuente «{data.source_name}» clasifica como{" "}
        {data.classification === "malicious" ? "malicioso" : data.classification === "suspicious" ? "sospechoso" : data.classification}.
        No confirma un compromiso: requiere análisis.
      </div>
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
        </div>
      )}

      {(data.actions.length > 0 || canIncident) && (
        <section className="panel panel--padded">
          <div className="actions">
            {(["acknowledge", "dismiss", "reopen"] as const)
              .filter((a) => data.actions.includes(a))
              .map((a) => (
                <button
                  key={a}
                  type="button"
                  className="button"
                  disabled={busy}
                  onClick={() =>
                    REASON_REQUIRED.has(a)
                      ? setPending(a)
                      : void execute(() => threatIntelApi.matchAction(data.match_id, a, data.version))
                  }
                >
                  {MATCH_ACTION_LABELS[a]}
                </button>
              ))}
            {canIncident && (
              <button
                type="button"
                className="button button--primary"
                disabled={busy}
                onClick={() =>
                  void execute(async () => {
                    const incident = await threatIntelApi.createIncident(data.match_id, data.version);
                    navigate(`/incidents/${incident.incident_id}`);
                  })
                }
              >
                {MATCH_ACTION_LABELS.incident}
              </button>
            )}
          </div>
          {pending && (
            <div className="stack">
              <label className="form-field">
                <span className="muted small">Motivo (obligatorio)</span>
                <textarea
                  className="input"
                  aria-label="Motivo"
                  maxLength={1000}
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                />
              </label>
              <div className="actions">
                <button
                  type="button"
                  className="button button--primary"
                  disabled={busy || reason.trim().length < 3}
                  onClick={() =>
                    void execute(() => threatIntelApi.matchAction(data.match_id, pending, data.version, reason))
                  }
                >
                  Confirmar: {MATCH_ACTION_LABELS[pending]}
                </button>
                <button type="button" className="button" onClick={() => setPending(undefined)}>
                  Cancelar
                </button>
              </div>
            </div>
          )}
        </section>
      )}

      <section className="panel panel--padded">
        <h2>Qué coincide</h2>
        <dl className="fields">
          <div className="field">
            <dt>Dato local</dt>
            <dd>
              {OBSERVATION_LABELS[data.observation_type]}: <span className="mono">{data.observed_value}</span>
              <div className="muted small mono">{data.observed_field}</div>
            </dd>
          </div>
          <div className="field">
            <dt>Indicador</dt>
            <dd>
              <Link className="mono" to={`/threat-intel/indicators/${data.indicator_id}`}>
                {data.indicator_value}
              </Link>{" "}
              ({INDICATOR_TYPE_LABELS[data.indicator_type] ?? data.indicator_type},{" "}
              {INDICATOR_STATE_LABELS[data.indicator_state] ?? data.indicator_state})
            </dd>
          </div>
          <div className="field">
            <dt>Fuente</dt>
            <dd>
              {data.source_name} <TrustBadge trust={data.source_trust} />
            </dd>
          </div>
          <div className="field">
            <dt>Confianza del indicador / de la coincidencia</dt>
            <dd>
              {CONFIDENCE_LABELS[data.indicator_confidence]} / {CONFIDENCE_LABELS[data.match_confidence]}
            </dd>
          </div>
          <div className="field">
            <dt>Observado</dt>
            <dd>
              {data.observation_count} veces · primera {formatDateTime(data.first_observed_at)} · última{" "}
              {formatRelative(data.last_observed_at)}
            </dd>
          </div>
          <div className="field">
            <dt>Estado</dt>
            <dd>
              <MatchStatusBadge status={data.status} /> · {data.status_changed_by},{" "}
              {formatRelative(data.status_changed_at)}
              {data.status_reason && <div className="small">Motivo: {data.status_reason}</div>}
            </dd>
          </div>
          {data.detection_id && (
            <div className="field">
              <dt>Detección</dt>
              <dd>
                <Link to={`/detections/${data.detection_id}`}>Threat Intel IOC Match (TI-001)</Link>
              </dd>
            </div>
          )}
        </dl>
      </section>

      {evidence.length > 0 && (
        <section className="panel panel--padded">
          <h2>Evidencia local</h2>
          <dl className="fields">
            {evidence.map(([key, value]) => (
              <div className="field" key={key}>
                <dt className="mono small">{key}</dt>
                <dd className="mono small">{typeof value === "object" ? JSON.stringify(value) : String(value)}</dd>
              </div>
            ))}
          </dl>
        </section>
      )}

      {data.incidents.length > 0 && (
        <section className="panel">
          <h2 className="panel__title">Incidentes</h2>
          <ul>
            {data.incidents.map((i) => (
              <li key={i.incident_id}>
                <Link to={`/incidents/${i.incident_id}`}>
                  {i.key} · {i.title}
                </Link>{" "}
                <span className="muted small">({i.status})</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
