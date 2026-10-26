import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { endpointApi, exclusionsApi } from "../api/sentra6e";
import type { DetectionExclusion } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ExclusionDialog } from "../components/detections/ExclusionDialog";
import { ConfirmDialog } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { EXCLUSION_FIELD_LABELS, formatSeconds } from "../lib/endpoint";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";

const REFRESH_MS = 60_000;

/**
 * Excepciones de reglas integradas (Fase 6E.5), junto a las reglas de detección. Cada
 * excepción es un valor exacto (ejecutable, nombre, hash, firmante, padre o IP remota) con
 * justificación y, opcionalmente, caducidad. Fase 7A.8: SCR-001, CORR-002 y NET-001 solo
 * admiten excepciones exactas (script con su hash, o ejecutable en un puerto de un equipo) y
 * con caducidad; el formulario lo aplica y el servidor lo vuelve a comprobar. Ver: rules:read; crear y revocar: rules:manage.
 * Con telemetry:read se muestran además la ingesta y la latencia medidas de la detección
 * conductual (BEH-*), que es periódica, no en tiempo real.
 */
export function DetectionExclusionsPage() {
  const auth = useAuth();
  const canManage = auth.can("rules:manage");
  const [includeInactive, setIncludeInactive] = useState(false);
  const fetcher = useCallback(
    (signal: AbortSignal) => exclusionsApi.list(includeInactive, signal),
    [includeInactive],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS, true, true);
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<DetectionExclusion>();

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <Link to="/detections/rules" className="back">
            ← Reglas
          </Link>
          <h1>Excepciones de detección</h1>
          <p className="muted small">
            Valores exactos que una regla integrada no debe tener en cuenta (por ejemplo, una herramienta de administración
            legítima). Toda excepción lleva su justificación y queda auditada.
          </p>
        </div>
        {canManage && (
          <div className="actions">
            <button type="button" className="button button--primary" onClick={() => setCreating(true)}>
              Nueva excepción
            </button>
          </div>
        )}
      </div>

      {auth.can("telemetry:read") && <BehaviorMetrics />}

      <section className="panel">
        <div className="panel__toolbar panel__toolbar--filters">
          <h2>Excepciones</h2>
          <label className="checkbox small">
            <input type="checkbox" checked={includeInactive} onChange={(e) => setIncludeInactive(e.target.checked)} /> Incluir
            revocadas y caducadas
          </label>
        </div>
        {loading ? (
          <LoadingState label="Cargando excepciones…" />
        ) : !data ? (
          <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
        ) : data.items.length === 0 ? (
          <EmptyState title="Sin excepciones">Ninguna regla tiene excepciones {includeInactive ? "" : "activas "}ahora.</EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Regla</th>
                  <th>Campo</th>
                  <th>Valor</th>
                  <th>Justificación</th>
                  <th className="col-secondary">Alcance</th>
                  <th className="col-secondary">Coincidencias</th>
                  <th className="col-secondary">Caduca</th>
                  {canManage && <th />}
                </tr>
              </thead>
              <tbody>
                {data.items.map((x) => (
                  <tr key={x.id}>
                    <td className="mono">
                      {x.rule_id}
                      {!x.active && <span className="badge badge--muted">{x.revoked_at ? "revocada" : "caducada"}</span>}
                    </td>
                    <td>{EXCLUSION_FIELD_LABELS[x.field] ?? x.field}</td>
                    <td className="mono small">
                      {x.value}
                      {/* Fase 7A.8: condiciones que además deben coincidir. */}
                      {x.require_sha256 && <div className="muted">con SHA-256 {x.require_sha256}</div>}
                      {x.port !== null && x.port !== undefined && <div className="muted">en el puerto {x.port}</div>}
                    </td>
                    <td className="small">
                      {x.reason}
                      <div className="muted">
                        {x.created_by} · {formatDateTime(x.created_at)}
                      </div>
                    </td>
                    <td className="col-secondary">{x.asset_id ? (x.asset_name ?? "un equipo") : "Todos los equipos"}</td>
                    <td className="col-secondary">
                      {x.hits}
                      {x.last_hit_at && <span className="muted small"> · {formatRelative(x.last_hit_at)}</span>}
                    </td>
                    <td className="col-secondary">{x.expires_at ? formatDateTime(x.expires_at) : "Nunca"}</td>
                    {canManage && (
                      <td>
                        {x.active && (
                          <button type="button" className="button button--small" onClick={() => setRevoking(x)}>
                            Revocar
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {creating && (
        <ExclusionDialog
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            refresh();
          }}
        />
      )}
      {revoking && (
        <ConfirmDialog
          title="Revocar excepción"
          confirmLabel="Revocar"
          danger
          onClose={() => setRevoking(undefined)}
          onConfirm={async () => {
            await exclusionsApi.revoke(revoking.id);
            refresh();
          }}
        >
          La regla <span className="mono">{revoking.rule_id}</span> volverá a evaluar{" "}
          <span className="mono">{revoking.value}</span>.
        </ConfirmDialog>
      )}
    </div>
  );
}

function BehaviorMetrics() {
  const fetcher = useCallback((signal: AbortSignal) => endpointApi.metrics(signal), []);
  const { data } = usePolling(fetcher, REFRESH_MS);
  if (!data) return null;
  return (
    <section className="panel panel--padded stack" aria-label="Detección conductual">
      <h2 className="panel__title">Detección conductual (BEH-001 a BEH-006)</h2>
      <dl className="fields">
        <div className="field">
          <dt>Detecciones en 24 h</dt>
          <dd>{data.behavior_detections_24h}</dd>
        </div>
        <div className="field">
          <dt>Latencia evidencia → detección (p50 / p95)</dt>
          <dd>
            {formatSeconds(data.detection_latency_p50_seconds)} / {formatSeconds(data.detection_latency_p95_seconds)}
          </dd>
        </div>
        <div className="field">
          <dt>Ingesta evento → servidor (p50 / p95)</dt>
          <dd>
            {formatSeconds(data.ingest_lag_p50_seconds)} / {formatSeconds(data.ingest_lag_p95_seconds)}
          </dd>
        </div>
        <div className="field">
          <dt>Equipos enviando actividad (última hora)</dt>
          <dd>
            {data.assets_reporting_last_hour} · {data.events_last_hour} eventos
          </dd>
        </div>
      </dl>
      <p className="muted small">El motor evalúa periódicamente: la latencia medida es la referencia, no «tiempo real».</p>
    </section>
  );
}
