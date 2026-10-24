import { useCallback, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { endpointApi, exclusionsApi } from "../api/sentra6e";
import type { DetectionExclusion, DetectionExclusionField } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog, Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { EXCLUSION_FIELD_LABELS, formatSeconds } from "../lib/endpoint";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";

const REFRESH_MS = 60_000;
const RULE_ID = /^[A-Z0-9-]{3,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Excepciones de reglas integradas (Fase 6E.5), junto a las reglas de detección. Cada
 * excepción es un valor exacto (ejecutable, nombre, hash, firmante, padre o IP remota) con
 * justificación y, opcionalmente, caducidad. Ver: rules:read; crear y revocar: rules:manage.
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
                    <td className="mono small">{x.value}</td>
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
        <CreateExclusionDialog
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

function CreateExclusionDialog({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [ruleId, setRuleId] = useState("");
  const [field, setField] = useState<DetectionExclusionField>("exe");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [assetId, setAssetId] = useState("");
  const [expires, setExpires] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const errors: string[] = [];
  if (!RULE_ID.test(ruleId.trim())) errors.push("Indica el identificador de la regla (p. ej. BEH-001).");
  if (!value.trim() || value.length > 1024) errors.push("Indica el valor exacto (máx. 1024 caracteres).");
  if (reason.trim().length < 3) errors.push("La justificación es obligatoria (mín. 3 caracteres).");
  if (assetId.trim() && !UUID.test(assetId.trim())) errors.push("El identificador de equipo no es válido.");
  const expiresAt = expires ? new Date(expires) : undefined;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) errors.push("La fecha de caducidad no es válida.");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (errors.length) return;
    // Se comprueba al enviar (no al dibujar): «ahora» cambia entre renders.
    if (expiresAt && expiresAt.getTime() <= Date.now()) {
      setError("La caducidad debe ser una fecha futura.");
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await exclusionsApi.create({
        rule_id: ruleId.trim(),
        field,
        value: value.trim(),
        reason: reason.trim(),
        asset_id: assetId.trim() || null,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
      });
      onCreated();
    } catch (err) {
      setError(errorMessage(toError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Nueva excepción" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
        <label className="form-field">
          <span>Regla</span>
          <input
            className="input mono"
            value={ruleId}
            placeholder="BEH-001"
            maxLength={64}
            onChange={(e) => setRuleId(e.target.value.toUpperCase())}
            disabled={busy}
          />
        </label>
        <label className="form-field">
          <span>Campo</span>
          <select
            className="input input--select"
            value={field}
            onChange={(e) => setField(e.target.value as DetectionExclusionField)}
            disabled={busy}
          >
            {Object.entries(EXCLUSION_FIELD_LABELS).map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="form-field">
          <span>Valor exacto</span>
          <input className="input mono" value={value} maxLength={1024} onChange={(e) => setValue(e.target.value)} disabled={busy} />
        </label>
        <label className="form-field">
          <span>Justificación</span>
          <textarea className="input" rows={2} value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} disabled={busy} />
        </label>
        <label className="form-field">
          <span>Solo para el equipo (identificador, opcional)</span>
          <input className="input mono" value={assetId} onChange={(e) => setAssetId(e.target.value)} disabled={busy} />
        </label>
        <label className="form-field">
          <span>Caduca (opcional)</span>
          <input className="input" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} disabled={busy} />
        </label>
        {errors.length > 0 && (ruleId || value || reason) && (
          <ul className="plain-list small text-crit">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || errors.length > 0}>
            {busy ? "Creando…" : "Crear excepción"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
