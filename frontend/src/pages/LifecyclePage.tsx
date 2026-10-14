import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { lifecycleApi } from "../api/sentra";
import type { CleanupAction, CleanupCandidate, CleanupResult, LifecycleSource } from "../api/types";
import { Pager } from "../components/ListControls";
import { ConfirmDialog } from "../components/Modal";
import { MethodBadge } from "../components/NetworkBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { LifecycleBadge } from "../components/StatusBadge";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import {
  CLEANUP_ACTION_LABELS,
  CLEANUP_ACTION_ORDER,
  IRREVERSIBLE_WARNING,
  SOURCE_LABELS,
  formatHours,
  historyText,
  reasonLabel,
} from "../lib/lifecycle";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;
// La vista previa es costosa y la selección depende de ella: se refresca a mano o tras ejecutar.
const PREVIEW_REFRESH_MS = 5 * 60_000;

const OUTCOME_LABELS: Record<CleanupResult["results"][number]["outcome"], string> = {
  deleted: "Eliminado",
  archived: "Archivado",
  skipped: "Omitido",
};

type Dialog = "archive" | "delete";

/**
 * Administración → Ciclo de vida (Fase 5C.2; solo assets:manage, que la API exige igualmente).
 * Muestra la política de limpieza, la vista previa paginada y permite archivar o eliminar
 * definitivamente por lotes. El servidor re-evalúa cada activo al ejecutar.
 */
export function LifecyclePage() {
  const [action, setAction] = useState<CleanupAction | "">("");
  const [source, setSource] = useState<LifecycleSource | "">("");
  const [page, setPage] = useState(1);
  // Selección por asset_id con la fila tal y como se vio (su versión va al servidor).
  const [selected, setSelected] = useState<Map<string, CleanupCandidate>>(new Map());
  const [dialog, setDialog] = useState<Dialog>();
  const [reason, setReason] = useState("");
  const [result, setResult] = useState<CleanupResult>();

  const fetchPreview = useCallback(
    (signal: AbortSignal) =>
      lifecycleApi.cleanupPreview(
        { action: action || undefined, source: source || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
        signal,
      ),
    [action, source, page],
  );
  const preview = usePolling(fetchPreview, PREVIEW_REFRESH_MS, true, true);

  const resetSelection = () => setSelected(new Map());
  const changeAction = (next: CleanupAction | "") => {
    setAction(next);
    setPage(1);
    resetSelection();
  };
  const changeSource = (next: LifecycleSource | "") => {
    setSource(next);
    setPage(1);
    resetSelection();
  };

  if (preview.loading) return <LoadingState label="Cargando ciclo de vida…" />;
  if (!preview.data) {
    return <ErrorState message={preview.error ? errorMessage(preview.error) : "Sin datos"} onRetry={preview.refresh} />;
  }

  const data = preview.data;
  const policy = data.policy;
  const batchSize = Math.max(1, policy.batch_size);
  const pages = Math.max(1, Math.ceil(data.total / PAGE_SIZE));
  const chosen = [...selected.values()];
  const deletable = chosen.filter((c) => c.hard_delete_eligible);
  const full = selected.size >= batchSize;

  const toggle = (candidate: CleanupCandidate) => {
    setSelected((prev) => {
      const next = new Map(prev);
      if (next.has(candidate.asset_id)) next.delete(candidate.asset_id);
      else if (next.size < batchSize) next.set(candidate.asset_id, candidate);
      return next;
    });
  };
  const allOnPage = data.items.length > 0 && data.items.every((c) => selected.has(c.asset_id));
  const togglePage = () => {
    setSelected((prev) => {
      const next = new Map(prev);
      if (allOnPage) {
        for (const c of data.items) next.delete(c.asset_id);
      } else {
        for (const c of data.items) if (next.size < batchSize) next.set(c.asset_id, c);
      }
      return next;
    });
  };

  async function execute(kind: "archive" | "hard_delete") {
    const rows = kind === "hard_delete" ? deletable : chosen;
    // Nunca más de un lote: el servidor responde 422 si se excede.
    const items = rows.slice(0, batchSize).map((c) => ({ asset_id: c.asset_id, version: c.version }));
    if (items.length === 0) throw new Error("No hay activos seleccionados que cumplan las condiciones.");
    let done: CleanupResult;
    if (kind === "archive") {
      const text = reason.trim();
      if (text.length < 3) throw new Error("Indica un motivo (mínimo 3 caracteres).");
      done = await lifecycleApi.cleanup("archive", items, text);
    } else {
      done = await lifecycleApi.cleanup("hard_delete", items);
    }
    setResult(done);
    setReason("");
    resetSelection();
    preview.refresh();
  }

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Ciclo de vida</h1>
          <p className="muted small">
            Activos inactivos según la política de limpieza. Vista previa generada {formatRelative(data.generated_at)}.
          </p>
        </div>
        <button type="button" className="button" onClick={preview.refresh} disabled={preview.refreshing}>
          {preview.refreshing ? "Actualizando…" : "Actualizar"}
        </button>
      </div>

      {preview.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(preview.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="panel" aria-label="Política de limpieza">
        <div className="panel__toolbar">
          <h2>Política</h2>
          <span className={`badge ${policy.auto_cleanup ? "badge--warn" : "badge--muted"}`}>
            Limpieza automática {policy.auto_cleanup ? "activada" : "desactivada"}
          </span>
        </div>
        <dl className="fields">
          <div className="field">
            <dt>Descubiertos: stale tras</dt>
            <dd>
              {policy.discovered_stale_after_hours} h y {policy.discovered_stale_missed_scans} escaneos completos sin
              verlos
            </dd>
          </div>
          <div className="field">
            <dt>Descubiertos: ventana de purga</dt>
            <dd>{policy.discovered_purge_after_days} días</dd>
          </div>
          <div className="field">
            <dt>Gestionados: stale tras</dt>
            <dd>{policy.managed_stale_after_days} días sin contacto</dd>
          </div>
          <div className="field">
            <dt>Máximo por lote</dt>
            <dd>{policy.batch_size}</dd>
          </div>
        </dl>
      </section>

      <section className="stats stats--5" aria-label="Activos por acción">
        {CLEANUP_ACTION_ORDER.map((key) => (
          <button
            key={key}
            type="button"
            className={`stat${action === key ? " stat--active" : ""}`}
            aria-pressed={action === key}
            onClick={() => changeAction(action === key ? "" : key)}
          >
            <span className="stat__label">{CLEANUP_ACTION_LABELS[key]}</span>
            <span className="stat__value">{data.counts[key] ?? 0}</span>
          </button>
        ))}
      </section>

      {result && <ResultPanel result={result} onDismiss={() => setResult(undefined)} />}

      <section className="panel">
        <div className="panel__toolbar">
          <h2>
            Vista previa <span className="muted">({data.total})</span>
          </h2>
          <select
            className="input input--select"
            aria-label="Acción"
            value={action}
            onChange={(event) => changeAction(event.target.value as CleanupAction | "")}
          >
            <option value="">Acción: todas</option>
            {CLEANUP_ACTION_ORDER.map((key) => (
              <option key={key} value={key}>
                {CLEANUP_ACTION_LABELS[key]}
              </option>
            ))}
          </select>
          <select
            className="input input--select"
            aria-label="Origen"
            value={source}
            onChange={(event) => changeSource(event.target.value as LifecycleSource | "")}
          >
            <option value="">Origen: todos</option>
            {(Object.keys(SOURCE_LABELS) as LifecycleSource[]).map((key) => (
              <option key={key} value={key}>
                {SOURCE_LABELS[key]}
              </option>
            ))}
          </select>
        </div>
        <div className="panel__toolbar">
          <span className="muted small" aria-live="polite">
            {selected.size} seleccionados{full && ` (máximo ${batchSize} por lote)`} · {deletable.length} eliminables
          </span>
          <span>
            <button
              type="button"
              className="button button--small"
              disabled={selected.size === 0}
              onClick={() => setDialog("archive")}
            >
              Archivar seleccionados
            </button>{" "}
            <button
              type="button"
              className="button button--small button--danger"
              disabled={deletable.length === 0}
              onClick={() => setDialog("delete")}
            >
              Eliminar definitivamente
            </button>
          </span>
        </div>
        {data.items.length === 0 ? (
          <EmptyState title="No hay activos inactivos con estos filtros" />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>
                    <input type="checkbox" aria-label="Seleccionar la página" checked={allOnPage} onChange={togglePage} />
                  </th>
                  <th>Activo</th>
                  <th>IP</th>
                  <th>Origen</th>
                  <th>Estado</th>
                  <th>Última actividad</th>
                  <th title="Escaneos completos y exitosos seguidos sin verlo">Escaneos perdidos</th>
                  <th>Inactivo</th>
                  <th>Acción</th>
                  <th>Motivos de bloqueo</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((c) => (
                  <tr key={c.asset_id}>
                    <td>
                      <input
                        type="checkbox"
                        aria-label={`Seleccionar ${c.display_name}`}
                        checked={selected.has(c.asset_id)}
                        disabled={!selected.has(c.asset_id) && full}
                        onChange={() => toggle(c)}
                      />
                    </td>
                    <td>
                      <Link to={`/assets/${c.asset_id}`} className="strong">
                        {c.display_name}
                      </Link>
                      {c.mac_address && <div className="muted small mono">{c.mac_address}</div>}
                    </td>
                    <td className="mono">{c.primary_ip}</td>
                    <td>
                      {SOURCE_LABELS[c.lifecycle_source] ?? c.lifecycle_source} <MethodBadge method={c.monitoring_method} />
                    </td>
                    <td>
                      <LifecycleBadge state={c.lifecycle_state} />
                    </td>
                    <td title={formatDateTime(c.last_activity_at)}>{formatRelative(c.last_activity_at)}</td>
                    <td>{c.missed_successful_scans}</td>
                    <td>{formatHours(c.stale_for_hours)}</td>
                    <td>
                      <span className={`badge ${c.hard_delete_eligible ? "badge--crit" : c.action === "blocked" ? "badge--warn" : "badge--muted"}`}>
                        {CLEANUP_ACTION_LABELS[c.action] ?? c.action}
                      </span>
                    </td>
                    <td className="small">
                      {c.blocking_reasons.length > 0 ? c.blocking_reasons.map(reasonLabel).join("; ") : "—"}
                      {Object.keys(c.dependencies).length > 0 && (
                        <div className="muted">Dependencias: {historyText(c.dependencies)}</div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {data.total > 0 && (
          <Pager
            page={page}
            pages={pages}
            total={data.total}
            noun="activos"
            onPage={(next) => {
              setPage(next);
              resetSelection();
            }}
          />
        )}
      </section>

      {dialog === "archive" && (
        <ConfirmDialog
          title="Archivar seleccionados"
          confirmLabel="Archivar"
          onClose={() => setDialog(undefined)}
          onConfirm={() => execute("archive")}
        >
          <p>
            Se archivarán {Math.min(chosen.length, batchSize)} activos: dejan de mostrarse por defecto y de contar en el
            resumen, conservando todo su historial. Se pueden restaurar. El servidor omite los que ya no estén inactivos o
            tengan un agente con credencial activa.
          </p>
          <label className="form-field">
            Motivo
            <textarea
              className="input"
              rows={3}
              maxLength={500}
              value={reason}
              onChange={(event) => setReason(event.target.value)}
              placeholder="Equipos retirados de la red…"
            />
          </label>
        </ConfirmDialog>
      )}
      {dialog === "delete" && (
        <ConfirmDialog
          title="Eliminar definitivamente"
          confirmLabel="Eliminar definitivamente"
          danger
          onClose={() => setDialog(undefined)}
          onConfirm={() => execute("hard_delete")}
        >
          <p className="banner banner--warn">{IRREVERSIBLE_WARNING}</p>
          <p>
            Se eliminarán {Math.min(deletable.length, batchSize)} activos elegibles
            {chosen.length > deletable.length &&
              ` (se ignoran ${chosen.length - deletable.length} seleccionados que no son elegibles)`}
            . El servidor vuelve a comprobar cada uno y omite los que hayan cambiado.
          </p>
          <ul className="small" aria-label="Activos a eliminar">
            {deletable.slice(0, batchSize).map((c) => (
              <li key={c.asset_id}>
                <strong>{c.display_name}</strong> · <span className="mono">{c.primary_ip}</span> ·{" "}
                <span className="mono muted">{c.asset_id}</span>
              </li>
            ))}
          </ul>
        </ConfirmDialog>
      )}
    </div>
  );
}

function ResultPanel({ result, onDismiss }: { result: CleanupResult; onDismiss: () => void }) {
  return (
    <section className="panel" aria-label="Resultado de la limpieza">
      <div className="panel__toolbar">
        <h2>Resultado</h2>
        <span className="small">
          {result.requested} solicitados · {result.succeeded} {result.action === "archive" ? "archivados" : "eliminados"} ·{" "}
          {result.skipped} omitidos
        </span>
        <button type="button" className="button button--ghost button--small" onClick={onDismiss}>
          Cerrar
        </button>
      </div>
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>Activo</th>
              <th>Resultado</th>
              <th>Motivos</th>
            </tr>
          </thead>
          <tbody>
            {result.results.map((r) => (
              <tr key={r.asset_id}>
                <td>
                  {r.outcome === "deleted" ? (
                    (r.display_name ?? <span className="mono">{r.asset_id}</span>)
                  ) : (
                    <Link to={`/assets/${r.asset_id}`}>{r.display_name ?? r.asset_id}</Link>
                  )}
                </td>
                <td>
                  <span className={`badge ${r.outcome === "skipped" ? "badge--warn" : "badge--ok"}`}>
                    {OUTCOME_LABELS[r.outcome] ?? r.outcome}
                  </span>
                </td>
                <td className="small">{r.reasons.length > 0 ? r.reasons.map(reasonLabel).join("; ") : "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
