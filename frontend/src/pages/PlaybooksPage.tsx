import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { responseApi } from "../api/sentra";
import type { Playbook } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { PlaybookEditor } from "../components/response/PlaybookEditor";
import { RunsTable } from "../components/response/HistoryTables";
import { RiskBadge } from "../components/response/ResponseViews";
import { RunPlaybookDialog } from "../components/response/RunPlaybookDialog";
import { Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { ROLE_REQUIRED_LABELS } from "../lib/response";
import { useAssetOptions } from "../lib/useAssetOptions";
import { usePolling } from "../lib/usePolling";

const TABS = [
  { key: "playbooks", label: "Playbooks" },
  { key: "runs", label: "Ejecuciones" },
] as const;
type Tab = (typeof TABS)[number]["key"];

function PlaybookCard({
  playbook,
  canExecute,
  canManage,
  onEdit,
  onRun,
  onChanged,
}: {
  playbook: Playbook;
  canExecute: boolean;
  canManage: boolean;
  onEdit: () => void;
  onRun: () => void;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const toggle = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await responseApi.setPlaybookEnabled(playbook.playbook_id, playbook.revision, !playbook.enabled);
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
      // Revisión obsoleta: se recarga la lista para que el siguiente intento use la actual.
      if (err instanceof ApiError && err.code === "response_conflict") onChanged();
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel panel--padded stack" aria-label={playbook.name}>
      <div className="page__header">
        <div>
          <h2 className="panel__title">
            {playbook.name} <span className="muted small">v{playbook.version}</span>
          </h2>
          <div className="detection-badges">
            <span className="badge">{playbook.builtin ? "Integrado" : "Personalizado"}</span>
            {playbook.enabled ? (
              <span className="badge badge--ok">Activo</span>
            ) : (
              <span className="badge badge--muted">Desactivado</span>
            )}
            <RiskBadge risk={playbook.risk_level} />
            <span className="muted small">
              Rol mínimo: {ROLE_REQUIRED_LABELS[playbook.required_role] ?? playbook.required_role}
            </span>
            {playbook.requires_confirmation && <span className="muted small">· Requiere confirmación</span>}
          </div>
        </div>
        <div className="actions">
          {canExecute && (
            <button type="button" className="button button--small" disabled={!playbook.enabled} onClick={onRun}>
              Ejecutar
            </button>
          )}
          {canManage && !playbook.builtin && (
            <button type="button" className="button button--small" onClick={onEdit}>
              Editar
            </button>
          )}
          {canManage && (
            <button type="button" className="button button--small" disabled={busy} onClick={() => void toggle()}>
              {playbook.enabled ? "Desactivar" : "Activar"}
            </button>
          )}
        </div>
      </div>
      {playbook.description && <p className="muted small">{playbook.description}</p>}
      <ol>
        {playbook.steps.map((step) => (
          <li key={step.order}>
            {step.action_name} <RiskBadge risk={step.risk_level} />
            {step.on_failure === "continue" && <span className="muted small"> · continúa si falla</span>}
            {Object.keys(step.parameters).length > 0 && (
              <span className="muted small mono"> {JSON.stringify(step.parameters)}</span>
            )}
          </li>
        ))}
      </ol>
      <p className="muted small">
        Creado por {playbook.created_by} · actualizado{" "}
        <span title={formatDateTime(playbook.updated_at)}>{formatRelative(playbook.updated_at)}</span>
      </p>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}

function PlaybooksTab() {
  const auth = useAuth();
  const canManage = auth.can("response:manage");
  const canExecute = auth.can("response:execute");
  const fetcher = useCallback((signal: AbortSignal) => responseApi.playbooks(undefined, signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  const [editing, setEditing] = useState<Playbook | "new">();
  const [running, setRunning] = useState<Playbook>();

  if (loading) return <LoadingState label="Cargando playbooks…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  return (
    <div className="stack">
      {canManage && (
        <div className="actions">
          <button type="button" className="button button--primary" onClick={() => setEditing("new")}>
            Nuevo playbook
          </button>
        </div>
      )}
      {data.items.length === 0 ? (
        <EmptyState title="Sin playbooks" />
      ) : (
        data.items.map((playbook) => (
          <PlaybookCard
            key={playbook.playbook_id}
            playbook={playbook}
            canExecute={canExecute}
            canManage={canManage}
            onEdit={() => setEditing(playbook)}
            onRun={() => setRunning(playbook)}
            onChanged={refresh}
          />
        ))
      )}
      {editing && (
        <PlaybookEditor
          playbook={editing === "new" ? undefined : editing}
          onClose={() => setEditing(undefined)}
          onSaved={() => {
            setEditing(undefined);
            refresh();
          }}
        />
      )}
      {running && <RunPlaybookFromList playbook={running} onClose={() => setRunning(undefined)} />}
    </div>
  );
}

/** Desde la lista no hay activo de contexto: se elige con el selector de activos. */
function RunPlaybookFromList({ playbook, onClose }: { playbook: Playbook; onClose: () => void }) {
  const [assetId, setAssetId] = useState("");
  const [label, setLabel] = useState("");
  if (!assetId) {
    return (
      <AssetChooser
        title={`Ejecutar: ${playbook.name}`}
        onClose={onClose}
        onChoose={(id, chosenLabel) => {
          setAssetId(id);
          setLabel(chosenLabel);
        }}
      />
    );
  }
  return (
    <RunPlaybookDialog
      title={`Ejecutar: ${playbook.name}`}
      targets={[{ assetId, label }]}
      playbookKeys={[playbook.key]}
      onClose={onClose}
    />
  );
}

/** Paso previo: elegir el activo objetivo (búsqueda en el servidor, como en otros selectores). */
function AssetChooser({
  title,
  onClose,
  onChoose,
}: {
  title: string;
  onClose: () => void;
  onChoose: (assetId: string, label: string) => void;
}) {
  const [query, setQuery] = useState("");
  const options = useAssetOptions(query);
  const [selected, setSelected] = useState("");
  const chosen = options.find((o) => o.asset_id === selected);
  return (
    <Modal title={title} onClose={onClose}>
      <div className="stack">
        <label className="form-field">
          <span className="muted small">Activo objetivo</span>
          <input
            className="input"
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Buscar por nombre o IP"
            aria-label="Buscar activo"
          />
          <select
            className="input input--select"
            aria-label="Activo objetivo"
            value={selected}
            onChange={(e) => setSelected(e.target.value)}
          >
            <option value="">Elige un activo</option>
            {options.map((asset) => (
              <option key={asset.asset_id} value={asset.asset_id}>
                {asset.display_name}
                {asset.primary_ip ? ` · ${asset.primary_ip}` : ""}
              </option>
            ))}
          </select>
        </label>
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose}>
            Cancelar
          </button>
          <button
            type="button"
            className="button button--primary"
            disabled={!chosen}
            onClick={() => chosen && onChoose(chosen.asset_id, chosen.display_name)}
          >
            Continuar
          </button>
        </div>
      </div>
    </Modal>
  );
}

/** Playbooks (Fase 5D): secuencias aprobadas de acciones del catálogo y su historial. */
export function PlaybooksPage() {
  const [params, setParams] = useSearchParams();
  const requested = params.get("tab");
  const tab: Tab = TABS.some((t) => t.key === requested) ? (requested as Tab) : "playbooks";
  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Playbooks</h1>
          <p className="muted small">
            Secuencias de acciones del catálogo de response. Cada paso pasa por la misma política que una acción
            manual; un fallo detiene el playbook salvo en pasos de bajo riesgo marcados para continuar.
          </p>
        </div>
      </div>
      <nav className="tabs" role="tablist" aria-label="Secciones de playbooks">
        {TABS.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setParams(key === "playbooks" ? {} : { tab: key }, { replace: true })}
          >
            {label}
          </button>
        ))}
      </nav>
      <div role="tabpanel">
        {tab === "playbooks" && <PlaybooksTab />}
        {tab === "runs" && (
          <RunsTable
            selected={params.get("run") ?? undefined}
            onSelect={(id) => setParams(id ? { tab: "runs", run: id } : { tab: "runs" }, { replace: true })}
          />
        )}
      </div>
    </div>
  );
}
