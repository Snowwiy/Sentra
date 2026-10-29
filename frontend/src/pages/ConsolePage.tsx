import { useCallback, useEffect, useMemo, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { detectionsApi, sentraApi } from "../api/sentra";
import { searchApi, toolsApi } from "../api/sentra7b";
import type { SearchResult, SearchUser, ToolExecutionOut, ToolOut } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { AddToCaseDialog, type CaseEvidenceKind } from "../components/console/AddToCaseDialog";
import { ExecutionStatus, ToolOutput } from "../components/console/ToolOutput";
import { CATEGORY_LABELS, ToolRunner } from "../components/console/ToolRunner";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";

const KIND_LABELS: Record<SearchResult["kind"], string> = {
  ip: "dirección IP",
  mac: "dirección MAC",
  sha256: "SHA-256",
  rule: "id de regla",
  case: "número de caso",
  text: "texto",
};

/** Número para mostrar: un valor ausente o no finito se muestra como "—", nunca como NaN. */
export function count(value: unknown): string {
  return typeof value === "number" && Number.isFinite(value) ? String(value) : "—";
}

const USER_ROLE_LABELS: Record<SearchUser["role"], string> = {
  admin: "Administrador",
  analyst: "Analista",
  viewer: "Lector",
};

type Entity = { type: "asset" | "detection"; id: string };

/** Ids del contexto del workspace por campo de entrada (asset_id, detection_id). */
export type WorkspaceContext = Partial<Record<"asset_id" | "detection_id", string>>;

function requiredOf(tool: ToolOut): string[] {
  return (tool.input_schema.required as string[] | undefined) ?? [];
}

// Herramientas que se ofrecen como atajo para el workspace: las que solo necesitan ids que el
// contexto ya tiene (el resto de campos tienen valor por defecto). Las acciones no son atajos:
// se lanzan desde el catálogo, con vista previa.
export function quickTools(tools: ToolOut[], context: WorkspaceContext): ToolOut[] {
  return tools.filter((t) => {
    const required = requiredOf(t);
    return (
      t.policy !== "preview_confirm" &&
      required.length > 0 &&
      required.every((name) => context[name as keyof WorkspaceContext] !== undefined)
    );
  });
}

/** Fase 7B-Fix1: ¿la herramienta encaja con el contexto? (todo lo obligatorio es un id que
 * el workspace aporta, o un campo que no es un id de entidad). */
export function compatibleWith(tool: ToolOut, context: WorkspaceContext): boolean {
  return requiredOf(tool).every(
    (name) => !name.endsWith("_id") || context[name as keyof WorkspaceContext] !== undefined,
  );
}

function SearchResults({ result, onPick }: { result: SearchResult; onPick: (entity: Entity) => void }) {
  const users = result.users ?? [];
  const empty =
    result.assets.length +
      result.detections.length +
      result.incidents.length +
      result.operations.length +
      users.length ===
    0;
  return (
    <div className="stack">
      <p className="small muted" role="status">
        Búsqueda interpretada como {KIND_LABELS[result.kind]}: «{result.query}».
      </p>
      {empty && <EmptyState title="Sin resultados" />}
      {result.assets.length > 0 && (
        <section aria-label="Activos encontrados">
          <h3>Activos</h3>
          <ul className="console-results">
            {result.assets.map((a) => (
              <li key={a.asset_id}>
                <button type="button" className="link-button strong" onClick={() => onPick({ type: "asset", id: a.asset_id })}>
                  {a.display_name}
                </button>{" "}
                <span className="mono small">{a.primary_ip}</span>
                {a.mac_address && <span className="mono small muted"> · {a.mac_address}</span>}
                {a.archived && <span className="badge badge--muted">Archivado</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.detections.length > 0 && (
        <section aria-label="Detecciones encontradas">
          <h3>Detecciones</h3>
          <ul className="console-results">
            {result.detections.map((d) => (
              <li key={d.detection_id}>
                <button
                  type="button"
                  className="link-button strong"
                  onClick={() => onPick({ type: "detection", id: d.detection_id })}
                >
                  {d.rule_id} · {d.title}
                </button>{" "}
                <span className="small muted">
                  {d.asset_name} · {formatRelative(d.last_seen_at)}
                </span>
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.incidents.length > 0 && (
        <section aria-label="Casos encontrados">
          <h3>Casos</h3>
          <ul className="console-results">
            {result.incidents.map((i) => (
              <li key={i.incident_id}>
                <Link to={`/incidents/${i.incident_id}`}>
                  INC-{String(i.number).padStart(6, "0")} · {i.title}
                </Link>
              </li>
            ))}
          </ul>
        </section>
      )}
      {result.operations.length > 0 && (
        <section aria-label="Operaciones de mantenimiento encontradas">
          <h3>Operaciones de mantenimiento</h3>
          <ul className="console-results">
            {result.operations.map((o) => (
              <li key={o.operation_id}>
                {o.title} <span className="small muted">({o.status}, {o.asset_name})</span>
                {o.artifact_path && <div className="mono small">{o.artifact_path}</div>}
              </li>
            ))}
          </ul>
        </section>
      )}
      {users.length > 0 && (
        <section aria-label="Usuarios encontrados">
          <h3>Usuarios de Sentra</h3>
          <ul className="console-results">
            {users.map((u) => (
              <li key={u.user_id}>
                <span className={u.active ? "strong" : "muted"}>{u.username}</span>{" "}
                <span className="small muted">
                  {USER_ROLE_LABELS[u.role]} · {u.open_cases === 1 ? "1 caso activo" : `${count(u.open_cases)} casos activos`}
                </span>
                {!u.active && <span className="badge badge--muted">Desactivado</span>}
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}

interface EntityInfo {
  label: string;
  // Fase 7B-Fix1: el activo de una detección entra en el contexto del workspace.
  assetId?: string;
}

/** Nombre legible de la entidad del workspace (en la URL solo va su id). */
function useEntityInfo({ type, id }: Entity) {
  const fetcher = useCallback(
    async (signal: AbortSignal): Promise<EntityInfo> => {
      if (type === "asset") {
        const asset = await sentraApi.getAsset(id, signal);
        return { label: `${asset.display_name} (${asset.primary_ip})`, assetId: asset.asset_id };
      }
      const detection = await detectionsApi.get(id, signal);
      return {
        label: [detection.rule_id, detection.title, detection.hostname].filter(Boolean).join(" · "),
        assetId: detection.asset_id,
      };
    },
    [type, id],
  );
  return usePolling(fetcher, config.refreshIntervalMs * 6, id !== "");
}

/** Detecciones activas del activo del workspace: se eligen con un clic, sin copiar ids. */
function AssetDetections({ assetId, current, onPick }: { assetId: string; current?: string; onPick: (id: string) => void }) {
  const fetcher = useCallback(
    (signal: AbortSignal) => detectionsApi.list({ assetId, active: true, limit: 10 }, signal),
    [assetId],
  );
  const state = usePolling(fetcher, config.refreshIntervalMs * 6);
  const items = state.data?.items ?? [];
  if (items.length === 0) return null;
  return (
    <div className="stack">
      <h3 className="small">Detecciones activas de este activo</h3>
      <ul className="console-results" aria-label="Detecciones del activo">
        {items.map((d) => (
          <li key={d.detection_id}>
            <button
              type="button"
              className="link-button"
              aria-pressed={current === d.detection_id}
              onClick={() => onPick(d.detection_id)}
            >
              {d.rule_id} · {d.title}
            </button>{" "}
            <span className="small muted">{formatRelative(d.last_seen_at)}</span>{" "}
            <Link to={`/detections/${d.detection_id}`} className="small">
              ficha
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
}

function ExecutionCard({
  execution,
  canExecute,
  onUpdate,
  onAddToCase,
}: {
  execution: ToolExecutionOut;
  canExecute: boolean;
  onUpdate: (execution: ToolExecutionOut) => void;
  onAddToCase: (execution: ToolExecutionOut) => void;
}) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const pending = execution.status === "previewed";
  const allowed = Boolean((execution.output?.preview as { allowed?: boolean } | undefined)?.allowed);
  const run = async (step: () => Promise<ToolExecutionOut>) => {
    setBusy(true);
    setError(undefined);
    try {
      onUpdate(await step());
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };
  return (
    <article className="panel panel--padded console-result" aria-label={`Resultado de ${execution.tool_name}`}>
      <header className="console-result__head">
        <h3>{execution.tool_name}</h3>
        <ExecutionStatus status={execution.status} />
        <span className="small muted">{CATEGORY_LABELS[execution.category] ?? execution.category}</span>
        {execution.target_label && <span className="small">· {execution.target_label}</span>}
      </header>
      <ToolOutput execution={execution} />
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      <div className="actions">
        {pending && canExecute && (
          <>
            <label className="field console-result__note">
              <span>Nota de aprobación (opcional)</span>
              <input className="input" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
            </label>
            <button
              type="button"
              className="button button--primary button--small"
              disabled={busy || !allowed}
              onClick={() => void run(() => toolsApi.confirm(execution.execution_id, execution.version, note))}
            >
              Confirmar y ejecutar
            </button>
            <button
              type="button"
              className="button button--small"
              disabled={busy}
              onClick={() => void run(() => toolsApi.cancel(execution.execution_id, execution.version))}
            >
              Descartar
            </button>
          </>
        )}
        {execution.status === "succeeded" && execution.category !== "action" && (
          <button type="button" className="button button--small" onClick={() => onAddToCase(execution)}>
            Añadir al caso…
          </button>
        )}
      </div>
    </article>
  );
}

/**
 * Analyst Console (Fase 7B.4). Una búsqueda global, un workspace con la entidad elegida
 * (activo o detección), atajos a las herramientas del motor 7A que encajan con ella, el
 * catálogo completo y el historial. No hay terminal ni consultas libres: cada botón es una
 * herramienta del registro cerrado, con RBAC, alcance de site y límites del servidor. La IA
 * no interviene.
 */
export function ConsolePage() {
  const auth = useAuth();
  const canExecute = auth.can("tools:execute");
  const { scopeId } = useSite();
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const assetParam = params.get("asset");
  const detectionParam = params.get("detection");
  // Con detección, el workspace es la detección (y su activo entra como contexto).
  const entity: Entity | undefined = detectionParam
    ? { type: "detection", id: detectionParam }
    : assetParam
      ? { type: "asset", id: assetParam }
      : undefined;
  const [onlyCompatible, setOnlyCompatible] = useState(true);
  const [draft, setDraft] = useState(q);
  const [search, setSearch] = useState<{ query: string; result?: SearchResult; error?: string }>();
  const [retry, setRetry] = useState(0);
  const [results, setResults] = useState<ToolExecutionOut[]>([]);
  const [selectedTool, setSelectedTool] = useState("");
  const [addTo, setAddTo] = useState<{ kind: CaseEvidenceKind; id: string; label: string; assetId?: string }>();
  const [notice, setNotice] = useState<{ text: string; ok: boolean }>();

  const fetchCatalog = useCallback((signal: AbortSignal) => toolsApi.catalog(signal), []);
  const catalog = usePolling(fetchCatalog, config.refreshIntervalMs * 6);
  const fetchHistory = useCallback((signal: AbortSignal) => toolsApi.executions({ limit: 20 }, signal), []);
  const history = usePolling(fetchHistory, config.refreshIntervalMs * 2);

  // La búsqueda vive en la URL (?q=): se puede enlazar y sobrevive a recargar.
  const query = q.trim();
  useEffect(() => {
    if (query.length < 2) return;
    const controller = new AbortController();
    searchApi
      .search(query, scopeId, controller.signal)
      .then((result) => setSearch({ query, result }))
      .catch((err: unknown) => {
        if (!controller.signal.aborted) {
          setSearch({ query, error: errorMessage(err instanceof Error ? err : new Error(String(err))) });
        }
      });
    return () => controller.abort();
  }, [query, scopeId, retry]);
  const current = search?.query === query ? search : undefined;
  const searching = query.length >= 2 && !current;

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const next = new URLSearchParams(params);
    next.set("q", draft.trim());
    setParams(next, { replace: true });
  };
  const pick = (picked: Entity) => {
    const next = new URLSearchParams(params);
    next.delete("asset");
    next.delete("detection");
    next.set(picked.type, picked.id);
    setParams(next, { replace: true });
  };
  const addResult = (execution: ToolExecutionOut) => {
    setResults((current) => [execution, ...current.filter((r) => r.execution_id !== execution.execution_id)].slice(0, 20));
    history.refresh();
  };

  const info = useEntityInfo(entity ?? { type: "asset", id: "" });
  const entityInfo = entity ? info.data : undefined;
  const context: WorkspaceContext = {};
  if (entity?.type === "detection") context.detection_id = entity.id;
  const assetContext = entity?.type === "asset" ? entity.id : (assetParam ?? entityInfo?.assetId);
  if (assetContext) context.asset_id = assetContext;
  const tools = useMemo(() => catalog.data?.items ?? [], [catalog.data]);
  const shortcuts = entity ? quickTools(tools, context) : [];
  const preset: Record<string, string> = { ...context };
  const listed = entity && onlyCompatible ? tools.filter((t) => compatibleWith(t, context)) : tools;
  const tool = tools.find((t) => t.id === selectedTool);
  const pickDetection = (id: string) => {
    const next = new URLSearchParams(params);
    if (assetContext) next.set("asset", assetContext);
    next.set("detection", id);
    setParams(next, { replace: true });
  };
  const quickRun = async (t: ToolOut) => {
    if (!entity) return;
    const input: Record<string, string> = {};
    for (const name of requiredOf(t)) input[name] = context[name as keyof WorkspaceContext]!;
    try {
      addResult(await toolsApi.execute(t.id, { input, siteId: scopeId }));
    } catch (err) {
      setNotice({ text: errorMessage(err instanceof Error ? err : new Error(String(err))), ok: false });
    }
  };

  return (
    <div className="stack console-page">
      <header className="page-header">
        <h1>Consola de analista</h1>
        <p className="muted small">
          Búsqueda, contexto y herramientas del registro cerrado de Sentra. No ejecuta comandos, scripts ni consultas
          libres; cada herramienta respeta tus permisos y el site elegido.
        </p>
      </header>

      <section className="panel panel--padded" aria-label="Búsqueda global">
        <form className="console-search" role="search" onSubmit={submit}>
          <label className="field console-search__field">
            <span>Buscar</span>
            <input
              className="input"
              value={draft}
              maxLength={128}
              onChange={(e) => setDraft(e.target.value)}
              placeholder="IP, MAC, SHA-256, regla (SCR-001), caso (INC-12), usuario o texto"
            />
          </label>
          <button type="submit" className="button button--primary" disabled={draft.trim().length < 2}>
            Buscar
          </button>
        </form>
        {searching && <LoadingState label="Buscando…" />}
        {current?.error && (
          <ErrorState
            message={current.error}
            onRetry={() => {
              setSearch(undefined);
              setRetry((n) => n + 1);
            }}
          />
        )}
        {current?.result && <SearchResults result={current.result} onPick={pick} />}
      </section>

      {notice && (
        <div className={`banner ${notice.ok ? "banner--ok" : "banner--warn"}`} role={notice.ok ? "status" : "alert"}>
          {notice.text}{" "}
          <button type="button" className="button button--small" onClick={() => setNotice(undefined)}>
            Cerrar
          </button>
        </div>
      )}

      {entity && (
        <section className="panel panel--padded" aria-label="Workspace">
          <h2>
            Workspace: {entity.type === "asset" ? "activo" : "detección"}{" "}
            {entityInfo ? (
              <span>{entityInfo.label}</span>
            ) : (
              <span className="mono small" title={info.error ? errorMessage(info.error) : undefined}>
                {entity.id}
              </span>
            )}
          </h2>
          <p className="small muted">
            Contexto:{" "}
            {context.asset_id && (
              <Link to={`/assets/${context.asset_id}`}>activo</Link>
            )}
            {context.asset_id && context.detection_id && " · "}
            {context.detection_id && <Link to={`/detections/${context.detection_id}`}>detección</Link>}
            . Las herramientas reciben estos ids sin copiarlos.
          </p>
          <div className="actions">
            <Link
              className="button button--small"
              to={entity.type === "asset" ? `/assets/${entity.id}` : `/detections/${entity.id}`}
            >
              Abrir ficha
            </Link>
            <button
              type="button"
              className="button button--small"
              onClick={() =>
                setAddTo({
                  kind: entity.type,
                  id: entity.id,
                  label: `${entity.type === "asset" ? "Activo" : "Detección"} ${entity.id}`,
                  assetId: entity.type === "asset" ? entity.id : undefined,
                })
              }
              disabled={!canExecute}
            >
              Añadir al caso…
            </button>
          </div>
          {canExecute ? (
            <div className="console-shortcuts" role="group" aria-label="Herramientas para esta entidad">
              {shortcuts.map((t) => (
                <button
                  key={t.id}
                  type="button"
                  className="button button--small"
                  title={t.description}
                  disabled={!t.permitted || t.availability !== "available"}
                  onClick={() => void quickRun(t)}
                >
                  {t.name}
                </button>
              ))}
            </div>
          ) : (
            <p className="small muted">Tu rol puede consultar pero no ejecutar herramientas.</p>
          )}
          {context.asset_id && (
            <AssetDetections assetId={context.asset_id} current={context.detection_id} onPick={pickDetection} />
          )}
        </section>
      )}

      {results.length > 0 && (
        <section aria-label="Resultados" className="stack">
          {results.map((execution) => (
            <ExecutionCard
              key={execution.execution_id}
              execution={execution}
              canExecute={canExecute}
              onUpdate={addResult}
              onAddToCase={(e) =>
                setAddTo({
                  kind: "tool_execution",
                  id: e.execution_id,
                  label: `${e.tool_name}${e.target_label ? ` · ${e.target_label}` : ""}`,
                  assetId: e.asset_id ?? undefined,
                })
              }
            />
          ))}
        </section>
      )}

      <section className="panel panel--padded" aria-label="Catálogo de herramientas">
        <h2>Catálogo de herramientas</h2>
        {!catalog.data ? (
          catalog.error ? (
            <ErrorState message={errorMessage(catalog.error)} onRetry={catalog.refresh} />
          ) : (
            <LoadingState label="Cargando catálogo…" />
          )
        ) : !catalog.data.enabled ? (
          <p className="muted">Las herramientas de analista están desactivadas en este servidor.</p>
        ) : (
          <>
            {entity && (
              <label className="checkbox small">
                <input type="checkbox" checked={onlyCompatible} onChange={(e) => setOnlyCompatible(e.target.checked)} /> Solo
                herramientas compatibles con el workspace ({listed.length} de {tools.length})
              </label>
            )}
            <label className="field">
              <span>Herramienta</span>
              <select className="input input--select" value={selectedTool} onChange={(e) => setSelectedTool(e.target.value)}>
                <option value="">Elige una herramienta…</option>
                {(["read", "investigation", "action"] as const).map((category) => (
                  <optgroup key={category} label={CATEGORY_LABELS[category]}>
                    {listed
                      .filter((t) => t.category === category)
                      .map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.name} ({t.id})
                        </option>
                      ))}
                  </optgroup>
                ))}
              </select>
            </label>
            {tool && (
              <div className="stack">
                <p className="small">
                  Riesgo <strong>{tool.risk_level}</strong> · política <strong>{tool.policy}</strong> ·{" "}
                  {`máximo ${count(tool.max_rows)} filas · ${count(tool.timeout_seconds)} s`} · fuentes:{" "}
                  {tool.sources.join(", ") || "—"}
                </p>
                <ToolRunner key={`${tool.id}-${entity?.id ?? ""}-${context.asset_id ?? ""}`} tool={tool} preset={preset} siteId={scopeId} onResult={addResult} />
              </div>
            )}
          </>
        )}
      </section>

      <section className="panel panel--padded" aria-label="Historial de ejecuciones">
        <h2>Historial</h2>
        {!history.data ? (
          history.error ? (
            <ErrorState message={errorMessage(history.error)} onRetry={history.refresh} />
          ) : (
            <LoadingState label="Cargando historial…" />
          )
        ) : history.data.items.length === 0 ? (
          <p className="muted small">Aún no has ejecutado ninguna herramienta.</p>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Herramienta</th>
                  <th>Objetivo</th>
                  <th>Estado</th>
                  <th>Cuándo</th>
                  <th>Acciones</th>
                </tr>
              </thead>
              <tbody>
                {history.data.items.map((e) => (
                  <tr key={e.execution_id}>
                    <td>{e.tool_name}</td>
                    <td className="small">{e.target_label ?? "—"}</td>
                    <td>
                      <ExecutionStatus status={e.status} />
                    </td>
                    <td className="small">{formatRelative(e.created_at)}</td>
                    <td>
                      <button type="button" className="button button--small" onClick={() => addResult(e)}>
                        Ver
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {addTo && (
        <AddToCaseDialog
          kind={addTo.kind}
          evidenceId={addTo.id}
          label={addTo.label}
          assetId={addTo.assetId}
          onClose={() => setAddTo(undefined)}
          onDone={(message) => {
            setNotice({ text: message, ok: true });
            history.refresh();
          }}
        />
      )}
    </div>
  );
}
