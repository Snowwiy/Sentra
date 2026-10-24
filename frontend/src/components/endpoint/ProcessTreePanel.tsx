import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { endpointApi } from "../../api/sentra6e";
import type { ProcessNode } from "../../api/types";
import { PARENT_RELATION_LABELS } from "../../lib/endpoint";
import { errorMessage, formatDateTime } from "../../lib/format";
import { LoadingState } from "../StateViews";

interface Level {
  status: "loading" | "ready" | "error";
  nodes: ProcessNode[];
  truncated: boolean;
  error?: string;
}

/** Clave del nivel raíz en el mapa de niveles cargados. */
const ROOT = "";

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

function processLabel(node: ProcessNode): string {
  return `${node.name ?? "(sin nombre)"} · PID ${node.pid}`;
}

/**
 * Árbol de procesos con carga diferida (Fase 6E.4). Nunca se pide el árbol completo: al abrir
 * la pestaña solo se cargan las raíces, y los hijos de un proceso se piden la primera vez que
 * se despliega (GET /process-tree?parent=<instance_key>). Con `search` el servidor devuelve
 * coincidencias planas; con `at`, los procesos vivos en ese instante.
 */
export function ProcessTreePanel({
  assetId,
  selected,
  onSelect,
}: {
  assetId: string;
  selected: string | undefined;
  onSelect: (instanceKey: string) => void;
}) {
  const [levels, setLevels] = useState<Map<string, Level>>(() => new Map());
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set());
  const [atInput, setAtInput] = useState("");
  const [searchInput, setSearchInput] = useState("");
  const [filters, setFilters] = useState<{ at?: string; search?: string }>({});
  // Cada carga lleva su propio AbortController; al cambiar de filtros o desmontar se cancelan.
  const controllers = useRef(new Set<AbortController>());

  const loadLevel = useCallback(
    async (parent: string) => {
      const controller = new AbortController();
      controllers.current.add(controller);
      setLevels((prev) => new Map(prev).set(parent, { status: "loading", nodes: prev.get(parent)?.nodes ?? [], truncated: false }));
      try {
        const tree = await endpointApi.processTree(
          assetId,
          { parent: parent || undefined, at: filters.at, search: parent ? undefined : filters.search, limit: 200 },
          controller.signal,
        );
        setLevels((prev) => new Map(prev).set(parent, { status: "ready", nodes: tree.nodes, truncated: tree.truncated }));
      } catch (err) {
        if (controller.signal.aborted) return;
        setLevels((prev) =>
          new Map(prev).set(parent, { status: "error", nodes: [], truncated: false, error: errorMessage(toError(err)) }),
        );
      } finally {
        controllers.current.delete(controller);
      }
    },
    [assetId, filters],
  );

  useEffect(() => {
    const active = controllers.current;
    // Filtros nuevos: se descarta lo cargado y se vuelve a empezar por las raíces.
    const initial = window.setTimeout(() => {
      setLevels(new Map());
      setExpanded(new Set());
      void loadLevel(ROOT);
    }, 0);
    return () => {
      window.clearTimeout(initial);
      for (const controller of active) controller.abort();
      active.clear();
    };
  }, [loadLevel]);

  const toggle = (node: ProcessNode) => {
    const key = node.instance_key;
    const next = new Set(expanded);
    if (next.has(key)) {
      next.delete(key);
    } else {
      next.add(key);
      // Solo la primera vez (o tras un error): lo ya cargado se reutiliza al volver a abrir.
      const level = levels.get(key);
      if (!level || level.status === "error") void loadLevel(key);
    }
    setExpanded(next);
  };

  const applyFilters = (event: FormEvent) => {
    event.preventDefault();
    const at = atInput ? new Date(atInput) : undefined;
    setFilters({
      at: at && !Number.isNaN(at.getTime()) ? at.toISOString() : undefined,
      search: searchInput.trim() || undefined,
    });
  };

  const root = levels.get(ROOT);
  const searching = Boolean(filters.search);

  const renderLevel = (parent: string, depth: number) => {
    const level = levels.get(parent);
    if (!level || level.status === "loading") {
      return (
        <li role="none" className="proc-tree__status muted small" style={{ paddingLeft: `${depth * 1.25}rem` }}>
          Cargando…
        </li>
      );
    }
    if (level.status === "error") {
      return (
        <li role="none" className="proc-tree__status small text-crit" style={{ paddingLeft: `${depth * 1.25}rem` }}>
          {level.error}{" "}
          <button type="button" className="link-button" onClick={() => void loadLevel(parent)}>
            Reintentar
          </button>
        </li>
      );
    }
    return (
      <>
        {level.nodes.map((node) => {
          const open = expanded.has(node.instance_key);
          const hasChildren = !searching && node.children_count > 0;
          return (
            <li
              key={node.instance_key}
              role="treeitem"
              aria-expanded={hasChildren ? open : undefined}
              aria-selected={selected === node.instance_key}
              aria-level={depth + 1}
              aria-label={processLabel(node)}
            >
              <div className="proc-tree__row" style={{ paddingLeft: `${depth * 1.25}rem` }}>
                {hasChildren ? (
                  <button
                    type="button"
                    className="iconbutton proc-tree__toggle"
                    aria-label={`${open ? "Contraer" : "Desplegar"} ${processLabel(node)}`}
                    onClick={() => toggle(node)}
                  >
                    {open ? "−" : "+"}
                  </button>
                ) : (
                  <span className="proc-tree__toggle" aria-hidden="true" />
                )}
                <button
                  type="button"
                  className={`link-button${selected === node.instance_key ? " strong" : ""}`}
                  onClick={() => onSelect(node.instance_key)}
                >
                  {node.name ?? "(sin nombre)"}
                </button>
                <span className="mono small muted"> PID {node.pid}</span>
                {node.username && <span className="small muted"> · {node.username}</span>}
                {!node.running && <span className="badge badge--muted">terminado</span>}
                {node.parent_relation && node.parent_relation !== "observed" && (
                  <span className="badge badge--warn">{PARENT_RELATION_LABELS[node.parent_relation] ?? node.parent_relation}</span>
                )}
                {hasChildren && <span className="small muted"> · {node.children_count} hijos</span>}
              </div>
              {hasChildren && open && (
                <ul role="group" className="proc-tree__group">
                  {renderLevel(node.instance_key, depth + 1)}
                </ul>
              )}
            </li>
          );
        })}
        {level.truncated && (
          <li role="none" className="proc-tree__status muted small" style={{ paddingLeft: `${depth * 1.25}rem` }}>
            Lista recortada a los primeros 200 procesos de este nivel.
          </li>
        )}
      </>
    );
  };

  return (
    <section className="panel stack" aria-label="Árbol de procesos">
      <form className="panel__toolbar panel__toolbar--filters" onSubmit={applyFilters}>
        <h2>Árbol de procesos</h2>
        <input
          type="search"
          className="input"
          placeholder="Nombre, ruta o PID"
          aria-label="Buscar procesos"
          value={searchInput}
          maxLength={128}
          onChange={(e) => setSearchInput(e.target.value)}
        />
        <label className="small">
          En el instante{" "}
          <input
            type="datetime-local"
            className="input"
            aria-label="Procesos vivos en el instante"
            value={atInput}
            onChange={(e) => setAtInput(e.target.value)}
          />
        </label>
        <button type="submit" className="button">
          Aplicar
        </button>
      </form>
      <p className="muted small panel--padded">
        {filters.at
          ? `Procesos vivos el ${formatDateTime(filters.at)}.`
          : "Procesos vivos y terminados en la última hora."}{" "}
        Los hijos se cargan al desplegar cada proceso.
      </p>
      {!root || (root.status === "loading" && root.nodes.length === 0) ? (
        <LoadingState label="Cargando procesos…" />
      ) : root.status === "ready" && root.nodes.length === 0 ? (
        <p className="muted small panel--padded">
          {searching
            ? "Ningún proceso coincide con la búsqueda."
            : "Sin procesos registrados: el agente necesita la versión 0.5.0 con la telemetría de actividad activa."}
        </p>
      ) : (
        <ul role="tree" aria-label="Procesos" className="proc-tree">
          {renderLevel(ROOT, 0)}
        </ul>
      )}
    </section>
  );
}
