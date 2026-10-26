import { lazy, Suspense, useCallback, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { topologyApi } from "../api/sentra";
import type { TopologyLinkKind, TopologyNode, TopologyStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect, SearchInput } from "../components/ListControls";
import { ErrorState, LoadingState } from "../components/StateViews";
import { TopologyCanvas, type CanvasHandle } from "../components/topology/TopologyCanvas";
import { LinkDetails, NodeDetails } from "../components/topology/TopologyDetails";
import { TopologyLegend } from "../components/topology/TopologyLegend";
import { config } from "../config";
import { describeDownloadError } from "../lib/download";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { saveBlob } from "../lib/reports";
import {
  computeLayout,
  CONFIDENCE_LABELS,
  exportFilename,
  exportSvg,
  LINK_KIND_LABELS,
  LINK_KINDS,
  linkAriaLabel,
  NODE_KIND_LABELS,
  nodeMatches,
  nodeTitle,
  relationLabel,
  REVIEW_LABELS,
  visibleLinks,
  type GroupMode,
} from "../lib/topology";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

type View = "map" | "list" | "history";

// Fase 6E.1: el historial (snapshots, diferencias y cambios) solo se descarga al abrir su pestaña.
const TopologyHistoryPanel = lazy(() =>
  import("../components/topology/TopologyHistoryPanel").then((m) => ({ default: m.TopologyHistoryPanel })),
);
// La topología se reconstruye cada 15 min por defecto: refrescar más a menudo no aporta.
const GRAPH_REFRESH_MS = Math.max(config.refreshIntervalMs * 4, 60_000);

const EVIDENCE_HELP: { key: keyof TopologyStatus["evidence_available"]; ok: string; missing: string }[] = [
  {
    key: "lldp_cdp",
    ok: "Hay vecinos LLDP/CDP informados por equipos de red.",
    missing:
      "Ningún equipo de red registrado informa vecinos LLDP/CDP: sin SNMP configurado (perfil y sensor), o LLDP/CDP deshabilitado en los switches.",
  },
  {
    key: "fdb",
    ok: "Hay tablas MAC (FDB) de switches.",
    missing: "No hay tablas MAC de switches: requieren consultas SNMP con BRIDGE-MIB a switches gestionables.",
  },
  {
    key: "wlan",
    ok: "Hay datos Wi-Fi (puntos de acceso y clientes).",
    missing: "No hay datos Wi-Fi de controladoras o puntos de acceso consultados por SNMP.",
  },
  {
    key: "agent_gateways",
    ok: "Los agentes informan su gateway por defecto.",
    missing: "Ningún agente ha informado su gateway por defecto (sin agentes o con versiones antiguas).",
  },
];

/** Por qué no hay enlaces (o pocos): qué evidencia falta según GET /topology/status. */
function EmptyExplanation({ status, canManage }: { status: TopologyStatus | undefined; canManage: boolean }) {
  return (
    <section className="panel panel--padded stack" aria-label="Por qué no hay enlaces">
      <h2 className="panel__title">No hay enlaces que mostrar</h2>
      <p className="small">
        Sentra solo dibuja enlaces con evidencia verificable. Compartir subred o gateway no crea un enlace físico, y sin
        evidencia el mapa no inventa conexiones.
      </p>
      {!status ? (
        <p className="muted small">No se pudo consultar el estado de la evidencia.</p>
      ) : (
        <>
          {!status.last_build && (
            <p className="small">
              La topología de este site no se ha reconstruido nunca.
              {canManage ? " Pulsa «Reconstruir» para derivar los enlaces de la evidencia disponible." : " Pide a un administrador que la reconstruya."}
            </p>
          )}
          <ul className="plain-list small" aria-label="Evidencia disponible">
            {EVIDENCE_HELP.map(({ key, ok, missing }) => (
              <li key={key}>
                <span className={status.evidence_available[key] ? "text-ok" : "text-warn"}>
                  {status.evidence_available[key] ? "Disponible" : "Sin datos"}
                </span>
                : {status.evidence_available[key] ? ok : missing}
              </li>
            ))}
          </ul>
          <p className="muted small">
            Para obtener enlaces: registra los switches y routers en <Link to="/infrastructure">Infraestructura</Link> con un
            perfil SNMP y un sensor, activa LLDP/CDP en ellos o instala agentes en los equipos.
          </p>
        </>
      )}
    </section>
  );
}

/** Rasteriza el SVG exportado (autónomo: no contamina el canvas) a PNG. */
async function svgToPng(svg: string): Promise<Blob> {
  const url = URL.createObjectURL(new Blob([svg], { type: "image/svg+xml" }));
  try {
    const image = new Image();
    await new Promise<void>((resolve, reject) => {
      image.onload = () => resolve();
      image.onerror = () => reject(new Error("No se pudo rasterizar el SVG"));
      image.src = url;
    });
    const canvas = document.createElement("canvas");
    // Tope de tamaño: los navegadores fallan con lienzos enormes.
    const scale = Math.min(1, 8000 / Math.max(image.width, image.height, 1));
    canvas.width = Math.max(1, Math.round(image.width * scale));
    canvas.height = Math.max(1, Math.round(image.height * scale));
    const context = canvas.getContext("2d");
    if (!context) throw new Error("Este navegador no permite generar PNG");
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    return await new Promise<Blob>((resolve, reject) =>
      canvas.toBlob((blob) => (blob ? resolve(blob) : reject(new Error("No se pudo generar el PNG"))), "image/png"),
    );
  } finally {
    URL.revokeObjectURL(url);
  }
}

/**
 * Topología de red (Fase 6D.2). Nodos y enlaces derivados de evidencia (LLDP/CDP, tablas MAC,
 * Wi-Fi, gateways de agentes) con su clase y confianza. Solo lectura salvo «Reconstruir» y la
 * revisión de enlaces, que exigen topology:manage (admin); la API vuelve a comprobarlo.
 */
export function TopologyPage({ embedded = false }: { embedded?: boolean }) {
  const auth = useAuth();
  // Fase 7A.5: dentro del hub Red el título de página es «Red»; aquí va un nivel por debajo.
  const Title = embedded ? "h2" : "h1";
  const canManage = auth.can("topology:manage");
  const site = useSite();
  const [siteFilter, setSiteFilter] = useState("");
  // La topología es siempre de UN site: sin alcance elegido, el filtro local o el site por
  // defecto (la API lo resuelve si no se envía site_id).
  const siteId = site.scopeId ?? (siteFilter || undefined);
  const [query, setQuery] = useState("");
  const q = useDebounced(query.trim(), 300);
  const [deviceType, setDeviceType] = useState("");
  const [kinds, setKinds] = useState<Set<TopologyLinkKind>>(() => new Set(LINK_KINDS));
  const [includeAbsent, setIncludeAbsent] = useState(false);
  const [includeRejected, setIncludeRejected] = useState(false);
  const [groupMode, setGroupMode] = useState<GroupMode>("network");
  const [view, setView] = useState<View>("map");
  const [selectedNode, setSelectedNode] = useState<string>();
  const [selectedLink, setSelectedLink] = useState<string>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "ok" | "warn"; text: string }>();
  const canvas = useRef<CanvasHandle>(null);

  const fetchGraph = useCallback(
    (signal: AbortSignal) =>
      topologyApi.graph({ siteId, includeAbsent, includeRejected, deviceType: deviceType || undefined, q: q || undefined }, signal),
    [siteId, includeAbsent, includeRejected, deviceType, q],
  );
  const graph = usePolling(fetchGraph, GRAPH_REFRESH_MS, true, true);
  const fetchStatus = useCallback((signal: AbortSignal) => topologyApi.status(siteId, signal), [siteId]);
  const status = usePolling(fetchStatus, GRAPH_REFRESH_MS);

  const data = graph.data;
  const nodes = useMemo(() => data?.nodes ?? [], [data]);
  const allLinks = useMemo(() => data?.links ?? [], [data]);
  const nodeIds = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const links = useMemo(() => visibleLinks(allLinks, nodeIds, kinds), [allLinks, nodeIds, kinds]);
  const layout = useMemo(() => computeLayout(nodes, data?.groups ?? [], groupMode), [nodes, data?.groups, groupMode]);
  const matches = useMemo(() => new Set(q ? nodes.filter((n) => nodeMatches(n, q)).map((n) => n.id) : []), [nodes, q]);
  const names = useMemo(() => new Map(nodes.map((n) => [n.id, nodeTitle(n)])), [nodes]);
  const nodeById = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);
  // Opciones de tipo: las del grafo cargado más la elegida (para poder volver a «Todos»).
  const deviceTypes = useMemo(() => {
    const types = new Set(nodes.map((n) => n.device_type).filter((t): t is string => Boolean(t)));
    if (deviceType) types.add(deviceType);
    return [...types].sort();
  }, [nodes, deviceType]);

  const node: TopologyNode | undefined = selectedNode ? nodeById.get(selectedNode) : undefined;
  const linkObj = selectedLink ? allLinks.find((l) => l.id === selectedLink) : undefined;

  const selectNode = useCallback((id: string) => {
    setSelectedNode(id);
    setSelectedLink(undefined);
  }, []);
  const selectLink = useCallback((id: string) => setSelectedLink(id), []);

  const toggleKind = (kind: TopologyLinkKind) =>
    setKinds((prev) => {
      const next = new Set(prev);
      if (next.has(kind)) next.delete(kind);
      else next.add(kind);
      return next;
    });

  const refreshGraph = graph.refresh;
  const refreshStatus = status.refresh;
  const reload = useCallback(() => {
    refreshGraph();
    refreshStatus();
  }, [refreshGraph, refreshStatus]);

  const rebuild = async () => {
    setBusy(true);
    setNotice(undefined);
    try {
      const build = await topologyApi.rebuild(siteId ?? data?.site.id);
      const present = build.counts?.["links_present"];
      setNotice({
        tone: build.status === "failed" ? "warn" : "ok",
        text:
          build.status === "failed"
            ? `La reconstrucción falló${build.error_code ? ` (${build.error_code})` : ""}.`
            : `Topología reconstruida${present !== undefined ? `: ${present} enlaces presentes` : ""}.`,
      });
    } catch (err) {
      setNotice({ tone: "warn", text: errorMessage(err instanceof Error ? err : new Error(String(err))) });
    } finally {
      setBusy(false);
      reload();
    }
  };

  const exportAs = async (format: "svg" | "png") => {
    if (!data) return;
    setNotice(undefined);
    const svg = exportSvg({ title: `Topología de red · ${data.site.name}`, nodes, links, layout });
    try {
      const blob = format === "svg" ? new Blob([svg], { type: "image/svg+xml" }) : await svgToPng(svg);
      saveBlob(blob, exportFilename(data.site.name, format));
    } catch (err) {
      setNotice({ tone: "warn", text: describeDownloadError(err, "la imagen") ?? "No se pudo exportar." });
    }
  };

  const showSiteFilter = !site.scopeId && site.selectableSites.length > 1;
  const filtersActive = Boolean(q || deviceType) || kinds.size !== LINK_KINDS.length;
  const lastBuild = status.data?.last_build ?? null;

  return (
    <div className="page topo-page">
      <div className="page__header">
        <div>
          <Title>Topología</Title>
          <p className="muted small page__scope">
            <SiteScopeChip siteId={data?.site.id} />
            <span>
              {data ? `Site ${data.site.name}. ` : ""}Enlaces derivados de LLDP/CDP, tablas MAC, Wi-Fi y gateways de agentes, con su
              evidencia.
              {lastBuild?.finished_at && (
                <>
                  {" "}
                  Última reconstrucción{" "}
                  <time dateTime={lastBuild.finished_at} title={formatDateTime(lastBuild.finished_at)}>
                    {formatRelative(lastBuild.finished_at)}
                  </time>
                  .
                </>
              )}
            </span>
          </p>
        </div>
        <div className="actions">
          <button type="button" className="button nowrap" disabled={!data} onClick={() => void exportAs("svg")}>
            Exportar SVG
          </button>
          <button type="button" className="button nowrap" disabled={!data} onClick={() => void exportAs("png")}>
            Exportar PNG
          </button>
          {canManage && (
            <button type="button" className="button button--primary nowrap" disabled={busy} onClick={() => void rebuild()}>
              {busy ? "Reconstruyendo…" : "Reconstruir"}
            </button>
          )}
        </div>
      </div>

      <div className="panel__toolbar panel__toolbar--filters topo-filters">
        {showSiteFilter && (
          <FilterSelect
            label="Site"
            value={siteFilter}
            allLabel="por defecto"
            options={site.selectableSites.map((s) => ({ value: s.site_id, label: s.name }))}
            onChange={(v) => {
              setSiteFilter(v);
              setSelectedNode(undefined);
              setSelectedLink(undefined);
            }}
          />
        )}
        <SearchInput value={query} onChange={setQuery} placeholder="IP, nombre, MAC o etiqueta" label="Buscar nodos" />
        <FilterSelect
          label="Tipo de dispositivo"
          value={deviceType}
          options={deviceTypes}
          onChange={setDeviceType}
        />
        <label className="small">
          Agrupar{" "}
          <select
            className="input input--select"
            value={groupMode}
            aria-label="Agrupar nodos"
            onChange={(e) => setGroupMode(e.target.value as GroupMode)}
          >
            <option value="network">por red</option>
            <option value="none">sin agrupar</option>
          </select>
        </label>
        <label className="checkbox small">
          <input type="checkbox" checked={includeAbsent} onChange={(e) => setIncludeAbsent(e.target.checked)} /> Mostrar
          ausentes
        </label>
        <label className="checkbox small">
          <input type="checkbox" checked={includeRejected} onChange={(e) => setIncludeRejected(e.target.checked)} /> Mostrar
          rechazados
        </label>
      </div>
      <fieldset className="topo-kinds">
        <legend className="small strong">Clases de enlace</legend>
        {LINK_KINDS.map((kind) => (
          <label key={kind} className="checkbox small">
            <input type="checkbox" checked={kinds.has(kind)} onChange={() => toggleKind(kind)} /> {LINK_KIND_LABELS[kind]}
          </label>
        ))}
      </fieldset>

      {notice && (
        <div className={`banner${notice.tone === "warn" ? " banner--warn" : ""}`} role={notice.tone === "warn" ? "alert" : "status"}>
          {notice.text}
        </div>
      )}
      {data?.truncated && (
        <div className="banner banner--warn" role="status">
          El grafo supera los límites ({data.limits.max_nodes} nodos / {data.limits.max_links} enlaces): se muestran
          primero la infraestructura y los nodos con enlaces. Usa la búsqueda o los filtros para acotar.
        </div>
      )}
      {graph.error && data && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(graph.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      {!data ? (
        graph.error ? (
          <ErrorState message={errorMessage(graph.error)} onRetry={reload} />
        ) : (
          <LoadingState label="Cargando topología…" />
        )
      ) : (
        <>
          {allLinks.length === 0 && !filtersActive && <EmptyExplanation status={status.data} canManage={canManage} />}
          <nav className="tabs" role="tablist" aria-label="Vista de la topología">
            {(
              [
                ["map", "Mapa"],
                ["list", "Lista accesible"],
                ["history", "Historial"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                id={`topo-tab-${key}`}
                aria-selected={view === key}
                aria-controls={`topo-panel-${key}`}
                className={`tabs__item${view === key ? " tabs__item--active" : ""}`}
                onClick={() => setView(key)}
              >
                {label}
              </button>
            ))}
          </nav>
          {view === "history" ? (
            <div role="tabpanel" id="topo-panel-history" aria-labelledby="topo-tab-history">
              <Suspense fallback={<LoadingState label="Cargando historial…" />}>
                <TopologyHistoryPanel siteId={data.site.id} canManage={canManage} />
              </Suspense>
            </div>
          ) : (
          <div className="topo-layout">
            <div className="topo-main" role="tabpanel" id={`topo-panel-${view}`} aria-labelledby={`topo-tab-${view}`}>
              {view === "map" ? (
                <div className="panel topo-canvas-wrap">
                  <div className="topo-zoom" role="toolbar" aria-label="Zoom del mapa">
                    <button type="button" className="iconbutton" aria-label="Acercar" onClick={() => canvas.current?.zoomBy(1.25)}>
                      +
                    </button>
                    <button type="button" className="iconbutton" aria-label="Alejar" onClick={() => canvas.current?.zoomBy(0.8)}>
                      −
                    </button>
                    <button type="button" className="button button--small" onClick={() => canvas.current?.fit()}>
                      Encajar
                    </button>
                    <span className="muted small">
                      {nodes.length} nodos · {links.length} enlaces
                      {q && ` · ${matches.size} coincidencias`}
                    </span>
                  </div>
                  {nodes.length === 0 ? (
                    <p className="muted small topo-empty">
                      {q || deviceType ? "Ningún nodo coincide con la búsqueda o el filtro." : "No hay nodos en este site."}
                    </p>
                  ) : (
                    <TopologyCanvas
                      handleRef={canvas}
                      nodes={nodes}
                      links={links}
                      layout={layout}
                      matches={matches}
                      selectedNode={selectedNode}
                      selectedLink={linkObj}
                      onSelectNode={selectNode}
                      onSelectLink={selectLink}
                    />
                  )}
                </div>
              ) : (
                <TopologyLists
                  nodes={nodes}
                  links={links}
                  names={names}
                  matches={matches}
                  onSelectNode={selectNode}
                  onSelectLink={selectLink}
                />
              )}
            </div>
            <aside className="topo-side stack">
              {selectedLink && (
                <LinkDetails
                  key={selectedLink}
                  linkId={selectedLink}
                  names={names}
                  canManage={canManage}
                  onReviewed={reload}
                  onClose={() => setSelectedLink(undefined)}
                />
              )}
              {node && (
                <NodeDetails
                  key={node.id}
                  node={node}
                  siteId={data?.site.id}
                  names={names}
                  onSelectLink={selectLink}
                  onClose={() => {
                    setSelectedNode(undefined);
                    setSelectedLink(undefined);
                  }}
                />
              )}
              {!node && !selectedLink && (
                <p className="muted small topo-hint">Selecciona un nodo o un enlace para ver sus datos y su evidencia.</p>
              )}
              <TopologyLegend />
            </aside>
          </div>
          )}
        </>
      )}
    </div>
  );
}

/** Alternativa accesible al mapa: las mismas listas de nodos y enlaces en tablas. */
function TopologyLists({
  nodes,
  links,
  names,
  matches,
  onSelectNode,
  onSelectLink,
}: {
  nodes: TopologyNode[];
  links: ReturnType<typeof visibleLinks>;
  names: Map<string, string>;
  matches: Set<string>;
  onSelectNode: (id: string) => void;
  onSelectLink: (id: string) => void;
}) {
  return (
    <div className="stack">
      <section className="panel" aria-label="Nodos">
        <div className="panel__toolbar">
          <h2>Nodos ({nodes.length})</h2>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Tipo</th>
                <th>IP</th>
                <th className="col-secondary">MAC</th>
                <th>Enlaces</th>
              </tr>
            </thead>
            <tbody>
              {nodes.map((n) => (
                <tr key={n.id} className={matches.has(n.id) ? "topo-row--match" : undefined}>
                  <td>
                    <button type="button" className="link-button" onClick={() => onSelectNode(n.id)}>
                      {nodeTitle(n)}
                    </button>
                    {matches.has(n.id) && <span className="badge badge--info">coincide</span>}
                  </td>
                  <td>{n.device_type ?? NODE_KIND_LABELS[n.kind]}</td>
                  <td className="mono">{n.ip ?? "—"}</td>
                  <td className="mono col-secondary">{n.mac ?? "—"}</td>
                  <td>{n.link_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel" aria-label="Enlaces">
        <div className="panel__toolbar">
          <h2>Enlaces ({links.length})</h2>
        </div>
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Extremos</th>
                <th>Clase</th>
                <th>Relación</th>
                <th>Confianza</th>
                <th className="col-secondary">Revisión</th>
              </tr>
            </thead>
            <tbody>
              {links.map((l) => (
                <tr key={l.id}>
                  <td>
                    <button type="button" className="link-button" aria-label={linkAriaLabel(l, names)} onClick={() => onSelectLink(l.id)}>
                      {names.get(l.source) ?? l.source} — {names.get(l.target) ?? l.target}
                    </button>
                    {!l.present && <span className="badge badge--muted">ausente</span>}
                  </td>
                  <td>{LINK_KIND_LABELS[l.kind]}</td>
                  <td>{relationLabel(l.relation)}</td>
                  <td>{CONFIDENCE_LABELS[l.confidence]}</td>
                  <td className="col-secondary">{REVIEW_LABELS[l.review_state]}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
