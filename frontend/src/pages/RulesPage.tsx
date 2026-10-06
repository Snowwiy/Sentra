import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { rulesApi } from "../api/sentra";
import type {
  CompileStatus,
  DetectionSeverity,
  RuleCatalog,
  RuleSort,
  RuleSource,
  RuleStatus,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { DetectionSeverityBadge, SEVERITY_LABELS, SEVERITY_ORDER } from "../components/detections/DetectionBadges";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import { CompileBadge, RuleSourceBadge, RuleStatusBadge } from "../components/rules/RuleBadges";
import { SigmaImportModal } from "../components/rules/SigmaImportModal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import type { SortState } from "../lib/listing";
import { COMPILE_LABELS, RULE_STATUS_LABELS, SOURCE_LABELS } from "../lib/rules";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;

const options = <K extends string>(labels: Record<K, string>) =>
  (Object.keys(labels) as K[]).map((value) => ({ value, label: labels[value] }));

/**
 * Detecciones → Reglas: catálogo unificado (built-in, personalizadas y Sigma). Filtros,
 * orden y paginación los resuelve el servidor. Crear e importar es solo de rules:manage.
 */
export function RulesPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [source, setSource] = useState("");
  const [status, setStatus] = useState("");
  const [compile, setCompile] = useState("");
  const [severity, setSeverity] = useState("");
  const [logsource, setLogsource] = useState("");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortState<RuleSort>>({ key: "title", dir: "asc" });
  const [page, setPage] = useState(1);
  const [importing, setImporting] = useState(false);
  const [catalog, setCatalog] = useState<RuleCatalog>();
  const q = useDebounced(query);

  useEffect(() => {
    const controller = new AbortController();
    rulesApi
      .catalog(controller.signal)
      .then(setCatalog)
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  const fetchRules = useCallback(
    (signal: AbortSignal) =>
      rulesApi.list(
        {
          source: (source || undefined) as RuleSource | undefined,
          status: (status || undefined) as RuleStatus | undefined,
          compileStatus: (compile || undefined) as CompileStatus | undefined,
          severity: (severity || undefined) as DetectionSeverity | undefined,
          logsource: logsource || undefined,
          q,
          sort: sort.key,
          order: sort.dir,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [source, status, compile, severity, logsource, q, sort, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchRules, config.refreshIntervalMs, true, true);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const reset =
    <T,>(set: (v: T) => void) =>
    (value: T) => {
      set(value);
      setPage(1);
    };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <Link to="/detections" className="back">
            ← Detecciones
          </Link>
          <h1>Reglas de detección</h1>
        </div>
        <div className="actions">
          {auth.can("rules:test") && (
            <button type="button" className="button" onClick={() => setImporting(true)}>
              Importar Sigma
            </button>
          )}
          {auth.can("rules:manage") && (
            <Link to="/detections/rules/new" className="button button--primary">
              Nueva regla
            </Link>
          )}
        </div>
      </div>
      <section className="panel">
        <Toolbar>
          <FilterSelect label="Origen" value={source} options={options(SOURCE_LABELS)} onChange={reset(setSource)} />
          <FilterSelect label="Estado" value={status} options={options(RULE_STATUS_LABELS)} onChange={reset(setStatus)} />
          <FilterSelect
            label="Compilación"
            value={compile}
            options={options(COMPILE_LABELS)}
            onChange={reset(setCompile)}
          />
          <FilterSelect
            label="Severidad"
            value={severity}
            options={SEVERITY_ORDER.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
            onChange={reset(setSeverity)}
            allLabel="Todas"
          />
          <FilterSelect
            label="Logsource"
            value={logsource}
            options={(catalog?.logsources ?? []).map((s) => ({ value: s.name, label: s.title }))}
            onChange={reset(setLogsource)}
          />
          <SearchInput
            value={query}
            onChange={reset(setQuery)}
            placeholder="Buscar por título o identificador"
            label="Buscar reglas"
          />
        </Toolbar>
        {error && data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {loading ? (
          <LoadingState label="Cargando reglas…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="Sin reglas para este filtro" />
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Regla</th>
                    <SortHeader label="Título" sortKey="title" sort={sort} onSort={reset(setSort)} />
                    <SortHeader label="Origen" sortKey="source" sort={sort} onSort={reset(setSort)} />
                    <th>Estado</th>
                    <th>Compilación</th>
                    <SortHeader label="Severidad" sortKey="severity" sort={sort} onSort={reset(setSort)} numeric />
                    <th>Versión</th>
                    <th>24 h</th>
                    <SortHeader
                      label="Última detección"
                      sortKey="last_triggered"
                      sort={sort}
                      onSort={reset(setSort)}
                      numeric
                    />
                    <SortHeader label="Actualizada" sortKey="updated_at" sort={sort} onSort={reset(setSort)} numeric />
                    <th>Errores</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((r) => (
                    <tr
                      key={r.rule_id}
                      className="table__row--link"
                      onClick={() => navigate(`/detections/rules/${encodeURIComponent(r.rule_id)}`)}
                    >
                      <td className="mono">{r.rule_id}</td>
                      <td>
                        <Link
                          to={`/detections/rules/${encodeURIComponent(r.rule_id)}`}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {r.title}
                        </Link>
                      </td>
                      <td>
                        <RuleSourceBadge source={r.source} />
                      </td>
                      <td>
                        <RuleStatusBadge status={r.status} />
                      </td>
                      <td>
                        <CompileBadge status={r.compile_status} />
                      </td>
                      <td>
                        <DetectionSeverityBadge severity={r.severity} />
                      </td>
                      <td className="mono">v{r.version}</td>
                      <td className="mono">{r.detections_24h}</td>
                      <td title={formatDateTime(r.last_triggered_at)}>{formatRelative(r.last_triggered_at)}</td>
                      <td title={formatDateTime(r.updated_at)}>{r.updated_at ? formatRelative(r.updated_at) : "—"}</td>
                      <td className={`mono${r.consecutive_errors ? " text-crit" : ""}`}>{r.errors || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="reglas" />
          </>
        )}
      </section>
      {importing && (
        <SigmaImportModal
          onClose={() => setImporting(false)}
          onImported={() => {
            refresh();
          }}
        />
      )}
    </div>
  );
}
