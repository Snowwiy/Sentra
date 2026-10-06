import { useCallback, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { vulnerabilitiesApi } from "../api/sentra";
import type {
  ExposureState,
  FindingSort,
  FindingStatus,
  MatchConfidence,
  MatchState,
  VulnSeverity,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import {
  ExposureBadge,
  FindingStatusBadge,
  MatchBadge,
  PriorityBadge,
  VulnSeverityBadge,
} from "../components/vulnerabilities/VulnBadges";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import type { SortState } from "../lib/listing";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";
import {
  CONFIDENCE_LABELS,
  EXPOSURE_LABELS,
  EXPOSURE_ORDER,
  formatCvss,
  MATCH_LABELS,
  MATCH_ORDER,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
  STATUS_LABELS,
  STATUS_ORDER,
} from "../lib/vulnerabilities";

const PAGE_SIZE = 50;

// "active" = open, acknowledged y mitigating (lo que necesita trabajo).
type StatusFilter = "active" | "all" | FindingStatus;

interface Filters {
  status: StatusFilter;
  severity: string;
  match: string;
  confidence: string;
  exposure: string;
  stale: string;
}

const DEFAULT_FILTERS: Filters = { status: "active", severity: "", match: "", confidence: "", exposure: "", stale: "" };

type CardKey = "confirmed" | "probable" | "potential" | "unknown" | "accepted" | "stale";

// Cada tarjeta es un atajo a un filtro. Confirmadas, probables y potenciales van SIEMPRE por
// separado: una potencial (solo nombre) nunca suma como confirmada.
const CARDS: { key: CardKey; label: string; tone: string; filters: Filters }[] = [
  { key: "confirmed", label: "Confirmadas", tone: "stat--crit", filters: { ...DEFAULT_FILTERS, match: "confirmed" } },
  { key: "probable", label: "Probables", tone: "stat--offline", filters: { ...DEFAULT_FILTERS, match: "probable" } },
  { key: "potential", label: "Potenciales", tone: "stat--idle", filters: { ...DEFAULT_FILTERS, match: "potential" } },
  {
    key: "unknown",
    label: "Evidencia insuficiente",
    tone: "stat--idle",
    filters: { ...DEFAULT_FILTERS, match: "unknown" },
  },
  {
    key: "accepted",
    label: "Riesgo aceptado",
    tone: "",
    filters: { ...DEFAULT_FILTERS, status: "accepted_risk" },
  },
  { key: "stale", label: "Evidencia antigua", tone: "", filters: { ...DEFAULT_FILTERS, stale: "true" } },
];

function sameFilters(a: Filters, b: Filters): boolean {
  return (Object.keys(a) as (keyof Filters)[]).every((key) => a[key] === b[key]);
}

/**
 * Vulnerabilidades del parque (Fase 5B). Filtros, búsqueda, orden y paginación los resuelve
 * el servidor; el navegador no decide ni guarda nada.
 */
export function VulnerabilitiesPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [params] = useSearchParams();
  // ?q= permite enlazar desde el catálogo (findings de un CVE).
  const [query, setQuery] = useState(() => params.get("q") ?? "");
  const [sort, setSort] = useState<SortState<FindingSort>>({ key: "priority", dir: "desc" });
  const [page, setPage] = useState(1);
  const q = useDebounced(query);

  const fetchOverview = useCallback((signal: AbortSignal) => vulnerabilitiesApi.overview(signal), []);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs);

  const fetchFindings = useCallback(
    (signal: AbortSignal) =>
      vulnerabilitiesApi.list(
        {
          active: filters.status === "active",
          status: filters.status === "active" || filters.status === "all" ? undefined : filters.status,
          severity: (filters.severity || undefined) as VulnSeverity | undefined,
          matchState: (filters.match || undefined) as MatchState | undefined,
          confidence: (filters.confidence || undefined) as MatchConfidence | undefined,
          exposure: (filters.exposure || undefined) as ExposureState | undefined,
          stale: (filters.stale || undefined) as "true" | "false" | undefined,
          q,
          sort: sort.key,
          order: sort.dir,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [filters, q, sort, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchFindings, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));

  const setFilter = (key: keyof Filters) => (value: string) => {
    setFilters((current) => ({ ...current, [key]: value || (key === "status" ? "active" : "") }));
    setPage(1);
  };
  const changeSort = (next: SortState<FindingSort>) => {
    setSort(next);
    setPage(1);
  };
  const applyCard = (next: Filters) => {
    setFilters((current) => (sameFilters(current, next) ? DEFAULT_FILTERS : next));
    setPage(1);
  };
  const o = overview.data;
  const counts: Record<CardKey, number | undefined> = {
    confirmed: o?.confirmed,
    probable: o?.probable,
    potential: o?.potential,
    unknown: o?.insufficient_evidence,
    accepted: o?.accepted_risk,
    stale: o?.stale,
  };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Vulnerabilidades</h1>
          {o && (
            <p className="muted small">
              {SEVERITY_ORDER.filter((s) => s !== "informational")
                .map((s) => `${SEVERITY_LABELS[s]}: ${o.by_severity[s] ?? 0}`)
                .join(" · ")}{" "}
              (confirmadas y probables activas) · {o.assets_affected} activos afectados · catálogo local:{" "}
              {o.catalog_records} registros
              {o.last_import_at ? `, importado ${formatRelative(o.last_import_at)}` : ", sin importar"}
              {o.evaluation_pending > 0 && ` · ${o.evaluation_pending} activos pendientes de evaluar`}
            </p>
          )}
        </div>
        <div className="actions">
          <Link className="button" to="/vulnerabilities/exposure">
            Exposición
          </Link>
          {auth.can("vulnerabilities:admin") && (
            <Link className="button" to="/vulnerabilities/catalog">
              Catálogo
            </Link>
          )}
        </div>
      </div>

      {o && o.catalog_records === 0 && (
        <div className="banner" role="note">
          No hay catálogo de vulnerabilidades importado. Sentra no consulta fuentes externas: un administrador debe
          importar un catálogo local para evaluar el software inventariado.
        </div>
      )}

      <section className="stats stats--6" aria-label="Resumen de vulnerabilidades">
        {CARDS.map((card) => (
          <button
            key={card.key}
            type="button"
            className={`stat ${card.tone}${sameFilters(filters, card.filters) ? " stat--active" : ""}`.trim()}
            aria-pressed={sameFilters(filters, card.filters)}
            onClick={() => applyCard(card.filters)}
          >
            <span className="stat__label">{card.label}</span>
            <span className="stat__value">{counts[card.key] ?? "—"}</span>
          </button>
        ))}
      </section>

      <section className="panel">
        <Toolbar>
          <FilterSelect
            label="Estado"
            value={filters.status === "active" ? "" : filters.status}
            options={[{ value: "all", label: "Todos" }, ...STATUS_ORDER.map((s) => ({ value: s, label: STATUS_LABELS[s] }))]}
            onChange={setFilter("status")}
            allLabel="Activas"
          />
          <FilterSelect
            label="Severidad"
            value={filters.severity}
            options={SEVERITY_ORDER.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
            onChange={setFilter("severity")}
            allLabel="Todas"
          />
          <FilterSelect
            label="Evidencia"
            value={filters.match}
            options={MATCH_ORDER.map((value) => ({ value, label: MATCH_LABELS[value] }))}
            onChange={setFilter("match")}
            allLabel="Toda"
          />
          <FilterSelect
            label="Confianza"
            value={filters.confidence}
            options={(["high", "medium", "low"] as const).map((value) => ({ value, label: CONFIDENCE_LABELS[value] }))}
            onChange={setFilter("confidence")}
            allLabel="Todas"
          />
          <FilterSelect
            label="Exposición"
            value={filters.exposure}
            options={EXPOSURE_ORDER.map((value) => ({ value, label: EXPOSURE_LABELS[value] }))}
            onChange={setFilter("exposure")}
            allLabel="Todas"
          />
          <FilterSelect
            label="Evidencia antigua"
            value={filters.stale}
            options={[
              { value: "true", label: "Sí" },
              { value: "false", label: "No" },
            ]}
            onChange={setFilter("stale")}
          />
          <SearchInput
            value={query}
            onChange={(value) => {
              setQuery(value);
              setPage(1);
            }}
            placeholder="CVE, título, producto, editor, hostname o IP"
            label="Buscar vulnerabilidades"
          />
        </Toolbar>
        {error && data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {loading ? (
          <LoadingState label="Cargando vulnerabilidades…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="Sin vulnerabilidades para este filtro">
            Sentra compara el software inventariado por los agentes con el catálogo local. Un puerto abierto no es una
            vulnerabilidad.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <SortHeader label="Prioridad" sortKey="priority" sort={sort} onSort={changeSort} numeric />
                    <th>Vulnerabilidad</th>
                    <SortHeader label="Severidad" sortKey="severity" sort={sort} onSort={changeSort} numeric />
                    <SortHeader label="CVSS" sortKey="cvss" sort={sort} onSort={changeSort} numeric />
                    <th>Evidencia</th>
                    <th>Activo</th>
                    <SortHeader label="Riesgo activo" sortKey="asset_risk" sort={sort} onSort={changeSort} numeric />
                    <th>Componente</th>
                    <th>Exposición</th>
                    <th>Estado</th>
                    <SortHeader label="Última vez" sortKey="last_seen" sort={sort} onSort={changeSort} numeric />
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((f) => (
                    <tr
                      key={f.finding_id}
                      className="table__row--link"
                      onClick={() => navigate(`/vulnerabilities/${f.finding_id}`)}
                    >
                      <td>
                        <PriorityBadge score={f.priority_score} level={f.priority_level} />
                      </td>
                      <td>
                        <Link
                          className="vuln-id"
                          to={`/vulnerabilities/${f.finding_id}`}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {f.vulnerability_id}
                        </Link>
                        <div className="muted small">{f.title}</div>
                      </td>
                      <td>
                        <VulnSeverityBadge severity={f.severity} />
                      </td>
                      <td>{formatCvss(f.cvss_score, f.cvss_version)}</td>
                      <td>
                        <MatchBadge state={f.match_state} confidence={f.confidence} />
                      </td>
                      <td>
                        <Link to={`/assets/${f.asset.asset_id}`} onClick={(e) => e.stopPropagation()}>
                          {f.asset.name}
                        </Link>
                        <div className="muted small mono">{f.asset.primary_ip}</div>
                      </td>
                      <td>{f.asset.risk_score ?? "—"}</td>
                      <td>
                        {f.component_name}
                        <div className="muted small">
                          {f.installed_version ?? "versión desconocida"}
                          {f.fixed_version && ` → ${f.fixed_version}`}
                        </div>
                      </td>
                      <td>
                        <ExposureBadge state={f.exposure_state} />
                      </td>
                      <td>
                        <FindingStatusBadge status={f.status} />
                        {f.stale && <div className="badge badge--warn">Evidencia antigua</div>}
                      </td>
                      <td title={formatDateTime(f.last_seen_at)}>{formatRelative(f.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager
              page={Math.min(page, pages)}
              pages={pages}
              total={data.total}
              onPage={setPage}
              noun="vulnerabilidades"
            />
          </>
        )}
      </section>
    </div>
  );
}
