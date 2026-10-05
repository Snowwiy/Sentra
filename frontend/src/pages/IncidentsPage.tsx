import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { incidentsApi } from "../api/sentra";
import type { IncidentLevel, IncidentSort, IncidentStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { CreateIncidentModal } from "../components/incidents/CreateIncidentModal";
import { IncidentStatusBadge, LevelBadge } from "../components/incidents/IncidentBadges";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { formatDuration, LEVEL_LABELS, LEVEL_ORDER, STATUS_LABELS, STATUS_ORDER } from "../lib/incidents";
import type { SortState } from "../lib/listing";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;

// "active" = open, triage, investigating y contained (el filtro por defecto del SOC).
type StatusFilter = "active" | "all" | IncidentStatus;

interface Filters {
  status: StatusFilter;
  severity: string;
  priority: string;
  owner: string;
}

const DEFAULT_FILTERS: Filters = { status: "active", severity: "", priority: "", owner: "" };

type CardKey = "open" | "triage" | "investigating" | "critical" | "unassigned" | "mine";

// Cada tarjeta es un atajo a un filtro del listado (los números vienen de /incidents/overview).
const CARDS: { key: CardKey; label: string; tone: string; filters: Filters }[] = [
  { key: "open", label: "Abiertos", tone: "stat--offline", filters: { ...DEFAULT_FILTERS, status: "open" } },
  { key: "triage", label: "Triage", tone: "", filters: { ...DEFAULT_FILTERS, status: "triage" } },
  {
    key: "investigating",
    label: "Investigando",
    tone: "",
    filters: { ...DEFAULT_FILTERS, status: "investigating" },
  },
  { key: "critical", label: "Críticos", tone: "stat--crit", filters: { ...DEFAULT_FILTERS, severity: "critical" } },
  {
    key: "unassigned",
    label: "Sin asignar",
    tone: "stat--idle",
    filters: { ...DEFAULT_FILTERS, owner: "unassigned" },
  },
  { key: "mine", label: "Asignados a mí", tone: "stat--online", filters: { ...DEFAULT_FILTERS, owner: "me" } },
];

const OWNER_OPTIONS = [
  { value: "me", label: "Asignados a mí" },
  { value: "unassigned", label: "Sin asignar" },
];

function sameFilters(a: Filters, b: Filters): boolean {
  return a.status === b.status && a.severity === b.severity && a.priority === b.priority && a.owner === b.owner;
}

/**
 * Lista de incidentes del SOC. Todo (filtros, búsqueda, orden y paginación) lo resuelve el
 * servidor; el navegador no guarda nada del caso.
 */
export function IncidentsPage() {
  const auth = useAuth();
  const navigate = useNavigate();
  const [filters, setFilters] = useState<Filters>(DEFAULT_FILTERS);
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortState<IncidentSort>>({ key: "last_activity", dir: "desc" });
  const [page, setPage] = useState(1);
  const [creating, setCreating] = useState(false);
  const q = useDebounced(query);

  const fetchOverview = useCallback((signal: AbortSignal) => incidentsApi.overview(signal), []);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs);

  const fetchIncidents = useCallback(
    (signal: AbortSignal) =>
      incidentsApi.list(
        {
          active: filters.status === "active",
          status: filters.status === "active" || filters.status === "all" ? undefined : filters.status,
          severity: (filters.severity || undefined) as IncidentLevel | undefined,
          priority: (filters.priority || undefined) as IncidentLevel | undefined,
          owner: filters.owner || undefined,
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
  const { data, error, loading, refresh } = usePolling(fetchIncidents, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));

  const setFilter = (key: keyof Filters) => (value: string) => {
    setFilters((current) => ({ ...current, [key]: value || (key === "status" ? "active" : "") }));
    setPage(1);
  };
  const changeSort = (next: SortState<IncidentSort>) => {
    setSort(next);
    setPage(1);
  };
  const applyCard = (next: Filters) => {
    setFilters((current) => (sameFilters(current, next) ? DEFAULT_FILTERS : next));
    setPage(1);
  };
  const counts: Record<CardKey, number | undefined> = {
    open: overview.data?.open,
    triage: overview.data?.triage,
    investigating: overview.data?.investigating,
    critical: overview.data?.critical,
    unassigned: overview.data?.unassigned,
    mine: overview.data?.assigned_to_me,
  };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Incidentes</h1>
          {overview.data && (
            <p className="muted small">
              Edad media de los casos activos: {formatDuration(overview.data.mean_age_seconds)} (dato observado, no
              un SLA)
            </p>
          )}
        </div>
        {auth.can("incidents:manage") && (
          <button type="button" className="button button--primary" onClick={() => setCreating(true)}>
            Nuevo incidente
          </button>
        )}
      </div>

      <section className="stats stats--6" aria-label="Resumen de incidentes">
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
            allLabel="Activos"
          />
          <FilterSelect
            label="Severidad"
            value={filters.severity}
            options={LEVEL_ORDER.map((value) => ({ value, label: LEVEL_LABELS[value] }))}
            onChange={setFilter("severity")}
            allLabel="Todas"
          />
          <FilterSelect
            label="Prioridad"
            value={filters.priority}
            options={LEVEL_ORDER.map((value) => ({ value, label: LEVEL_LABELS[value] }))}
            onChange={setFilter("priority")}
            allLabel="Todas"
          />
          <FilterSelect label="Responsable" value={filters.owner} options={OWNER_OPTIONS} onChange={setFilter("owner")} />
          <SearchInput
            value={query}
            onChange={(value) => {
              setQuery(value);
              setPage(1);
            }}
            placeholder="INC-000123, título, hostname, IP o detección"
            label="Buscar incidentes"
          />
        </Toolbar>
        {error && data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {loading ? (
          <LoadingState label="Cargando incidentes…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="Sin incidentes para este filtro">
            Un incidente agrupa detecciones, alertas y activos relacionados. Créalo a mano o desde una detección o
            alerta.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <SortHeader label="Incidente" sortKey="number" sort={sort} onSort={changeSort} numeric />
                    <th>Título</th>
                    <SortHeader label="Severidad" sortKey="severity" sort={sort} onSort={changeSort} numeric />
                    <SortHeader label="Prioridad" sortKey="priority" sort={sort} onSort={changeSort} numeric />
                    <SortHeader label="Estado" sortKey="status" sort={sort} onSort={changeSort} />
                    <th>Responsable</th>
                    <th>Activos</th>
                    <SortHeader
                      label="Última actividad"
                      sortKey="last_activity"
                      sort={sort}
                      onSort={changeSort}
                      numeric
                    />
                    <SortHeader label="Creado" sortKey="created_at" sort={sort} onSort={changeSort} numeric />
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((incident) => (
                    <tr
                      key={incident.incident_id}
                      className="table__row--link"
                      onClick={() => navigate(`/incidents/${incident.incident_id}`)}
                    >
                      <td className="incident-key">{incident.key}</td>
                      <td>
                        <Link to={`/incidents/${incident.incident_id}`} onClick={(e) => e.stopPropagation()}>
                          {incident.title}
                        </Link>
                      </td>
                      <td>
                        <LevelBadge level={incident.severity} kind="severity" />
                      </td>
                      <td>
                        <LevelBadge level={incident.priority} kind="priority" />
                      </td>
                      <td>
                        <IncidentStatusBadge status={incident.status} />
                      </td>
                      <td>
                        {incident.owner ? (
                          <span className={incident.owner.active ? "" : "muted"}>
                            {incident.owner.username}
                            {!incident.owner.active && " (desactivado)"}
                          </span>
                        ) : (
                          <span className="muted">Sin asignar</span>
                        )}
                      </td>
                      <td className="muted">
                        {incident.assets.join(", ") || "—"}
                        {incident.asset_count > incident.assets.length &&
                          ` +${incident.asset_count - incident.assets.length}`}
                      </td>
                      <td title={formatDateTime(incident.last_activity_at)}>{formatRelative(incident.last_activity_at)}</td>
                      <td title={formatDateTime(incident.created_at)}>{formatRelative(incident.created_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="incidentes" />
          </>
        )}
      </section>

      {creating && (
        <CreateIncidentModal
          onClose={() => setCreating(false)}
          onCreated={(incident) => navigate(`/incidents/${incident.incident_id}`)}
        />
      )}
    </div>
  );
}
