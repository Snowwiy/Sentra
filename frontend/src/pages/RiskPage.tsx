import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { riskApi, type RiskSortKey } from "../api/sentra";
import type { AssetCriticality, AssetStatus, RiskConfidence, RiskLevel } from "../api/types";
import { config } from "../config";
import { FilterSelect, Pager, SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import { CriticalityBadge, RiskLevelBadge } from "../components/risk/RiskBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { StatusBadge } from "../components/StatusBadge";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { DEVICE_TYPE_LABELS, deviceTypeLabel } from "../lib/identity";
import type { SortState } from "../lib/listing";
import {
  CRITICALITY_LABELS,
  CRITICALITY_ORDER,
  formatPoints,
  reasonLabel,
  RISK_CATEGORY_LABELS,
  RISK_CONFIDENCE_LABELS,
  RISK_CONFIDENCE_ORDER,
  RISK_LEVEL_LABELS,
  RISK_LEVEL_ORDER,
} from "../lib/risk";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;

// Tarjetas del resumen: los cuatro niveles accionables más el total evaluado.
const LEVEL_CARDS: RiskLevel[] = ["critical", "high", "medium", "low"];

const STATUS_OPTIONS: { value: AssetStatus; label: string }[] = [
  { value: "online", label: "Online" },
  { value: "offline", label: "Offline" },
  { value: "unknown", label: "Desconocido" },
];

const DEVICE_OPTIONS = [
  ...Object.entries(DEVICE_TYPE_LABELS).map(([value, label]) => ({ value, label })),
  { value: "unknown", label: "Sin clasificar" },
];

/**
 * Riesgo por activo (motor 4I): score 0-100, nivel y confianza por separado. El cálculo es
 * determinista y vive en el backend; aquí solo se presenta y se filtra, nunca se recalcula.
 */
export function RiskPage() {
  const navigate = useNavigate();
  const [level, setLevel] = useState("");
  const [confidence, setConfidence] = useState("");
  const [deviceType, setDeviceType] = useState("");
  const [status, setStatus] = useState("");
  const [criticality, setCriticality] = useState("");
  const [query, setQuery] = useState("");
  const [sort, setSort] = useState<SortState<RiskSortKey>>({ key: "score", dir: "desc" });
  const [page, setPage] = useState(1);
  const q = useDebounced(query);

  const fetchOverview = useCallback((signal: AbortSignal) => riskApi.overview(signal), []);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs);

  const fetchList = useCallback(
    (signal: AbortSignal) =>
      riskApi.list(
        {
          level: (level || undefined) as RiskLevel | undefined,
          confidence: (confidence || undefined) as RiskConfidence | undefined,
          deviceType: deviceType || undefined,
          status: (status || undefined) as AssetStatus | undefined,
          criticality: (criticality || undefined) as AssetCriticality | undefined,
          q,
          sort: sort.key,
          order: sort.dir,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [level, confidence, deviceType, status, criticality, q, sort, page],
  );
  const list = usePolling(fetchList, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((list.data?.total ?? 0) / PAGE_SIZE));
  const reset =
    <T,>(set: (v: T) => void) =>
    (value: T) => {
      set(value);
      setPage(1);
    };
  const sortHeader = (label: string, key: RiskSortKey, numeric = false) => (
    <SortHeader label={label} sortKey={key} sort={sort} onSort={reset(setSort)} numeric={numeric} />
  );

  const data = overview.data;
  return (
    <div className="page">
      <div className="page__header">
        <h1>Riesgo</h1>
        {data?.last_calculated_at && (
          <span className="muted small" title={formatDateTime(data.last_calculated_at)}>
            Último cálculo {formatRelative(data.last_calculated_at)}
          </span>
        )}
      </div>

      {overview.error && !data && <ErrorState message={errorMessage(overview.error)} onRetry={overview.refresh} />}
      {data && (
        <>
          <section className="stats stats--5" aria-label="Activos por nivel de riesgo">
            {LEVEL_CARDS.map((key) => (
              <button
                key={key}
                type="button"
                className={`stat stat--risk-${key}${level === key ? " stat--active" : ""}`}
                aria-pressed={level === key}
                onClick={() => reset(setLevel)(level === key ? "" : key)}
              >
                <span className="stat__label">{RISK_LEVEL_LABELS[key]}</span>
                <span className="stat__value">{data.by_level[key]}</span>
              </button>
            ))}
            <button
              type="button"
              className={`stat${level === "" ? " stat--active" : ""}`}
              aria-pressed={level === ""}
              onClick={() => reset(setLevel)("")}
            >
              <span className="stat__label">Total evaluados</span>
              <span className="stat__value">{data.evaluated}</span>
              {data.pending > 0 && <span className="muted small">{data.pending} pendientes</span>}
            </button>
          </section>

          <div className="risk-columns">
            <section className="panel" aria-label="Principales factores de riesgo">
              <div className="panel__toolbar">
                <h3>Principales factores</h3>
              </div>
              {data.top_factors.length === 0 ? (
                <p className="muted small risk-empty">Ningún factor activo.</p>
              ) : (
                <ul className="risk-factors risk-factors--padded">
                  {data.top_factors.map((factor) => (
                    <li key={`${factor.category}-${factor.label}`}>
                      <span>
                        {factor.label}{" "}
                        <span className="muted small">
                          · {RISK_CATEGORY_LABELS[factor.category] ?? factor.category} · {factor.assets}{" "}
                          {factor.assets === 1 ? "activo" : "activos"}
                        </span>
                      </span>
                      <span className="mono risk-points risk-points--up">{formatPoints(factor.points)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
            <section className="panel" aria-label="Transiciones recientes">
              <div className="panel__toolbar">
                <h3>Transiciones recientes</h3>
              </div>
              {data.recent_transitions.length === 0 ? (
                <p className="muted small risk-empty">Sin cambios de nivel recientes.</p>
              ) : (
                <ul className="risk-changes risk-changes--padded">
                  {data.recent_transitions.map((t) => (
                    <li key={t.snapshot_id}>
                      <span className="muted small" title={formatDateTime(t.calculated_at)}>
                        {formatRelative(t.calculated_at)}
                      </span>{" "}
                      {t.transition && (
                        <span className={`risk-arrow risk-arrow--${t.transition}`} aria-hidden="true">
                          {t.transition === "up" ? "▲" : "▼"}
                        </span>
                      )}{" "}
                      <Link to={`/assets/${t.asset_id}?tab=risk`}>{t.display_name}</Link>{" "}
                      {t.previous_level ? `${RISK_LEVEL_LABELS[t.previous_level]} → ` : ""}
                      <strong>{RISK_LEVEL_LABELS[t.level]}</strong> ({t.score})
                      <span className="muted small"> · {reasonLabel(t.reason)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </div>
        </>
      )}

      <section className="panel">
        <Toolbar>
          <FilterSelect
            label="Nivel"
            value={level}
            options={RISK_LEVEL_ORDER.map((value) => ({ value, label: RISK_LEVEL_LABELS[value] }))}
            onChange={reset(setLevel)}
          />
          <FilterSelect
            label="Confianza"
            value={confidence}
            options={RISK_CONFIDENCE_ORDER.map((value) => ({ value, label: RISK_CONFIDENCE_LABELS[value] }))}
            onChange={reset(setConfidence)}
            allLabel="Todas"
          />
          <FilterSelect label="Tipo" value={deviceType} options={DEVICE_OPTIONS} onChange={reset(setDeviceType)} />
          <FilterSelect label="Estado" value={status} options={STATUS_OPTIONS} onChange={reset(setStatus)} />
          <FilterSelect
            label="Criticidad"
            value={criticality}
            options={CRITICALITY_ORDER.map((value) => ({ value, label: CRITICALITY_LABELS[value] }))}
            onChange={reset(setCriticality)}
            allLabel="Todas"
          />
          <SearchInput
            value={query}
            onChange={reset(setQuery)}
            placeholder="Buscar nombre o IP"
            label="Buscar activos por riesgo"
          />
        </Toolbar>
        {list.error && list.data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(list.error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {list.loading ? (
          <LoadingState label="Cargando riesgo…" />
        ) : !list.data && list.error ? (
          <ErrorState message={errorMessage(list.error)} onRetry={list.refresh} />
        ) : !list.data || list.data.items.length === 0 ? (
          <EmptyState title="Ningún activo para este filtro">
            El riesgo se calcula a partir de las detecciones, la exposición de red y la criticidad de cada activo. Un
            activo nuevo aparece como pendiente hasta su primer cálculo.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    {sortHeader("Activo", "name")}
                    {sortHeader("Risk score", "score", true)}
                    <th>Risk level</th>
                    <th>Confianza</th>
                    {sortHeader("Criticidad", "criticality", true)}
                    <th>Principal factor</th>
                    {sortHeader("Último cambio", "changed_at", true)}
                    {sortHeader("Last seen", "last_seen", true)}
                  </tr>
                </thead>
                <tbody>
                  {list.data.items.map((item) => (
                    <tr
                      key={item.asset_id}
                      className="table__row--link"
                      onClick={() => navigate(`/assets/${item.asset_id}?tab=risk`)}
                    >
                      <td>
                        <Link
                          to={`/assets/${item.asset_id}?tab=risk`}
                          className="strong"
                          onClick={(e) => e.stopPropagation()}
                        >
                          {item.display_name}
                        </Link>
                        <div className="muted small">
                          <span className="mono">{item.primary_ip}</span> · {deviceTypeLabel(item.device_type)}{" "}
                          <StatusBadge status={item.status} />
                        </div>
                      </td>
                      <td className="mono strong">{item.score ?? <span className="muted">Pendiente</span>}</td>
                      <td>{item.level ? <RiskLevelBadge level={item.level} /> : <span className="muted">—</span>}</td>
                      <td>{item.confidence ? RISK_CONFIDENCE_LABELS[item.confidence] : "—"}</td>
                      <td>
                        <CriticalityBadge criticality={item.criticality} />
                      </td>
                      <td>{item.top_factor ?? <span className="muted">—</span>}</td>
                      <td title={formatDateTime(item.changed_at)}>{formatRelative(item.changed_at)}</td>
                      <td title={formatDateTime(item.last_seen_at)}>{formatRelative(item.last_seen_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={list.data.total} onPage={setPage} noun="activos" />
          </>
        )}
      </section>
    </div>
  );
}
