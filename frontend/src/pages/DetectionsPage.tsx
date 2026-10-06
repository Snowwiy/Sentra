import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { detectionsApi } from "../api/sentra";
import type {
  DetectionConfidence,
  DetectionRule,
  DetectionSeverity,
  DetectionStatus,
} from "../api/types";
import { config } from "../config";
import {
  CONFIDENCE_LABELS,
  CONFIDENCE_ORDER,
  ConfidenceBadge,
  DetectionSeverityBadge,
  DetectionStatusBadge,
  SEVERITY_LABELS,
  SEVERITY_ORDER,
} from "../components/detections/DetectionBadges";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { useAssetOptions } from "../lib/useAssetOptions";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;

type StatusFilter = "active" | DetectionStatus | "all";

const STATUS_FILTERS: { key: StatusFilter; label: string }[] = [
  { key: "active", label: "Activas" },
  { key: "open", label: "Abiertas" },
  { key: "acknowledged", label: "Reconocidas" },
  { key: "resolved", label: "Resueltas" },
  { key: "all", label: "Todas" },
];

// Rango sobre la última actividad (last_seen_at), en horas.
const RANGES = [
  { value: "1", label: "Última hora" },
  { value: "24", label: "Últimas 24 h" },
  { value: "168", label: "Últimos 7 días" },
  { value: "720", label: "Últimos 30 días" },
];

/**
 * Detecciones del motor: conclusiones con evidencia, no notificaciones (eso son las alertas).
 * El activo puede venir en la URL (?asset=<id>) desde el detalle de un activo.
 */
export function DetectionsPage() {
  const navigate = useNavigate();
  const [params, setParams] = useSearchParams();
  const assetId = params.get("asset") ?? "";
  const [status, setStatus] = useState<StatusFilter>("active");
  const [severity, setSeverity] = useState("");
  const [confidence, setConfidence] = useState("");
  const [rule, setRule] = useState("");
  const [range, setRange] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [assetQuery, setAssetQuery] = useState("");
  const assets = useAssetOptions(assetQuery, assetId);
  const q = useDebounced(query);

  // Catálogos de los filtros: si fallan, los filtros quedan vacíos pero la lista funciona.
  useEffect(() => {
    const controller = new AbortController();
    detectionsApi
      .rules(controller.signal)
      .then((list) => setRules(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  const fetchDetections = useCallback(
    (signal: AbortSignal) =>
      detectionsApi.list(
        {
          active: status === "active",
          status: status === "active" || status === "all" ? undefined : status,
          severity: (severity || undefined) as DetectionSeverity | undefined,
          confidence: (confidence || undefined) as DetectionConfidence | undefined,
          ruleId: rule || undefined,
          assetId: assetId || undefined,
          // El instante se redondea al minuto para no cambiar la petición en cada render.
          since: range
            ? new Date(Math.floor(Date.now() / 60_000) * 60_000 - Number(range) * 3_600_000).toISOString()
            : undefined,
          q,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [status, severity, confidence, rule, assetId, range, q, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchDetections, config.refreshIntervalMs);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const reset =
    <T,>(set: (v: T) => void) =>
    (value: T) => {
      set(value);
      setPage(1);
    };
  const setAsset = (value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set("asset", value);
    else next.delete("asset");
    setParams(next, { replace: true });
    setPage(1);
  };

  return (
    <div className="page">
      <div className="page__header">
        <h1>Detecciones</h1>
        <Link to="/detections/rules" className="button">
          Reglas
        </Link>
      </div>
      <section className="panel">
        <Toolbar>
          <div className="segmented" role="group" aria-label="Filtrar por estado">
            {STATUS_FILTERS.map(({ key, label }) => (
              <button
                key={key}
                type="button"
                className={`segmented__item${status === key ? " segmented__item--active" : ""}`}
                aria-pressed={status === key}
                onClick={() => reset(setStatus)(key)}
              >
                {label}
              </button>
            ))}
          </div>
          <FilterSelect
            label="Severidad"
            value={severity}
            options={SEVERITY_ORDER.map((value) => ({ value, label: SEVERITY_LABELS[value] }))}
            onChange={reset(setSeverity)}
            allLabel="Todas"
          />
          <FilterSelect
            label="Confianza"
            value={confidence}
            options={CONFIDENCE_ORDER.map((value) => ({ value, label: CONFIDENCE_LABELS[value] }))}
            onChange={reset(setConfidence)}
            allLabel="Todas"
          />
          <FilterSelect
            label="Regla"
            value={rule}
            options={rules.map((r) => ({ value: r.rule_id, label: `${r.rule_id} · ${r.title}` }))}
            onChange={reset(setRule)}
            allLabel="Todas"
          />
          <SearchInput
            value={assetQuery}
            onChange={setAssetQuery}
            placeholder="Buscar activo"
            label="Buscar activo"
          />
          <FilterSelect
            label="Activo"
            value={assetId}
            options={assets.map((a) => ({ value: a.asset_id, label: a.display_name }))}
            onChange={setAsset}
          />
          <FilterSelect label="Periodo" value={range} options={RANGES} onChange={reset(setRange)} allLabel="Siempre" />
          <SearchInput
            value={query}
            onChange={reset(setQuery)}
            placeholder="Buscar en título, regla o activo"
            label="Buscar detecciones"
          />
        </Toolbar>
        {error && data && (
          <div className="banner banner--warn" role="alert">
            Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
          </div>
        )}
        {loading ? (
          <LoadingState label="Cargando detecciones…" />
        ) : !data && error ? (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        ) : !data || data.items.length === 0 ? (
          <EmptyState title="Sin detecciones para este filtro">
            El motor evalúa eventos de seguridad, cambios de inventario, procesos nuevos y exposición de red. La primera
            recogida de cada activo solo fija la línea base.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Severidad</th>
                    <th>Confianza</th>
                    <th>Regla</th>
                    <th>Activo</th>
                    <th>Título</th>
                    <th>Primera vez</th>
                    <th>Última vez</th>
                    <th>Ocurrencias</th>
                    <th>Estado</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((d) => (
                    <tr
                      key={d.detection_id}
                      className="table__row--link"
                      onClick={() => navigate(`/detections/${d.detection_id}`)}
                    >
                      <td>
                        <DetectionSeverityBadge severity={d.severity} />
                      </td>
                      <td>
                        <ConfidenceBadge confidence={d.confidence} />
                      </td>
                      <td className="mono">{d.rule_id}</td>
                      <td>
                        <Link to={`/assets/${d.asset_id}`} className="strong" onClick={(e) => e.stopPropagation()}>
                          {d.hostname}
                        </Link>
                      </td>
                      <td>
                        <Link to={`/detections/${d.detection_id}`} onClick={(e) => e.stopPropagation()}>
                          {d.title}
                        </Link>
                      </td>
                      <td title={formatDateTime(d.first_seen_at)}>{formatRelative(d.first_seen_at)}</td>
                      <td title={formatDateTime(d.last_seen_at)}>{formatRelative(d.last_seen_at)}</td>
                      <td className="mono">{d.occurrence_count}</td>
                      <td>
                        <DetectionStatusBadge status={d.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="detecciones" />
          </>
        )}
      </section>
    </div>
  );
}
