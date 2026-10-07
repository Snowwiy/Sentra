import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { threatIntelApi } from "../../api/sentra";
import type { IndicatorClassification, ObservationType, ThreatMatchStatus } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  CLASSIFICATION_LABELS,
  CLASSIFICATION_ORDER,
  CONFIDENCE_LABELS,
  MATCH_STATUS_LABELS,
  OBSERVATION_LABELS,
  TRUST_LABELS,
} from "../../lib/threatIntel";
import { usePolling } from "../../lib/usePolling";
import { FilterSelect, Pager, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { ClassificationBadge, MatchStatusBadge } from "./IntelBadges";

const PAGE_SIZE = 50;

/** Coincidencias de indicadores con datos locales (todas o las de un activo). */
export function MatchesTable({ assetId }: { assetId?: string }) {
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ status: "", classification: "", observation: "" });
  const [page, setPage] = useState(1);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      threatIntelApi.matches(
        {
          status: (filters.status || undefined) as ThreatMatchStatus | undefined,
          active: !filters.status,
          classification: (filters.classification || undefined) as IndicatorClassification | undefined,
          observationType: (filters.observation || undefined) as ObservationType | undefined,
          assetId,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [filters, page, assetId],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs, true, true);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const set = (key: keyof typeof filters) => (value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
  };
  return (
    <section className="panel">
      <Toolbar>
        <FilterSelect
          label="Estado"
          value={filters.status}
          options={(["open", "acknowledged", "dismissed"] as const).map((value) => ({
            value,
            label: MATCH_STATUS_LABELS[value],
          }))}
          onChange={set("status")}
          allLabel="No descartados"
        />
        <FilterSelect
          label="Clasificación"
          value={filters.classification}
          options={CLASSIFICATION_ORDER.map((value) => ({ value, label: CLASSIFICATION_LABELS[value] }))}
          onChange={set("classification")}
          allLabel="Todas"
        />
        <FilterSelect
          label="Observación"
          value={filters.observation}
          options={Object.entries(OBSERVATION_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={set("observation")}
          allLabel="Todas"
        />
      </Toolbar>
      {loading ? (
        <LoadingState label="Cargando coincidencias…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin coincidencias">
          Sentra solo busca coincidencias exactas de IPs, redes y nombres de activos en datos que ya tiene (inicios de
          sesión, conexiones establecidas e inventario de activos).
        </EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Indicador</th>
                  <th>Activo</th>
                  <th>Observado en</th>
                  <th>Clasificación</th>
                  <th>Confianza</th>
                  <th>Veces</th>
                  <th>Última vez</th>
                  <th>Estado</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((m) => (
                  <tr
                    key={m.match_id}
                    className="table__row--link"
                    onClick={() => navigate(`/threat-intel/matches/${m.match_id}`)}
                  >
                    <td className="mono">
                      <Link to={`/threat-intel/matches/${m.match_id}`} onClick={(e) => e.stopPropagation()}>
                        {m.indicator_value}
                      </Link>
                      <div className="muted small">
                        {m.source_name} · {TRUST_LABELS[m.source_trust]}
                      </div>
                    </td>
                    <td>
                      <Link to={`/assets/${m.asset.asset_id}`} onClick={(e) => e.stopPropagation()}>
                        {m.asset.name}
                      </Link>
                    </td>
                    <td>
                      {OBSERVATION_LABELS[m.observation_type]}
                      <div className="muted small mono">{m.observed_value}</div>
                    </td>
                    <td>
                      <ClassificationBadge value={m.classification} />
                    </td>
                    <td>{CONFIDENCE_LABELS[m.match_confidence]}</td>
                    <td>{m.observation_count}</td>
                    <td title={formatDateTime(m.last_observed_at)}>{formatRelative(m.last_observed_at)}</td>
                    <td>
                      <MatchStatusBadge status={m.status} />
                      {m.detection_id && <div className="muted small">Con detección</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="coincidencias" />
        </>
      )}
    </section>
  );
}
