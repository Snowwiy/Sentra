import { useCallback, useMemo } from "react";
import { sensorsApi, sitesApi } from "../../api/sentra";
import type { ObservationMethod, ObservationReachability } from "../../api/types";
import { METHOD_NAMES, REACHABILITY_LABELS } from "../../lib/discovery";
import { ApiError } from "../../api/client";
import { errorMessage } from "../../lib/format";
import { useDebounced } from "../../lib/useDebounced";
import { useListState } from "../../lib/useListState";
import { usePolling } from "../../lib/usePolling";
import { useSite } from "../../site/SiteContext";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { LatestObservationRows, OBSERVATION_PAGE_SIZE, useObservations } from "./ObservationTable";

const METHODS: ObservationMethod[] = ["icmp", "tcp", "arp", "dns"];
const REACHABILITIES: ObservationReachability[] = ["responded", "no_response", "unknown"];
// Sensores y redes de un site cambian poco: basta con consultarlos cada pocos minutos.
const CATALOG_MS = 5 * 60_000;
const REFRESH_MS = 60_000;
/** Valor del filtro "Sensor" para lo ejecutado desde el servidor local. */
const LOCAL = "local";

type Filters = { site: string; network: string; sensor: string; method: string; reachability: string };

/**
 * Fase 6A: última observación por (site, IP), con filtros y paginación en el servidor.
 *
 * `allowedNetworks` son las redes autorizadas del servidor local; con un site concreto se
 * añaden las redes de ese site. El servidor vuelve a validar cada filtro (422 si no vale).
 */
export function NetworkObservations({ scopeId, allowedNetworks }: { scopeId: string | undefined; allowedNetworks: string[] }) {
  const site = useSite();
  const list = useListState<"observed", Filters>(
    { key: "observed", dir: "desc" },
    { site: "", network: "", sensor: "", method: "", reachability: "" },
  );
  const { filters } = list;
  // Con un alcance global elegido el site lo fija el selector de la cabecera.
  const siteId = scopeId ?? (filters.site || undefined);
  const showSiteFilter = !scopeId && site.selectableSites.length > 1;
  const showSite = !siteId && site.sites.length > 1;

  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(siteId, signal), [siteId]);
  const sensors = usePolling(fetchSensors, CATALOG_MS, site.sites.length > 0);
  const fetchNetworks = useCallback(
    (signal: AbortSignal) => sitesApi.networks(siteId ?? "", signal),
    [siteId],
  );
  const siteNetworks = usePolling(fetchNetworks, CATALOG_MS, Boolean(siteId));

  const networks = useMemo(() => {
    const known = new Set(allowedNetworks);
    for (const n of siteNetworks.data?.items ?? []) known.add(n.cidr);
    return [...known];
  }, [allowedNetworks, siteNetworks.data]);

  const q = useDebounced(list.query.trim(), 300);
  const observations = useObservations(
    {
      latest: true,
      siteId,
      network: filters.network || undefined,
      executor: filters.sensor === LOCAL ? "local" : undefined,
      sensorId: filters.sensor && filters.sensor !== LOCAL ? filters.sensor : undefined,
      method: (filters.method || undefined) as ObservationMethod | undefined,
      reachability: (filters.reachability || undefined) as ObservationReachability | undefined,
      q: q || undefined,
    },
    list.page,
    REFRESH_MS,
  );

  const data = observations.data;
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / OBSERVATION_PAGE_SIZE));
  const filtered = Boolean(
    list.query.trim() || filters.site || filters.network || filters.sensor || filters.method || filters.reachability,
  );
  const sensorOptions = [
    { value: LOCAL, label: "Servidor local" },
    ...(sensors.data?.items ?? []).map((s) => ({ value: s.sensor_id, label: s.name })),
  ];

  return (
    <section className="panel" aria-label="Observaciones de red">
      <div className="panel__toolbar">
        <h2>Observaciones de red</h2>
        <span className="muted small">Última observación de cada IP por site.</span>
      </div>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={(value) => list.setQuery(value.slice(0, 100))}
          placeholder="Buscar IP, hostname o MAC"
          label="Buscar observaciones"
        />
        {showSiteFilter && (
          <FilterSelect
            label="Site"
            value={filters.site}
            options={site.selectableSites.map((s) => ({ value: s.site_id, label: s.name }))}
            onChange={(value) => {
              list.setFilter("site", value);
              // Red y sensor dependen del site: se limpian para no dejar un filtro imposible.
              list.setFilter("network", "");
              list.setFilter("sensor", "");
            }}
          />
        )}
        {networks.length > 0 && (
          <FilterSelect
            label="Red"
            value={filters.network}
            options={networks}
            onChange={(value) => list.setFilter("network", value)}
            allLabel="Todas"
          />
        )}
        <FilterSelect
          label="Sensor"
          value={filters.sensor}
          options={sensorOptions}
          onChange={(value) => list.setFilter("sensor", value)}
        />
        <FilterSelect
          label="Método"
          value={filters.method}
          options={METHODS.map((m) => ({ value: m, label: METHOD_NAMES[m] }))}
          onChange={(value) => list.setFilter("method", value)}
        />
        <FilterSelect
          label="Alcance"
          value={filters.reachability}
          options={REACHABILITIES.map((r) => ({ value: r, label: REACHABILITY_LABELS[r] }))}
          onChange={(value) => list.setFilter("reachability", value)}
        />
      </Toolbar>
      {data && observations.error && (
        <div className="banner banner--warn" role="alert">
          {filterError(observations.error)}
        </div>
      )}
      {!data ? (
        observations.error ? (
          <ErrorState message={filterError(observations.error, false)} onRetry={observations.refresh} />
        ) : (
          <LoadingState label="Cargando observaciones…" />
        )
      ) : data.items.length === 0 ? (
        filtered || list.page > 1 ? (
          <EmptyState title="Ninguna observación coincide con el filtro" />
        ) : (
          <EmptyState title="Sin observaciones">
            Lanza un descubrimiento con un perfil avanzado (Quick, Standard o Deep) para registrar
            observaciones de red.
          </EmptyState>
        )
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hostname</th>
                  <th>MAC</th>
                  {showSite && <th>Site</th>}
                  <th>Fuente</th>
                  <th>Alcance</th>
                  <th>Puertos</th>
                  <th>Última vez</th>
                  <th>Confianza</th>
                </tr>
              </thead>
              <tbody>
                <LatestObservationRows items={data.items} showSite={showSite} />
              </tbody>
            </table>
          </div>
          <Pager page={list.page} pages={pages} total={total} onPage={list.setPage} noun="observaciones" />
        </>
      )}
    </section>
  );
}

function filterError(error: Error, stale = true): string {
  if (error instanceof ApiError && error.code === "discovery_filter_invalid") {
    return `El servidor rechazó el filtro: ${error.message}`;
  }
  return stale ? `Fallo al actualizar: ${errorMessage(error)}. Se muestran los últimos datos.` : errorMessage(error);
}
