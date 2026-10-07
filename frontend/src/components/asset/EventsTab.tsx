import { useCallback, useState } from "react";
import { sentraApi } from "../../api/sentra";
import type { Asset, EventCoverageState, EventLevel } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  COVERAGE_CLASSES,
  COVERAGE_LABELS,
  COVERAGE_SOURCES,
  LINUX_EVENT_TYPES,
  LINUX_PROVIDERS,
  isLinux,
} from "../../lib/linuxEvents";
import { useDebounced } from "../../lib/useDebounced";
import { usePolling } from "../../lib/usePolling";
import { EventTable } from "../EventTable";
import { FilterSelect, SearchInput, Toolbar } from "../ListControls";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

const PAGE_SIZE = 50;

const LEVELS: { value: EventLevel; label: string }[] = [
  { value: "warning", label: "Warning o más" },
  { value: "error", label: "Error o más" },
  { value: "critical", label: "Critical" },
];

// The channels the agent collects (see agent/sentra_agent/events.py).
const CHANNELS = ["System", "Application", "Security", "Microsoft-Windows-PowerShell/Operational"];

const EVENT_TYPES = Object.entries(LINUX_EVENT_TYPES).map(([value, label]) => ({ value, label }));

const COPY = {
  windows: "El agente envía advertencias, errores y eventos de seguridad seleccionados del Visor de eventos de Windows.",
  linux:
    "El agente envía eventos seleccionados del journal de systemd: accesos SSH, sudo, cambios de cuentas y grupos, servicios con fallo y errores del kernel. Los secretos de los comandos se ocultan antes de enviarse.",
};

/** Estado de cada fuente del journal informado por el agente Linux (Fase 5C.1). */
function CoverageSection({ asset }: { asset: Asset }) {
  const coverage = asset.event_coverage;
  if (!coverage) {
    return (
      <p className="muted small">
        Cobertura: el agente no ha informado el estado del journal (agente anterior a 0.2.1 o todavía sin enviar).
      </p>
    );
  }
  return (
    <div className="small" aria-label="Cobertura de eventos">
      <strong>Cobertura</strong>{" "}
      <span className="muted" title={formatDateTime(asset.event_coverage_at)}>
        (informada {formatRelative(asset.event_coverage_at)})
      </span>
      :{" "}
      {COVERAGE_SOURCES.filter((source) => coverage[source.key]).map((source) => {
        const state = coverage[source.key] as EventCoverageState;
        return (
          <span key={source.key} title={source.hint}>
            {source.label} <span className={`badge ${COVERAGE_CLASSES[state]}`}>{COVERAGE_LABELS[state]}</span>{" "}
          </span>
        );
      })}
      {coverage.journal === "no_permission" && (
        <p className="banner banner--warn">
          El agente no puede leer el journal: añade el usuario sentra-agent al grupo systemd-journal (el instalador lo
          hace) y reinicia el servicio. Mientras tanto «0 eventos» no significa «sin actividad».
        </p>
      )}
    </div>
  );
}

export function EventsTab({ asset }: { asset: Asset }) {
  const linux = isLinux(asset);
  const [level, setLevel] = useState("");
  const [channel, setChannel] = useState("");
  const [provider, setProvider] = useState("");
  const [eventType, setEventType] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const q = useDebounced(query);
  const assetId = asset.asset_id;

  const fetchEvents = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listEvents(
        {
          assetId,
          minLevel: (level || undefined) as EventLevel | undefined,
          channel: linux ? undefined : channel,
          provider: linux ? provider : undefined,
          eventType: linux ? eventType : undefined,
          q,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [assetId, linux, level, channel, provider, eventType, q, page],
  );
  // Older pages do not change: only the newest one is refreshed periodically.
  const { data, error, loading, refresh } = usePolling(
    fetchEvents,
    page === 1 ? config.refreshIntervalMs : 10 * 60_000,
  );
  const reset = (set: (v: string) => void) => (value: string) => {
    set(value);
    setPage(1);
  };

  return (
    <section className="panel">
      {linux && <CoverageSection asset={asset} />}
      <Toolbar>
        <FilterSelect label="Nivel" value={level} options={LEVELS} onChange={reset(setLevel)} allLabel="todos" />
        {linux ? (
          <>
            <FilterSelect label="Fuente" value={provider} options={LINUX_PROVIDERS} onChange={reset(setProvider)} />
            <FilterSelect label="Tipo" value={eventType} options={EVENT_TYPES} onChange={reset(setEventType)} />
          </>
        ) : (
          <FilterSelect label="Canal" value={channel} options={CHANNELS} onChange={reset(setChannel)} />
        )}
        <SearchInput value={query} onChange={reset(setQuery)} placeholder="Buscar en mensaje u origen" label="Buscar eventos" />
      </Toolbar>
      {loading ? (
        <LoadingState label="Cargando eventos…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin eventos para este filtro">{linux ? COPY.linux : COPY.windows}</EmptyState>
      ) : (
        <>
          <EventTable events={data.items} showAsset={false} linux={linux} />
          <div className="pager">
            <span className="muted small">
              Página {page} · {data.items.length} eventos
            </span>
            <span className="pager__buttons">
              <button type="button" className="button" disabled={page <= 1} onClick={() => setPage(page - 1)}>
                Más recientes
              </button>
              <button type="button" className="button" disabled={!data.has_more} onClick={() => setPage(page + 1)}>
                Más antiguos
              </button>
            </span>
          </div>
        </>
      )}
    </section>
  );
}
