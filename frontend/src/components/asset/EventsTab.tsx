import { useCallback, useState } from "react";
import { sentraApi } from "../../api/sentra";
import type { EventLevel } from "../../api/types";
import { config } from "../../config";
import { errorMessage } from "../../lib/format";
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

export function EventsTab({ assetId }: { assetId: string }) {
  const [level, setLevel] = useState("");
  const [channel, setChannel] = useState("");
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const q = useDebounced(query);

  const fetchEvents = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listEvents(
        {
          assetId,
          minLevel: (level || undefined) as EventLevel | undefined,
          channel,
          q,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [assetId, level, channel, q, page],
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
      <Toolbar>
        <FilterSelect label="Nivel" value={level} options={LEVELS} onChange={reset(setLevel)} allLabel="todos" />
        <FilterSelect label="Canal" value={channel} options={CHANNELS} onChange={reset(setChannel)} />
        <SearchInput value={query} onChange={reset(setQuery)} placeholder="Buscar en mensaje u origen" label="Buscar eventos" />
      </Toolbar>
      {loading ? (
        <LoadingState label="Cargando eventos…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin eventos para este filtro">
          El agente envía advertencias, errores y eventos de seguridad seleccionados de Windows.
        </EmptyState>
      ) : (
        <>
          <EventTable events={data.items} showAsset={false} />
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
