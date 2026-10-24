import { useCallback, useState } from "react";
import { forensicsApi } from "../api/sentra6e";
import type { InvestigationStatus } from "../api/types";
import { InvestigationTable } from "../components/forensics/InvestigationTable";
import { FilterSelect, Pager } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage } from "../lib/format";
import { INVESTIGATION_STATUS_LABELS } from "../lib/forensics";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";

const PAGE_SIZE = 50;

/**
 * Investigaciones forenses (Fase 6E.6). Se abren desde la pestaña Investigaciones de un activo
 * (forensics:acquire); aquí se listan todas las del alcance de site elegido.
 */
export function InvestigationsPage() {
  const site = useSite();
  const [status, setStatus] = useState<InvestigationStatus | "">("open");
  const [page, setPage] = useState(1);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      forensicsApi.list(
        { status: status || undefined, siteId: site.scopeId, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
        signal,
      ),
    [status, site.scopeId, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, Math.max(config.refreshIntervalMs, 30_000), true, true);

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Investigaciones</h1>
          <p className="muted small">
            Evidencias forenses recogidas de los equipos con su SHA-256, notas e interpretaciones. Para abrir una nueva, ve a
            la ficha del equipo, pestaña Investigaciones.
          </p>
        </div>
      </div>
      <section className="panel">
        <div className="panel__toolbar panel__toolbar--filters">
          <FilterSelect
            label="Estado"
            value={status}
            allLabel="todos"
            options={Object.entries(INVESTIGATION_STATUS_LABELS).map(([value, label]) => ({ value, label }))}
            onChange={(v) => {
              setStatus(v as InvestigationStatus | "");
              setPage(1);
            }}
          />
        </div>
        {loading ? (
          <LoadingState label="Cargando investigaciones…" />
        ) : !data ? (
          <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
        ) : data.items.length === 0 ? (
          <EmptyState title="Sin investigaciones">No hay investigaciones con este filtro.</EmptyState>
        ) : (
          <>
            {error && (
              <div className="banner banner--warn" role="alert">
                Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
              </div>
            )}
            <InvestigationTable items={data.items} />
            <Pager
              page={page}
              pages={Math.max(1, Math.ceil(data.total / PAGE_SIZE))}
              total={data.total}
              onPage={setPage}
              noun="investigaciones"
            />
          </>
        )}
      </section>
    </div>
  );
}
