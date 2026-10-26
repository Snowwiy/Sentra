import { JobsPanel, SchedulePanel, ScopePanel } from "../../components/discovery/DiscoveryPanels";
import { NetworkObservations } from "../../components/discovery/NetworkObservations";
import { useNetworkHub } from "./hubContext";

/**
 * Red › Descubrimiento (Fase 7A.5): ejecuciones recientes (cada una abre su progreso o su
 * resultado), el scheduler, las redes autorizadas y las observaciones de los scans avanzados
 * (Fase 6A), paginadas en el servidor. Iniciar un descubrimiento está en la cabecera del hub.
 */
export function DiscoveryTab() {
  const hub = useNetworkHub();
  return (
    <div className="stack">
      <JobsPanel
        jobs={hub.jobs.data?.items}
        loading={hub.jobs.loading}
        error={hub.jobs.error}
        onOpen={(job) => hub.openDiscovery(job.job_id)}
        showSite={hub.showSite}
      />
      <div className="panels-2">
        <SchedulePanel schedule={hub.schedule.data} error={hub.schedule.error} />
        <ScopePanel scope={hub.scope.data} error={hub.scope.error} />
      </div>
      <NetworkObservations scopeId={hub.scopeId} allowedNetworks={hub.scope.data?.allowed_networks ?? []} />
    </div>
  );
}
