// Estado del hub Red que comparten sus pestañas (Fase 7A.5): el descubrimiento en curso y la
// configuración de discovery se consultan una sola vez en el hub, no en cada pestaña.
import { useOutletContext } from "react-router-dom";
import type { DiscoveryJobList, DiscoverySchedule, DiscoveryScope } from "../../api/types";
import type { PollingState } from "../../lib/usePolling";

export interface NetworkHubContext {
  /** Alcance de site (undefined = todos). */
  scopeId: string | undefined;
  /** Columna Site solo con «todos los sites» y más de uno. */
  showSite: boolean;
  /** Hay un descubrimiento en cola o en curso: las tablas se refrescan más a menudo. */
  discovering: boolean;
  /** Cambia cada vez que termina un descubrimiento: las pestañas recargan sus datos al momento. */
  discoveryEpoch: number;
  jobs: PollingState<DiscoveryJobList>;
  scope: PollingState<DiscoveryScope>;
  schedule: PollingState<DiscoverySchedule>;
  /** Abre el modal de descubrimiento (con un job concreto o para iniciar uno). */
  openDiscovery: (jobId?: string) => void;
}

export function useNetworkHub(): NetworkHubContext {
  return useOutletContext<NetworkHubContext>();
}
