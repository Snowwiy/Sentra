import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { Outlet, useLocation, useNavigate } from "react-router-dom";
import { sentraApi as api } from "../api/sentra";
import type { DiscoveryJob } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { DISABLED_MESSAGE, DISCOVERY_FEATURE, DiscoveryModal } from "../components/discovery/DiscoveryModal";
import { RouteTabs } from "../components/RouteTabs";
import { LoadingState } from "../components/StateViews";
import { config } from "../config";
import { devicesLink } from "../lib/deviceFilters";
import { isActive } from "../lib/discovery";
import { useConsole } from "../lib/useConsole";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";
import type { NetworkHubContext } from "./network/hubContext";
import { networkTabFor, networkTabPath, visibleNetworkTabs } from "./network/tabs";

// Discovery runs every few minutes at most: no need to poll as often as live telemetry.
const REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);
// Mientras hay un descubrimiento activo el historial se consulta cada 2 s; en reposo se vuelve
// a REFRESH_MS.
const ACTIVE_JOBS_MS = 2_000;
const SCHEDULE_MS = 30_000;
const PANEL_ID = "network-tabpanel";

type ModalState = { jobId?: string } | undefined;

/**
 * Red (Fase 7A.5): un único hub para lo que antes eran Activos, Red, Topología y DHCP, con una
 * pestaña por vista y una ruta por pestaña (/network/devices, /network/topology...).
 *
 * El hub consulta lo que comparten las pestañas (historial y configuración de discovery) y
 * aloja el inicio de un descubrimiento, que se puede lanzar desde cualquier pestaña. Al
 * cambiar de site todo empieza de cero.
 */
export function NetworkPage() {
  const { scopeId } = useSite();
  return <NetworkHub key={scopeId ?? "all"} scopeId={scopeId} />;
}

function NetworkHub({ scopeId }: { scopeId: string | undefined }) {
  const auth = useAuth();
  const site = useSite();
  const location = useLocation();
  const navigate = useNavigate();
  const showSite = !scopeId && site.sites.length > 1;

  // Si hay algún job en cola o en curso, según la última respuesta del historial. Se
  // actualiza dentro del fetcher (no en un efecto) para elegir el intervalo de polling.
  const [discovering, setDiscovering] = useState(false);
  const fetchJobs = useCallback(
    async (signal: AbortSignal) => {
      const result = await api.discoveryJobs(10, signal, scopeId);
      setDiscovering(result.items.some(isActive));
      return result;
    },
    [scopeId],
  );
  const jobs = usePolling(fetchJobs, discovering ? ACTIVE_JOBS_MS : REFRESH_MS);
  const fetchScope = useCallback((signal: AbortSignal) => api.discoveryScope(signal), []);
  const scope = usePolling(fetchScope, 10 * REFRESH_MS);
  const fetchSchedule = useCallback((signal: AbortSignal) => api.discoverySchedule(signal), []);
  const schedule = usePolling(fetchSchedule, SCHEDULE_MS);
  const consoleState = useConsole(DISCOVERY_FEATURE, "discovery:run");
  const [modal, setModal] = useState<ModalState>();
  // Contador que avisa a las pestañas de que un descubrimiento terminó (activos nuevos).
  const [discoveryEpoch, setDiscoveryEpoch] = useState(0);

  // Al terminar el último descubrimiento activo, las pestañas recargan en el acto, sin esperar
  // al siguiente intervalo.
  const wasDiscovering = useRef(false);
  const refreshSchedule = schedule.refresh;
  useEffect(() => {
    if (wasDiscovering.current && !discovering) {
      setDiscoveryEpoch((n) => n + 1);
      refreshSchedule();
    }
    wasDiscovering.current = discovering;
  }, [discovering, refreshSchedule]);

  const refreshJobs = jobs.refresh;
  const jobChanged = useCallback(
    (job: DiscoveryJob) => {
      // El modal ve antes que el historial que un job empezó o terminó.
      refreshJobs();
      if (!isActive(job)) setDiscoveryEpoch((n) => n + 1);
    },
    [refreshJobs],
  );

  const showDevices = (target: string) => {
    // La red del job y los descubiertos más recientes primero: los nuevos quedan arriba.
    setModal(undefined);
    navigate(devicesLink({ subnet: target, sort: "first", dir: "desc" }));
  };

  const activeJobs = (jobs.data?.items ?? []).filter(isActive);
  // Fase 5F: además del servidor local (site por defecto), cualquier site activo con sensores
  // puede descubrir; el modal decide el destino concreto.
  const sensorSites = site.sites.some((s) => s.status === "active" && s.sensor_count > 0);
  const scopeEnabled = scope.data?.enabled === true || sensorSites;
  const startDisabledReason =
    !scope.data && !sensorSites ? "Cargando redes autorizadas…" : !scopeEnabled ? DISABLED_MESSAGE : consoleState.reason;

  const tabs = visibleNetworkTabs(auth.can);
  const current = networkTabFor(location.pathname);
  const openDiscovery = useCallback((jobId?: string) => setModal({ jobId }), []);
  const context: NetworkHubContext = { scopeId, showSite, discovering, discoveryEpoch, jobs, scope, schedule, openDiscovery };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Red</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            Dispositivos descubiertos y gestionados, descubrimiento, topología, servicios, cambios, identidad y
            telemetría en un solo lugar.
          </p>
        </div>
        {consoleState.allowed && (
          <div className="actions">
            <button
              type="button"
              className="button button--primary"
              disabled={!scopeEnabled || !consoleState.available}
              title={startDisabledReason}
              onClick={() => setModal({})}
            >
              Iniciar descubrimiento
            </button>
          </div>
        )}
      </div>

      {activeJobs.length > 0 && (
        <p className="muted small" role="status">
          <span className="spinner spinner--inline" aria-hidden="true" /> Descubrimiento{" "}
          {activeJobs[0]?.status === "queued" ? "en cola" : "en curso"} en{" "}
          <span className="mono">{activeJobs.map((j) => j.target).join(", ")}</span> ·{" "}
          <button type="button" className="link-button" onClick={() => setModal({ jobId: activeJobs[0]?.job_id })}>
            Ver progreso
          </button>
        </p>
      )}
      {scope.data && scopeEnabled && consoleState.reason && !consoleState.loading && (
        <div className="banner" role="status">
          {consoleState.reason} Puedes consultar el estado y el historial.
        </div>
      )}

      <RouteTabs
        tabs={tabs.map((tab) => ({ key: tab.key, to: networkTabPath(tab), label: tab.label }))}
        active={current?.key}
        label="Secciones de red"
        idPrefix="network"
        panelId={PANEL_ID}
      />
      <div
        role="tabpanel"
        id={PANEL_ID}
        aria-labelledby={current ? `network-tab-${current.key}` : undefined}
        className="network-tabpanel"
      >
        <Suspense fallback={<LoadingState label="Cargando…" />}>
          <Outlet context={context} />
        </Suspense>
      </div>

      {modal && (
        <DiscoveryModal
          scope={scope.data}
          activeJobs={activeJobs}
          initialJobId={modal.jobId}
          canAdminister={consoleState.available}
          adminReason={consoleState.reason}
          onClose={() => setModal(undefined)}
          onShowDevices={showDevices}
          onChanged={jobChanged}
        />
      )}
    </div>
  );
}
