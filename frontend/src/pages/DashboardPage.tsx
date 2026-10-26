import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { sentraApi } from "../api/sentra";
import type { AssetStatus } from "../api/types";
import { AlertTable } from "../components/AlertTable";
import {
  ExposedPortsList,
  NewDevicesList,
  RecentDetectionsList,
  SummaryCharts,
} from "../components/charts/DashboardCharts";
import { PostureCard } from "../components/charts/PostureCard";
import { RiskHistoryChart, type HistoryDays } from "../components/charts/RiskHistoryChart";
import { AssetName, DeviceTypeCell } from "../components/DeviceIdentity";
import { EventTable } from "../components/EventTable";
import { IncidentsOverviewPanel } from "../components/incidents/IncidentsOverviewPanel";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { AssetStateBadge } from "../components/StatusBadge";
import { VulnSummaryCard } from "../components/vulnerabilities/VulnSummaryCard";
import { config } from "../config";
import { DEVICES_PATH, devicesLink } from "../lib/deviceFilters";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

type StatusCard = AssetStatus | "all";

const STAT_CARDS: { key: StatusCard; label: string }[] = [
  { key: "all", label: "Total de dispositivos" },
  { key: "online", label: "En línea" },
  { key: "offline", label: "Sin conexión" },
  { key: "unknown", label: "Desconocidos" },
];

/** Dispositivos recientes que se muestran en el panel; la lista completa está en Red. */
const RECENT_DEVICES = 5;

/**
 * Panel (Fase 7A.5): la página de entrada resume el estado de la plataforma (recuentos,
 * riesgo, vulnerabilidades, incidentes, alertas y actividad). La tabla completa de activos que
 * había aquí se unió con la de Red en Red › Dispositivos; cada tarjeta lleva allí ya filtrada.
 */
export function DashboardPage() {
  // Fase 5F: KPIs, tablas y recuentos con el mismo alcance de site.
  const { scopeId } = useSite();
  const fetchSummary = useCallback(
    (signal: AbortSignal) => sentraApi.dashboardSummary(signal, scopeId),
    [scopeId],
  );
  const summary = usePolling(fetchSummary, config.refreshIntervalMs);
  // Fase 7A.7: postura, historial y listas. Su fallo no tumba el Panel: se avisa en su sitio.
  const [historyDays, setHistoryDays] = useState<HistoryDays>(30);
  const fetchOverview = useCallback(
    (signal: AbortSignal) => sentraApi.securityOverview(signal, scopeId, historyDays),
    [scopeId, historyDays],
  );
  // Se conservan los datos anteriores al cambiar el periodo (sin parpadeo), pero nunca se
  // muestran los de otro site: el eco site_id del servidor tiene que coincidir con el alcance.
  const overview = usePolling(fetchOverview, config.refreshIntervalMs, true, true);
  const overviewData =
    overview.data && (overview.data.site_id ?? undefined) === (scopeId ?? undefined) ? overview.data : undefined;
  const fetchRecent = useCallback(
    (signal: AbortSignal) =>
      sentraApi.listAssets(signal, { siteId: scopeId, sort: "first_seen", order: "desc", limit: RECENT_DEVICES }),
    [scopeId],
  );
  const recent = usePolling(fetchRecent, config.refreshIntervalMs);
  const fetchOpenAlerts = useCallback(
    (signal: AbortSignal) => sentraApi.listAlerts({ active: true, limit: 5, siteId: scopeId }, signal),
    [scopeId],
  );
  const openAlerts = usePolling(fetchOpenAlerts, config.refreshIntervalMs);
  const fetchActivity = useCallback(
    (signal: AbortSignal) => sentraApi.listEvents({ minLevel: "warning", limit: 10 }, signal),
    [],
  );
  // Los eventos del sistema no se filtran por site: solo se muestran con "Todos los sites".
  const activity = usePolling(fetchActivity, config.refreshIntervalMs, !scopeId);

  const refreshAll = () => {
    summary.refresh();
    overview.refresh();
    recent.refresh();
    openAlerts.refresh();
    if (!scopeId) activity.refresh();
  };

  if (summary.loading) return <LoadingState label="Cargando panel…" />;
  if (!summary.data) {
    return <ErrorState message={errorMessage(summary.error ?? new Error("Sin datos"))} onRetry={summary.refresh} />;
  }
  const kpis = summary.data;
  const counts: Record<StatusCard, number> = {
    all: kpis.assets.total,
    online: kpis.assets.online,
    offline: kpis.assets.offline,
    unknown: kpis.assets.unknown,
  };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Panel</h1>
          <p className="muted small page__scope">
            {/* Eco del servidor (summary.site_id): el alcance que de verdad se aplicó. */}
            <SiteScopeChip siteId={kpis.site_id ?? undefined} />
            {summary.updatedAt && `Actualizado ${formatRelative(summary.updatedAt.toISOString())} · `}
            refresco cada {config.refreshIntervalMs / 1000} s
          </p>
        </div>
        <button type="button" className="button" onClick={refreshAll} disabled={summary.refreshing}>
          {summary.refreshing ? "Actualizando…" : "Actualizar"}
        </button>
      </div>

      {summary.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(summary.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      {/* Cada tarjeta abre Red › Dispositivos con ese estado ya filtrado. */}
      <section className="stats" aria-label="Resumen de estado">
        {STAT_CARDS.map(({ key, label }) => (
          <Link
            key={key}
            className={`stat stat--${key}`}
            to={key === "all" ? DEVICES_PATH : devicesLink({ status: key })}
          >
            <span className="stat__label">{label}</span>
            <span className="stat__value">{counts[key]}</span>
          </Link>
        ))}
      </section>

      {overviewData ? (
        <PostureCard posture={overviewData.posture} />
      ) : !overview.error ? (
        <LoadingState label="Cargando postura…" />
      ) : (
        <ErrorState
          message={`No se pudo cargar la postura de seguridad: ${errorMessage(overview.error ?? new Error("Sin datos"))}`}
          onRetry={overview.refresh}
        />
      )}

      <SummaryCharts summary={kpis} incidentsByStatus={overviewData?.incidents_by_status} />

      {overviewData && (
        <>
          <RiskHistoryChart
            points={overviewData.risk_history}
            days={historyDays}
            onDays={setHistoryDays}
            busy={overview.refreshing}
          />
          <div className="overview-grid">
            <RecentDetectionsList items={overviewData.detections_recent} />
            <NewDevicesList data={overviewData.new_devices} />
            <ExposedPortsList data={overviewData.exposed_ports} />
          </div>
        </>
      )}

      <p className="muted small" aria-label="Resumen de la plataforma">
        {kpis.assets.by_method.agent} gestionados con agente · {kpis.assets.by_method.discovered} descubiertos ·
        riesgo crítico {kpis.risk.by_level.critical ?? 0} · riesgo alto {kpis.risk.by_level.high ?? 0} ·{" "}
        {kpis.detections.active} detecciones activas · {kpis.active_alerts} alertas activas
      </p>
      {kpis.vulnerabilities && <VulnSummaryCard data={kpis.vulnerabilities} />}

      {scopeId ? (
        // El resumen SOC de incidentes es global; con un site elegido se usan los KPIs del alcance.
        kpis.incidents && (
          <p className="muted small" aria-label="Incidentes del site">
            <Link to="/incidents">Incidentes</Link>: {kpis.incidents.active} activos ·{" "}
            {kpis.incidents.critical} críticos · {kpis.incidents.unassigned} sin asignar
          </p>
        )
      ) : (
        <IncidentsOverviewPanel />
      )}

      {openAlerts.data && openAlerts.data.items.length > 0 && (
        <section className="panel panel--alerts" aria-label="Alertas abiertas">
          <div className="panel__toolbar">
            <h2>Alertas abiertas</h2>
            <Link to="/alerts" className="small">
              Ver todas
            </Link>
          </div>
          <AlertTable alerts={openAlerts.data.items} />
        </section>
      )}

      <section className="panel" aria-label="Dispositivos recientes">
        <div className="panel__toolbar">
          <h2>Dispositivos recientes</h2>
          <Link to={DEVICES_PATH} className="small">
            Ver todos los dispositivos
          </Link>
        </div>
        {recent.loading ? (
          <LoadingState label="Cargando dispositivos…" />
        ) : !recent.data ? (
          <ErrorState message={errorMessage(recent.error ?? new Error("Sin datos"))} onRetry={recent.refresh} />
        ) : recent.data.items.length === 0 ? (
          <EmptyState title="No hay dispositivos registrados">
            Aparecerán cuando un agente se registre en la API o cuando el descubrimiento de red encuentre equipos
            en las redes autorizadas.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Dispositivo</th>
                  <th>Tipo</th>
                  <th>Estado</th>
                  <th>Descubierto</th>
                </tr>
              </thead>
              <tbody>
                {recent.data.items.map((asset) => {
                  const first = asset.discovered_at ?? asset.first_seen_at;
                  return (
                    <tr key={asset.asset_id}>
                      <td>
                        <AssetName asset={asset} />
                      </td>
                      <td>
                        <DeviceTypeCell asset={asset} />
                      </td>
                      <td>
                        <AssetStateBadge asset={asset} />
                      </td>
                      <td title={formatDateTime(first)}>{formatRelative(first)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {!scopeId && activity.data && activity.data.items.length > 0 && (
        <section className="panel" aria-label="Actividad reciente">
          <div className="panel__toolbar">
            <h2>Actividad reciente</h2>
            <span className="muted small">advertencias y errores del sistema</span>
          </div>
          <EventTable events={activity.data.items} />
        </section>
      )}
    </div>
  );
}
