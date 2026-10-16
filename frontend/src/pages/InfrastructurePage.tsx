import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { networkApi } from "../api/sentra";
import type { DeviceClassification, MonitoringStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { CreateDeviceModal } from "../components/infrastructure/DeviceFormModal";
import { ClassificationLabel, FreshnessBadge, MonitoringBadge } from "../components/infrastructure/InfraBadges";
import { SnmpProfilesPanel } from "../components/infrastructure/SnmpProfilesPanel";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import {
  CLASSIFICATION_LABELS,
  CLASSIFICATIONS,
  MONITORING_STATUS_LABELS,
  MONITORING_STATUSES,
} from "../lib/network";
import { useDebounced } from "../lib/useDebounced";
import { useListState } from "../lib/useListState";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

export const DEVICE_PAGE_SIZE = 25;

type Filters = { site: string; classification: string; monitoring: string; archived: string };
type Tab = "devices" | "profiles";

/** Listado de equipos administrables con filtros y paginación en el servidor. */
function DevicesPanel() {
  const auth = useAuth();
  const canManage = auth.can("network:manage");
  const navigate = useNavigate();
  const site = useSite();
  const { scopeId } = site;
  const list = useListState<"name", Filters>(
    { key: "name", dir: "asc" },
    { site: "", classification: "", monitoring: "", archived: "" },
  );
  const { filters } = list;
  // Con un site elegido en la cabecera, el filtro de site de la tabla no aplica.
  const siteId = scopeId ?? (filters.site || undefined);
  const showSiteFilter = !scopeId && site.selectableSites.length > 1;
  const showSite = !siteId && site.sites.length > 1;
  const q = useDebounced(list.query.trim(), 300);
  // Al cambiar el alcance global se vuelve a la primera página.
  const [scopeSeen, setScopeSeen] = useState(scopeId);
  if (scopeSeen !== scopeId) {
    setScopeSeen(scopeId);
    list.setPage(1);
  }

  const fetchDevices = useCallback(
    (signal: AbortSignal) =>
      networkApi.devices(
        {
          siteId,
          classification: (filters.classification || undefined) as DeviceClassification | undefined,
          monitoringStatus: (filters.monitoring || undefined) as MonitoringStatus | undefined,
          q: q || undefined,
          includeArchived: filters.archived === "yes",
          limit: DEVICE_PAGE_SIZE,
          offset: (list.page - 1) * DEVICE_PAGE_SIZE,
        },
        signal,
      ),
    [siteId, filters.classification, filters.monitoring, filters.archived, q, list.page],
  );
  const devices = usePolling(fetchDevices, config.refreshIntervalMs * 2, true, true);
  const [registering, setRegistering] = useState(false);

  const data = devices.data;
  const total = data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / DEVICE_PAGE_SIZE));
  const filtered = Boolean(
    list.query.trim() || filters.site || filters.classification || filters.monitoring || filters.archived,
  );
  const activeSites = site.sites.filter((s) => s.status === "active");

  return (
    <section className="panel" aria-label="Equipos de red">
      <div className="panel__toolbar">
        <h2>Equipos de red</h2>
        <span className="muted small">
          Switches, routers, puntos de acceso y firewalls consultados por SNMP desde un sensor de su site.
        </span>
        {canManage && (
          <button type="button" className="button button--primary nowrap" onClick={() => setRegistering(true)}>
            Registrar equipo
          </button>
        )}
      </div>
      <Toolbar>
        <SearchInput
          value={list.query}
          onChange={(value) => list.setQuery(value.slice(0, 100))}
          placeholder="Buscar nombre, sysName o dirección"
          label="Buscar equipos"
        />
        {showSiteFilter && (
          <FilterSelect
            label="Site"
            value={filters.site}
            options={site.selectableSites.map((s) => ({ value: s.site_id, label: s.name }))}
            onChange={(value) => list.setFilter("site", value)}
          />
        )}
        <FilterSelect
          label="Clasificación"
          value={filters.classification}
          options={CLASSIFICATIONS.map((c) => ({ value: c, label: CLASSIFICATION_LABELS[c] }))}
          onChange={(value) => list.setFilter("classification", value)}
          allLabel="Todas"
        />
        <FilterSelect
          label="Monitorización"
          value={filters.monitoring}
          options={MONITORING_STATUSES.map((m) => ({ value: m, label: MONITORING_STATUS_LABELS[m] }))}
          onChange={(value) => list.setFilter("monitoring", value)}
        />
        <label className="checkbox small">
          <input
            type="checkbox"
            checked={filters.archived === "yes"}
            onChange={(e) => list.setFilter("archived", e.target.checked ? "yes" : "")}
          />{" "}
          Incluir archivados
        </label>
      </Toolbar>
      {data && devices.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(devices.error)}. Se muestran los últimos datos.
        </div>
      )}
      {!data ? (
        devices.error ? (
          <ErrorState message={errorMessage(devices.error)} onRetry={devices.refresh} />
        ) : (
          <LoadingState label="Cargando equipos de red…" />
        )
      ) : data.items.length === 0 ? (
        filtered || list.page > 1 ? (
          <EmptyState title="Ningún equipo coincide con el filtro" />
        ) : (
          <EmptyState title="Todavía no hay equipos de red registrados">
            {canManage
              ? "Pulsa «Registrar equipo» e indica su dirección de gestión, un perfil SNMP y un sensor del site."
              : "Un administrador puede registrar los switches y routers del site para consultarlos por SNMP."}
          </EmptyState>
        )
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Nombre</th>
                  <th>Dirección</th>
                  {showSite && <th>Site</th>}
                  <th>Clasificación</th>
                  <th>Monitorización</th>
                  <th>Evidencia</th>
                  <th>Última consulta correcta</th>
                  <th>Interfaces up/total</th>
                  <th>Vecinos</th>
                  <th>Sensor</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((device) => (
                  <tr key={device.device_id}>
                    <td>
                      <Link to={`/infrastructure/devices/${device.device_id}`} className="strong">
                        {device.display_name}
                      </Link>
                      {device.status === "archived" && <div className="muted small">archivado</div>}
                    </td>
                    <td className="mono">
                      {device.management_address}
                      {device.snmp_port !== 161 && <span className="muted">:{device.snmp_port}</span>}
                    </td>
                    {showSite && <td className="small">{device.site_name}</td>}
                    <td>
                      <ClassificationLabel
                        classification={device.classification}
                        confidence={device.classification_confidence}
                      />
                    </td>
                    <td>
                      <MonitoringBadge status={device.monitoring_status} />
                    </td>
                    <td>
                      <FreshnessBadge freshness={device.freshness} />
                    </td>
                    <td className="muted" title={formatDateTime(device.last_success_at)}>
                      {device.last_success_at ? formatRelative(device.last_success_at) : "nunca"}
                    </td>
                    <td>
                      {device.interfaces_up}/{device.interfaces_total}
                    </td>
                    <td>{device.neighbors_total}</td>
                    <td className="small">{device.sensor?.name ?? <span className="muted">sin sensor</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={list.page} pages={pages} total={total} onPage={list.setPage} noun="equipos" />
        </>
      )}
      {registering && (
        <CreateDeviceModal
          sites={activeSites}
          initialSiteId={siteId}
          onClose={() => setRegistering(false)}
          onCreated={(device) => {
            devices.refresh();
            void navigate(`/infrastructure/devices/${device.device_id}`);
          }}
        />
      )}
    </section>
  );
}

/**
 * Infraestructura de red (Fase 6B): equipos administrables consultados por SNMP y, para
 * quien tiene snmp_credentials:manage, sus perfiles de credenciales.
 */
export function InfrastructurePage() {
  const auth = useAuth();
  const canProfiles = auth.can("snmp_credentials:manage");
  const [tab, setTab] = useState<Tab>("devices");
  const tabs: { key: Tab; label: string }[] = [
    { key: "devices", label: "Equipos" },
    ...(canProfiles ? [{ key: "profiles" as const, label: "Perfiles SNMP" }] : []),
  ];
  const active = canProfiles ? tab : "devices";

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Infraestructura</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Inventario SNMP, vecinos LLDP/CDP y tablas MAC informados por los propios equipos.</span>
          </p>
        </div>
      </div>
      <div className="banner" role="note">
        Los datos proceden de la última consulta SNMP de cada equipo. Un estado correcto no garantiza que el equipo siga
        disponible ahora, y los vecinos LLDP/CDP son lo que informa el equipo, no enlaces confirmados.
      </div>
      {tabs.length > 1 && (
        <nav className="tabs" role="tablist" aria-label="Secciones de infraestructura">
          {tabs.map(({ key, label }) => (
            <button
              key={key}
              type="button"
              role="tab"
              id={`infra-tab-${key}`}
              aria-selected={active === key}
              aria-controls={`infra-panel-${key}`}
              className={`tabs__item${active === key ? " tabs__item--active" : ""}`}
              onClick={() => setTab(key)}
            >
              {label}
            </button>
          ))}
        </nav>
      )}
      {active === "devices" ? (
        <div role={tabs.length > 1 ? "tabpanel" : undefined} id="infra-panel-devices" aria-labelledby={tabs.length > 1 ? "infra-tab-devices" : undefined}>
          <DevicesPanel />
        </div>
      ) : (
        <div role="tabpanel" id="infra-panel-profiles" aria-labelledby="infra-tab-profiles">
          <SnmpProfilesPanel />
        </div>
      )}
    </div>
  );
}
