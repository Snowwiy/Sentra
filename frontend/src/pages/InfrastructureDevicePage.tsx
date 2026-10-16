import { useCallback, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { networkApi } from "../api/sentra";
import type { NetworkDeviceDetail, NetworkPoll } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ArchiveDeviceModal, EditDeviceModal } from "../components/infrastructure/DeviceFormModal";
import {
  InterfacesTab,
  MacTableTab,
  NeighborsTab,
  POLL_PAGE_SIZE,
  PollsTab,
  VlansTab,
} from "../components/infrastructure/DeviceInventory";
import { ClassificationLabel, FreshnessBadge, MonitoringBadge } from "../components/infrastructure/InfraBadges";
import { ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative, formatUptime } from "../lib/format";
import {
  describeModules,
  describePollBlocker,
  evidenceSourceLabel,
  FRESHNESS_HELP,
  isOpenPoll,
  pollBlockersFromError,
  SNMP_VERSION_LABELS,
  snmpErrorText,
  VENDOR_SOURCE_LABELS,
} from "../lib/network";
import { usePolling } from "../lib/usePolling";

// Mientras hay una consulta abierta se refresca más a menudo para ver el resultado pronto.
const ACTIVE_MS = 5_000;

type Tab = "interfaces" | "neighbors" | "vlans" | "mac" | "polls";

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

function Summary({ device }: { device: NetworkDeviceDetail }) {
  return (
    <section className="panel" aria-label="Resumen del equipo">
      <div className="panel__toolbar">
        <h2>Resumen</h2>
        <span className="muted small">Datos informados por el equipo en su última consulta correcta.</span>
      </div>
      <dl className="fields fields--inline">
        <Field label="sysName">{device.sys_name ?? <span className="muted">—</span>}</Field>
        <Field label="Fabricante">
          {device.vendor ? (
            <>
              {device.vendor}
              {device.vendor_source && (
                <div className="muted small">{VENDOR_SOURCE_LABELS[device.vendor_source] ?? device.vendor_source}</div>
              )}
            </>
          ) : (
            <span className="muted">no identificado</span>
          )}
        </Field>
        {device.model && <Field label="Modelo">{device.model}</Field>}
        {device.firmware && <Field label="Firmware">{device.firmware}</Field>}
        {device.serial_number && <Field label="Número de serie">{device.serial_number}</Field>}
        {device.sys_location && <Field label="Ubicación (sysLocation)">{device.sys_location}</Field>}
        {device.sys_uptime_seconds != null && (
          <Field label="Uptime informado">{formatUptime(device.sys_uptime_seconds)}</Field>
        )}
        <Field label="Monitorización">
          <MonitoringBadge status={device.monitoring_status} />
          <div className="muted small">
            {device.monitoring_enabled ? "consulta periódica activada" : "consulta periódica desactivada"}
          </div>
        </Field>
        <Field label="Evidencia">
          <FreshnessBadge freshness={device.freshness} />
        </Field>
        <Field label="Última consulta correcta">
          <span title={formatDateTime(device.last_success_at)}>
            {device.last_success_at ? formatRelative(device.last_success_at) : "nunca"}
          </span>
        </Field>
        <Field label="Perfil SNMP">
          {device.profile ? (
            <>
              {device.profile.name}
              <div className="muted small">
                {SNMP_VERSION_LABELS[device.profile.snmp_version]}
                {device.profile.status === "revoked" && " · revocado"}
              </div>
            </>
          ) : (
            <span className="muted">sin perfil</span>
          )}
        </Field>
        <Field label="Sensor">
          {device.sensor ? (
            <>
              {device.sensor.name}
              <div className="muted small">estado del sensor: {device.sensor.status}</div>
            </>
          ) : (
            <span className="muted">sin sensor</span>
          )}
        </Field>
      </dl>
      {device.sys_descr && (
        <p className="small">
          <span className="muted">sysDescr: </span>
          <span className="mono">{device.sys_descr}</span>
        </p>
      )}
      <div className="stack">
        <div>
          <span className="strong">Clasificación: </span>
          <ClassificationLabel classification={device.classification} confidence={device.classification_confidence} />
          {device.layer3 != null && (
            <span className="muted small"> · {device.layer3 ? "enruta (capa 3)" : "sin enrutamiento informado"}</span>
          )}
        </div>
        {device.classification_evidence.length > 0 ? (
          <ul className="small" aria-label="Evidencias de la clasificación">
            {device.classification_evidence.map((e, index) => (
              <li key={`${e.source}-${index}`}>
                <span className="strong">{evidenceSourceLabel(e.source)}:</span> {e.detail}
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">Sin evidencias de clasificación.</p>
        )}
        {Object.keys(device.last_modules).length > 0 && (
          <p className="muted small">Módulos de la última consulta: {describeModules(device.last_modules)}</p>
        )}
      </div>
      {device.last_error_code && (
        <div className="banner banner--warn" role="status">
          <span className="strong">Último error</span>
          {device.last_error_at && <> ({formatRelative(device.last_error_at)})</>}: {snmpErrorText(device.last_error_code)}
          {device.consecutive_failures > 1 && <> {device.consecutive_failures} fallos consecutivos.</>}
        </div>
      )}
    </section>
  );
}

/** Detalle de un equipo de red (Fase 6B): resumen e inventario SNMP con su procedencia. */
export function InfrastructureDevicePage() {
  const { deviceId = "" } = useParams();
  const auth = useAuth();
  const canPoll = auth.can("network:poll");
  const canManage = auth.can("network:manage");
  const [fast, setFast] = useState(false);
  const interval = fast ? ACTIVE_MS : config.refreshIntervalMs;

  const fetchDevice = useCallback((signal: AbortSignal) => networkApi.device(deviceId, signal), [deviceId]);
  const device = usePolling(fetchDevice, interval);
  const [pollPage, setPollPage] = useState(1);
  const fetchPolls = useCallback(
    (signal: AbortSignal) =>
      networkApi.polls(deviceId, { limit: POLL_PAGE_SIZE, offset: (pollPage - 1) * POLL_PAGE_SIZE }, signal),
    [deviceId, pollPage],
  );
  const polls = usePolling(fetchPolls, interval, true, true);

  const [tab, setTab] = useState<Tab>("interfaces");
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [blockers, setBlockers] = useState<string[]>([]);
  const [modal, setModal] = useState<"edit" | "archive">();

  const openPoll = polls.data?.items.find((p) => isOpenPoll(p.status));
  // Ritmo de refresco derivado en el render (sin efectos), como en el detalle de informes.
  const nowFast = Boolean(openPoll) || device.data?.monitoring_status === "polling";
  if (nowFast !== fast) setFast(nowFast);

  const refreshDevice = device.refresh;
  const refreshPolls = polls.refresh;
  const refreshAll = useCallback(() => {
    refreshDevice();
    refreshPolls();
  }, [refreshDevice, refreshPolls]);

  if (device.loading) return <LoadingState label="Cargando equipo…" />;
  if (!device.data) {
    return (
      <div className="page">
        <Link to="/infrastructure" className="muted">
          Volver a Infraestructura
        </Link>
        <ErrorState
          message={device.error ? errorMessage(device.error) : "Sin datos"}
          onRetry={device.error instanceof ApiError && device.error.status === 404 ? undefined : device.refresh}
        />
      </div>
    );
  }
  const d = device.data;
  const archived = d.status === "archived";

  const requestPoll = async () => {
    setBusy(true);
    setActionError(undefined);
    setBlockers([]);
    try {
      await networkApi.requestPoll(d.device_id);
      setTab("polls");
      setPollPage(1);
    } catch (err) {
      setActionError(errorMessage(asError(err)));
      setBlockers(pollBlockersFromError(err));
    } finally {
      setBusy(false);
      refreshAll();
    }
  };

  const cancelPoll = async (poll: NetworkPoll) => {
    setBusy(true);
    setActionError(undefined);
    try {
      await networkApi.cancelPoll(poll.poll_id);
    } catch (err) {
      setActionError(errorMessage(asError(err)));
    } finally {
      setBusy(false);
      refreshAll();
    }
  };

  const tabs: { key: Tab; label: string; count?: number }[] = [
    { key: "interfaces", label: "Interfaces", count: d.interfaces_total },
    { key: "neighbors", label: "Vecinos LLDP/CDP", count: d.neighbors_total },
    { key: "vlans", label: "VLANs", count: d.vlans_total },
    { key: "mac", label: "Tabla MAC", count: d.mac_entries_total },
    { key: "polls", label: "Historial de consultas" },
  ];

  return (
    <div className="page">
      <Link to="/infrastructure" className="muted">
        Volver a Infraestructura
      </Link>
      <div className="page__header">
        <div>
          <h1>{d.display_name}</h1>
          <p className="muted small">
            <span className="mono">
              {d.management_address}:{d.snmp_port}
            </span>{" "}
            · site {d.site_name}
            {archived && " · archivado"}
            {device.updatedAt && <> · actualizado {formatRelative(device.updatedAt.toISOString())}</>}
          </p>
        </div>
        <div className="actions">
          {canPoll && !archived && (
            <button
              type="button"
              className="button button--primary nowrap"
              disabled={busy || !d.can_poll || Boolean(openPoll)}
              onClick={() => void requestPoll()}
            >
              {busy ? "Procesando…" : "Consultar ahora"}
            </button>
          )}
          {canPoll && openPoll && (
            <button type="button" className="button nowrap" disabled={busy} onClick={() => void cancelPoll(openPoll)}>
              Cancelar consulta
            </button>
          )}
          {canManage && !archived && (
            <>
              <button type="button" className="button nowrap" onClick={() => setModal("edit")}>
                Editar
              </button>
              <button type="button" className="button button--danger nowrap" onClick={() => setModal("archive")}>
                Archivar
              </button>
            </>
          )}
        </div>
      </div>

      {d.freshness === "historical" && (
        <div className="banner banner--warn" role="note">
          Evidencia histórica: {FRESHNESS_HELP.historical}
        </div>
      )}
      {d.freshness === "none" && !archived && (
        <div className="banner" role="note">
          Este equipo todavía no se ha consultado correctamente: no hay inventario que mostrar.
        </div>
      )}
      {canPoll && !archived && !d.can_poll && d.poll_blockers.length > 0 && (
        <div className="banner" role="status" aria-label="Motivos por los que no se puede consultar">
          No se puede consultar ahora:
          <ul>
            {d.poll_blockers.map((b) => (
              <li key={b}>{describePollBlocker(b)}</li>
            ))}
          </ul>
        </div>
      )}
      {openPoll && (
        <div className="banner" role="status">
          <span className="spinner spinner--inline" aria-hidden="true" /> Consulta{" "}
          {openPoll.status === "queued" ? "en cola" : "en curso"}
          {openPoll.sensor_name && <> en el sensor {openPoll.sensor_name}</>}.
        </div>
      )}
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
          {blockers.length > 0 && (
            <ul>
              {blockers.map((b) => (
                <li key={b}>{describePollBlocker(b)}</li>
              ))}
            </ul>
          )}
        </div>
      )}
      {device.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(device.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <Summary device={d} />

      <nav className="tabs" role="tablist" aria-label="Inventario del equipo">
        {tabs.map(({ key, label, count }) => (
          <button
            key={key}
            type="button"
            role="tab"
            id={`device-tab-${key}`}
            aria-selected={tab === key}
            aria-controls={`device-panel-${key}`}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setTab(key)}
          >
            {label}
            {count != null && <span className="tabs__count">{count}</span>}
          </button>
        ))}
      </nav>
      <section
        className="panel"
        role="tabpanel"
        id={`device-panel-${tab}`}
        aria-labelledby={`device-tab-${tab}`}
      >
        {tab === "interfaces" && <InterfacesTab deviceId={d.device_id} />}
        {tab === "neighbors" && <NeighborsTab deviceId={d.device_id} />}
        {tab === "vlans" && <VlansTab deviceId={d.device_id} />}
        {tab === "mac" && <MacTableTab deviceId={d.device_id} />}
        {tab === "polls" && (
          <PollsTab
            polls={polls}
            page={pollPage}
            onPage={setPollPage}
            canPoll={canPoll}
            onCancel={(poll) => void cancelPoll(poll)}
          />
        )}
      </section>

      {modal === "edit" && <EditDeviceModal device={d} onClose={() => setModal(undefined)} onSaved={refreshAll} />}
      {modal === "archive" && (
        <ArchiveDeviceModal device={d} onClose={() => setModal(undefined)} onDone={refreshAll} />
      )}
    </div>
  );
}
