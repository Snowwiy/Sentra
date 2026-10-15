import { useCallback, useState } from "react";
import { ApiError } from "../../api/client";
import { consoleApi, sensorsApi, sitesApi, type DiscoveryStartOptions } from "../../api/sentra";
import type { DiscoveryExecutionTarget, DiscoveryJob, DiscoveryScope, Sensor, Site } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { useSite } from "../../site/SiteContext";
import { Modal } from "../Modal";
import { DiscoveryJobView, type JobActions } from "./DiscoveryJobView";

export const DISCOVERY_FEATURE = "El descubrimiento de red";

export const DISABLED_MESSAGE =
  "El descubrimiento de red está desactivado. Configure DISCOVERY_ALLOWED_NETWORKS en el servidor.";

function startError(err: unknown): string {
  if (err instanceof ApiError && err.code === "permission_denied") {
    return "Tu rol no permite iniciar ni cancelar descubrimientos.";
  }
  if (err instanceof ApiError && err.code === "discovery_busy") {
    return "Ya hay un descubrimiento en cola o en curso para esa red.";
  }
  if (err instanceof ApiError && err.code === "discovery_target_refused") {
    return `El servidor rechazó la red: ${err.message}`;
  }
  if (err instanceof ApiError && err.code === "discovery_disabled") return DISABLED_MESSAGE;
  if (err instanceof ApiError && err.code === "sensor_not_available") {
    return "El sensor elegido no está disponible (deshabilitado o revocado). Elige otro.";
  }
  return errorMessage(err instanceof Error ? err : new Error(String(err)));
}

export interface DiscoveryModalProps {
  scope: DiscoveryScope | undefined;
  /** Jobs en cola o en curso, para avisar antes de lanzar otro sobre la misma red. */
  activeJobs: DiscoveryJob[];
  /** Abrir directamente el detalle de un job (historial, "Ver progreso"). */
  initialJobId?: string;
  canAdminister: boolean;
  adminReason: string | undefined;
  onClose: () => void;
  onShowDevices: (target: string) => void;
  onChanged: (job: DiscoveryJob) => void;
}

/** Un sensor puede recibir jobs salvo si está deshabilitado o revocado (offline: quedan en cola). */
export function sensorUsable(sensor: Sensor): boolean {
  return sensor.status !== "disabled" && sensor.status !== "revoked";
}

const SENSOR_STATE_HINT: Partial<Record<Sensor["status"], string>> = {
  pending: "pendiente",
  offline: "offline",
  stale: "sin contacto",
};

// Las redes y sensores de un site cambian poco mientras el modal está abierto.
const SITE_DATA_MS = 60_000;

/** Site inicial: el alcance elegido si se puede usar; si no, el site por defecto. */
function initialSite(sites: Site[], scopeId: string | undefined): string {
  const usable = sites.filter((s) => s.status === "active");
  return usable.find((s) => s.site_id === scopeId)?.site_id ?? usable.find((s) => s.is_default)?.site_id ?? usable[0]?.site_id ?? "";
}

/**
 * Iniciar un descubrimiento y seguirlo hasta el resultado.
 *
 * Solo ofrece las redes autorizadas que devuelve el servidor; aun así el backend vuelve a
 * validar el target, porque cualquier cliente puede llamar a la API sin esta pantalla.
 *
 * Fase 5F: se elige site, destino de ejecución y red. "Servidor local" solo existe en el site
 * por defecto (redes de DISCOVERY_ALLOWED_NETWORKS); con un sensor, solo se ofrecen sensores de
 * ESE site no deshabilitados ni revocados y las redes habilitadas del site. Sin catálogo de
 * sites (servidor anterior) se mantiene el comportamiento clásico.
 */
export function DiscoveryModal(props: DiscoveryModalProps) {
  const { scope, activeJobs, canAdminister, adminReason, onClose } = props;
  const site = useSite();
  const [jobId, setJobId] = useState<string | undefined>(props.initialJobId);
  const multiSite = site.sites.length > 0;
  const [chosenSite, setChosenSite] = useState<string>("");
  const siteId = chosenSite || initialSite(site.sites, site.scopeId);
  const selectedSite = site.sites.find((s) => s.site_id === siteId);
  const isDefaultSite = !multiSite || Boolean(selectedSite?.is_default);

  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(siteId, signal), [siteId]);
  const sensors = usePolling(fetchSensors, SITE_DATA_MS, multiSite && Boolean(siteId));
  const fetchNetworks = useCallback((signal: AbortSignal) => sitesApi.networks(siteId, signal), [siteId]);
  const siteNetworks = usePolling(fetchNetworks, SITE_DATA_MS, multiSite && Boolean(siteId));

  // Defensa adicional: aunque la API ya filtra por site, nunca se ofrece un sensor de otro site.
  const usableSensors = (sensors.data?.items ?? []).filter((s) => s.site_id === siteId && sensorUsable(s));
  const [chosenExecution, setChosenExecution] = useState<DiscoveryExecutionTarget | "">("");
  const execution: DiscoveryExecutionTarget = !isDefaultSite
    ? "sensor"
    : chosenExecution || "local";
  const [chosenSensor, setChosenSensor] = useState<string>("");
  const sensorId = usableSensors.some((s) => s.sensor_id === chosenSensor)
    ? chosenSensor
    : (usableSensors[0]?.sensor_id ?? "");

  const networks =
    execution === "local"
      ? (scope?.networks ?? []).map((n) => ({ network: n.network, hosts: n.hosts, label: n.network }))
      : (siteNetworks.data?.items ?? [])
          .filter((n) => n.enabled)
          .map((n) => ({ network: n.cidr, hosts: n.host_count, label: n.name ? `${n.cidr} (${n.name})` : n.cidr }));
  const [chosen, setChosen] = useState<string>("");
  // El alcance puede llegar después de abrir el modal: por defecto, la primera red.
  const target = networks.some((n) => n.network === chosen) ? chosen : (networks[0]?.network ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const changeSite = (value: string) => {
    setChosenSite(value);
    setChosenExecution("");
    setChosenSensor("");
    setChosen("");
    setError(undefined);
  };

  const start = async (network: string, options: DiscoveryStartOptions) => {
    setBusy(true);
    setError(undefined);
    try {
      const job = await consoleApi.startDiscovery(network, options);
      props.onChanged(job);
      setJobId(job.job_id);
    } catch (err) {
      setError(startError(err));
      // Vuelve al formulario para que el error se vea junto a la red elegida.
      setJobId(undefined);
      setChosen(network);
    } finally {
      setBusy(false);
    }
  };

  const currentOptions = (): DiscoveryStartOptions =>
    multiSite && siteId
      ? { siteId, executionTarget: execution, sensorId: execution === "sensor" ? sensorId : undefined }
      : {};

  const actions: JobActions = {
    onShowDevices: props.onShowDevices,
    // Repetir con el mismo site y destino que el job original.
    onRunAgain: (job) =>
      void start(
        job.target,
        multiSite && job.site_id
          ? {
              siteId: job.site_id,
              executionTarget: job.execution_target,
              sensorId: job.sensor_id ?? undefined,
            }
          : {},
      ),
    onChanged: props.onChanged,
    canAdminister,
    adminReason,
  };

  if (jobId) {
    return (
      <Modal title="Descubrimiento de red" onClose={onClose} wide>
        <DiscoveryJobView key={jobId} jobId={jobId} actions={actions} />
      </Modal>
    );
  }

  const selected = networks.find((n) => n.network === target);
  const running = activeJobs.find((job) => job.target === target && (!multiSite || job.site_id === siteId));
  const localEnabled = Boolean(scope?.enabled);
  const siteActive = !multiSite || selectedSite?.status === "active";
  const loadingNetworks = execution === "local" ? !scope : siteNetworks.loading;
  const ready =
    siteActive &&
    Boolean(target) &&
    (execution === "local" ? localEnabled : Boolean(sensorId));

  return (
    <Modal title="Iniciar descubrimiento" onClose={busy ? () => undefined : onClose} wide>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (ready) void start(target, currentOptions());
        }}
      >
        <div className="banner banner--warn" role="note">
          {execution === "local"
            ? "Solo se analizan las redes autorizadas en el servidor (DISCOVERY_ALLOWED_NETWORKS)."
            : "El sensor solo analiza las redes habilitadas de su site."}{" "}
          El servidor vuelve a validar la red antes de escanear: TCP connect, ping, tabla ARP y DNS
          inverso, con límite de velocidad. Sin ataques, fuerza bruta ni credenciales.
        </div>

        {multiSite && (
          <label className="form-field form-field--inline">
            <span>Site</span>
            <select
              className="input input--select"
              value={siteId}
              onChange={(event) => changeSite(event.target.value)}
              disabled={busy}
            >
              {site.selectableSites.map((s) => (
                <option key={s.site_id} value={s.site_id} disabled={s.status !== "active"}>
                  {s.name}
                  {s.is_default ? " (por defecto)" : s.status !== "active" ? " (deshabilitado)" : ""}
                </option>
              ))}
            </select>
          </label>
        )}

        {multiSite && (
          <fieldset className="form-field">
            <legend>Ejecutar desde</legend>
            <div className="toolbar">
              {isDefaultSite && (
                <label className="checkbox">
                  <input
                    type="radio"
                    name="execution-target"
                    value="local"
                    checked={execution === "local"}
                    onChange={() => setChosenExecution("local")}
                    disabled={busy}
                  />{" "}
                  Servidor local
                </label>
              )}
              <label className="checkbox">
                <input
                  type="radio"
                  name="execution-target"
                  value="sensor"
                  checked={execution === "sensor"}
                  onChange={() => setChosenExecution("sensor")}
                  disabled={busy || usableSensors.length === 0}
                />{" "}
                Sensor del site
              </label>
            </div>
            {!isDefaultSite && (
              <span className="muted small">El servidor local solo analiza el site por defecto.</span>
            )}
          </fieldset>
        )}

        {multiSite && execution === "sensor" && (
          sensors.loading ? (
            <p className="muted">Cargando sensores del site…</p>
          ) : usableSensors.length === 0 ? (
            <div className="banner" role="status">
              Este site no tiene sensores disponibles (los deshabilitados y revocados no reciben trabajos).
              Registra uno en Sensores.
            </div>
          ) : (
            <label className="form-field form-field--inline">
              <span>Sensor</span>
              <select
                className="input input--select"
                value={sensorId}
                onChange={(event) => setChosenSensor(event.target.value)}
                disabled={busy}
              >
                {usableSensors.map((s) => (
                  <option key={s.sensor_id} value={s.sensor_id}>
                    {s.name}
                    {SENSOR_STATE_HINT[s.status] ? ` (${SENSOR_STATE_HINT[s.status]})` : ""}
                  </option>
                ))}
              </select>
            </label>
          )
        )}

        {multiSite && !siteActive ? (
          <div className="banner" role="status">
            El site no está activo: actívalo en Configuración → Sites para lanzar descubrimientos.
          </div>
        ) : loadingNetworks ? (
          <p className="muted">Cargando redes autorizadas…</p>
        ) : execution === "local" && !localEnabled ? (
          <div className="banner" role="status">
            {DISABLED_MESSAGE}
          </div>
        ) : networks.length === 0 ? (
          <div className="banner" role="status">
            El site no tiene redes habilitadas. Añádelas en Configuración → Sites.
          </div>
        ) : (
          <>
            <div>
              <h3 className="discovery-job__title">Redes autorizadas</h3>
              <ul className="plain-list mono">
                {networks.map((n) => (
                  <li key={n.network}>
                    {n.label} <span className="muted small">({n.hosts} direcciones)</span>
                  </li>
                ))}
              </ul>
            </div>
            <label className="form-field form-field--inline">
              <span>Red a analizar</span>
              {/* Lista cerrada: no se puede escribir un target fuera de la allowlist. */}
              <select
                className="input input--select"
                value={target}
                onChange={(event) => setChosen(event.target.value)}
                disabled={busy}
              >
                {networks.map((n) => (
                  <option key={n.network} value={n.network}>
                    {n.network}
                  </option>
                ))}
              </select>
            </label>
            <dl className="fields fields--inline" aria-label="Alcance">
              <div className="field">
                <dt>Direcciones a sondear</dt>
                <dd>{selected?.hosts ?? "—"}</dd>
              </div>
              {execution === "local" && scope && (
                <>
                  <div className="field">
                    <dt>Puertos TCP</dt>
                    <dd className="small">{scope.ports.length}</dd>
                  </div>
                  <div className="field">
                    <dt>Ritmo máximo</dt>
                    <dd className="small">{scope.max_probes_per_second} sondas/s</dd>
                  </div>
                  {scope.excluded.length > 0 && (
                    <div className="field">
                      <dt>Excluidas</dt>
                      <dd className="mono small">{scope.excluded.join(", ")}</dd>
                    </div>
                  )}
                </>
              )}
            </dl>
            <p className="muted small" role="status">
              Estado:{" "}
              {running
                ? `ya hay un descubrimiento ${running.status === "queued" ? "en cola" : "en curso"} en esta red.`
                : "sin descubrimientos activos en esta red."}
            </p>
          </>
        )}

        {!canAdminister && adminReason && (
          <div className="banner banner--warn" role="alert">
            {adminReason}
          </div>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}

        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cerrar
          </button>
          {running ? (
            <button type="button" className="button button--primary" onClick={() => setJobId(running.job_id)}>
              Ver progreso
            </button>
          ) : (
            <button
              type="submit"
              className="button button--primary"
              disabled={!ready || !canAdminister || busy}
              title={adminReason}
            >
              {busy ? "Iniciando…" : "Iniciar"}
            </button>
          )}
        </div>
      </form>
    </Modal>
  );
}
