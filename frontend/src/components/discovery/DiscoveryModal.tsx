import { useCallback, useState } from "react";
import { ApiError } from "../../api/client";
import { consoleApi, sensorsApi, sentraApi, sitesApi, type DiscoveryStartOptions } from "../../api/sentra";
import type {
  DiscoveryExecutionTarget,
  DiscoveryJob,
  DiscoveryProfileCatalog,
  DiscoveryProfileName,
  DiscoveryScope,
  Sensor,
  Site,
} from "../../api/types";
import {
  ADVANCED_CAPABILITY,
  TUNABLE_LIMITS,
  checkLimits,
  limitDraft,
  parsePorts,
  sensorSupportsAdvanced,
  type LimitDraft,
} from "../../lib/discovery";
import { errorMessage } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { useSite } from "../../site/SiteContext";
import { Modal } from "../Modal";
import { DiscoveryJobView, type JobActions } from "./DiscoveryJobView";
import { DiscoveryProfileFields, type ProfileChoice } from "./DiscoveryProfileFields";

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
    return "El sensor elegido no está disponible (deshabilitado, revocado o sin soporte para el perfil avanzado). Elige otro.";
  }
  // Fase 6A: errores de perfiles, puertos y límites.
  if (err instanceof ApiError && err.code === "discovery_tune_forbidden") {
    return "Tu rol no permite ajustar límites ni usar puertos fuera del perfil (requiere discovery:tune).";
  }
  if (err instanceof ApiError && err.code === "discovery_limit_exceeded") {
    const fields = limitDetails(err.details);
    return fields
      ? `Un valor supera el tope del servidor: ${fields}.`
      : `Un valor supera el tope del servidor: ${err.message}`;
  }
  if (err instanceof ApiError && err.code === "discovery_scope_too_large") {
    return "La red tiene más direcciones que el máximo de hosts del perfil. Elige una red más pequeña o sube el límite.";
  }
  if (err instanceof ApiError && err.code === "discovery_options_require_profile") {
    return "Los puertos y límites solo se pueden fijar con un perfil avanzado.";
  }
  return errorMessage(err instanceof Error ? err : new Error(String(err)));
}

/** details de discovery_limit_exceeded: [{"field": "...", "max": n}] → "Concurrencia (máx. 64)". */
function limitDetails(details: unknown): string | undefined {
  if (!Array.isArray(details)) return undefined;
  const parts = details
    .filter((d): d is { field: string; max?: number } => typeof d === "object" && d !== null && "field" in d)
    .map((d) => {
      const label = TUNABLE_LIMITS.find((l) => l.key === d.field)?.label ?? d.field;
      return typeof d.max === "number" ? `${label} (máx. ${d.max})` : label;
    });
  return parts.length > 0 ? parts.join(", ") : undefined;
}

// El catálogo de perfiles solo cambia con la configuración del servidor.
const PROFILES_MS = 10 * 60_000;

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

  // Fase 6A: perfil, puertos y límites. Sin catálogo (servidor anterior) solo existe "Básico".
  const fetchProfiles = useCallback((signal: AbortSignal) => sentraApi.discoveryProfiles(signal), []);
  const profiles = usePolling(fetchProfiles, PROFILES_MS);
  const catalog: DiscoveryProfileCatalog | undefined = profiles.data;
  const selectedSensor = usableSensors.find((s) => s.sensor_id === sensorId);
  const advancedBlocked =
    execution === "sensor" && selectedSensor && !sensorSupportsAdvanced(selectedSensor)
      ? `El sensor ${selectedSensor.name} no declara la capacidad ${ADVANCED_CAPABILITY}: solo admite el descubrimiento básico. Actualízalo para usar Quick, Standard o Deep.`
      : undefined;
  const [chosenProfile, setChosenProfile] = useState<ProfileChoice | "">("");
  const defaultProfile: ProfileChoice =
    catalog && catalog.profiles.some((p) => p.name === catalog.default_profile) ? catalog.default_profile : "basic";
  const wanted = chosenProfile || defaultProfile;
  const profileChoice: ProfileChoice =
    !catalog || advancedBlocked || !catalog.profiles.some((p) => p.name === wanted) ? "basic" : wanted;
  const profile = catalog?.profiles.find((p) => p.name === profileChoice);
  const canTune = Boolean(catalog?.can_tune);
  const [portChoice, setPortChoice] = useState<Partial<Record<DiscoveryProfileName, number[]>>>({});
  const [extraPorts, setExtraPorts] = useState("");
  const [limitDrafts, setLimitDrafts] = useState<Partial<Record<DiscoveryProfileName, LimitDraft>>>({});

  const selectedPorts = profile ? (portChoice[profile.name] ?? profile.ports) : [];
  const extra = canTune ? parsePorts(extraPorts) : { ports: [] as number[] };
  const finalPorts = [...new Set([...selectedPorts, ...extra.ports])].sort((a, b) => a - b);
  const portsError = !profile
    ? undefined
    : extra.error
      ? extra.error
      : finalPorts.length === 0
        ? "Elige al menos un puerto."
        : catalog && finalPorts.length > catalog.caps.max_ports
          ? `Como máximo ${catalog.caps.max_ports} puertos.`
          : undefined;
  const draft = profile ? (limitDrafts[profile.name] ?? limitDraft(profile.limits)) : undefined;
  const limitCheck = profile && catalog && canTune && draft ? checkLimits(draft, profile.limits, catalog.caps) : undefined;
  const limitsInvalid = Boolean(limitCheck && Object.keys(limitCheck.errors).length > 0);
  const portsChanged =
    profile !== undefined &&
    (finalPorts.length !== profile.ports.length || finalPorts.some((p) => !profile.ports.includes(p)));

  const togglePort = (port: number) => {
    if (!profile) return;
    const name = profile.name;
    setPortChoice((current) => {
      const ports = current[name] ?? profile.ports;
      return {
        ...current,
        [name]: ports.includes(port) ? ports.filter((p) => p !== port) : [...ports, port],
      };
    });
  };
  const changeLimit = (key: keyof LimitDraft, value: string) => {
    if (!profile || !draft) return;
    setLimitDrafts((current) => ({ ...current, [profile.name]: { ...draft, [key]: value } }));
  };

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

  const profileOptions = (): DiscoveryStartOptions =>
    profile
      ? {
          profile: profile.name,
          // Solo se envían si cambian respecto al perfil: lo demás lo decide el servidor.
          ...(portsChanged ? { ports: finalPorts } : {}),
          ...(limitCheck && Object.keys(limitCheck.changed).length > 0 ? { limits: limitCheck.changed } : {}),
        }
      : {};

  const currentOptions = (): DiscoveryStartOptions => ({
    ...(multiSite && siteId
      ? { siteId, executionTarget: execution, sensorId: execution === "sensor" ? sensorId : undefined }
      : {}),
    ...profileOptions(),
  });

  const actions: JobActions = {
    onShowDevices: props.onShowDevices,
    // Repetir con el mismo site y destino que el job original.
    onRunAgain: (job) =>
      void start(job.target, {
        ...(multiSite && job.site_id
          ? {
              siteId: job.site_id,
              executionTarget: job.execution_target,
              sensorId: job.sensor_id ?? undefined,
            }
          : {}),
        // Mismo perfil y puertos; los límites ajustados no se repiten (los fija quien tenga tune).
        ...(job.profile ? { profile: job.profile, ports: rerunPorts(job, catalog) } : {}),
      }),
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
  // Ayuda en cliente: con perfil avanzado, una red mayor que su máximo de hosts se rechazaría.
  const maxHosts = profile ? (limitCheck?.changed.max_hosts ?? profile.limits.max_hosts) : undefined;
  const scopeTooLarge = maxHosts !== undefined && selected !== undefined && selected.hosts > maxHosts;
  const ready =
    siteActive &&
    Boolean(target) &&
    (execution === "local" ? localEnabled : Boolean(sensorId)) &&
    !portsError &&
    !limitsInvalid &&
    !scopeTooLarge;

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
              {execution === "local" && scope && !profile && (
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
            <DiscoveryProfileFields
              catalog={catalog}
              catalogError={profiles.error}
              value={profileChoice}
              onChange={(value) => {
                setChosenProfile(value);
                setError(undefined);
              }}
              advancedBlocked={advancedBlocked}
              selectedPorts={selectedPorts}
              onTogglePort={togglePort}
              extraPorts={extraPorts}
              onExtraPorts={setExtraPorts}
              portsError={portsError}
              limits={draft}
              onLimit={changeLimit}
              limitCheck={limitCheck}
              disabled={busy}
            />
            {scopeTooLarge && (
              <div className="banner banner--warn" role="alert">
                La red tiene {selected?.hosts} direcciones y el perfil admite como máximo {maxHosts} hosts.
                {canTune ? " Sube el máximo de hosts o elige una red más pequeña." : " Elige una red más pequeña."}
              </div>
            )}
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

/** Puertos de un job avanzado para repetirlo; sin tune solo se repiten los del perfil actual. */
function rerunPorts(job: DiscoveryJob, catalog: DiscoveryProfileCatalog | undefined): number[] | undefined {
  const ports = job.parameters?.ports;
  if (!Array.isArray(ports) || !ports.every((p): p is number => typeof p === "number")) return undefined;
  const profile = catalog?.profiles.find((p) => p.name === job.profile);
  if (!profile) return undefined;
  const same = ports.length === profile.ports.length && ports.every((p) => profile.ports.includes(p));
  if (same) return undefined;
  return catalog?.can_tune || ports.every((p) => profile.ports.includes(p)) ? ports : undefined;
}
