import { useState } from "react";
import { ApiError } from "../../api/client";
import { consoleApi } from "../../api/sentra";
import type { DiscoveryJob, DiscoveryScope } from "../../api/types";
import { errorMessage } from "../../lib/format";
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

/**
 * Iniciar un descubrimiento y seguirlo hasta el resultado.
 *
 * Solo ofrece las redes autorizadas que devuelve el servidor; aun así el backend vuelve a
 * validar el target, porque cualquier cliente puede llamar a la API sin esta pantalla.
 */
export function DiscoveryModal(props: DiscoveryModalProps) {
  const { scope, activeJobs, canAdminister, adminReason, onClose } = props;
  const [jobId, setJobId] = useState<string | undefined>(props.initialJobId);
  const networks = scope?.networks ?? [];
  const [chosen, setChosen] = useState<string>("");
  // El alcance puede llegar después de abrir el modal: por defecto, la primera red.
  const target = chosen || networks[0]?.network || "";
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const start = async (network: string) => {
    setBusy(true);
    setError(undefined);
    try {
      const job = await consoleApi.startDiscovery(network);
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

  const actions: JobActions = {
    onShowDevices: props.onShowDevices,
    onRunAgain: (network) => void start(network),
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
  const running = activeJobs.find((job) => job.target === target);
  const enabled = Boolean(scope?.enabled);

  return (
    <Modal title="Iniciar descubrimiento" onClose={busy ? () => undefined : onClose} wide>
      <form
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          if (target) void start(target);
        }}
      >
        <div className="banner banner--warn" role="note">
          Solo se analizan las redes autorizadas en el servidor (DISCOVERY_ALLOWED_NETWORKS). El
          servidor vuelve a validar la red antes de escanear: TCP connect, ping, tabla ARP y DNS
          inverso, con límite de velocidad. Sin ataques, fuerza bruta ni credenciales.
        </div>

        {!scope ? (
          <p className="muted">Cargando redes autorizadas…</p>
        ) : !enabled ? (
          <div className="banner" role="status">
            {DISABLED_MESSAGE}
          </div>
        ) : (
          <>
            <div>
              <h3 className="discovery-job__title">Redes autorizadas</h3>
              <ul className="plain-list mono">
                {networks.map((n) => (
                  <li key={n.network}>
                    {n.network} <span className="muted small">({n.hosts} direcciones)</span>
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
              disabled={!enabled || !target || !canAdminister || busy}
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
