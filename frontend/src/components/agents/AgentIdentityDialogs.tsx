import { useCallback, useState } from "react";
import { consoleApi } from "../../api/sentra";
import type { Agent, AgentRecovery, AgentRecoveryCreated } from "../../api/types";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { CopyButton } from "../CopyButton";
import { ConfirmDialog, Modal } from "../Modal";

const RECOVERY_STATES: Record<AgentRecovery["state"], string> = {
  active: "Activa",
  consumed: "Usada",
  expired: "Caducada",
  revoked: "Revocada",
};

const MIN_REASON = 10;

/**
 * Fase 7D.1 (H01): autorizar la recuperación de la identidad de ESTE agente.
 *
 * Un token de instalación ordinario solo da de alta equipos nuevos; reinstalar un equipo que
 * ya es un activo (credencial perdida, disco nuevo, revocado y reactivado) exige esta
 * autorización: un solo uso, vida corta, ligada al agente, a su activo y a su site, con
 * motivo obligatorio y confirmación explícita. El token se muestra una vez y solo vive en el
 * estado de este componente.
 */
export function RecoveryDialog({
  agent,
  onClose,
  onChanged,
}: {
  agent: Agent;
  onClose: () => void;
  onChanged: () => void;
}) {
  const name = agent.hostname ?? agent.display_name;
  const [reason, setReason] = useState("");
  const [hostname, setHostname] = useState(agent.hostname ?? "");
  const [pinHostname, setPinHostname] = useState(true);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [created, setCreated] = useState<AgentRecoveryCreated>();
  const fetchHistory = useCallback(
    (signal: AbortSignal) => consoleApi.listAgentRecoveries(agent.asset_id, signal),
    [agent.asset_id],
  );
  const history = usePolling(fetchHistory, 10_000);

  const trimmed = reason.trim();
  const valid = trimmed.length >= MIN_REASON && confirmed;

  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const result = await consoleApi.createAgentRecovery(agent.asset_id, {
        reason: trimmed,
        confirm: true,
        ...(pinHostname && hostname.trim() ? { expected_hostname: hostname.trim() } : {}),
      });
      setCreated(result);
      history.refresh();
      onChanged();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={`Recuperar identidad de ${name}`} onClose={busy ? () => undefined : onClose} wide>
      <div className="stack">
        {created ? (
          <>
            <div className="banner banner--warn" role="status">
              Copia la autorización ahora: no se volverá a mostrar. Un solo uso, caduca{" "}
              {formatRelative(created.expires_at)} ({formatDateTime(created.expires_at)}).
            </div>
            <div className="form-field">
              <span>Autorización de recuperación</span>
              <code className="mono small" data-testid="recovery-token" style={{ wordBreak: "break-all" }}>
                {created.token}
              </code>
              <span>
                <CopyButton text={created.token} label="Copiar autorización" />
              </span>
            </div>
            <p className="muted small">
              Úsala en {name} como token de instalación: en Windows, el instalador con <code>-Reenroll</code>;
              en Linux y macOS, <code>sentra-agent-setup --server https://… --token-file FICHERO</code>. El
              agente conserva su agent_id: sigue siendo este mismo activo, con su histórico. Su credencial
              actual deja de valer al usarla.
            </p>
            <div className="modal__actions">
              <button type="button" className="button button--primary" onClick={onClose}>
                Hecho
              </button>
            </div>
          </>
        ) : (
          <>
            <p>
              Un token de instalación ordinario ya no puede volver a registrar un agente existente. Esta
              autorización permite que <strong>{name}</strong> recupere su identidad una sola vez.
            </p>
            <label className="form-field">
              <span>Motivo (obligatorio, queda en la auditoría)</span>
              <textarea
                className="input"
                value={reason}
                minLength={MIN_REASON}
                maxLength={500}
                rows={2}
                placeholder="Reinstalación tras cambio de disco"
                onChange={(event) => setReason(event.target.value)}
              />
              {trimmed.length > 0 && trimmed.length < MIN_REASON && (
                <span className="muted small">Al menos {MIN_REASON} caracteres.</span>
              )}
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={pinHostname}
                onChange={(event) => setPinHostname(event.target.checked)}
              />{" "}
              Solo válida si el equipo informa este nombre:
              <input
                className="input"
                type="text"
                value={hostname}
                maxLength={255}
                disabled={!pinHostname}
                aria-label="Nombre de equipo esperado"
                onChange={(event) => setHostname(event.target.value)}
              />
            </label>
            <label className="checkbox">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
              />{" "}
              Confirmo que este equipo es <strong>{name}</strong> y que su credencial actual se sustituirá al
              usar la autorización.
            </label>
            {error && (
              <div className="banner banner--warn" role="alert">
                {error}
              </div>
            )}
            <div className="modal__actions">
              <button type="button" className="button" onClick={onClose} disabled={busy}>
                Cancelar
              </button>
              <button
                type="button"
                className="button button--primary"
                disabled={!valid || busy}
                onClick={() => void submit()}
              >
                {busy ? "Generando…" : "Autorizar recuperación"}
              </button>
            </div>
          </>
        )}
        <RecoveryHistory
          items={history.data?.items ?? []}
          onRevoke={async (recovery) => {
            await consoleApi.revokeAgentRecovery(recovery.recovery_id);
            history.refresh();
          }}
        />
      </div>
    </Modal>
  );
}

function RecoveryHistory({
  items,
  onRevoke,
}: {
  items: AgentRecovery[];
  onRevoke: (recovery: AgentRecovery) => Promise<void>;
}) {
  const [revoking, setRevoking] = useState<AgentRecovery>();
  if (items.length === 0) return null;
  return (
    <section aria-label="Autorizaciones de recuperación">
      <h3 className="small">Autorizaciones anteriores</h3>
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Estado</th>
            <th>Motivo</th>
            <th>Por</th>
            <th>Emitida</th>
            <th aria-label="Acciones" />
          </tr>
        </thead>
        <tbody>
          {items.map((item) => (
            <tr key={item.recovery_id}>
              <td>{RECOVERY_STATES[item.state]}</td>
              <td className="small">{item.reason}</td>
              <td className="small">{item.created_by}</td>
              <td className="muted small" title={formatDateTime(item.created_at)}>
                {formatRelative(item.created_at)}
              </td>
              <td>
                {item.state === "active" && (
                  <button type="button" className="button button--small" onClick={() => setRevoking(item)}>
                    Revocar
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {revoking && (
        <ConfirmDialog
          title="Revocar autorización"
          confirmLabel="Revocar"
          danger
          onClose={() => setRevoking(undefined)}
          onConfirm={() => onRevoke(revoking)}
        >
          <p>La autorización dejará de valer aunque no se haya usado.</p>
        </ConfirmDialog>
      )}
    </section>
  );
}

/** Fase 7D.1: pedir al agente que rote su credencial en el próximo heartbeat (sin corte). */
export function RotationDialog({
  agent,
  onClose,
  onChanged,
}: {
  agent: Agent;
  onClose: () => void;
  onChanged: () => void;
}) {
  const name = agent.hostname ?? agent.display_name;
  return (
    <ConfirmDialog
      title="Rotar credencial"
      confirmLabel="Pedir rotación"
      onClose={onClose}
      onConfirm={async () => {
        await consoleApi.requestAgentRotation(agent.asset_id, "Rotación pedida desde el dashboard");
        onChanged();
      }}
    >
      <p>
        <strong>{name}</strong> cambiará su credencial por una nueva en su próximo heartbeat por HTTPS. La
        anterior sigue valiendo hasta que use la nueva: no hay corte de monitorización.
      </p>
      <p className="muted small">
        Necesita el agente 0.7.0 o posterior. Un agente que aún habla por HTTP en claro no rota hasta migrar a
        HTTPS (la credencial nueva viajaría también en claro).
      </p>
    </ConfirmDialog>
  );
}

const TRANSPORT_LABELS: Record<string, string> = {
  https: "HTTPS",
  http_loopback: "HTTP local",
  http_remote: "HTTP en claro",
};

/** Transporte del último heartbeat; HTTP fuera de loopback se marca para migrarlo. */
export function TransportBadge({ agent }: { agent: Agent }) {
  if (!agent.transport) return <span className="muted">—</span>;
  const insecure = agent.transport === "http_remote";
  return (
    <span
      className={`badge ${insecure ? "badge--warn" : "badge--ok"}`}
      title={
        insecure
          ? "La credencial del agente viaja sin cifrar por la red. Migra a HTTPS (docs/agent-https-migration.md) y rota la credencial."
          : formatDateTime(agent.transport_at)
      }
    >
      {TRANSPORT_LABELS[agent.transport] ?? agent.transport}
    </span>
  );
}
