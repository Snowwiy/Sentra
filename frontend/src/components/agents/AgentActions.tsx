import { useState } from "react";
import { consoleApi } from "../../api/sentra";
import type { Agent } from "../../api/types";
import type { ConsoleState } from "../../lib/useConsole";
import { ConfirmDialog } from "../Modal";
import { RecoveryDialog, RotationDialog } from "./AgentIdentityDialogs";

// Fase 7D.1 (H01): volver a registrar un agente existente ya no usa un token de instalación
// ordinario (el servidor lo rechaza con agent_recovery_required) sino una autorización de
// recuperación de un solo uso ligada a este agente.
type Dialog = "revoke" | "reinstate" | "recovery" | "rotate" | null;

/** Revoke / reinstate / new token for one agent, each behind a confirmation. */
export function AgentActions({
  agent,
  console: consoleState,
  onChanged,
  compact = false,
}: {
  agent: Agent;
  console: ConsoleState;
  onChanged: () => void;
  compact?: boolean;
}) {
  const [dialog, setDialog] = useState<Dialog>(null);
  const name = agent.hostname ?? agent.display_name;
  const disabledReason = consoleState.available ? undefined : consoleState.reason;
  const archived = agent.asset_state === "archived";
  const size = compact ? " button--small" : "";
  // Sin permiso (viewer, analyst) no se muestra ninguna acción; el backend respondería 403.
  if (!consoleState.allowed) return null;

  return (
    <span className="actions" onClick={(event) => event.stopPropagation()}>
      {agent.credential_status === "active" && (
        <button
          type="button"
          className={`button button--danger${size}`}
          disabled={!consoleState.available}
          title={disabledReason}
          onClick={() => setDialog("revoke")}
        >
          {compact ? "Revocar" : "Revocar agente"}
        </button>
      )}
      {agent.credential_status === "revoked" && (
        <button
          type="button"
          className={`button${size}`}
          disabled={!consoleState.available}
          title={disabledReason}
          onClick={() => setDialog("reinstate")}
        >
          Reactivar…
        </button>
      )}
      {agent.credential_status === "active" && !archived && !compact && (
        <button
          type="button"
          className={`button${size}`}
          disabled={!consoleState.available}
          title={disabledReason}
          onClick={() => setDialog("rotate")}
        >
          Rotar credencial…
        </button>
      )}
      {(agent.credential_status === "re_enrollment_required" ||
        (agent.credential_status === "active" && !compact)) &&
        !archived && (
          <button
            type="button"
            className={`button${size}`}
            disabled={!consoleState.available}
            title={disabledReason ?? "Reinstalación o credencial perdida: autoriza que este equipo recupere su identidad"}
            onClick={() => setDialog("recovery")}
          >
            {compact ? "Recuperar…" : "Recuperar identidad…"}
          </button>
        )}

      {dialog === "revoke" && (
        <ConfirmDialog
          title="Revocar agente"
          confirmLabel="Revocar agente"
          danger
          onClose={() => setDialog(null)}
          onConfirm={async () => {
            await consoleApi.revokeAgent(agent.asset_id);
            onChanged();
          }}
        >
          <p>
            El agente <strong>{name}</strong> dejará de poder enviar telemetry, heartbeat, inventory y
            events.
          </p>
          <p className="muted small">
            Su credencial se invalida al instante. El activo y todo su histórico (telemetría, eventos,
            alertas, descubrimiento y exposición) se conservan para auditoría. Para volver a usarlo habrá
            que reactivarlo y autorizar la recuperación de su identidad.
          </p>
        </ConfirmDialog>
      )}
      {dialog === "reinstate" && (
        <ConfirmDialog
          title="Reactivar agente"
          confirmLabel="Reactivar"
          // También se ejecuta tras confirmar: no cerrar el diálogo de recuperación que abre onConfirm.
          onClose={() => setDialog((open) => (open === "reinstate" ? null : open))}
          onConfirm={async () => {
            await consoleApi.reinstateAgent(agent.asset_id);
            onChanged();
            // La credencial anterior no vuelve: se pasa directamente a la autorización.
            setDialog("recovery");
          }}
        >
          <p>
            Se permitirá que <strong>{name}</strong> vuelva a registrarse. Requiere volver a registrarse: no
            recupera su credencial anterior.
          </p>
          <p className="muted small">
            A continuación podrás autorizar la recuperación de su identidad (un solo uso, con motivo) y
            ejecutar de nuevo el instalador en el equipo; seguirá siendo el mismo activo, con su histórico.
          </p>
        </ConfirmDialog>
      )}
      {dialog === "recovery" && (
        <RecoveryDialog agent={agent} onClose={() => setDialog(null)} onChanged={onChanged} />
      )}
      {dialog === "rotate" && (
        <RotationDialog agent={agent} onClose={() => setDialog(null)} onChanged={onChanged} />
      )}
    </span>
  );
}
