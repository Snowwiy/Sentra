import { useState } from "react";
import { consoleApi } from "../../api/sentra";
import type { Agent } from "../../api/types";
import type { ConsoleState } from "../../lib/useConsole";
import { ConfirmDialog } from "../Modal";
import { AddAgentWizard, type WizardPreset } from "./AddAgentWizard";

type Dialog = "revoke" | "reinstate" | "wizard" | null;

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
  const linux = agent.platform === "linux";
  const disabledReason = consoleState.available ? undefined : consoleState.reason;
  const preset: WizardPreset = {
    hostname: agent.hostname ?? undefined,
    note: `Nuevo token para que ${name} vuelva a registrarse. Ejecuta de nuevo el instalador en ese equipo: conservará su identidad (mismo activo e histórico).`,
  };
  const size = compact ? " button--small" : "";

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
      {agent.credential_status === "re_enrollment_required" && (
        <button
          type="button"
          className={`button${size}`}
          disabled={!consoleState.available || !linux}
          title={
            disabledReason ??
            (linux ? undefined : "El instalador Windows aún no está disponible desde el dashboard")
          }
          onClick={() => setDialog("wizard")}
        >
          Nuevo token…
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
            que reactivarlo e instalar con un token nuevo.
          </p>
        </ConfirmDialog>
      )}
      {dialog === "reinstate" && (
        <ConfirmDialog
          title="Reactivar agente"
          confirmLabel="Reactivar"
          // Runs after a successful confirm too: keep the wizard opened by onConfirm.
          onClose={() => setDialog((open) => (open === "reinstate" ? null : open))}
          onConfirm={async () => {
            await consoleApi.reinstateAgent(agent.asset_id);
            onChanged();
            // The old credential never comes back: go straight to a new one-time token.
            if (linux && consoleState.info) setDialog("wizard");
          }}
        >
          <p>
            Se permitirá que <strong>{name}</strong> vuelva a registrarse. Re-enrollment required: no
            recupera su credencial anterior.
          </p>
          <p className="muted small">
            Necesitará un token de instalación nuevo y volver a ejecutar el instalador en el equipo;
            seguirá siendo el mismo activo, con su histórico.
            {!linux && " El instalador Windows aún no está disponible desde el dashboard."}
          </p>
        </ConfirmDialog>
      )}
      {dialog === "wizard" && consoleState.info && (
        <AddAgentWizard
          info={consoleState.info}
          preset={preset}
          onClose={() => setDialog(null)}
          onRegistered={onChanged}
        />
      )}
    </span>
  );
}
