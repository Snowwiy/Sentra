import { useCallback } from "react";
import { sentraApi } from "../../api/sentra";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { useConsole } from "../../lib/useConsole";
import { usePolling } from "../../lib/usePolling";
import { AgentActions } from "../agents/AgentActions";
import { AgentStateBadge, CredentialBadge, PLATFORM_LABELS } from "../agents/AgentBadges";
import { ErrorState, LoadingState } from "../StateViews";

/** "Agent" section of a managed asset: identity, credential state and actions. */
export function AgentPanel({ assetId }: { assetId: string }) {
  const fetchAgent = useCallback(
    (signal: AbortSignal) => sentraApi.getAssetAgent(assetId, signal),
    [assetId],
  );
  const { data: agent, error, loading, refresh } = usePolling(fetchAgent, config.refreshIntervalMs);
  const consoleState = useConsole();

  return (
    <section className="panel" aria-label="Agent">
      <div className="panel__toolbar">
        <h2>Agent</h2>
        {agent && (
          <span className="actions">
            <AgentActions agent={agent} console={consoleState} onChanged={refresh} />
            <button
              type="button"
              className="button"
              disabled
              title="Sin control remoto: Sentra solo monitoriza. Reinicia el servicio en el equipo (sudo systemctl restart sentra-agent)."
            >
              Reiniciar agente
            </button>
          </span>
        )}
      </div>
      {loading ? (
        <LoadingState label="Cargando agente…" />
      ) : !agent ? (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      ) : (
        <>
          <dl className="fields fields--inline">
            <div className="field">
              <dt>Agent ID</dt>
              <dd className="mono small">{agent.agent_id}</dd>
            </div>
            <div className="field">
              <dt>Versión</dt>
              <dd className="mono">{agent.agent_version ?? "—"}</dd>
            </div>
            <div className="field">
              <dt>Plataforma</dt>
              <dd>{PLATFORM_LABELS[agent.platform]}</dd>
            </div>
            <div className="field">
              <dt>Estado</dt>
              <dd>
                <AgentStateBadge agent={agent} />
              </dd>
            </div>
            <div className="field">
              <dt>Credencial</dt>
              <dd>
                <CredentialBadge status={agent.credential_status} />
                {agent.revoked_at && (
                  <span className="muted small" title={formatDateTime(agent.revoked_at)}>
                    {" "}
                    {formatRelative(agent.revoked_at)}
                  </span>
                )}
              </dd>
            </div>
            <div className="field">
              <dt>Enrolado</dt>
              <dd title={formatDateTime(agent.enrolled_at)}>{formatRelative(agent.enrolled_at)}</dd>
            </div>
            <div className="field">
              <dt>Credencial emitida</dt>
              <dd title={formatDateTime(agent.credential_issued_at)}>
                {agent.credential_issued_at ? formatRelative(agent.credential_issued_at) : "—"}
              </dd>
            </div>
            <div className="field">
              <dt>Último heartbeat</dt>
              <dd title={formatDateTime(agent.last_seen_at)}>{formatRelative(agent.last_seen_at)}</dd>
            </div>
            <div className="field">
              <dt>Método de instalación</dt>
              <dd className="muted" title="El agente todavía no informa de cómo se instaló">
                No reportado
              </dd>
            </div>
          </dl>
          {agent.credential_status === "re_enrollment_required" && (
            <p className="muted small">
              Re-enrollment required: genera un token nuevo y ejecuta otra vez el instalador en el
              equipo; seguirá siendo este mismo activo.
            </p>
          )}
          {!consoleState.available && consoleState.reason && !consoleState.loading && (
            <p className="muted small">{consoleState.reason}</p>
          )}
        </>
      )}
    </section>
  );
}
