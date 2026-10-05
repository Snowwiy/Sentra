import { useCallback, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { consoleApi, sentraApi } from "../api/sentra";
import type { Agent } from "../api/types";
import { AddAgentWizard } from "../components/agents/AddAgentWizard";
import { AgentActions } from "../components/agents/AgentActions";
import {
  AgentStateBadge,
  CredentialBadge,
  PLATFORM_LABELS,
  agentState,
  type AgentState,
} from "../components/agents/AgentBadges";
import { TokensPanel } from "../components/agents/TokensPanel";
import { SearchInput, SortHeader, Toolbar } from "../components/ListControls";
import { MethodBadge } from "../components/NetworkBadges";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { compareBy, listPage, matchesText } from "../lib/listing";
import { ipSortKey } from "../lib/net";
import { useConsole } from "../lib/useConsole";
import { useListState } from "../lib/useListState";
import { usePolling } from "../lib/usePolling";

type Key = "name" | "ip" | "os" | "version" | "state" | "last" | "enrolled";

const SORTERS: Record<Key, (a: Agent) => string | number | null> = {
  name: (a) => a.hostname ?? a.display_name,
  ip: (a) => ipSortKey(a.primary_ip),
  os: (a) => a.os_name,
  version: (a) => a.agent_version,
  state: (a) => agentState(a),
  last: (a) => a.last_seen_at,
  enrolled: (a) => a.enrolled_at,
};

const CARDS: { key: AgentState | ""; label: string; className: string }[] = [
  { key: "", label: "Total", className: "" },
  { key: "online", label: "Online", className: "stat--online" },
  { key: "offline", label: "Offline", className: "stat--offline" },
  { key: "revoked", label: "Revoked", className: "stat--revoked" },
  { key: "pending", label: "Pending", className: "stat--unknown" },
];

export function AgentsPage() {
  const fetchAgents = useCallback((signal: AbortSignal) => sentraApi.listAgents(signal), []);
  const agents = usePolling(fetchAgents, config.refreshIntervalMs);
  const consoleState = useConsole();
  const fetchTokens = useCallback(
    (signal: AbortSignal) => consoleApi.listEnrollmentTokens(signal),
    [],
  );
  const tokens = usePolling(fetchTokens, config.refreshIntervalMs, consoleState.available);
  const [adding, setAdding] = useState(false);
  const navigate = useNavigate();
  const list = useListState<Key, { state: string }>({ key: "name", dir: "asc" }, { state: "" });

  const refreshAgents = agents.refresh;
  const refreshTokens = tokens.refresh;
  const changed = useCallback(() => {
    refreshAgents();
    refreshTokens();
  }, [refreshAgents, refreshTokens]);

  const items = useMemo(() => agents.data?.items ?? [], [agents.data]);
  const summary = agents.data?.summary;
  const page = listPage(items, {
    filter: (a) =>
      (!list.filters.state || agentState(a) === list.filters.state) &&
      matchesText(list.query, a.hostname, a.display_name, a.primary_ip, a.agent_id, a.os_name),
    compare: compareBy(SORTERS[list.sort.key], list.sort.dir),
    page: list.page,
    pageSize: 100,
  });
  const header = (label: string, key: Key) => (
    <SortHeader label={label} sortKey={key} sort={list.sort} onSort={list.setSort} />
  );

  if (agents.loading) return <LoadingState label="Cargando agentes…" />;
  if (!agents.data && agents.error) {
    return <ErrorState message={errorMessage(agents.error)} onRetry={agents.refresh} />;
  }

  const count = (key: AgentState | "") =>
    !summary ? 0 : key === "" ? summary.total : summary[key];

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Agentes</h1>
          <p className="muted small">
            Equipos con Sentra Agent: estado, credencial y tokens de instalación.
            {agents.updatedAt && ` Actualizado ${formatRelative(agents.updatedAt.toISOString())}.`}
          </p>
        </div>
        {consoleState.allowed && (
          <button
            type="button"
            className="button button--primary nowrap"
            disabled={!consoleState.available}
            title={consoleState.reason}
            onClick={() => setAdding(true)}
          >
            + Añadir agente
          </button>
        )}
      </div>

      {consoleState.reason && !consoleState.loading && (
        <div className="banner banner--warn" role="status">
          {consoleState.reason}
        </div>
      )}
      {agents.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(agents.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="stats stats--5" aria-label="Agentes por estado">
        {CARDS.map((card) => (
          <button
            key={card.label}
            type="button"
            className={`stat ${card.className}${list.filters.state === card.key ? " stat--active" : ""}`}
            aria-pressed={list.filters.state === card.key}
            onClick={() => list.setFilter("state", list.filters.state === card.key ? "" : card.key)}
          >
            <span className="stat__label">{card.label}</span>
            <span className="stat__value">{count(card.key)}</span>
          </button>
        ))}
      </section>

      <section className="panel">
        <Toolbar>
          <SearchInput
            value={list.query}
            onChange={list.setQuery}
            placeholder="Buscar hostname, IP o agent ID"
            label="Buscar agentes"
          />
        </Toolbar>
        {items.length === 0 ? (
          <EmptyState title="Todavía no hay agentes">
            Pulsa «Añadir agente», genera un token de instalación y ejecuta el comando en el equipo:
            aparecerá aquí en cuanto se registre.
          </EmptyState>
        ) : page.total === 0 ? (
          <EmptyState title="Ningún agente coincide con el filtro" />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  {header("Hostname", "name")}
                  {header("IP", "ip")}
                  {header("OS", "os")}
                  <th>Plataforma</th>
                  {header("Versión", "version")}
                  {header("Estado", "state")}
                  {header("Último contacto", "last")}
                  {header("Enrolado", "enrolled")}
                  <th>Método</th>
                  <th>Agent ID</th>
                  <th>Credencial</th>
                  <th aria-label="Acciones" />
                </tr>
              </thead>
              <tbody>
                {page.items.map((agent) => (
                  <tr
                    key={agent.asset_id}
                    className="table__row--link"
                    onClick={() => navigate(`/assets/${agent.asset_id}`)}
                  >
                    <td>
                      <Link
                        to={`/assets/${agent.asset_id}`}
                        className="strong"
                        onClick={(event) => event.stopPropagation()}
                      >
                        {agent.hostname ?? agent.display_name}
                      </Link>
                    </td>
                    <td className="mono">{agent.primary_ip}</td>
                    <td title={[agent.os_name, agent.os_version, agent.architecture].filter(Boolean).join(" ")}>
                      {agent.os_name ?? "—"}
                    </td>
                    <td>{PLATFORM_LABELS[agent.platform]}</td>
                    <td className="mono small">{agent.agent_version ?? "—"}</td>
                    <td>
                      <AgentStateBadge agent={agent} />
                    </td>
                    <td className="muted" title={formatDateTime(agent.last_seen_at)}>
                      {formatRelative(agent.last_seen_at)}
                    </td>
                    <td className="muted" title={formatDateTime(agent.enrolled_at)}>
                      {formatRelative(agent.enrolled_at)}
                    </td>
                    <td>
                      <MethodBadge method={agent.monitoring_method} />
                    </td>
                    <td className="mono small muted" title={agent.agent_id}>
                      {agent.agent_id.slice(0, 8)}…
                    </td>
                    <td>
                      <CredentialBadge status={agent.credential_status} />
                    </td>
                    <td>
                      <AgentActions agent={agent} console={consoleState} onChanged={changed} compact />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Los tokens de instalación son credenciales: solo los ve quien puede gestionarlos. */}
      {consoleState.allowed && (
        <TokensPanel
          tokens={tokens.data?.items}
          loading={tokens.loading}
          error={tokens.error}
          available={consoleState.available}
          reason={consoleState.reason}
          onChanged={tokens.refresh}
        />
      )}

      {adding && consoleState.info && (
        <AddAgentWizard
          info={consoleState.info}
          onClose={() => {
            setAdding(false);
            changed(); // the new token now shows in the list
          }}
          onRegistered={changed}
        />
      )}
    </div>
  );
}
