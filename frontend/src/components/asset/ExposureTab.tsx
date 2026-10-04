import { useCallback } from "react";
import { sentraApi } from "../../api/sentra";
import type { AgentListener, PortProcess } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { ChangesList } from "./ChangesList";

const REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);

function ProcessCell({ process }: { process: PortProcess | null }) {
  if (!process) return <span className="muted">—</span>;
  return (
    <span title={[process.exe, process.username].filter(Boolean).join("\n")}>
      <span className="strong">{process.name ?? "?"}</span>
      {process.pid != null && <span className="muted mono small"> · PID {process.pid}</span>}
      {process.username && <span className="muted small"> · {process.username}</span>}
      {process.exe && <div className="muted mono small">{process.exe}</div>}
    </span>
  );
}

function exposedLabel(listener: AgentListener): { text: string; className: string } {
  if (listener.exposed === true) return { text: "Accesible desde la red", className: "text-warn" };
  if (listener.exposed === false) return { text: "No accesible", className: "text-ok" };
  return { text: "No comprobado", className: "muted" };
}

export function ExposureTab({ assetId, managed }: { assetId: string; managed: boolean }) {
  const fetchExposure = useCallback(
    (signal: AbortSignal) => sentraApi.getExposure(assetId, signal),
    [assetId],
  );
  const { data, error, loading, refresh } = usePolling(fetchExposure, REFRESH_MS);

  if (loading) return <LoadingState label="Cargando exposición…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;

  return (
    <div className="stack">
      <section className="panel">
        <div className="panel__toolbar">
          <h2>Puertos accesibles desde Sentra</h2>
          <span className="muted small">
            {data.baseline_at
              ? `línea base ${formatRelative(data.baseline_at)}`
              : "sin escanear todavía"}
          </span>
        </div>
        {data.ports.length === 0 ? (
          <EmptyState title={data.baseline_at ? "Ningún puerto abierto" : "Sin datos de red"}>
            {data.baseline_at
              ? "Ninguno de los puertos configurados respondió desde el servidor Sentra."
              : "El descubrimiento de red todavía no ha visto este activo."}
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Puerto</th>
                  <th>Protocolo</th>
                  <th>Estado</th>
                  <th>Servicio (por puerto)</th>
                  <th>Primera vez</th>
                  <th>Última vez</th>
                  <th>Proceso (agente)</th>
                </tr>
              </thead>
              <tbody>
                {data.ports.map((port) => (
                  <tr key={`${port.protocol}-${port.port}`}>
                    <td className="mono strong">
                      {port.port}
                      {port.sensitive && (
                        <span className="badge badge--crit" title="Administración remota, compartición de ficheros o base de datos">
                          sensible
                        </span>
                      )}
                    </td>
                    <td className="mono">{port.protocol.toUpperCase()}</td>
                    <td className={port.state === "open" ? "text-ok" : "muted"}>
                      {port.state === "open" ? "Abierto" : `Cerrado ${port.closed_at ? formatRelative(port.closed_at) : ""}`}
                    </td>
                    <td className="muted">{port.service_hint ?? "—"}</td>
                    <td className="muted" title={formatDateTime(port.first_seen_at)}>
                      {formatRelative(port.first_seen_at)}
                    </td>
                    <td className="muted" title={formatDateTime(port.last_seen_at)}>
                      {formatRelative(port.last_seen_at)}
                    </td>
                    <td>
                      <ProcessCell process={port.process} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {managed && (
        <section className="panel">
          <div className="panel__toolbar">
            <h2>Puertos en escucha según el agente</h2>
            <span className="muted small">correlación agente + red</span>
          </div>
          {data.agent_listeners.length === 0 ? (
            <EmptyState title="Sin datos del agente">
              El inventario del agente no incluye sockets en escucha.
            </EmptyState>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Puerto</th>
                    <th>Protocolo</th>
                    <th>Dirección local</th>
                    <th>Proceso</th>
                    <th>Desde la red</th>
                  </tr>
                </thead>
                <tbody>
                  {data.agent_listeners.map((listener) => {
                    const exposed = exposedLabel(listener);
                    return (
                      <tr key={`${listener.protocol}-${listener.port}`}>
                        <td className="mono strong">{listener.port}</td>
                        <td className="mono">{listener.protocol.toUpperCase()}</td>
                        <td className="mono muted">{listener.process.local_address ?? "—"}</td>
                        <td>
                          <ProcessCell process={listener.process} />
                        </td>
                        <td className={exposed.className}>{exposed.text}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <ChangesList assetId={assetId} category="exposure" title="Cambios de exposición" />
    </div>
  );
}
