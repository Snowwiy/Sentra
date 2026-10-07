import { Link } from "react-router-dom";
import type { EventLevel, SystemEvent } from "../api/types";
import { formatDateTime, formatRelative } from "../lib/format";
import { eventTypeLabel } from "../lib/linuxEvents";

const LEVEL_LABELS: Record<EventLevel, string> = {
  info: "Info",
  warning: "Warning",
  error: "Error",
  critical: "Critical",
};

// Reuses the alert severity palette so "critical" looks the same everywhere.
const LEVEL_CLASS: Record<EventLevel, string> = {
  info: "info",
  warning: "warning",
  error: "critical",
  critical: "critical",
};

/** Origen legible: Windows "proveedor · canal · ID", Linux "proveedor · tipo" (Fase 5C.1). */
function origin(event: SystemEvent): string {
  if (event.event_code === null) return eventTypeLabel(event.event_type);
  return `${event.channel} · ID ${event.event_code}`;
}

/**
 * Tabla de eventos. `linux` muestra las columnas del journal (fuente, tipo, usuario, IP de
 * origen) en lugar del canal y el Event ID de Windows, que en Linux no existen.
 */
export function EventTable({
  events,
  showAsset = true,
  linux = false,
}: {
  events: SystemEvent[];
  showAsset?: boolean;
  linux?: boolean;
}) {
  return (
    <div className="table-wrap table-wrap--scroll">
      <table className="table table--wrap">
        <thead>
          <tr>
            <th>Nivel</th>
            <th>Cuándo</th>
            {showAsset && <th>Activo</th>}
            {linux ? (
              <>
                <th>Fuente</th>
                <th>Tipo</th>
                <th>Usuario</th>
                <th>Origen/IP</th>
              </>
            ) : (
              <th>Origen</th>
            )}
            <th>Mensaje</th>
          </tr>
        </thead>
        <tbody>
          {events.map((event) => (
            <tr key={event.event_id}>
              <td>
                <span className={`severity severity--${LEVEL_CLASS[event.level]}`}>
                  {LEVEL_LABELS[event.level]}
                </span>
              </td>
              <td className="nowrap" title={formatDateTime(event.occurred_at)}>
                {formatRelative(event.occurred_at)}
              </td>
              {showAsset && (
                <td className="nowrap">
                  <Link to={`/assets/${event.asset_id}`} className="strong">
                    {event.hostname}
                  </Link>
                </td>
              )}
              {linux ? (
                <>
                  <td className="nowrap">{event.provider}</td>
                  <td className="nowrap">{eventTypeLabel(event.event_type)}</td>
                  <td className="nowrap mono small">{event.data?.user ?? "—"}</td>
                  <td className="nowrap mono small">{event.data?.source_ip ?? "—"}</td>
                </>
              ) : (
                <td className="nowrap">
                  {event.provider}
                  <span className="muted small"> · {origin(event)}</span>
                </td>
              )}
              <td title={event.message}>
                {/* Clamped in a div: line clamping does not work on a table cell itself. */}
                <div className="event-message">
                  {event.message || <span className="muted">Sin mensaje</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
