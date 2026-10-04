import { Link } from "react-router-dom";
import type { EventLevel, SystemEvent } from "../api/types";
import { formatDateTime, formatRelative } from "../lib/format";

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

export function EventTable({ events, showAsset = true }: { events: SystemEvent[]; showAsset?: boolean }) {
  return (
    <div className="table-wrap table-wrap--scroll">
      <table className="table table--wrap">
        <thead>
          <tr>
            <th>Nivel</th>
            <th>Cuándo</th>
            {showAsset && <th>Activo</th>}
            <th>Origen</th>
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
              <td className="nowrap">
                {event.provider}
                <span className="muted small">
                  {" "}
                  · {event.channel} {event.event_code}
                </span>
              </td>
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
