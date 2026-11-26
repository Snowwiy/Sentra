import type { SiemEventRead, SiemSeverity } from "../../api/types";
import { formatDateTime, formatRelative } from "../../lib/format";

// Tabla de eventos SIEM compartida por la pestaña Eventos, la búsqueda (7F.6) y el Live SOC
// (7F.7). Todo el contenido es texto de una fuente externa: se pinta como texto.

export const SEVERITY_LABELS: Record<SiemSeverity, string> = {
  informational: "Informativa",
  low: "Baja",
  medium: "Media",
  high: "Alta",
  critical: "Crítica",
  unknown: "Desconocida",
};


export function severityClass(severity: string): string {
  if (severity === "critical" || severity === "high") return "badge badge--crit";
  if (severity === "medium") return "badge badge--warn";
  return "badge badge--muted";
}


export function SiemSeverityBadge({ severity }: { severity: string }) {
  return <span className={severityClass(severity)}>{SEVERITY_LABELS[severity as SiemSeverity] ?? severity}</span>;
}


export function SiemEventsTable({ items, onOpen }: { items: SiemEventRead[]; onOpen: (event: SiemEventRead) => void }) {
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Hora</th>
            <th>Fuente</th>
            <th>Tipo</th>
            <th>Severidad</th>
            <th>Origen</th>
            <th>Destino</th>
            <th>Activo</th>
            <th>Mensaje</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.event_id}>
              <td title={formatDateTime(e.timestamp)}>
                <button type="button" className="link-button" onClick={() => onOpen(e)}>
                  {formatRelative(e.timestamp)}
                </button>
              </td>
              <td className="small">{e.source_name}</td>
              <td className="mono small">{e.event_type}</td>
              <td>
                <SiemSeverityBadge severity={e.severity} />
              </td>
              <td className="mono small">
                {e.source_ip ?? "—"}
                {e.source_port !== null ? `:${e.source_port}` : ""}
              </td>
              <td className="mono small">
                {e.destination_ip ?? "—"}
                {e.destination_port !== null ? `:${e.destination_port}` : ""}
              </td>
              <td className="small">{e.asset?.name ?? <span className="muted">Sin atribuir</span>}</td>
              <td className="small">{e.message ?? "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
