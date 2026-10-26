// Panel (Fase 7A.7): gráficos de anillo, postura, historial de riesgo y listas recientes.
// Todo es SVG y tablas hechos a mano: sin dependencias de gráficos.
import { Link } from "react-router-dom";
import type { DashboardSummary, DetectionSeverity, IncidentStatus, MonitoringMethod, SecurityOverview } from "../../api/types";
import { categoricalColor, groupSmallSlices, NEUTRAL_COLOR, SEVERITY_COLORS, type ChartSlice } from "../../lib/charts";
import { devicesLink } from "../../lib/deviceFilters";
import { formatDateTime, formatRelative } from "../../lib/format";
import { deviceTypeLabel } from "../../lib/identity";
import { STATUS_LABELS as INCIDENT_STATUS_LABELS, STATUS_ORDER as INCIDENT_STATUS_ORDER } from "../../lib/incidents";
import { RISK_LEVEL_LABELS } from "../../lib/risk";
import { DetectionSeverityBadge, SEVERITY_LABELS } from "../detections/DetectionBadges";
import { METHOD_LABELS } from "../NetworkBadges";
import { EmptyState } from "../StateViews";
import { DonutChart } from "./DonutChart";

const SEVERITY_ORDER: DetectionSeverity[] = ["critical", "high", "medium", "low", "informational"];
const METHOD_ORDER: MonitoringMethod[] = ["agent", "agentless", "discovered"];

/** Detecciones activas por severidad (summary.detections.by_severity). */
export function detectionSlices(bySeverity: Record<string, number>): ChartSlice[] {
  return SEVERITY_ORDER.map((severity) => ({
    key: severity,
    label: SEVERITY_LABELS[severity],
    value: bySeverity[severity] ?? 0,
    color: SEVERITY_COLORS[severity],
  }));
}

/** Activos por nivel de riesgo, más los que aún no tienen riesgo calculado (en gris). */
export function riskSlices(byLevel: Record<string, number>, unscored: number): ChartSlice[] {
  const slices: ChartSlice[] = SEVERITY_ORDER.map((level) => ({
    key: level,
    label: RISK_LEVEL_LABELS[level],
    value: byLevel[level] ?? 0,
    color: SEVERITY_COLORS[level],
  }));
  slices.push({ key: "unscored", label: "Sin calcular", value: unscored, color: NEUTRAL_COLOR });
  return slices;
}

/**
 * Activos por tipo: como mucho siete sectores; el resto se agrupa en "Otros". El color va por
 * posición en el orden de tamaño, pero el nombre siempre está en la leyenda junto al valor.
 */
export function deviceTypeSlices(byType: Record<string, number>): ChartSlice[] {
  const grouped = groupSmallSlices(
    Object.entries(byType).map(([key, value]) => ({ key, label: deviceTypeLabel(key === "unknown" ? null : key), value })),
  );
  return grouped.map((entry, index) => ({
    key: entry.key,
    label: entry.grouped ? `${entry.label} (${entry.grouped.length} tipos)` : entry.label,
    value: entry.value,
    color: entry.grouped ? NEUTRAL_COLOR : categoricalColor(index),
    href: entry.grouped ? undefined : devicesLink({ type: entry.key }),
  }));
}

/** Gestionados (agente), monitorizados sin agente y solo descubiertos. */
export function methodSlices(byMethod: Partial<Record<MonitoringMethod, number>>): ChartSlice[] {
  return METHOD_ORDER.map((method, index) => ({
    key: method,
    label: METHOD_LABELS[method],
    value: byMethod[method] ?? 0,
    color: categoricalColor(index),
    href: devicesLink({ method }),
  }));
}

/** Incidentes por estado, cada estado con su color fijo (el color sigue al estado). */
export function incidentSlices(byStatus: Record<string, number>): ChartSlice[] {
  return INCIDENT_STATUS_ORDER.map((status: IncidentStatus, index) => ({
    key: status,
    label: INCIDENT_STATUS_LABELS[status],
    value: byStatus[status] ?? 0,
    color: categoricalColor(index),
  }));
}

/** Los cinco anillos del Panel. El de incidentes se oculta si el rol no puede leerlos. */
export function SummaryCharts({
  summary,
  incidentsByStatus,
}: {
  summary: DashboardSummary;
  incidentsByStatus: Record<string, number> | null | undefined;
}) {
  return (
    <section className="chart-grid-layout" aria-label="Distribuciones">
      <DonutChart
        title="Detecciones activas por severidad"
        slices={detectionSlices(summary.detections.by_severity)}
        centerLabel="activas"
        emptyText="No hay detecciones activas en este alcance."
      />
      <DonutChart
        title="Distribución del riesgo"
        slices={riskSlices(summary.risk.by_level, summary.risk.unscored)}
        centerLabel="activos"
        emptyText="No hay activos en este alcance."
        note="«Sin calcular»: activos en los que el Risk Engine aún no ha evaluado el riesgo."
      />
      <DonutChart
        title="Activos por tipo"
        slices={deviceTypeSlices(summary.assets.by_device_type)}
        centerLabel="activos"
        emptyText="No hay activos en este alcance."
      />
      <DonutChart
        title="Gestionados y descubiertos"
        slices={methodSlices(summary.assets.by_method)}
        centerLabel="activos"
        emptyText="No hay activos en este alcance."
      />
      {incidentsByStatus && (
        <DonutChart
          title="Incidentes por estado"
          slices={incidentSlices(incidentsByStatus)}
          centerLabel="incidentes"
          emptyText="No hay incidentes en este alcance."
        />
      )}
    </section>
  );
}

const KNOWN_SEVERITIES = new Set<string>(SEVERITY_ORDER);

export function RecentDetectionsList({ items }: { items: SecurityOverview["detections_recent"] }) {
  return (
    <section className="panel panel--padded stack" aria-label="Detecciones recientes">
      <div className="panel__toolbar">
        <h2>Detecciones recientes</h2>
        <Link to="/detections" className="small">
          Ver todas
        </Link>
      </div>
      {items.length === 0 ? (
        <EmptyState title="Sin detecciones activas" />
      ) : (
        <ul className="overview-list">
          {items.map((item) => (
            <li key={item.detection_id}>
              {KNOWN_SEVERITIES.has(item.severity) ? (
                <DetectionSeverityBadge severity={item.severity as DetectionSeverity} />
              ) : (
                <span className="badge">{item.severity}</span>
              )}
              <div className="overview-list__main">
                <Link to={`/detections/${item.detection_id}`}>{item.title}</Link>
                <span className="muted small">
                  <span className="mono">{item.rule_id}</span> · {item.asset_name}
                </span>
              </div>
              <span className="muted small" title={formatDateTime(item.last_seen_at)}>
                {formatRelative(item.last_seen_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function NewDevicesList({ data }: { data: SecurityOverview["new_devices"] }) {
  return (
    <section className="panel panel--padded stack" aria-label="Dispositivos nuevos">
      <div className="panel__toolbar">
        <h2>Dispositivos nuevos</h2>
        <span className="muted small">
          {data.count} en los últimos {data.window_days} días
        </span>
      </div>
      {data.items.length === 0 ? (
        <EmptyState title="Ningún dispositivo nuevo">No apareció ningún equipo en este periodo.</EmptyState>
      ) : (
        <ul className="overview-list">
          {data.items.map((item) => (
            <li key={item.asset_id}>
              <div className="overview-list__main">
                <Link to={`/assets/${item.asset_id}`}>{item.name}</Link>
                <span className="muted small">
                  {deviceTypeLabel(item.device_type)} ·{" "}
                  {METHOD_LABELS[item.monitoring_method as MonitoringMethod] ?? item.monitoring_method}
                </span>
              </div>
              <span className="muted small" title={formatDateTime(item.first_seen_at)}>
                {formatRelative(item.first_seen_at)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function ExposedPortsList({ data }: { data: SecurityOverview["exposed_ports"] }) {
  const max = Math.max(1, ...data.top.map((item) => item.assets));
  return (
    <section className="panel panel--padded stack" aria-label="Puertos expuestos">
      <div className="panel__toolbar">
        <h2>Puertos expuestos</h2>
        <Link to={devicesLink({ sort: "ports", dir: "desc" })} className="small">
          Ver dispositivos
        </Link>
      </div>
      <p className="muted small">
        {data.open_ports} puertos abiertos en {data.assets_with_open_ports} activos.
      </p>
      {data.top.length === 0 ? (
        <EmptyState title="Sin puertos abiertos conocidos" />
      ) : (
        <table className="table table--compact bar-table">
          <thead>
            <tr>
              <th scope="col">Puerto</th>
              <th scope="col">Activos</th>
            </tr>
          </thead>
          <tbody>
            {data.top.map((item) => (
              <tr key={`${item.port}/${item.protocol}`}>
                <td className="mono">
                  {item.port}/{item.protocol}
                </td>
                <td>
                  <span className="bar-table__cell">
                    <span
                      className="bar-table__bar"
                      style={{ width: `${(item.assets / max) * 100}%` }}
                      aria-hidden="true"
                    />
                    <span className="num">{item.assets}</span>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
