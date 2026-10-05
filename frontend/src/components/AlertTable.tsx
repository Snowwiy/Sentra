import { Link } from "react-router-dom";
import type { Alert, AlertRule, AlertSeverity } from "../api/types";
import { formatDateTime, formatRelative } from "../lib/format";

export const RULE_LABELS: Record<AlertRule, string> = {
  asset_offline: "Activo offline",
  high_cpu: "CPU elevada",
  high_ram: "RAM elevada",
  disk_critical: "Disco crítico",
  service_stopped: "Servicio detenido",
  event_burst: "Ráfaga de errores",
  admin_changed: "Cambio de administradores",
  critical_event: "Evento crítico",
  asset_discovered: "Nuevo activo",
  unknown_device: "Dispositivo desconocido",
  asset_disappeared: "Activo desaparecido",
  port_exposed: "Nuevo puerto expuesto",
  port_closed: "Puerto cerrado",
  monitoring_lost: "Monitorización perdida",
  security_detection: "Detección de seguridad",
  risk_critical: "Riesgo crítico",
};

const SEVERITY_LABELS: Record<AlertSeverity, string> = {
  info: "Info",
  warning: "Warning",
  critical: "Critical",
};

export function SeverityBadge({ severity }: { severity: AlertSeverity }) {
  return <span className={`severity severity--${severity}`}>{SEVERITY_LABELS[severity]}</span>;
}

/** Alert list; `showAsset` is off on the asset detail page where the host is implied. */
export function AlertTable({ alerts, showAsset = true }: { alerts: Alert[]; showAsset?: boolean }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Severidad</th>
            <th>Regla</th>
            {showAsset && <th>Activo</th>}
            <th>Detalle</th>
            <th>Abierta</th>
            <th>Estado</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert) => (
            <tr key={alert.alert_id}>
              <td>
                <SeverityBadge severity={alert.severity} />
              </td>
              <td>{RULE_LABELS[alert.rule]}</td>
              {showAsset && (
                <td>
                  <Link to={`/assets/${alert.asset_id}`} className="strong">
                    {alert.hostname}
                  </Link>
                </td>
              )}
              <td className="muted">{alert.message}</td>
              <td title={formatDateTime(alert.opened_at)}>{formatRelative(alert.opened_at)}</td>
              <td>
                {alert.status === "open" ? (
                  <span className="alert-state alert-state--open">Abierta</span>
                ) : alert.status === "acknowledged" ? (
                  <span className="alert-state" title={formatDateTime(alert.acknowledged_at)}>
                    Reconocida
                  </span>
                ) : (
                  <span className="muted" title={formatDateTime(alert.resolved_at)}>
                    Resuelta {formatRelative(alert.resolved_at)}
                  </span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
