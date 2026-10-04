import type { MonitoringMethod } from "../api/types";

/** DISCOVERED → MONITORED → MANAGED, as in the hybrid monitoring model. */
export const METHOD_LABELS: Record<MonitoringMethod, string> = {
  discovered: "Discovered",
  agentless: "Monitored",
  agent: "Managed",
};

const METHOD_TITLES: Record<MonitoringMethod, string> = {
  discovered: "Encontrado en la red; solo se conoce lo observable desde la red",
  agentless: "Monitorizado en remoto sin agente",
  agent: "Con Sentra Agent instalado",
};

export function MethodBadge({ method }: { method: MonitoringMethod }) {
  return (
    <span className={`badge badge--method-${method}`} title={METHOD_TITLES[method]}>
      {METHOD_LABELS[method]}
    </span>
  );
}

export const DEVICE_TYPE_LABELS: Record<string, string> = {
  windows: "Windows",
  linux: "Linux",
  printer: "Impresora",
  network_device: "Dispositivo de red",
};

export function deviceTypeLabel(type: string | null | undefined): string {
  if (!type) return "Desconocido";
  return DEVICE_TYPE_LABELS[type] ?? type;
}

export function PortList({ ports, limit = 8 }: { ports: number[]; limit?: number }) {
  if (ports.length === 0) return <span className="muted">—</span>;
  const shown = ports.slice(0, limit);
  return (
    <span className="mono small" title={ports.join(", ")}>
      {shown.join(", ")}
      {ports.length > limit && <span className="muted"> +{ports.length - limit}</span>}
    </span>
  );
}
