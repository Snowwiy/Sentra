// Presentación de la telemetría de endpoint y del árbol de procesos (Fase 6E.3/6E.4).
import type { ActivityCategory, ActivityEvent, CmdlinePolicy, DetectionExclusionField } from "../api/types";

export const ACTIVITY_CATEGORY_LABELS: Record<ActivityCategory, string> = {
  process: "Procesos",
  network: "Red",
  service: "Servicios",
  scheduled_task: "Tareas programadas",
  persistence: "Persistencia",
  auth: "Autenticación",
  dns: "DNS",
  protection: "Protección",
  firewall: "Firewall",
  agent_health: "Salud del agente",
};

export const PARENT_RELATION_LABELS: Record<string, string> = {
  observed: "padre observado",
  inferred: "padre inferido",
  missing: "padre no observado",
  pid_reused: "PID reutilizado",
};

export const CMDLINE_POLICY_LABELS: Record<CmdlinePolicy, string> = {
  off: "No se recogen líneas de comando",
  redacted: "Líneas de comando redactadas (sin contraseñas ni tokens)",
  full: "Líneas de comando completas",
};

export const COLLECTOR_STATE_LABELS: Record<string, string> = {
  active: "Activo",
  unavailable: "No disponible",
  permission_denied: "Sin permisos",
  disabled: "Desactivado",
  error: "Error",
};

export const EXCLUSION_FIELD_LABELS: Record<DetectionExclusionField, string> = {
  exe: "Ruta del ejecutable",
  name: "Nombre del proceso",
  sha256: "SHA-256",
  signer: "Firmante",
  parent_name: "Proceso padre",
  remote_address: "IP remota",
  script_path: "Ruta del script",
  script_sha256: "SHA-256 del script",
};

/** Segundos medidos como texto; null = sin medida (nunca se muestra como 0). */
export function formatSeconds(value: number | null | undefined): string {
  if (value === null || value === undefined) return "sin medida";
  if (value < 1) return `${Math.round(value * 1000)} ms`;
  if (value < 120) return `${value.toFixed(1)} s`;
  return `${Math.round(value / 60)} min`;
}

/** Resumen de una línea de un evento de actividad (todo como texto plano). */
export function activitySummary(event: ActivityEvent): string {
  const d = event.data;
  const text = (key: string) => {
    const value = d[key];
    return value === null || value === undefined || value === "" ? undefined : String(value);
  };
  switch (event.category) {
    case "process":
      return [text("name"), text("pid") && `PID ${text("pid")}`, text("username")].filter(Boolean).join(" · ");
    case "network": {
      const remote = text("remote_address") ? `${text("remote_address")}:${text("remote_port") ?? "?"}` : undefined;
      const local = text("local_address") ? `${text("local_address")}:${text("local_port") ?? "?"}` : undefined;
      return [text("protocol")?.toUpperCase(), local, remote && `→ ${remote}`, text("state")].filter(Boolean).join(" ");
    }
    case "auth":
      return [text("user"), text("logon_type") && `tipo ${text("logon_type")}`, text("source_ip")].filter(Boolean).join(" · ");
    case "dns":
      return [text("query"), text("record_type")].filter(Boolean).join(" ");
    default:
      return [text("name") ?? text("product") ?? text("profile") ?? text("mechanism"), text("location") ?? text("exe")]
        .filter(Boolean)
        .join(" · ");
  }
}
