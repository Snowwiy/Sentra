import type {
  DiscoveryJob,
  DiscoveryJobStatus,
  DiscoveryLimits,
  DiscoveryProfileName,
  DiscoveryTunableLimit,
  EvidenceState,
  ObservationChangeKind,
  ObservationMethod,
  ObservationReachability,
  Sensor,
} from "../api/types";

/** Etiquetas en español de los estados de Fase 4D (el valor de la API no cambia). */
export const JOB_STATUS_LABELS: Record<DiscoveryJobStatus, string> = {
  queued: "En cola",
  running: "En ejecución",
  completed: "Completado",
  failed: "Fallido",
  cancelled: "Cancelado",
};

export const JOB_STATUS_CLASS: Record<DiscoveryJobStatus, string> = {
  queued: "badge",
  running: "badge badge--info",
  completed: "badge badge--ok",
  failed: "badge badge--crit",
  cancelled: "badge badge--warn",
};

const STOP_REASONS: Record<string, string> = {
  operator: "cancelado por un operador",
  shutdown: "la API se detuvo durante el scan",
  timeout: "alcanzó DISCOVERY_JOB_TIMEOUT_MINUTES",
  interrupted: "el proceso que lo ejecutaba dejó de responder",
  error: "error durante el scan",
};

export function isActive(job: Pick<DiscoveryJob, "status"> | undefined): boolean {
  return job?.status === "queued" || job?.status === "running";
}

export function stopReasonLabel(reason: string | null): string | undefined {
  return reason ? (STOP_REASONS[reason] ?? reason) : undefined;
}

export function originLabel(job: Pick<DiscoveryJob, "trigger" | "requested_via">): string {
  if (job.requested_via === "dashboard") return "Consola";
  if (job.requested_via === "cli") return "CLI";
  if (job.trigger === "scheduled") return "Programado";
  return "Manual";
}

/** Perfil del scan a partir de los parámetros guardados en el job (puertos, ICMP, DNS). */
export function profileLabel(parameters: Record<string, unknown> | null): string {
  if (!parameters) return "—";
  const ports = Array.isArray(parameters.ports) ? parameters.ports.length : 0;
  const parts = [`${ports} puertos TCP`];
  if (parameters.icmp === true) parts.push("ICMP");
  if (parameters.reverse_dns === true) parts.push("DNS");
  if (parameters.identify === true) parts.push("nombres (mDNS/NetBIOS/UPnP)");
  return parts.join(" · ");
}

/** mm:ss (o h:mm:ss) para cronómetros y duraciones. */
export function formatClock(totalSeconds: number | null | undefined): string {
  if (totalSeconds == null || !Number.isFinite(totalSeconds) || totalSeconds < 0) return "—";
  const seconds = Math.floor(totalSeconds);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/** Duración de un job: la final si terminó; si está en curso, la transcurrida hasta `now`. */
export function jobElapsedSeconds(job: DiscoveryJob, now = Date.now()): number | null {
  if (job.duration_seconds != null) return job.duration_seconds;
  if (job.status !== "running") return null;
  return Math.max(0, (now - new Date(job.started_at).getTime()) / 1000);
}

export interface ExactProgress {
  label: string;
  done: number;
  total: number;
}

/**
 * Progreso exacto si existe; si no, undefined y la UI muestra spinner + contadores.
 *
 * Solo hay un denominador real en la fase de liveness (todas las direcciones a sondear) y
 * en la de detalle (los hosts vivos ya encontrados). No se combina en un porcentaje global
 * porque el peso de cada fase depende de cuántos hosts respondan: sería un número inventado.
 */
export function exactProgress(job: DiscoveryJob): ExactProgress | undefined {
  if (job.status !== "running" || !job.progress) return undefined;
  if (job.progress.phase === "liveness" && job.hosts_total > 0) {
    return { label: "Hosts procesados", done: job.hosts_scanned, total: job.hosts_total };
  }
  if (job.progress.phase === "details" && job.progress.details_total > 0) {
    return {
      label: "Puertos de hosts activos",
      done: job.progress.details_done,
      total: job.progress.details_total,
    };
  }
  return undefined;
}

export const PHASE_LABELS: Record<string, string> = {
  queued: "En cola",
  pending: "Preparando",
  liveness: "Buscando hosts activos",
  details: "Analizando puertos y nombres",
  done: "Guardando resultados",
};

/** Fase 5F: dónde se ejecutó un job ("Servidor local" o "Sensor <nombre>"). */
export function executionLabel(job: Pick<DiscoveryJob, "execution_target" | "sensor_name" | "sensor_id">): string {
  if (job.execution_target !== "sensor") return "Servidor local";
  return `Sensor ${job.sensor_name ?? job.sensor_id?.slice(0, 8) ?? "desconocido"}`;
}

// --- Fase 6A: descubrimiento avanzado ---------------------------------------------------------

/** Capacidad que debe declarar un sensor para recibir perfiles avanzados. */
export const ADVANCED_CAPABILITY = "network.discovery.advanced";

export function sensorSupportsAdvanced(sensor: Pick<Sensor, "capabilities"> | undefined): boolean {
  return Boolean(sensor?.capabilities?.includes(ADVANCED_CAPABILITY));
}

export const BASIC_PROFILE_LABEL = "Básico";

export const PROFILE_LABELS: Record<DiscoveryProfileName, string> = {
  quick: "Quick",
  standard: "Standard",
  deep: "Deep",
};

/** Nombre del perfil de un job: el avanzado elegido o "Básico" (jobs anteriores incluidos). */
export function jobProfileName(job: Pick<DiscoveryJob, "profile">): string {
  return job.profile ? (PROFILE_LABELS[job.profile] ?? job.profile) : BASIC_PROFILE_LABEL;
}

export function jobTypeLabel(job: Pick<DiscoveryJob, "job_type" | "profile">): string {
  const advanced = job.job_type ? job.job_type === "discovery_advanced" : Boolean(job.profile);
  return advanced ? "Avanzado" : "Básico";
}

/** Límites editables con discovery:tune, en el orden del formulario. */
export const TUNABLE_LIMITS: { key: DiscoveryTunableLimit; label: string; unit: string; min: number }[] = [
  { key: "timeout_ms", label: "Timeout por sonda", unit: "ms", min: 1 },
  { key: "dns_timeout_ms", label: "Timeout DNS", unit: "ms", min: 1 },
  { key: "concurrency", label: "Concurrencia", unit: "sondas", min: 1 },
  { key: "max_probes_per_second", label: "Sondas por segundo", unit: "sondas/s", min: 1 },
  { key: "tcp_retries", label: "Reintentos TCP", unit: "", min: 0 },
  { key: "max_hosts", label: "Máximo de hosts", unit: "hosts", min: 1 },
  { key: "deadline_minutes", label: "Duración máxima", unit: "min", min: 1 },
];

export type LimitDraft = Record<DiscoveryTunableLimit, string>;

export function limitDraft(limits: DiscoveryLimits): LimitDraft {
  const draft = {} as LimitDraft;
  for (const { key } of TUNABLE_LIMITS) draft[key] = String(limits[key]);
  return draft;
}

export interface LimitCheck {
  /** Solo las claves que cambian respecto al perfil (lo que se envía al servidor). */
  changed: Partial<Record<DiscoveryTunableLimit, number>>;
  errors: Partial<Record<DiscoveryTunableLimit, string>>;
}

/**
 * Validación en cliente de los límites contra `caps`. Es solo una ayuda: el servidor vuelve a
 * validar y responde 422 discovery_limit_exceeded si algo supera sus topes.
 */
export function checkLimits(draft: LimitDraft, profile: DiscoveryLimits, caps: DiscoveryLimits): LimitCheck {
  const result: LimitCheck = { changed: {}, errors: {} };
  for (const { key, min } of TUNABLE_LIMITS) {
    const raw = draft[key].trim();
    if (!/^\d+$/.test(raw)) {
      result.errors[key] = "Debe ser un número entero.";
      continue;
    }
    const value = Number(raw);
    if (value < min) result.errors[key] = `Mínimo ${min}.`;
    else if (value > caps[key]) result.errors[key] = `Máximo ${caps[key]} (tope del servidor).`;
    else if (value !== profile[key]) result.changed[key] = value;
  }
  return result;
}

/** "22, 8080 443" → puertos válidos y únicos, o un mensaje de error. */
export function parsePorts(text: string): { ports: number[]; error?: string } {
  const parts = text.split(/[\s,;]+/).filter(Boolean);
  const ports: number[] = [];
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return { ports: [], error: `«${part}» no es un puerto.` };
    const port = Number(part);
    if (port < 1 || port > 65535) return { ports: [], error: `${port} está fuera de 1–65535.` };
    if (!ports.includes(port)) ports.push(port);
  }
  return { ports };
}

export const METHOD_NAMES: Record<ObservationMethod, string> = {
  icmp: "ICMP",
  tcp: "TCP",
  arp: "ARP",
  dns: "DNS",
};

export const REACHABILITY_LABELS: Record<ObservationReachability, string> = {
  responded: "Respondió",
  no_response: "Sin respuesta",
  unknown: "Desconocido",
};

export const REACHABILITY_CLASS: Record<ObservationReachability, string> = {
  responded: "badge badge--ok",
  no_response: "badge badge--warn",
  unknown: "badge",
};

export const CONFIDENCE_LABELS: Record<string, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
};

export const EVIDENCE_STATE_LABELS: Record<EvidenceState, string> = {
  observed: "observado",
  inferred: "inferido",
};

export const OBSERVATION_CHANGE_LABELS: Record<ObservationChangeKind, string> = {
  new_host: "host nuevo",
  host_unresponsive: "host sin respuesta",
  port_new: "puerto nuevo",
  port_unresponsive: "puerto sin respuesta",
  hostname_changed: "hostname cambiado",
  address_changed: "dirección cambiada",
};

/** Fuente de una observación: "Servidor local" o el nombre del sensor. */
export function observationSource(o: { executor: string; sensor_name: string | null; sensor_id: string | null }): string {
  if (o.executor !== "sensor") return "Servidor local";
  return `Sensor ${o.sensor_name ?? o.sensor_id?.slice(0, 8) ?? "desconocido"}`;
}
