import type { DiscoveryJob, DiscoveryJobStatus } from "../api/types";

/** Nombres de estado tal como los define la especificación de Fase 4D. */
export const JOB_STATUS_LABELS: Record<DiscoveryJobStatus, string> = {
  queued: "Queued",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
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
  if (job.requested_via === "dashboard") return "Dashboard";
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
