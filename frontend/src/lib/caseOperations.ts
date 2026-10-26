// Fase 7A.6: textos y reglas de presentación de las tareas de caso y de las solicitudes de
// control de red. Las reglas de verdad (transiciones, quién puede qué, objetivos válidos) las
// aplica el servidor; aquí solo se evita enviar lo que seguro rechazaría.
import { ApiError } from "../api/client";
import type {
  CaseEvidenceType,
  CaseTaskKind,
  CaseTaskStatus,
  ControlDirection,
  EnforcementStatus,
  NetworkControlStatus,
  NetworkControlType,
} from "../api/types";

export const TASK_KIND_LABELS: Record<CaseTaskKind, string> = {
  investigate_port: "Investigar un puerto expuesto",
  verify_service: "Verificar un servicio",
  review_vulnerability: "Revisar una vulnerabilidad",
  analyze_evidence: "Analizar evidencia",
  investigate_script: "Investigar un script",
  review_network_activity: "Revisar actividad de red",
  request_policy: "Solicitar una política",
  verify_remediation: "Verificar una corrección",
  prepare_block_rule: "Preparar una regla de bloqueo",
  document_exception: "Documentar una excepción",
  other: "Otra",
};

export const TASK_STATUS_LABELS: Record<CaseTaskStatus, string> = {
  open: "Abierta",
  in_progress: "En curso",
  blocked: "Bloqueada",
  done: "Terminada",
  cancelled: "Cancelada",
};

export const TASK_STATUS_BADGES: Record<CaseTaskStatus, string> = {
  open: "badge",
  in_progress: "badge badge--info",
  blocked: "badge badge--warn",
  done: "badge badge--ok",
  cancelled: "badge badge--muted",
};

/** Botón de cada transición: verbos de trabajo humano, nunca de ejecución técnica. */
export const TASK_TRANSITION_LABELS: Record<CaseTaskStatus, string> = {
  open: "Reabrir",
  in_progress: "Empezar",
  blocked: "Marcar bloqueada",
  done: "Terminar…",
  cancelled: "Cancelar tarea",
};

export const ACTIVE_TASK_STATUSES: CaseTaskStatus[] = ["open", "in_progress", "blocked"];

export const EVIDENCE_TYPE_LABELS: Record<CaseEvidenceType, string> = {
  detection: "Detección",
  alert: "Alerta",
  asset: "Activo",
  vulnerability: "Vulnerabilidad (finding)",
  tool_execution: "Ejecución de herramienta",
  response_execution: "Ejecución de Response",
};

/** Ruta de la UI de cada evidencia (las ejecuciones no tienen vista propia por id). */
export function evidenceLink(type: CaseEvidenceType, id: string): string | null {
  const enc = encodeURIComponent(id);
  switch (type) {
    case "detection":
      return `/detections/${enc}`;
    case "asset":
      return `/assets/${enc}`;
    case "vulnerability":
      return `/vulnerabilities/${enc}`;
    default:
      return null;
  }
}

export const CONTROL_TYPE_LABELS: Record<NetworkControlType, string> = {
  block_port: "Bloquear un puerto",
  block_service: "Bloquear un servicio",
  block_address: "Bloquear una dirección o red",
  block_domain: "Bloquear un dominio",
  restrict_site_access: "Restringir el acceso a un sitio",
  prevent_upload: "Impedir subidas a un destino",
};

export const CONTROL_STATUS_LABELS: Record<NetworkControlStatus, string> = {
  pending_approval: "Pendiente de aprobación",
  approved: "Aprobada",
  rejected: "Rechazada",
  cancelled: "Cancelada",
  expired: "Caducada",
};

export const CONTROL_STATUS_BADGES: Record<NetworkControlStatus, string> = {
  pending_approval: "badge badge--warn",
  approved: "badge badge--ok",
  rejected: "badge badge--crit",
  cancelled: "badge badge--muted",
  expired: "badge badge--muted",
};

export const ENFORCEMENT_LABELS: Record<EnforcementStatus, string> = {
  not_evaluated: "Sin evaluar (pendiente de decisión)",
  no_enforcement_point: "Sin punto de control: Sentra no la aplica",
  applied_manually: "Aplicada manualmente fuera de Sentra",
};

export const DIRECTION_LABELS: Record<ControlDirection, string> = {
  inbound: "Entrante",
  outbound: "Saliente",
  both: "Ambos sentidos",
};

/** Tipos que necesitan sentido; los demás son siempre salientes. */
export const DIRECTIONAL_CONTROLS: ReadonlySet<NetworkControlType> = new Set([
  "block_port",
  "block_service",
  "block_address",
]);

/** Campos del formulario de objetivo de cada tipo (las claves exactas del servidor). */
export interface ControlTargetForm {
  port: string;
  protocol: "tcp" | "udp";
  service: string;
  cidr: string;
  domain: string;
  destination: string;
}

export const EMPTY_TARGET: ControlTargetForm = {
  port: "",
  protocol: "tcp",
  service: "",
  cidr: "",
  domain: "",
  destination: "",
};

const PORT = /^\d{1,5}$/;
const SERVICE = /^[a-z0-9][a-z0-9._+-]{0,63}$/;
const DOMAIN = /^(\*\.)?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]*[a-z0-9]$/;
const CIDR = /^[0-9a-f:.]+(\/\d{1,3})?$/i;

function validPort(text: string): boolean {
  return PORT.test(text) && Number(text) >= 1 && Number(text) <= 65535;
}

/**
 * Objetivo con las claves exactas del tipo, o la lista de problemas. Solo comprobaciones de
 * forma: lo demasiado amplio (un /8, un TLD, loopback) lo rechaza el servidor con su motivo.
 */
export function buildTarget(
  type: NetworkControlType,
  form: ControlTargetForm,
): { target: Record<string, unknown> } | { errors: string[] } {
  const errors: string[] = [];
  switch (type) {
    case "block_port":
      if (!validPort(form.port.trim())) errors.push("Indica un puerto entre 1 y 65535.");
      return errors.length ? { errors } : { target: { port: Number(form.port.trim()), protocol: form.protocol } };
    case "block_service": {
      const service = form.service.trim().toLowerCase();
      if (!SERVICE.test(service)) errors.push("Indica el nombre corto del servicio (p. ej. smb, rdp).");
      const port = form.port.trim();
      if (port && !validPort(port)) errors.push("El puerto debe estar entre 1 y 65535.");
      if (errors.length) return { errors };
      return { target: port ? { service, port: Number(port) } : { service } };
    }
    case "block_address": {
      const cidr = form.cidr.trim();
      if (!CIDR.test(cidr)) errors.push("Indica una dirección IP o una red en formato CIDR.");
      return errors.length ? { errors } : { target: { cidr } };
    }
    case "block_domain":
    case "restrict_site_access": {
      const domain = form.domain.trim().toLowerCase().replace(/\.$/, "");
      if (!DOMAIN.test(domain)) errors.push("Indica un dominio completo (p. ej. ejemplo.com o *.ejemplo.com).");
      return errors.length ? { errors } : { target: { domain } };
    }
    case "prevent_upload": {
      const destination = form.destination.trim().toLowerCase().replace(/\.$/, "");
      if (!DOMAIN.test(destination)) errors.push("Indica el dominio de destino (p. ej. subidas.ejemplo.com).");
      return errors.length ? { errors } : { target: { destination } };
    }
  }
}

/** Objetivo guardado como texto: "445/tcp", "smb (445)", "10.0.0.0/24", "*.ejemplo.com". */
export function describeTarget(type: NetworkControlType, target: Record<string, unknown>): string {
  const text = (key: string) => (target[key] === undefined || target[key] === null ? "" : String(target[key]));
  switch (type) {
    case "block_port":
      return `${text("port")}/${text("protocol")}`;
    case "block_service":
      return text("port") ? `${text("service")} (${text("port")})` : text("service");
    case "block_address":
      return text("cidr");
    case "block_domain":
    case "restrict_site_access":
      return text("domain");
    case "prevent_upload":
      return text("destination");
  }
}

/** ¿Es un 409 de versión vieja de una tarea o solicitud? (la UI recarga, nunca reintenta sola) */
export function isVersionConflict(error: unknown): boolean {
  return error instanceof ApiError && (error.code === "task_conflict" || error.code === "network_control_conflict");
}
