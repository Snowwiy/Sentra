// Utilidades de Threat Intelligence (Fase 5C): etiquetas en español y helpers puros.
//
// Vocabulario: la inteligencia es contexto EXTERNO. "Explotación conocida reportada (KEV)"
// significa que se ha explotado en algún sitio, no en este activo; EPSS es una probabilidad
// estadística de explotación, no un porcentaje de vulnerabilidad ni de compromiso. Un match
// dice que un dato local coincide con un indicador, no que el activo esté comprometido.
import { ApiError } from "../api/client";
import type {
  IndicatorClassification,
  IntelConfidence,
  IntelSourceState,
  IntelTrust,
  ObservationType,
  ThreatMatchStatus,
} from "../api/types";

export const TRUST_LABELS: Record<IntelTrust, string> = {
  official: "Oficial",
  trusted: "De confianza",
  community: "Comunidad",
  local: "Local",
};

export const SOURCE_STATE_LABELS: Record<IntelSourceState, string> = {
  fresh: "Al día",
  stale: "Desactualizada",
  never_synced: "Sin datos todavía",
  disabled: "Desactivada",
  archived: "Archivada",
};

export const SYNC_STATUS_LABELS: Record<string, string> = {
  never: "Nunca",
  ok: "Correcta",
  success: "Correcta",
  not_modified: "Sin cambios",
  error: "Error",
  unavailable: "No disponible",
  syncing: "Sincronizando",
  running: "En curso",
  failed: "Fallida",
};

export const CLASSIFICATION_LABELS: Record<IndicatorClassification, string> = {
  malicious: "Malicioso",
  suspicious: "Sospechoso",
  benign: "Benigno",
  unknown: "Desconocido",
};

export const CLASSIFICATION_ORDER: IndicatorClassification[] = ["malicious", "suspicious", "unknown", "benign"];

export const CONFIDENCE_LABELS: Record<IntelConfidence, string> = {
  high: "Alta",
  medium: "Media",
  low: "Baja",
};

export const MATCH_STATUS_LABELS: Record<ThreatMatchStatus, string> = {
  open: "Abierto",
  acknowledged: "Reconocido",
  dismissed: "Descartado (falso positivo)",
};

export const OBSERVATION_LABELS: Record<ObservationType, string> = {
  auth_source_ip: "IP de origen de un inicio de sesión",
  connection_remote_ip: "IP remota de una conexión establecida",
  asset_address: "IP de un activo",
  asset_name: "Nombre de un activo",
};

export const INDICATOR_TYPE_LABELS: Record<string, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  cidr: "Red (CIDR)",
  domain: "Dominio",
  hostname: "Hostname",
  url: "URL",
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
  email: "Email",
};

export const INDICATOR_STATE_LABELS: Record<string, string> = {
  active: "Vigente",
  revoked: "Revocado",
  expired: "Caducado",
  not_yet_valid: "Aún no vigente",
};

export const MATCHING_LABELS: Record<string, string> = {
  supported: "Se busca en los datos de Sentra",
  partial: "Visibilidad parcial",
  unsupported: "No soportado: Sentra no recoge este dato",
};

export const EPSS_BAND_LABELS: Record<string, string> = {
  high: "Alta",
  elevated: "Elevada",
  low: "Baja",
  none: "Sin dato",
};

export const CHANGE_LABELS: Record<string, string> = {
  kev_added: "Añadida a KEV",
  kev_readded: "Vuelve a KEV",
  kev_updated: "Entrada KEV actualizada",
  kev_removed: "Retirada de KEV",
  epss_material_change: "Cambio relevante de EPSS",
  epss_removed: "Sin puntuación EPSS",
  indicator_added: "Indicador nuevo",
  indicator_reclassified: "Indicador reclasificado",
  indicator_revoked: "Indicador revocado",
  indicator_restored: "Indicador restaurado",
};

export const ERROR_LABELS: Record<string, string> = {
  blocked_destination: "Destino bloqueado por las protecciones de red (SSRF)",
  unavailable: "La fuente no responde",
  timeout: "Tiempo de espera agotado",
  tls_error: "Certificado TLS no válido",
  too_large: "El contenido supera el tamaño máximo",
  http_error: "La fuente respondió con un error HTTP",
  intel_invalid_json: "El contenido no es JSON válido",
  intel_invalid_format: "El contenido no tiene el formato esperado",
  intel_feed_shrunk: "El feed llegó mucho más pequeño de lo habitual: se conserva el anterior",
  intel_too_many_records: "Demasiados registros",
  threat_intel_sync_disabled: "La sincronización por red está desactivada en el servidor",
};

/** Texto de un código de error de la fuente (o el propio código si no se conoce). */
export function errorLabel(code: string | null | undefined): string {
  if (!code) return "—";
  return ERROR_LABELS[code] ?? code;
}

/** EPSS como probabilidad con 1 decimal: "91,2 %". Nunca "91 % vulnerable". */
export function formatEpss(score: number | null | undefined): string {
  if (score == null) return "—";
  return `${(score * 100).toLocaleString("es-ES", { maximumFractionDigits: 1, minimumFractionDigits: 1 })} %`;
}

/** Percentil EPSS ("percentil 99"). */
export function formatPercentile(value: number | null | undefined): string {
  if (value == null) return "—";
  return `percentil ${Math.floor(value * 100)}`;
}

/** Misma banda que el backend (app/threat_intel/epss.py: alta >= 0,5; elevada >= 0,1). */
export function epssBand(score: number | null | undefined): "high" | "elevated" | "low" | "none" {
  if (score == null) return "none";
  if (score >= 0.5) return "high";
  if (score >= 0.1) return "elevated";
  return "low";
}

/** Acciones de triage que exigen motivo escrito (descartar y reabrir). */
export const REASON_REQUIRED: ReadonlySet<string> = new Set(["dismiss", "reopen"]);

export const MATCH_ACTION_LABELS: Record<string, string> = {
  acknowledge: "Reconocer",
  dismiss: "Descartar (falso positivo)",
  reopen: "Reabrir",
  incident: "Crear incidente",
};

/** ¿Es un 409 de concurrencia (otra persona o el matching cambió el dato)? */
export function isConflict(error: unknown): boolean {
  return error instanceof ApiError && (error.code === "threat_intel_conflict" || error.code === "threat_intel_changed");
}

/** Formato del fichero a partir de su contenido (bundle STIX o sentra-ioc/1). */
export function detectFormat(content: string): "stix" | "sentra-ioc" {
  try {
    const parsed: unknown = JSON.parse(content);
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      const record = parsed as Record<string, unknown>;
      if (record.format === "sentra-ioc/1") return "sentra-ioc";
      if (record.type === "bundle" || Array.isArray(record.objects)) return "stix";
    }
  } catch {
    // JSON inválido: el servidor lo rechazará con su código; da igual el formato elegido.
  }
  return "sentra-ioc";
}
