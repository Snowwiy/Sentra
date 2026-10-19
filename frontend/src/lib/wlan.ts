// Etiquetas y utilidades del inventario Wi-Fi / AP / WLAN (Fase 6C.3).
//
// Reglas de presentación (docs/wlan-discovery.md):
// - Todo es observación pasiva con su procedencia. La UI nunca convierte la evidencia en una
//   afirmación más fuerte: un AP "up" es lo que informa la controladora, un BSS visto por un
//   agente es "observado", no "de la organización".
// - Nada se muestra como desaparecido salvo que la API lo marque (`present = false`). La
//   evidencia antigua (`freshness = historical`) se muestra como histórica, no como ausente.
// - Una MAC aleatoria (localmente administrada) nunca identifica un dispositivo.
// - No existe la clasificación "rogue": solo unknown / authorized / external, y siempre manual.
// - Las configuraciones inseguras son avisos informativos; no alimentan el Risk Engine ni
//   disparan acciones.

import { ApiError } from "../api/client";
import type {
  WlanApReportedStatus,
  WlanAuthorizationStatus,
  WlanBand,
  WlanClientState,
  WlanConfidence,
  WlanCorrelationBasis,
  WlanFindingCode,
  WlanFreshness,
  WlanIdentityConfidence,
  WlanLinkEvidence,
  WlanObservationRead,
  WlanProtection,
  WlanSource,
  WlanSourceAvailability,
  WlanSourceStatus,
} from "../api/types";
import { errorMessage } from "./format";

export const WLAN_BANDS: WlanBand[] = ["2.4", "5", "6"];

export const BAND_LABELS: Record<WlanBand, string> = {
  "2.4": "2,4 GHz",
  "5": "5 GHz",
  "6": "6 GHz",
};

export const AUTHORIZATION_STATUSES: WlanAuthorizationStatus[] = ["unknown", "authorized", "external"];

export const AUTHORIZATION_LABELS: Record<WlanAuthorizationStatus, string> = {
  unknown: "Sin clasificar",
  authorized: "Autorizado",
  external: "Externo (vecino)",
};

export const AUTHORIZATION_HELP: Record<WlanAuthorizationStatus, string> = {
  unknown: "Nadie lo ha clasificado todavía. No implica que sea hostil.",
  authorized: "Un operador lo ha marcado como parte de la red de la organización.",
  external: "Un operador lo ha marcado como ajeno (por ejemplo, la red de un vecino).",
};

/** Texto del botón para pasar a cada estado. */
export const AUTHORIZATION_ACTIONS: Record<WlanAuthorizationStatus, string> = {
  authorized: "Marcar como autorizado",
  external: "Marcar como externo",
  unknown: "Volver a sin clasificar",
};

export const AP_STATUSES: WlanApReportedStatus[] = ["up", "down", "transitional", "unknown"];

export const AP_STATUS_LABELS: Record<WlanApReportedStatus, string> = {
  up: "Activo (informado)",
  down: "Caído (informado)",
  transitional: "En transición",
  unknown: "Desconocido",
};

export const FRESHNESS_VALUES: WlanFreshness[] = ["recent", "historical"];

export const FRESHNESS_LABELS: Record<WlanFreshness, string> = {
  recent: "Evidencia reciente",
  historical: "Evidencia histórica",
};

export const FRESHNESS_HELP: Record<WlanFreshness, string> = {
  recent: "Visto dentro de la ventana de frescura de su fuente (SNMP: consultas recientes; agentes: 24 h).",
  historical: "Solo hay evidencia antigua. No significa que haya desaparecido: puede que nadie lo haya vuelto a consultar.",
};

export const PROTECTIONS: WlanProtection[] = [
  "open",
  "owe",
  "wep",
  "wpa",
  "wpa_wpa2",
  "wpa2",
  "wpa2_wpa3",
  "wpa3",
  "rsn",
  "legacy",
  "unknown",
];

export const PROTECTION_LABELS: Record<WlanProtection, string> = {
  open: "Abierta",
  owe: "OWE (abierta cifrada)",
  wep: "WEP",
  wpa: "WPA",
  wpa_wpa2: "WPA/WPA2",
  wpa2: "WPA2",
  wpa2_wpa3: "WPA2/WPA3",
  wpa3: "WPA3",
  rsn: "RSN (WPA2 o superior)",
  legacy: "Privacidad heredada",
  unknown: "Desconocida",
};

/** Protecciones que la propia API considera inseguras (mismo criterio que sus findings). */
export const INSECURE_PROTECTIONS = new Set<WlanProtection>(["open", "wep", "wpa", "wpa_wpa2", "legacy"]);

export const FINDING_LABELS: Record<WlanFindingCode, string> = {
  open_network: "Red abierta sin cifrado",
  wep: "Cifrado WEP",
  wpa1: "WPA (versión 1)",
  wpa1_allowed: "Admite WPA1 (modo mixto)",
  legacy_privacy: "Privacidad heredada",
  tkip_allowed: "TKIP permitido",
};

export const SOURCES: WlanSource[] = ["snmp_ieee802dot11", "snmp_airespace", "snmp_unifi", "agent"];

export const SOURCE_LABELS: Record<WlanSource, string> = {
  snmp_ieee802dot11: "SNMP IEEE 802.11 (AP autónomo)",
  snmp_airespace: "SNMP AireOS (controladora)",
  snmp_unifi: "SNMP UniFi",
  agent: "Agente",
};

export const CONFIDENCES: WlanConfidence[] = ["reported_by_device", "observed"];

export const CONFIDENCE_LABELS: Record<WlanConfidence, string> = {
  reported_by_device: "Informado por el equipo",
  observed: "Observado por un agente",
};

export const IDENTITY_CONFIDENCES: WlanIdentityConfidence[] = ["confirmed", "probable", "observation_only"];

export const IDENTITY_LABELS: Record<WlanIdentityConfidence, string> = {
  confirmed: "Identidad confirmada",
  probable: "Identidad probable",
  observation_only: "Solo observación",
};

export const CORRELATION_LABELS: Record<WlanCorrelationBasis, string> = {
  agent_self: "lo informa el propio agente",
  mac_match: "MAC global coincidente con el activo",
  agent_reported_mac: "MAC informada por el agente",
};

export const CLIENT_STATES: WlanClientState[] = [
  "associated",
  "authenticated",
  "connected",
  "idle",
  "power_save",
  "disassociated",
  "pending",
  "probing",
  "excluded",
  "unknown",
];

export const CLIENT_STATE_LABELS: Record<WlanClientState, string> = {
  associated: "Asociado",
  authenticated: "Autenticado",
  connected: "Conectado",
  idle: "Inactivo",
  power_save: "Ahorro de energía",
  disassociated: "Desasociado",
  pending: "Pendiente",
  probing: "Sondeando",
  excluded: "Excluido",
  unknown: "Desconocido",
};

export const LINK_BASIS_LABELS: Record<WlanLinkEvidence["basis"], string> = {
  management_ip: "IP de gestión coincidente",
  mac: "MAC Ethernet coincidente",
  source_device: "el AP es el propio equipo consultado",
};

const AVAILABILITY_LABELS: Record<WlanSourceAvailability, string> = {
  available: "Informando",
  partial: "Parcial",
  unavailable: "Sin datos utilizables",
  not_configured: "No configurado",
};

export const AVAILABILITY_CLASS: Record<WlanSourceAvailability, string> = {
  available: "badge badge--ok",
  partial: "badge badge--warn",
  unavailable: "badge badge--warn",
  not_configured: "badge badge--muted",
};

export function availabilityLabel(value: WlanSourceAvailability): string {
  return AVAILABILITY_LABELS[value] ?? value;
}

// Estado del módulo wlan en la última consulta SNMP de cada equipo y estado del informe
// Wi-Fi de cada agente. Una clave desconocida se muestra tal cual en lugar de ocultarse.
const SNMP_MODULE_LABELS: Record<string, string> = {
  complete: "completa",
  partial: "parcial",
  unsupported: "sin MIB Wi-Fi compatible",
  failed: "fallida",
};

const AGENT_STATUS_LABELS: Record<string, string> = {
  ok: "correcto",
  no_adapter: "sin adaptador Wi-Fi",
  permission_limited: "permisos limitados",
  unsupported: "no soportado",
  error: "error",
};

export interface SourceDescription {
  title: string;
  reporters: string;
  breakdown: string | undefined;
  explanation: string;
  /** Aviso cuando parte de los datos procede de una consulta o informe incompleto. */
  partialNote: string | undefined;
}

function breakdown(byStatus: Record<string, number>, labels: Record<string, string>): string | undefined {
  const parts = Object.entries(byStatus)
    .filter(([, n]) => n > 0)
    // Primero lo más frecuente; a igualdad, orden estable por clave.
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([key, n]) => `${n} ${labels[key] ?? key}`);
  return parts.length ? parts.join(", ") : undefined;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** Texto en español de un indicador de disponibilidad (el `detail` del backend va en inglés). */
export function describeSource(status: WlanSourceStatus): SourceDescription {
  if (status.source === "snmp") {
    const partial = status.by_status.partial ?? 0;
    const explanation: Record<WlanSourceAvailability, string> = {
      available: "Al menos un equipo consultado por SNMP ha entregado datos Wi-Fi completos.",
      partial: "El módulo Wi-Fi solo se ha recogido en parte: los datos pueden estar incompletos.",
      unavailable:
        status.reporters > 0 && Object.keys(status.by_status).length === 0
          ? "Hay sensores con la capacidad snmp.wlan, pero todavía no se ha consultado ninguna controladora o AP."
          : "Los equipos consultados no exponen una MIB Wi-Fi compatible o la consulta falló.",
      not_configured: "Ningún sensor declara la capacidad snmp.wlan (requiere el sensor 0.4.0 o posterior).",
    };
    const modules = breakdown(status.by_status, SNMP_MODULE_LABELS);
    return {
      title: "SNMP (controladoras y AP)",
      reporters: plural(status.reporters, "sensor con snmp.wlan", "sensores con snmp.wlan"),
      breakdown: modules ? `Última consulta Wi-Fi por equipo: ${modules}` : undefined,
      explanation: explanation[status.availability] ?? status.detail,
      partialNote:
        partial > 0
          ? `La última consulta Wi-Fi de ${plural(partial, "equipo fue parcial", "equipos fue parcial")}: lo que no informó no se marca como ausente.`
          : undefined,
    };
  }
  const limited = status.by_status.permission_limited ?? 0;
  const explanation: Record<WlanSourceAvailability, string> = {
    available: "Al menos un agente informa de las redes Wi-Fi que ve su equipo.",
    partial: "Los agentes informan con permisos limitados del sistema operativo: faltan redes o datos.",
    unavailable: "Los agentes que informan no tienen adaptador Wi-Fi o no obtienen datos útiles.",
    not_configured: "Ningún agente ha enviado todavía un informe Wi-Fi (campo wireless del inventario).",
  };
  const states = breakdown(status.by_status, AGENT_STATUS_LABELS);
  return {
    title: "Agentes (Wi-Fi de cada equipo)",
    reporters: plural(status.reporters, "agente con informe Wi-Fi", "agentes con informe Wi-Fi"),
    breakdown: states ? `Estado del último informe: ${states}` : undefined,
    explanation: explanation[status.availability] ?? status.detail,
    partialNote:
      limited > 0
        ? `${plural(limited, "agente informa", "agentes informan")} con permisos limitados: la lista de redes puede estar incompleta.`
        : undefined,
  };
}

/** Siguientes estados que se ofrecen (todos menos el actual). Nunca "rogue". */
export function authorizationTargets(current: WlanAuthorizationStatus): WlanAuthorizationStatus[] {
  return (["authorized", "external", "unknown"] as const).filter((s) => s !== current);
}

const MAC_RE = /^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$/i;

/** Una MAC con ":" o "-", la forma que acepta la API en el filtro `bssid`. */
export function looksLikeMac(value: string): boolean {
  return MAC_RE.test(value.trim());
}

/** Procedencia legible de una observación: quién la informó y por qué vía. */
export function observationProvenance(observation: WlanObservationRead): string {
  const parts: string[] = [SOURCE_LABELS[observation.source] ?? observation.source];
  if (observation.reported_by) parts.push(`equipo ${observation.reported_by.display_name}`);
  if (observation.sensor) parts.push(`sensor ${observation.sensor.name}`);
  if (observation.agent_asset) parts.push(`activo ${observation.agent_asset.display_name}`);
  return parts.join(" · ");
}

const DATA_KEYS_LIMIT = 8;

/** Datos observados en una línea, acotados (la fuente no es de confianza y puede ser larga). */
export function summarizeObservationData(data: WlanObservationRead["data"]): string {
  const entries = Object.entries(data).filter(([, value]) => value !== null && value !== "");
  if (entries.length === 0) return "sin datos";
  const shown = entries.slice(0, DATA_KEYS_LIMIT).map(([key, value]) => `${key}: ${String(value)}`);
  const rest = entries.length - shown.length;
  return rest > 0 ? `${shown.join(" · ")} · (+${rest})` : shown.join(" · ");
}

const ENTITY_LABELS: Record<WlanObservationRead["entity"], string> = {
  access_point: "AP",
  bss: "BSS",
  client: "Cliente",
};

export function entityLabel(entity: WlanObservationRead["entity"]): string {
  return ENTITY_LABELS[entity] ?? entity;
}

// Errores de las acciones WLAN con un mensaje en español; el resto conserva el del backend.
const WLAN_ERRORS: Record<string, string> = {
  wlan_version_conflict: "Otro usuario ha cambiado este elemento mientras lo editabas. Se han recargado los datos; revisa y repite la acción.",
  wlan_link_site_mismatch: "Solo se puede vincular con un activo o equipo del mismo site que el AP.",
  wlan_link_evidence_insufficient:
    "No hay evidencia suficiente para el vínculo: la IP de gestión o la MAC Ethernet del AP deben coincidir con el destino.",
  wlan_access_point_not_found: "El AP ya no existe.",
  wlan_bss_not_found: "El BSS ya no existe.",
  invalid_mac: "La MAC indicada no es válida.",
};

export function wlanErrorText(error: Error): string {
  if (error instanceof ApiError && WLAN_ERRORS[error.code]) return WLAN_ERRORS[error.code] as string;
  return errorMessage(error);
}

export function isVersionConflict(error: unknown): boolean {
  return error instanceof ApiError && error.code === "wlan_version_conflict";
}
