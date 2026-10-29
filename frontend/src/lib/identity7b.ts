// Fase 7B.2: textos de la identidad de dispositivos (estado, niveles, evidencias de
// coincidencia y motivos de bloqueo de una asociación manual). Los códigos llegan del servidor
// en inglés; aquí solo se traducen. Un código desconocido se muestra tal cual, nunca se oculta.
import type { CandidateEvidence, IdentityComparison, IdentityState, IdentityStrength, MacProfile } from "../api/types";

export const IDENTITY_STATE_LABELS: Record<IdentityState, string> = {
  confirmed: "Confirmada",
  probable: "Probable",
  identity_unresolved: "Sin resolver",
};

export const IDENTITY_STATE_HELP: Record<IdentityState, string> = {
  confirmed: "Identidad confirmada por un agente instalado en el equipo.",
  probable: "Identidad deducida de la red (MAC universal, nombres o huellas). Puede cambiar.",
  identity_unresolved:
    "Sin identificador estable: MAC privada o aleatoria, o ninguna MAC. Revisa las coincidencias antes de asociarlo.",
};

export const IDENTITY_STATE_CLASS: Record<IdentityState, string> = {
  confirmed: "badge--ok",
  probable: "badge--info",
  identity_unresolved: "badge--warn",
};

const REASON_LABELS: Record<string, string> = {
  agent_identity: "agente instalado",
  random_mac: "MAC privada o aleatoria",
  no_stable_identifier: "sin identificador estable",
  universal_mac: "MAC universal",
  virtual_mac: "MAC de máquina virtual",
  stale_sources_only: "solo fuentes antiguas",
  manual_link: "asociado a mano",
  // Niveles (nombre, fabricante, tipo, SO).
  agent_reported: "lo informa el agente",
  stale_source: "fuente antigua",
  generic_name: "nombre genérico",
  corroborated: "corroborado por otra fuente",
  no_name_source: "ninguna fuente lo nombra",
  device_announced: "lo anuncia el propio equipo",
  network_adapter_only: "solo el fabricante de la tarjeta de red",
  no_vendor_evidence: "sin evidencia de fabricante",
  manual_type: "fijado a mano",
  no_type_evidence: "sin evidencia de tipo",
  network_fingerprint: "huella de red",
  no_os_evidence: "sin evidencia de sistema operativo",
  confidence_high: "confianza alta",
  confidence_medium: "confianza media",
  confidence_low: "confianza baja",
  confidence_none: "sin confianza",
  // Fase 7B-Fix1.
  no_model_evidence: "ningún anuncio declara el modelo",
  model_code_confirmed: "código de modelo respaldado por el fabricante",
  admin_label: "lo asignó un administrador",
  no_admin_label: "sin nombre asignado",
};

export function reasonLabel(code: string): string {
  if (REASON_LABELS[code]) return REASON_LABELS[code];
  // Nombre probable: "<fuente>_name" (mdns_name, dhcp_lease_name...).
  if (code.endsWith("_name")) return `nombre por ${sourceLabel(code.slice(0, -5))}`;
  return code;
}

// Fase 7B-Fix1: confirmado (agente o admin), inferido (deducido de la red, con su fuente) o
// desconocido. El servidor sigue enviando confirmed/probable/unresolved.
export const TIER_STATE_LABELS: Record<string, string> = {
  confirmed: "Confirmado",
  probable: "Inferido",
  unresolved: "Desconocido",
};

export const GAP_FIELD_LABELS: Record<string, string> = {
  name: "Nombre",
  vendor: "Fabricante",
  model: "Modelo",
  device_type: "Tipo",
  os: "Sistema operativo",
  stable_identity: "Identidad estable",
};

export const FRESHNESS_LABELS: Record<string, string> = {
  fresh: "reciente",
  stale: "antiguo",
  unknown: "sin fecha",
};

export const STRENGTH_LABELS: Record<IdentityStrength, string> = {
  strong: "Fuerte",
  medium: "Media",
  weak: "Débil",
};

export const STRENGTH_CLASS: Record<IdentityStrength, string> = {
  strong: "badge--ok",
  medium: "badge--info",
  weak: "badge--muted",
};

const EVIDENCE_LABELS: Record<string, string> = {
  same_machine_id: "Mismo identificador de máquina",
  same_agent_lineage: "Mismo linaje de agente",
  manual_link: "Asociación manual",
  agent_reported_mac: "El agente informa esta MAC",
  same_universal_mac: "Misma MAC universal",
  mac_in_history: "MAC vista antes en el otro registro",
  same_device_name: "Mismo nombre",
  same_ip: "Misma IP",
  same_vendor: "Mismo fabricante",
  same_os: "Mismo sistema operativo",
};

export function evidenceText(evidence: CandidateEvidence): string {
  const label = EVIDENCE_LABELS[evidence.code] ?? evidence.code;
  return evidence.detail ? `${label}: ${evidence.detail}` : label;
}

const BLOCKER_LABELS: Record<string, string> = {
  same_asset: "Es el mismo registro.",
  different_site: "Los registros pertenecen a sites distintos.",
  target_archived: "El equipo de destino está archivado.",
  alias_has_agent: "El registro a asociar tiene agente: usa la reconciliación de ciclo de vida.",
  alias_already_linked: "El registro ya está asociado a otro equipo.",
  client_already_linked: "El cliente Wi-Fi ya está asociado.",
  client_confirmed_by_agent: "El cliente Wi-Fi ya está confirmado por un agente.",
};

export function blockerText(code: string): string {
  return BLOCKER_LABELS[code] ?? code;
}

export const CLASSIFICATION_LABELS: Record<IdentityComparison["classification"], string> = {
  same_agent_reinstalled: "Mismo equipo con el agente reinstalado",
  historical_asset: "Registro histórico del mismo equipo",
  ip_reuse: "Reutilización de IP (equipos distintos)",
  reconcilable_identity: "Probablemente el mismo dispositivo",
  distinct_records: "Registros distintos",
};

const SOURCE_LABELS: Record<string, string> = {
  agent: "agente",
  agent_hostname: "agente",
  agent_os: "agente",
  manual: "manual",
  custom_label: "etiqueta",
  dhcp_lease: "DHCP",
  mdns: "mDNS",
  mdns_service: "servicios mDNS",
  netbios: "NetBIOS",
  reverse_dns: "DNS inverso",
  upnp: "UPnP",
  ssdp: "SSDP",
  web: "web",
  mac_vendor: "OUI de la MAC",
  classification: "clasificación",
  inference: "inferencia de red",
  discovery: "descubrimiento",
  wlan_manual: "Wi-Fi (manual)",
  wlan_observation: "Wi-Fi",
};

export function sourceLabel(source: string | null): string {
  if (!source) return "—";
  if (SOURCE_LABELS[source]) return SOURCE_LABELS[source];
  return source.startsWith("wlan_") ? `Wi-Fi (${source.slice(5)})` : source;
}

/** Explicación corta del tipo de MAC (IEEE 802c para las administradas localmente). */
export function macNote(mac: MacProfile): string | null {
  if (mac.kind === "none") return "Sin MAC conocida";
  if (mac.kind === "multicast") return "MAC multicast (no identifica a un equipo)";
  if (mac.kind === "virtual") return "MAC de máquina virtual";
  if (mac.randomized) {
    return mac.slap_quadrant === "aai" || mac.slap_quadrant === null
      ? "MAC privada (aleatoria): no identifica al equipo de forma estable"
      : `MAC administrada localmente (802c ${mac.slap_quadrant.toUpperCase()})`;
  }
  return null;
}

const EFFECT_LABELS: Record<string, string> = {
  map_mac_to_target: "Los próximos descubrimientos con esta MAC actualizarán el equipo de destino, no el alias.",
  archive_alias: "El registro alias se archiva (con todo su historial); revocar la asociación lo restaura.",
  alias_already_archived: "El registro alias ya estaba archivado: se queda así.",
  keep_alias_history: "No se borra ni se fusiona nada: eventos, detecciones e historial siguen en cada registro.",
  client_identity_manual: "El cliente Wi-Fi queda asociado al equipo con identidad confirmada a mano.",
  replaces_previous_correlation: "Sustituye la correlación automática anterior del cliente Wi-Fi.",
};

export function effectText(code: string): string {
  return EFFECT_LABELS[code] ?? code;
}
