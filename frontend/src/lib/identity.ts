// Presentación de la identificación de un activo (Fase 4E): nombre, tipo, confianza y
// evidencias en español. La API manda identificadores en inglés; aquí solo se traducen,
// nunca se deducen datos nuevos.
import type {
  Asset,
  AssetNameStatus,
  ClassificationConfidence,
  ClassificationEvidence,
  ObservedName,
  ObservedNameKind,
} from "../api/types";

export const DEVICE_TYPE_LABELS: Record<string, string> = {
  pc: "PC",
  laptop: "Portátil",
  server: "Servidor",
  mobile: "Móvil",
  tablet: "Tablet",
  console: "Consola",
  printer: "Impresora",
  router: "Router",
  network_switch: "Switch de red",
  access_point: "Punto de acceso",
  iot: "IoT",
  voice_assistant: "IoT / Asistente",
  smart_tv: "Smart TV",
  nas: "NAS",
  virtual_machine: "Máquina virtual",
};

export const UNKNOWN_DEVICE = "Dispositivo desconocido";

export const CONFIDENCE_LABELS: Record<ClassificationConfidence, string> = {
  low: "Baja",
  medium: "Media",
  high: "Alta",
};

export const EVIDENCE_LABELS: Record<string, string> = {
  agent_hostname: "Hostname del agente",
  agent_os: "SO del agente",
  reverse_dns: "DNS inverso",
  mdns: "mDNS",
  netbios: "NetBIOS",
  upnp: "UPnP",
  ssdp: "SSDP",
  mac_vendor: "Fabricante MAC",
  mac_random: "MAC aleatoria",
  ports: "Puertos",
  gateway: "Gateway",
  conflict: "Evidencia contradictoria",
  // Fase 6E.2: hostname de una concesión DHCP con coincidencia alta (MAC e IP).
  dhcp_lease: "Concesión DHCP",
};

/** Corrección 6C: clase de cada nombre observado, tal y como la decide el servidor. */
export const NAME_KIND_LABELS: Record<ObservedNameKind, string> = {
  agent: "Hostname del agente",
  device: "Nombre publicado por el dispositivo",
  dhcp: "Nombre del router o DHCP (inferido)",
  dns: "Nombre DNS",
  generic: "Nombre genérico del sistema (no identifica al equipo)",
};

export const NAME_SOURCE_LABELS: Record<string, string> = {
  agent_hostname: "reportado por el agente",
  reverse_dns: "DNS inverso",
  mdns: "mDNS",
  netbios: "NetBIOS",
  upnp: "UPnP",
  vendor_model: "fabricante y modelo",
  dhcp_lease: "Concesión DHCP",
};

/** Tipo en español; "Desconocido" si no se pudo determinar. */
export function deviceTypeLabel(type: string | null | undefined): string {
  if (!type) return "Desconocido";
  return DEVICE_TYPE_LABELS[type] ?? type;
}

/**
 * ¿Se presenta como hipótesis? Todo lo que no es confianza alta lleva "probable": una
 * pista media sigue siendo una deducción, no un hecho comprobado.
 */
export function isProbable(asset: Pick<Asset, "device_type" | "classification_confidence">): boolean {
  return asset.device_type !== null && asset.classification_confidence !== "high";
}

/** "Consola" o "Consola probable" según la confianza; "Desconocido" sin tipo. */
export function typeWithConfidence(asset: Pick<Asset, "device_type" | "classification_confidence">): string {
  const label = deviceTypeLabel(asset.device_type);
  return isProbable(asset) ? `${label} probable` : label;
}

type TitleFields = Pick<Asset, "device_name" | "hostname" | "device_type" | "classification_confidence">;

/**
 * Título principal del activo: nunca vacío y nunca la IP (que se muestra aparte).
 * Etiqueta personalizada → nombre automático (ver automaticTitle).
 *
 * Corrección 6C: la etiqueta la pone una persona y gana siempre en la presentación, pero no
 * sustituye a la evidencia: el nombre automático se sigue mostrando aparte.
 */
export function assetTitle(asset: TitleFields & { custom_label?: string | null }): string {
  return asset.custom_label || automaticTitle(asset);
}

/**
 * Nombre automático: nombre resuelto → hostname del agente → tipo ("Consola probable") →
 * "Dispositivo desconocido".
 */
export function automaticTitle(asset: TitleFields): string {
  if (asset.device_name) return asset.device_name;
  if (asset.hostname) return asset.hostname;
  if (asset.device_type) return typeWithConfidence(asset);
  return UNKNOWN_DEVICE;
}

/** SO real (agente) o SO probable (red, sin versión). Null si no se sabe. */
/**
 * Fase 6D.3: explicación de por qué un activo no tiene nombre útil. Solo para generic_only y
 * unnamed; con nombre o etiqueta no hay nada que explicar.
 */
export const NAME_STATUS_HELP: Partial<Record<AssetNameStatus, string>> = {
  generic_only: "Solo anuncia un nombre genérico del sistema (p. ej. linux.local), que no identifica al equipo.",
  unnamed:
    "Ninguna fuente lo ha nombrado: el perfil quick no consulta DNS ni sondas de nombre, mDNS solo funciona en el mismo segmento, NetBIOS solo responde en equipos Windows/SMB y muchos routers (p. ej. TP-Link Archer) no publican los nombres DHCP por DNS. Puedes ponerle una etiqueta manual.",
};

export function nameStatusHelp(status: AssetNameStatus | null | undefined): string | null {
  return (status && NAME_STATUS_HELP[status]) || null;
}

export function osLabel(asset: Pick<Asset, "os_name" | "os_version" | "probable_os">): string | null {
  if (asset.os_name) return [asset.os_name, asset.os_version].filter(Boolean).join(" ");
  if (asset.probable_os) return `${asset.probable_os} probable`;
  return null;
}

export function evidenceLabel(evidence: ClassificationEvidence): string {
  return `${EVIDENCE_LABELS[evidence.source] ?? evidence.source}: ${evidence.value}`;
}

export function confidenceLabel(confidence: ClassificationConfidence | null): string | null {
  return confidence ? CONFIDENCE_LABELS[confidence] : null;
}

/** Texto de procedencia de un nombre observado: fuente, clase y avisos de confianza. */
export function observedNameNote(name: ObservedName): string {
  const parts = [EVIDENCE_LABELS[name.source] ?? name.source, NAME_KIND_LABELS[name.kind]];
  if (name.confirmed === true) parts.push("resuelve a esta IP");
  if (name.confirmed === false) parts.push("no confirmado: no resuelve a esta IP");
  if (name.stale) parts.push("sin observaciones recientes");
  return parts.join(" · ");
}

// Corrección 6C: misma normalización que el servidor (app/schemas/asset.py normalize_label)
// para avisar antes de enviar. El servidor valida igualmente: esto solo ahorra un viaje.
export const LABEL_MAX = 64;
const LABEL_FORBIDDEN = /[\p{Cc}\p{Cf}\p{Co}\p{Cs}\p{Zl}\p{Zp}]/u;

/** Etiqueta normalizada o el motivo por el que no es válida. */
export function normalizeLabel(value: string): { label: string } | { error: string } {
  const text = value.normalize("NFC");
  if (LABEL_FORBIDDEN.test(text)) {
    return { error: "La etiqueta no puede contener saltos de línea ni caracteres invisibles o de control." };
  }
  const label = text.split(/\s+/u).filter(Boolean).join(" ");
  if (!label) return { error: "Escribe una etiqueta o usa «Quitar etiqueta»." };
  if ([...label].length > LABEL_MAX) return { error: `Máximo ${LABEL_MAX} caracteres.` };
  return { label };
}
