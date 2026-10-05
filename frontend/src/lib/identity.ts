// Presentación de la identificación de un activo (Fase 4E): nombre, tipo, confianza y
// evidencias en español. La API manda identificadores en inglés; aquí solo se traducen,
// nunca se deducen datos nuevos.
import type { Asset, ClassificationConfidence, ClassificationEvidence } from "../api/types";

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
};

export const NAME_SOURCE_LABELS: Record<string, string> = {
  agent_hostname: "reportado por el agente",
  reverse_dns: "DNS inverso",
  mdns: "mDNS",
  netbios: "NetBIOS",
  upnp: "UPnP",
  vendor_model: "fabricante y modelo",
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

/**
 * Título principal del activo: nunca vacío y nunca la IP (que se muestra aparte).
 * Nombre resuelto → hostname del agente → tipo ("Consola probable") → "Dispositivo desconocido".
 */
export function assetTitle(
  asset: Pick<Asset, "device_name" | "hostname" | "device_type" | "classification_confidence">,
): string {
  if (asset.device_name) return asset.device_name;
  if (asset.hostname) return asset.hostname;
  if (asset.device_type) return typeWithConfidence(asset);
  return UNKNOWN_DEVICE;
}

/** SO real (agente) o SO probable (red, sin versión). Null si no se sabe. */
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
