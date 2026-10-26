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
  // Fase 7A.4: cámaras y grabadores salen de IoT porque su exposición es otra (vídeo,
  // credenciales por defecto); "equipo de red" cuando no se puede afirmar si es router o switch.
  ip_camera: "Cámara IP",
  dvr_nvr: "Grabador (DVR/NVR)",
  network_device: "Equipo de red",
};

/** Tipos que un admin puede fijar a mano (los mismos del servidor), ordenados por su nombre. */
export const DEVICE_TYPE_OPTIONS: { value: string; label: string }[] = Object.entries(DEVICE_TYPE_LABELS)
  .map(([value, label]) => ({ value, label }))
  .sort((a, b) => a.label.localeCompare(b.label, "es"));

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
  // Fase 7A.4: huellas de servicio que publica el propio equipo y el tipo fijado por un admin.
  mdns_service: "Servicios mDNS",
  web: "Huella web/TLS",
  manual: "Asignado manualmente",
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

/** Fase 7A.4: ¿el tipo lo fijó un admin? Entonces no es una deducción y no lleva confianza. */
export function isManualType(asset: Pick<Asset, "manual_device_type">): boolean {
  return Boolean(asset.manual_device_type);
}

/** Tipo en español; "Desconocido" si no se pudo determinar. */
export function deviceTypeLabel(type: string | null | undefined): string {
  if (!type) return "Desconocido";
  return DEVICE_TYPE_LABELS[type] ?? type;
}

type TypeFields = Pick<Asset, "device_type" | "classification_confidence"> & {
  manual_device_type?: string | null;
};

/**
 * ¿Se presenta como hipótesis? Todo lo que no es confianza alta lleva "probable": una
 * pista media sigue siendo una deducción, no un hecho comprobado.
 */
export function isProbable(asset: TypeFields): boolean {
  // Un tipo fijado a mano es un hecho declarado, no una hipótesis.
  if (asset.manual_device_type) return false;
  return asset.device_type !== null && asset.classification_confidence !== "high";
}

/** "Consola" o "Consola probable" según la confianza; "Desconocido" sin tipo. */
export function typeWithConfidence(asset: TypeFields): string {
  const label = deviceTypeLabel(asset.device_type);
  return isProbable(asset) ? `${label} probable` : label;
}

type TitleFields = Pick<Asset, "device_name" | "hostname"> & TypeFields;

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

// --- Fase 7A.4: huellas de servicio ----------------------------------------------------------

/** Fuentes de evidencia que son huellas de servicio (se muestran juntas, no como evidencias sueltas). */
export const FINGERPRINT_SOURCES: ReadonlySet<string> = new Set(["mdns_service", "web"]);

export type FingerprintKind = "services" | "model" | "web";

export interface Fingerprint {
  kind: FingerprintKind;
  /** Texto tal cual lo describe el servidor, sin la marca de antigüedad. */
  value: string;
  /** Ninguna observación reciente la repite: se conserva como evidencia, pero ya no decide. */
  stale: boolean;
}

export const FINGERPRINT_LABELS: Record<FingerprintKind, string> = {
  services: "Servicios mDNS",
  model: "Modelo (mDNS)",
  web: "Web/TLS",
};

// El servidor describe las huellas en texto (app/discovery/classify.py): «modelo X» para el
// modelo de _device-info y « (antiguo)» al final cuando la observación caducó. La API no expone
// las observaciones en bruto, así que se reconocen esos dos marcadores y el resto se muestra
// tal cual: si el texto cambia, solo se pierde la clasificación, nunca el dato.
const STALE_SUFFIX = " (antiguo)";
const MODEL_PREFIX = "modelo ";

/** Huellas mDNS y web/TLS de la evidencia de clasificación, en el orden en que llegan. */
export function fingerprints(evidence: ClassificationEvidence[]): Fingerprint[] {
  const found: Fingerprint[] = [];
  for (const item of evidence) {
    if (!FINGERPRINT_SOURCES.has(item.source)) continue;
    const stale = item.value.endsWith(STALE_SUFFIX);
    const value = stale ? item.value.slice(0, -STALE_SUFFIX.length) : item.value;
    if (!value) continue;
    if (item.source === "web") found.push({ kind: "web", value, stale });
    else if (value.startsWith(MODEL_PREFIX)) found.push({ kind: "model", value: value.slice(MODEL_PREFIX.length), stale });
    else found.push({ kind: "services", value, stale });
  }
  return found;
}
