// Etiquetas y utilidades de la infraestructura de red SNMP / LLDP / CDP (Fase 6B).
//
// Regla de presentación: la UI nunca convierte la evidencia en una afirmación más fuerte. Un
// equipo no está "online" (se muestra su estado de monitorización y la frescura de la última
// consulta correcta), un vecino LLDP/CDP está "informado por el equipo" y una entrada de la
// tabla MAC es evidencia de reenvío, no de cableado.

import { ApiError } from "../api/client";
import type {
  AdminStatus,
  DeviceClassification,
  DeviceClassificationConfidence,
  EvidenceFreshness,
  LocalPortMatch,
  MacLocation,
  MacStatus,
  ModuleStatus,
  MonitoringStatus,
  NeighborProtocol,
  NetworkDevice,
  NetworkDeviceUpdate,
  OperStatus,
  PollStatus,
  PortKind,
  RemoteMatchBasis,
  SnmpAuthProtocol,
  SnmpErrorCode,
  SnmpPrivProtocol,
  SnmpProfileCreate,
  SnmpProfileRotate,
  SnmpVersion,
  VlanSource,
} from "../api/types";

export const CLASSIFICATIONS: DeviceClassification[] = [
  "managed_switch",
  "router",
  "access_point",
  "firewall",
  "unclassified",
];

export const CLASSIFICATION_LABELS: Record<DeviceClassification, string> = {
  managed_switch: "Switch gestionable",
  router: "Router",
  access_point: "Punto de acceso",
  firewall: "Firewall",
  unclassified: "Sin clasificar",
};

export const CONFIDENCE_LABELS: Record<DeviceClassificationConfidence, string> = {
  high: "confianza alta",
  medium: "confianza media",
  low: "confianza baja",
  none: "sin evidencia",
};

export const MONITORING_STATUSES: MonitoringStatus[] = [
  "ok",
  "partial",
  "failing",
  "polling",
  "never_polled",
  "credentials_pending",
  "sensor_pending",
  "disabled",
  "archived",
];

export const MONITORING_STATUS_LABELS: Record<MonitoringStatus, string> = {
  ok: "Consulta correcta",
  partial: "Consulta parcial",
  failing: "Consultas fallidas",
  polling: "Consultando",
  never_polled: "Nunca consultado",
  credentials_pending: "Falta perfil SNMP",
  sensor_pending: "Falta sensor",
  disabled: "Monitorización desactivada",
  archived: "Archivado",
};

// Ninguna ayuda dice "online": la última consulta solo prueba que el equipo respondió entonces.
export const MONITORING_STATUS_HELP: Record<MonitoringStatus, string> = {
  ok: "La última consulta SNMP terminó correctamente. No garantiza que el equipo siga respondiendo ahora.",
  partial: "La última consulta solo obtuvo parte de los módulos (MIB no soportadas o errores parciales).",
  failing: "Las últimas consultas han fallado. Revisa el último error.",
  polling: "Hay una consulta en cola o en curso.",
  never_polled: "Todavía no se ha consultado este equipo.",
  credentials_pending: "Asigna un perfil SNMP activo para poder consultarlo.",
  sensor_pending: "Asigna un sensor del mismo site para poder consultarlo.",
  disabled: "La consulta periódica está desactivada; se puede consultar manualmente si hay perfil y sensor.",
  archived: "Equipo archivado: se conserva su historial, pero no se consulta.",
};

const MONITORING_STATUS_CLASS: Record<MonitoringStatus, string> = {
  ok: "status--online",
  partial: "status--stale",
  failing: "status--offline",
  polling: "status--pending",
  never_polled: "status--unknown",
  credentials_pending: "status--pending",
  sensor_pending: "status--pending",
  disabled: "status--disabled",
  archived: "status--archived",
};

export function monitoringStatusClass(status: MonitoringStatus): string {
  return MONITORING_STATUS_CLASS[status] ?? "status--unknown";
}

export const FRESHNESS_LABELS: Record<EvidenceFreshness, string> = {
  recent: "Evidencia reciente",
  historical: "Evidencia histórica",
  none: "Sin evidencia",
};

export const FRESHNESS_HELP: Record<EvidenceFreshness, string> = {
  recent: "La última consulta correcta es reciente.",
  historical:
    "Solo hay datos de consultas antiguas: el inventario puede haber cambiado y no indica que el equipo esté disponible.",
  none: "El equipo nunca se ha consultado correctamente.",
};

export const POLL_STATUS_LABELS: Record<PollStatus, string> = {
  queued: "En cola",
  running: "En curso",
  succeeded: "Correcta",
  partial: "Parcial",
  failed: "Fallida",
  cancelled: "Cancelada",
  expired: "Caducada",
};

/** Una consulta abierta todavía se puede cancelar. */
export function isOpenPoll(status: PollStatus): boolean {
  return status === "queued" || status === "running";
}

export const MODULE_LABELS: Record<string, string> = {
  system: "Sistema",
  entity: "ENTITY-MIB",
  interfaces: "Interfaces",
  lldp: "LLDP",
  cdp: "CDP",
  bridge: "Bridge / MAC",
  vlan: "VLAN",
};

export const MODULE_STATUS_LABELS: Record<ModuleStatus, string> = {
  complete: "completo",
  partial: "parcial",
  unsupported: "no soportado",
  failed: "fallido",
  skipped: "omitido",
};

/** "Interfaces: completo · LLDP: no soportado" (orden estable por módulo). */
export function describeModules(modules: Record<string, ModuleStatus>): string {
  const order = Object.keys(MODULE_LABELS);
  return Object.entries(modules)
    .sort(([a], [b]) => {
      const ia = order.indexOf(a);
      const ib = order.indexOf(b);
      return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib) || a.localeCompare(b);
    })
    .map(([name, status]) => `${MODULE_LABELS[name] ?? name}: ${MODULE_STATUS_LABELS[status] ?? status}`)
    .join(" · ");
}

// Taxonomía de errores SNMP: cada código tiene su texto para que el operador sepa qué revisar.
export const SNMP_ERROR_LABELS: Record<SnmpErrorCode, string> = {
  timeout: "Sin respuesta SNMP a tiempo: revisa que el equipo tenga SNMP habilitado y que el puerto UDP no esté filtrado.",
  host_unreachable: "El sensor no alcanza la dirección de gestión (sin ruta o equipo apagado).",
  auth_failed: "El equipo rechazó las credenciales: usuario, protocolos, passwords o comunidad no coinciden.",
  unsupported_version: "El equipo no admite la versión SNMP del perfil.",
  oid_unavailable: "El equipo no expone alguno de los OID consultados.",
  no_lldp: "El equipo no expone la LLDP-MIB (LLDP deshabilitado o no soportado).",
  no_cdp: "El equipo no expone la CDP-MIB (CDP deshabilitado o no soportado).",
  partial: "La consulta solo obtuvo parte de los datos.",
  sensor_offline: "El sensor asignado no está conectado: la consulta no pudo empezar.",
  sensor_lost: "Se perdió el contacto con el sensor durante la consulta.",
  credentials_unavailable: "El servidor no pudo entregar las credenciales al sensor (perfil revocado o almacén de secretos no disponible).",
  job_expired: "La consulta caducó antes de que el sensor la ejecutara.",
  job_rejected: "El sensor rechazó la consulta (capacidad SNMP ausente o destino fuera de su alcance).",
  cancelled: "La consulta se canceló.",
  limit_exceeded: "La respuesta superó los límites de tamaño o tiempo configurados.",
  malformed_response: "El equipo devolvió una respuesta SNMP mal formada.",
  internal: "Error interno al procesar la consulta.",
};

export function snmpErrorText(code: string | null | undefined): string {
  if (!code) return "";
  return SNMP_ERROR_LABELS[code as SnmpErrorCode] ?? `Error de consulta (${code}).`;
}

// El contrato de la API no fija aún la lista de bloqueos de consulta: se traducen los
// conocidos y el resto se muestra con su código, sin inventar el motivo.
const POLL_BLOCKER_LABELS: Record<string, string> = {
  device_archived: "El equipo está archivado.",
  site_not_active: "El site del equipo no está activo.",
  profile_missing: "No tiene perfil SNMP asignado.",
  profile_revoked: "Su perfil SNMP está revocado.",
  profile_other_site: "El perfil SNMP pertenece a otro site.",
  v2c_disabled: "El perfil es SNMPv2c y la política del servidor no permite v2c.",
  secret_store_unavailable: "El servidor no tiene configurado el almacén cifrado de secretos.",
  sensor_missing: "No tiene sensor asignado.",
  sensor_other_site: "El sensor asignado pertenece a otro site.",
  sensor_revoked: "El sensor asignado está revocado.",
  sensor_disabled: "El sensor asignado está deshabilitado.",
  sensor_offline: "El sensor asignado no está conectado.",
  sensor_version_unsupported: "La versión del sensor no está soportada; actualízalo a 0.3.0 o superior.",
  sensor_without_snmp: "El sensor asignado no declara la capacidad SNMP (falta el extra snmp).",
  sensor_without_snmp_version: "El sensor asignado no soporta la versión SNMP del perfil.",
  address_out_of_scope: "La dirección de gestión está fuera de las redes habilitadas del site.",
  poll_in_progress: "Ya hay una consulta encolada o en curso para este equipo.",
};

export function describePollBlocker(code: string): string {
  return POLL_BLOCKER_LABELS[code] ?? `Bloqueo: ${code}.`;
}

/** Bloqueos de un 409 network_poll_unavailable (details: [{blockers: [...]}]). */
export function pollBlockersFromError(error: unknown): string[] {
  if (!(error instanceof ApiError) || error.code !== "network_poll_unavailable") return [];
  if (!Array.isArray(error.details)) return [];
  const blockers: string[] = [];
  for (const entry of error.details) {
    if (entry && typeof entry === "object" && Array.isArray((entry as { blockers?: unknown }).blockers)) {
      for (const b of (entry as { blockers: unknown[] }).blockers) if (typeof b === "string") blockers.push(b);
    }
  }
  return blockers;
}

/** true en los 409 de versión obsoleta: la UI recarga antes de dejar reintentar. */
export function isVersionConflict(error: unknown): boolean {
  return error instanceof ApiError && (error.code === "network_device_conflict" || error.code === "snmp_profile_conflict");
}

export const PORT_KINDS: PortKind[] = ["physical", "lag", "logical", "vlan", "loopback", "tunnel", "wireless", "other"];

export const PORT_KIND_LABELS: Record<PortKind, string> = {
  physical: "Físico",
  lag: "LAG",
  logical: "Lógico",
  vlan: "VLAN (SVI)",
  loopback: "Loopback",
  tunnel: "Túnel",
  wireless: "Inalámbrico",
  other: "Otro",
};

export const ADMIN_STATUS_LABELS: Record<AdminStatus, string> = {
  up: "habilitado",
  down: "deshabilitado",
  testing: "en pruebas",
  unknown: "desconocido",
};

export const OPER_STATUSES: OperStatus[] = ["up", "down", "dormant", "lower_layer_down", "not_present", "testing", "unknown"];

export const OPER_STATUS_LABELS: Record<OperStatus, string> = {
  up: "up",
  down: "down",
  testing: "en pruebas",
  unknown: "desconocido",
  dormant: "dormant",
  not_present: "no presente",
  lower_layer_down: "capa inferior caída",
};

export const NEIGHBOR_PROTOCOL_LABELS: Record<NeighborProtocol, string> = { lldp: "LLDP", cdp: "CDP" };

export const MATCH_BASIS_LABELS: Record<RemoteMatchBasis, string> = {
  chassis_mac: "por MAC de chasis",
  mgmt_address: "por dirección de gestión",
  sys_name: "por sysName",
};

export const LOCAL_PORT_MATCH_LABELS: Record<LocalPortMatch, string> = {
  if_index: "cruce por ifIndex",
  if_name: "cruce por ifName",
  if_descr: "cruce por ifDescr",
  unmatched: "puerto local sin cruzar",
};

export const MAC_LOCATION_LABELS: Record<MacLocation, string> = {
  edge_candidate: "Posible puerto de acceso",
  uplink_or_shared: "Uplink o puerto compartido",
  unknown: "Sin valorar",
};

export const MAC_STATUS_LABELS: Record<MacStatus, string> = {
  learned: "aprendida",
  mgmt: "gestión",
  self: "propia",
  other: "otra",
  invalid: "no válida",
};

export const VLAN_SOURCE_LABELS: Record<VlanSource, string> = {
  fdb_vlan_map: "VLAN según Q-BRIDGE",
  fdb_id_assumed: "VLAN supuesta (FDB id)",
  none: "sin VLAN",
};

export const VLAN_TABLE_SOURCE_LABELS: Record<string, string> = {
  q_bridge_static: "Q-BRIDGE (estática)",
  q_bridge_current: "Q-BRIDGE (actual)",
};

export const VENDOR_SOURCE_LABELS: Record<string, string> = {
  sys_object_id: "según sysObjectID (número de empresa IANA)",
  entity_mib: "según ENTITY-MIB",
};

const EVIDENCE_SOURCE_LABELS: Record<string, string> = {
  lldp_capabilities: "Capacidades LLDP",
  sys_services: "sysServices",
  bridge_mib: "BRIDGE-MIB",
  ip_forwarding: "ipForwarding",
  sys_object_id: "sysObjectID",
  if_type: "Tipos de interfaz",
  snmp: "SNMP",
  if_mib: "IF-MIB",
  lldp_mib: "LLDP-MIB",
  cdp_mib: "CDP-MIB",
  q_bridge_mib: "Q-BRIDGE-MIB",
  // Procedencia de cada fila de inventario: MIB de la que salió (backend app/network/catalog.py).
  "snmp:SNMPv2-MIB": "SNMPv2-MIB (SNMP)",
  "snmp:ENTITY-MIB": "ENTITY-MIB (SNMP)",
  "snmp:IF-MIB": "IF-MIB (SNMP)",
  "snmp:LLDP-MIB": "LLDP-MIB (SNMP)",
  "snmp:CISCO-CDP-MIB": "CISCO-CDP-MIB (SNMP)",
  "snmp:BRIDGE-MIB/Q-BRIDGE-MIB": "BRIDGE-MIB / Q-BRIDGE-MIB (SNMP)",
  "snmp:Q-BRIDGE-MIB": "Q-BRIDGE-MIB (SNMP)",
};

/** Fuente legible de una evidencia; las desconocidas se muestran con su identificador. */
export function evidenceSourceLabel(source: string): string {
  return EVIDENCE_SOURCE_LABELS[source] ?? source;
}

export const AUTH_PROTOCOLS: SnmpAuthProtocol[] = ["sha", "sha224", "sha256", "sha384", "sha512"];
export const PRIV_PROTOCOLS: SnmpPrivProtocol[] = ["aes128", "aes192", "aes256"];

export const AUTH_PROTOCOL_LABELS: Record<SnmpAuthProtocol, string> = {
  sha: "SHA-1",
  sha224: "SHA-224",
  sha256: "SHA-256",
  sha384: "SHA-384",
  sha512: "SHA-512",
};

export const PRIV_PROTOCOL_LABELS: Record<SnmpPrivProtocol, string> = {
  aes128: "AES-128",
  aes192: "AES-192",
  aes256: "AES-256",
};

export const SNMP_VERSION_LABELS: Record<SnmpVersion, string> = {
  v3: "SNMPv3 authPriv",
  v2c: "SNMPv2c (heredado)",
};

/** 1000 → "1 Gb/s", 100 → "100 Mb/s". */
export function formatSpeed(mbps: number | null | undefined): string {
  if (mbps == null || mbps <= 0) return "—";
  if (mbps >= 1000) {
    const gbps = mbps / 1000;
    return `${Number.isInteger(gbps) ? gbps : gbps.toFixed(1)} Gb/s`;
  }
  return `${mbps} Mb/s`;
}

/** Contador con separador de miles; null → "—". */
export function formatCounter(value: number | null | undefined): string {
  return value == null ? "—" : value.toLocaleString("es-ES");
}

/** Lista compacta de VLANs: [1,2,3,5] → "1-3, 5". */
export function formatVlanList(vlans: readonly number[]): string {
  if (vlans.length === 0) return "";
  const sorted = [...new Set(vlans)].sort((a, b) => a - b);
  const parts: string[] = [];
  let start = sorted[0]!;
  let prev = start;
  for (const vlan of sorted.slice(1).concat(Number.NaN)) {
    if (vlan === prev + 1) {
      prev = vlan;
      continue;
    }
    parts.push(start === prev ? String(start) : `${start}-${prev}`);
    start = vlan;
    prev = vlan;
  }
  return parts.join(", ");
}

// --- formularios de perfil SNMP --------------------------------------------------------------

/** Estado del formulario de credenciales. Los secretos solo viven aquí hasta el envío. */
export interface SnmpSecretsForm {
  username: string;
  authProtocol: SnmpAuthProtocol;
  privProtocol: SnmpPrivProtocol;
  authPassword: string;
  privPassword: string;
  community: string;
}

export const EMPTY_SECRETS: SnmpSecretsForm = {
  username: "",
  authProtocol: "sha256",
  privProtocol: "aes128",
  authPassword: "",
  privPassword: "",
  community: "",
};

const DEFAULT_COMMUNITIES = new Set(["public", "private"]);

/**
 * Mismas reglas que el backend (RFC 3414: passphrases de 8 a 128 caracteres y distintas; sin
 * comunidades de fábrica). `partial` = rotación: un campo vacío se deja como está.
 */
export function validateSecrets(version: SnmpVersion, form: SnmpSecretsForm, partial = false): string | undefined {
  if (version === "v3") {
    if (!partial && !form.username.trim()) return "Indica el usuario SNMPv3.";
    for (const [value, label] of [
      [form.authPassword, "La password de autenticación"],
      [form.privPassword, "La password de cifrado"],
    ] as const) {
      if (!value && partial) continue;
      if (value.length < 8 || value.length > 128) return `${label} debe tener entre 8 y 128 caracteres.`;
    }
    if (partial && !form.authPassword && !form.privPassword) return "Indica al menos una password nueva.";
    if (form.authPassword && form.authPassword === form.privPassword) {
      return "Las passwords de autenticación y de cifrado deben ser distintas.";
    }
    return undefined;
  }
  if (!form.community) return "Indica la comunidad SNMPv2c.";
  if (form.community.length > 64) return "La comunidad puede tener como máximo 64 caracteres.";
  if (DEFAULT_COMMUNITIES.has(form.community.toLowerCase())) {
    return "No se aceptan las comunidades de fábrica (public, private).";
  }
  return undefined;
}

export function buildProfileCreate(
  siteId: string,
  name: string,
  description: string,
  version: SnmpVersion,
  form: SnmpSecretsForm,
): SnmpProfileCreate {
  const base = { site_id: siteId, name: name.trim(), description: description.trim() || null, snmp_version: version };
  if (version === "v3") {
    return {
      ...base,
      username: form.username.trim(),
      auth_protocol: form.authProtocol,
      priv_protocol: form.privProtocol,
      auth_password: form.authPassword,
      priv_password: form.privPassword,
    };
  }
  return { ...base, community: form.community };
}

/** Rotación: solo se envían los campos que el administrador ha cambiado o rellenado. */
export function buildProfileRotate(
  version: number,
  snmpVersion: SnmpVersion,
  form: SnmpSecretsForm,
  current: { username: string | null; auth_protocol: SnmpAuthProtocol | null; priv_protocol: SnmpPrivProtocol | null },
): SnmpProfileRotate {
  if (snmpVersion === "v2c") return { version, community: form.community };
  const body: SnmpProfileRotate = { version };
  if (form.username.trim() && form.username.trim() !== current.username) body.username = form.username.trim();
  if (form.authProtocol !== current.auth_protocol) body.auth_protocol = form.authProtocol;
  if (form.privProtocol !== current.priv_protocol) body.priv_protocol = form.privProtocol;
  if (form.authPassword) body.auth_password = form.authPassword;
  if (form.privPassword) body.priv_password = form.privPassword;
  return body;
}

// --- formulario de equipo ---------------------------------------------------------------------

export interface DeviceForm {
  name: string;
  port: string;
  profileId: string;
  sensorId: string;
  monitoring: boolean;
}

export function deviceFormFrom(device: NetworkDevice): DeviceForm {
  return {
    name: device.name ?? "",
    port: String(device.snmp_port),
    profileId: device.profile?.profile_id ?? "",
    sensorId: device.sensor?.sensor_id ?? "",
    monitoring: device.monitoring_enabled,
  };
}

export function validPort(port: string): boolean {
  const value = Number(port);
  return Number.isInteger(value) && value >= 1 && value <= 65535;
}

/**
 * PATCH con solo lo que cambió. Quitar perfil o sensor usa clear_profile/clear_sensor: un null
 * ausente no borra nada en el servidor. El nombre no se puede vaciar (el contrato no tiene
 * clear_name), así que un nombre vacío se deja como estaba.
 */
export function buildDeviceUpdate(device: NetworkDevice, form: DeviceForm): NetworkDeviceUpdate {
  const body: NetworkDeviceUpdate = { version: device.version };
  const name = form.name.trim();
  if (name && name !== (device.name ?? "")) body.name = name;
  const port = Number(form.port);
  if (port !== device.snmp_port) body.snmp_port = port;
  const profileId = device.profile?.profile_id ?? "";
  if (form.profileId !== profileId) {
    if (form.profileId) body.profile_id = form.profileId;
    else body.clear_profile = true;
  }
  const sensorId = device.sensor?.sensor_id ?? "";
  if (form.sensorId !== sensorId) {
    if (form.sensorId) body.sensor_id = form.sensorId;
    else body.clear_sensor = true;
  }
  if (form.monitoring !== device.monitoring_enabled) body.monitoring_enabled = form.monitoring;
  return body;
}
