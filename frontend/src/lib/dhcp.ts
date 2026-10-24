// Presentación de DHCP e identidad avanzada (Fase 6E.2). La API manda códigos en inglés; aquí
// solo se traducen. Nunca se deduce un nombre: si el servidor no lo eligió, se explica por qué.
import type {
  DhcpFormat,
  DhcpLeaseMatch,
  DhcpLeaseState,
  DhcpSourceKind,
  DhcpSourceStatus,
  IdentityField,
  UnidentifiedReason,
} from "../api/types";

export const UNIDENTIFIED_REASON_LABELS: Record<UnidentifiedReason, string> = {
  no_name_sources: "Ninguna fuente (agente, DNS, mDNS, NetBIOS, UPnP o DHCP) ha publicado un nombre para este equipo.",
  randomized_mac:
    "Usa una MAC aleatoria (privada): no se puede asociar de forma fiable a concesiones DHCP ni al fabricante.",
  only_generic_names: "Solo se han visto nombres genéricos del sistema (localhost, android, iphone…), que no lo identifican.",
  dhcp_source_missing: "No hay ninguna fuente DHCP configurada en este site.",
  dhcp_no_lease: "Hay fuente DHCP, pero ninguna concesión coincide con su MAC e IP.",
  dhcp_lease_unusable_name: "Su concesión DHCP no trae un nombre utilizable (vacío, genérico o repetido por varios equipos).",
  names_stale: "Los nombres observados son antiguos: ninguna fuente los repite desde hace tiempo.",
  only_vendor: "Solo se conoce el fabricante, que describe el equipo pero no lo identifica.",
};

export const LEASE_MATCH_LABELS: Record<DhcpLeaseMatch, string> = {
  mac_ip: "MAC e IP coinciden",
  mac_moved: "MAC coincide (IP cambiada)",
  ip_only: "Solo IP (no se asocia)",
  randomized_mac: "MAC aleatoria (no se asocia)",
  ambiguous: "Ambigua",
  no_asset: "Sin activo",
  expired: "Caducada",
};

export const LEASE_STATE_LABELS: Record<DhcpLeaseState, string> = {
  active: "Activa",
  expired: "Caducada",
  released: "Liberada",
  unknown: "Desconocido",
};

export const DHCP_FORMAT_LABELS: Record<DhcpFormat, string> = {
  dnsmasq: "dnsmasq",
  isc_dhcpd: "ISC dhcpd (dhcpd.leases)",
  kea_csv: "Kea (CSV)",
  windows_dhcp_csv: "Windows DHCP (CSV)",
  generic_csv: "CSV genérico",
};

export const DHCP_KIND_LABELS: Record<DhcpSourceKind, string> = {
  lease_import: "Importación manual",
  sensor_file: "Fichero de un sensor",
};

export const DHCP_STATUS_LABELS: Record<DhcpSourceStatus, string> = {
  pending: "Pendiente",
  ok: "Correcta",
  error: "Error",
  disabled: "Deshabilitada",
};

export const DHCP_STATUS_BADGES: Record<DhcpSourceStatus, string> = {
  pending: "badge badge--info",
  ok: "badge badge--ok",
  error: "badge badge--crit",
  disabled: "badge badge--muted",
};

export const IDENTITY_FIELD_LABELS: Record<IdentityField, string> = {
  name: "Nombre",
  label: "Etiqueta",
  ip: "IP",
  mac: "MAC",
  vendor: "Fabricante",
  device_type: "Tipo",
};

/** Mismo patrón que el servidor (DhcpSourceCreate.name). */
export const DHCP_SOURCE_NAME = /^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$/;
/** Mismo patrón que [[dhcp_lease_files]].name del sensor 0.6.0. */
export const SENSOR_SOURCE_NAME = /^[a-z0-9_-]{1,64}$/;
/** Tope de DhcpImportIn.content (3 MiB de texto). */
export const DHCP_IMPORT_MAX_CHARS = 3_145_728;
