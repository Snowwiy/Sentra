// Presentación del historial de topología (Fase 6E.1): tipos de cambio, estados de revisión y
// calidad de los snapshots, en español.
import type { NetworkChangeStatus, NetworkChangeType, TopologySnapshotQuality } from "../api/types";

export const CHANGE_TYPE_LABELS: Record<NetworkChangeType, string> = {
  device_appeared: "Equipo nuevo",
  device_not_observed: "Equipo no observado",
  device_disappeared: "Equipo desaparecido",
  device_retired: "Equipo retirado",
  ip_changed: "Cambio de IP",
  mac_changed: "Cambio de MAC",
  name_changed: "Cambio de nombre",
  vendor_changed: "Cambio de fabricante",
  gateway_changed: "Cambio de gateway",
  role_changed: "Cambio de rol",
  classification_changed: "Cambio de clasificación",
  connectivity_changed: "Cambio de conectividad",
  link_added: "Enlace nuevo",
  link_not_observed: "Enlace no observado",
  link_removed: "Enlace eliminado",
  link_port_changed: "Cambio de puerto",
  link_vlan_changed: "Cambio de VLAN",
  link_kind_changed: "Cambio de clase de enlace",
  link_confidence_changed: "Cambio de confianza del enlace",
  wifi_association_changed: "Cambio de asociación Wi-Fi",
  wifi_ap_changed: "Cambio de punto de acceso",
};

export const CHANGE_STATUS_LABELS: Record<NetworkChangeStatus, string> = {
  detected: "Detectado",
  confirmed: "Confirmado",
  dismissed: "Descartado",
};

export const SNAPSHOT_QUALITY_LABELS: Record<TopologySnapshotQuality, string> = {
  complete: "Completo",
  partial: "Parcial",
  degraded: "Degradado",
};

/** Valor libre (antes/después, evidencia) como texto: nunca se interpreta como HTML. */
export function plainValue(value: unknown): string {
  if (value === null || value === undefined) return "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
