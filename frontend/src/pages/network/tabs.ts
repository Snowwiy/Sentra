// Fase 7A.5: pestañas del hub Red. Una sola definición para la barra de pestañas y para las
// rutas (App), así una pestaña con permiso no puede quedar visible sin su RequirePermission.
import type { Permission } from "../../api/types";

export type NetworkTabKey =
  | "overview"
  | "devices"
  | "discovery"
  | "topology"
  | "services"
  | "changes"
  | "identity"
  | "telemetry";

export interface NetworkTab {
  key: NetworkTabKey;
  /** Segmento bajo /network ("" = la propia /network). */
  path: string;
  label: string;
  /**
   * Permiso que exigen los datos de la pestaña: sin él la pestaña no se muestra y su ruta
   * responde «Acceso restringido». La API vuelve a comprobarlo en cada petición.
   */
  permission?: Permission;
}

export const NETWORK_TABS: NetworkTab[] = [
  { key: "overview", path: "", label: "Resumen" },
  { key: "devices", path: "devices", label: "Dispositivos" },
  { key: "discovery", path: "discovery", label: "Descubrimiento" },
  // Topología, historial e identidad/DHCP exigían monitoring:read en sus páginas propias.
  { key: "topology", path: "topology", label: "Topología", permission: "monitoring:read" },
  // La exposición consolidada es la de Vulnerabilidades › Exposición (vulnerabilities:read).
  { key: "services", path: "services", label: "Puertos y servicios", permission: "vulnerabilities:read" },
  { key: "changes", path: "changes", label: "Historial de cambios", permission: "monitoring:read" },
  { key: "identity", path: "identity", label: "Identidad y evidencias", permission: "monitoring:read" },
  { key: "telemetry", path: "telemetry", label: "Telemetría" },
];

export const NETWORK_BASE = "/network";

export function networkTabPath(tab: Pick<NetworkTab, "path">): string {
  return tab.path ? `${NETWORK_BASE}/${tab.path}` : NETWORK_BASE;
}

/** Pestañas que puede abrir el usuario. */
export function visibleNetworkTabs(can: (permission: Permission) => boolean): NetworkTab[] {
  return NETWORK_TABS.filter((tab) => !tab.permission || can(tab.permission));
}

/** Pestaña de una ruta (/network/devices → Dispositivos); undefined fuera del hub. */
export function networkTabFor(pathname: string): NetworkTab | undefined {
  const base = pathname.replace(/\/+$/, "");
  if (base === NETWORK_BASE) return NETWORK_TABS[0];
  if (!base.startsWith(`${NETWORK_BASE}/`)) return undefined;
  const segment = base.slice(NETWORK_BASE.length + 1).split("/")[0];
  return NETWORK_TABS.find((tab) => tab.path !== "" && tab.path === segment);
}
