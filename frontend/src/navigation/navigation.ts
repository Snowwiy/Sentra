import type { IconName } from "../components/icons";

/**
 * Mapa de navegación (Fase 6C): una sola definición para el menú lateral, la barra superior
 * y el drawer móvil, así los tres no pueden divergir.
 *
 * `permission` solo decide si se MUESTRA la entrada. No es un control de acceso: cada ruta
 * sigue protegida por RequirePermission y cada endpoint por la API. Ocultar una entrada sin
 * permiso evita enlaces que terminarían en 403; mostrarla nunca concede nada.
 */
export interface NavItem {
  to: string;
  label: string;
  icon: IconName;
  permission?: string;
  /**
   * Prefijos de ruta que activan la entrada además de `to`. La entrada activa es la de
   * prefijo más largo, para que /detections/rules marque "Reglas" y no "Detecciones".
   */
  match?: string[];
  /** Ruta exacta (solo "/" la necesita: si no, todas las rutas la activarían). */
  exact?: boolean;
}

export interface NavGroup {
  id: string;
  label: string;
  items: NavItem[];
}

export const NAV_GROUPS: NavGroup[] = [
  {
    id: "general",
    label: "General",
    items: [
      { to: "/", label: "Activos", icon: "dashboard", exact: true, match: ["/assets/"] },
      { to: "/alerts", label: "Alertas", icon: "alert" },
      { to: "/detections", label: "Detecciones", icon: "detection" },
      { to: "/incidents", label: "Incidentes", icon: "incident", permission: "incidents:read" },
      { to: "/risk", label: "Riesgo", icon: "risk" },
    ],
  },
  {
    id: "infrastructure",
    label: "Infraestructura",
    items: [
      { to: "/network", label: "Red", icon: "network" },
      { to: "/infrastructure", label: "Infraestructura", icon: "infrastructure", permission: "monitoring:read" },
      { to: "/wlan", label: "Wi-Fi", icon: "wifi", permission: "monitoring:read" },
      { to: "/topology", label: "Topología", icon: "topology", permission: "monitoring:read" },
      { to: "/dhcp", label: "DHCP", icon: "dhcp", permission: "monitoring:read" },
      { to: "/agents", label: "Agentes", icon: "agent" },
      { to: "/sensors", label: "Sensores", icon: "sensor", permission: "monitoring:read" },
      { to: "/settings/sites", label: "Sites", icon: "site", permission: "monitoring:read" },
    ],
  },
  {
    id: "security",
    label: "Seguridad",
    items: [
      { to: "/vulnerabilities", label: "Vulnerabilidades", icon: "vulnerability", permission: "vulnerabilities:read" },
      { to: "/threat-intel", label: "Inteligencia", icon: "intel", permission: "threat_intel:read" },
      {
        to: "/detections/rules",
        label: "Reglas",
        icon: "rules",
        permission: "rules:read",
        // Fase 6E.5: las excepciones de reglas cuelgan de Reglas, no de Detecciones.
        match: ["/detections/exclusions"],
      },
      { to: "/response", label: "Response", icon: "response", permission: "response:read" },
      { to: "/investigations", label: "Investigaciones", icon: "forensics", permission: "forensics:read" },
      { to: "/containment", label: "Aislamiento", icon: "isolation", permission: "containment:preview" },
      { to: "/playbooks", label: "Playbooks", icon: "playbook", permission: "response:read" },
    ],
  },
  {
    id: "analysis",
    label: "Análisis",
    items: [
      { to: "/reports", label: "Informes", icon: "report", permission: "reports:read" },
      { to: "/ai", label: "AI Insights", icon: "ai", permission: "ai:use" },
    ],
  },
  {
    id: "admin",
    label: "Administración",
    items: [
      { to: "/admin/users", label: "Usuarios", icon: "users", permission: "users:manage" },
      { to: "/admin/lifecycle", label: "Ciclo de vida", icon: "lifecycle", permission: "assets:manage" },
      // Sin permiso: todos pueden elegir su estilo de navegación. Las secciones de
      // configuración con permiso propio (IA local, Sites) se filtran dentro de la página.
      { to: "/settings", label: "Configuración", icon: "settings", exact: true, match: ["/settings/ai"] },
    ],
  },
];

/** Grupos visibles para el usuario: sin entradas que no puede abrir y sin grupos vacíos. */
export function visibleGroups(can: (permission: string) => boolean, groups: NavGroup[] = NAV_GROUPS): NavGroup[] {
  return groups
    .map((group) => ({ ...group, items: group.items.filter((item) => !item.permission || can(item.permission)) }))
    .filter((group) => group.items.length > 0);
}

function covers(prefix: string, pathname: string): boolean {
  const base = prefix.replace(/\/+$/, "");
  return pathname === base || pathname.startsWith(`${base}/`);
}

function matchLength(item: NavItem, pathname: string): number {
  // +1: a igual longitud gana la coincidencia exacta frente a un prefijo.
  if (item.exact ? pathname === item.to : covers(item.to, pathname)) return item.to.length + 1;
  let best = -1;
  for (const prefix of item.match ?? []) {
    if (covers(prefix, pathname)) best = Math.max(best, prefix.replace(/\/+$/, "").length);
  }
  return best;
}

/** La entrada activa para una ruta: la de coincidencia más específica, o ninguna. */
export function activeItem(groups: NavGroup[], pathname: string): NavItem | undefined {
  let best: NavItem | undefined;
  let bestLength = -1;
  for (const group of groups) {
    for (const item of group.items) {
      const length = matchLength(item, pathname);
      if (length > bestLength) {
        best = item;
        bestLength = length;
      }
    }
  }
  return bestLength >= 0 ? best : undefined;
}

export function groupOf(groups: NavGroup[], item: NavItem | undefined): NavGroup | undefined {
  return item ? groups.find((group) => group.items.includes(item)) : undefined;
}
