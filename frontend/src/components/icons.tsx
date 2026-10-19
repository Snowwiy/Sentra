import type { SVGProps } from "react";

/**
 * Iconos de línea propios (Fase 6C): 24x24, trazo 1.75, color heredado (currentColor).
 * Se dibujan en el bundle en lugar de añadir una biblioteca de iconos: son pocos, estables y
 * así no hay dependencia nueva que mantener ni peticiones a CDNs.
 */
export type IconName =
  | "menu"
  | "close"
  | "chevron-down"
  | "chevron-right"
  | "chevrons-left"
  | "chevrons-right"
  | "dashboard"
  | "alert"
  | "detection"
  | "incident"
  | "risk"
  | "network"
  | "infrastructure"
  | "wifi"
  | "agent"
  | "sensor"
  | "site"
  | "vulnerability"
  | "intel"
  | "rules"
  | "response"
  | "playbook"
  | "report"
  | "ai"
  | "users"
  | "lifecycle"
  | "settings"
  | "more"
  | "user"
  | "logout"
  | "layout-sidebar"
  | "layout-top"
  | "layout-auto";

const PATHS: Record<IconName, string> = {
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "M6 6l12 12M18 6L6 18",
  "chevron-down": "M6 9l6 6 6-6",
  "chevron-right": "M9 6l6 6-6 6",
  "chevrons-left": "M11 17l-5-5 5-5M18 17l-5-5 5-5",
  "chevrons-right": "M13 17l5-5-5-5M6 17l5-5-5-5",
  dashboard: "M4 4h7v7H4zM13 4h7v4h-7zM13 10h7v10h-7zM4 13h7v7H4z",
  alert: "M12 3l9 16H3zM12 10v4M12 17h.01",
  detection: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14zM20 20l-4-4M11 8v3l2 2",
  incident: "M12 3l8 4v5c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V7zM12 8v5M12 16h.01",
  risk: "M4 20V10M10 20V4M16 20v-7M22 20H2",
  network: "M12 4v5M5 15v-3h14v3M5 15a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM19 15a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 15a2 2 0 1 0 0 4 2 2 0 0 0 0-4zM12 12v3M10 2h4v2h-4z",
  infrastructure: "M4 5h16v5H4zM4 14h16v5H4zM7 7.5h.01M7 16.5h.01M11 7.5h6M11 16.5h6",
  wifi: "M2 9a15 15 0 0 1 20 0M5 12.5a10 10 0 0 1 14 0M8.5 16a5 5 0 0 1 7 0M12 19.5h.01",
  agent: "M4 5h16v11H4zM8 20h8M12 16v4",
  sensor: "M12 12m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0M7.8 7.8a6 6 0 0 0 0 8.4M16.2 16.2a6 6 0 0 0 0-8.4M5 5a10 10 0 0 0 0 14M19 19a10 10 0 0 0 0-14",
  site: "M12 21s-7-6.2-7-12a7 7 0 0 1 14 0c0 5.8-7 12-7 12zM12 9m-2.5 0a2.5 2.5 0 1 0 5 0 2.5 2.5 0 1 0-5 0",
  vulnerability: "M12 3l8 4v5c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V7zM9 12l2 2 4-4",
  intel: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18zM3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z",
  rules: "M8 6h12M8 12h12M8 18h12M4 6h.01M4 12h.01M4 18h.01",
  response: "M13 2L4 14h7l-1 8 9-12h-7z",
  playbook: "M5 4h11l3 3v13H5zM9 9h6M9 13h6M9 17h3",
  report: "M6 3h9l4 4v14H6zM9 13v4M12 10v7M15 14v3",
  ai: "M12 3l1.8 4.7L18.5 9.5l-4.7 1.8L12 16l-1.8-4.7L5.5 9.5l4.7-1.8zM19 15l.9 2.1L22 18l-2.1.9L19 21l-.9-2.1L16 18l2.1-.9z",
  users: "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM2 21v-1a6 6 0 0 1 12 0v1M16 3.1a4 4 0 0 1 0 7.8M22 21v-1a6 6 0 0 0-4-5.7",
  lifecycle: "M20 12a8 8 0 0 1-14.3 4.9M4 12a8 8 0 0 1 14.3-4.9M18 3v4h-4M6 21v-4h4",
  settings:
    "M12 9a3 3 0 1 0 0 6 3 3 0 0 0 0-6zM19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z",
  more: "M5 12h.01M12 12h.01M19 12h.01",
  user: "M12 12a4 4 0 1 0 0-8 4 4 0 0 0 0 8zM4 21v-1a7 7 0 0 1 14 0v1",
  logout: "M15 4h4v16h-4M10 8l-4 4 4 4M6 12h10",
  "layout-sidebar": "M3 4h18v16H3zM9 4v16",
  "layout-top": "M3 4h18v16H3zM3 9h18",
  "layout-auto": "M3 4h18v16H3zM9 9v11M3 9h18",
};

export function Icon({ name, size = 20, ...props }: { name: IconName; size?: number } & SVGProps<SVGSVGElement>) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.75}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      <path d={PATHS[name]} />
    </svg>
  );
}
