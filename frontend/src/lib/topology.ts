// Topología de red (Fase 6D.2): textos, codificación visual, distribución determinista,
// búsqueda local y exportación SVG. Todo es puro (sin estado ni efectos) para poder probarlo
// sin navegador y para que el mismo grafo produzca siempre las mismas posiciones y bytes.
import type {
  TopologyConfidence,
  TopologyGroup,
  TopologyLink,
  TopologyLinkKind,
  TopologyNode,
  TopologyNodeKind,
  TopologyReviewState,
} from "../api/types";

export const LINK_KINDS: TopologyLinkKind[] = ["physical", "logical", "observed", "candidate", "unknown"];

export const LINK_KIND_LABELS: Record<TopologyLinkKind, string> = {
  physical: "Física (LLDP/CDP)",
  logical: "Lógica (gateway, controladora)",
  observed: "Observada (tabla MAC, Wi-Fi)",
  candidate: "Candidata (no concluyente)",
  unknown: "Desconocida",
};

export const LINK_KIND_HELP: Record<TopologyLinkKind, string> = {
  physical: "Adyacencia física informada por un protocolo de enlace (LLDP o CDP).",
  logical: "Relación de capa 3 o de gestión; no implica un cable directo.",
  observed: "Un equipo de red ve directamente al otro extremo (MAC única en un puerto de acceso o asociación Wi-Fi).",
  candidate: "Evidencia compatible pero no concluyente (puerto de acceso con varias MACs).",
  unknown: "Hay relación pero no se sabe su naturaleza (puerto sin interfaz resuelta).",
};

/**
 * Codificación de cada clase de enlace. El patrón de trazo la distingue SIN color (daltonismo,
 * impresión en blanco y negro); el color solo refuerza. Los valores de color son los tokens de
 * tokens.css copiados aquí porque la exportación SVG debe ser autónoma (sin CSS externo).
 */
export const LINK_STYLES: Record<TopologyLinkKind, { dash: string; color: string; width: number; pattern: string }> = {
  physical: { dash: "", color: "#22d3ee", width: 2.5, pattern: "continuo" },
  logical: { dash: "10 5", color: "#38bdf8", width: 2, pattern: "discontinuo" },
  observed: { dash: "2 4", color: "#22c55e", width: 2, pattern: "punteado" },
  candidate: { dash: "10 4 2 4", color: "#f59e0b", width: 1.5, pattern: "raya y punto" },
  unknown: { dash: "1 7", color: "#94a3b8", width: 1.5, pattern: "puntos espaciados" },
};

export const CONFIDENCE_LABELS: Record<TopologyConfidence, string> = { high: "alta", medium: "media", low: "baja" };

/** La confianza se ve en la opacidad y el grosor: una relación de baja confianza "pesa" menos. */
export const CONFIDENCE_OPACITY: Record<TopologyConfidence, number> = { high: 1, medium: 0.8, low: 0.5 };
export const CONFIDENCE_WIDTH: Record<TopologyConfidence, number> = { high: 1, medium: 0, low: -0.5 };

export const REVIEW_LABELS: Record<TopologyReviewState, string> = {
  unreviewed: "Sin revisar",
  accepted: "Aceptado",
  rejected: "Rechazado",
};

export const MEDIUM_LABELS: Record<string, string> = { wired: "cable", wireless: "inalámbrico", unknown: "desconocido" };

export const RELATION_LABELS: Record<string, string> = {
  lldp: "LLDP",
  cdp: "CDP",
  default_gateway: "Gateway por defecto (agente)",
  wlan_managed_by: "AP gestionado por controladora",
  fdb_edge: "MAC única en puerto de acceso",
  wlan_association: "Cliente Wi-Fi asociado",
  fdb_shared: "Puerto de acceso con varias MACs",
  fdb_unmapped: "Puerto de bridge sin interfaz resuelta",
};

export const NODE_KIND_LABELS: Record<TopologyNodeKind, string> = {
  asset: "Activo",
  network_device: "Equipo de red",
  wlan_ap: "Punto de acceso Wi-Fi",
  external: "Identidad externa (LLDP/CDP)",
};

export const ROLE_LABELS: Record<string, string> = {
  infrastructure: "Infraestructura",
  endpoint: "Equipo final",
  unknown: "Desconocido",
};

export const EVIDENCE_SOURCE_LABELS: Record<string, string> = {
  lldp: "LLDP",
  cdp: "CDP",
  fdb: "Tabla MAC (FDB)",
  wlan: "Wi-Fi",
  agent: "Agente",
  agent_gateway: "Gateway del agente",
  snmp: "SNMP",
};

export function relationLabel(relation: string): string {
  return RELATION_LABELS[relation] ?? relation;
}

/** Forma del nodo: también distingue el papel sin color. */
export type NodeShape = "square" | "circle" | "diamond" | "triangle";

export function nodeShape(node: Pick<TopologyNode, "kind" | "role">): NodeShape {
  if (node.kind === "external") return "diamond";
  if (node.kind === "wlan_ap") return "triangle";
  return node.role === "infrastructure" ? "square" : "circle";
}

export const SHAPE_LABELS: Record<NodeShape, string> = {
  square: "Cuadrado: infraestructura (router, switch, firewall, equipo de red)",
  circle: "Círculo: equipo final o rol desconocido",
  triangle: "Triángulo: punto de acceso Wi-Fi",
  diamond: "Rombo: identidad externa sin resolver",
};

export function nodeFill(status: string | null): string {
  if (status === "online") return "#22c55e";
  if (status === "offline") return "#ef4444";
  if (status === "stale") return "#f59e0b";
  return "#64748b";
}

// --- Distribución determinista -----------------------------------------------------------

export type GroupMode = "network" | "none";

export const UNASSIGNED_GROUP = "unassigned";
export const EXTERNAL_GROUP = "external";
const ALL_GROUP = "all";

export interface LayoutBox {
  id: string;
  label: string;
  x: number;
  y: number;
  width: number;
  height: number;
  count: number;
}

export interface Layout {
  positions: Map<string, { x: number; y: number }>;
  boxes: LayoutBox[];
  width: number;
  height: number;
}

export const CELL_W = 132;
export const CELL_H = 92;
const BOX_PAD = 28;
const BOX_HEADER = 30;
const BOX_GAP = 48;
const MAX_ROW_WIDTH = 2400;

function compareIds(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Grupo principal de un nodo: el primero por orden de id (estable aunque cambie el orden de la API). */
export function primaryGroup(node: TopologyNode, mode: GroupMode): string {
  if (mode === "none") return ALL_GROUP;
  if (node.kind === "external") return EXTERNAL_GROUP;
  const groups = [...node.groups].sort(compareIds);
  return groups[0] ?? UNASSIGNED_GROUP;
}

function groupRank(id: string): number {
  // Redes primero; después "sin red" y por último las identidades externas.
  if (id === UNASSIGNED_GROUP) return 1;
  if (id === EXTERNAL_GROUP) return 2;
  return 0;
}

export function groupLabel(id: string, groups: TopologyGroup[]): string {
  if (id === ALL_GROUP) return "Todos los nodos";
  if (id === UNASSIGNED_GROUP) return "Sin red asignada";
  if (id === EXTERNAL_GROUP) return "Identidades externas";
  const group = groups.find((g) => g.id === id);
  if (!group) return id.replace(/^network:/, "");
  return group.name && group.cidr ? `${group.name} · ${group.cidr}` : (group.cidr ?? group.name ?? id);
}

function nodeRank(node: TopologyNode): number {
  // Infraestructura arriba (fila superior del grupo), luego APs, equipos finales y externos.
  if (node.role === "infrastructure") return 0;
  if (node.kind === "wlan_ap") return 1;
  if (node.role === "endpoint") return 2;
  return 3;
}

/**
 * Distribución estable: cada nodo cae en la caja de su grupo, en una rejilla ordenada por papel
 * y por id. Solo depende de los ids, papeles y grupos (nunca del orden de la respuesta ni de
 * números aleatorios), así que el mismo grafo da siempre las mismas coordenadas y un nodo nuevo
 * en un grupo no mueve los nodos de los grupos anteriores.
 */
export function computeLayout(nodes: TopologyNode[], groups: TopologyGroup[], mode: GroupMode): Layout {
  const byGroup = new Map<string, TopologyNode[]>();
  for (const node of nodes) {
    const key = primaryGroup(node, mode);
    const list = byGroup.get(key);
    if (list) list.push(node);
    else byGroup.set(key, [node]);
  }
  const groupIds = [...byGroup.keys()].sort((a, b) => groupRank(a) - groupRank(b) || compareIds(a, b));
  const positions = new Map<string, { x: number; y: number }>();
  const boxes: LayoutBox[] = [];
  let cursorX = 0;
  let cursorY = 0;
  let rowHeight = 0;
  let maxWidth = 0;
  for (const groupId of groupIds) {
    const members = (byGroup.get(groupId) ?? []).sort((a, b) => nodeRank(a) - nodeRank(b) || compareIds(a.id, b.id));
    const infra = members.filter((n) => nodeRank(n) === 0);
    const rest = members.filter((n) => nodeRank(n) !== 0);
    const columns = Math.max(3, Math.min(16, Math.ceil(Math.sqrt(members.length * 1.6))));
    const infraRows = Math.ceil(infra.length / columns);
    const restRows = Math.ceil(rest.length / columns);
    const rows = Math.max(1, infraRows + restRows);
    const width = columns * CELL_W + BOX_PAD * 2;
    const height = rows * CELL_H + BOX_PAD * 2 + BOX_HEADER;
    if (cursorX > 0 && cursorX + width > MAX_ROW_WIDTH) {
      cursorX = 0;
      cursorY += rowHeight + BOX_GAP;
      rowHeight = 0;
    }
    const place = (list: TopologyNode[], firstRow: number) => {
      list.forEach((node, index) => {
        const row = firstRow + Math.floor(index / columns);
        const inRow = Math.min(columns, list.length - (row - firstRow) * columns);
        // Las filas incompletas se centran (la infraestructura queda centrada arriba).
        const offset = ((columns - inRow) * CELL_W) / 2;
        const col = index % columns;
        positions.set(node.id, {
          x: cursorX + BOX_PAD + offset + col * CELL_W + CELL_W / 2,
          y: cursorY + BOX_HEADER + BOX_PAD + row * CELL_H + CELL_H / 2,
        });
      });
    };
    place(infra, 0);
    place(rest, infraRows);
    boxes.push({
      id: groupId,
      label: groupLabel(groupId, groups),
      x: cursorX,
      y: cursorY,
      width,
      height,
      count: members.length,
    });
    cursorX += width + BOX_GAP;
    rowHeight = Math.max(rowHeight, height);
    maxWidth = Math.max(maxWidth, cursorX - BOX_GAP);
  }
  return { positions, boxes, width: Math.max(maxWidth, CELL_W), height: Math.max(cursorY + rowHeight, CELL_H) };
}

// --- Filtros y búsqueda --------------------------------------------------------------------

function normalizeMac(value: string): string {
  return value.toLowerCase().replace(/[^0-9a-f]/g, "");
}

/** Coincidencia local con la búsqueda (IP, nombre, etiqueta o MAC), para resaltar. */
export function nodeMatches(node: TopologyNode, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return false;
  const texts = [node.label, node.custom_label, node.automatic_name, node.ip, node.vendor];
  if (texts.some((t) => t && t.toLowerCase().includes(q))) return true;
  const mac = normalizeMac(q);
  return mac.length >= 4 && Boolean(node.mac && normalizeMac(node.mac).includes(mac));
}

/** Enlaces visibles: clase elegida y con los dos extremos presentes en la lista de nodos. */
export function visibleLinks(links: TopologyLink[], nodeIds: Set<string>, kinds: Set<TopologyLinkKind>): TopologyLink[] {
  return links.filter((l) => kinds.has(l.kind) && nodeIds.has(l.source) && nodeIds.has(l.target));
}

/** Nombre visible de un nodo: la etiqueta personalizada gana; si no, el nombre automático. */
export function nodeTitle(node: Pick<TopologyNode, "label" | "custom_label" | "automatic_name" | "ip">): string {
  return node.custom_label || node.label || node.automatic_name || node.ip || "Nodo sin nombre";
}

/** Ruta del inventario de un nodo. Solo rutas internas: nunca una URL absoluta ni //host. */
export function inventoryPath(node: TopologyNode, fromApi?: string | null): string | null {
  if (fromApi && /^\/(?!\/)[\w\-/.]*$/.test(fromApi)) return fromApi;
  if (node.asset_id) return `/assets/${encodeURIComponent(node.asset_id)}`;
  if (node.network_device_id) return `/infrastructure/devices/${encodeURIComponent(node.network_device_id)}`;
  return null;
}

export function linkAriaLabel(link: TopologyLink, names: Map<string, string>): string {
  const source = names.get(link.source) ?? link.source;
  const target = names.get(link.target) ?? link.target;
  return `${LINK_KIND_LABELS[link.kind]} entre ${source} y ${target}, confianza ${CONFIDENCE_LABELS[link.confidence]}${
    link.present ? "" : ", ausente"
  }${link.review_state === "rejected" ? ", rechazado" : ""}`;
}

// --- Exportación SVG -----------------------------------------------------------------------

/** Escapa texto para XML. Además elimina los caracteres de control que XML no admite. */
export function escapeXml(text: string): string {
  return (
    text
      // eslint-disable-next-line no-control-regex
      .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;")
  );
}

function fmt(n: number): string {
  // Dos decimales como máximo y sin "-0": bytes idénticos en cualquier motor.
  const rounded = Math.round(n * 100) / 100;
  return Object.is(rounded, -0) ? "0" : String(rounded);
}

export function shapePath(shape: NodeShape, x: number, y: number, r: number): string {
  switch (shape) {
    case "square":
      return `M${fmt(x - r)} ${fmt(y - r)}h${fmt(2 * r)}v${fmt(2 * r)}h${fmt(-2 * r)}Z`;
    case "diamond":
      return `M${fmt(x)} ${fmt(y - r * 1.25)}L${fmt(x + r * 1.25)} ${fmt(y)}L${fmt(x)} ${fmt(y + r * 1.25)}L${fmt(x - r * 1.25)} ${fmt(y)}Z`;
    case "triangle":
      return `M${fmt(x)} ${fmt(y - r * 1.2)}L${fmt(x + r * 1.15)} ${fmt(y + r * 0.9)}L${fmt(x - r * 1.15)} ${fmt(y + r * 0.9)}Z`;
    case "circle":
      return `M${fmt(x - r)} ${fmt(y)}a${fmt(r)} ${fmt(r)} 0 1 0 ${fmt(2 * r)} 0a${fmt(r)} ${fmt(r)} 0 1 0 ${fmt(-2 * r)} 0Z`;
  }
}

export const NODE_RADIUS = 14;

export interface SvgExportInput {
  title: string;
  nodes: TopologyNode[];
  links: TopologyLink[];
  layout: Layout;
}

/**
 * SVG autónomo y seguro: sin <script>, sin atributos on*, sin <foreignObject>, sin href ni
 * referencias externas (ni fuentes, ni imágenes, ni CSS), todo el texto escapado. Se recorren
 * nodos y enlaces ordenados por id y las coordenadas se redondean, así que el mismo grafo da
 * siempre los mismos bytes (se puede comparar o firmar). No incluye fecha de generación por
 * ese mismo motivo; el título lleva el site.
 */
export function exportSvg({ title, nodes, links, layout }: SvgExportInput): string {
  const margin = 40;
  const legendH = 28 * LINK_KINDS.length + 40;
  const width = Math.ceil(layout.width + margin * 2);
  const height = Math.ceil(layout.height + margin * 2 + legendH + 30);
  const out: string[] = [];
  out.push('<?xml version="1.0" encoding="UTF-8"?>');
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" role="img" aria-label="${escapeXml(title)}">`,
  );
  out.push(`<title>${escapeXml(title)}</title>`);
  out.push(`<rect x="0" y="0" width="${width}" height="${height}" fill="#060a12"/>`);
  out.push(`<text x="${margin}" y="26" fill="#e3e9f2" font-family="sans-serif" font-size="16">${escapeXml(title)}</text>`);
  out.push(`<g transform="translate(${margin} ${margin})">`);
  for (const box of [...layout.boxes].sort((a, b) => compareIds(a.id, b.id))) {
    out.push(
      `<rect x="${fmt(box.x)}" y="${fmt(box.y)}" width="${fmt(box.width)}" height="${fmt(box.height)}" rx="10" fill="#0c1320" stroke="#2b3c56"/>`,
    );
    out.push(
      `<text x="${fmt(box.x + 12)}" y="${fmt(box.y + 20)}" fill="#8d9db4" font-family="sans-serif" font-size="12">${escapeXml(
        `${box.label} (${box.count})`,
      )}</text>`,
    );
  }
  const sortedLinks = [...links].sort((a, b) => compareIds(a.id, b.id));
  for (const link of sortedLinks) {
    const a = layout.positions.get(link.source);
    const b = layout.positions.get(link.target);
    if (!a || !b) continue;
    const style = LINK_STYLES[link.kind];
    const dash = style.dash ? ` stroke-dasharray="${style.dash}"` : "";
    const opacity = link.present ? CONFIDENCE_OPACITY[link.confidence] : 0.3;
    out.push(
      `<line x1="${fmt(a.x)}" y1="${fmt(a.y)}" x2="${fmt(b.x)}" y2="${fmt(b.y)}" stroke="${
        link.review_state === "rejected" ? "#ef4444" : style.color
      }" stroke-width="${fmt(style.width + CONFIDENCE_WIDTH[link.confidence])}" stroke-opacity="${fmt(opacity)}"${dash} stroke-linecap="round"/>`,
    );
  }
  const sortedNodes = [...nodes].sort((a, b) => compareIds(a.id, b.id));
  for (const node of sortedNodes) {
    const p = layout.positions.get(node.id);
    if (!p) continue;
    out.push(
      `<path d="${shapePath(nodeShape(node), p.x, p.y, NODE_RADIUS)}" fill="${nodeFill(node.status)}" stroke="#e3e9f2" stroke-width="1.5"/>`,
    );
    out.push(
      `<text x="${fmt(p.x)}" y="${fmt(p.y + NODE_RADIUS + 16)}" fill="#e3e9f2" font-family="sans-serif" font-size="11" text-anchor="middle">${escapeXml(
        truncate(nodeTitle(node), 22),
      )}</text>`,
    );
  }
  out.push("</g>");
  // Leyenda: patrón de trazo y texto, legible también en blanco y negro.
  const legendY = Math.ceil(layout.height + margin * 2);
  out.push(`<g transform="translate(${margin} ${legendY})">`);
  out.push(`<text x="0" y="0" fill="#e3e9f2" font-family="sans-serif" font-size="13">Leyenda</text>`);
  LINK_KINDS.forEach((kind, i) => {
    const style = LINK_STYLES[kind];
    const y = 22 + i * 28;
    const dash = style.dash ? ` stroke-dasharray="${style.dash}"` : "";
    out.push(`<line x1="0" y1="${y}" x2="60" y2="${y}" stroke="${style.color}" stroke-width="${style.width}"${dash}/>`);
    out.push(
      `<text x="72" y="${y + 4}" fill="#e3e9f2" font-family="sans-serif" font-size="12">${escapeXml(
        `${LINK_KIND_LABELS[kind]} (trazo ${style.pattern})`,
      )}</text>`,
    );
  });
  out.push("</g>");
  out.push("</svg>");
  return `${out.join("\n")}\n`;
}

export function truncate(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

/** Nombre de fichero para la exportación: sin caracteres peligrosos y determinista. */
export function exportFilename(siteName: string, extension: "svg" | "png"): string {
  const slug = siteName
    .normalize("NFKD")
    .replace(/[^\w-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .toLowerCase()
    .slice(0, 40);
  return `sentra-topologia-${slug || "site"}.${extension}`;
}
