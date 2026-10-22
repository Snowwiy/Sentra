// @vitest-environment jsdom
import { describe, expect, it } from "vitest";
import type { TopologyGroup, TopologyLink, TopologyNode } from "../api/types";
import { topoLink, topoNode } from "../test/topology";
import {
  computeLayout,
  escapeXml,
  exportFilename,
  exportSvg,
  inventoryPath,
  LINK_KINDS,
  LINK_STYLES,
  nodeMatches,
  nodeShape,
  primaryGroup,
  visibleLinks,
} from "./topology";

const GROUPS: TopologyGroup[] = [
  { id: "network:192.0.2.0/24", kind: "network", cidr: "192.0.2.0/24", name: "LAN", node_count: 4 },
  { id: "network:198.51.100.0/24", kind: "network", cidr: "198.51.100.0/24", name: "IoT", node_count: 2 },
];

const NODES: TopologyNode[] = [
  topoNode({ id: "asset:03", ip: "192.0.2.3" }),
  topoNode({ id: "asset:01", ip: "192.0.2.1", role: "infrastructure", device_type: "router" }),
  topoNode({ id: "asset:02", ip: "192.0.2.2", custom_label: "Alexa Sala", mac: "AA:BB:CC:00:11:22" }),
  topoNode({ id: "asset:10", ip: "198.51.100.10", groups: ["network:198.51.100.0/24"] }),
  topoNode({ id: "asset:11", groups: [] }),
  topoNode({ id: "external:abcd", kind: "external", groups: [], role: "unknown", label: "sw-remoto" }),
];

function positions(nodes: TopologyNode[]) {
  return Object.fromEntries([...computeLayout(nodes, GROUPS, "network").positions.entries()].sort());
}

describe("distribución determinista", () => {
  it("el mismo grafo en otro orden da exactamente las mismas posiciones", () => {
    const shuffled = [NODES[4], NODES[0], NODES[5], NODES[2], NODES[1], NODES[3]] as TopologyNode[];
    expect(positions(shuffled)).toEqual(positions(NODES));
    expect(positions(NODES)).toEqual(positions(NODES));
  });

  it("agrupa por red: redes ordenadas, luego sin red y al final externos", () => {
    const layout = computeLayout(NODES, GROUPS, "network");
    expect(layout.boxes.map((b) => b.id)).toEqual([
      "network:192.0.2.0/24",
      "network:198.51.100.0/24",
      "unassigned",
      "external",
    ]);
    expect(layout.boxes[0]?.label).toBe("LAN · 192.0.2.0/24");
    expect(layout.boxes[2]?.label).toBe("Sin red asignada");
  });

  it("la infraestructura queda arriba de su grupo", () => {
    const layout = computeLayout(NODES, GROUPS, "network");
    const router = layout.positions.get("asset:01");
    const endpoint = layout.positions.get("asset:02");
    expect(router && endpoint && router.y < endpoint.y).toBe(true);
  });

  it("es estable: un nodo nuevo en un grupo posterior no mueve los anteriores", () => {
    const before = computeLayout(NODES, GROUPS, "network");
    const after = computeLayout([...NODES, topoNode({ id: "asset:12", groups: [] })], GROUPS, "network");
    for (const id of ["asset:01", "asset:02", "asset:03", "asset:10"]) {
      expect(after.positions.get(id)).toEqual(before.positions.get(id));
    }
  });

  it("sin agrupar, una sola caja con todos los nodos", () => {
    const layout = computeLayout(NODES, GROUPS, "none");
    expect(layout.boxes).toHaveLength(1);
    expect(layout.positions.size).toBe(NODES.length);
  });

  it("el grupo principal no depende del orden de la lista de grupos del nodo", () => {
    const a = topoNode({ id: "asset:x", groups: ["network:b", "network:a"] });
    const b = topoNode({ id: "asset:x", groups: ["network:a", "network:b"] });
    expect(primaryGroup(a, "network")).toBe(primaryGroup(b, "network"));
  });

  it("escala a 1500 nodos sin solapar posiciones", () => {
    const many = Array.from({ length: 1500 }, (_, i) =>
      topoNode({ id: `asset:${String(i).padStart(5, "0")}`, groups: [`network:10.${i % 7}.0.0/16`] }),
    );
    const layout = computeLayout(many, [], "network");
    const keys = new Set([...layout.positions.values()].map((p) => `${p.x},${p.y}`));
    expect(keys.size).toBe(1500);
  });
});

describe("búsqueda y filtros", () => {
  const node = NODES[2] as TopologyNode;
  it("coincide por IP, etiqueta personalizada, nombre y MAC con cualquier separador", () => {
    expect(nodeMatches(node, "192.0.2.2")).toBe(true);
    expect(nodeMatches(node, "alexa")).toBe(true);
    expect(nodeMatches(node, "aa-bb-cc")).toBe(true);
    expect(nodeMatches(node, "aabbcc001122")).toBe(true);
    expect(nodeMatches(node, "nada")).toBe(false);
    expect(nodeMatches(node, "  ")).toBe(false);
  });

  it("filtra enlaces por clase y descarta los que no tienen sus dos extremos", () => {
    const links = [
      topoLink({ id: "l1", source: "asset:01", target: "asset:02" }),
      topoLink({ id: "l2", source: "asset:01", target: "asset:03", kind: "candidate" }),
      topoLink({ id: "l3", source: "asset:01", target: "asset:99" }),
    ];
    const ids = new Set(NODES.map((n) => n.id));
    expect(visibleLinks(links, ids, new Set(LINK_KINDS)).map((l) => l.id)).toEqual(["l1", "l2"]);
    expect(visibleLinks(links, ids, new Set(["physical"])).map((l) => l.id)).toEqual(["l1"]);
  });

  it("cada clase de enlace se distingue sin color (patrón de trazo único)", () => {
    const dashes = LINK_KINDS.map((k) => LINK_STYLES[k].dash);
    expect(new Set(dashes).size).toBe(LINK_KINDS.length);
    const patterns = LINK_KINDS.map((k) => LINK_STYLES[k].pattern);
    expect(new Set(patterns).size).toBe(LINK_KINDS.length);
  });

  it("formas por papel: infraestructura, equipo final, AP y externo", () => {
    expect(nodeShape({ kind: "asset", role: "infrastructure" })).toBe("square");
    expect(nodeShape({ kind: "asset", role: "endpoint" })).toBe("circle");
    expect(nodeShape({ kind: "wlan_ap", role: "infrastructure" })).toBe("triangle");
    expect(nodeShape({ kind: "external", role: "unknown" })).toBe("diamond");
  });

  it("la ruta del inventario solo admite rutas internas", () => {
    const n = topoNode({ id: "asset:1", asset_id: "1" });
    expect(inventoryPath(n, "/assets/1")).toBe("/assets/1");
    expect(inventoryPath(n, "//evil.example/x")).toBe("/assets/1");
    expect(inventoryPath(n, "https://evil.example")).toBe("/assets/1");
    expect(inventoryPath(n, "javascript:alert(1)")).toBe("/assets/1");
    expect(inventoryPath(topoNode({ id: "network_device:2", network_device_id: "2" }))).toBe("/infrastructure/devices/2");
    expect(inventoryPath(topoNode({ id: "external:x", kind: "external" }))).toBeNull();
  });
});

describe("exportación SVG", () => {
  const hostile = [
    ...NODES,
    topoNode({
      id: "asset:zz",
      custom_label: '<script>x</script>"',
      label: "x",
      automatic_name: "&amp;",
    }),
  ];
  const links = [
    topoLink({ id: "l1", source: "asset:01", target: "asset:02" }),
    topoLink({ id: "l2", source: "asset:01", target: "asset:zz", kind: "observed", confidence: "low" }),
  ];
  const svgOf = (nodes: TopologyNode[], ls: TopologyLink[]) =>
    exportSvg({ title: 'Topología de red · Sede <Norte>" onload="alert(1)', nodes, links: ls, layout: computeLayout(nodes, GROUPS, "network") });

  it("mismo grafo → mismos bytes, aunque cambie el orden de nodos y enlaces", () => {
    const a = svgOf(hostile, links);
    const b = svgOf([...hostile].reverse(), [...links].reverse());
    expect(b).toBe(a);
  });

  it("sin scripts, manejadores, referencias externas ni HTML embebido; texto escapado", () => {
    const svg = svgOf(hostile, links);
    expect(svg).not.toMatch(/<script/i);
    // Ningún atributo on* en el árbol XML (el texto escapado puede contener "onload=").
    const doc = new DOMParser().parseFromString(svg, "image/svg+xml");
    for (const el of Array.from(doc.getElementsByTagName("*"))) {
      for (const attr of Array.from(el.attributes)) expect(attr.name.toLowerCase().startsWith("on")).toBe(false);
    }
    expect(doc.getElementsByTagName("script")).toHaveLength(0);
    expect(svg).not.toMatch(/href|xlink|foreignObject|<image|<style|url\(|@import|javascript:/i);
    expect(svg).toContain("&lt;script&gt;x&lt;/script&gt;&quot;");
    expect(svg).toContain("Sede &lt;Norte&gt;");
    // El único espacio de nombres es el estándar de SVG (no se descarga nada).
    expect(svg.match(/https?:\/\/[^"]+/g)).toEqual(["http://www.w3.org/2000/svg"]);
  });

  it("es XML bien formado y lleva la leyenda con el patrón de cada clase", () => {
    const svg = svgOf(hostile, links);
    const doc = new DOMParser().parseFromString(svg, "image/svg+xml");
    expect(doc.getElementsByTagName("parsererror")).toHaveLength(0);
    for (const kind of LINK_KINDS) expect(svg).toContain(`trazo ${LINK_STYLES[kind].pattern}`);
  });

  it("escapa también caracteres de control y comillas simples", () => {
    expect(escapeXml("a\u0000b'c&")).toBe("ab&apos;c&amp;");
  });

  it("nombre de fichero seguro", () => {
    expect(exportFilename("Sede ../Norte <1>", "svg")).toBe("sentra-topologia-sede-norte-1.svg");
    expect(exportFilename("", "png")).toBe("sentra-topologia-site.png");
  });
});
