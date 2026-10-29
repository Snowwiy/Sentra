// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Role, TopologyGraph, TopologyLinkDetail, TopologyStatus } from "../api/types";
import { WithRole } from "../test/auth";
import { installFetch, type Call, type Handler } from "../test/sites";
import { topoLink, topoNode } from "../test/topology";
import { TopologyPage } from "./TopologyPage";

const SITE = { id: "00000000-0000-0000-0000-00000000d5f1", name: "Principal" };
const ROUTER = "asset:00000000-0000-0000-0000-000000000001";
const ALEXA = "asset:00000000-0000-0000-0000-000000000002";
const PC = "asset:00000000-0000-0000-0000-000000000003";
const LINK = "11111111-0000-0000-0000-000000000001";
const CAND = "11111111-0000-0000-0000-000000000002";

function graph(overrides: Partial<TopologyGraph> = {}): TopologyGraph {
  return {
    site: SITE,
    generated_at: "2026-10-21T10:00:00Z",
    last_build: { id: "b1", status: "succeeded", finished_at: "2026-10-21T09:59:00Z" },
    truncated: false,
    limits: { max_nodes: 1500, max_links: 5000 },
    nodes: [
      topoNode({ id: ROUTER, label: "archer-gx90", role: "infrastructure", device_type: "router", ip: "192.0.2.1", asset_id: ROUTER.slice(6), link_count: 2 }),
      topoNode({ id: ALEXA, label: "Alexa Sala", custom_label: "Alexa Sala", automatic_name: "echo-1", ip: "192.0.2.20", mac: "AA:BB:CC:00:00:20", asset_id: ALEXA.slice(6), device_type: "iot", link_count: 1 }),
      topoNode({ id: PC, label: "pc-ana", ip: "192.0.2.30", device_type: "pc", asset_id: PC.slice(6), link_count: 1 }),
    ],
    links: [
      topoLink({ id: LINK, source: ROUTER, target: ALEXA, kind: "observed", relation: "fdb_edge", confidence: "medium" }),
      topoLink({ id: CAND, source: ROUTER, target: PC, kind: "candidate", relation: "fdb_shared", confidence: "low" }),
    ],
    groups: [{ id: "network:192.0.2.0/24", kind: "network", cidr: "192.0.2.0/24", name: "LAN", node_count: 3 }],
    coverage: { nodes: 3, nodes_without_links: 0, unlinked_by_type: {}, links_by_kind: { observed: 1, candidate: 1 }, limitations: [] },
    ...overrides,
  };
}

function status(overrides: Partial<TopologyStatus> = {}): TopologyStatus {
  return {
    site: SITE,
    last_build: null,
    links_present: 0,
    links_by_kind: {},
    evidence_available: { lldp_cdp: false, fdb: false, wlan: false, agent_gateways: true },
    ...overrides,
  };
}

function linkDetail(version = 3): TopologyLinkDetail {
  return {
    ...topoLink({ id: LINK, source: ROUTER, target: ALEXA, kind: "observed", relation: "fdb_edge", confidence: "medium" }),
    source_port: "Gi1/0/3",
    evidence: [{ source: "fdb", detail: "MAC única en Gi1/0/3 (VLAN 10)", observed_at: "2026-10-21T09:00:00Z" }],
    target_external: null,
    review_note: null,
    reviewed_by: null,
    reviewed_at: null,
    version,
  };
}

let calls: Call[];
let routes: Record<string, Handler>;
let currentGraph: TopologyGraph;

beforeEach(() => {
  currentGraph = graph();
  routes = {
    "GET /topology/graph": () => ({ body: currentGraph }),
    "GET /topology/status": () => ({ body: status({ links_present: 2 }) }),
    [`GET /topology/nodes/${encodeURIComponent(ROUTER)}`]: () => ({
      body: {
        node: currentGraph.nodes[0],
        links: currentGraph.links,
        observed_names: [],
        inventory_path: `/assets/${ROUTER.slice(6)}`,
      },
    }),
    [`GET /topology/links/${LINK}`]: () => ({ body: linkDetail() }),
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderPage(role: Role = "admin") {
  return render(
    <MemoryRouter initialEntries={["/topology"]}>
      <WithRole role={role}>
        <Routes>
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/assets/:id" element={<p>inventario</p>} />
        </Routes>
      </WithRole>
    </MemoryRouter>,
  );
}

const graphCalls = () => calls.filter((c) => c.path === "/topology/graph");

describe("TopologyPage", () => {
  it("dibuja nodos accesibles por teclado, enlaces codificados y la leyenda", async () => {
    renderPage("viewer");
    const canvas = await screen.findByTestId("topology-canvas");
    const nodes = within(canvas).getAllByRole("button");
    expect(nodes).toHaveLength(3);
    // Orden de tabulación = orden determinista (por id); la etiqueta personalizada se ve.
    expect(nodes[1]).toHaveAttribute("aria-label", expect.stringContaining("Alexa Sala"));
    expect(nodes[1]).toHaveAttribute("tabindex", "0");
    expect(canvas).toHaveTextContent("Alexa Sala");
    const lines = canvas.querySelectorAll("line[data-kind]");
    expect([...lines].map((l) => [l.getAttribute("data-kind"), l.getAttribute("stroke-dasharray")])).toEqual([
      ["observed", "2 4"],
      ["candidate", "10 4 2 4"],
    ]);
    const legend = screen.getByRole("region", { name: "Leyenda de la topología" });
    for (const pattern of ["continuo", "discontinuo", "punteado", "raya y punto", "puntos espaciados"]) {
      expect(legend).toHaveTextContent(`trazo ${pattern}`);
    }
  });

  it("Enter sobre un nodo abre su panel con enlaces, acceso al inventario y al riesgo", async () => {
    renderPage("viewer");
    const canvas = await screen.findByTestId("topology-canvas");
    const router = within(canvas).getAllByRole("button")[0] as HTMLElement;
    fireEvent.keyDown(router, { key: "Enter" });
    const panel = await screen.findByRole("region", { name: "Detalles del nodo" });
    expect(within(panel).getByRole("heading", { name: "archer-gx90" })).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Ver en el inventario" })).toHaveAttribute("href", `/assets/${ROUTER.slice(6)}`);
    expect(within(panel).getByRole("link", { name: "Ver riesgo" })).toHaveAttribute("href", `/assets/${ROUTER.slice(6)}?tab=risk`);
    const links = await within(panel).findByRole("list", { name: "Enlaces del nodo" });
    expect(links).toHaveTextContent("Alexa Sala");
    expect(links).toHaveTextContent("Observada");
    // El detalle del nodo se pide en el site del grafo, no en el site por defecto.
    const nodeCall = calls.find((c) => c.path.startsWith("/topology/nodes/"));
    expect(nodeCall?.url.searchParams.get("site_id")).toBe(SITE.id);
    fireEvent.click(within(links).getAllByRole("button", { name: "Evidencia" })[0] as HTMLElement);
    const linkPanel = await screen.findByRole("region", { name: "Detalles del enlace" });
    expect(await within(linkPanel).findByRole("list", { name: "Evidencia del enlace" })).toHaveTextContent(
      "MAC única en Gi1/0/3",
    );
  });

  it("viewer no ve Reconstruir ni la revisión de enlaces", async () => {
    renderPage("viewer");
    const canvas = await screen.findByTestId("topology-canvas");
    expect(screen.queryByRole("button", { name: "Reconstruir" })).not.toBeInTheDocument();
    fireEvent.click(canvas.querySelector(`[data-link-id="${LINK}"] line`) as Element);
    const linkPanel = await screen.findByRole("region", { name: "Detalles del enlace" });
    await within(linkPanel).findByRole("list", { name: "Evidencia del enlace" });
    expect(within(linkPanel).queryByRole("form", { name: "Revisar enlace" })).not.toBeInTheDocument();
  });

  it("admin revisa un enlace con nota y versión; un 409 avisa y recarga", async () => {
    let reviews = 0;
    routes[`PATCH /topology/links/${LINK}/review`] = (init) => {
      reviews += 1;
      expect(JSON.parse(String(init.body))).toEqual({ review_state: "accepted", note: "Comprobado en el armario", version: 3 });
      return { status: 409, body: { error: { code: "topology_link_conflict", message: "version changed" } } };
    };
    renderPage("admin");
    const canvas = await screen.findByTestId("topology-canvas");
    fireEvent.click(canvas.querySelector(`[data-link-id="${LINK}"] line`) as Element);
    const form = await screen.findByRole("form", { name: "Revisar enlace" });
    fireEvent.change(within(form).getByRole("combobox"), { target: { value: "accepted" } });
    fireEvent.change(within(form).getByRole("textbox"), { target: { value: "Comprobado en el armario" } });
    const before = calls.filter((c) => c.path === `/topology/links/${LINK}`).length;
    fireEvent.click(within(form).getByRole("button", { name: "Guardar revisión" }));
    expect(await screen.findByText(/Otro administrador ha revisado este enlace/)).toBeInTheDocument();
    expect(reviews).toBe(1);
    await waitFor(() => expect(calls.filter((c) => c.path === `/topology/links/${LINK}`).length).toBeGreaterThan(before));
  });

  it("admin reconstruye la topología del site", async () => {
    routes["POST /topology/rebuild"] = () => ({
      body: { id: "b2", site_id: SITE.id, status: "succeeded", trigger: "manual", requested_by: "admin", started_at: null, finished_at: null, duration_ms: 12, counts: { links_present: 2 }, error_code: null },
    });
    renderPage("admin");
    await screen.findByTestId("topology-canvas");
    fireEvent.click(screen.getByRole("button", { name: "Reconstruir" }));
    expect(await screen.findByText("Topología reconstruida: 2 enlaces presentes.")).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST" && c.path === "/topology/rebuild");
    expect(JSON.parse(String(post?.init.body))).toEqual({ site_id: SITE.id });
  });

  it("la búsqueda usa q del API y resalta las coincidencias", async () => {
    renderPage("viewer");
    await screen.findByTestId("topology-canvas");
    fireEvent.change(screen.getByRole("searchbox", { name: "Buscar nodos" }), { target: { value: "aa:bb:cc" } });
    await waitFor(() => expect(graphCalls().some((c) => c.url.searchParams.get("q") === "aa:bb:cc")).toBe(true));
    await waitFor(() => expect(screen.getByTestId("topology-canvas").querySelectorAll(".topo-node--match")).toHaveLength(1));
    expect(screen.getByText(/1 coincidencias/)).toBeInTheDocument();
  });

  it("filtra por clase de enlace (local) y por tipo de dispositivo y ausentes (API)", async () => {
    renderPage("viewer");
    const canvas = await screen.findByTestId("topology-canvas");
    expect(canvas.querySelectorAll("line[data-kind]")).toHaveLength(2);
    fireEvent.click(screen.getByRole("checkbox", { name: /Candidata/ }));
    expect(screen.getByTestId("topology-canvas").querySelectorAll("line[data-kind]")).toHaveLength(1);
    fireEvent.change(screen.getByRole("combobox", { name: "Tipo de dispositivo" }), { target: { value: "router" } });
    await waitFor(() => expect(graphCalls().some((c) => c.url.searchParams.get("device_type") === "router")).toBe(true));
    fireEvent.click(screen.getByRole("checkbox", { name: /Mostrar ausentes/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: /Mostrar rechazados/ }));
    await waitFor(() =>
      expect(
        graphCalls().some(
          (c) => c.url.searchParams.get("include_absent") === "true" && c.url.searchParams.get("include_rejected") === "true",
        ),
      ).toBe(true),
    );
  });

  it("ofrece la alternativa en tabla de nodos y enlaces", async () => {
    renderPage("viewer");
    await screen.findByTestId("topology-canvas");
    fireEvent.click(screen.getByRole("tab", { name: "Lista accesible" }));
    const nodes = screen.getByRole("region", { name: "Nodos" });
    expect(within(nodes).getAllByRole("row")).toHaveLength(4);
    const links = screen.getByRole("region", { name: "Enlaces" });
    expect(within(links).getByText("Puerto de acceso con varias MACs")).toBeInTheDocument();
    fireEvent.click(within(nodes).getByRole("button", { name: "Alexa Sala" }));
    expect(await screen.findByRole("region", { name: "Detalles del nodo" })).toBeInTheDocument();
  });

  it("estado vacío: explica qué evidencia falta y que nunca se reconstruyó", async () => {
    currentGraph = graph({ links: [], last_build: null });
    routes["GET /topology/status"] = () => ({ body: status() });
    renderPage("admin");
    const empty = await screen.findByRole("region", { name: "Por qué no hay enlaces" });
    expect(empty).toHaveTextContent("no se ha reconstruido nunca");
    expect(empty).toHaveTextContent("Pulsa «Reconstruir»");
    const evidence = await within(empty).findByRole("list", { name: "Evidencia disponible" });
    expect(evidence).toHaveTextContent("Sin datos: Ningún equipo de red registrado informa vecinos LLDP/CDP");
    expect(evidence).toHaveTextContent("Disponible: Los agentes informan su gateway por defecto.");
    expect(empty).toHaveTextContent("Compartir subred o gateway no crea un enlace físico");
  });

  it("avisa si el grafo está truncado", async () => {
    currentGraph = graph({ truncated: true });
    renderPage("viewer");
    expect(await screen.findByText(/supera los límites \(1500 nodos \/ 5000 enlaces\)/)).toBeInTheDocument();
  });

  it("exporta un SVG seguro con el nombre del site", async () => {
    let saved: Blob | undefined;
    vi.stubGlobal(
      "URL",
      Object.assign(URL, {
        createObjectURL: vi.fn((blob: Blob) => {
          saved = blob;
          return "blob:topo";
        }),
        revokeObjectURL: vi.fn(),
      }),
    );
    const names: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      names.push(this.download);
    });
    renderPage("viewer");
    await screen.findByTestId("topology-canvas");
    fireEvent.click(screen.getByRole("button", { name: "Exportar SVG" }));
    await waitFor(() => expect(names).toEqual(["sentra-topologia-principal.svg"]));
    expect(saved?.type).toBe("image/svg+xml");
  });
});
