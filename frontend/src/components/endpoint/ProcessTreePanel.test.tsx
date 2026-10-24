// @vitest-environment jsdom
// Fase 6E.4: el árbol de procesos nunca se pide entero. Al abrir solo se cargan las raíces y
// los hijos de un proceso se piden la primera vez que se despliega.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ASSET_ID, processNode } from "../../test/phase6e";
import { installFetch, type Call } from "../../test/sites";
import { ProcessTreePanel } from "./ProcessTreePanel";

const WININIT = "a".repeat(32);
const SERVICES = "b".repeat(32);
const SVCHOST = "c".repeat(32);
const EXPLORER = "d".repeat(32);
const PATH = `/assets/${ASSET_ID}/process-tree`;

let calls: Call[];

beforeEach(() => {
  calls = installFetch({
    [`GET ${PATH}`]: (_init, url) => {
      const parent = url.searchParams.get("parent");
      if (url.searchParams.get("search")) {
        return { body: { asset_id: ASSET_ID, parent: null, at: null, truncated: false, nodes: [processNode({ instance_key: SVCHOST, name: "svchost.exe", pid: 900, children_count: 3 })] } };
      }
      const nodes =
        parent === WININIT
          ? [processNode({ instance_key: SERVICES, name: "services.exe", pid: 700, children_count: 1 })]
          : parent === SERVICES
            ? [processNode({ instance_key: SVCHOST, name: "svchost.exe", pid: 900 })]
            : [
                processNode({ instance_key: WININIT, name: "wininit.exe", pid: 500, children_count: 1 }),
                processNode({ instance_key: EXPLORER, name: "explorer.exe", pid: 4000, parent_relation: "missing" }),
              ];
      return { body: { asset_id: ASSET_ID, parent, at: null, truncated: false, nodes } };
    },
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

const treeCalls = () => calls.filter((c) => c.path === PATH);

describe("ProcessTreePanel", () => {
  it("carga solo las raíces y despliega cada nivel bajo demanda, una sola vez", async () => {
    const onSelect = vi.fn();
    render(<ProcessTreePanel assetId={ASSET_ID} selected={undefined} onSelect={onSelect} />);
    const tree = await screen.findByRole("tree", { name: "Procesos" });
    expect(within(tree).getByRole("treeitem", { name: "wininit.exe · PID 500" })).toHaveAttribute("aria-expanded", "false");
    // Sin hijos no hay botón de desplegar; un padre no observado se marca.
    expect(within(tree).getByRole("treeitem", { name: "explorer.exe · PID 4000" })).not.toHaveAttribute("aria-expanded");
    expect(within(tree).getByText("padre no observado")).toBeInTheDocument();
    expect(treeCalls()).toHaveLength(1);
    expect(treeCalls()[0]?.url.searchParams.has("parent")).toBe(false);
    expect(screen.queryByText("services.exe")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Desplegar wininit.exe · PID 500" }));
    expect(await screen.findByText("services.exe")).toBeInTheDocument();
    expect(treeCalls()).toHaveLength(2);
    expect(treeCalls()[1]?.url.searchParams.get("parent")).toBe(WININIT);
    // El nieto no se ha pedido: solo un nivel por despliegue.
    expect(screen.queryByText("svchost.exe")).toBeNull();

    // Contraer y volver a desplegar reutiliza lo cargado.
    fireEvent.click(screen.getByRole("button", { name: "Contraer wininit.exe · PID 500" }));
    expect(screen.queryByText("services.exe")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Desplegar wininit.exe · PID 500" }));
    expect(await screen.findByText("services.exe")).toBeInTheDocument();
    expect(treeCalls()).toHaveLength(2);

    fireEvent.click(screen.getByRole("button", { name: "Desplegar services.exe · PID 700" }));
    expect(await screen.findByText("svchost.exe")).toBeInTheDocument();
    expect(treeCalls()).toHaveLength(3);
    expect(treeCalls()[2]?.url.searchParams.get("parent")).toBe(SERVICES);

    fireEvent.click(screen.getByRole("button", { name: "svchost.exe" }));
    expect(onSelect).toHaveBeenCalledWith(SVCHOST);
  });

  it("la búsqueda devuelve coincidencias planas sin desplegar hijos", async () => {
    render(<ProcessTreePanel assetId={ASSET_ID} selected={undefined} onSelect={() => undefined} />);
    await screen.findByText("wininit.exe");
    fireEvent.change(screen.getByLabelText("Buscar procesos"), { target: { value: "svchost" } });
    fireEvent.click(screen.getByRole("button", { name: "Aplicar" }));
    expect(await screen.findByText("svchost.exe")).toBeInTheDocument();
    await waitFor(() => expect(treeCalls().at(-1)?.url.searchParams.get("search")).toBe("svchost"));
    expect(screen.queryByRole("button", { name: /Desplegar svchost/ })).toBeNull();
  });
});
