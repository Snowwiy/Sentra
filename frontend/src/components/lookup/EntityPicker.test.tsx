// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installFetch, type Call, type Handler } from "../../test/sites";
import { lookupItem, lookupResult } from "../../test/lookup";
import { EntityMultiPicker } from "./EntityMultiPicker";
import { EntityPicker } from "./EntityPicker";

// Datos sintéticos de test: no proceden de ningún host real.
const A1 = "a7c00000-0000-0000-0000-000000000001";
const A2 = "a7c00000-0000-0000-0000-000000000002";
const PC1 = lookupItem({ kind: "asset", id: A1, label: "pc-ventas", secondary: "10.0.0.10 · Principal", match_field: "ip", exact: true });
const PC2 = lookupItem({ kind: "asset", id: A2, label: "pc-almacen", secondary: "10.0.0.10 · Norte", match_field: "ip", exact: true });

let routes: Record<string, Handler>;
let calls: Call[];

beforeEach(() => {
  routes = {
    "GET /lookup/asset": (_init, url) => {
      const result = lookupResult(url, PC1, PC2);
      // Dos equipos con la misma IP exacta: el servidor lo marca como ambiguo.
      return { body: url.searchParams.has("q") ? { ...result, resolution: "ambiguous" } : result };
    },
  };
  calls = installFetch(routes);
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function Single({ initial = "", onPick = () => undefined }: { initial?: string; onPick?: (id: string) => void }) {
  const [value, setValue] = useState(initial);
  return (
    <EntityPicker
      kind="asset"
      label="Activo"
      value={value}
      siteId="s1"
      onChange={(id) => {
        setValue(id);
        onPick(id);
      }}
    />
  );
}

const searches = () => calls.filter((c) => c.path === "/lookup/asset" && c.url.searchParams.has("q"));

describe("EntityPicker (Fase 7C.3)", () => {
  it("busca por lo que el usuario reconoce, avisa de la ambigüedad y no elige solo", async () => {
    const onPick = vi.fn();
    render(<Single onPick={onPick} />);
    const input = screen.getByRole("combobox", { name: "Activo" });
    fireEvent.change(input, { target: { value: "10.0.0.10" } });
    expect(await screen.findByText("Varias coincidencias exactas: elige la correcta.")).toBeInTheDocument();
    const options = within(screen.getByRole("listbox", { name: "Opciones de Activo" })).getAllByRole("option");
    expect(options).toHaveLength(2);
    expect(options[0]).toHaveTextContent("exacta · IP");
    expect(onPick).not.toHaveBeenCalled();
    expect(searches()[0]!.url.searchParams.get("q")).toBe("10.0.0.10");
    expect(searches()[0]!.url.searchParams.get("site_id")).toBe("s1");
  });

  it("se maneja con el teclado: flechas, Intro elige y queda el nombre con Cambiar", async () => {
    const onPick = vi.fn();
    render(<Single onPick={onPick} />);
    const input = screen.getByRole("combobox", { name: "Activo" });
    fireEvent.change(input, { target: { value: "pc" } });
    await screen.findByRole("listbox");
    expect(input).toHaveAttribute("aria-expanded", "true");
    fireEvent.keyDown(input, { key: "ArrowDown" });
    expect(input.getAttribute("aria-activedescendant")).toMatch(/-1$/);
    fireEvent.keyDown(input, { key: "Enter" });
    expect(onPick).toHaveBeenCalledWith(A2);
    expect(screen.getByText("pc-almacen")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Cambiar" }));
    expect(onPick).toHaveBeenLastCalledWith("");
    expect(screen.getByRole("combobox", { name: "Activo" })).toHaveValue("");
  });

  it("Escape cierra la lista y un texto corto no consulta al servidor", async () => {
    render(<Single />);
    const input = screen.getByRole("combobox", { name: "Activo" });
    fireEvent.change(input, { target: { value: "p" } });
    await new Promise((r) => setTimeout(r, 300));
    expect(searches()).toHaveLength(0);
    fireEvent.change(input, { target: { value: "pc" } });
    await screen.findByRole("listbox");
    fireEvent.keyDown(input, { key: "Escape" });
    expect(screen.queryByRole("listbox")).toBeNull();
  });

  it("un id que llega de fuera se enseña con su nombre; uno sin acceso lo dice", async () => {
    render(<Single initial={A1} />);
    expect(await screen.findByText("pc-ventas")).toBeInTheDocument();
    cleanup();
    render(<Single initial="a7c00000-0000-0000-0000-0000000000ff" />);
    expect(await screen.findByRole("alert")).toHaveTextContent("No se encuentra o no tienes acceso");
  });

  it("un id pegado se resuelve directamente, sin búsqueda de texto", async () => {
    const onPick = vi.fn();
    render(<Single onPick={onPick} />);
    fireEvent.change(screen.getByRole("combobox", { name: "Activo" }), { target: { value: A1 } });
    fireEvent.click(await screen.findByRole("option", { name: /pc-ventas/ }));
    expect(onPick).toHaveBeenCalledWith(A1);
    expect(searches()).toHaveLength(0);
  });
});

describe("EntityMultiPicker (Fase 7C.3)", () => {
  function Multi({ initial }: { initial: string[] }) {
    const [values, setValues] = useState(initial);
    return (
      <>
        <EntityMultiPicker kind="asset" label="Activos" values={values} onChange={setValues} />
        <output data-testid="ids">{values.join(",")}</output>
      </>
    );
  }

  it("enseña los ids previos con su nombre, añade y quita sin duplicar", async () => {
    render(<Multi initial={[A1]} />);
    const chips = screen.getByRole("list", { name: "Activos elegidos" });
    expect(await within(chips).findByText("pc-ventas")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("combobox", { name: "Activos" }), { target: { value: "pc" } });
    fireEvent.click(await screen.findByRole("option", { name: /pc-almacen/ }));
    expect(screen.getByTestId("ids")).toHaveTextContent(`${A1},${A2}`);
    // Elegir otra vez uno ya presente no lo duplica.
    fireEvent.change(screen.getByRole("combobox", { name: "Activos" }), { target: { value: "pc" } });
    fireEvent.click(await screen.findByRole("option", { name: /pc-ventas/ }));
    expect(screen.getByTestId("ids")).toHaveTextContent(`${A1},${A2}`);
    fireEvent.click(screen.getByRole("button", { name: "Quitar pc-ventas" }));
    await waitFor(() => expect(screen.getByTestId("ids")).toHaveTextContent(A2));
    expect(screen.getByTestId("ids").textContent).toBe(A2);
  });
});
