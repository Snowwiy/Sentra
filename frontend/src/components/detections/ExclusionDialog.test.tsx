// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WithRole } from "../../test/auth";
import { ExclusionDialog } from "./ExclusionDialog";
import { RuleDetailsPanel } from "./RuleDetailsPanel";

// Datos sintéticos de test: no proceden de ningún host real.
const SHA = "ab".repeat(32);
const ASSET = "aaaaaaaa-0000-0000-0000-000000000001";

const json = (status: number, body: unknown) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

let posted: unknown[];
let reply: Response | undefined;

beforeEach(() => {
  posted = [];
  reply = undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_input: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posted.push(JSON.parse(String(init.body)));
        return reply ?? json(201, {});
      }
      return json(404, { error: { code: "not_found", message: "x" } });
    }),
  );
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

function renderDialog(initial: Parameters<typeof ExclusionDialog>[0]["initial"], onCreated = vi.fn()) {
  render(
    <MemoryRouter>
      <WithRole role="admin">
        <ExclusionDialog initial={initial} onClose={() => undefined} onCreated={onCreated} />
      </WithRole>
    </MemoryRouter>,
  );
  return screen.getByRole("dialog", { name: "Nueva excepción" });
}

describe("ExclusionDialog (Fase 7A.8)", () => {
  it("SCR-001 por ruta pide el SHA-256 y propone caducidad", async () => {
    const onCreated = vi.fn();
    const dialog = renderDialog({ ruleId: "SCR-001", field: "script_path", value: "C:\\s\\a.ps1" }, onCreated);
    expect(within(dialog).getByRole("note", { name: "Política de la regla" })).toHaveTextContent("SHA-256");
    fireEvent.change(within(dialog).getByLabelText("Justificación"), { target: { value: "Script de inventario" } });
    const problems = within(dialog).getByRole("list", { name: "Problemas del formulario" });
    expect(problems).toHaveTextContent("Una excepción por ruta de script exige también el SHA-256 del script.");
    const submit = within(dialog).getByRole("button", { name: "Crear excepción" });
    expect(submit).toBeDisabled();
    expect((within(dialog).getByLabelText(/Caduca \(obligatorio/) as HTMLInputElement).value).not.toBe("");

    fireEvent.change(within(dialog).getByLabelText(/SHA-256 del script que debe coincidir/), {
      target: { value: SHA.toUpperCase() },
    });
    expect(within(dialog).queryByRole("list", { name: "Problemas del formulario" })).not.toBeInTheDocument();
    fireEvent.click(submit);
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(posted[0]).toMatchObject({
      rule_id: "SCR-001",
      field: "script_path",
      value: "C:\\s\\a.ps1",
      require_sha256: SHA,
      port: null,
    });
  });

  it("NET-001 exige puerto y equipo y rechaza un intérprete entero", () => {
    const dialog = renderDialog({ ruleId: "NET-001", field: "exe", value: "python.exe" });
    fireEvent.change(within(dialog).getByLabelText("Justificación"), { target: { value: "Servidor de pruebas" } });
    const problems = within(dialog).getByRole("list", { name: "Problemas del formulario" });
    expect(problems).toHaveTextContent("intérprete del sistema");
    expect(problems).toHaveTextContent("NET-001 exige el puerto.");
    expect(problems).toHaveTextContent("NET-001 exige indicar el equipo.");
    fireEvent.change(within(dialog).getByLabelText("Valor exacto"), { target: { value: "C:\\apps\\srv.exe" } });
    fireEvent.change(within(dialog).getByLabelText("Puerto"), { target: { value: "8443" } });
    fireEvent.change(within(dialog).getByLabelText("Equipo (identificador, obligatorio)"), { target: { value: ASSET } });
    expect(within(dialog).queryByRole("list", { name: "Problemas del formulario" })).not.toBeInTheDocument();
    expect(within(dialog).getByRole("button", { name: "Crear excepción" })).toBeEnabled();
  });

  it("caducidad de más de 90 días no se puede enviar", () => {
    const dialog = renderDialog({ ruleId: "SCR-001", field: "script_sha256", value: SHA });
    fireEvent.change(within(dialog).getByLabelText("Justificación"), { target: { value: "Script de inventario" } });
    const later = new Date(Date.now() + 120 * 86_400_000);
    const local = new Date(later.getTime() - later.getTimezoneOffset() * 60_000).toISOString().slice(0, 16);
    fireEvent.change(within(dialog).getByLabelText(/Caduca \(obligatorio/), { target: { value: local } });
    expect(within(dialog).getByRole("list", { name: "Problemas del formulario" })).toHaveTextContent(
      "La caducidad de SCR-001 no puede superar 90 días.",
    );
    expect(within(dialog).getByRole("button", { name: "Crear excepción" })).toBeDisabled();
  });

  it("las reglas sin política no ofrecen campos de script", () => {
    const dialog = renderDialog({ ruleId: "PROC-001" });
    const select = within(dialog).getByLabelText("Campo");
    const options = within(select).getAllByRole("option").map((option) => option.getAttribute("value"));
    expect(options).not.toContain("script_path");
    expect(options).not.toContain("script_sha256");
    expect(within(dialog).queryByLabelText("Puerto")).not.toBeInTheDocument();
  });

  it("muestra claro un 422 exclusion_too_broad del servidor", async () => {
    reply = json(422, { error: { code: "exclusion_too_broad", message: "NET-001 exclusions require a port" } });
    const dialog = renderDialog({ ruleId: "SCR-001", field: "script_sha256", value: SHA });
    fireEvent.change(within(dialog).getByLabelText("Justificación"), { target: { value: "Script de inventario" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Crear excepción" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Excepción demasiado amplia: la regla exige el puerto.");
  });
});

describe("RuleDetailsPanel (Fase 7A.8)", () => {
  it("SCR-001 enseña script, proceso, contexto que falta y el aviso sobre Sentra", () => {
    render(
      <RuleDetailsPanel
        ruleId="SCR-001"
        details={{
          script: { script_path: "C:\\Sentra\\collect.ps1", script_sha256: SHA, script_origin: "file" },
          process: { process_name: "powershell.exe", process_cmdline: "powershell -File collect.ps1" },
          trigger: { keywords: ["Invoke-Expression"] },
          sentra: { script_name_match: true },
          missing_context: ["process_not_in_telemetry"],
          explanation: ["PowerShell marcó el bloque como sospechoso."],
        }}
      />,
    );
    const panel = screen.getByRole("region", { name: "Detalle del script" });
    expect(panel).toHaveTextContent("C:\\Sentra\\collect.ps1");
    expect(panel).toHaveTextContent("Invoke-Expression");
    expect(within(panel).getByRole("note", { name: "Relación con Sentra" })).toHaveTextContent("Un nombre no prueba nada");
    expect(within(panel).getByRole("list", { name: "Contexto que falta" }).children).toHaveLength(1);
    expect(within(panel).getByRole("list", { name: "Explicación" })).toHaveTextContent("PowerShell marcó el bloque");
  });

  it("NET-001 sin proceso conocido lo dice en vez de inventarlo", () => {
    render(<RuleDetailsPanel ruleId="NET-001" details={{ port: 8443, sensitive: true, owner: {} }} />);
    const panel = screen.getByRole("region", { name: "Detalle del puerto" });
    expect(panel).toHaveTextContent("Puerto 8443/tcp");
    expect(panel).toHaveTextContent("no se sabe qué proceso escucha");
  });

  it("otras reglas no muestran este bloque", () => {
    const { container } = render(<RuleDetailsPanel ruleId="BEH-001" details={{ script: {} }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
