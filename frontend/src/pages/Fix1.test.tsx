// @vitest-environment jsdom
// Fase 7B-Fix1: correlaciones causales, riesgo por clase, revisión de CORR-002, identidad,
// topología incompleta, hipótesis de duplicados y consola con contexto.
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RiskContribution, ToolExecutionOut, ToolOut, TopologyCoverage } from "../api/types";
import { CorrelationReviewPanel } from "../components/detections/CorrelationReviewPanel";
import { RuleDetailsPanel } from "../components/detections/RuleDetailsPanel";
import { entityLink, ToolOutput } from "../components/console/ToolOutput";
import { contributionDetail, riskByClass } from "../components/risk/RiskPanel";
import { TopologyCoverageNotice } from "../components/topology/TopologyLegend";
import { TIER_STATE_LABELS } from "../lib/identity7b";
import { hypothesisText } from "../lib/lifecycle";
import { WithRole } from "../test/auth";
import { installFetch, type Handler } from "../test/sites";
import { compatibleWith, count, quickTools } from "./ConsolePage";

const ASSET = "a7000000-0000-0000-0000-000000000001";
const DETECTION = "d7000000-0000-0000-0000-000000000001";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("CORR-002 v5 y PER-001 v3", () => {
  it("CORR-002 enseña la relación causal, la clasificación y la revisión", () => {
    render(
      <RuleDetailsPanel
        ruleId="CORR-002"
        details={{
          powershell_events: 200,
          distinct_scripts: 3,
          causal_links: [{ code: "install_event_after_script", strength: "strong", detail: "7045 de Updater posterior." }],
          persistence: {
            service: "Updater",
            source: "event_7045",
            classification: {
              kind: "installed",
              verification: "unverified",
              checks: [{ code: "signature", result: "fail", detail: "Firma NotSigned." }],
              explanation: "",
            },
          },
          correlation_review: { verdict: "causal", actor: "admin", explanation: ["Relación causal."] },
        }}
      />,
    );
    const panel = screen.getByRole("region", { name: "Detalle de la secuencia" });
    expect(within(panel).getByRole("list", { name: "Relación causal" })).toHaveTextContent(
      "Evento 7045 posterior al script (evidencia fuerte)",
    );
    expect(panel).toHaveTextContent("Scripts distintos");
    expect(within(panel).getByRole("note", { name: "Revisión de la correlación" })).toHaveTextContent(
      "Relación causal demostrada",
    );
    expect(panel).toHaveTextContent("No cumple · Firma NotSigned.");
  });

  it("SCR-001 muestra los servicios cercanos como contexto, no como causa", () => {
    render(
      <RuleDetailsPanel
        ruleId="SCR-001"
        details={{
          script: {},
          temporal_context: [
            { service: "WpnUserService_6df11", source: "inventory", position: "before_script", minutes: 5, verification: "verified" },
          ],
        }}
      />,
    );
    const list = screen.getByRole("list", { name: "Contexto temporal" });
    expect(list).toHaveTextContent("WpnUserService_6df11");
    expect(list).toHaveTextContent("5 min antes del script · Verificada");
  });

  it("PER-001 enseña el servicio y sus comprobaciones", () => {
    render(
      <RuleDetailsPanel
        ruleId="PER-001"
        details={{
          service: "WpnUserService_6df11",
          image_path: "C:\\Users\\Public\\svchost.exe",
          classification: {
            kind: "user_service_instance",
            verification: "suspicious",
            checks: [{ code: "host_image", result: "fail", detail: "no es System32" }],
            explanation: "Puede ser una suplantación.",
          },
        }}
      />,
    );
    const panel = screen.getByRole("region", { name: "Detalle del servicio" });
    expect(panel).toHaveTextContent("Sospechosa: lo comprobado no casa");
    expect(panel).toHaveTextContent("Ejecutable svchost.exe de System32");
  });
});

describe("Riesgo v7", () => {
  const base: RiskContribution = {
    factor: "detection",
    category: "execution",
    label: "SCR-001",
    points: 0,
    nominal_points: 10,
    detection_id: DETECTION,
    rule_id: "SCR-001",
    port: null,
    details: {},
  } as RiskContribution;

  it("explica por qué una contribución no suma y la accesibilidad del puerto", () => {
    expect(
      contributionDetail({ ...base, details: { absorbed_by: { rule_id: "CORR-002" }, absorbed_reason: "same_causal_chain" } }),
    ).toBe("Incluida en CORR-002 (sin doble conteo: misma cadena causal)");
    expect(contributionDetail({ ...base, factor: "repetition", points: 4, details: { detections: 50 } })).toBe(
      "50 detecciones agrupadas",
    );
    expect(
      contributionDetail({ ...base, factor: "exposure", port: 5432, details: { reachability: "self_only" } }),
    ).toContain("visto solo desde el propio equipo");
    // Campos ausentes o no numéricos nunca producen "NaN" ni "undefined".
    const text = contributionDetail({ ...base, factor: "repetition", details: { detections: Number.NaN } });
    expect(text).not.toMatch(/NaN|undefined/);
  });

  it("reparte el riesgo por clase solo con números finitos", () => {
    expect(riskByClass({ by_class: { direct: 10, correlated: 5, contextual: Number.NaN } })).toEqual([
      ["Directo", 10],
      ["Correlacionado", 5],
    ]);
    expect(riskByClass(null)).toEqual([]);
  });
});

describe("Revisión de correlaciones CORR-002", () => {
  it("vista previa, selección explícita y confirmación", async () => {
    const posts: unknown[] = [];
    const routes: Record<string, Handler> = {
      "POST /detections/correlation-review/preview": () => ({
        body: {
          items: [
            {
              detection_id: DETECTION,
              asset_id: ASSET,
              hostname: "ravenslg",
              rule_version: 4,
              status: "open",
              title: "PowerShell y servicio",
              verdict: "temporal_only",
              would_resolve: true,
              causal_links: [],
              temporal_context: {},
              explanation: ["El servicio se vio ANTES del primer script."],
            },
          ],
          causal: 0,
          temporal_only: 1,
          insufficient_evidence: 0,
        },
      }),
      "POST /detections/correlation-review/apply": (init) => {
        posts.push(JSON.parse(String(init.body)));
        return { body: { reviewed: 1, resolved: 1, kept: 0 } };
      },
    };
    installFetch(routes);
    render(
      <MemoryRouter>
        <WithRole role="analyst">
          <CorrelationReviewPanel />
        </WithRole>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Vista previa" }));
    expect(await screen.findByText(/Solo coincidencia en el tiempo/)).toBeInTheDocument();
    const apply = screen.getByRole("button", { name: "Aplicar revisión" });
    expect(apply).toBeDisabled();
    fireEvent.click(screen.getByRole("checkbox", { name: /He revisado la evidencia/ }));
    fireEvent.click(apply);
    expect(await screen.findByRole("status")).toHaveTextContent("1 resueltas");
    expect(posts).toEqual([{ detection_ids: [DETECTION], note: null, confirm: true }]);
  });

  it("un lector no ve el panel", () => {
    render(
      <MemoryRouter>
        <WithRole role="viewer">
          <CorrelationReviewPanel />
        </WithRole>
      </MemoryRouter>,
    );
    expect(screen.queryByText(/Revisar correlaciones/)).toBeNull();
  });
});

describe("Identidad, topología y duplicados", () => {
  it("los niveles se leen como confirmado, inferido o desconocido", () => {
    expect([TIER_STATE_LABELS.confirmed, TIER_STATE_LABELS.probable, TIER_STATE_LABELS.unresolved]).toEqual([
      "Confirmado",
      "Inferido",
      "Desconocido",
    ]);
  });

  it("la topología incompleta lo dice explícitamente", () => {
    const coverage: TopologyCoverage = {
      nodes: 12,
      nodes_without_links: 9,
      unlinked_by_type: { mobile: 3, unknown: 6 },
      links_by_kind: { logical: 3 },
      limitations: ["nodes_without_link_evidence", "no_physical_link_evidence"],
    };
    render(<TopologyCoverageNotice coverage={coverage} />);
    const note = screen.getByRole("note", { name: "Cobertura de la topología" });
    expect(note).toHaveTextContent("9 de 12 nodos sin enlace");
    expect(note).toHaveTextContent("no los une al gateway por estar en la misma subred");
    cleanup();
    const { container } = render(<TopologyCoverageNotice coverage={{ ...coverage, limitations: [] }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("la hipótesis de un duplicado se explica y la desconocida no se inventa", () => {
    expect(hypothesisText("reinstall")).toMatch(/Reinstalación probable/);
    expect(hypothesisText("unknown")).toBeNull();
    expect(hypothesisText(undefined)).toBeNull();
  });
});

describe("Consola con contexto", () => {
  const tool = (id: string, required: string[], policy: ToolOut["policy"] = "direct") =>
    ({ id, policy, input_schema: { required } }) as unknown as ToolOut;

  it("ofrece las herramientas que el contexto puede rellenar", () => {
    const tools = [
      tool("asset.profile", ["asset_id"]),
      tool("detection.explain", ["detection_id"]),
      tool("detection.context", ["asset_id", "detection_id"]),
      tool("case.link", ["incident_id"], "preview_confirm"),
      tool("search.text", ["text"]),
    ];
    const both = { asset_id: ASSET, detection_id: DETECTION };
    expect(quickTools(tools, both).map((t) => t.id)).toEqual(["asset.profile", "detection.explain", "detection.context"]);
    expect(quickTools(tools, { asset_id: ASSET }).map((t) => t.id)).toEqual(["asset.profile"]);
    expect(tools.filter((t) => compatibleWith(t, { asset_id: ASSET })).map((t) => t.id)).toEqual([
      "asset.profile",
      "search.text",
    ]);
  });

  it("los ids de la salida enlazan a su ficha y el texto sigue siendo texto", () => {
    expect(entityLink("asset_id", ASSET)).toBe(`/assets/${ASSET}`);
    expect(entityLink("asset_id", "<b>x</b>")).toBeNull();
    expect(entityLink("hostname", ASSET)).toBeNull();
  });

  it("regresión: ningún número inválido llega a React como hijo NaN", () => {
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});
    const execution = {
      execution_id: "e1",
      status: "succeeded",
      summary: null,
      error_code: null,
      output: { asset_id: ASSET, score: Number.NaN, rows: [{ detection_id: DETECTION, count: Number.NaN }] },
      created_at: new Date().toISOString(),
      duration_ms: null,
      truncated: false,
      output_sha256: null,
    } as unknown as ToolExecutionOut;
    render(
      <MemoryRouter>
        <ToolOutput execution={execution} />
      </MemoryRouter>,
    );
    expect(screen.getByRole("link", { name: ASSET })).toHaveAttribute("href", `/assets/${ASSET}`);
    expect(screen.getByRole("link", { name: DETECTION })).toHaveAttribute("href", `/detections/${DETECTION}`);
    expect(count(Number.NaN)).toBe("—");
    expect(count(undefined)).toBe("—");
    expect(count(3)).toBe("3");
    expect(errors.mock.calls.flat().join(" ")).not.toMatch(/NaN/);
  });

  it("abre con la detección y su activo como contexto", async () => {
    installFetch({
      "GET /tools": () => ({ body: { items: [tool("asset.profile", ["asset_id"])], enabled: true } }),
      "GET /tools/executions": () => ({ body: { items: [], total: 0 } }),
      [`GET /detections/${DETECTION}`]: () => ({
        body: { detection_id: DETECTION, asset_id: ASSET, rule_id: "CORR-002", title: "Secuencia", hostname: "ravenslg" },
      }),
      "GET /detections": () => ({ body: { items: [], total: 0, limit: 10, offset: 0 } }),
    });
    const { ConsolePage } = await import("./ConsolePage");
    render(
      <MemoryRouter initialEntries={[`/console?detection=${DETECTION}`]}>
        <WithRole role="analyst">
          <ConsolePage />
        </WithRole>
      </MemoryRouter>,
    );
    const workspace = await screen.findByRole("region", { name: "Workspace" });
    expect(await within(workspace).findByText("CORR-002 · Secuencia · ravenslg")).toBeInTheDocument();
    await waitFor(() => expect(within(workspace).getByRole("link", { name: "activo" })).toHaveAttribute("href", `/assets/${ASSET}`));
  });
});
