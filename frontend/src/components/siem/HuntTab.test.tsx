// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SiemEventRead } from "../../api/types";
import { WithRole } from "../../test/auth";
import { installFetch, type Call } from "../../test/sites";
import { buildFilter, formFromSaved, HuntTab } from "./HuntTab";

// Eventos SINTÉTICOS con la forma de la API (Fase 7F.6).
const ISO = "2026-11-24T08:00:00Z";
function event(n: number, message: string): SiemEventRead {
  return {
    event_id: `e7000000-0000-0000-0000-00000000000${n}`,
    schema_version: 1,
    normalization_version: "suricata_eve/1.0.0",
    source_id: "57000000-0000-0000-0000-000000000001",
    source_name: "suricata",
    source_type: "suricata_eve",
    site_id: "51000000-0000-0000-0000-000000000001",
    event_type: "ids.alert",
    category: "detection",
    timestamp: ISO,
    collected_at: null,
    received_at: ISO,
    time_quality: "source",
    severity: "high",
    source_severity: "1",
    confidence: "low",
    hostname: null,
    source_ip: "198.51.100.23",
    destination_ip: "10.70.0.20",
    source_port: 50000,
    destination_port: 445,
    protocol: "tcp",
    username: null,
    process_name: null,
    action: null,
    outcome: null,
    signature_id: "1:2024217:3",
    rule_id: "1:2024217:3",
    message,
    tags: [],
    mitre_techniques: ["T1210"],
    external_id: null,
    flow_ref: null,
    raw_reference: "upload:x#1",
    evidence_hash: "c".repeat(64),
    asset: null,
    attribution: null,
  };
}

let calls: Call[];

beforeEach(() => {
  calls = installFetch({
    "GET /siem/searches": () => ({
      body: {
        items: [
          {
            search_id: "55000000-0000-0000-0000-000000000001",
            name: "SMB",
            query: { since: "2026-11-24T00:00:00Z", until: "2026-11-24T06:00:00Z", ip: "10.70.0.0/16" },
            created_at: ISO,
            updated_at: ISO,
          },
        ],
      },
    }),
    "POST /siem/search": (init) => {
      const body = JSON.parse(String(init.body));
      return body.cursor
        ? { body: { items: [event(2, "segunda página")], next_cursor: null, count: null, count_capped: false, took_ms: 3 } }
        : { body: { items: [event(1, '<img src=x onerror="alert(1)">')], next_cursor: "abc", count: 2, count_capped: false, took_ms: 4 } };
    },
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("HuntTab", () => {
  it("builds a typed filter with only the filled fields", () => {
    const now = new Date("2026-11-24T10:00:00Z");
    const form = { ...formFromSaved({}), hours: "2", ip: " 10.0.0.0/24 ", mitre: "t1110", port: "x" };
    expect(buildFilter(form, "site-1", now)).toEqual({
      since: "2026-11-24T08:00:00.000Z",
      until: "2026-11-24T10:00:00.000Z",
      site_id: "site-1",
      ip: "10.0.0.0/24",
      mitre_technique: "T1110",
    });
  });

  it("loads a saved search window as hours", () => {
    expect(formFromSaved({ since: "2026-11-24T00:00:00Z", until: "2026-11-24T06:00:00Z", ip: "10.70.0.0/16" })).toMatchObject({
      hours: "6",
      ip: "10.70.0.0/16",
    });
  });

  it("searches, pages with the cursor and renders hostile text inert", async () => {
    render(
      <MemoryRouter>
        <WithRole role="analyst">
          <HuntTab scopeId={undefined} />
        </WithRole>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByRole("button", { name: "SMB" }));
    fireEvent.click(screen.getByRole("button", { name: "Buscar" }));
    expect(await screen.findByText(/2 eventos/)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
    const first = JSON.parse(String(calls.find((c) => c.path === "/siem/search")?.init.body));
    expect(first).toMatchObject({ ip: "10.70.0.0/16", limit: 50, cursor: null, count: true });
    fireEvent.click(screen.getByRole("button", { name: "Cargar más" }));
    expect(await screen.findByText("segunda página")).toBeInTheDocument();
    const second = JSON.parse(String(calls.filter((c) => c.path === "/siem/search")[1]?.init.body));
    expect(second).toMatchObject({ cursor: "abc", count: false });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Cargar más" })).toBeNull());
  });
});
