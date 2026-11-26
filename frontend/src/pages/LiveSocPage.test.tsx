// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SiteProvider } from "../site/SiteContext";
import { WithRole } from "../test/auth";
import { installFetch, SITES } from "../test/sites";
import { LiveSocPage } from "./LiveSocPage";

// EventSource falso: el test emite los mensajes que mandaría el servidor (datos sintéticos).
class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  readyState = 1;
  onerror: (() => void) | null = null;
  listeners = new Map<string, ((event: MessageEvent<string>) => void)[]>();
  closed = false;
  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }
  addEventListener(type: string, fn: (event: MessageEvent<string>) => void) {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }
  emit(type: string, data: unknown, id = "") {
    const event = new MessageEvent(type, { data: JSON.stringify(data), lastEventId: id });
    for (const fn of this.listeners.get(type) ?? []) fn(event);
  }
  close() {
    this.closed = true;
    this.readyState = 2;
  }
}

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal("EventSource", FakeEventSource);
  installFetch({
    "GET /sites": () => ({ body: { items: SITES } }),
    "GET /siem/overview": () => ({
      body: {
        window_hours: 24,
        sources_total: 1,
        sources_by_status: { healthy: 1 },
        events: 3,
        rejected: 0,
        duplicates: 0,
        by_source_type: [],
        by_severity: [],
        by_category: [],
        lagging_sources: 0,
        last_event_received_at: null,
      },
    }),
  });
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

function renderPage() {
  return render(
    <MemoryRouter>
      <WithRole role="analyst">
        <SiteProvider>
          <LiveSocPage />
        </SiteProvider>
      </WithRole>
    </MemoryRouter>,
  );
}

describe("LiveSocPage", () => {
  it("shows the stream state, real items only and hostile text as text", async () => {
    renderPage();
    expect(screen.getByRole("status", { name: "Estado del stream" })).toHaveTextContent("Conectando");
    expect(screen.getByText("Sin eventos nuevos todavía.")).toBeInTheDocument();
    const es = FakeEventSource.instances[0]!;
    expect(es.url).toBe("/api/v1/live/stream");
    act(() => {
      es.emit("status", { state: "live", channels: ["detection", "alert", "incident", "siem"] }, "d0-a0-i0-s0");
      es.emit(
        "detection",
        { id: "d7000000-0000-0000-0000-000000000001", rule_id: "AUTH-001", title: "Fuerza bruta", asset_name: "web01", severity: "high" },
        "d1-a0-i0-s0",
      );
      es.emit("siem", { id: "e1", source_name: "suricata", event_type: "ids.alert", message: '<img src=x onerror="alert(1)">' }, "d1-a0-i0-s1");
    });
    expect(screen.getByRole("status", { name: "Estado del stream" })).toHaveTextContent("En directo");
    expect(screen.getByRole("link", { name: /AUTH-001: Fuerza bruta · web01/ })).toHaveAttribute(
      "href",
      "/detections/d7000000-0000-0000-0000-000000000001",
    );
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByRole("button", { name: "Detecciones: 1" })).toBeInTheDocument();
    expect(await screen.findByText("Operativa: 1")).toBeInTheDocument();
  });

  it("reports degraded, reconnecting and ended sessions without retrying", () => {
    vi.useFakeTimers();
    try {
      renderPage();
      const es = FakeEventSource.instances[0]!;
      act(() => es.emit("status", { state: "degraded", reason: "backlog_skipped" }));
      expect(screen.getByText(/demasiados eventos pendientes/)).toBeInTheDocument();
      act(() => {
        es.readyState = 0;
        es.onerror?.();
      });
      expect(screen.getByRole("status", { name: "Estado del stream" })).toHaveTextContent("Reconectando");
      act(() => es.emit("session_ended", { reason: "session_invalid" }));
      expect(screen.getByRole("status", { name: "Estado del stream" })).toHaveTextContent("Desconectado");
      expect(es.closed).toBe(true);
      act(() => vi.advanceTimersByTime(120_000));
      expect(FakeEventSource.instances).toHaveLength(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it("reopens with the last cursor after a hard close", () => {
    vi.useFakeTimers();
    try {
      renderPage();
      const es = FakeEventSource.instances[0]!;
      act(() => {
        es.emit("status", { state: "live", channels: ["alert"] }, "d5-a6-i7-s8");
        es.readyState = 2;
        es.onerror?.();
      });
      expect(screen.getByRole("status", { name: "Estado del stream" })).toHaveTextContent("Desconectado");
      act(() => vi.advanceTimersByTime(2000));
      expect(FakeEventSource.instances[1]?.url).toBe("/api/v1/live/stream?resume=d5-a6-i7-s8");
    } finally {
      vi.useRealTimers();
    }
  });
});
