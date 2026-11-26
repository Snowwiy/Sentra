// @vitest-environment jsdom
import { cleanup, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it } from "vitest";
import type { SiemEventDetail } from "../../api/types";
import { SiemAttributionView, SiemLinksView, WazuhProvenance } from "./SiemEventDetail";

// Alerta SINTÉTICA con la forma que devuelve la API para una fuente wazuh_alerts (Fase 7F.5).
const ISO = "2026-11-24T08:00:00Z";
const DETECTION_ID = "d7000000-0000-0000-0000-000000000001";
const WAZUH: SiemEventDetail = {
  event_id: "e7000000-0000-0000-0000-000000000005",
  schema_version: 1,
  normalization_version: "wazuh_alerts/1.0.0",
  source_id: "57000000-0000-0000-0000-000000000005",
  source_name: "wazuh",
  source_type: "wazuh_alerts",
  site_id: "51000000-0000-0000-0000-000000000001",
  event_type: "wazuh.alert",
  category: "detection",
  timestamp: ISO,
  collected_at: ISO,
  received_at: ISO,
  time_quality: "source",
  severity: "unknown",
  source_severity: "level 10",
  confidence: "low",
  hostname: "web01",
  source_ip: "203.0.113.77",
  destination_ip: null,
  source_port: null,
  destination_port: null,
  protocol: null,
  username: "root",
  process_name: null,
  action: null,
  outcome: null,
  signature_id: "5712",
  rule_id: "5712",
  message: "sshd: brute force trying to get access to the system.",
  tags: ["sshd"],
  mitre_techniques: ["T1110"],
  external_id: "1732435200.123456",
  flow_ref: null,
  raw_reference: "upload:abc#1",
  evidence_hash: "b".repeat(64),
  asset: null,
  attribution: {
    verdict: "hostname_hint",
    candidates: [{ asset_id: null, asset_name: null, role: "host", method: "hostname_match", confidence: "low", value: "web01" }],
    ambiguous: 0,
    origin: "probable_match",
  },
  links: [
    {
      kind: "detection",
      target_ref: DETECTION_ID,
      method: "same_asset_topic_time",
      confidence: "medium",
      explanation: "Probablemente el mismo hecho visto por Wazuh: no se crea otra detección.",
      created_at: ISO,
    },
  ],
  raw_excerpt: null,
  data: {
    origin_product: "wazuh",
    alert_id: "1732435200.123456",
    rule_level: 10,
    rule_groups: ["syslog", "sshd", "authentication_failures"],
    agent_id: "003",
    agent_name: "web01",
    agent_ip: "10.80.0.15",
    manager: "wazuh-manager",
    decoder: "sshd",
    location: "/var/log/auth.log",
    mitre_tactic_names: ["Credential Access"],
  },
};

afterEach(cleanup);

describe("SiemEventDetail con Wazuh", () => {
  it("shows Wazuh provenance as data from Wazuh", () => {
    render(<WazuhProvenance event={WAZUH} />);
    expect(screen.getByText("Según Wazuh")).toBeInTheDocument();
    expect(screen.getByText("003 · web01 · 10.80.0.15")).toBeInTheDocument();
    expect(screen.getByText("syslog, sshd, authentication_failures")).toBeInTheDocument();
    expect(screen.getByText(/no identifica el activo por sí solo/)).toBeInTheDocument();
  });

  it("renders nothing for other sources", () => {
    const { container } = render(<WazuhProvenance event={{ ...WAZUH, source_type: "suricata_eve" }} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("explains hostname hints, probable matches and links the native detection", () => {
    render(
      <MemoryRouter>
        <SiemAttributionView attribution={WAZUH.attribution} />
        <SiemLinksView links={WAZUH.links} />
      </MemoryRouter>,
    );
    expect(screen.getByText(/solo coincide el nombre de equipo/)).toBeInTheDocument();
    expect(screen.getByText(/no se crea otra$/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: DETECTION_ID })).toHaveAttribute("href", `/detections/${DETECTION_ID}`);
  });
});
