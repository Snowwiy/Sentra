// Utilidades de test de la topología (Fase 6D.2). Datos sintéticos: direcciones de
// documentación y MACs inventadas. Solo las importan los *.test.tsx.
import type { TopologyLink, TopologyNode } from "../api/types";

export function topoNode(overrides: Partial<TopologyNode> & { id: string }): TopologyNode {
  return {
    kind: "asset",
    label: overrides.id,
    automatic_name: null,
    custom_label: null,
    asset_id: null,
    network_device_id: null,
    ip: null,
    mac: null,
    vendor: null,
    device_type: null,
    role: "endpoint",
    status: "online",
    managed: false,
    risk_score: null,
    risk_level: null,
    criticality: null,
    groups: ["network:192.0.2.0/24"],
    sources: ["discovery"],
    identity_confidence: "medium",
    link_count: 0,
    ...overrides,
  };
}

export function topoLink(overrides: Partial<TopologyLink> & { id: string; source: string; target: string }): TopologyLink {
  return {
    kind: "physical",
    medium: "wired",
    relation: "lldp",
    confidence: "high",
    source_port: null,
    target_port: null,
    evidence_sources: ["lldp"],
    present: true,
    first_seen_at: null,
    last_seen_at: null,
    last_evidence_at: null,
    review_state: "unreviewed",
    ...overrides,
  };
}
