import type { Agent, CredentialStatus, EnrollmentTokenState } from "../../api/types";

export type AgentState = "online" | "offline" | "revoked" | "pending";

/** What the operator cares about first: revoked beats liveness; never reported = pending. */
export function agentState(agent: Agent): AgentState {
  if (agent.credential_status === "revoked") return "revoked";
  if (agent.status === "online") return "online";
  if (agent.status === "offline") return "offline";
  return "pending";
}

const STATE_LABELS: Record<AgentState, string> = {
  online: "Online",
  offline: "Offline",
  revoked: "Revoked",
  pending: "Pending",
};

const STATE_TITLES: Record<AgentState, string> = {
  online: "Reporta con normalidad",
  offline: "Sin contacto dentro del plazo de heartbeat",
  revoked: "Revocado por un operador: no puede enviar datos",
  pending: "Registrado, todavía sin reportar (o pendiente de volver a registrarse)",
};

const STATE_CLASSES: Record<AgentState, string> = {
  online: "online",
  offline: "offline",
  revoked: "revoked",
  pending: "unknown",
};

export function AgentStateBadge({ agent }: { agent: Agent }) {
  const state = agentState(agent);
  return (
    <span className={`status status--${STATE_CLASSES[state]}`} title={STATE_TITLES[state]}>
      <span className="status__dot" aria-hidden="true" />
      {STATE_LABELS[state]}
    </span>
  );
}

export const CREDENTIAL_LABELS: Record<CredentialStatus, string> = {
  active: "Active",
  revoked: "Revoked",
  re_enrollment_required: "Re-enrollment required",
};

const CREDENTIAL_CLASSES: Record<CredentialStatus, string> = {
  active: "badge--ok",
  revoked: "badge--crit",
  re_enrollment_required: "badge--warn",
};

export function CredentialBadge({ status }: { status: CredentialStatus }) {
  return <span className={`badge ${CREDENTIAL_CLASSES[status]}`}>{CREDENTIAL_LABELS[status]}</span>;
}

export const TOKEN_STATE_LABELS: Record<EnrollmentTokenState, string> = {
  active: "Active",
  consumed: "Consumed",
  expired: "Expired",
  revoked: "Revoked",
};

const TOKEN_STATE_CLASSES: Record<EnrollmentTokenState, string> = {
  active: "badge--ok",
  consumed: "",
  expired: "badge--warn",
  revoked: "badge--crit",
};

export function TokenStateBadge({ state }: { state: EnrollmentTokenState }) {
  return <span className={`badge ${TOKEN_STATE_CLASSES[state]}`}>{TOKEN_STATE_LABELS[state]}</span>;
}

export const PLATFORM_LABELS: Record<Agent["platform"], string> = {
  linux: "Linux",
  windows: "Windows",
  other: "Otra",
};
