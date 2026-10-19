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
  online: "En línea",
  offline: "Sin conexión",
  revoked: "Revocado",
  pending: "Pendiente",
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
  active: "Activa",
  revoked: "Revocada",
  re_enrollment_required: "Requiere volver a registrarse",
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
  active: "Activo",
  consumed: "Usado",
  expired: "Caducado",
  revoked: "Revocado",
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
  macos: "macOS",
  other: "Otra",
};

/** Etiqueta de una plataforma que llega como texto libre (p. ej. expected_platform de un token). */
export function platformLabel(value: string | null | undefined): string | null {
  if (!value) return null;
  return (PLATFORM_LABELS as Record<string, string>)[value] ?? value;
}
