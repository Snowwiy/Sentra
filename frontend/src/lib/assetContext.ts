import type {
  AssetContext,
  AssetContextUpdate,
  AssetCriticality,
  AssetEnvironment,
  AssetRole,
  DataSensitivity,
  ManagedState,
  NetworkZone,
} from "../api/types";

// Etiquetas en español de Asset Context (Fase 4L). Los valores (en inglés) son el contrato
// de la API; solo se traduce lo que ve el operador.

export const ROLE_LABELS: Record<AssetRole, string> = {
  workstation: "Estación de trabajo",
  server: "Servidor",
  domain_controller: "Controlador de dominio",
  database: "Base de datos",
  web_server: "Servidor web",
  application_server: "Servidor de aplicaciones",
  security_server: "Servidor de seguridad",
  network_device: "Dispositivo de red",
  router: "Router",
  switch: "Switch",
  firewall: "Firewall",
  wireless_ap: "Punto de acceso Wi-Fi",
  printer: "Impresora",
  iot: "IoT",
  mobile: "Móvil",
  virtual_machine: "Máquina virtual",
  container_host: "Host de contenedores",
  unknown: "Desconocido",
  other: "Otro",
};

export const ENVIRONMENT_LABELS: Record<AssetEnvironment, string> = {
  production: "Producción",
  staging: "Preproducción",
  development: "Desarrollo",
  testing: "Pruebas",
  lab: "Laboratorio",
  personal: "Personal",
  unknown: "Desconocido",
};

export const SENSITIVITY_LABELS: Record<DataSensitivity, string> = {
  unknown: "Desconocida",
  public: "Pública",
  internal: "Interna",
  confidential: "Confidencial",
  restricted: "Restringida",
};

export const ZONE_LABELS: Record<NetworkZone, string> = {
  unknown: "Desconocida",
  user: "Usuarios",
  server: "Servidores",
  management: "Gestión",
  dmz: "DMZ",
  guest: "Invitados",
  iot: "IoT",
  security: "Seguridad",
  lab: "Laboratorio",
};

export const MANAGED_STATE_LABELS: Record<ManagedState, string> = {
  DISCOVERED: "Descubierto (solo red)",
  MONITORED: "Monitorizado sin agente",
  MANAGED: "Gestionado (agente)",
};

export const SOURCE_LABELS: Record<string, string> = {
  manual: "manual",
  agent: "agente",
  discovery: "descubrimiento",
  inferred: "inferido",
};

export const FIELD_LABELS: Record<string, string> = {
  criticality: "Criticidad",
  criticality_rationale: "Justificación de la criticidad",
  role: "Rol",
  environment: "Entorno",
  owner: "Owner",
  department: "Equipo/Departamento",
  data_sensitivity: "Sensibilidad",
  network_zone: "Zona de red",
  internet_exposed: "Exposición Internet",
  tags: "Tags",
};

export const ROLE_ORDER = Object.keys(ROLE_LABELS) as AssetRole[];
export const ENVIRONMENT_ORDER = Object.keys(ENVIRONMENT_LABELS) as AssetEnvironment[];
export const SENSITIVITY_ORDER = Object.keys(SENSITIVITY_LABELS) as DataSensitivity[];
export const ZONE_ORDER = Object.keys(ZONE_LABELS) as NetworkZone[];

/** Tri-estado: null es "desconocido", nunca "no expuesto". */
export function exposureLabel(value: boolean | null): string {
  if (value === null) return "Desconocida";
  return value ? "Expuesto (confirmado)" : "No expuesto";
}

export type Exposure = "true" | "false" | "unknown";

export function exposureToForm(value: boolean | null): Exposure {
  return value === null ? "unknown" : value ? "true" : "false";
}

export function exposureFromForm(value: Exposure): boolean | null {
  return value === "unknown" ? null : value === "true";
}

/**
 * Normaliza etiquetas como el backend ("Critical Service" -> "critical-service"), quita
 * duplicados y vacíos. El backend vuelve a validar: esto solo evita sorpresas al guardar.
 */
export function parseTags(raw: string): string[] {
  const tags = raw
    .split(",")
    .map((t) => t.trim().toLowerCase().split(/\s+/).filter(Boolean).join("-"))
    .filter(Boolean);
  return [...new Set(tags)];
}

const TAG_RE = /^[a-z0-9][a-z0-9._-]{0,31}$/;

export function invalidTags(tags: string[]): string[] {
  return tags.filter((t) => !TAG_RE.test(t));
}

/** Estado editable del formulario de contexto (texto libre como string, "" = vacío). */
export interface ContextForm {
  criticality: AssetCriticality;
  criticality_rationale: string;
  role: AssetRole;
  environment: AssetEnvironment;
  owner: string;
  department: string;
  data_sensitivity: DataSensitivity;
  network_zone: NetworkZone;
  internet_exposed: Exposure;
  tags: string;
}

export function toForm(ctx: AssetContext): ContextForm {
  return {
    criticality: ctx.criticality,
    criticality_rationale: ctx.criticality_rationale ?? "",
    role: ctx.role,
    environment: ctx.environment,
    owner: ctx.owner ?? "",
    department: ctx.department ?? "",
    data_sensitivity: ctx.data_sensitivity,
    network_zone: ctx.network_zone,
    internet_exposed: exposureToForm(ctx.internet_exposed),
    tags: ctx.tags.join(", "),
  };
}

const clean = (value: string) => value.trim().replace(/\s+/g, " ");

/**
 * PATCH con SOLO los campos que el admin cambió (más la versión leída). Así un guardado no
 * reescribe campos que no tocó, y el historial/auditoría reflejan lo que de verdad cambió.
 */
export function buildUpdate(ctx: AssetContext, form: ContextForm): AssetContextUpdate {
  const body: AssetContextUpdate = { version: ctx.version };
  if (form.criticality !== ctx.criticality) body.criticality = form.criticality;
  if (clean(form.criticality_rationale) !== (ctx.criticality_rationale ?? "")) {
    body.criticality_rationale = clean(form.criticality_rationale) || null;
  }
  if (form.role !== ctx.role) body.role = form.role;
  if (form.environment !== ctx.environment) body.environment = form.environment;
  if (clean(form.owner) !== (ctx.owner ?? "")) body.owner = clean(form.owner) || null;
  if (clean(form.department) !== (ctx.department ?? "")) {
    body.department = clean(form.department) || null;
  }
  if (form.data_sensitivity !== ctx.data_sensitivity) body.data_sensitivity = form.data_sensitivity;
  if (form.network_zone !== ctx.network_zone) body.network_zone = form.network_zone;
  const exposure = exposureFromForm(form.internet_exposed);
  if (exposure !== ctx.internet_exposed) body.internet_exposed = exposure;
  const tags = parseTags(form.tags);
  const same = tags.length === ctx.tags.length && tags.every((t) => ctx.tags.includes(t));
  if (!same) body.tags = tags;
  return body;
}

/** Errores de validación locales (el backend valida igual). */
export function validateForm(
  form: ContextForm,
  limits: { owner: number; department: number; rationale: number; tags: number },
): string[] {
  const errors: string[] = [];
  if (clean(form.owner).length > limits.owner) errors.push(`Owner: máximo ${limits.owner} caracteres.`);
  if (clean(form.department).length > limits.department) {
    errors.push(`Equipo/Departamento: máximo ${limits.department} caracteres.`);
  }
  if (clean(form.criticality_rationale).length > limits.rationale) {
    errors.push(`Justificación: máximo ${limits.rationale} caracteres.`);
  }
  for (const [label, value] of [
    ["Owner", form.owner],
    ["Equipo/Departamento", form.department],
    ["Justificación", form.criticality_rationale],
  ] as const) {
    if (/[<>]/.test(value)) errors.push(`${label}: solo texto plano (sin < ni >).`);
  }
  const tags = parseTags(form.tags);
  if (tags.length > limits.tags) errors.push(`Máximo ${limits.tags} tags por activo.`);
  const bad = invalidTags(tags);
  if (bad.length) errors.push(`Tags no válidos: ${bad.join(", ")} (a-z, 0-9, . _ -; máx. 32).`);
  return errors;
}
