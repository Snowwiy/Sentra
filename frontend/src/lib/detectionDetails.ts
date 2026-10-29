// Fase 7A.8: lectura defensiva de `details` de SCR-001, CORR-002 y NET-001 (backend
// app/detection/rules.py: script_details, CORR-002 y _port_exposed). Todo llega como datos sin
// tipar: aquí se convierte en estructuras con solo los campos que existen, para que la vista
// nunca muestre "undefined" ni interprete un valor como HTML.

/** Contexto que faltó al registrar el script, en lenguaje claro. */
export const MISSING_CONTEXT_LABELS: Record<string, string> = {
  agent_without_script_context:
    "El agente no envió el contexto del script (ruta, bloque o PID): probablemente es anterior a la versión 0.6.0.",
  process_not_in_telemetry:
    "Se conoce el PID, pero ese proceso no aparece en la telemetría del equipo: no se sabe qué lo ejecutó.",
  script_hash_unavailable:
    "El script se ejecutó desde un fichero, pero no se pudo calcular su SHA-256: sin él no se puede crear una excepción exacta.",
};

export const SCRIPT_ORIGIN_LABELS: Record<string, string> = {
  file: "Fichero",
  inline: "En línea (consola, -Command o -EncodedCommand)",
};

export const SENTRA_COMPONENT_LABELS: Record<string, string> = {
  sentra_agent: "el agente de Sentra",
  sentra_sensor: "el sensor de Sentra",
  sentra_api: "la API de Sentra",
};

export const PERSISTENCE_SOURCE_LABELS: Record<string, string> = {
  event_7045: "Evento 7045 (instalación de servicio)",
  inventory: "Inventario de servicios (sin ruta ni cuenta de instalación)",
};

export const SEQUENCE_LABELS: Record<string, string> = {
  powershell_first: "Primero el script, después el servicio",
  service_first: "Primero el servicio, después el script (relación más débil)",
};

// Fase 7B-Fix1: relación causal de CORR-002 v5 (app/detection/rules.py causal_links).
export const CAUSAL_LINK_LABELS: Record<string, string> = {
  install_event_after_script: "Evento 7045 posterior al script",
  script_started_service_binary: "Un proceso hijo del PowerShell ejecutó el binario del servicio",
  suspicious_service_after_script: "Servicio sospechoso visto después del script",
  service_modified_after_script: "Ejecutable de un servicio cambiado después del script",
};

export const SERVICE_KIND_LABELS: Record<string, string> = {
  installed: "Instalado (evento 7045)",
  user_service_instance: "Instancia de servicio por usuario",
  modified: "Servicio existente modificado",
  discovered: "Descubierto por el inventario",
};

export const VERIFICATION_LABELS: Record<string, string> = {
  verified: "Verificada",
  probable: "Probable (faltan datos del agente)",
  unverified: "Sin verificar",
  suspicious: "Sospechosa: lo comprobado no casa",
};

export const CHECK_LABELS: Record<string, string> = {
  template: "Plantilla del servicio",
  session_peers: "Otras instancias de la sesión",
  service_type: "Tipo en el registro (bit 0x80)",
  host_image: "Ejecutable svchost.exe de System32",
  host_group: "Grupo de svchost (-k)",
  signature: "Firma Authenticode",
  previous_image: "Ejecutable anterior",
};

export const CHECK_RESULT_LABELS: Record<string, string> = { pass: "Cumple", fail: "No cumple", missing: "Sin dato" };

export const REVIEW_VERDICT_LABELS: Record<string, string> = {
  causal: "Relación causal demostrada",
  temporal_only: "Solo coincidencia en el tiempo",
  insufficient_evidence: "Evidencia insuficiente para reevaluar",
};

export type Fields = [label: string, value: string][];

const record = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

/** Texto plano de un valor (los objetos no se esperan aquí; si llegan se serializan). */
export function plainText(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function fields(source: Record<string, unknown>, labels: [key: string, label: string][]): Fields {
  return labels
    .map(([key, label]): [string, string] => [label, plainText(source[key])])
    .filter(([, value]) => value !== "");
}

const strings = (value: unknown): string[] =>
  Array.isArray(value) ? value.map(plainText).filter((item) => item !== "") : [];

export interface ScriptInfo {
  script: Fields;
  process: Fields;
  pid: string;
  userSid: string;
  keywords: string[];
  sentraNameMatch: boolean;
  sentraComponent: string | null;
  explanation: string[];
  missing: string[];
}

/** Bloque de script_details() (SCR-001 y cada elemento de CORR-002 details.scripts). */
export function scriptInfo(raw: unknown): ScriptInfo {
  const data = record(raw);
  const script = record(data.script);
  const origin = plainText(script.script_origin);
  const part = plainText(script.script_part);
  const parts = plainText(script.script_parts);
  const scriptFields = fields(script, [
    ["script_path", "Ruta"],
    ["script_name", "Nombre"],
    ["script_sha256", "SHA-256"],
    ["script_block_id", "Id del bloque"],
  ]);
  if (part && parts) scriptFields.push(["Parte", `${part} de ${parts}`]);
  if (origin) scriptFields.push(["Origen", SCRIPT_ORIGIN_LABELS[origin] ?? origin]);
  const sentra = record(data.sentra);
  const trigger = record(data.trigger);
  const component = plainText(sentra.component);
  return {
    script: scriptFields,
    process: fields(record(data.process), [
      ["process_name", "Proceso"],
      ["process_exe", "Ejecutable"],
      ["process_cmdline", "Línea de comandos"],
      ["process_user", "Usuario"],
      ["process_sha256", "SHA-256 del proceso"],
      ["process_signer", "Firmante"],
      ["parent_name", "Proceso padre"],
      ["parent_exe", "Ejecutable del padre"],
      ["parent_cmdline", "Línea de comandos del padre"],
    ]),
    pid: plainText(data.pid),
    userSid: plainText(data.user_sid),
    keywords: strings(trigger.keywords),
    sentraNameMatch: sentra.script_name_match === true,
    sentraComponent: component || null,
    explanation: strings(data.explanation),
    missing: strings(data.missing_context),
  };
}

export interface CausalLink {
  code: string;
  label: string;
  strength: string;
  detail: string;
}

export function causalLinks(raw: unknown): CausalLink[] {
  return (Array.isArray(raw) ? raw : []).map((item) => {
    const link = record(item);
    const code = plainText(link.code);
    return {
      code,
      label: CAUSAL_LINK_LABELS[code] ?? code,
      strength: plainText(link.strength),
      detail: plainText(link.detail),
    };
  });
}

export interface ServiceClassInfo {
  kind: string;
  verification: string;
  explanation: string;
  checks: Fields;
}

/** Clasificación de un servicio (app/detection/service_identity.py). */
export function serviceClassInfo(raw: unknown): ServiceClassInfo | null {
  const data = record(raw);
  const kind = plainText(data.kind);
  if (!kind) return null;
  const checks = (Array.isArray(data.checks) ? data.checks : []).map((item): [string, string] => {
    const check = record(item);
    const code = plainText(check.code);
    const result = plainText(check.result);
    const detail = plainText(check.detail);
    return [CHECK_LABELS[code] ?? code, `${CHECK_RESULT_LABELS[result] ?? result}${detail ? ` · ${detail}` : ""}`];
  });
  const verification = plainText(data.verification);
  return {
    kind: SERVICE_KIND_LABELS[kind] ?? kind,
    verification: VERIFICATION_LABELS[verification] ?? verification,
    explanation: plainText(data.explanation),
    checks,
  };
}

export interface TemporalContextItem {
  service: string;
  source: string;
  position: string;
  minutes: string;
  verification: string;
}

/** Servicios cercanos a un script sin relación causal (SCR-001 details.temporal_context). */
export function temporalContext(raw: unknown): TemporalContextItem[] {
  return (Array.isArray(raw) ? raw : []).map((item) => {
    const data = record(item);
    const source = plainText(data.source);
    const verification = plainText(data.verification);
    return {
      service: plainText(data.service),
      source: PERSISTENCE_SOURCE_LABELS[source] ?? source,
      position: data.position === "before_script" ? "antes del script" : "después del script",
      minutes: plainText(data.minutes),
      verification: VERIFICATION_LABELS[verification] ?? verification,
    };
  });
}

export interface CorrelationReviewInfo {
  verdict: string;
  actor: string;
  reviewedAt: string;
  explanation: string[];
}

export function correlationReviewInfo(raw: unknown): CorrelationReviewInfo | null {
  const data = record(raw);
  const verdict = plainText(data.verdict);
  if (!verdict) return null;
  return {
    verdict: REVIEW_VERDICT_LABELS[verdict] ?? verdict,
    actor: plainText(data.actor),
    reviewedAt: plainText(data.reviewed_at),
    explanation: strings(data.explanation),
  };
}

export interface ScriptCorrelationInfo {
  scripts: ScriptInfo[];
  persistence: Fields;
  sentraServiceName: boolean;
  sequence: string;
  explanation: string[];
  counts: Fields;
  links: CausalLink[];
  classification: ServiceClassInfo | null;
  review: CorrelationReviewInfo | null;
}

/** Detalles de CORR-002 (PowerShell sospechoso + servicio nuevo). */
export function correlationInfo(raw: unknown): ScriptCorrelationInfo {
  const data = record(raw);
  const persistence = record(data.persistence);
  const source = plainText(persistence.source);
  const persistenceFields = fields(persistence, [
    ["service", "Servicio"],
    ["image_path", "Ejecutable"],
    ["account", "Cuenta"],
    ["start_type", "Inicio"],
    ["unusual_location", "Ubicación inusual"],
  ]);
  if (source) persistenceFields.push(["Fuente", PERSISTENCE_SOURCE_LABELS[source] ?? source]);
  return {
    scripts: (Array.isArray(data.scripts) ? data.scripts : []).map(scriptInfo),
    persistence: persistenceFields,
    sentraServiceName: persistence.sentra_service_name === true,
    sequence: plainText(data.sequence),
    explanation: strings(data.explanation),
    links: causalLinks(data.causal_links),
    classification: serviceClassInfo(persistence.classification),
    review: correlationReviewInfo(data.correlation_review),
    counts: fields(data, [
      ["powershell_events", "Bloques de PowerShell"],
      ["distinct_scripts", "Scripts distintos"],
      ["excluded_powershell_events", "Bloques con excepción (no cuentan)"],
      ["new_processes", "Procesos nuevos"],
      ["unusual_processes", "Procesos en ubicación inusual"],
    ]),
  };
}

export interface PortExposureInfo {
  port: string;
  serviceHint: string;
  sensitive: boolean;
  owner: Fields;
  sentraComponent: string | null;
  explanation: string[];
}

/** Detalles de NET-001 (puerto expuesto y proceso que escucha, si se conoce). */
export function portExposureInfo(raw: unknown): PortExposureInfo {
  const data = record(raw);
  const owner = record(data.owner);
  const component = plainText(owner.sentra_component);
  return {
    port: plainText(data.port),
    serviceHint: plainText(data.service_hint),
    sensitive: data.sensitive === true,
    owner: fields(owner, [
      ["name", "Proceso"],
      ["exe", "Ejecutable"],
      ["pid", "PID"],
      ["sha256", "SHA-256"],
      ["signer", "Firmante"],
      ["process_user", "Usuario"],
      ["process_cmdline", "Línea de comandos"],
      ["listener_address", "Dirección de escucha"],
    ]),
    sentraComponent: component || null,
    explanation: strings(data.explanation),
  };
}

export interface ServiceDetectionInfo {
  service: Fields;
  classification: ServiceClassInfo | null;
  explanation: string[];
}

/** Detalles de PER-001 v3 (servicio nuevo o modificado con su clasificación). */
export function serviceDetectionInfo(raw: unknown): ServiceDetectionInfo {
  const data = record(raw);
  return {
    service: fields(data, [
      ["service", "Servicio"],
      ["image_path", "Ejecutable"],
      ["binpath", "Línea de comandos"],
      ["previous_binpath", "Línea de comandos anterior"],
      ["account", "Cuenta"],
      ["unusual_location", "Ubicación inusual"],
    ]),
    classification: serviceClassInfo(data.classification),
    explanation: strings(data.explanation),
  };
}

/** Reglas cuyo detalle tiene vista propia. */
export const RULES_WITH_DETAILS = new Set(["SCR-001", "CORR-002", "NET-001", "PER-001"]);
