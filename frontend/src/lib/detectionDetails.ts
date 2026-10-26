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

export interface ScriptCorrelationInfo {
  scripts: ScriptInfo[];
  persistence: Fields;
  sentraServiceName: boolean;
  sequence: string;
  explanation: string[];
  counts: Fields;
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
    counts: fields(data, [
      ["powershell_events", "Bloques de PowerShell"],
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

/** Reglas cuyo detalle tiene vista propia. */
export const RULES_WITH_DETAILS = new Set(["SCR-001", "CORR-002", "NET-001"]);
