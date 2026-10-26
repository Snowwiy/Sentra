// Fase 7A.8: política de excepciones por regla, copia de backend/app/detection/exclusions.py
// (RULE_POLICIES y check_policy). El formulario la usa para pedir los campos correctos antes de
// enviar; el servidor la vuelve a aplicar y responde 422 exclusion_too_broad si no se cumple.
import type { DetectionDetail, DetectionExclusionField } from "../api/types";

export interface RulePolicy {
  fields: readonly DetectionExclusionField[];
  /** Campos que solo valen junto con require_sha256 (la ruta sola se puede reutilizar). */
  hashRequiredFor: readonly DetectionExclusionField[];
  portRequired: boolean;
  assetRequired: boolean;
  /** Caducidad obligatoria y como mucho este plazo: una excepción se revisa, no se olvida. */
  maxDays: number;
  /** Explicación para el formulario. */
  summary: string;
}

const SCRIPT_POLICY: RulePolicy = {
  fields: ["script_path", "script_sha256"],
  hashRequiredFor: ["script_path"],
  portRequired: false,
  assetRequired: false,
  maxDays: 90,
  summary:
    "Solo por script: su SHA-256, o su ruta junto con el SHA-256 que debe coincidir. Caducidad obligatoria (máximo 90 días).",
};

export const RULE_POLICIES: Record<string, RulePolicy> = {
  "SCR-001": SCRIPT_POLICY,
  "CORR-002": SCRIPT_POLICY,
  // Puerto expuesto: un ejecutable (o su hash) en un puerto de un activo, nunca "python".
  "NET-001": {
    fields: ["exe", "sha256"],
    hashRequiredFor: [],
    portRequired: true,
    assetRequired: true,
    maxDays: 90,
    summary:
      "Solo un ejecutable (ruta o SHA-256) en un puerto concreto de un equipo concreto. Caducidad obligatoria (máximo 90 días).",
  },
};

export const SCRIPT_FIELDS: readonly DetectionExclusionField[] = ["script_path", "script_sha256"];

// Intérpretes del sistema (backend app/detection/behavior.py SHELLS): excluir uno entero
// ocultaría cualquier cosa ejecutada con él.
const SHELLS = [
  "cmd.exe",
  "powershell.exe",
  "pwsh.exe",
  "wscript.exe",
  "cscript.exe",
  "mshta.exe",
  "rundll32.exe",
  "regsvr32.exe",
  "msbuild.exe",
  "installutil.exe",
  "bitsadmin.exe",
  "certutil.exe",
  "sh",
  "bash",
  "dash",
  "zsh",
  "python",
  "python3",
  "perl",
];
const INTERPRETERS = new Set([...SHELLS, ...SHELLS.map((shell) => `${shell}.exe`)]);
const SYSTEM_DIRS = [
  "\\windows\\system32\\",
  "\\windows\\syswow64\\",
  "\\program files\\powershell\\",
  "/usr/bin/",
  "/usr/local/bin/",
  "/bin/",
];
const SHA256 = /^[0-9a-f]{64}$/i;
const DAY_MS = 86_400_000;

function basename(path: string): string {
  return path.trim().split(/[\\/]/).at(-1)?.toLowerCase() ?? "";
}

/** ¿La excepción cubriría cualquier uso de un intérprete del sistema? (igual que el servidor) */
export function interpreterWide(field: DetectionExclusionField, value: string): boolean {
  const lowered = value.trim().toLowerCase();
  if ((field !== "exe" && field !== "name") || !INTERPRETERS.has(basename(lowered))) return false;
  if (field === "name" || (!lowered.includes("\\") && !lowered.includes("/"))) return true;
  return SYSTEM_DIRS.some((dir) => lowered.includes(dir));
}

export interface ExclusionDraft {
  ruleId: string;
  field: DetectionExclusionField;
  value: string;
  requireSha256: string;
  port: string;
  assetId: string;
  /** Fecha de caducidad ya interpretada (undefined = sin caducidad). */
  expiresAt: Date | undefined;
}

/** Campos que admite la regla (todos si no tiene política propia, salvo los de script). */
export function allowedFields(ruleId: string, all: readonly DetectionExclusionField[]): DetectionExclusionField[] {
  const policy = RULE_POLICIES[ruleId];
  if (policy) return [...policy.fields];
  return all.filter((field) => !SCRIPT_FIELDS.includes(field));
}

/**
 * Problemas de la política (en español), en el mismo orden que el servidor. `now` se pasa al
 * validar al enviar: «ahora» cambia entre renders.
 */
export function policyErrors(draft: ExclusionDraft, now: number): string[] {
  const errors: string[] = [];
  if (draft.value.trim() && interpreterWide(draft.field, draft.value)) {
    errors.push("No se puede exceptuar un intérprete del sistema entero (PowerShell, cmd, Python...).");
  }
  const sha = draft.requireSha256.trim();
  const port = draft.port.trim();
  if (sha && !SHA256.test(sha)) errors.push("El SHA-256 exigido debe tener 64 caracteres hexadecimales.");
  if (port && !(/^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535)) {
    errors.push("El puerto debe estar entre 1 y 65535.");
  }
  if ((draft.field === "sha256" || draft.field === "script_sha256") && draft.value.trim() && !SHA256.test(draft.value.trim())) {
    errors.push("El valor debe ser un SHA-256 (64 caracteres hexadecimales).");
  }
  const policy = RULE_POLICIES[draft.ruleId];
  if (!policy) {
    if (SCRIPT_FIELDS.includes(draft.field)) errors.push("Los campos de script solo valen para SCR-001 y CORR-002.");
    if (sha || port) errors.push("Esta regla no usa SHA-256 exigido ni puerto.");
    return errors;
  }
  if (!policy.fields.includes(draft.field)) {
    errors.push(`${draft.ruleId} solo admite excepciones por: ${policy.fields.join(", ")}.`);
  }
  if (policy.hashRequiredFor.includes(draft.field) && !sha) {
    errors.push("Una excepción por ruta de script exige también el SHA-256 del script.");
  }
  if (!policy.hashRequiredFor.includes(draft.field) && sha) {
    errors.push("El SHA-256 exigido solo se usa con la ruta del script.");
  }
  if (policy.portRequired && !port) errors.push(`${draft.ruleId} exige el puerto.`);
  if (!policy.portRequired && port) errors.push(`${draft.ruleId} no usa puerto.`);
  if (policy.assetRequired && !draft.assetId.trim()) errors.push(`${draft.ruleId} exige indicar el equipo.`);
  if (!draft.expiresAt) {
    errors.push(`${draft.ruleId} exige una fecha de caducidad (máximo ${policy.maxDays} días).`);
  } else if (draft.expiresAt.getTime() <= now) {
    errors.push("La caducidad debe ser una fecha futura.");
  } else if (draft.expiresAt.getTime() > now + policy.maxDays * DAY_MS) {
    errors.push(`La caducidad de ${draft.ruleId} no puede superar ${policy.maxDays} días.`);
  }
  return errors;
}

const text = (value: unknown): string => (typeof value === "string" ? value : "");
const record = (value: unknown): Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value) ? (value as Record<string, unknown>) : {};

/** Valores de partida de una excepción iniciada desde una detección (exactos, no amplios). */
export function draftFromDetection(
  detection: Pick<DetectionDetail, "rule_id" | "asset_id" | "details">,
): Partial<Omit<ExclusionDraft, "expiresAt">> {
  const details = record(detection.details);
  const base = { ruleId: detection.rule_id };
  if (detection.rule_id === "SCR-001" || detection.rule_id === "CORR-002") {
    // CORR-002 trae los scripts de la ventana; se parte del más reciente.
    const scripts = Array.isArray(details.scripts) ? details.scripts : [];
    const source = detection.rule_id === "CORR-002" ? record(scripts.at(-1)) : details;
    const script = record(source.script);
    const path = text(script.script_path);
    const sha = text(script.script_sha256);
    if (path) return { ...base, field: "script_path", value: path, requireSha256: sha };
    if (sha) return { ...base, field: "script_sha256", value: sha };
    return { ...base, field: "script_sha256" };
  }
  if (detection.rule_id === "NET-001") {
    const owner = record(details.owner);
    const port = typeof details.port === "number" ? String(details.port) : "";
    const exe = text(owner.exe);
    const sha = text(owner.sha256);
    return {
      ...base,
      field: exe || !sha ? "exe" : "sha256",
      value: exe || sha,
      port,
      assetId: detection.asset_id,
    };
  }
  return { ...base, assetId: detection.asset_id };
}

// Motivos de exclusion_too_broad (backend check_policy) en español.
const TOO_BROAD: [RegExp, string][] = [
  [/system interpreter/i, "no se puede exceptuar un intérprete del sistema entero (PowerShell, cmd, Python...)"],
  [/Script fields only apply/i, "los campos de script solo valen para las reglas de PowerShell (SCR-001, CORR-002)"],
  [/does not use require_sha256 or port/i, "esta regla no usa SHA-256 exigido ni puerto"],
  [/exclusions must use: (.+)$/i, "la regla solo admite excepciones por: $1"],
  [/require require_sha256/i, "una excepción por ruta de script exige también su SHA-256"],
  [/require_sha256 only applies/i, "el SHA-256 exigido solo se usa con la ruta del script"],
  [/require a port/i, "la regla exige el puerto"],
  [/do not use a port/i, "la regla no usa puerto"],
  [/must name an asset/i, "la regla exige indicar el equipo"],
  [/need a future expires_at/i, "la regla exige una fecha de caducidad futura"],
  [/expire within (\d+) days/i, "la caducidad no puede superar $1 días"],
];

/** Mensaje en español del 422 exclusion_too_broad (conserva el original si no se reconoce). */
export function explainTooBroad(message: string): string {
  for (const [pattern, spanish] of TOO_BROAD) {
    const match = pattern.exec(message);
    if (match) return `Excepción demasiado amplia: ${match[0].replace(pattern, spanish)}.`;
  }
  return `Excepción demasiado amplia: ${message}`;
}
