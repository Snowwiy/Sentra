import { useState, type FormEvent } from "react";
import { exclusionsApi } from "../../api/sentra6e";
import type { DetectionExclusionField } from "../../api/types";
import { EXCLUSION_FIELD_LABELS } from "../../lib/endpoint";
import { allowedFields, policyErrors, RULE_POLICIES, type ExclusionDraft } from "../../lib/exclusionPolicy";
import { errorMessage, toLocalInputValue } from "../../lib/format";
import { Modal } from "../Modal";

const RULE_ID = /^[A-Z0-9-]{3,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ALL_FIELDS = Object.keys(EXCLUSION_FIELD_LABELS) as DetectionExclusionField[];
// Caducidad propuesta para las reglas con política: dentro del máximo y fácil de revisar.
const DEFAULT_POLICY_DAYS = 30;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

export type ExclusionPrefill = Partial<Omit<ExclusionDraft, "expiresAt">>;

/**
 * Nueva excepción de una regla integrada (rules:manage). Para SCR-001, CORR-002 y NET-001 el
 * formulario aplica la política exacta del servidor (Fase 7A.8): qué campos admite, si exige el
 * SHA-256 del script, el puerto o el equipo, y una caducidad de como mucho 90 días. Iniciada
 * desde una detección, llega rellenada con sus valores exactos; nunca se propone un intérprete.
 */
/** Hora actual para validar al enviar (solo desde manejadores de eventos, nunca al renderizar). */
function currentTime(): number {
  return Date.now();
}

export function ExclusionDialog({
  initial = {},
  assetLabel,
  onClose,
  onCreated,
}: {
  initial?: ExclusionPrefill;
  /** Nombre del equipo prellenado (el identificador solo no le dice nada a una persona). */
  assetLabel?: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [ruleId, setRuleId] = useState(initial.ruleId ?? "");
  const [field, setField] = useState<DetectionExclusionField>(initial.field ?? "exe");
  const [value, setValue] = useState(initial.value ?? "");
  const [requireSha256, setRequireSha256] = useState(initial.requireSha256 ?? "");
  const [port, setPort] = useState(initial.port ?? "");
  const [reason, setReason] = useState("");
  const [assetId, setAssetId] = useState(initial.assetId ?? "");
  // Se fija una vez al abrir: la caducidad propuesta y el «ahora» de la validación en pantalla.
  const [openedAt] = useState(() => Date.now());
  const [expires, setExpires] = useState(() =>
    initial.ruleId && RULE_POLICIES[initial.ruleId]
      ? toLocalInputValue(new Date(openedAt + DEFAULT_POLICY_DAYS * 86_400_000))
      : "",
  );
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const rule = ruleId.trim();
  const policy = RULE_POLICIES[rule];
  const fields = allowedFields(rule, ALL_FIELDS);
  const expiresAt = expires ? new Date(expires) : undefined;
  const showRequireSha = policy ? policy.hashRequiredFor.includes(field) : requireSha256 !== "";
  const showPort = policy ? policy.portRequired : port !== "";
  // Un campo oculto no cuenta: al cambiar de campo o de regla su valor viejo no se envía.
  const draft: ExclusionDraft = {
    ruleId: rule,
    field,
    value,
    requireSha256: showRequireSha ? requireSha256 : "",
    port: showPort ? port : "",
    assetId,
    expiresAt,
  };

  const errors: string[] = [];
  if (!RULE_ID.test(rule)) errors.push("Indica el identificador de la regla (p. ej. BEH-001).");
  if (!value.trim() || value.length > 1024) errors.push("Indica el valor exacto (máx. 1024 caracteres).");
  if (reason.trim().length < 3) errors.push("La justificación es obligatoria (mín. 3 caracteres).");
  if (assetId.trim() && !UUID.test(assetId.trim())) errors.push("El identificador de equipo no es válido.");
  if (expiresAt && Number.isNaN(expiresAt.getTime())) errors.push("La fecha de caducidad no es válida.");
  else errors.push(...policyErrors(draft, openedAt));
  const changeRule = (next: string) => {
    setRuleId(next);
    const nextFields = allowedFields(next.trim(), ALL_FIELDS);
    if (!nextFields.includes(field) && nextFields[0]) setField(nextFields[0]);
    // Las reglas con política exigen caducidad: se propone la habitual si aún no hay ninguna.
    if (RULE_POLICIES[next.trim()] && !expires) {
      setExpires(toLocalInputValue(new Date(Date.now() + DEFAULT_POLICY_DAYS * 86_400_000)));
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    // Se repite al enviar con la hora real: el formulario puede llevar tiempo abierto.
    const now = currentTime();
    const late = policyErrors(draft, now);
    if (errors.length || late.length) {
      setError(late[0] ?? errors[0]);
      return;
    }
    if (expiresAt && expiresAt.getTime() <= now) {
      setError("La caducidad debe ser una fecha futura.");
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await exclusionsApi.create({
        rule_id: rule,
        field,
        value: value.trim(),
        reason: reason.trim(),
        asset_id: assetId.trim() || null,
        expires_at: expiresAt ? expiresAt.toISOString() : null,
        require_sha256: showRequireSha && requireSha256.trim() ? requireSha256.trim().toLowerCase() : null,
        port: showPort && port.trim() ? Number(port) : null,
      });
      onCreated();
    } catch (err) {
      setError(errorMessage(toError(err)));
      setBusy(false);
    }
  };

  const touched = ruleId || value || reason;
  return (
    <Modal title="Nueva excepción" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
        <label className="form-field">
          <span>Regla</span>
          <input
            className="input mono"
            value={ruleId}
            placeholder="BEH-001"
            maxLength={64}
            onChange={(e) => changeRule(e.target.value.toUpperCase())}
            disabled={busy}
          />
        </label>
        {policy && (
          <div className="banner" role="note" aria-label="Política de la regla">
            <strong>{rule}</strong> solo admite excepciones exactas. {policy.summary}
          </div>
        )}
        <label className="form-field">
          <span>Campo</span>
          <select
            className="input input--select"
            value={field}
            onChange={(e) => setField(e.target.value as DetectionExclusionField)}
            disabled={busy}
          >
            {fields.map((v) => (
              <option key={v} value={v}>
                {EXCLUSION_FIELD_LABELS[v]}
              </option>
            ))}
          </select>
        </label>
        <label className="form-field">
          <span>Valor exacto</span>
          <input className="input mono" value={value} maxLength={1024} onChange={(e) => setValue(e.target.value)} disabled={busy} />
        </label>
        {showRequireSha && (
          <label className="form-field">
            <span>SHA-256 del script que debe coincidir</span>
            <input
              className="input mono"
              value={requireSha256}
              maxLength={64}
              onChange={(e) => setRequireSha256(e.target.value)}
              disabled={busy}
            />
            <span className="muted small">Si el script cambia, su hash cambia y la excepción deja de aplicarse.</span>
          </label>
        )}
        {showPort && (
          <label className="form-field">
            <span>Puerto</span>
            <input
              className="input mono"
              inputMode="numeric"
              value={port}
              maxLength={5}
              onChange={(e) => setPort(e.target.value)}
              disabled={busy}
            />
          </label>
        )}
        <label className="form-field">
          <span>Justificación</span>
          <textarea className="input" rows={2} value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} disabled={busy} />
        </label>
        <label className="form-field">
          <span>
            {policy?.assetRequired ? "Equipo (identificador, obligatorio)" : "Solo para el equipo (identificador, opcional)"}
          </span>
          <input className="input mono" value={assetId} onChange={(e) => setAssetId(e.target.value)} disabled={busy} />
          {assetLabel && assetId === initial.assetId && <span className="muted small">{assetLabel}</span>}
        </label>
        <label className="form-field">
          <span>{policy ? `Caduca (obligatorio, máximo ${policy.maxDays} días)` : "Caduca (opcional)"}</span>
          <input className="input" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} disabled={busy} />
        </label>
        {errors.length > 0 && touched && (
          <ul className="plain-list small text-crit" aria-label="Problemas del formulario">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || errors.length > 0}>
            {busy ? "Creando…" : "Crear excepción"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
