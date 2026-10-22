import { useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { sentraApi } from "../../api/sentra";
import type { Asset } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { LABEL_MAX, automaticTitle, normalizeLabel } from "../../lib/identity";
import { Modal } from "../Modal";

/** Detalle del 409 asset_label_conflict: la versión y la etiqueta que hay ahora. */
function conflictDetails(error: unknown): { version: number; label: string | null } | null {
  if (!(error instanceof ApiError) || error.code !== "asset_label_conflict") return null;
  const [first] = Array.isArray(error.details) ? (error.details as unknown[]) : [];
  if (typeof first !== "object" || first === null) return null;
  const { current_version: version, custom_label: label } = first as Record<string, unknown>;
  if (typeof version !== "number") return null;
  return { version, label: typeof label === "string" ? label : null };
}

/**
 * Corrección 6C: poner, cambiar o quitar la etiqueta personalizada de un activo.
 *
 * La etiqueta es solo el nombre visible: no toca la evidencia ni el nombre automático, que se
 * muestra aquí para que se vea qué se está sustituyendo. Se envía la versión leída; si otra
 * persona la cambió entretanto (409), se enseña su valor y hay que confirmar de nuevo: nunca
 * se pisa un cambio ajeno sin verlo.
 */
export function AssetLabelDialog({
  asset,
  onClose,
  onSaved,
}: {
  asset: Asset;
  onClose: () => void;
  onSaved: (asset: Asset) => void;
}) {
  const [value, setValue] = useState(asset.custom_label ?? "");
  const [version, setVersion] = useState(asset.custom_label_version);
  const [current, setCurrent] = useState(asset.custom_label);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const automatic = automaticTitle(asset);

  const save = async (label: string | null) => {
    setBusy(true);
    setError(undefined);
    try {
      const updated = await sentraApi.setAssetLabel(asset.asset_id, label, version);
      onSaved(updated);
      onClose();
    } catch (err) {
      const conflict = conflictDetails(err);
      if (conflict) {
        setVersion(conflict.version);
        setCurrent(conflict.label);
        setError(
          conflict.label
            ? `Otra persona acaba de cambiar la etiqueta a «${conflict.label}». Revisa y vuelve a guardar.`
            : "Otra persona acaba de quitar la etiqueta. Revisa y vuelve a guardar.",
        );
      } else {
        setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      }
      setBusy(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    const result = normalizeLabel(value);
    if ("error" in result) {
      setError(result.error);
      return;
    }
    void save(result.label);
  };

  return (
    <Modal title="Etiqueta del activo" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={submit} noValidate>
        <p className="small">
          Nombre automático: <strong>{automatic}</strong> <span className="mono muted">{asset.primary_ip}</span>
        </p>
        <label className="form-field">
          Etiqueta personalizada
          <input
            className="input"
            value={value}
            maxLength={LABEL_MAX * 2}
            autoComplete="off"
            onChange={(event) => setValue(event.target.value)}
            placeholder="Alexa Sala, Impresora oficina…"
            aria-describedby="asset-label-hint"
            disabled={busy}
          />
        </label>
        <p id="asset-label-hint" className="muted small label-editor__hint">
          Máximo {LABEL_MAX} caracteres. Solo cambia el nombre visible: el descubrimiento y el agente no la
          sobrescriben y la evidencia original se conserva.
        </p>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          {current && (
            <button type="button" className="button" onClick={() => void save(null)} disabled={busy}>
              Quitar etiqueta
            </button>
          )}
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Guardando…" : "Guardar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
