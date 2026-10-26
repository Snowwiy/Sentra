import { useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { sentraApi } from "../../api/sentra";
import type { Asset } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { DEVICE_TYPE_OPTIONS, confidenceLabel, deviceTypeLabel, typeWithConfidence } from "../../lib/identity";
import { Modal } from "../Modal";

/** Detalle del 409 asset_label_conflict del tipo: la versión y el tipo manual que hay ahora. */
function conflictDetails(error: unknown): { version: number; manual: string | null } | null {
  if (!(error instanceof ApiError) || error.code !== "asset_label_conflict") return null;
  const [first] = Array.isArray(error.details) ? (error.details as unknown[]) : [];
  if (typeof first !== "object" || first === null) return null;
  const { current_version: version, manual_device_type: manual } = first as Record<string, unknown>;
  if (typeof version !== "number") return null;
  return { version, manual: typeof manual === "string" ? manual : null };
}

/**
 * Fase 7A.4: fijar a mano el tipo de un activo o volver a la identificación automática.
 *
 * Como la etiqueta, el tipo manual manda sobre la deducción pero no borra su evidencia: si la
 * identificación automática apunta a otro tipo, el servidor lo deja como conflicto visible. Se
 * envía la versión leída (la misma que protege la etiqueta); si otra persona cambió la
 * identidad entretanto (409), se avisa, se recarga el activo y hay que confirmar de nuevo.
 */
export function AssetTypeDialog({
  asset,
  onClose,
  onSaved,
  onConflict,
}: {
  asset: Asset;
  onClose: () => void;
  onSaved: (asset: Asset) => void;
  /** Otra persona cambió la identidad: el llamador recarga el activo para mostrar lo vigente. */
  onConflict?: () => void;
}) {
  const [value, setValue] = useState(asset.manual_device_type ?? asset.device_type ?? "");
  const [version, setVersion] = useState(asset.custom_label_version);
  const [manual, setManual] = useState(asset.manual_device_type);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const save = async (deviceType: string | null) => {
    setBusy(true);
    setError(undefined);
    try {
      const updated = await sentraApi.setAssetDeviceType(asset.asset_id, deviceType, version);
      onSaved(updated);
      onClose();
    } catch (err) {
      const conflict = conflictDetails(err);
      if (conflict) {
        setVersion(conflict.version);
        setManual(conflict.manual);
        setError(
          conflict.manual === manual
            ? "La identidad del activo cambió mientras editabas (por ejemplo, su etiqueta). Revisa y vuelve a guardar."
            : conflict.manual
              ? `Otra persona acaba de asignar el tipo «${deviceTypeLabel(conflict.manual)}». Revisa y vuelve a guardar.`
              : "Otra persona acaba de volver a la identificación automática. Revisa y vuelve a guardar.",
        );
        onConflict?.();
      } else {
        setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      }
      setBusy(false);
    }
  };

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!value) {
      setError("Elige un tipo o usa «Volver a automático».");
      return;
    }
    void save(value);
  };

  const confidence = confidenceLabel(asset.classification_confidence);
  return (
    <Modal title="Tipo del dispositivo" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={submit} noValidate>
        <p className="small">
          {manual ? (
            <>
              Tipo actual: <strong>{deviceTypeLabel(manual)}</strong>{" "}
              <span className="badge badge--info">Asignado manualmente</span>
            </>
          ) : (
            <>
              Tipo automático: <strong>{typeWithConfidence(asset)}</strong>
              {confidence && <span className="muted"> · confianza {confidence.toLowerCase()}</span>}
            </>
          )}{" "}
          <span className="mono muted">{asset.primary_ip}</span>
        </p>
        <label className="form-field">
          Tipo de dispositivo
          <select
            className="input input--select"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            aria-describedby="asset-type-hint"
            disabled={busy}
          >
            <option value="">Elige un tipo</option>
            {DEVICE_TYPE_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                {option.label}
              </option>
            ))}
          </select>
        </label>
        <p id="asset-type-hint" className="muted small label-editor__hint">
          El tipo asignado manda sobre la identificación automática, que sigue guardando sus evidencias: si apunta a otro
          tipo, aparecerá como evidencia contradictoria. Cambia los filtros y el rol sugerido para todos.
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
          {manual && (
            <button type="button" className="button" onClick={() => void save(null)} disabled={busy}>
              Volver a automático
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
