import { useEffect, useState, type FormEvent } from "react";
import { incidentsApi, sentraApi } from "../../api/sentra";
import type { Asset, IncidentDetail, IncidentLevel } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { LEVEL_LABELS, LEVEL_ORDER } from "../../lib/incidents";
import { Modal } from "../Modal";

/**
 * Alta manual de un incidente (incidents:manage). Severidad y prioridad se eligen por
 * separado; la confianza no se pide aquí: sin evidencia vinculada no se inventa.
 */
export function CreateIncidentModal({
  onClose,
  onCreated,
}: {
  onClose: () => void;
  onCreated: (incident: IncidentDetail) => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<IncidentLevel>("medium");
  const [priority, setPriority] = useState<IncidentLevel>("medium");
  const [assetId, setAssetId] = useState("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const controller = new AbortController();
    sentraApi
      .listAssets(controller.signal)
      .then((list) => setAssets(list.items))
      .catch(() => undefined);
    return () => controller.abort();
  }, []);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      const created = await incidentsApi.create({
        title: title.trim(),
        description: description.trim() || null,
        severity,
        priority,
        asset_ids: assetId ? [assetId] : [],
      });
      onCreated(created);
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
      setBusy(false);
    }
  }

  return (
    <Modal title="Nuevo incidente" onClose={busy ? () => undefined : onClose}>
      <form className="incident-form" onSubmit={(e) => void submit(e)}>
        <label>
          <span className="muted small">Título</span>
          <input
            className="input"
            required
            minLength={3}
            maxLength={200}
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            aria-label="Título"
          />
        </label>
        <label>
          <span className="muted small">Descripción (opcional)</span>
          <textarea
            className="input"
            maxLength={10000}
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            aria-label="Descripción"
          />
        </label>
        <div className="actions">
          <label>
            <span className="muted small">Severidad (impacto)</span>
            <select
              className="input input--select"
              value={severity}
              onChange={(e) => setSeverity(e.target.value as IncidentLevel)}
              aria-label="Severidad"
            >
              {LEVEL_ORDER.map((level) => (
                <option key={level} value={level}>
                  {LEVEL_LABELS[level]}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span className="muted small">Prioridad (urgencia)</span>
            <select
              className="input input--select"
              value={priority}
              onChange={(e) => setPriority(e.target.value as IncidentLevel)}
              aria-label="Prioridad"
            >
              {LEVEL_ORDER.map((level) => (
                <option key={level} value={level}>
                  {LEVEL_LABELS[level]}
                </option>
              ))}
            </select>
          </label>
        </div>
        <label>
          <span className="muted small">Activo afectado (opcional)</span>
          <select
            className="input input--select"
            value={assetId}
            onChange={(e) => setAssetId(e.target.value)}
            aria-label="Activo afectado"
          >
            <option value="">Ninguno</option>
            {assets.map((asset) => (
              <option key={asset.asset_id} value={asset.asset_id}>
                {asset.display_name}
                {asset.primary_ip ? ` · ${asset.primary_ip}` : ""}
              </option>
            ))}
          </select>
        </label>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || title.trim().length < 3}>
            {busy ? "Creando…" : "Crear incidente"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
