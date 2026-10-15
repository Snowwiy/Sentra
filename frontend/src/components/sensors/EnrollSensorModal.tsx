import { useState, type FormEvent } from "react";
import { sensorsApi } from "../../api/sentra";
import type { SensorEnrollmentCreated, Site } from "../../api/types";
import { errorMessage, formatDateTime } from "../../lib/format";
import { CopyButton } from "../CopyButton";
import { Modal } from "../Modal";

const DEFAULT_TTL = 60;

/**
 * Registrar un sensor: site + nombre + caducidad → token de un solo uso.
 *
 * El token vive solo en el estado de este componente: se muestra una vez, no se guarda en el
 * navegador ni en la URL, no se registra y desaparece al cerrar. El comando lo construye el
 * servidor con su URL pública configurada (command_example); aquí nunca se inventa una URL.
 */
export function EnrollSensorModal({
  sites,
  initialSiteId,
  onClose,
}: {
  /** Sites activos (los únicos que aceptan tokens). */
  sites: Site[];
  initialSiteId?: string;
  onClose: () => void;
}) {
  const [siteId, setSiteId] = useState(
    sites.some((s) => s.site_id === initialSiteId) ? (initialSiteId ?? "") : (sites[0]?.site_id ?? ""),
  );
  const [name, setName] = useState("");
  const [ttl, setTtl] = useState(String(DEFAULT_TTL));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [created, setCreated] = useState<SensorEnrollmentCreated>();

  const ttlNumber = Number(ttl);
  const ttlValid = Number.isInteger(ttlNumber) && ttlNumber >= 5 && ttlNumber <= 1440;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!siteId || !name.trim() || !ttlValid) return;
    setBusy(true);
    setError(undefined);
    try {
      setCreated(await sensorsApi.createEnrollment({ site_id: siteId, name: name.trim(), ttl_minutes: ttlNumber }));
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <Modal title="Token de sensor creado" onClose={onClose} wide>
        <div className="stack">
          <div className="banner banner--warn" role="note">
            Copia el token ahora: solo se muestra esta vez y el servidor no puede volver a enseñarlo. Caduca el{" "}
            {formatDateTime(created.expires_at)} y sirve para un único sensor.
          </div>
          <dl className="fields fields--inline">
            <div className="field">
              <dt>Site</dt>
              <dd>{created.site_name}</dd>
            </div>
            <div className="field">
              <dt>Nombre</dt>
              <dd>{created.name}</dd>
            </div>
          </dl>
          <div className="token-box">
            <code className="token-box__value" aria-label="Token de enrollment del sensor">
              {created.token}
            </code>
            <CopyButton text={created.token} label="Copiar token" />
          </div>
          <div className="stack">
            <span className="muted small">Ejecuta en el equipo del sensor:</span>
            <code className="command-box mono small" aria-label="Comando de enrollment">
              {created.command_example}
            </code>
            <div>
              <CopyButton text={created.command_example} label="Copiar comando" />
            </div>
          </div>
          <div className="modal__actions">
            <button type="button" className="button button--primary" onClick={onClose}>
              Hecho
            </button>
          </div>
        </div>
      </Modal>
    );
  }

  return (
    <Modal title="Registrar sensor" onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        {sites.length === 0 ? (
          <div className="banner" role="status">
            No hay sites activos. Crea o activa uno en Configuración → Sites.
          </div>
        ) : (
          <label>
            <span>Site</span>
            <select className="input input--select" value={siteId} onChange={(e) => setSiteId(e.target.value)}>
              {sites.map((s) => (
                <option key={s.site_id} value={s.site_id}>
                  {s.name}
                  {s.is_default ? " (por defecto)" : ""}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>
          <span>Nombre del sensor</span>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={100}
            placeholder="p. ej. sensor-oficina-norte"
            required
            autoFocus
          />
        </label>
        <label>
          <span>Caducidad del token (minutos, 5–1440)</span>
          <input
            className="input"
            type="number"
            min={5}
            max={1440}
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            aria-invalid={!ttlValid}
          />
        </label>
        {error && (
          <div className="banner banner--warn" role="alert">
            No se pudo crear el token: {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button
            type="submit"
            className="button button--primary"
            disabled={busy || !siteId || !name.trim() || !ttlValid}
          >
            {busy ? "Generando…" : "Generar token"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
