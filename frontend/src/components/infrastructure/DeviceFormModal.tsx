import { useCallback, useState, type FormEvent } from "react";
import { networkApi, sensorsApi } from "../../api/sentra";
import type { NetworkDevice, Site } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import {
  buildDeviceUpdate,
  deviceFormFrom,
  isVersionConflict,
  SNMP_VERSION_LABELS,
  validPort,
  type DeviceForm,
} from "../../lib/network";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";

// Perfiles, sensores y candidatos de un site cambian poco mientras el formulario está abierto.
const CATALOG_MS = 5 * 60_000;

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/** Selects de perfil y sensor del site elegido (solo del mismo site: el servidor lo exige). */
function AssignmentFields({
  siteId,
  form,
  onChange,
  current,
}: {
  siteId: string;
  form: DeviceForm;
  onChange: (next: DeviceForm) => void;
  current?: NetworkDevice;
}) {
  const auth = useAuth();
  // Listar perfiles exige snmp_credentials:manage; sin él se conserva la asignación actual.
  const canListProfiles = auth.can("snmp_credentials:manage");
  const fetchProfiles = useCallback((signal: AbortSignal) => networkApi.profiles(siteId, false, signal), [siteId]);
  const profiles = usePolling(fetchProfiles, CATALOG_MS, canListProfiles && Boolean(siteId));
  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(siteId, signal), [siteId]);
  const sensors = usePolling(fetchSensors, CATALOG_MS, Boolean(siteId));

  const profileOptions = (profiles.data?.items ?? []).filter((p) => p.site_id === siteId && p.status === "active");
  const sensorOptions = (sensors.data?.items ?? []).filter((s) => s.site_id === siteId && s.status !== "revoked");

  return (
    <>
      {canListProfiles ? (
        <label>
          <span>Perfil SNMP</span>
          <select
            className="input input--select"
            value={form.profileId}
            onChange={(e) => onChange({ ...form, profileId: e.target.value })}
          >
            <option value="">Sin perfil</option>
            {profileOptions.map((p) => (
              <option key={p.profile_id} value={p.profile_id}>
                {p.name} ({SNMP_VERSION_LABELS[p.snmp_version]})
              </option>
            ))}
            {/* La asignación actual se conserva aunque ya no esté en la lista (revocada). */}
            {current?.profile && !profileOptions.some((p) => p.profile_id === current.profile?.profile_id) && (
              <option value={current.profile.profile_id}>{current.profile.name} (actual)</option>
            )}
          </select>
          {profiles.error && <span className="muted small">No se pudieron cargar los perfiles: {errorMessage(profiles.error)}</span>}
        </label>
      ) : (
        <p className="muted small">
          Perfil SNMP: {current?.profile?.name ?? "sin perfil"}. Tu rol no puede listar perfiles SNMP; un administrador
          puede asignarlo.
        </p>
      )}
      <label>
        <span>Sensor del site</span>
        <select
          className="input input--select"
          value={form.sensorId}
          onChange={(e) => onChange({ ...form, sensorId: e.target.value })}
        >
          <option value="">Sin sensor</option>
          {sensorOptions.map((s) => (
            <option key={s.sensor_id} value={s.sensor_id}>
              {s.name} ({s.status})
            </option>
          ))}
          {current?.sensor && !sensorOptions.some((s) => s.sensor_id === current.sensor?.sensor_id) && (
            <option value={current.sensor.sensor_id}>{current.sensor.name} (actual)</option>
          )}
        </select>
        {sensors.error && <span className="muted small">No se pudieron cargar los sensores: {errorMessage(sensors.error)}</span>}
      </label>
      <label className="checkbox">
        <input
          type="checkbox"
          checked={form.monitoring}
          onChange={(e) => onChange({ ...form, monitoring: e.target.checked })}
        />{" "}
        Consultar periódicamente
      </label>
    </>
  );
}

const EMPTY_FORM: DeviceForm = { name: "", port: "161", profileId: "", sensorId: "", monitoring: false };

/** Registrar un equipo de red administrable (network:manage). */
export function CreateDeviceModal({
  sites,
  initialSiteId,
  onClose,
  onCreated,
}: {
  sites: Site[];
  initialSiteId?: string;
  onClose: () => void;
  onCreated: (device: NetworkDevice) => void;
}) {
  const [siteId, setSiteId] = useState(
    sites.some((s) => s.site_id === initialSiteId) ? (initialSiteId ?? "") : (sites[0]?.site_id ?? ""),
  );
  const [address, setAddress] = useState("");
  const [assetId, setAssetId] = useState("");
  const [form, setForm] = useState<DeviceForm>(EMPTY_FORM);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const fetchCandidates = useCallback((signal: AbortSignal) => networkApi.candidates(siteId, 100, signal), [siteId]);
  const candidates = usePolling(fetchCandidates, CATALOG_MS, Boolean(siteId));
  const candidateItems = candidates.data?.items ?? [];

  const chooseCandidate = (value: string) => {
    setAssetId(value);
    const candidate = candidateItems.find((c) => c.asset_id === value);
    if (candidate) {
      setAddress(candidate.address);
      if (!form.name && candidate.hostname) setForm({ ...form, name: candidate.hostname });
    }
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!siteId || !address.trim()) return;
    if (!validPort(form.port)) {
      setError("El puerto SNMP debe estar entre 1 y 65535.");
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      const device = await networkApi.createDevice({
        site_id: siteId,
        management_address: address.trim(),
        snmp_port: Number(form.port),
        name: form.name.trim() || null,
        profile_id: form.profileId || null,
        sensor_id: form.sensorId || null,
        monitoring_enabled: form.monitoring,
        asset_id: assetId || null,
      });
      onCreated(device);
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Registrar equipo de red" onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        {sites.length === 0 ? (
          <div className="banner" role="status">
            No hay sites activos.
          </div>
        ) : (
          <label>
            <span>Site</span>
            <select
              className="input input--select"
              value={siteId}
              onChange={(e) => {
                setSiteId(e.target.value);
                // Perfil, sensor y activo dependen del site: se limpian para no enviar una mezcla.
                setForm({ ...form, profileId: "", sensorId: "" });
                setAssetId("");
              }}
            >
              {sites.map((s) => (
                <option key={s.site_id} value={s.site_id}>
                  {s.name}
                </option>
              ))}
            </select>
          </label>
        )}
        {candidateItems.length > 0 && (
          <label>
            <span>Activo descubierto (opcional)</span>
            <select className="input input--select" value={assetId} onChange={(e) => chooseCandidate(e.target.value)}>
              <option value="">Ninguno</option>
              {candidateItems.map((c) => (
                <option key={c.asset_id} value={c.asset_id}>
                  {c.address}
                  {c.hostname ? ` · ${c.hostname}` : ""}
                  {c.device_type ? ` · ${c.device_type}` : ""}
                </option>
              ))}
            </select>
          </label>
        )}
        <label>
          <span>Dirección de gestión (IP)</span>
          <input
            className="input mono"
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            maxLength={45}
            placeholder="p. ej. 10.20.0.2"
            required
          />
        </label>
        <label>
          <span>Puerto SNMP</span>
          <input
            className="input"
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })}
            aria-invalid={!validPort(form.port)}
          />
        </label>
        <label>
          <span>Nombre (opcional)</span>
          <input
            className="input"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            maxLength={100}
          />
        </label>
        {siteId && <AssignmentFields siteId={siteId} form={form} onChange={setForm} />}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !siteId || !address.trim()}>
            {busy ? "Registrando…" : "Registrar equipo"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/**
 * Editar un equipo (network:manage). Un 409 network_device_conflict recarga el equipo y
 * reinicia el formulario con la versión actual: nunca se sobrescribe en silencio.
 */
export function EditDeviceModal({
  device: initial,
  onClose,
  onSaved,
}: {
  device: NetworkDevice;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [device, setDevice] = useState(initial);
  const [form, setForm] = useState<DeviceForm>(() => deviceFormFrom(initial));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!validPort(form.port)) {
      setError("El puerto SNMP debe estar entre 1 y 65535.");
      return;
    }
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.updateDevice(device.device_id, buildDeviceUpdate(device, form));
      onSaved();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      if (isVersionConflict(err)) {
        try {
          const fresh = await networkApi.device(device.device_id);
          setDevice(fresh);
          setForm(deviceFormFrom(fresh));
        } catch {
          // Si la recarga falla, el mensaje de conflicto ya pide recargar.
        }
        onSaved();
      }
      setBusy(false);
    }
  };

  return (
    <Modal title={`Editar ${device.display_name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p className="muted small">
          {device.site_name} · <span className="mono">{device.management_address}</span>. La dirección y el site no se
          pueden cambiar: archiva el equipo y regístralo de nuevo.
        </p>
        <label>
          <span>Nombre</span>
          <input
            className="input"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            maxLength={100}
          />
        </label>
        <label>
          <span>Puerto SNMP</span>
          <input
            className="input"
            type="number"
            min={1}
            max={65535}
            value={form.port}
            onChange={(e) => setForm({ ...form, port: e.target.value })}
            aria-invalid={!validPort(form.port)}
          />
        </label>
        <AssignmentFields siteId={device.site_id} form={form} onChange={setForm} current={device} />
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Guardando…" : "Guardar cambios"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Archivar conserva el historial; el motivo es opcional en el contrato. */
export function ArchiveDeviceModal({
  device,
  onClose,
  onDone,
}: {
  device: NetworkDevice;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.archiveDevice(device.device_id, device.version, reason.trim() || undefined);
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      if (isVersionConflict(err)) onDone();
    }
  };
  return (
    <Modal title={`Archivar ${device.display_name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p>El equipo deja de consultarse. Su inventario y su historial de consultas se conservan.</p>
        <label>
          <span>Motivo (opcional)</span>
          <textarea className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} />
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
          <button type="submit" className="button button--danger" disabled={busy}>
            {busy ? "Archivando…" : "Archivar equipo"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
