import { useCallback, useState, type FormEvent } from "react";
import { networkApi } from "../../api/sentra";
import type { Site, SnmpProfile, SnmpVersion } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  AUTH_PROTOCOL_LABELS,
  AUTH_PROTOCOLS,
  buildProfileCreate,
  buildProfileRotate,
  EMPTY_SECRETS,
  isVersionConflict,
  PRIV_PROTOCOL_LABELS,
  PRIV_PROTOCOLS,
  SNMP_VERSION_LABELS,
  validateSecrets,
  type SnmpSecretsForm,
} from "../../lib/network";
import { usePolling } from "../../lib/usePolling";
import { useSite } from "../../site/SiteContext";
import { Modal } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/** Vacía los secretos del estado: se llama al enviar, antes de esperar la respuesta. */
function withoutSecrets(form: SnmpSecretsForm): SnmpSecretsForm {
  return { ...form, authPassword: "", privPassword: "", community: "" };
}

/**
 * Campos de credenciales SNMP. Los secretos son inputs de tipo password con
 * autocomplete="new-password" (el navegador no los autocompleta ni los ofrece guardar como
 * login) y su valor solo vive en el estado del formulario hasta el envío.
 */
function SecretsFields({
  version,
  form,
  onChange,
  rotating = false,
}: {
  version: SnmpVersion;
  form: SnmpSecretsForm;
  onChange: (next: SnmpSecretsForm) => void;
  rotating?: boolean;
}) {
  if (version === "v2c") {
    return (
      <label>
        <span>{rotating ? "Comunidad nueva" : "Comunidad"}</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          value={form.community}
          onChange={(e) => onChange({ ...form, community: e.target.value })}
          maxLength={64}
          required
        />
      </label>
    );
  }
  return (
    <>
      <label>
        <span>{rotating ? "Usuario SNMPv3 (vacío = sin cambios)" : "Usuario SNMPv3"}</span>
        <input
          className="input"
          autoComplete="off"
          spellCheck={false}
          value={form.username}
          onChange={(e) => onChange({ ...form, username: e.target.value })}
          maxLength={64}
          required={!rotating}
        />
      </label>
      <div className="panels-2">
        <label>
          <span>Protocolo de autenticación</span>
          <select
            className="input input--select"
            value={form.authProtocol}
            onChange={(e) => onChange({ ...form, authProtocol: e.target.value as SnmpSecretsForm["authProtocol"] })}
          >
            {AUTH_PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {AUTH_PROTOCOL_LABELS[p]}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Protocolo de cifrado</span>
          <select
            className="input input--select"
            value={form.privProtocol}
            onChange={(e) => onChange({ ...form, privProtocol: e.target.value as SnmpSecretsForm["privProtocol"] })}
          >
            {PRIV_PROTOCOLS.map((p) => (
              <option key={p} value={p}>
                {PRIV_PROTOCOL_LABELS[p]}
              </option>
            ))}
          </select>
        </label>
      </div>
      <label>
        <span>{rotating ? "Password de autenticación nueva (vacío = sin cambios)" : "Password de autenticación"}</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          value={form.authPassword}
          onChange={(e) => onChange({ ...form, authPassword: e.target.value })}
          maxLength={128}
          required={!rotating}
        />
      </label>
      <label>
        <span>{rotating ? "Password de cifrado nueva (vacío = sin cambios)" : "Password de cifrado"}</span>
        <input
          className="input"
          type="password"
          autoComplete="new-password"
          spellCheck={false}
          value={form.privPassword}
          onChange={(e) => onChange({ ...form, privPassword: e.target.value })}
          maxLength={128}
          required={!rotating}
        />
      </label>
      <p className="muted small">Entre 8 y 128 caracteres; la de autenticación y la de cifrado deben ser distintas.</p>
    </>
  );
}

function V2cWarning() {
  return (
    <div className="banner banner--warn" role="note">
      SNMPv2c es un protocolo heredado e inseguro: la comunidad viaja en claro por la red del site y cualquiera que la
      capture puede leer el inventario del equipo. Úsalo solo con equipos que no admitan SNMPv3.
    </div>
  );
}

function CreateProfileModal({
  sites,
  initialSiteId,
  v2cAllowed,
  onClose,
  onDone,
}: {
  sites: Site[];
  initialSiteId?: string;
  v2cAllowed: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const [siteId, setSiteId] = useState(
    sites.some((s) => s.site_id === initialSiteId) ? (initialSiteId ?? "") : (sites[0]?.site_id ?? ""),
  );
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [version, setVersion] = useState<SnmpVersion>("v3");
  const [secrets, setSecrets] = useState<SnmpSecretsForm>(EMPTY_SECRETS);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const invalid = !siteId ? "Elige un site." : !name.trim() ? "Indica un nombre." : validateSecrets(version, secrets);
    if (invalid) {
      setError(invalid);
      return;
    }
    const body = buildProfileCreate(siteId, name, description, version, secrets);
    // Los secretos salen del estado ya: no quedan en el formulario ni tras un error.
    setSecrets(withoutSecrets(secrets));
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.createProfile(body);
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Nuevo perfil SNMP" onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)} autoComplete="off">
        <label>
          <span>Site</span>
          <select className="input input--select" value={siteId} onChange={(e) => setSiteId(e.target.value)}>
            {sites.map((s) => (
              <option key={s.site_id} value={s.site_id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Nombre del perfil</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required />
        </label>
        <label>
          <span>Descripción (opcional)</span>
          <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
        </label>
        <label>
          <span>Versión SNMP</span>
          <select
            className="input input--select"
            value={version}
            onChange={(e) => {
              setVersion(e.target.value as SnmpVersion);
              // Al cambiar de versión no se arrastran secretos de la otra.
              setSecrets(withoutSecrets(secrets));
            }}
          >
            <option value="v3">{SNMP_VERSION_LABELS.v3}</option>
            {v2cAllowed && <option value="v2c">{SNMP_VERSION_LABELS.v2c}</option>}
          </select>
        </label>
        {version === "v2c" && <V2cWarning />}
        <SecretsFields version={version} form={secrets} onChange={setSecrets} />
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
            {busy ? "Guardando…" : "Crear perfil"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RotateProfileModal({
  profile,
  onClose,
  onDone,
}: {
  profile: SnmpProfile;
  onClose: () => void;
  onDone: () => void;
}) {
  const [secrets, setSecrets] = useState<SnmpSecretsForm>({
    ...EMPTY_SECRETS,
    username: profile.username ?? "",
    authProtocol: profile.auth_protocol ?? EMPTY_SECRETS.authProtocol,
    privProtocol: profile.priv_protocol ?? EMPTY_SECRETS.privProtocol,
  });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const invalid = validateSecrets(profile.snmp_version, secrets, true);
    if (invalid) {
      setError(invalid);
      return;
    }
    const body = buildProfileRotate(profile.version, profile.snmp_version, secrets, profile);
    setSecrets(withoutSecrets(secrets));
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.rotateProfile(profile.profile_id, body);
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      // 409 de versión: se recarga la lista para que el administrador vea el estado actual.
      if (isVersionConflict(err)) onDone();
    }
  };

  return (
    <Modal title={`Rotar secretos de ${profile.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)} autoComplete="off">
        <p>
          Los secretos nuevos sustituyen a los actuales para todos los equipos que usan este perfil
          ({profile.devices_count}). Cambia antes las credenciales en los equipos o las consultas fallarán con error de
          autenticación.
        </p>
        {profile.snmp_version === "v2c" && <V2cWarning />}
        <SecretsFields version={profile.snmp_version} form={secrets} onChange={setSecrets} rotating />
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
            {busy ? "Rotando…" : "Rotar secretos"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function EditProfileModal({
  profile,
  onClose,
  onDone,
}: {
  profile: SnmpProfile;
  onClose: () => void;
  onDone: () => void;
}) {
  const [name, setName] = useState(profile.name);
  const [description, setDescription] = useState(profile.description ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.updateProfile(profile.profile_id, {
        version: profile.version,
        ...(name.trim() !== profile.name ? { name: name.trim() } : {}),
        ...(description.trim() !== (profile.description ?? "") ? { description: description.trim() || null } : {}),
      });
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      if (isVersionConflict(err)) onDone();
    }
  };

  return (
    <Modal title={`Editar perfil ${profile.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p className="muted small">Solo nombre y descripción. Para cambiar usuario, protocolos o secretos, usa «Rotar».</p>
        <label>
          <span>Nombre del perfil</span>
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} maxLength={100} required />
        </label>
        <label>
          <span>Descripción</span>
          <input className="input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
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
          <button type="submit" className="button button--primary" disabled={busy || !name.trim()}>
            {busy ? "Guardando…" : "Guardar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function RevokeProfileModal({
  profile,
  onClose,
  onDone,
}: {
  profile: SnmpProfile;
  onClose: () => void;
  onDone: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!reason.trim()) return;
    setBusy(true);
    setError(undefined);
    try {
      await networkApi.revokeProfile(profile.profile_id, profile.version, reason.trim());
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      if (isVersionConflict(err)) onDone();
    }
  };
  return (
    <Modal title={`Revocar perfil ${profile.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p>
          El secreto cifrado deja de poder usarse de inmediato. Los {profile.devices_count} equipos que lo usan no podrán
          consultarse hasta asignarles otro perfil. La revocación no se puede deshacer.
        </p>
        <label>
          <span>Motivo</span>
          <textarea className="input" value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} required />
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
          <button type="submit" className="button button--danger" disabled={busy || !reason.trim()}>
            {busy ? "Revocando…" : "Revocar perfil"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

type ProfileAction = { kind: "rotate" | "edit" | "revoke"; profile: SnmpProfile };

/**
 * Perfiles de credenciales SNMP (snmp_credentials:manage). Los secretos son de solo
 * escritura: la tabla solo dice si hay un secreto configurado y cuándo cambió.
 */
export function SnmpProfilesPanel() {
  const site = useSite();
  const { scopeId } = site;
  const [includeRevoked, setIncludeRevoked] = useState(false);
  const fetchProfiles = useCallback(
    (signal: AbortSignal) => networkApi.profiles(scopeId, includeRevoked, signal),
    [scopeId, includeRevoked],
  );
  const profiles = usePolling(fetchProfiles, config.refreshIntervalMs * 4, true, true);
  const [creating, setCreating] = useState(false);
  const [action, setAction] = useState<ProfileAction>();

  const data = profiles.data;
  const storeAvailable = data?.secret_store_available ?? false;
  const showSite = !scopeId && site.sites.length > 1;
  const activeSites = site.sites.filter((s) => s.status === "active");

  return (
    <section className="panel" aria-label="Perfiles SNMP">
      <div className="panel__toolbar">
        <h2>Perfiles SNMP</h2>
        <span className="muted small">Credenciales por site. Los secretos nunca se muestran después de guardarlos.</span>
        <label className="checkbox small">
          <input type="checkbox" checked={includeRevoked} onChange={(e) => setIncludeRevoked(e.target.checked)} /> Mostrar
          revocados
        </label>
        {data && storeAvailable && (
          <button type="button" className="button button--primary nowrap" onClick={() => setCreating(true)}>
            Nuevo perfil
          </button>
        )}
      </div>
      {data && !storeAvailable && (
        <div className="banner banner--warn" role="note">
          El servidor no tiene configurado el almacén cifrado de secretos, así que no se pueden crear perfiles ni rotar
          secretos. Un administrador del servidor debe configurar la clave de cifrado de credenciales SNMP y reiniciar la
          API.
        </div>
      )}
      {data && profiles.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(profiles.error)}. Se muestran los últimos datos.
        </div>
      )}
      {!data ? (
        profiles.error ? (
          <ErrorState message={errorMessage(profiles.error)} onRetry={profiles.refresh} />
        ) : (
          <LoadingState label="Cargando perfiles SNMP…" />
        )
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin perfiles SNMP">
          {storeAvailable ? "Crea un perfil para poder consultar equipos por SNMP." : undefined}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Nombre</th>
                {showSite && <th>Site</th>}
                <th>Versión</th>
                <th>Usuario / protocolos</th>
                <th>Secreto</th>
                <th>Equipos</th>
                <th>Estado</th>
                <th aria-label="Acciones" />
              </tr>
            </thead>
            <tbody>
              {data.items.map((profile) => {
                const revoked = profile.status === "revoked";
                return (
                  <tr key={profile.profile_id}>
                    <td>
                      <span className="strong">{profile.name}</span>
                      {profile.description && <div className="muted small">{profile.description}</div>}
                    </td>
                    {showSite && <td className="small">{profile.site_name}</td>}
                    <td>
                      {SNMP_VERSION_LABELS[profile.snmp_version]}
                      {profile.snmp_version === "v2c" && <div className="badge badge--warn">inseguro</div>}
                    </td>
                    <td className="small">
                      {profile.snmp_version === "v3" ? (
                        <>
                          <span className="mono">{profile.username ?? "—"}</span>
                          <div className="muted">
                            {profile.auth_protocol ? AUTH_PROTOCOL_LABELS[profile.auth_protocol] : "—"} /{" "}
                            {profile.priv_protocol ? PRIV_PROTOCOL_LABELS[profile.priv_protocol] : "—"}
                          </div>
                        </>
                      ) : (
                        <span className="muted">comunidad</span>
                      )}
                    </td>
                    <td className="small">
                      {profile.secret_configured ? (
                        <span title={formatDateTime(profile.secret_updated_at)}>
                          Secreto configurado
                          {profile.secret_updated_at && (
                            <div className="muted">actualizado {formatRelative(profile.secret_updated_at)}</div>
                          )}
                        </span>
                      ) : (
                        <span className="muted">Sin secreto</span>
                      )}
                    </td>
                    <td>{profile.devices_count}</td>
                    <td className="small">
                      {revoked ? (
                        <span title={profile.revoke_reason ?? undefined}>
                          Revocado {profile.revoked_at && formatRelative(profile.revoked_at)}
                          {profile.revoke_reason && <div className="muted">{profile.revoke_reason}</div>}
                        </span>
                      ) : (
                        "Activo"
                      )}
                    </td>
                    <td>
                      {!revoked && (
                        <div className="actions">
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Editar perfil ${profile.name}`}
                            onClick={() => setAction({ kind: "edit", profile })}
                          >
                            Editar
                          </button>
                          {storeAvailable && (
                            <button
                              type="button"
                              className="button button--small"
                              aria-label={`Rotar secretos de ${profile.name}`}
                              onClick={() => setAction({ kind: "rotate", profile })}
                            >
                              Rotar
                            </button>
                          )}
                          <button
                            type="button"
                            className="button button--small button--danger"
                            aria-label={`Revocar perfil ${profile.name}`}
                            onClick={() => setAction({ kind: "revoke", profile })}
                          >
                            Revocar
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {creating && data && (
        <CreateProfileModal
          sites={activeSites}
          initialSiteId={scopeId}
          v2cAllowed={data.v2c_allowed}
          onClose={() => setCreating(false)}
          onDone={profiles.refresh}
        />
      )}
      {action?.kind === "rotate" && (
        <RotateProfileModal profile={action.profile} onClose={() => setAction(undefined)} onDone={profiles.refresh} />
      )}
      {action?.kind === "edit" && (
        <EditProfileModal profile={action.profile} onClose={() => setAction(undefined)} onDone={profiles.refresh} />
      )}
      {action?.kind === "revoke" && (
        <RevokeProfileModal profile={action.profile} onClose={() => setAction(undefined)} onDone={profiles.refresh} />
      )}
    </section>
  );
}
