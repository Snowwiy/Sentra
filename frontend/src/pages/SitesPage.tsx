import { useCallback, useState, type FormEvent } from "react";
import { ApiError } from "../api/client";
import { sitesApi } from "../api/sentra";
import type { Site, SiteNetwork, SiteStatus } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { ConfirmDialog, Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";

export const SITE_STATUS_LABELS: Record<SiteStatus, string> = {
  active: "Activo",
  disabled: "Deshabilitado",
  archived: "Archivado",
};

const SITE_STATUS_CLASS: Record<SiteStatus, string> = {
  active: "badge badge--ok",
  disabled: "badge badge--warn",
  archived: "badge badge--muted",
};

const SLUG_PATTERN = /^[a-z0-9][a-z0-9-]{0,62}$/;

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/** Un 409 de versión obsoleta: la UI recarga en lugar de sobrescribir en silencio. */
function isConflict(err: unknown): boolean {
  return err instanceof ApiError && err.code === "site_conflict";
}

/** Crear o editar un site. Al editar se manda la `version` leída (409 site_conflict si cambió). */
function SiteFormModal({
  site,
  onClose,
  onSaved,
  onConflict,
}: {
  site?: Site;
  onClose: () => void;
  onSaved: () => void;
  onConflict: (message: string) => void;
}) {
  const [name, setName] = useState(site?.name ?? "");
  const [slug, setSlug] = useState(site?.slug ?? "");
  const [description, setDescription] = useState(site?.description ?? "");
  const [location, setLocation] = useState(site?.location_label ?? "");
  const [timezone, setTimezone] = useState(site?.timezone ?? "UTC");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const slugInvalid = !site && slug.trim() !== "" && !SLUG_PATTERN.test(slug.trim());

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim() || slugInvalid) return;
    setBusy(true);
    setError(undefined);
    try {
      if (site) {
        await sitesApi.update(site.site_id, {
          version: site.version,
          name: name.trim(),
          description: description.trim() || null,
          location_label: location.trim() || null,
          timezone: timezone.trim() || "UTC",
        });
      } else {
        await sitesApi.create({
          name: name.trim(),
          ...(slug.trim() ? { slug: slug.trim() } : {}),
          ...(description.trim() ? { description: description.trim() } : {}),
          ...(location.trim() ? { location_label: location.trim() } : {}),
          ...(timezone.trim() ? { timezone: timezone.trim() } : {}),
        });
      }
      onSaved();
      onClose();
    } catch (err) {
      if (isConflict(err)) {
        onConflict(errorMessage(asError(err)));
        onClose();
        return;
      }
      setError(errorMessage(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title={site ? `Editar site ${site.name}` : "Nuevo site"} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <label>
          <span>Nombre</span>
          <input
            className="input"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={100}
            required
            autoFocus
          />
        </label>
        {!site && (
          <label>
            <span>Identificador (slug, opcional)</span>
            <input
              className="input mono"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              maxLength={63}
              placeholder="se deriva del nombre"
              spellCheck={false}
              aria-invalid={slugInvalid}
            />
            {slugInvalid && (
              <span className="small" role="alert">
                Solo minúsculas, números y guiones; debe empezar por letra o número.
              </span>
            )}
          </label>
        )}
        <label>
          <span>Descripción (opcional)</span>
          <textarea className="input" value={description} onChange={(e) => setDescription(e.target.value)} maxLength={500} />
        </label>
        <label>
          <span>Ubicación (opcional)</span>
          <input className="input" value={location} onChange={(e) => setLocation(e.target.value)} maxLength={200} />
        </label>
        <label>
          <span>Zona horaria (IANA)</span>
          <input
            className="input"
            value={timezone}
            onChange={(e) => setTimezone(e.target.value)}
            placeholder="UTC, Europe/Madrid…"
            spellCheck={false}
          />
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
          <button type="submit" className="button button--primary" disabled={busy || !name.trim() || slugInvalid}>
            {busy ? "Guardando…" : site ? "Guardar" : "Crear site"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Archivar exige motivo y confirmación explícita. */
function ArchiveSiteModal({
  site,
  onClose,
  onDone,
  onConflict,
}: {
  site: Site;
  onClose: () => void;
  onDone: () => void;
  onConflict: (message: string) => void;
}) {
  const [reason, setReason] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!reason.trim() || !confirmed) return;
    setBusy(true);
    setError(undefined);
    try {
      await sitesApi.archive(site.site_id, site.version, reason.trim());
      onDone();
      onClose();
    } catch (err) {
      if (isConflict(err)) {
        onConflict(errorMessage(asError(err)));
        onClose();
        return;
      }
      setError(errorMessage(asError(err)));
      setBusy(false);
    }
  };
  return (
    <Modal title={`Archivar site ${site.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p>
          El site dejará de aparecer en el selector y sus sensores no recibirán trabajos. Sus activos y su
          historial se conservan; se puede restaurar más tarde.
        </p>
        <label>
          <span>Motivo</span>
          <textarea
            className="input"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            maxLength={500}
            required
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo que
          quiero archivar este site
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
          <button type="submit" className="button button--danger" disabled={busy || !reason.trim() || !confirmed}>
            {busy ? "Archivando…" : "Archivar site"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

/** Redes (CIDR) de un site: las que sus sensores pueden analizar. */
function NetworksPanel({ site, canManage, onChanged }: { site: Site; canManage: boolean; onChanged: () => void }) {
  const fetchNetworks = useCallback((signal: AbortSignal) => sitesApi.networks(site.site_id, signal), [site.site_id]);
  const networks = usePolling(fetchNetworks, config.refreshIntervalMs * 4);
  const [cidr, setCidr] = useState("");
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [removing, setRemoving] = useState<SiteNetwork>();
  const archived = site.status === "archived";
  const editable = canManage && !archived;

  const refresh = () => {
    networks.refresh();
    onChanged();
  };

  const add = async (event: FormEvent) => {
    event.preventDefault();
    if (!cidr.trim()) return;
    setBusy(true);
    setError(undefined);
    try {
      await sitesApi.addNetwork(site.site_id, { cidr: cidr.trim(), ...(name.trim() ? { name: name.trim() } : {}) });
      setCidr("");
      setName("");
      refresh();
    } catch (err) {
      setError(errorMessage(asError(err)));
    } finally {
      setBusy(false);
    }
  };

  const toggle = async (network: SiteNetwork) => {
    setError(undefined);
    try {
      await sitesApi.updateNetwork(site.site_id, network.network_id, { enabled: !network.enabled });
      refresh();
    } catch (err) {
      setError(errorMessage(asError(err)));
    }
  };

  const items = networks.data?.items ?? [];
  return (
    <section className="panel" aria-label={`Redes del site ${site.name}`}>
      <div className="panel__toolbar">
        <h2>Redes de {site.name}</h2>
        <span className="muted small">Los sensores del site solo analizan las redes habilitadas.</span>
      </div>
      {networks.loading ? (
        <LoadingState label="Cargando redes…" />
      ) : !networks.data && networks.error ? (
        <ErrorState message={errorMessage(networks.error)} onRetry={networks.refresh} />
      ) : items.length === 0 ? (
        <EmptyState title="Sin redes">
          {editable ? "Añade una red (CIDR) para que los sensores del site puedan descubrirla." : undefined}
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Red</th>
                <th>Nombre</th>
                <th>Direcciones</th>
                <th>Estado</th>
                <th>Creada</th>
                {editable && <th aria-label="Acciones" />}
              </tr>
            </thead>
            <tbody>
              {items.map((network) => (
                <tr key={network.network_id}>
                  <td className="mono">{network.cidr}</td>
                  <td>{network.name ?? <span className="muted">—</span>}</td>
                  <td>{network.host_count}</td>
                  <td>
                    {network.enabled ? (
                      <span className="badge badge--ok">Habilitada</span>
                    ) : (
                      <span className="badge badge--muted">Deshabilitada</span>
                    )}
                  </td>
                  <td className="muted" title={formatDateTime(network.created_at)}>
                    {formatRelative(network.created_at)}
                  </td>
                  {editable && (
                    <td>
                      <div className="actions">
                        <button
                          type="button"
                          className="button button--small"
                          onClick={() => void toggle(network)}
                          aria-label={`${network.enabled ? "Deshabilitar" : "Habilitar"} red ${network.cidr}`}
                        >
                          {network.enabled ? "Deshabilitar" : "Habilitar"}
                        </button>
                        <button
                          type="button"
                          className="button button--small button--danger"
                          onClick={() => setRemoving(network)}
                          aria-label={`Quitar red ${network.cidr}`}
                        >
                          Quitar
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {editable && (
        <form className="toolbar" onSubmit={(event) => void add(event)} aria-label="Añadir red">
          <label className="form-field form-field--inline">
            <span>CIDR</span>
            <input
              className="input mono"
              value={cidr}
              onChange={(e) => setCidr(e.target.value)}
              placeholder="192.168.10.0/24"
              spellCheck={false}
              required
            />
          </label>
          <label className="form-field form-field--inline">
            <span>Nombre</span>
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="opcional" />
          </label>
          <button type="submit" className="button button--primary" disabled={busy || !cidr.trim()}>
            {busy ? "Añadiendo…" : "Añadir red"}
          </button>
        </form>
      )}
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {removing && (
        <ConfirmDialog
          title="Quitar red"
          confirmLabel="Quitar red"
          danger
          onClose={() => setRemoving(undefined)}
          onConfirm={async () => {
            await sitesApi.removeNetwork(site.site_id, removing.network_id);
            refresh();
          }}
        >
          <p>
            Los sensores de {site.name} dejarán de poder analizar <span className="mono">{removing.cidr}</span>. Los
            activos ya descubiertos se conservan.
          </p>
        </ConfirmDialog>
      )}
    </section>
  );
}

type Dialog =
  | { kind: "create" }
  | { kind: "edit"; site: Site }
  | { kind: "archive"; site: Site }
  | { kind: "restore"; site: Site }
  | { kind: "status"; site: Site; status: "active" | "disabled" };

/**
 * Configuración → Sites (Fase 5F). Todos los roles ven los sites y sus redes; solo
 * sites:manage crea, edita, deshabilita, archiva y gestiona redes. El backend lo vuelve a
 * comprobar en cada petición: ocultar los botones es solo UX.
 */
export function SitesPage() {
  const auth = useAuth();
  const canManage = auth.can("sites:manage");
  const siteContext = useSite();
  const fetchSites = useCallback((signal: AbortSignal) => sitesApi.list(signal), []);
  const sites = usePolling(fetchSites, config.refreshIntervalMs * 4);
  const [showArchived, setShowArchived] = useState(false);
  const [dialog, setDialog] = useState<Dialog>();
  const [selected, setSelected] = useState<string>();
  const [notice, setNotice] = useState<string>();

  const refreshSites = sites.refresh;
  const refreshContext = siteContext.refresh;
  const changed = useCallback(() => {
    refreshSites();
    // El selector global también ve el cambio (nombre, estado, archivado).
    refreshContext();
  }, [refreshSites, refreshContext]);
  const conflict = useCallback(
    (message: string) => {
      setNotice(message);
      changed();
    },
    [changed],
  );

  if (sites.loading) return <LoadingState label="Cargando sites…" />;
  if (!sites.data && sites.error) return <ErrorState message={errorMessage(sites.error)} onRetry={sites.refresh} />;

  const all = sites.data?.items ?? [];
  const archivedCount = all.filter((s) => s.status === "archived").length;
  const visible = all.filter((s) => showArchived || s.status !== "archived");
  const selectedSite = all.find((s) => s.site_id === selected);

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Sites</h1>
          <p className="muted small">
            Ubicaciones o redes separadas, cada una con sus activos, redes y sensores.
            {!canManage && " Solo lectura: la gestión de sites es exclusiva de administradores."}
          </p>
        </div>
        {canManage && (
          <button type="button" className="button button--primary" onClick={() => setDialog({ kind: "create" })}>
            + Nuevo site
          </button>
        )}
      </div>

      {notice && (
        <div className="banner banner--warn" role="alert">
          {notice}{" "}
          <button type="button" className="link-button" onClick={() => setNotice(undefined)}>
            Cerrar aviso
          </button>
        </div>
      )}
      {sites.error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(sites.error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <section className="panel" aria-label="Sites">
        <div className="panel__toolbar">
          <h2>
            Sites <span className="muted">({visible.length})</span>
          </h2>
          <label className="checkbox small">
            <input type="checkbox" checked={showArchived} onChange={(e) => setShowArchived(e.target.checked)} />{" "}
            Mostrar archivados{archivedCount ? ` (${archivedCount})` : ""}
          </label>
        </div>
        {visible.length === 0 ? (
          <EmptyState title="Sin sites" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Nombre</th>
                  <th>Slug</th>
                  <th>Estado</th>
                  <th>Ubicación</th>
                  <th>Zona horaria</th>
                  <th>Activos</th>
                  <th>Sensores</th>
                  <th>Redes</th>
                  <th>Actualizado</th>
                  <th aria-label="Acciones" />
                </tr>
              </thead>
              <tbody>
                {visible.map((site) => (
                  <tr key={site.site_id}>
                    <td>
                      <span className="strong">{site.name}</span>
                      {site.is_default && <span className="badge badge--info"> por defecto</span>}
                      {site.description && <div className="muted small">{site.description}</div>}
                    </td>
                    <td className="mono small">{site.slug}</td>
                    <td>
                      <span className={SITE_STATUS_CLASS[site.status]}>{SITE_STATUS_LABELS[site.status]}</span>
                    </td>
                    <td>{site.location_label ?? <span className="muted">—</span>}</td>
                    <td className="small">{site.timezone}</td>
                    <td>{site.asset_count}</td>
                    <td>{site.sensor_count}</td>
                    <td>{site.network_count}</td>
                    <td className="muted" title={formatDateTime(site.updated_at)}>
                      {formatRelative(site.updated_at)}
                    </td>
                    <td>
                      <div className="actions">
                        <button
                          type="button"
                          className="button button--small"
                          aria-pressed={site.site_id === selected}
                          aria-label={`Redes de ${site.name}`}
                          onClick={() => setSelected(site.site_id === selected ? undefined : site.site_id)}
                        >
                          Redes
                        </button>
                        {canManage && site.status !== "archived" && (
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Editar ${site.name}`}
                            onClick={() => setDialog({ kind: "edit", site })}
                          >
                            Editar
                          </button>
                        )}
                        {canManage && !site.is_default && site.status === "active" && (
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Deshabilitar ${site.name}`}
                            onClick={() => setDialog({ kind: "status", site, status: "disabled" })}
                          >
                            Deshabilitar
                          </button>
                        )}
                        {canManage && site.status === "disabled" && (
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Activar ${site.name}`}
                            onClick={() => setDialog({ kind: "status", site, status: "active" })}
                          >
                            Activar
                          </button>
                        )}
                        {canManage && !site.is_default && site.status !== "archived" && (
                          <button
                            type="button"
                            className="button button--small button--danger"
                            aria-label={`Archivar ${site.name}`}
                            onClick={() => setDialog({ kind: "archive", site })}
                          >
                            Archivar
                          </button>
                        )}
                        {canManage && site.status === "archived" && (
                          <button
                            type="button"
                            className="button button--small"
                            aria-label={`Restaurar ${site.name}`}
                            onClick={() => setDialog({ kind: "restore", site })}
                          >
                            Restaurar
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {selectedSite && <NetworksPanel key={selectedSite.site_id} site={selectedSite} canManage={canManage} onChanged={changed} />}

      {(dialog?.kind === "create" || dialog?.kind === "edit") && (
        <SiteFormModal
          site={dialog.kind === "edit" ? dialog.site : undefined}
          onClose={() => setDialog(undefined)}
          onSaved={changed}
          onConflict={conflict}
        />
      )}
      {dialog?.kind === "archive" && (
        <ArchiveSiteModal site={dialog.site} onClose={() => setDialog(undefined)} onDone={changed} onConflict={conflict} />
      )}
      {dialog?.kind === "restore" && (
        <ConfirmDialog
          title={`Restaurar site ${dialog.site.name}`}
          confirmLabel="Restaurar"
          onClose={() => setDialog(undefined)}
          onConfirm={async () => {
            try {
              await sitesApi.restore(dialog.site.site_id, dialog.site.version);
              changed();
            } catch (err) {
              if (isConflict(err)) changed();
              throw err;
            }
          }}
        >
          <p>El site vuelve a estar activo y a aparecer en el selector.</p>
        </ConfirmDialog>
      )}
      {dialog?.kind === "status" && (
        <ConfirmDialog
          title={`${dialog.status === "disabled" ? "Deshabilitar" : "Activar"} site ${dialog.site.name}`}
          confirmLabel={dialog.status === "disabled" ? "Deshabilitar" : "Activar"}
          danger={dialog.status === "disabled"}
          onClose={() => setDialog(undefined)}
          onConfirm={async () => {
            try {
              await sitesApi.update(dialog.site.site_id, { version: dialog.site.version, status: dialog.status });
              changed();
            } catch (err) {
              if (isConflict(err)) changed();
              throw err;
            }
          }}
        >
          <p>
            {dialog.status === "disabled"
              ? "Un site deshabilitado conserva sus datos, pero no acepta nuevos descubrimientos ni tokens de sensor."
              : "El site vuelve a aceptar descubrimientos y tokens de sensor."}
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}
