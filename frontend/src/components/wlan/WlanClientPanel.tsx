import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { identityApi, wlanClientApi } from "../../api/sentra7b";
import type { IdentityLinkPreview, IdentityLinkRead } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { blockerText, effectText, evidenceText } from "../../lib/identity7b";
import { useAssetOptions } from "../../lib/useAssetOptions";
import { usePolling } from "../../lib/usePolling";
import { BAND_LABELS, CLIENT_STATE_LABELS, CORRELATION_LABELS, IDENTITY_LABELS, SOURCE_LABELS } from "../../lib/wlan";
import { Icon } from "../icons";
import { trapTab } from "../layout/navKeys";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";
import { ObservationTable } from "./AccessPointPanel";
import { EvidenceBadges, MacText } from "./WlanBadges";

const REASON_MAX = 500;

/** Asociar el cliente a un activo: buscar el activo, vista previa del servidor y motivo. */
function LinkClientDialog({ clientId, onClose, onDone }: { clientId: string; onClose: () => void; onDone: () => void }) {
  const [query, setQuery] = useState("");
  const [target, setTarget] = useState("");
  const options = useAssetOptions(query, target);
  const [preview, setPreview] = useState<IdentityLinkPreview>();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    if (!target) return;
    let active = true;
    identityApi
      .preview({ kind: "wlan_client", target_asset_id: target, wlan_client_id: clientId })
      .then((result) => {
        if (!active) return;
        setPreview(result);
        setError(undefined);
      })
      .catch((err: unknown) => active && setError(errorMessage(err instanceof Error ? err : new Error(String(err)))));
    return () => {
      active = false;
    };
  }, [target, clientId]);

  const trimmed = reason.trim();
  const current = preview && preview.target.asset_id === target ? preview : undefined;
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await identityApi.create({ kind: "wlan_client", target_asset_id: target, wlan_client_id: clientId, reason: trimmed });
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };

  return (
    <Modal title="Asociar cliente Wi-Fi a un activo" onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p className="small muted">
          Solo cuando sabes qué equipo es (por ejemplo, lo compruebas en el propio dispositivo). Una MAC privada no se
          usa como prueba: la asociación queda como manual y auditada, y se puede revocar.
        </p>
        <label className="field">
          <span>Buscar activo</span>
          <input className="input" value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Nombre o IP" />
        </label>
        <label className="field">
          <span>Activo</span>
          <select
            className="input input--select"
            value={target}
            onChange={(e) => {
              setTarget(e.target.value);
              setPreview(undefined);
            }}
          >
            <option value="">Elige un activo…</option>
            {options.map((o) => (
              <option key={o.asset_id} value={o.asset_id}>
                {o.display_name}
                {o.primary_ip && o.primary_ip !== o.display_name ? ` (${o.primary_ip})` : ""}
              </option>
            ))}
          </select>
        </label>
        {target && !current && !error && <LoadingState label="Calculando vista previa…" />}
        {current && (
          <>
            {current.blockers.length > 0 && (
              <div className="banner banner--warn" role="alert">
                No se puede asociar:
                <ul>
                  {current.blockers.map((code) => (
                    <li key={code}>{blockerText(code)}</li>
                  ))}
                </ul>
              </div>
            )}
            {current.evidence.length > 0 && (
              <ul className="small">
                {current.evidence.map((e) => (
                  <li key={`${e.code}-${e.detail ?? ""}`}>{evidenceText(e)}</li>
                ))}
              </ul>
            )}
            {current.allowed && (
              <>
                <ul className="small">
                  {current.effects.map((code) => (
                    <li key={code}>{effectText(code)}</li>
                  ))}
                </ul>
                <label className="field">
                  <span>Motivo (queda en la auditoría)</span>
                  <textarea
                    className="input"
                    rows={3}
                    maxLength={REASON_MAX}
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                  />
                </label>
              </>
            )}
          </>
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
          <button
            type="button"
            className="button button--primary"
            disabled={busy || !current?.allowed || trimmed.length < 3}
            onClick={() => void submit()}
          >
            {busy ? "Asociando…" : "Confirmar asociación"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function RevokeClientLink({ link, onDone }: { link: IdentityLinkRead; onDone: () => void }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async () => {
    setBusy(true);
    try {
      await identityApi.revoke(link.link_id, reason.trim());
      setOpen(false);
      onDone();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };
  return (
    <>
      <button type="button" className="button button--small" onClick={() => setOpen(true)}>
        Revocar
      </button>
      {open && (
        <Modal title="Revocar asociación del cliente" onClose={busy ? () => undefined : () => setOpen(false)}>
          <div className="stack">
            <label className="field">
              <span>Motivo</span>
              <textarea className="input" rows={2} maxLength={REASON_MAX} value={reason} onChange={(e) => setReason(e.target.value)} />
            </label>
            {error && (
              <div className="banner banner--warn" role="alert">
                {error}
              </div>
            )}
            <div className="modal__actions">
              <button type="button" className="button" onClick={() => setOpen(false)} disabled={busy}>
                Cancelar
              </button>
              <button
                type="button"
                className="button button--danger"
                disabled={busy || reason.trim().length < 3}
                onClick={() => void submit()}
              >
                Revocar
              </button>
            </div>
          </div>
        </Modal>
      )}
    </>
  );
}

/**
 * Fase 7B.2: detalle de un cliente Wi-Fi con su historial de observaciones y, para un admin,
 * la asociación manual a un activo. No se habla con el router: los datos vienen de las
 * fuentes que ya existen (SNMP del controlador e informes de agentes).
 */
export function WlanClientPanel({ clientId, onClose, onChanged }: { clientId: string; onClose: () => void; onChanged: () => void }) {
  const canManage = useAuth().can("identity:manage");
  const fetcher = useCallback(
    async (signal: AbortSignal) => {
      const [client, observations, links] = await Promise.all([
        wlanClientApi.get(clientId, signal),
        wlanClientApi.observations(clientId, signal),
        identityApi.links({ wlanClientId: clientId }, signal),
      ]);
      return { client, observations: observations.items, links: links.items };
    },
    [clientId],
  );
  const state = usePolling(fetcher, config.refreshIntervalMs * 2);
  const [linking, setLinking] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panelRef.current?.focus();
    return () => {
      if (opener && opener.isConnected) opener.focus();
    };
  }, []);
  useEffect(() => {
    if (linking) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, linking]);
  const changed = () => {
    state.refresh();
    onChanged();
  };
  const client = state.data?.client;
  const active = state.data?.links.find((l) => l.active);

  return (
    <div className="side-panel-layer side-panel-layer--dim" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panelRef}
        className="side-panel"
        role="dialog"
        aria-modal="true"
        aria-label="Detalle del cliente Wi-Fi"
        tabIndex={-1}
        onKeyDown={linking ? undefined : trapTab}
      >
        <div className="modal__header">
          <h2>Cliente Wi-Fi</h2>
          <button type="button" className="iconbutton" onClick={onClose} aria-label="Cerrar detalle">
            <Icon name="close" />
          </button>
        </div>
        <div className="modal__body stack">
          {!client ? (
            state.error ? (
              <ErrorState message={errorMessage(state.error)} onRetry={state.refresh} />
            ) : (
              <LoadingState label="Cargando cliente…" />
            )
          ) : (
            <>
              <dl className="fields fields--inline">
                <div className="field">
                  <dt>MAC</dt>
                  <dd>
                    <MacText mac={client.mac} randomized={client.mac_randomized} />
                  </dd>
                </div>
                <div className="field">
                  <dt>Activo</dt>
                  <dd>
                    {client.asset ? (
                      <Link to={`/assets/${client.asset.asset_id}`}>{client.asset.display_name}</Link>
                    ) : (
                      <span className="muted">Sin activo asociado</span>
                    )}
                  </dd>
                </div>
                <div className="field">
                  <dt>Identidad</dt>
                  <dd>
                    {IDENTITY_LABELS[client.identity_confidence] ?? client.identity_confidence}
                    {client.correlation_basis && (
                      <div className="muted small">{CORRELATION_LABELS[client.correlation_basis] ?? client.correlation_basis}</div>
                    )}
                  </dd>
                </div>
                <div className="field">
                  <dt>Red</dt>
                  <dd>
                    {client.ssid ?? "—"} {client.band && <span className="muted small">({BAND_LABELS[client.band]})</span>}
                    {client.bssid && <div className="mono small">{client.bssid}</div>}
                  </dd>
                </div>
                <div className="field">
                  <dt>Estado</dt>
                  <dd>
                    {CLIENT_STATE_LABELS[client.state] ?? client.state}{" "}
                    <span className="muted small">({SOURCE_LABELS[client.source] ?? client.source})</span>
                  </dd>
                </div>
                <div className="field">
                  <dt>Evidencia</dt>
                  <dd>
                    <EvidenceBadges freshness={client.freshness} present={client.present} />{" "}
                    <span className="muted small" title={formatDateTime(client.last_seen_at)}>
                      {formatRelative(client.last_seen_at)}
                    </span>
                  </dd>
                </div>
              </dl>
              {client.mac_randomized && (
                <p className="small muted">
                  MAC privada: el dispositivo puede cambiarla por red o con el tiempo. Sentra no la usa para unir registros
                  por su cuenta.
                </p>
              )}
              {canManage && (
                <div className="actions">
                  {active ? (
                    <span className="small">
                      Asociado a mano a <strong>{active.target_name}</strong> por {active.created_by}: {active.reason}{" "}
                      <RevokeClientLink link={active} onDone={changed} />
                    </span>
                  ) : (
                    <button type="button" className="button button--small" onClick={() => setLinking(true)}>
                      Asociar a un activo…
                    </button>
                  )}
                </div>
              )}
              <section className="wlan-section" aria-label="Historial de observaciones">
                <h3>Historial de observaciones</h3>
                {state.data && state.data.observations.length > 0 ? (
                  <ObservationTable items={state.data.observations} />
                ) : (
                  <p className="muted small">Sin observaciones guardadas.</p>
                )}
              </section>
            </>
          )}
        </div>
      </div>
      {linking && <LinkClientDialog clientId={clientId} onClose={() => setLinking(false)} onDone={changed} />}
    </div>
  );
}
