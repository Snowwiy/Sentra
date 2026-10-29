import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { wlanApi } from "../../api/sentra";
import type { WlanAccessPointDetail, WlanAuthorizationStatus, WlanObservationRead } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import {
  AUTHORIZATION_ACTIONS,
  authorizationTargets,
  BAND_LABELS,
  CONFIDENCE_LABELS,
  entityLabel,
  FINDING_LABELS,
  LINK_BASIS_LABELS,
  observationProvenance,
  SOURCE_LABELS,
  summarizeObservationData,
} from "../../lib/wlan";
import { trapTab } from "../layout/navKeys";
import { Icon } from "../icons";
import { ErrorState, LoadingState } from "../StateViews";
import { AuthorizationModal, LinkModal, UnlinkModal } from "./WlanActions";
import {
  ApStatusBadge,
  AuthorizationBadge,
  EvidenceBadges,
  FindingBadges,
  MacText,
  ProtectionLabel,
} from "./WlanBadges";

export const OBSERVATION_PAGE_SIZE = 50;

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd>{children}</dd>
    </div>
  );
}

const none = <span className="muted">no informado</span>;

function When({ iso }: { iso: string | null }) {
  if (!iso) return <span className="muted">—</span>;
  return (
    <time dateTime={iso} title={formatDateTime(iso)}>
      {formatRelative(iso)}
    </time>
  );
}

export function ObservationTable({ items }: { items: WlanObservationRead[] }) {
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Observado</th>
            <th>Entidad</th>
            <th>Procedencia</th>
            <th>Confianza</th>
            <th>Datos</th>
          </tr>
        </thead>
        <tbody>
          {items.map((observation) => (
            <tr key={observation.observation_id}>
              <td className="nowrap">
                <span title={`Recibido: ${formatDateTime(observation.received_at)}`}>
                  {formatDateTime(observation.observed_at)}
                </span>
              </td>
              <td>{entityLabel(observation.entity)}</td>
              <td className="small">{observationProvenance(observation)}</td>
              <td className="small">{CONFIDENCE_LABELS[observation.confidence] ?? observation.confidence}</td>
              <td className="small mono">{summarizeObservationData(observation.data)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Historial: las 50 más recientes vienen en el detalle; el resto se pide por páginas. */
function ObservationHistory({ ap }: { ap: WlanAccessPointDetail }) {
  const [extra, setExtra] = useState<WlanObservationRead[]>([]);
  const [total, setTotal] = useState<number>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const shown = [...ap.observations, ...extra];
  const more = total === undefined ? ap.observations.length >= OBSERVATION_PAGE_SIZE : shown.length < total;

  const loadMore = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const page = await wlanApi.accessPointObservations(ap.access_point_id, {
        limit: OBSERVATION_PAGE_SIZE,
        offset: shown.length,
      });
      setExtra((current) => [...current, ...page.items]);
      setTotal(page.total);
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="wlan-section" aria-label="Historial de observaciones">
      <h3>Historial de observaciones</h3>
      <p className="muted small">
        Cada fila es lo que informó una fuente en un momento dado, con su procedencia. El historial solo crece cuando los
        datos cambian o ha pasado al menos una hora.
      </p>
      {shown.length === 0 ? (
        <p className="muted small">Sin observaciones guardadas.</p>
      ) : (
        <ObservationTable items={shown} />
      )}
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {more && (
        <button type="button" className="button" disabled={busy} onClick={() => void loadMore()}>
          {busy ? "Cargando…" : "Cargar más observaciones"}
        </button>
      )}
    </section>
  );
}

function Details({
  ap,
  canManage,
  onAuthorize,
  onLink,
  onUnlink,
}: {
  ap: WlanAccessPointDetail;
  canManage: boolean;
  onAuthorize: (target: WlanAuthorizationStatus) => void;
  onLink: () => void;
  onUnlink: () => void;
}) {
  const linked = Boolean(ap.asset || ap.network_device);
  return (
    <>
      <div className="wlan-badges">
        <ApStatusBadge status={ap.reported_status} />
        <AuthorizationBadge status={ap.authorization_status} />
        <EvidenceBadges freshness={ap.freshness} present={ap.present} />
      </div>
      {canManage && (
        <div className="actions" aria-label="Acciones sobre el AP" role="group">
          {authorizationTargets(ap.authorization_status).map((target) => (
            <button key={target} type="button" className="button button--small" onClick={() => onAuthorize(target)}>
              {AUTHORIZATION_ACTIONS[target]}
            </button>
          ))}
          <button type="button" className="button button--small" onClick={onLink}>
            Vincular
          </button>
          {linked && (
            <button type="button" className="button button--small button--danger" onClick={onUnlink}>
              Desvincular
            </button>
          )}
        </div>
      )}
      {ap.findings.length > 0 && (
        <div className="banner banner--warn" role="note">
          <span className="strong">Configuración insegura observada (informativo):</span>{" "}
          {ap.findings.map((f) => FINDING_LABELS[f.code] ?? f.code).join(", ")}. No afecta al riesgo ni dispara acciones.
        </div>
      )}

      <section className="wlan-section" aria-label="Identidad del AP">
        <h3>Identidad y procedencia</h3>
        <dl className="fields">
          <Field label="Nombre informado">{ap.name ?? none}</Field>
          <Field label="Site">{ap.site_name}</Field>
          <Field label="Fabricante / modelo">
            {ap.vendor || ap.model ? [ap.vendor, ap.model].filter(Boolean).join(" ") : none}
          </Field>
          <Field label="Firmware">{ap.firmware ?? none}</Field>
          <Field label="Número de serie">{ap.serial_number ?? none}</Field>
          <Field label="Ubicación">{ap.location ?? none}</Field>
          <Field label="IP de gestión">{ap.management_ip ? <span className="mono">{ap.management_ip}</span> : none}</Field>
          <Field label="MAC Ethernet">
            {ap.ethernet_mac ? <span className="mono">{ap.ethernet_mac}</span> : none}
          </Field>
          <Field label="MAC de radio">{ap.radio_mac ? <span className="mono">{ap.radio_mac}</span> : none}</Field>
          <Field label="Fuente">
            {SOURCE_LABELS[ap.source] ?? ap.source}
            <div className="muted small">{CONFIDENCE_LABELS[ap.confidence] ?? ap.confidence}</div>
          </Field>
          <Field label="Informado por">
            {ap.reported_by ? (
              <Link to={`/infrastructure/devices/${ap.reported_by.device_id}`}>{ap.reported_by.display_name}</Link>
            ) : (
              none
            )}
            {ap.sensor && <div className="muted small">sensor {ap.sensor.name}</div>}
          </Field>
          <Field label="Visto">
            primera vez <When iso={ap.first_seen_at} />
            <div className="muted small">
              última vez <When iso={ap.last_seen_at} />
            </div>
          </Field>
        </dl>
      </section>

      <section className="wlan-section" aria-label="Clasificación y vínculos">
        <h3>Clasificación y vínculos</h3>
        <dl className="fields">
          <Field label="Clasificación">
            <AuthorizationBadge status={ap.authorization_status} />
            {ap.authorization_by && (
              <div className="muted small">
                por {ap.authorization_by} <When iso={ap.authorization_at} />
              </div>
            )}
            {ap.authorization_reason && <div className="small">{ap.authorization_reason}</div>}
          </Field>
          <Field label="Equipo de red">
            {ap.network_device ? (
              <Link to={`/infrastructure/devices/${ap.network_device.device_id}`}>{ap.network_device.display_name}</Link>
            ) : (
              <span className="muted">sin vincular</span>
            )}
            {ap.link_evidence.network_device && (
              <div className="muted small">
                {LINK_BASIS_LABELS[ap.link_evidence.network_device.basis]} ({ap.link_evidence.network_device.value}) ·{" "}
                {ap.link_evidence.network_device.method === "automatic" ? "automático" : "manual"}
              </div>
            )}
          </Field>
          <Field label="Activo">
            {ap.asset ? (
              <Link to={`/assets/${ap.asset.asset_id}`}>{ap.asset.display_name}</Link>
            ) : (
              <span className="muted">sin vincular</span>
            )}
            {ap.link_evidence.asset && (
              <div className="muted small">
                {LINK_BASIS_LABELS[ap.link_evidence.asset.basis]} ({ap.link_evidence.asset.value}) ·{" "}
                {ap.link_evidence.asset.method === "automatic" ? "automático" : "manual"}
              </div>
            )}
          </Field>
        </dl>
        {ap.link_suppressed && (
          <p className="muted small">
            Un operador lo desvinculó: la vinculación automática no lo volverá a enlazar.
          </p>
        )}
      </section>

      <section className="wlan-section" aria-label="Radios">
        <h3>Radios</h3>
        {ap.radios.length === 0 ? (
          <p className="muted small">La fuente no informa de radios.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Slot</th>
                  <th>Banda</th>
                  <th>Canal</th>
                  <th>SSID</th>
                  <th>Estándar</th>
                  <th>Estado informado</th>
                  <th>Clientes</th>
                </tr>
              </thead>
              <tbody>
                {ap.radios.map((radio) => (
                  <tr key={radio.slot}>
                    <td>{radio.slot}</td>
                    <td>{radio.band ? BAND_LABELS[radio.band] : "—"}</td>
                    <td>{radio.channel ?? "—"}</td>
                    <td>{radio.ssid ?? <span className="muted">—</span>}</td>
                    <td>{radio.standard ?? "—"}</td>
                    <td>{radio.status ?? "—"}</td>
                    <td>{radio.clients ?? "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="wlan-section" aria-label="BSS del AP">
        <h3>BSS ({ap.bss.length})</h3>
        {ap.bss.length === 0 ? (
          <p className="muted small">Sin BSS asociados.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>BSSID</th>
                  <th>SSID</th>
                  <th>Banda / canal</th>
                  <th>Seguridad</th>
                  <th>Evidencia</th>
                </tr>
              </thead>
              <tbody>
                {ap.bss.map((bss) => (
                  <tr key={bss.bss_id}>
                    <td>
                      <MacText mac={bss.bssid} randomized={bss.bssid_randomized} />
                    </td>
                    <td>{bss.ssid ?? <span className="muted">oculto</span>}</td>
                    <td>
                      {bss.band ? BAND_LABELS[bss.band] : "—"}
                      {bss.channel != null && <span className="muted"> · canal {bss.channel}</span>}
                    </td>
                    <td>
                      <ProtectionLabel protection={bss.protection} reported={bss.protection_reported} />
                      <FindingBadges findings={bss.findings} />
                    </td>
                    <td>
                      <EvidenceBadges freshness={bss.freshness} present={bss.present} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <ObservationHistory key={ap.access_point_id} ap={ap} />
    </>
  );
}

type Action = { kind: "authorize"; target: WlanAuthorizationStatus } | { kind: "link" } | { kind: "unlink" };

/**
 * Detalle de un AP en un panel lateral (el listado sigue debajo). Escape o el botón de cierre
 * lo cierran; el foco queda dentro mientras está abierto y vuelve al elemento que lo abrió.
 */
export function AccessPointPanel({
  accessPointId,
  onClose,
  onChanged,
}: {
  accessPointId: string;
  onClose: () => void;
  /** El listado se refresca tras una acción (clasificación o vínculo). */
  onChanged: () => void;
}) {
  const auth = useAuth();
  const canManage = auth.can("network:manage");
  const fetchAp = useCallback((signal: AbortSignal) => wlanApi.accessPoint(accessPointId, signal), [accessPointId]);
  const ap = usePolling(fetchAp, config.refreshIntervalMs * 2);
  const [action, setAction] = useState<Action>();
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panelRef.current?.focus();
    // Como en Modal: el fondo no hace scroll mientras el panel está abierto.
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
      if (opener && opener.isConnected) opener.focus();
    };
  }, []);
  useEffect(() => {
    // Con un diálogo de acción abierto, Escape cierra ese diálogo y no el panel.
    if (action) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, action]);

  const refresh = ap.refresh;
  const changed = useCallback(() => {
    refresh();
    onChanged();
  }, [refresh, onChanged]);

  const detail = ap.data;
  const title = detail ? detail.display_name : "Punto de acceso";

  return (
    <div className="side-panel-layer side-panel-layer--dim" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panelRef}
        className="side-panel"
        role="dialog"
        aria-modal="true"
        aria-label={`Detalle del AP ${title}`}
        tabIndex={-1}
        onKeyDown={action ? undefined : trapTab}
      >
        <div className="modal__header">
          <h2>{title}</h2>
          <button type="button" className="iconbutton" onClick={onClose} aria-label="Cerrar detalle">
            <Icon name="close" />
          </button>
        </div>
        <div className="modal__body stack">
          {!detail ? (
            ap.error ? (
              <ErrorState message={errorMessage(ap.error)} onRetry={ap.refresh} />
            ) : (
              <LoadingState label="Cargando AP…" />
            )
          ) : (
            <>
              {ap.error && (
                <div className="banner banner--warn" role="alert">
                  Fallo al actualizar: {errorMessage(ap.error)}. Se muestran los últimos datos.
                </div>
              )}
              <Details
                ap={detail}
                canManage={canManage}
                onAuthorize={(target) => setAction({ kind: "authorize", target })}
                onLink={() => setAction({ kind: "link" })}
                onUnlink={() => setAction({ kind: "unlink" })}
              />
            </>
          )}
        </div>
      </div>
      {detail && action?.kind === "authorize" && (
        <AuthorizationModal
          subject={detail.display_name}
          current={detail.authorization_status}
          target={action.target}
          version={detail.version}
          onSubmit={(input) => wlanApi.setAccessPointAuthorization(detail.access_point_id, input)}
          onDone={changed}
          onConflict={refresh}
          onClose={() => setAction(undefined)}
        />
      )}
      {detail && action?.kind === "link" && (
        <LinkModal ap={detail} onDone={changed} onClose={() => setAction(undefined)} />
      )}
      {detail && action?.kind === "unlink" && (
        <UnlinkModal ap={detail} onDone={changed} onClose={() => setAction(undefined)} />
      )}
    </div>
  );
}
