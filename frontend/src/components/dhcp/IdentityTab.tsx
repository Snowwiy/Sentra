import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { dhcpApi } from "../../api/sentra6e";
import type { AssetIdentity, AssetIdentityHistoryEntry, IdentityField } from "../../api/types";
import {
  IDENTITY_FIELD_LABELS,
  LEASE_MATCH_LABELS,
  LEASE_STATE_LABELS,
  UNIDENTIFIED_REASON_LABELS,
} from "../../lib/dhcp";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { deviceTypeLabel, EVIDENCE_LABELS, NAME_SOURCE_LABELS, observedNameNote } from "../../lib/identity";
import { usePolling } from "../../lib/usePolling";
import { FilterSelect } from "../ListControls";
import { ErrorState, LoadingState } from "../StateViews";

const REFRESH_MS = 120_000;
const HISTORY_PAGE = 50;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Pestaña Identidad del activo (Fase 6E.2): nombre elegido y su fuente, todos los nombres
 * observados, concesiones DHCP asociadas, Wi-Fi e historial de cambios. La etiqueta
 * personalizada gana siempre. Si el equipo sigue sin identificar no se inventa ningún nombre:
 * se muestran los motivos que devuelve el servidor.
 */
export function IdentityTab({ assetId }: { assetId: string }) {
  const fetchIdentity = useCallback((signal: AbortSignal) => dhcpApi.identity(assetId, signal), [assetId]);
  const { data, error, loading, refresh } = usePolling(fetchIdentity, REFRESH_MS);
  if (loading) return <LoadingState label="Cargando identidad…" />;
  if (!data) return <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />;
  return (
    <div className="stack">
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      <IdentitySummary identity={data} />
      <LeasesPanel identity={data} />
      <IdentityHistory assetId={assetId} />
    </div>
  );
}

function IdentitySummary({ identity }: { identity: AssetIdentity }) {
  const unidentified = !identity.custom_label && !identity.automatic_name;
  const sourceLabel = identity.name_source
    ? (NAME_SOURCE_LABELS[identity.name_source] ?? EVIDENCE_LABELS[identity.name_source] ?? identity.name_source)
    : null;
  return (
    <section className="panel panel--padded stack" aria-label="Identidad">
      <h2 className="panel__title">
        {unidentified ? "Equipo sin identificar" : identity.custom_label || identity.automatic_name}
      </h2>
      <dl className="fields">
        {identity.custom_label && (
          <div className="field">
            <dt>Etiqueta personalizada</dt>
            <dd>
              {identity.custom_label} <span className="muted small">(prevalece sobre cualquier nombre automático)</span>
            </dd>
          </div>
        )}
        <div className="field">
          <dt>{identity.custom_label ? "Nombre automático" : "Nombre"}</dt>
          <dd>
            {identity.automatic_name ?? <span className="muted">Ninguno</span>}
            {identity.automatic_name && sourceLabel && <span className="muted small"> ({sourceLabel})</span>}
          </dd>
        </div>
        <div className="field">
          <dt>IP</dt>
          <dd className="mono">{identity.ip}</dd>
        </div>
        <div className="field">
          <dt>MAC</dt>
          <dd>
            <span className="mono">{identity.mac ?? "—"}</span>
            {identity.mac_randomized && <span className="badge badge--warn">aleatoria</span>}
          </dd>
        </div>
        <div className="field">
          <dt>Tipo</dt>
          <dd>{deviceTypeLabel(identity.device_type)}</dd>
        </div>
        {identity.vendor && (
          <div className="field">
            <dt>Fabricante</dt>
            <dd>
              {identity.vendor} <span className="muted small">(describe el equipo, no lo identifica)</span>
            </dd>
          </div>
        )}
        {identity.wifi && (
          <div className="field">
            <dt>Wi-Fi</dt>
            <dd>
              {identity.wifi.ssid ?? "SSID oculto"}
              {identity.wifi.access_point_name && ` · ${identity.wifi.access_point_name}`}
              {identity.wifi.band && ` · ${identity.wifi.band}`}
              <span className="muted small"> · visto {formatRelative(identity.wifi.last_seen_at)}</span>
            </dd>
          </div>
        )}
      </dl>
      {identity.unidentified_reasons.length > 0 && (
        <div className="banner banner--warn" role="status">
          <strong>Por qué no tiene nombre</strong>
          <ul className="plain-list small" aria-label="Motivos sin identificar">
            {identity.unidentified_reasons.map((r) => (
              <li key={r}>{UNIDENTIFIED_REASON_LABELS[r] ?? r}</li>
            ))}
          </ul>
        </div>
      )}
      {identity.names.length > 0 && (
        <div>
          <h3 className="small strong">Nombres observados</h3>
          <ul className="plain-list small" aria-label="Nombres observados">
            {identity.names.map((name) => (
              <li key={`${name.source}:${name.value}`}>
                <span className={name.kind === "generic" || name.stale ? "muted" : undefined}>{name.value}</span>
                {name.selected && <span className="badge badge--info">elegido</span>}{" "}
                <span className="muted">{observedNameNote(name)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

function LeasesPanel({ identity }: { identity: AssetIdentity }) {
  return (
    <section className="panel" aria-label="Concesiones DHCP">
      <div className="panel__toolbar">
        <h2>Concesiones DHCP</h2>
        <Link to="/dhcp" className="small">
          Fuentes DHCP
        </Link>
      </div>
      {identity.leases.length === 0 ? (
        <p className="muted small panel--padded">Ninguna concesión DHCP asociada a este equipo.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Hostname</th>
                <th>IP</th>
                <th>Estado</th>
                <th>Asociación</th>
                <th className="col-secondary">Fuente</th>
                <th className="col-secondary">Vence</th>
              </tr>
            </thead>
            <tbody>
              {identity.leases.map((l) => (
                <tr key={`${l.source_id}:${l.ip}:${l.mac}`}>
                  <td>
                    {l.hostname ?? <span className="muted">—</span>}
                    {l.hostname && !l.hostname_usable && <span className="badge badge--muted">no utilizable</span>}
                  </td>
                  <td className="mono">{l.ip}</td>
                  <td>{LEASE_STATE_LABELS[l.state] ?? l.state}</td>
                  <td>{LEASE_MATCH_LABELS[l.match] ?? l.match}</td>
                  <td className="col-secondary">{l.source_name}</td>
                  <td className="col-secondary">{l.ends_at ? formatDateTime(l.ends_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

function IdentityHistory({ assetId }: { assetId: string }) {
  const [field, setField] = useState<IdentityField | "">("");
  const [items, setItems] = useState<AssetIdentityHistoryEntry[]>([]);
  const [next, setNext] = useState<number | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>();

  const load = useCallback(
    async (beforeId: number | undefined, signal?: AbortSignal) => {
      setLoading(true);
      setError(undefined);
      try {
        const page = await dhcpApi.identityHistory(
          assetId,
          { beforeId, limit: HISTORY_PAGE, field: field || undefined },
          signal,
        );
        setItems((prev) => (beforeId ? [...prev, ...page.items] : page.items));
        setNext(page.next_before_id);
      } catch (err) {
        if (signal?.aborted) return;
        setError(errorMessage(toError(err)));
      } finally {
        if (!signal?.aborted) setLoading(false);
      }
    },
    [assetId, field],
  );

  useEffect(() => {
    const controller = new AbortController();
    const initial = window.setTimeout(() => void load(undefined, controller.signal), 0);
    return () => {
      window.clearTimeout(initial);
      controller.abort();
    };
  }, [load]);

  return (
    <section className="panel" aria-label="Historial de identidad">
      <div className="panel__toolbar panel__toolbar--filters">
        <h2>Historial de identidad</h2>
        <FilterSelect
          label="Campo"
          value={field}
          options={Object.entries(IDENTITY_FIELD_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={(v) => setField(v as IdentityField | "")}
        />
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {items.length === 0 && !loading && !error ? (
        <p className="muted small panel--padded">Sin cambios de identidad registrados.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Cuándo</th>
                <th>Campo</th>
                <th>Antes</th>
                <th>Después</th>
                <th className="col-secondary">Fuente</th>
              </tr>
            </thead>
            <tbody>
              {items.map((h, index) => (
                <tr key={`${h.observed_at}:${h.field}:${index}`}>
                  <td>{formatDateTime(h.observed_at)}</td>
                  <td>{IDENTITY_FIELD_LABELS[h.field] ?? h.field}</td>
                  <td className="mono small">{h.old_value ?? "—"}</td>
                  <td className="mono small">{h.new_value ?? "—"}</td>
                  <td className="col-secondary small">
                    {NAME_SOURCE_LABELS[h.source] ?? EVIDENCE_LABELS[h.source] ?? h.source}
                    <span className="muted"> · {h.confidence}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="panel__toolbar">
        {loading && <span className="muted small">Cargando…</span>}
        {!loading && next !== null && (
          <button type="button" className="button" onClick={() => void load(next)}>
            Cargar más antiguos
          </button>
        )}
      </div>
    </section>
  );
}
