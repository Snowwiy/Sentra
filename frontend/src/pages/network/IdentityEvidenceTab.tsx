import { useCallback, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { sentraApi } from "../../api/sentra";
import { topologyHistoryApi } from "../../api/sentra6e";
import type { NetworkChangeList, NetworkChangeType } from "../../api/types";
import { IdentificationPanel } from "../../components/DeviceIdentity";
import { DhcpPanels } from "../../components/dhcp/DhcpPanels";
import { IdentityTab } from "../../components/dhcp/IdentityTab";
import { FilterSelect } from "../../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../../components/StateViews";
import { devicesLink } from "../../lib/deviceFilters";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { CHANGE_TYPE_LABELS, plainValue } from "../../lib/topologyHistory";
import { useAssetOptions } from "../../lib/useAssetOptions";
import { usePolling } from "../../lib/usePolling";
import { useNetworkHub } from "./hubContext";

const REFRESH_MS = 120_000;
const CHANGES_LIMIT = 20;

/** Cambios que afectan a la identidad de un equipo (no a enlaces ni conectividad). */
export const IDENTITY_CHANGE_TYPES: readonly NetworkChangeType[] = [
  "name_changed",
  "ip_changed",
  "mac_changed",
  "vendor_changed",
  "classification_changed",
];

/**
 * Red › Identidad y evidencias (Fase 7A.5): reúne lo que antes estaba repartido entre la página
 * DHCP y la ficha de cada activo. Arriba, la identificación de un equipo elegido (tipo con su
 * confianza o asignación manual, evidencias, huellas, nombres observados, concesiones e
 * historial); debajo, los últimos cambios de identidad de la red y las fuentes DHCP con sus
 * concesiones, con todas las acciones de la antigua página /dhcp.
 */
export function IdentityEvidenceTab() {
  const hub = useNetworkHub();
  const [params, setParams] = useSearchParams();
  const assetId = params.get("asset") ?? "";
  // El equipo elegido vive en la URL (?asset=) para poder enlazarlo y para que recargar la
  // página no lo pierda.
  const selectAsset = (id: string) => {
    const next = new URLSearchParams(params);
    if (id) next.set("asset", id);
    else next.delete("asset");
    setParams(next, { replace: true });
  };

  return (
    <div className="stack">
      <section className="panel" aria-label="Identificación de un equipo">
        <div className="panel__toolbar">
          <div>
            <h2>Identificación de un equipo</h2>
            <p className="muted small">
              Tipo, evidencias y nombres de un equipo concreto. Los equipos sin tipo están en{" "}
              <Link to={devicesLink({ type: "unknown" })}>Dispositivos sin identificar</Link>.
            </p>
          </div>
        </div>
        <AssetPicker value={assetId} onChange={selectAsset} />
        {assetId && <SelectedAsset key={assetId} assetId={assetId} />}
      </section>

      <IdentityChanges siteId={hub.scopeId} />

      <DhcpPanels />
    </div>
  );
}

function AssetPicker({ value, onChange }: { value: string; onChange: (assetId: string) => void }) {
  const [query, setQuery] = useState("");
  const options = useAssetOptions(query, value);
  return (
    <div className="panel__toolbar panel__toolbar--filters">
      <input
        className="input"
        type="search"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        placeholder="Buscar por nombre o IP"
        aria-label="Buscar equipo"
      />
      <select className="input input--select" aria-label="Equipo" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="">Elige un equipo</option>
        {options.map((asset) => (
          <option key={asset.asset_id} value={asset.asset_id}>
            {asset.display_name}
            {asset.primary_ip ? ` · ${asset.primary_ip}` : ""}
          </option>
        ))}
      </select>
    </div>
  );
}

/** Identificación (con asignación manual de tipo) e identidad DHCP del equipo elegido. */
function SelectedAsset({ assetId }: { assetId: string }) {
  const fetchAsset = useCallback((signal: AbortSignal) => sentraApi.getAsset(assetId, signal), [assetId]);
  const asset = usePolling(fetchAsset, REFRESH_MS);
  if (asset.loading) return <LoadingState label="Cargando equipo…" />;
  if (!asset.data) return <ErrorState message={errorMessage(asset.error ?? new Error("Sin datos"))} onRetry={asset.refresh} />;
  return (
    <div className="stack panel--padded">
      <p className="small">
        <Link to={`/assets/${encodeURIComponent(assetId)}`}>Abrir la ficha de {asset.data.display_name}</Link>
      </p>
      <IdentificationPanel asset={asset.data} onChanged={asset.refresh} />
      <IdentityTab assetId={assetId} />
    </div>
  );
}

/**
 * Últimos cambios de identidad. El API filtra por un solo tipo de cambio, así que "todos"
 * pide cada tipo de identidad por separado y los mezcla por fecha: pedir sin filtro traería
 * sobre todo cambios de enlaces, que aquí no interesan.
 */
function IdentityChanges({ siteId }: { siteId: string | undefined }) {
  const [changeType, setChangeType] = useState<NetworkChangeType | "">("");
  const fetcher = useCallback(
    async (signal: AbortSignal): Promise<NetworkChangeList> => {
      const types = changeType ? [changeType] : IDENTITY_CHANGE_TYPES;
      const lists = await Promise.all(
        types.map((type) => topologyHistoryApi.changes({ siteId, changeType: type, limit: CHANGES_LIMIT }, signal)),
      );
      const items = lists
        .flatMap((list) => list.items)
        .sort((a, b) => b.detected_at.localeCompare(a.detected_at))
        .slice(0, CHANGES_LIMIT);
      return { items, total: lists.reduce((sum, list) => sum + list.total, 0) };
    },
    [siteId, changeType],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS);

  return (
    <section className="panel" aria-label="Cambios de identidad">
      <div className="panel__toolbar">
        <h2>Cambios de identidad</h2>
        <FilterSelect
          label="Tipo de cambio"
          value={changeType}
          options={IDENTITY_CHANGE_TYPES.map((type) => ({ value: type, label: CHANGE_TYPE_LABELS[type] }))}
          onChange={(value) => setChangeType(value as NetworkChangeType | "")}
        />
        <Link to="/network/changes" className="small">
          Historial completo
        </Link>
      </div>
      {loading ? (
        <LoadingState label="Cargando cambios de identidad…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin cambios de identidad">
          No se ha detectado ningún cambio de nombre, IP, MAC, fabricante o clasificación.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Detectado</th>
                <th>Cambio</th>
                <th>Equipo</th>
                <th>Antes</th>
                <th>Después</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((c) => (
                <tr key={c.id}>
                  <td title={formatDateTime(c.detected_at)}>{formatRelative(c.detected_at)}</td>
                  <td>{CHANGE_TYPE_LABELS[c.change_type] ?? c.change_type}</td>
                  <td>
                    {c.asset_id ? (
                      <Link to={`/assets/${encodeURIComponent(c.asset_id)}`}>{c.subject_label ?? c.subject_key}</Link>
                    ) : (
                      (c.subject_label ?? c.subject_key)
                    )}
                  </td>
                  <td className="mono small">{plainValue(c.before)}</td>
                  <td className="mono small">{plainValue(c.after)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
