import type { Asset } from "../../api/types";
import { IDENTITY_STATE_CLASS, IDENTITY_STATE_HELP, IDENTITY_STATE_LABELS } from "../../lib/identity7b";

/**
 * Fase 7B.2: estado de identidad del activo (Confirmada / Probable / Sin resolver) y su MAC.
 * Una MAC privada se marca aparte: es la causa más habitual de duplicados en Wi-Fi y nunca
 * debe leerse como el identificador del equipo.
 */
export function IdentityBadge({
  asset,
  showMac = true,
}: {
  asset: Pick<Asset, "identity_state" | "mac_randomized" | "mac_address">;
  showMac?: boolean;
}) {
  const state = asset.identity_state ?? "probable";
  return (
    <div className="identity-cell">
      <span className={`badge ${IDENTITY_STATE_CLASS[state]}`} title={IDENTITY_STATE_HELP[state]}>
        {IDENTITY_STATE_LABELS[state]}
      </span>
      {asset.mac_randomized && (
        <span className="badge badge--muted" title="MAC administrada localmente (privada o aleatoria)">
          MAC privada
        </span>
      )}
      {showMac && asset.mac_address && <div className="mono small muted identity-cell__mac">{asset.mac_address}</div>}
    </div>
  );
}
