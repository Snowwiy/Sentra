import { useCallback, useState, type FormEvent } from "react";
import { networkApi, wlanApi } from "../../api/sentra";
import type {
  WlanAccessPointDetail,
  WlanAuthorizationStatus,
  WlanAuthorizationUpdate,
  WlanUnlinkTarget,
} from "../../api/types";
import { useAssetOptions } from "../../lib/useAssetOptions";
import { usePolling } from "../../lib/usePolling";
import { AUTHORIZATION_ACTIONS, AUTHORIZATION_HELP, AUTHORIZATION_LABELS, isVersionConflict, wlanErrorText } from "../../lib/wlan";
import { Modal } from "../Modal";

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

// La API rechaza caracteres de control en el motivo (422): se quitan al escribir, así un
// pegado con saltos de línea no hace fallar la acción.
function cleanReason(value: string): string {
  // eslint-disable-next-line no-control-regex
  return value.replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 500);
}

/**
 * Confirmación de un cambio de clasificación (AP o BSS). Siempre manual y auditado en el
 * servidor; nunca se ofrece "rogue" ni se cambia nada en la red. Envía la versión leída para
 * que un cambio concurrente devuelva 409 en lugar de pisarlo.
 */
export function AuthorizationModal({
  subject,
  current,
  target,
  version,
  onSubmit,
  onDone,
  onConflict,
  onClose,
}: {
  /** Nombre visible del AP o BSS. */
  subject: string;
  current: WlanAuthorizationStatus;
  target: WlanAuthorizationStatus;
  version: number;
  onSubmit: (input: WlanAuthorizationUpdate) => Promise<unknown>;
  onDone: () => void;
  /** Tras un 409 se recargan los datos para que el operador decida con la versión actual. */
  onConflict: () => void;
  onClose: () => void;
}) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const title = `${AUTHORIZATION_ACTIONS[target]}: ${subject}`;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    const trimmed = reason.trim();
    try {
      await onSubmit({ status: target, version, ...(trimmed ? { reason: trimmed } : {}) });
      onDone();
      onClose();
    } catch (err) {
      setError(wlanErrorText(asError(err)));
      if (isVersionConflict(err)) onConflict();
      setBusy(false);
    }
  };

  return (
    <Modal title={title} onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <p>
          Pasará de <span className="strong">{AUTHORIZATION_LABELS[current]}</span> a{" "}
          <span className="strong">{AUTHORIZATION_LABELS[target]}</span>. {AUTHORIZATION_HELP[target]}
        </p>
        <p className="muted small">
          Es solo una clasificación para el inventario: Sentra no bloquea, desautentica ni cambia nada en la red. El cambio
          queda auditado con tu usuario.
        </p>
        <label className="form-field">
          <span>Motivo (opcional)</span>
          <input
            className="input"
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(cleanReason(e.target.value))}
            placeholder="Por ejemplo: AP de la planta 2 instalado por sistemas"
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
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Guardando…" : AUTHORIZATION_ACTIONS[target]}
          </button>
        </div>
      </form>
    </Modal>
  );
}

type LinkKind = "network_device" | "asset";

/**
 * Vincula un AP con un equipo de red o un activo del mismo site. El servidor solo lo acepta
 * con evidencia (IP de gestión o MAC Ethernet coincidentes) y lo audita; aquí solo se elige
 * el destino y se pide confirmación explícita.
 */
export function LinkModal({
  ap,
  onDone,
  onClose,
}: {
  ap: WlanAccessPointDetail;
  onDone: (detail: WlanAccessPointDetail) => void;
  onClose: () => void;
}) {
  const [kind, setKind] = useState<LinkKind>("network_device");
  const [deviceId, setDeviceId] = useState("");
  const [assetQuery, setAssetQuery] = useState(ap.management_ip ?? "");
  const [assetId, setAssetId] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const fetchDevices = useCallback(
    (signal: AbortSignal) => networkApi.devices({ siteId: ap.site_id, limit: 200 }, signal),
    [ap.site_id],
  );
  // Solo una carga: el intervalo largo evita refrescos mientras el diálogo está abierto.
  const devices = usePolling(fetchDevices, 10 * 60_000);
  const assets = useAssetOptions(kind === "asset" ? assetQuery : "", assetId);
  const target = kind === "network_device" ? deviceId : assetId;

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!target || !confirmed) return;
    setBusy(true);
    setError(undefined);
    try {
      const detail = await wlanApi.linkAccessPoint(
        ap.access_point_id,
        kind === "network_device" ? { network_device_id: target } : { asset_id: target },
      );
      onDone(detail);
      onClose();
    } catch (err) {
      setError(wlanErrorText(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title={`Vincular ${ap.display_name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <p className="small">
          El servidor solo acepta el vínculo si hay evidencia: la IP de gestión ({ap.management_ip ?? "no informada"}) o la
          MAC Ethernet ({ap.ethernet_mac ?? "no informada"}) del AP deben coincidir con el destino, del site{" "}
          {ap.site_name}.
        </p>
        <label className="form-field">
          <span>Vincular con</span>
          <select
            className="input input--select"
            value={kind}
            onChange={(e) => {
              setKind(e.target.value as LinkKind);
              setConfirmed(false);
            }}
          >
            <option value="network_device">Equipo de red (Infraestructura)</option>
            <option value="asset">Activo del inventario</option>
          </select>
        </label>
        {kind === "network_device" ? (
          <label className="form-field">
            <span>Equipo de red</span>
            <select className="input input--select" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
              <option value="">{devices.data ? "Elige un equipo" : "Cargando equipos…"}</option>
              {devices.data?.items.map((device) => (
                <option key={device.device_id} value={device.device_id}>
                  {device.display_name} ({device.management_address})
                </option>
              ))}
            </select>
          </label>
        ) : (
          <>
            <label className="form-field">
              <span>Buscar activo</span>
              <input
                className="input"
                type="search"
                value={assetQuery}
                maxLength={100}
                onChange={(e) => setAssetQuery(e.target.value)}
              />
            </label>
            <label className="form-field">
              <span>Activo</span>
              <select className="input input--select" value={assetId} onChange={(e) => setAssetId(e.target.value)}>
                <option value="">Elige un activo</option>
                {assets.map((asset) => (
                  <option key={asset.asset_id} value={asset.asset_id}>
                    {asset.display_name}
                    {asset.primary_ip ? ` (${asset.primary_ip})` : ""}
                  </option>
                ))}
              </select>
            </label>
          </>
        )}
        <label className="checkbox small">
          <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo que este
          AP corresponde al destino elegido
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
          <button type="submit" className="button button--primary" disabled={busy || !target || !confirmed}>
            {busy ? "Vinculando…" : "Vincular"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

const UNLINK_LABELS: Record<WlanUnlinkTarget, string> = {
  all: "Todos los vínculos",
  asset: "Solo el activo",
  network_device: "Solo el equipo de red",
};

/**
 * Desvincula un AP. El servidor recuerda la decisión (`link_suppressed`) para que la
 * vinculación automática no lo vuelva a enlazar sin intervención de un operador.
 */
export function UnlinkModal({
  ap,
  onDone,
  onClose,
}: {
  ap: WlanAccessPointDetail;
  onDone: (detail: WlanAccessPointDetail) => void;
  onClose: () => void;
}) {
  const options: WlanUnlinkTarget[] = [
    ...(ap.asset && ap.network_device ? (["all"] as const) : []),
    ...(ap.asset ? (["asset"] as const) : []),
    ...(ap.network_device ? (["network_device"] as const) : []),
  ];
  const [target, setTarget] = useState<WlanUnlinkTarget>(options[0] ?? "all");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    const trimmed = reason.trim();
    try {
      const detail = await wlanApi.unlinkAccessPoint(ap.access_point_id, {
        target,
        ...(trimmed ? { reason: trimmed } : {}),
      });
      onDone(detail);
      onClose();
    } catch (err) {
      setError(wlanErrorText(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title={`Desvincular ${ap.display_name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(event) => void submit(event)}>
        <p className="small">
          El AP deja de estar asociado y no se volverá a vincular automáticamente; un administrador puede vincularlo de
          nuevo a mano. No cambia nada en el equipo ni en la red.
        </p>
        {options.length > 1 && (
          <label className="form-field">
            <span>Qué desvincular</span>
            <select
              className="input input--select"
              value={target}
              onChange={(e) => setTarget(e.target.value as WlanUnlinkTarget)}
            >
              {options.map((option) => (
                <option key={option} value={option}>
                  {UNLINK_LABELS[option]}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="form-field">
          <span>Motivo (opcional)</span>
          <input
            className="input"
            value={reason}
            maxLength={500}
            onChange={(e) => setReason(cleanReason(e.target.value))}
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
          <button type="submit" className="button button--danger" disabled={busy}>
            {busy ? "Desvinculando…" : "Desvincular"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
