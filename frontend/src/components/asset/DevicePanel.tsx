import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { identityApi } from "../../api/sentra7b";
import type {
  Asset,
  AssetIdentityProfile,
  IdentityCandidate,
  IdentityLinkPreview,
  IdentityLinkRead,
  IdentityTier,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { assetTitle } from "../../lib/identity";
import {
  blockerText,
  effectText,
  evidenceText,
  FRESHNESS_LABELS,
  IDENTITY_STATE_CLASS,
  IDENTITY_STATE_HELP,
  IDENTITY_STATE_LABELS,
  macNote,
  reasonLabel,
  sourceLabel,
  STRENGTH_CLASS,
  STRENGTH_LABELS,
  GAP_FIELD_LABELS,
  TIER_STATE_LABELS,
} from "../../lib/identity7b";
import { usePolling } from "../../lib/usePolling";
import { Icon } from "../icons";
import { trapTab } from "../layout/navKeys";
import { Modal } from "../Modal";
import { RiskCell } from "../risk/RiskBadges";
import { ErrorState, LoadingState } from "../StateViews";
import { AssetStateBadge } from "../StatusBadge";

type TierKey = keyof Pick<
  AssetIdentityProfile,
  "assigned_name" | "name" | "vendor" | "model" | "device_type" | "os"
>;
// Fase 7B-Fix1: el nombre asignado por un admin va primero (manda sobre lo deducido); el
// fabricante de la NIC se muestra aparte en la MAC, no como marca del equipo.
const TIERS: [TierKey, string][] = [
  ["assigned_name", "Nombre asignado"],
  ["name", "Nombre detectado"],
  ["vendor", "Fabricante del equipo"],
  ["model", "Modelo"],
  ["device_type", "Tipo"],
  ["os", "Sistema operativo"],
];
const REASON_MIN = 3;
const REASON_MAX = 500;

function TierRow({ label, tier }: { label: string; tier: IdentityTier }) {
  return (
    <tr>
      <th scope="row">{label}</th>
      <td>{tier.value ?? <span className="muted">—</span>}</td>
      <td className="small">{sourceLabel(tier.source)}</td>
      <td className="small">
        {TIER_STATE_LABELS[tier.state] ?? tier.state}
        {tier.reasons.length > 0 && <div className="muted">{tier.reasons.map(reasonLabel).join(", ")}</div>}
        {tier.alternatives.length > 0 && (
          <div className="muted">
            También: {tier.alternatives.map((a) => `${a.value ?? "—"} (${sourceLabel(a.source)})`).join("; ")}
          </div>
        )}
      </td>
    </tr>
  );
}

/** Vista previa del servidor y confirmación con motivo: nada se asocia sin ambas. */
function LinkDialog({
  current,
  candidate,
  onClose,
  onDone,
}: {
  current: AssetIdentityProfile;
  candidate: IdentityCandidate;
  onClose: () => void;
  onDone: () => void;
}) {
  // El registro gestionado (con agente) es el destino; si ninguno lo es, el candidato.
  const target = current.managed ? current.asset_id : candidate.asset.asset_id;
  const alias = current.managed ? candidate.asset.asset_id : current.asset_id;
  const [preview, setPreview] = useState<IdentityLinkPreview>();
  const [error, setError] = useState<string>();
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const request = useMemo(
    () => ({ kind: "asset_alias" as const, target_asset_id: target, alias_asset_id: alias }),
    [target, alias],
  );

  useEffect(() => {
    let active = true;
    identityApi
      .preview(request)
      .then((result) => active && setPreview(result))
      .catch((err: unknown) => active && setError(errorMessage(err instanceof Error ? err : new Error(String(err)))));
    return () => {
      active = false;
    };
  }, [request]);

  const trimmed = reason.trim();
  const valid = trimmed.length >= REASON_MIN && trimmed.length <= REASON_MAX;
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await identityApi.create({ ...request, reason: trimmed });
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };

  return (
    <Modal title="Asociar registros del mismo dispositivo" onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        {!preview && !error && <LoadingState label="Calculando vista previa…" />}
        {preview && (
          <>
            <p>
              <strong>{preview.alias?.display_name ?? "—"}</strong> pasa a ser un alias de{" "}
              <strong>{preview.target.display_name}</strong>.
            </p>
            {preview.blockers.length > 0 && (
              <div className="banner banner--warn" role="alert">
                No se puede asociar:
                <ul>
                  {preview.blockers.map((code) => (
                    <li key={code}>{blockerText(code)}</li>
                  ))}
                </ul>
              </div>
            )}
            {preview.evidence.length > 0 && (
              <div>
                <h3 className="small">Evidencias</h3>
                <ul className="small">
                  {preview.evidence.map((e) => (
                    <li key={`${e.code}-${e.detail ?? ""}`}>{evidenceText(e)}</li>
                  ))}
                </ul>
              </div>
            )}
            {preview.allowed && (
              <>
                <div>
                  <h3 className="small">Qué cambia</h3>
                  <ul className="small">
                    {preview.effects.map((code) => (
                      <li key={code}>{effectText(code)}</li>
                    ))}
                  </ul>
                </div>
                <label className="field">
                  <span>Motivo (queda en la auditoría)</span>
                  <textarea
                    className="input"
                    rows={3}
                    maxLength={REASON_MAX}
                    value={reason}
                    onChange={(event) => setReason(event.target.value)}
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
            onClick={() => void submit()}
            disabled={busy || !preview?.allowed || !valid}
          >
            {busy ? "Asociando…" : "Confirmar asociación"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function RevokeDialog({ link, onClose, onDone }: { link: IdentityLinkRead; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const trimmed = reason.trim();
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await identityApi.revoke(link.link_id, trimmed);
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(err instanceof Error ? err : new Error(String(err))));
      setBusy(false);
    }
  };
  return (
    <Modal title="Revocar asociación" onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p>
          Se deshace la asociación de <strong>{link.alias_name ?? link.mac ?? "—"}</strong> con{" "}
          <strong>{link.target_name}</strong>. Si el alias se archivó al asociarlo, se restaura.
        </p>
        <label className="field">
          <span>Motivo</span>
          <textarea
            className="input"
            rows={2}
            maxLength={REASON_MAX}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
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
          <button
            type="button"
            className="button button--danger"
            disabled={busy || trimmed.length < REASON_MIN}
            onClick={() => void submit()}
          >
            {busy ? "Revocando…" : "Revocar"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

function Candidates({
  profile,
  candidates,
  canManage,
  onLink,
}: {
  profile: AssetIdentityProfile;
  candidates: IdentityCandidate[];
  canManage: boolean;
  onLink: (candidate: IdentityCandidate) => void;
}) {
  if (candidates.length === 0) {
    return <p className="muted small">No hay otros registros con evidencias de ser el mismo dispositivo.</p>;
  }
  return (
    <ul className="candidate-list">
      {candidates.map((c) => (
        <li key={c.asset.asset_id} className="candidate">
          <div className="candidate__head">
            <Link to={`/assets/${c.asset.asset_id}`} className="strong">
              {c.asset.display_name}
            </Link>
            <span className={`badge ${STRENGTH_CLASS[c.strength]}`}>Coincidencia {STRENGTH_LABELS[c.strength].toLowerCase()}</span>
            {c.asset.managed && <span className="badge badge--ok">Con agente</span>}
            {c.asset.archived && <span className="badge badge--muted">Archivado</span>}
          </div>
          <div className="small muted">
            <span className="mono">{c.asset.primary_ip}</span>
            {c.asset.mac_address && (
              <>
                {" · "}
                <span className="mono">{c.asset.mac_address}</span>
              </>
            )}
            {c.asset.last_seen_at && ` · visto ${formatRelative(c.asset.last_seen_at)}`}
          </div>
          <ul className="small">
            {c.evidence.map((e) => (
              <li key={`${e.code}-${e.detail ?? ""}`}>{evidenceText(e)}</li>
            ))}
          </ul>
          {/* Solo una coincidencia fuerte o media ofrece asociar; el servidor lo vuelve a comprobar. */}
          {canManage && c.strength !== "weak" && !(profile.managed && c.asset.managed) && (
            <button type="button" className="button button--small" onClick={() => onLink(c)}>
              Asociar como el mismo dispositivo…
            </button>
          )}
        </li>
      ))}
    </ul>
  );
}

/**
 * Fase 7B.3: panel lateral de un dispositivo. Resume la fila y añade la identidad por niveles
 * (con procedencia y antigüedad), los cambios de IP/MAC, las asociaciones manuales y los
 * candidatos a ser el mismo equipo. Nada se fusiona automáticamente: asociar exige
 * identity:manage, vista previa del servidor y un motivo que queda auditado.
 */
export function DevicePanel({ asset, onClose, onChanged }: { asset: Asset; onClose: () => void; onChanged: () => void }) {
  const canManage = useAuth().can("identity:manage");
  const fetchProfile = useCallback(
    async (signal: AbortSignal) => {
      const [profile, candidates] = await Promise.all([
        identityApi.profile(asset.asset_id, signal),
        identityApi.candidates(asset.asset_id, signal),
      ]);
      return { profile, candidates: candidates.items };
    },
    [asset.asset_id],
  );
  const state = usePolling(fetchProfile, config.refreshIntervalMs * 2);
  const [linking, setLinking] = useState<IdentityCandidate>();
  const [revoking, setRevoking] = useState<IdentityLinkRead>();
  const dialogOpen = Boolean(linking || revoking);
  const panelRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    panelRef.current?.focus();
    return () => {
      // El foco vuelve a la fila que abrió el panel (navegación por teclado).
      if (opener && opener.isConnected) opener.focus();
    };
  }, []);
  useEffect(() => {
    // Con un diálogo abierto, Escape cierra el diálogo y no el panel.
    if (dialogOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose, dialogOpen]);

  const refresh = state.refresh;
  const changed = () => {
    refresh();
    onChanged();
  };
  const title = assetTitle(asset);
  const profile = state.data?.profile;
  const note = profile ? macNote(profile.mac) : null;

  return (
    <div className="side-panel-layer side-panel-layer--dim" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div
        ref={panelRef}
        className="side-panel"
        role="dialog"
        aria-modal="true"
        aria-label={`Detalle de ${title}`}
        tabIndex={-1}
        onKeyDown={dialogOpen ? undefined : trapTab}
      >
        <div className="modal__header">
          <h2>{title}</h2>
          <button type="button" className="iconbutton" onClick={onClose} aria-label="Cerrar detalle">
            <Icon name="close" />
          </button>
        </div>
        <div className="modal__body stack">
          <dl className="fields fields--inline">
            <div className="field">
              <dt>Estado</dt>
              <dd>
                <AssetStateBadge asset={asset} />
              </dd>
            </div>
            <div className="field">
              <dt>IP</dt>
              <dd className="mono">{asset.primary_ip}</dd>
            </div>
            <div className="field">
              <dt>MAC</dt>
              <dd className="mono">{asset.mac_address ?? "—"}</dd>
            </div>
            <div className="field">
              <dt>Riesgo</dt>
              <dd>
                <RiskCell score={asset.risk_score} level={asset.risk_level} confidence={asset.risk_confidence} />
              </dd>
            </div>
            <div className="field">
              <dt>Última actividad</dt>
              <dd title={formatDateTime(asset.last_activity_at)}>{formatRelative(asset.last_activity_at)}</dd>
            </div>
          </dl>
          <div className="actions" role="group" aria-label="Acciones del dispositivo">
            <Link className="button button--small button--primary" to={`/assets/${asset.asset_id}`}>
              Abrir ficha
            </Link>
            <Link className="button button--small" to={`/console?asset=${encodeURIComponent(asset.asset_id)}`}>
              Investigar en la consola
            </Link>
          </div>

          {!state.data ? (
            state.error ? (
              <ErrorState message={errorMessage(state.error)} onRetry={state.refresh} />
            ) : (
              <LoadingState label="Cargando identidad…" />
            )
          ) : (
            profile && (
              <>
                <section aria-label="Identidad" className="wlan-section">
                  <h3>
                    Identidad{" "}
                    <span className={`badge ${IDENTITY_STATE_CLASS[profile.state]}`} title={IDENTITY_STATE_HELP[profile.state]}>
                      {IDENTITY_STATE_LABELS[profile.state]}
                    </span>
                  </h3>
                  <p className="muted small">
                    {profile.reasons.map(reasonLabel).join(", ")}
                    {note && ` · ${note}`}
                  </p>
                  <div className="table-wrap">
                    <table className="table table--nostack table--compact">
                      <thead>
                        <tr>
                          <th>Nivel</th>
                          <th>Valor</th>
                          <th>Fuente</th>
                          <th>Estado</th>
                        </tr>
                      </thead>
                      <tbody>
                        {TIERS.filter(([key]) => profile[key]).map(([key, label]) => (
                          <TierRow key={key} label={label} tier={profile[key]} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {profile.mac.nic_vendor && (
                    <p className="small">
                      Fabricante de la tarjeta de red (OUI): {profile.mac.nic_vendor}. No es necesariamente la marca del
                      equipo.
                    </p>
                  )}
                  {(profile.missing ?? []).length > 0 && (
                    <div className="stack">
                      <h4>Qué falta para identificarlo</h4>
                      <ul className="plain-list small" aria-label="Información que falta">
                        {(profile.missing ?? []).map((gap) => (
                          <li key={`${gap.field}-${gap.code}`}>
                            <strong>{GAP_FIELD_LABELS[gap.field] ?? gap.field}:</strong> {gap.detail}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                  {profile.sources.length > 0 && (
                    <p className="small muted">
                      Fuentes:{" "}
                      {profile.sources
                        .map(
                          (s) =>
                            `${sourceLabel(s.source)} (${FRESHNESS_LABELS[s.freshness] ?? s.freshness}${
                              s.seen_at ? `, ${formatRelative(s.seen_at)}` : ""
                            })`,
                        )
                        .join(" · ")}
                    </p>
                  )}
                </section>

                {profile.addresses.length > 0 && (
                  <section aria-label="Cambios de dirección" className="wlan-section">
                    <h3>Cambios de IP y MAC</h3>
                    <ul className="small">
                      {profile.addresses.slice(0, 8).map((a) => (
                        <li key={`${a.field}-${a.observed_at}-${a.new_value ?? ""}`}>
                          {a.field.toUpperCase()}: <span className="mono">{a.old_value ?? "—"}</span> →{" "}
                          <span className="mono">{a.new_value ?? "—"}</span>{" "}
                          <span className="muted" title={formatDateTime(a.observed_at)}>
                            ({sourceLabel(a.source)}, {formatRelative(a.observed_at)})
                          </span>
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                {profile.links.length > 0 && (
                  <section aria-label="Asociaciones manuales" className="wlan-section">
                    <h3>Asociaciones manuales</h3>
                    <ul className="small">
                      {profile.links.map((l) => (
                        <li key={l.link_id}>
                          {l.alias_name ?? l.mac ?? "Cliente Wi-Fi"} → {l.target_name}{" "}
                          <span className="muted">
                            ({l.active ? "activa" : "revocada"}, {l.created_by}, {formatRelative(l.created_at)}): {l.reason}
                          </span>{" "}
                          {canManage && l.active && (
                            <button type="button" className="button button--small" onClick={() => setRevoking(l)}>
                              Revocar
                            </button>
                          )}
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                <section aria-label="Posibles coincidencias" className="wlan-section">
                  <h3>Posibles coincidencias</h3>
                  <Candidates
                    profile={profile}
                    candidates={state.data.candidates}
                    canManage={canManage}
                    onLink={setLinking}
                  />
                </section>
              </>
            )
          )}
        </div>
      </div>
      {profile && linking && (
        <LinkDialog current={profile} candidate={linking} onClose={() => setLinking(undefined)} onDone={changed} />
      )}
      {revoking && <RevokeDialog link={revoking} onClose={() => setRevoking(undefined)} onDone={changed} />}
    </div>
  );
}
