import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { lifecycleApi } from "../../api/sentra";
import type { Asset, AssetDeleteCheck, DuplicateCandidate, DuplicateConfidence, DuplicatePair } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import {
  CONFIDENCE_CLASSES,
  CONFIDENCE_LABELS,
  CONFLICT_LABELS,
  DELETE_CONFIRMATION,
  DELETE_REFUSED,
  IRREVERSIBLE_WARNING,
  NOT_YET_DELETABLE,
  REENROLL_HINT,
  SOURCE_LABELS,
  blockedByHistory,
  blockerLabel,
  lifecycleError,
  reasonLabel,
  reasonsText,
  warningLabel,
} from "../../lib/lifecycle";
import { usePolling } from "../../lib/usePolling";
import { CredentialBadge } from "../agents/AgentBadges";
import { ConfirmDialog, Modal } from "../Modal";
import { MethodBadge } from "../NetworkBadges";
import { ErrorState, LoadingState } from "../StateViews";
import { LifecycleBadge } from "../StatusBadge";
import { EvidenceList, ReconcileWizard } from "./ReconcileWizard";

// Los textos viven en lib/lifecycle; se reexportan para quien ya los importaba de aquí.
export { DELETE_CONFIRMATION, DELETE_REFUSED, REENROLL_HINT, lifecycleError };

// El diálogo carga la comprobación al abrirse; el servidor la repite al confirmar, así que
// no hace falta refrescarla a menudo mientras está abierto.
const CHECK_REFRESH_MS = 10 * 60_000;

const REMOVES_LABELS: Record<string, string> = {
  ports: "puertos",
  changes: "cambios",
  detections: "detecciones de bajo impacto",
  alerts: "alertas resueltas",
  risk_snapshots: "instantáneas de riesgo",
};

/** Banner de activo archivado, con restaurar para admin. */
function ArchivedBanner({ asset, canManage, onChanged }: { asset: Asset; canManage: boolean; onChanged: () => void }) {
  const [restoring, setRestoring] = useState(false);
  return (
    <div className="banner banner--warn" role="status">
      <strong>Archivado</strong> {formatRelative(asset.archived_at)}
      {asset.archived_by && ` por ${asset.archived_by}`}
      {asset.archive_reason && ` · Motivo: ${asset.archive_reason}`}. Se conserva todo su historial; no cuenta en el
      resumen ni en el riesgo actual.
      {canManage && (
        <>
          {" "}
          <button type="button" className="button button--small" onClick={() => setRestoring(true)}>
            Restaurar
          </button>
        </>
      )}
      {restoring && (
        <ConfirmDialog
          title="Restaurar activo"
          confirmLabel="Restaurar"
          onClose={() => setRestoring(false)}
          onConfirm={async () => {
            try {
              await lifecycleApi.restore(asset.asset_id, asset.lifecycle_version);
            } catch (error) {
              throw lifecycleError(error);
            }
            onChanged();
          }}
        >
          <p>El activo vuelve a mostrarse y a contar en el resumen.</p>
          <p className="muted small">
            Restaurar no reactiva la credencial de su agente: si estaba revocado, sigue revocado.
          </p>
        </ConfirmDialog>
      )}
    </div>
  );
}

function ArchiveDialog({ asset, onClose, onDone }: { asset: Asset; onClose: () => void; onDone: () => void }) {
  const [reason, setReason] = useState("");
  const fetchCheck = useCallback((signal: AbortSignal) => lifecycleApi.deleteCheck(asset.asset_id, signal), [asset.asset_id]);
  const check = usePolling(fetchCheck, CHECK_REFRESH_MS);
  const blocked = check.data ? !check.data.can_archive : false;
  return (
    <ConfirmDialog
      title="Archivar activo"
      confirmLabel="Archivar"
      onClose={onClose}
      onConfirm={async () => {
        if (reason.trim().length < 3) throw new Error("Indica un motivo (mínimo 3 caracteres).");
        if (blocked) throw new Error("Revoca el agente en Agentes antes de archivar este activo.");
        try {
          await lifecycleApi.archive(asset.asset_id, reason.trim(), asset.lifecycle_version);
        } catch (error) {
          throw lifecycleError(error);
        }
        onDone();
      }}
    >
      <p>
        El activo deja de mostrarse por defecto y de contar en el resumen y el riesgo actual. Se conserva todo su
        historial (telemetría, eventos, detecciones, vulnerabilidades, incidentes) y se puede restaurar.
      </p>
      {blocked && (
        <p className="banner banner--warn" role="alert">
          Su agente tiene la credencial activa: revócalo antes en Agentes. Revocar no archiva y archivar no revoca.
        </p>
      )}
      <label className="form-field">
        Motivo
        <textarea
          className="input"
          rows={3}
          maxLength={500}
          value={reason}
          onChange={(event) => setReason(event.target.value)}
          placeholder="Equipo retirado, reinstalado como otro activo…"
        />
      </label>
    </ConfirmDialog>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: DuplicateConfidence }) {
  return <span className={`badge ${CONFIDENCE_CLASSES[confidence]}`}>{CONFIDENCE_LABELS[confidence]}</span>;
}

/** Fase 5C.2: estado de ciclo de vida, escaneos perdidos y última actividad (todos los roles). */
function LifecycleSummary({ asset }: { asset: Asset }) {
  // Un servidor anterior a 5C.2 no envía el estado: no se muestra nada.
  if (!asset.lifecycle_state) return null;
  return (
    <p className="muted small" aria-label="Ciclo de vida">
      Ciclo de vida: <LifecycleBadge state={asset.lifecycle_state} />
      {asset.lifecycle_source && ` · ${SOURCE_LABELS[asset.lifecycle_source]}`} · última actividad{" "}
      <span title={formatDateTime(asset.last_activity_at)}>{formatRelative(asset.last_activity_at)}</span> ·{" "}
      {asset.missed_discovery_scans === 1
        ? "1 escaneo completo sin verlo"
        : `${asset.missed_discovery_scans ?? 0} escaneos completos sin verlo`}
    </p>
  );
}

function DeleteDialog({
  asset,
  onClose,
  onArchive,
}: {
  asset: Asset;
  onClose: () => void;
  onArchive: () => void;
}) {
  const navigate = useNavigate();
  const fetchCheck = useCallback((signal: AbortSignal) => lifecycleApi.deleteCheck(asset.asset_id, signal), [asset.asset_id]);
  const check = usePolling(fetchCheck, CHECK_REFRESH_MS);
  if (check.loading) {
    return (
      <Modal title="Eliminar activo" onClose={onClose}>
        <LoadingState label="Comprobando historial…" />
      </Modal>
    );
  }
  if (!check.data) {
    return (
      <Modal title="Eliminar activo" onClose={onClose}>
        <ErrorState message={check.error ? errorMessage(check.error) : "Sin datos"} onRetry={check.refresh} />
      </Modal>
    );
  }
  const data: AssetDeleteCheck = check.data;
  const identity = (
    <dl className="fields fields--inline" aria-label="Activo a eliminar">
      <div className="field">
        <dt>Nombre</dt>
        <dd>{data.hostname ?? data.display_name}</dd>
      </div>
      <div className="field">
        <dt>IP</dt>
        <dd className="mono">{data.primary_ip}</dd>
      </div>
      <div className="field">
        <dt>MAC</dt>
        <dd className="mono">{data.mac_address ?? "—"}</dd>
      </div>
      <div className="field">
        <dt>Asset ID</dt>
        <dd className="mono small">{data.asset_id}</dd>
      </div>
      {data.lifecycle_state && (
        <div className="field">
          <dt>Ciclo de vida</dt>
          <dd>
            <LifecycleBadge state={data.lifecycle_state} />
          </dd>
        </div>
      )}
      {data.missed_discovery_scans !== undefined && (
        <div className="field">
          <dt>Escaneos perdidos</dt>
          <dd>{data.missed_discovery_scans}</dd>
        </div>
      )}
      <div className="field">
        <dt>Última actividad</dt>
        <dd title={formatDateTime(data.last_activity_at ?? data.last_seen_at)}>
          {formatRelative(data.last_activity_at ?? data.last_seen_at)}
        </dd>
      </div>
      <div className="field">
        <dt>Elegible para eliminación definitiva</dt>
        <dd className="strong">{data.deletable ? "Sí" : "No"}</dd>
      </div>
    </dl>
  );
  if (!data.deletable) {
    return (
      <Modal title="Eliminar activo" onClose={onClose}>
        <div className="stack">
          <p className="banner banner--warn" role="alert">
            {blockedByHistory(data.blocking_reasons) ? DELETE_REFUSED : NOT_YET_DELETABLE}
          </p>
          {identity}
          <ul className="small" aria-label="Motivos">
            {data.blocking_reasons.map((reason) => (
              <li key={reason}>{reasonLabel(reason)}</li>
            ))}
          </ul>
          <div className="modal__actions">
            <button type="button" className="button" onClick={onClose}>
              Cerrar
            </button>
            {data.can_archive && asset.archived_at === null && (
              <button type="button" className="button button--primary" onClick={onArchive}>
                Archivar
              </button>
            )}
          </div>
        </div>
      </Modal>
    );
  }
  const removes = Object.entries(data.removes);
  return (
    <ConfirmDialog
      title="Eliminar activo"
      confirmLabel="Eliminar permanentemente"
      danger
      onClose={onClose}
      onConfirm={async () => {
        try {
          await lifecycleApi.remove(asset.asset_id, data.version);
        } catch (error) {
          throw lifecycleError(error);
        }
        navigate("/", { replace: true });
      }}
    >
      <p>
        <strong>{DELETE_CONFIRMATION}</strong>
      </p>
      {identity}
      {removes.length > 0 && (
        <p className="muted small">
          Se borra también:{" "}
          {removes.map(([name, n]) => `${n} ${REMOVES_LABELS[name] ?? name}`).join(", ")}.
        </p>
      )}
      <p className="banner banner--warn">{IRREVERSIBLE_WARNING}</p>
    </ConfirmDialog>
  );
}

function DuplicateCandidates({
  asset,
  canReconcile,
  onReconcile,
}: {
  asset: Asset;
  canReconcile: boolean;
  onReconcile: (targetId: string) => void;
}) {
  const fetchCandidates = useCallback(
    (signal: AbortSignal) => lifecycleApi.candidates(asset.asset_id, signal),
    [asset.asset_id],
  );
  const candidates = usePolling(fetchCandidates, Math.max(config.refreshIntervalMs, 60_000));
  const items = candidates.data?.items ?? [];
  if (items.length === 0) return null;
  // Solo se sugiere el re-enrolado con evidencia media o alta y sin identidades contradictorias.
  const likely =
    items.some((c) => c.confidence !== "low" && (c.conflicts ?? []).length === 0) && asset.monitoring_method === "agent";
  return (
    <section className="panel" aria-label="Posibles duplicados">
      <div className="panel__toolbar">
        <h2>Posible duplicado</h2>
        <span className="muted small">Sin confirmar: solo sugerencias, un administrador decide</span>
      </div>
      {likely && <p className="banner banner--warn">{REENROLL_HINT}</p>}
      <div className="table-wrap">
        <table className="table table--compact">
          <thead>
            <tr>
              <th>Activo</th>
              <th>IP</th>
              <th>Método</th>
              <th>Credencial</th>
              <th>Evidencia</th>
              <th>Confianza</th>
              <th>Último contacto</th>
              <th aria-label="Acciones" />
            </tr>
          </thead>
          <tbody>
            {items.map((candidate: DuplicateCandidate) => {
              const conflicts = candidate.conflicts ?? [];
              const warnings = candidate.reconcile_warnings ?? [];
              return (
                <tr key={candidate.asset.asset_id}>
                  <td>
                    <Link to={`/assets/${candidate.asset.asset_id}`} className="strong">
                      {candidate.asset.display_name}
                    </Link>{" "}
                    {candidate.asset.agent_version && <span className="muted small">v{candidate.asset.agent_version}</span>}{" "}
                    {candidate.asset.archived && <span className="badge badge--muted">Archivado</span>}
                  </td>
                  <td className="mono">{candidate.asset.primary_ip}</td>
                  <td>
                    <MethodBadge method={candidate.asset.monitoring_method} />
                  </td>
                  <td>
                    {candidate.asset.credential_status ? (
                      <CredentialBadge status={candidate.asset.credential_status} />
                    ) : (
                      <span className="muted">—</span>
                    )}
                  </td>
                  <td>
                    {candidate.evidence && candidate.evidence.length > 0 ? (
                      <EvidenceList evidence={candidate.evidence} />
                    ) : (
                      <span className="small">{reasonsText(candidate.reasons)}</span>
                    )}
                    {conflicts.length > 0 && (
                      <span className="badge badge--warn" title="Identidades contradictorias">
                        Conflicto: {conflicts.map((c) => CONFLICT_LABELS[c] ?? c).join(", ")}
                      </span>
                    )}
                  </td>
                  <td>
                    <ConfidenceBadge confidence={candidate.confidence} />
                  </td>
                  <td title={formatDateTime(candidate.asset.last_seen_at)}>{formatRelative(candidate.asset.last_seen_at)}</td>
                  <td>
                    {canReconcile && candidate.reconcilable ? (
                      <>
                        <button
                          type="button"
                          className="button button--small"
                          onClick={() => onReconcile(candidate.asset.asset_id)}
                        >
                          Reconciliar con activo existente
                        </button>
                        {candidate.requires_acknowledgement && (
                          <div className="muted small" title={warnings.map(warningLabel).join("; ")}>
                            Requiere confirmar evidencia débil
                          </div>
                        )}
                      </>
                    ) : (
                      candidate.reconcile_blockers.length > 0 && (
                        <span className="muted small" title={candidate.reconcile_blockers.map(blockerLabel).join("; ")}>
                          No reconciliable
                        </span>
                      )
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

/** Ciclo de vida en el detalle del activo: estado, acciones admin, duplicados y reconciliación. */
export function LifecyclePanel({ asset, onChanged }: { asset: Asset; onChanged: () => void }) {
  const auth = useAuth();
  const navigate = useNavigate();
  const canManage = auth.can("assets:manage");
  const canReconcile = canManage && auth.can("agents:manage");
  const canSeeDuplicates = auth.can("assets:duplicates_read");
  const [dialog, setDialog] = useState<"archive" | "delete">();
  // undefined = cerrado; "" = abierto sin destino preseleccionado.
  const [reconcileTarget, setReconcileTarget] = useState<string>();
  const archived = asset.archived_at !== null;
  return (
    <div className="stack">
      {archived && <ArchivedBanner asset={asset} canManage={canManage} onChanged={onChanged} />}
      <LifecycleSummary asset={asset} />
      {canManage && (
        <div className="panel__toolbar">
          <span className="muted small">
            {asset.managed_history
              ? "Activo gestionado: no se elimina, se archiva conservando su historial."
              : "Activo descubierto: puede eliminarse solo si no tiene historial y es candidato a limpieza."}
          </span>
          <span>
            {canReconcile && !archived && asset.monitoring_method === "agent" && (
              <>
                <button type="button" className="button button--small" onClick={() => setReconcileTarget("")}>
                  Reconciliar manualmente…
                </button>{" "}
              </>
            )}
            {!archived && (
              <button type="button" className="button button--small" onClick={() => setDialog("archive")}>
                Archivar
              </button>
            )}{" "}
            {!asset.managed_history && (
              <button type="button" className="button button--small button--danger" onClick={() => setDialog("delete")}>
                Eliminar
              </button>
            )}
          </span>
        </div>
      )}
      {canSeeDuplicates && !archived && (
        <DuplicateCandidates asset={asset} canReconcile={canReconcile} onReconcile={setReconcileTarget} />
      )}
      {dialog === "archive" && (
        <ArchiveDialog asset={asset} onClose={() => setDialog(undefined)} onDone={onChanged} />
      )}
      {dialog === "delete" && (
        <DeleteDialog asset={asset} onClose={() => setDialog(undefined)} onArchive={() => setDialog("archive")} />
      )}
      {canReconcile && reconcileTarget !== undefined && (
        <ReconcileWizard
          source={asset}
          initialTargetId={reconcileTarget || undefined}
          onClose={() => {
            setReconcileTarget(undefined);
            onChanged();
          }}
          onDone={(target) => navigate(`/assets/${target}`)}
        />
      )}
    </div>
  );
}

/** Pares de posible duplicado de toda la flota (página Agentes). */
export function DuplicatePairsPanel() {
  const auth = useAuth();
  const allowed = auth.can("assets:duplicates_read");
  const fetchPairs = useCallback((signal: AbortSignal) => lifecycleApi.duplicates(signal), []);
  const pairs = usePolling(fetchPairs, Math.max(config.refreshIntervalMs, 60_000), allowed);
  const items: DuplicatePair[] = (pairs.data?.items ?? []).filter((p) => !p.asset.archived);
  if (!allowed || items.length === 0) return null;
  return (
    <section className="panel" aria-label="Posibles duplicados">
      <div className="panel__toolbar">
        <h2>Posibles duplicados</h2>
        <span className="muted small">{REENROLL_HINT} Sin confirmar: revísalo en el activo nuevo.</span>
      </div>
      <ul className="stack small">
        {items.map((pair) => (
          <li key={`${pair.asset.asset_id}-${pair.candidate.asset_id}`}>
            <Link to={`/assets/${pair.asset.asset_id}`} className="strong">
              {pair.asset.display_name}
            </Link>
            {pair.asset.agent_version && ` (v${pair.asset.agent_version})`} podría ser el mismo equipo que{" "}
            <Link to={`/assets/${pair.candidate.asset_id}`}>{pair.candidate.display_name}</Link>
            {pair.candidate.agent_version && ` (v${pair.candidate.agent_version})`}
            {pair.candidate.credential_status && (
              <>
                {" "}
                <CredentialBadge status={pair.candidate.credential_status} />
              </>
            )}{" "}
            · {reasonsText(pair.reasons)} <ConfidenceBadge confidence={pair.confidence} />
            {(pair.conflicts ?? []).length > 0 && (
              <>
                {" "}
                <span className="badge badge--warn">
                  Conflicto: {pair.conflicts.map((c) => CONFLICT_LABELS[c] ?? c).join(", ")}
                </span>
              </>
            )}
          </li>
        ))}
      </ul>
    </section>
  );
}
