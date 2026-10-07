import { useCallback, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError } from "../../api/client";
import { lifecycleApi } from "../../api/sentra";
import type {
  Asset,
  AssetDeleteCheck,
  DeleteBlockingReason,
  DuplicateCandidate,
  DuplicateConfidence,
  DuplicatePair,
  DuplicateReason,
  ReconcileBlocker,
} from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { CredentialBadge } from "../agents/AgentBadges";
import { ConfirmDialog, Modal } from "../Modal";
import { MethodBadge } from "../NetworkBadges";
import { ErrorState, LoadingState } from "../StateViews";

// Textos exactos de la especificación (Fase 5C.1).
export const DELETE_CONFIRMATION =
  "Este activo descubierto no tiene historial gestionado y será eliminado permanentemente.";
export const DELETE_REFUSED = "No se puede eliminar porque contiene historial.";
export const REENROLL_HINT = "Este agente parece corresponder a un activo existente.";

// El diálogo carga la comprobación al abrirse; el servidor la repite al confirmar, así que
// no hace falta refrescarla a menudo mientras está abierto.
const CHECK_REFRESH_MS = 10 * 60_000;

export const DUPLICATE_REASON_LABELS: Record<DuplicateReason, string> = {
  same_machine_id: "misma identidad de máquina",
  same_hostname: "mismo hostname",
  same_ip: "misma IP",
  same_mac: "misma MAC",
};

export const CONFIDENCE_LABELS: Record<DuplicateConfidence, string> = {
  high: "Confianza alta",
  medium: "Confianza media",
  low: "Confianza baja",
};

const CONFIDENCE_CLASSES: Record<DuplicateConfidence, string> = {
  high: "badge--crit",
  medium: "badge--warn",
  low: "badge--muted",
};

const BLOCKING_LABELS: Record<DeleteBlockingReason, string> = {
  managed_history: "tuvo un agente (historial gestionado)",
  agent_history: "telemetría, eventos o inventario de agente",
  detections: "detecciones de impacto medio o superior",
  incidents: "forma parte de incidentes",
  vulnerabilities: "vulnerabilidades evaluadas",
  threat_intel: "coincidencias de inteligencia de amenazas",
  audit_dependency: "contexto editado o análisis de IA",
  other: "alertas sin resolver",
};

const RECONCILE_BLOCKER_LABELS: Record<ReconcileBlocker, string> = {
  same_asset: "es el mismo activo",
  source_without_agent: "este activo no tiene agente",
  source_archived: "este activo está archivado",
  target_never_managed: "el candidato nunca tuvo agente",
  target_agent_online: "el agente del candidato sigue activo y en línea",
  platform_mismatch: "sistemas operativos distintos",
  machine_id_mismatch: "identidades de máquina distintas",
  insufficient_evidence: "evidencia insuficiente (solo hostname o solo IP)",
};

const REMOVES_LABELS: Record<string, string> = {
  ports: "puertos",
  changes: "cambios",
  detections: "detecciones de bajo impacto",
  alerts: "alertas resueltas",
  risk_snapshots: "instantáneas de riesgo",
};

/** Mensaje en español para los 409 del ciclo de vida (la API los da en inglés). */
export function lifecycleError(error: unknown): Error {
  if (error instanceof ApiError) {
    switch (error.code) {
      case "asset_lifecycle_conflict":
        return new Error("El activo cambió mientras tanto. Recarga la página y vuelve a intentarlo.");
      case "asset_state_conflict":
        return new Error(
          "No se puede en su estado actual (¿agente con credencial activa o ya archivado?). Revoca el agente en Agentes antes de archivar.",
        );
      case "asset_not_deletable":
        return new Error(DELETE_REFUSED);
      case "asset_reconcile_refused":
        return new Error("El servidor no ve evidencia suficiente para reconciliar estos activos.");
    }
    return error;
  }
  return error instanceof Error ? error : new Error(String(error));
}

function reasonsText(reasons: DuplicateReason[]): string {
  return reasons.map((r) => DUPLICATE_REASON_LABELS[r]).join(", ");
}

export function ConfidenceBadge({ confidence }: { confidence: DuplicateConfidence }) {
  return <span className={`badge ${CONFIDENCE_CLASSES[confidence]}`}>{CONFIDENCE_LABELS[confidence]}</span>;
}

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
    <dl className="fields fields--inline">
      <div className="field">
        <dt>Hostname</dt>
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
        <dt>Visto por última vez</dt>
        <dd title={formatDateTime(data.last_seen_at)}>{formatRelative(data.last_seen_at)}</dd>
      </div>
    </dl>
  );
  if (!data.deletable) {
    return (
      <Modal title="Eliminar activo" onClose={onClose}>
        <div className="stack">
          <p className="banner banner--warn" role="alert">
            {DELETE_REFUSED}
          </p>
          {identity}
          <ul className="small">
            {data.blocking_reasons.map((reason) => (
              <li key={reason}>{BLOCKING_LABELS[reason]}</li>
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
    </ConfirmDialog>
  );
}

function ReconcileDialog({
  asset,
  candidate,
  onClose,
  onDone,
}: {
  asset: Asset;
  candidate: DuplicateCandidate;
  onClose: () => void;
  onDone: (targetId: string) => void;
}) {
  return (
    <ConfirmDialog
      title="Reconciliar con activo existente"
      confirmLabel="Reconciliar"
      onClose={onClose}
      onConfirm={async () => {
        try {
          await lifecycleApi.reconcile(
            asset.asset_id,
            candidate.asset.asset_id,
            asset.lifecycle_version,
            candidate.asset.version,
          );
        } catch (error) {
          throw lifecycleError(error);
        }
        onDone(candidate.asset.asset_id);
      }}
    >
      <p>
        El agente de este activo pasa a informar en <strong>{candidate.asset.display_name}</strong>, que conserva su
        historial (detecciones, riesgo, vulnerabilidades, incidentes). Este activo queda sin agente y archivado con lo
        poco que el agente llegó a enviar.
      </p>
      <p className="muted small">
        Evidencia: {reasonsText(candidate.reasons)} · {CONFIDENCE_LABELS[candidate.confidence]}. El servidor vuelve a
        validarla; ninguna credencial sale del servidor.
      </p>
    </ConfirmDialog>
  );
}

function DuplicateCandidates({ asset, canReconcile }: { asset: Asset; canReconcile: boolean }) {
  const navigate = useNavigate();
  const fetchCandidates = useCallback(
    (signal: AbortSignal) => lifecycleApi.candidates(asset.asset_id, signal),
    [asset.asset_id],
  );
  const candidates = usePolling(fetchCandidates, Math.max(config.refreshIntervalMs, 60_000));
  const [reconciling, setReconciling] = useState<DuplicateCandidate>();
  const items = candidates.data?.items ?? [];
  if (items.length === 0) return null;
  const likely = items.some((c) => c.confidence !== "low") && asset.monitoring_method === "agent";
  return (
    <section className="panel" aria-label="Posibles duplicados">
      <div className="panel__toolbar">
        <h2>Posible duplicado</h2>
        <span className="muted small">Solo sugerencias: un administrador decide</span>
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
              <th>Razones</th>
              <th>Confianza</th>
              <th>Último contacto</th>
              <th aria-label="Acciones" />
            </tr>
          </thead>
          <tbody>
            {items.map((candidate) => (
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
                <td className="small">{reasonsText(candidate.reasons)}</td>
                <td>
                  <ConfidenceBadge confidence={candidate.confidence} />
                </td>
                <td title={formatDateTime(candidate.asset.last_seen_at)}>{formatRelative(candidate.asset.last_seen_at)}</td>
                <td>
                  {canReconcile && candidate.reconcilable ? (
                    <button type="button" className="button button--small" onClick={() => setReconciling(candidate)}>
                      Reconciliar con activo existente
                    </button>
                  ) : (
                    candidate.reconcile_blockers.length > 0 && (
                      <span
                        className="muted small"
                        title={candidate.reconcile_blockers.map((b) => RECONCILE_BLOCKER_LABELS[b]).join("; ")}
                      >
                        No reconciliable
                      </span>
                    )
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {reconciling && (
        <ReconcileDialog
          asset={asset}
          candidate={reconciling}
          onClose={() => setReconciling(undefined)}
          onDone={(target) => navigate(`/assets/${target}`)}
        />
      )}
    </section>
  );
}

/** Ciclo de vida en el detalle del activo: estado archivado, acciones admin y duplicados. */
export function LifecyclePanel({ asset, onChanged }: { asset: Asset; onChanged: () => void }) {
  const auth = useAuth();
  const canManage = auth.can("assets:manage");
  const canReconcile = canManage && auth.can("agents:manage");
  const canSeeDuplicates = auth.can("assets:duplicates_read");
  const [dialog, setDialog] = useState<"archive" | "delete">();
  const archived = asset.archived_at !== null;
  return (
    <div className="stack">
      {archived && <ArchivedBanner asset={asset} canManage={canManage} onChanged={onChanged} />}
      {canManage && (
        <div className="panel__toolbar">
          <span className="muted small">
            {asset.managed_history
              ? "Activo gestionado: no se elimina, se archiva conservando su historial."
              : "Activo descubierto: puede eliminarse solo si no tiene historial."}
          </span>
          <span>
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
      {canSeeDuplicates && !archived && <DuplicateCandidates asset={asset} canReconcile={canReconcile} />}
      {dialog === "archive" && (
        <ArchiveDialog asset={asset} onClose={() => setDialog(undefined)} onDone={onChanged} />
      )}
      {dialog === "delete" && (
        <DeleteDialog asset={asset} onClose={() => setDialog(undefined)} onArchive={() => setDialog("archive")} />
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
        <span className="muted small">{REENROLL_HINT} Revísalo en el activo nuevo.</span>
      </div>
      <ul className="stack small">
        {items.map((pair) => (
          <li key={`${pair.asset.asset_id}-${pair.candidate.asset_id}`}>
            <Link to={`/assets/${pair.asset.asset_id}`} className="strong">
              {pair.asset.display_name}
            </Link>
            {pair.asset.agent_version && ` (v${pair.asset.agent_version})`} parece el mismo equipo que{" "}
            <Link to={`/assets/${pair.candidate.asset_id}`}>{pair.candidate.display_name}</Link>
            {pair.candidate.agent_version && ` (v${pair.candidate.agent_version})`}
            {pair.candidate.credential_status && (
              <>
                {" "}
                <CredentialBadge status={pair.candidate.credential_status} />
              </>
            )}{" "}
            · {reasonsText(pair.reasons)} <ConfidenceBadge confidence={pair.confidence} />
          </li>
        ))}
      </ul>
    </section>
  );
}
