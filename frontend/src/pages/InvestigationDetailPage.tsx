import { useCallback, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { responseApi } from "../api/sentra";
import { forensicsApi } from "../api/sentra6e";
import type {
  ForensicArtifact,
  ForensicArtifactDetail,
  Investigation,
  InvestigationDetail,
  InvestigationNoteKind,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { PackageDownload } from "../components/forensics/PackageDownload";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatBytes, formatDateTime } from "../lib/format";
import {
  artifactText,
  FORENSIC_ACTIONS,
  forensicActionLabel,
  INTEGRITY_LABELS,
  INVESTIGATION_STATUS_LABELS,
  NOTE_KIND_LABELS,
  validForensicPath,
} from "../lib/forensics";
import { newReportKey } from "../lib/reports";
import { usePolling } from "../lib/usePolling";

// Mientras hay recogidas en curso el detalle se refresca a menudo para ver llegar la evidencia.
const ACTIVE_REFRESH_MS = 5_000;
const IDLE_REFRESH_MS = 60_000;
const RUNNING = new Set(["pending", "approval_required", "queued", "running"]);

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Detalle de una investigación forense (Fase 6E.6). La evidencia (artefactos con su SHA-256) y
 * las interpretaciones (notas y resúmenes de IA) se muestran en secciones separadas, como en el
 * paquete ZIP. Un artefacto cuyo hash no coincide con el del agente se marca siempre.
 */
export function InvestigationDetailPage() {
  const { investigationId = "" } = useParams();
  const auth = useAuth();
  const [active, setActive] = useState(false);
  const fetcher = useCallback((signal: AbortSignal) => forensicsApi.get(investigationId, signal), [investigationId]);
  const { data, error, loading, refresh } = usePolling(fetcher, active ? ACTIVE_REFRESH_MS : IDLE_REFRESH_MS);
  const nowActive = Boolean(data?.collections.some((c) => RUNNING.has(c.status)));
  if (nowActive !== active) setActive(nowActive);

  if (loading) return <LoadingState label="Cargando investigación…" />;
  if (!data) {
    return (
      <div className="page">
        <Link to="/investigations" className="back">
          ← Investigaciones
        </Link>
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      </div>
    );
  }
  const inv = data.investigation;
  const open = inv.status === "open";

  return (
    <div className="page">
      <Link to="/investigations" className="back">
        ← Investigaciones
      </Link>
      <div className="page__header">
        <div>
          <h1>{inv.title}</h1>
          <div className="detection-badges">
            <span className={open ? "badge badge--info" : "badge badge--muted"}>{INVESTIGATION_STATUS_LABELS[inv.status]}</span>
            {inv.legal_hold && <span className="badge badge--warn">Retención legal</span>}
            <span className="muted small">
              Equipo:{" "}
              {inv.asset_exists ? (
                <Link to={`/assets/${encodeURIComponent(inv.asset_id)}?tab=investigations`}>{inv.asset_label}</Link>
              ) : (
                `${inv.asset_label} (ya no existe)`
              )}
              {inv.incident_id && (
                <>
                  {" · "}
                  <Link to={`/incidents/${encodeURIComponent(inv.incident_id)}`}>Incidente vinculado</Link>
                </>
              )}
              {" · "}abierta por {inv.created_by} el {formatDateTime(inv.created_at)}
            </span>
          </div>
        </div>
        {auth.can("forensics:manage") && <ManageActions investigation={inv} onChanged={refresh} />}
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {inv.mismatch_count > 0 && (
        <div className="banner banner--warn" role="alert" data-testid="integrity-warning">
          {inv.mismatch_count} evidencia(s) con SHA-256 que no coincide con el que calculó el agente: pudieron alterarse
          entre el equipo y el servidor. No las uses como prueba sin verificarlas.
        </div>
      )}

      <EvidenceSection detail={data} />
      <CollectionSection
        detail={data}
        canCollect={open && inv.asset_exists && auth.can("forensics:acquire") && auth.can("response:execute")}
        canFileMetadata={auth.can("response:manage")}
        onStarted={refresh}
      />
      <InterpretationsSection detail={data} canWrite={open && auth.can("forensics:acquire")} onAdded={refresh} />

      <section className="panel panel--padded stack" aria-label="Paquetes de evidencias">
        <h2 className="panel__title">Paquete de evidencias</h2>
        <p className="small muted">
          ZIP con manifest.json (hashes y cadena de custodia), evidence/ e interpretations/. Su SHA-256 se verifica en el
          navegador antes de guardarlo y cada descarga queda registrada.
        </p>
        {auth.can("forensics:download") ? (
          <PackageDownload investigationId={inv.id} mismatchCount={inv.mismatch_count} onDownloaded={refresh} />
        ) : (
          <p className="muted small">Tu rol no permite descargar evidencias.</p>
        )}
        {data.packages.length > 0 && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Generado</th>
                  <th>Artefactos</th>
                  <th>Tamaño</th>
                  <th className="col-secondary">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {data.packages.map((p) => (
                  <tr key={p.id}>
                    <td>
                      {formatDateTime(p.created_at)} <span className="muted small">· {p.created_by}</span>
                    </td>
                    <td>
                      {p.artifact_count}
                      {p.includes_mismatch && <span className="badge badge--crit">incluye no verificados</span>}
                    </td>
                    <td>{formatBytes(p.size_bytes)}</td>
                    <td className="col-secondary mono small">{p.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function ManageActions({ investigation, onChanged }: { investigation: Investigation; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
    } catch (err) {
      setError(errorMessage(toError(err)));
    } finally {
      setBusy(false);
      // También tras un 409 investigation_version_conflict: se recarga la versión actual.
      onChanged();
    }
  };
  const { id, version } = investigation;
  return (
    <div className="actions">
      {investigation.status === "open" ? (
        <button type="button" className="button" disabled={busy} onClick={() => void run(() => forensicsApi.close(id, version))}>
          Cerrar investigación
        </button>
      ) : (
        <button type="button" className="button" disabled={busy} onClick={() => void run(() => forensicsApi.reopen(id, version))}>
          Reabrir
        </button>
      )}
      <button
        type="button"
        className="button"
        disabled={busy}
        onClick={() => void run(() => forensicsApi.setLegalHold(id, !investigation.legal_hold, version))}
      >
        {investigation.legal_hold ? "Quitar retención legal" : "Activar retención legal"}
      </button>
      {error && (
        <span className="text-crit small" role="alert">
          {error}
        </span>
      )}
    </div>
  );
}

function IntegrityBadge({ artifact }: { artifact: ForensicArtifact }) {
  return (
    <span className={artifact.integrity === "verified" ? "badge badge--ok" : "badge badge--crit"}>
      {INTEGRITY_LABELS[artifact.integrity] ?? artifact.integrity}
    </span>
  );
}

/** Evidencia: lo que devolvió el agente, con su hash y procedencia. Nunca se edita. */
function EvidenceSection({ detail }: { detail: InvestigationDetail }) {
  const [viewing, setViewing] = useState<string>();
  return (
    <section className="panel" aria-label="Evidencias">
      <div className="panel__toolbar">
        <h2>Evidencias ({detail.artifacts.length})</h2>
        <span className="muted small">Datos recogidos del equipo, tal como se recibieron.</span>
      </div>
      {detail.artifacts.length === 0 ? (
        <p className="muted small panel--padded">Aún no hay evidencias. Lanza una recogida desde la sección siguiente.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Recogida</th>
                <th>Cuándo</th>
                <th>Integridad</th>
                <th>Tamaño</th>
                <th className="col-secondary">Operador</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {detail.artifacts.map((a) => (
                <tr key={a.id} className={a.integrity === "mismatch" ? "row--crit" : undefined}>
                  <td>
                    {forensicActionLabel(a.action)}
                    {a.truncated && <span className="badge badge--warn">recortado</span>}
                    {a.limitations.length > 0 && <span className="badge badge--muted">{a.limitations.length} limitaciones</span>}
                  </td>
                  <td>{formatDateTime(a.collected_at ?? a.received_at)}</td>
                  <td>
                    <IntegrityBadge artifact={a} />
                    <div className="mono small" title="SHA-256 calculado por el servidor">
                      {a.sha256.slice(0, 16)}…
                    </div>
                    {a.integrity === "mismatch" && (
                      <div className="mono small text-crit" title="SHA-256 declarado por el agente">
                        agente: {a.agent_sha256 ? `${a.agent_sha256.slice(0, 16)}…` : "—"}
                      </div>
                    )}
                  </td>
                  <td>{formatBytes(a.size_bytes)}</td>
                  <td className="col-secondary">{a.operator}</td>
                  <td>
                    <button
                      type="button"
                      className="button button--small"
                      onClick={() => setViewing(viewing === a.id ? undefined : a.id)}
                    >
                      {viewing === a.id ? "Ocultar" : "Ver contenido"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {viewing && <ArtifactViewer key={viewing} investigationId={detail.investigation.id} artifactId={viewing} />}
    </section>
  );
}

function ArtifactViewer({ investigationId, artifactId }: { investigationId: string; artifactId: string }) {
  const fetcher = useCallback(
    (signal: AbortSignal) => forensicsApi.artifact(investigationId, artifactId, signal),
    [investigationId, artifactId],
  );
  const { data, error, loading, refresh } = usePolling<ForensicArtifactDetail>(fetcher, 3_600_000);
  if (loading) return <LoadingState label="Cargando evidencia…" />;
  if (!data) return <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />;
  return (
    <div className="panel--padded stack" aria-label="Contenido de la evidencia">
      <h3 className="small strong">
        {forensicActionLabel(data.action)} <IntegrityBadge artifact={data} />
      </h3>
      <dl className="fields">
        <div className="field">
          <dt>SHA-256 (servidor)</dt>
          <dd className="mono small">{data.sha256}</dd>
        </div>
        <div className="field">
          <dt>SHA-256 (agente)</dt>
          <dd className={`mono small${data.integrity === "mismatch" ? " text-crit" : ""}`}>{data.agent_sha256 ?? "—"}</dd>
        </div>
        <div className="field">
          <dt>Agente</dt>
          <dd>
            {data.agent_version ?? "—"} · {data.platform ?? "—"}
          </dd>
        </div>
      </dl>
      {data.limitations.length > 0 && (
        <ul className="plain-list small" aria-label="Limitaciones">
          {data.limitations.map((l, i) => (
            <li key={i}>{artifactText(l)}</li>
          ))}
        </ul>
      )}
      {/* Siempre texto: el contenido del equipo nunca se interpreta como HTML. */}
      <pre className="code-block artifact-content">{artifactText(data.content)}</pre>
    </div>
  );
}

function CollectionSection({
  detail,
  canCollect,
  canFileMetadata,
  onStarted,
}: {
  detail: InvestigationDetail;
  canCollect: boolean;
  canFileMetadata: boolean;
  onStarted: () => void;
}) {
  return (
    <section className="panel" aria-label="Recogidas">
      <div className="panel__toolbar">
        <h2>Recogidas</h2>
      </div>
      {canCollect && <CollectForm detail={detail} canFileMetadata={canFileMetadata} onStarted={onStarted} />}
      {detail.collections.length > 0 && (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Acción</th>
                <th>Estado</th>
                <th>Pedida</th>
                <th className="col-secondary">Fin</th>
              </tr>
            </thead>
            <tbody>
              {detail.collections.map((c) => (
                <tr key={c.execution_id}>
                  <td>{forensicActionLabel(c.action)}</td>
                  <td>
                    <span className="mono small">{c.status}</span>
                    {c.error_code && <span className="text-crit small"> ({c.error_code})</span>}
                  </td>
                  <td>
                    {formatDateTime(c.created_at)} <span className="muted small">· {c.actor}</span>
                  </td>
                  <td className="col-secondary">{c.finished_at ? formatDateTime(c.finished_at) : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * Recogida forense: la misma acción del Response Engine (POST /response/executions) con
 * investigation_id. Solo lectura en el equipo; metadatos de fichero es MEDIUM (admin) y exige
 * confirmación explícita.
 */
function CollectForm({
  detail,
  canFileMetadata,
  onStarted,
}: {
  detail: InvestigationDetail;
  canFileMetadata: boolean;
  onStarted: () => void;
}) {
  const actions = FORENSIC_ACTIONS.filter((a) => !a.needsPath || canFileMetadata);
  const [action, setAction] = useState(actions[0]?.id ?? "");
  const [path, setPath] = useState("");
  const [hash, setHash] = useState(false);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [notice, setNotice] = useState<string>();
  const needsPath = FORENSIC_ACTIONS.find((a) => a.id === action)?.needsPath ?? false;
  const pathOk = !needsPath || validForensicPath(path);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!pathOk || (needsPath && !confirmed)) return;
    setBusy(true);
    setError(undefined);
    setNotice(undefined);
    try {
      const execution = await responseApi.execute({
        action_id: action,
        target_type: "asset",
        target_id: detail.investigation.asset_id,
        investigation_id: detail.investigation.id,
        parameters: needsPath ? { path: path.trim(), hash } : {},
        confirm: needsPath ? confirmed : false,
        idempotency_key: newReportKey(),
      });
      setNotice(
        execution.deduplicated
          ? "Ya había una recogida igual en curso: se sigue esa."
          : `Recogida solicitada (${execution.status}). La evidencia aparecerá al responder el agente.`,
      );
      setConfirmed(false);
      onStarted();
    } catch (err) {
      setError(errorMessage(toError(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="panel--padded stack" onSubmit={(e) => void submit(e)} aria-label="Nueva recogida" noValidate>
      <div className="form-grid">
        <label className="form-field">
          <span>Qué recoger</span>
          <select className="input input--select" value={action} onChange={(e) => setAction(e.target.value)} disabled={busy}>
            {actions.map((a) => (
              <option key={a.id} value={a.id}>
                {a.label}
              </option>
            ))}
          </select>
        </label>
        {needsPath && (
          <>
            <label className="form-field">
              <span>Ruta absoluta del fichero</span>
              <input
                className="input mono"
                value={path}
                maxLength={1024}
                placeholder="C:\Users\Public\fichero.exe"
                onChange={(e) => setPath(e.target.value)}
                disabled={busy}
                aria-invalid={path !== "" && !pathOk}
              />
            </label>
            <label className="checkbox small">
              <input type="checkbox" checked={hash} onChange={(e) => setHash(e.target.checked)} disabled={busy} /> Calcular
              SHA-256 del fichero
            </label>
            <label className="checkbox small">
              <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} disabled={busy} />{" "}
              Confirmo la lectura de metadatos de este fichero (nunca su contenido)
            </label>
          </>
        )}
      </div>
      {needsPath && path !== "" && !pathOk && (
        <p className="small text-crit">La ruta debe ser absoluta y no puede contener «..».</p>
      )}
      <p className="muted small">
        Solo lectura: el agente devuelve un artefacto con su SHA-256. El agente rechaza rutas fuera de su lista local de
        rutas permitidas.
      </p>
      <div className="actions">
        <button
          type="submit"
          className="button button--primary"
          disabled={busy || !pathOk || (needsPath && (!path || !confirmed))}
        >
          {busy ? "Solicitando…" : "Recoger"}
        </button>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {notice && (
        <div className="banner banner--ok" role="status">
          {notice}
        </div>
      )}
    </form>
  );
}

/** Interpretaciones: notas y resúmenes de IA, separados de la evidencia y etiquetados como tales. */
function InterpretationsSection({
  detail,
  canWrite,
  onAdded,
}: {
  detail: InvestigationDetail;
  canWrite: boolean;
  onAdded: () => void;
}) {
  const [body, setBody] = useState("");
  const [kind, setKind] = useState<InvestigationNoteKind>("note");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!body.trim()) return;
    setBusy(true);
    setError(undefined);
    try {
      await forensicsApi.addNote(detail.investigation.id, body.trim(), kind);
      setBody("");
      onAdded();
    } catch (err) {
      setError(errorMessage(toError(err)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel panel--padded stack interpretations" aria-label="Interpretaciones">
      <h2 className="panel__title">Interpretaciones ({detail.notes.length})</h2>
      <p className="muted small">
        Conclusiones y resúmenes de personas o de la IA. No son evidencia: el paquete las guarda aparte, en interpretations/.
      </p>
      {detail.notes.length === 0 ? (
        <p className="muted small">Sin notas todavía.</p>
      ) : (
        <ul className="plain-list stack" aria-label="Notas">
          {detail.notes.map((n) => (
            <li key={n.id} className="note">
              <div className="small">
                <span className={n.kind === "ai_summary" ? "badge badge--info" : "badge"}>{NOTE_KIND_LABELS[n.kind]}</span>{" "}
                <span className="muted">
                  {n.author} · {formatDateTime(n.created_at)}
                </span>
              </div>
              <p className="note__body">{n.body}</p>
            </li>
          ))}
        </ul>
      )}
      {canWrite && (
        <form className="stack" onSubmit={(e) => void submit(e)} aria-label="Nueva nota">
          <label className="form-field">
            <span>Nueva nota</span>
            <textarea
              className="input"
              rows={3}
              maxLength={8000}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              disabled={busy}
            />
          </label>
          <div className="actions">
            <select
              className="input input--select"
              aria-label="Tipo de nota"
              value={kind}
              onChange={(e) => setKind(e.target.value as InvestigationNoteKind)}
              disabled={busy}
            >
              <option value="note">{NOTE_KIND_LABELS.note}</option>
              <option value="ai_summary">{NOTE_KIND_LABELS.ai_summary}</option>
            </select>
            <button type="submit" className="button" disabled={busy || !body.trim()}>
              {busy ? "Guardando…" : "Añadir nota"}
            </button>
          </div>
          {error && (
            <div className="banner banner--warn" role="alert">
              {error}
            </div>
          )}
        </form>
      )}
    </section>
  );
}
