import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { maintenanceApi } from "../api/sentra7b";
import type {
  AttributionPreview,
  MaintenanceArtifactIn,
  MaintenanceKind,
  MaintenanceOperationRead,
  MaintenanceStatus,
  ReferenceArtifact,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect, Toolbar } from "../components/ListControls";
import { Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { VERDICT_CLASS, VERDICT_LABELS } from "../lib/attribution";
import { errorMessage, formatDateTime, formatRelative, toLocalInputValue } from "../lib/format";
import { useAssetOptions } from "../lib/useAssetOptions";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";

const KIND_LABELS: Record<MaintenanceKind, string> = {
  agent_install: "Instalación del agente",
  agent_upgrade: "Actualización del agente",
  sensor_install: "Instalación del sensor",
  database_init: "Inicialización de la base de datos",
  server_setup: "Instalación del servidor",
  software_install: "Instalación de software",
  other: "Otra",
};

const STATUS_LABELS: Record<MaintenanceStatus, string> = {
  pending_review: "Pendiente de aprobar",
  approved: "Aprobada",
  revoked: "Revocada",
  superseded: "Sustituida",
};

const STATUS_CLASS: Record<MaintenanceStatus, string> = {
  pending_review: "badge--warn",
  approved: "badge--ok",
  revoked: "badge--muted",
  superseded: "badge--muted",
};

const SHA256 = /^[0-9a-fA-F]{64}$/;
const HOUR = 3_600_000;

function lines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
}

function fail(err: unknown): string {
  return errorMessage(err instanceof Error ? err : new Error(String(err)));
}

interface ArtifactRow {
  kind: MaintenanceArtifactIn["kind"];
  path: string;
  sha256: string;
  serviceName: string;
  imagePath: string;
  serviceAccount: string;
  reference: boolean;
}

const EMPTY_ROW: ArtifactRow = {
  kind: "script",
  path: "",
  sha256: "",
  serviceName: "",
  imagePath: "",
  serviceAccount: "",
  reference: false,
};

function toArtifact(row: ArtifactRow): MaintenanceArtifactIn | string {
  if (row.kind === "service") {
    if (!row.serviceName.trim() || !row.imagePath.trim()) return "Un servicio necesita nombre e ImagePath completo.";
    return {
      kind: "service",
      service_name: row.serviceName.trim(),
      image_path: row.imagePath.trim(),
      service_account: row.serviceAccount.trim() || null,
    };
  }
  if (!row.path.trim() || !SHA256.test(row.sha256.trim())) return "Un script o binario necesita ruta completa y SHA-256.";
  return {
    kind: row.kind,
    path: row.path.trim(),
    sha256: row.sha256.trim().toLowerCase(),
    reference_source: row.reference ? "server_distribution" : "manual",
  };
}

/** Alta de una operación (queda pendiente de aprobar). Nada se verifica por el nombre. */
function CreateDialog({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  // Valores iniciales calculados una vez al abrir el diálogo.
  const [now] = useState(() => Date.now());
  const [assetQuery, setAssetQuery] = useState("");
  const [assetId, setAssetId] = useState("");
  const assets = useAssetOptions(assetQuery, assetId);
  const [kind, setKind] = useState<MaintenanceKind>("agent_install");
  const [title, setTitle] = useState("");
  const [reason, setReason] = useState("");
  const [start, setStart] = useState(toLocalInputValue(new Date(now - HOUR)));
  const [end, setEnd] = useState(toLocalInputValue(new Date(now + 2 * HOUR)));
  const [expires, setExpires] = useState(toLocalInputValue(new Date(now + 30 * 24 * HOUR)));
  const [accounts, setAccounts] = useState("");
  const [interpreters, setInterpreters] = useState("");
  const [rows, setRows] = useState<ArtifactRow[]>([{ ...EMPTY_ROW }]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const fetchRefs = useCallback((signal: AbortSignal) => maintenanceApi.references(signal), []);
  const refs = usePolling(fetchRefs, config.refreshIntervalMs * 30);

  const update = (index: number, changes: Partial<ArtifactRow>) =>
    setRows((current) => current.map((row, i) => (i === index ? { ...row, ...changes } : row)));
  const applyReference = (index: number, ref: ReferenceArtifact) =>
    // El hash lo calculó el servidor sobre su propia copia; la ruta del equipo la escribe el admin.
    update(index, { sha256: ref.sha256, reference: true, path: rows[index]?.path || ref.name });

  const submit = async () => {
    const artifacts: MaintenanceArtifactIn[] = [];
    for (const row of rows) {
      const built = toArtifact(row);
      if (typeof built === "string") {
        setError(built);
        return;
      }
      artifacts.push(built);
    }
    setBusy(true);
    setError(undefined);
    try {
      await maintenanceApi.create({
        asset_id: assetId,
        kind,
        title: title.trim(),
        reason: reason.trim(),
        window_start: new Date(start).toISOString(),
        window_end: new Date(end).toISOString(),
        expires_at: new Date(expires).toISOString(),
        accounts: lines(accounts),
        interpreters: lines(interpreters),
        artifacts,
      });
      onDone();
      onClose();
    } catch (err) {
      setError(fail(err));
      setBusy(false);
    }
  };

  const ready = assetId && title.trim().length >= 3 && reason.trim().length >= 10;
  return (
    <Modal title="Registrar operación de mantenimiento" onClose={busy ? () => undefined : onClose} wide>
      <div className="stack">
        <p className="small muted">
          Describe una intervención concreta (ventana de 72 h como máximo). Un script se verifica por SHA-256, ruta, cuenta y
          ventana; un servicio por nombre, ImagePath exacto y cuenta. Queda pendiente hasta que un administrador la apruebe.
        </p>
        <div className="form-grid">
          <label className="field">
            <span>Buscar equipo</span>
            <input className="input" value={assetQuery} onChange={(e) => setAssetQuery(e.target.value)} />
          </label>
          <label className="field">
            <span>Equipo</span>
            <select className="input input--select" value={assetId} onChange={(e) => setAssetId(e.target.value)}>
              <option value="">Elige un equipo…</option>
              {assets.map((a) => (
                <option key={a.asset_id} value={a.asset_id}>
                  {a.display_name}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Tipo</span>
            <select className="input input--select" value={kind} onChange={(e) => setKind(e.target.value as MaintenanceKind)}>
              {Object.entries(KIND_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Título</span>
            <input className="input" maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label className="field">
            <span>Inicio de la ventana</span>
            <input className="input" type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
          </label>
          <label className="field">
            <span>Fin de la ventana</span>
            <input className="input" type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
          </label>
          <label className="field">
            <span>Caduca</span>
            <input className="input" type="datetime-local" value={expires} onChange={(e) => setExpires(e.target.value)} />
          </label>
        </div>
        <label className="field">
          <span>Motivo</span>
          <textarea className="input" rows={2} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} />
        </label>
        <div className="form-grid">
          <label className="field">
            <span>Cuentas que ejecutan (una por línea)</span>
            <textarea
              className="input mono"
              rows={2}
              value={accounts}
              onChange={(e) => setAccounts(e.target.value)}
              placeholder={"DESKTOP-01\\admin"}
            />
          </label>
          <label className="field">
            <span>Intérpretes (opcional, una ruta por línea)</span>
            <textarea className="input mono" rows={2} value={interpreters} onChange={(e) => setInterpreters(e.target.value)} />
          </label>
        </div>
        <fieldset className="stack">
          <legend>Artefactos</legend>
          {rows.map((row, index) => (
            <div key={index} className="artifact-row">
              <select
                className="input input--select"
                aria-label={`Tipo del artefacto ${index + 1}`}
                value={row.kind}
                onChange={(e) => update(index, { kind: e.target.value as ArtifactRow["kind"] })}
              >
                <option value="script">Script</option>
                <option value="binary">Binario</option>
                <option value="service">Servicio</option>
              </select>
              {row.kind === "service" ? (
                <>
                  <input
                    className="input"
                    aria-label={`Nombre del servicio ${index + 1}`}
                    placeholder="SentraAgent"
                    value={row.serviceName}
                    onChange={(e) => update(index, { serviceName: e.target.value })}
                  />
                  <input
                    className="input mono"
                    aria-label={`ImagePath ${index + 1}`}
                    placeholder='"C:\\Program Files\\Sentra\\...\\sentra-agent.exe" run'
                    value={row.imagePath}
                    onChange={(e) => update(index, { imagePath: e.target.value })}
                  />
                  <input
                    className="input"
                    aria-label={`Cuenta del servicio ${index + 1}`}
                    placeholder="NT SERVICE\\SentraAgent"
                    value={row.serviceAccount}
                    onChange={(e) => update(index, { serviceAccount: e.target.value })}
                  />
                </>
              ) : (
                <>
                  <input
                    className="input mono"
                    aria-label={`Ruta completa ${index + 1}`}
                    placeholder="C:\\Sentra\\scripts\\install-sentra-agent.ps1"
                    value={row.path}
                    onChange={(e) => update(index, { path: e.target.value })}
                  />
                  <input
                    className="input mono"
                    aria-label={`SHA-256 ${index + 1}`}
                    placeholder="SHA-256 (Get-FileHash)"
                    value={row.sha256}
                    onChange={(e) => update(index, { sha256: e.target.value, reference: false })}
                  />
                  {refs.data && refs.data.items.length > 0 && (
                    <select
                      className="input input--select"
                      aria-label={`Hash de referencia del servidor ${index + 1}`}
                      value=""
                      onChange={(e) => {
                        const ref = refs.data?.items.find((r) => r.relative_path === e.target.value);
                        if (ref) applyReference(index, ref);
                      }}
                    >
                      <option value="">Usar hash de referencia del servidor…</option>
                      {refs.data.items.map((r) => (
                        <option key={r.relative_path} value={r.relative_path}>
                          {r.relative_path}
                        </option>
                      ))}
                    </select>
                  )}
                </>
              )}
              {rows.length > 1 && (
                <button
                  type="button"
                  className="button button--small"
                  onClick={() => setRows((current) => current.filter((_, i) => i !== index))}
                >
                  Quitar
                </button>
              )}
            </div>
          ))}
          {rows.length < 20 && (
            <button type="button" className="button button--small" onClick={() => setRows((r) => [...r, { ...EMPTY_ROW }])}>
              Añadir artefacto
            </button>
          )}
        </fieldset>
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="button" className="button button--primary" disabled={busy || !ready} onClick={() => void submit()}>
            {busy ? "Registrando…" : "Registrar (pendiente de aprobar)"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/** Vista previa de los veredictos y aplicación con confirmación explícita. */
function PreviewDialog({ operation, onClose, onDone }: { operation: MaintenanceOperationRead; onClose: () => void; onDone: () => void }) {
  const fetcher = useCallback(() => maintenanceApi.preview(operation.id), [operation.id]);
  const preview = usePolling<AttributionPreview>(fetcher, 3_600_000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<string>();
  const apply = async () => {
    setBusy(true);
    setError(undefined);
    try {
      const applied = await maintenanceApi.apply(operation.id);
      setResult(`Evaluadas ${applied.evaluated}, verificadas ${applied.verified}, cerradas ${applied.resolved}.`);
      onDone();
    } catch (err) {
      setError(fail(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Modal title={`Vista previa: ${operation.title}`} onClose={busy ? () => undefined : onClose} wide>
      <div className="stack">
        {!preview.data ? (
          preview.error ? (
            <ErrorState message={errorMessage(preview.error)} onRetry={preview.refresh} />
          ) : (
            <LoadingState label="Evaluando detecciones de la ventana…" />
          )
        ) : preview.data.items.length === 0 ? (
          <EmptyState title="Ninguna detección atribuible en la ventana de esta operación" />
        ) : (
          <>
            <p className="small">
              {preview.data.verified} verificadas, {preview.data.not_verified} sin verificar. Solo se cierran las verificadas;
              el resto se queda como está.
            </p>
            <div className="table-wrap">
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Detección</th>
                    <th>Actual</th>
                    <th>Tras aplicar</th>
                    <th>Se cierra</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.data.items.map((item) => (
                    <tr key={item.detection_id}>
                      <td>
                        <Link to={`/detections/${item.detection_id}`}>
                          {item.rule_id} · {item.title}
                        </Link>
                      </td>
                      <td className="small">{item.current_verdict ? VERDICT_LABELS[item.current_verdict] : "—"}</td>
                      <td>
                        <span className={`badge ${VERDICT_CLASS[item.verdict]}`}>{VERDICT_LABELS[item.verdict]}</span>
                      </td>
                      <td>{item.would_resolve ? "Sí" : "No"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
        {result && (
          <div className="banner banner--ok" role="status">
            {result}
          </div>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cerrar
          </button>
          {!result && (
            <button
              type="button"
              className="button button--primary"
              disabled={busy || !preview.data || preview.data.items.length === 0 || operation.status !== "approved"}
              onClick={() => void apply()}
            >
              {busy ? "Aplicando…" : "Aplicar veredictos"}
            </button>
          )}
        </div>
      </div>
    </Modal>
  );
}

function DecisionDialog({
  operation,
  mode,
  onClose,
  onDone,
}: {
  operation: MaintenanceOperationRead;
  mode: "approve" | "revoke";
  onClose: () => void;
  onDone: () => void;
}) {
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      if (mode === "approve") await maintenanceApi.approve(operation.id, text);
      else await maintenanceApi.revoke(operation.id, text.trim());
      onDone();
      onClose();
    } catch (err) {
      setError(fail(err));
      setBusy(false);
    }
  };
  return (
    <Modal title={mode === "approve" ? "Aprobar operación" : "Revocar operación"} onClose={busy ? () => undefined : onClose}>
      <div className="stack">
        <p>
          <strong>{operation.title}</strong> en {operation.asset_name}, de {formatDateTime(operation.window_start)} a{" "}
          {formatDateTime(operation.window_end)}.
        </p>
        <ul className="small">
          {operation.artifacts.map((a, i) => (
            <li key={i} className="mono">
              {a.kind === "service" ? `${a.service_name} → ${a.image_path}` : `${a.path} · ${a.sha256}`}
            </li>
          ))}
        </ul>
        {mode === "approve" && (
          <p className="small muted">
            Al aprobar, Sentra reconocerá sola las detecciones NUEVAS de esta ventana cuya evidencia, toda posterior a la
            aprobación, case exactamente (hash, ruta, cuenta, servicio). Las detecciones que ya existen solo cambian con
            «Vista previa» y «Aplicar». Un script nuevo o modificado nunca se reconoce, y los puertos expuestos siguen
            contando en el riesgo.
          </p>
        )}
        <label className="field">
          <span>{mode === "approve" ? "Nota (opcional)" : "Motivo"}</span>
          <textarea className="input" rows={2} maxLength={500} value={text} onChange={(e) => setText(e.target.value)} />
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
            className={`button ${mode === "approve" ? "button--primary" : "button--danger"}`}
            disabled={busy || (mode === "revoke" && text.trim().length < 3)}
            onClick={() => void submit()}
          >
            {mode === "approve" ? "Aprobar" : "Revocar"}
          </button>
        </div>
      </div>
    </Modal>
  );
}

/**
 * Operaciones de mantenimiento (Fase 7B.1): la única forma de que una detección de script,
 * servicio, proceso o puerto pase a «verificada como legítima». Nunca por el nombre SENTRA.
 */
export function MaintenancePage() {
  const canManage = useAuth().can("maintenance:manage");
  const { scopeId } = useSite();
  const [status, setStatus] = useState<MaintenanceStatus | "">("");
  const fetcher = useCallback(
    (signal: AbortSignal) => maintenanceApi.list({ status: status || undefined, siteId: scopeId, limit: 100 }, signal),
    [status, scopeId],
  );
  const list = usePolling(fetcher, config.refreshIntervalMs * 2, true, true);
  const [creating, setCreating] = useState(false);
  const [decision, setDecision] = useState<{ operation: MaintenanceOperationRead; mode: "approve" | "revoke" }>();
  const [previewing, setPreviewing] = useState<MaintenanceOperationRead>();

  return (
    <div className="stack">
      <header className="page-header">
        <h1>Operaciones de mantenimiento</h1>
        <p className="muted small">
          Intervenciones autorizadas (instalar el agente, inicializar la base de datos...) con sus artefactos exactos. Una
          detección solo se verifica como legítima si TODA su evidencia casa con una operación aprobada.
        </p>
      </header>
      <section className="panel" aria-label="Operaciones">
        <div className="panel__toolbar">
          <h2>
            Operaciones <span className="muted">({list.data?.total ?? 0})</span>
          </h2>
          {canManage && (
            <button type="button" className="button button--primary button--small" onClick={() => setCreating(true)}>
              Registrar operación
            </button>
          )}
        </div>
        <Toolbar>
          <FilterSelect
            label="Estado"
            value={status}
            options={Object.entries(STATUS_LABELS).map(([value, label]) => ({ value, label }))}
            onChange={(v) => setStatus(v as MaintenanceStatus | "")}
          />
        </Toolbar>
        {!list.data ? (
          list.error ? (
            <ErrorState message={errorMessage(list.error)} onRetry={list.refresh} />
          ) : (
            <LoadingState label="Cargando operaciones…" />
          )
        ) : list.data.items.length === 0 ? (
          <EmptyState title="Sin operaciones de mantenimiento" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Operación</th>
                  <th>Equipo</th>
                  <th>Ventana</th>
                  <th>Estado</th>
                  <th>Coincidencias</th>
                  {canManage && <th>Acciones</th>}
                </tr>
              </thead>
              <tbody>
                {list.data.items.map((op) => (
                  <tr key={op.id}>
                    <td>
                      <strong>{op.title}</strong>
                      <div className="small muted">
                        {KIND_LABELS[op.kind]} · v{op.version} · {op.artifacts.length} artefacto(s) · {op.created_by}
                      </div>
                    </td>
                    <td>
                      <Link to={`/assets/${op.asset_id}`}>{op.asset_name}</Link>
                    </td>
                    <td className="small">
                      {formatDateTime(op.window_start)} → {formatDateTime(op.window_end)}
                      <div className="muted">caduca {formatRelative(op.expires_at)}</div>
                    </td>
                    <td>
                      <span className={`badge ${STATUS_CLASS[op.status]}`}>{STATUS_LABELS[op.status]}</span>
                      {op.approved_by && <div className="small muted">por {op.approved_by}</div>}
                      {op.revoke_reason && <div className="small muted">{op.revoke_reason}</div>}
                    </td>
                    <td className="small">
                      {op.matches}
                      {op.last_match_at && <div className="muted">{formatRelative(op.last_match_at)}</div>}
                    </td>
                    {canManage && (
                      <td>
                        <div className="row-actions">
                          {op.status === "pending_review" && (
                            <button
                              type="button"
                              className="button button--small"
                              onClick={() => setDecision({ operation: op, mode: "approve" })}
                            >
                              Aprobar
                            </button>
                          )}
                          {op.status === "approved" && (
                            <button type="button" className="button button--small" onClick={() => setPreviewing(op)}>
                              Vista previa
                            </button>
                          )}
                          {(op.status === "pending_review" || op.status === "approved") && (
                            <button
                              type="button"
                              className="button button--small button--danger"
                              onClick={() => setDecision({ operation: op, mode: "revoke" })}
                            >
                              Revocar
                            </button>
                          )}
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {creating && <CreateDialog onClose={() => setCreating(false)} onDone={list.refresh} />}
      {decision && (
        <DecisionDialog
          operation={decision.operation}
          mode={decision.mode}
          onClose={() => setDecision(undefined)}
          onDone={list.refresh}
        />
      )}
      {previewing && <PreviewDialog operation={previewing} onClose={() => setPreviewing(undefined)} onDone={list.refresh} />}
    </div>
  );
}
