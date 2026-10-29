import { Link } from "react-router-dom";
import type { ToolExecutionOut } from "../../api/types";
import { formatDateTime } from "../../lib/format";

// Salida de una herramienta del motor 7A. Todo se pinta como texto (React escapa): la salida
// puede contener datos del host (rutas, nombres, líneas de comando) y nunca se interpreta.
const MAX_COLUMNS = 8;
const MAX_ROWS = 200;
const MAX_TEXT = 160;

const STATUS_LABELS: Record<string, string> = {
  previewed: "Vista previa pendiente",
  running: "En curso",
  succeeded: "Completada",
  failed: "Fallida",
  cancelled: "Cancelada",
  timed_out: "Tiempo agotado",
  rejected: "Rechazada",
  expired: "Caducada",
};

const STATUS_CLASS: Record<string, string> = {
  previewed: "badge--info",
  running: "badge--info",
  succeeded: "badge--ok",
  failed: "badge--crit",
  timed_out: "badge--warn",
  rejected: "badge--warn",
  expired: "badge--muted",
  cancelled: "badge--muted",
};

export function ExecutionStatus({ status }: { status: string }) {
  return <span className={`badge ${STATUS_CLASS[status] ?? "badge--muted"}`}>{STATUS_LABELS[status] ?? status}</span>;
}

function text(value: unknown): string {
  if (value === null || value === undefined) return "—";
  const raw = typeof value === "string" ? value : typeof value === "object" ? JSON.stringify(value) : String(value);
  return raw.length > MAX_TEXT ? `${raw.slice(0, MAX_TEXT)}…` : raw;
}

// Fase 7B-Fix1: un id de entidad en la salida enlaza a su ficha (solo si es un UUID; el texto
// sigue siendo texto). Nada se interpreta como HTML.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const ENTITY_ROUTES: Record<string, string> = {
  asset_id: "/assets/",
  detection_id: "/detections/",
  incident_id: "/incidents/",
  investigation_id: "/investigations/",
};

export function entityLink(key: string, value: unknown): string | null {
  const route = ENTITY_ROUTES[key];
  return route && typeof value === "string" && UUID.test(value) ? `${route}${value}` : null;
}

function Cell({ name, value }: { name: string; value: unknown }) {
  const href = entityLink(name, value);
  return href ? (
    <Link to={href} className="mono">
      {text(value)}
    </Link>
  ) : (
    <>{text(value)}</>
  );
}

function isRecordArray(value: unknown): value is Record<string, unknown>[] {
  return Array.isArray(value) && value.length > 0 && value.every((v) => v && typeof v === "object" && !Array.isArray(v));
}

function Rows({ rows, label }: { rows: Record<string, unknown>[]; label: string }) {
  const columns: string[] = [];
  for (const row of rows.slice(0, 10)) {
    for (const key of Object.keys(row)) {
      if (!columns.includes(key) && columns.length < MAX_COLUMNS) columns.push(key);
    }
  }
  return (
    <div className="table-wrap">
      <table className="table table--compact" aria-label={label}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c}>{c}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.slice(0, MAX_ROWS).map((row, i) => (
            <tr key={i}>
              {columns.map((c) => (
                <td key={c} className="small">
                  <Cell name={c} value={row[c]} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      {rows.length > MAX_ROWS && <p className="small muted">Se muestran {MAX_ROWS} de {rows.length} filas.</p>}
    </div>
  );
}

function Value({ name, value }: { name: string; value: unknown }) {
  if (isRecordArray(value)) return <Rows rows={value} label={name} />;
  if (Array.isArray(value)) return <span>{value.length ? value.map(text).join(", ") : "—"}</span>;
  return (
    <span className="small">
      <Cell name={name} value={value} />
    </span>
  );
}

function Preview({ preview }: { preview: Record<string, unknown> }) {
  const effects = Array.isArray(preview.effects) ? (preview.effects as unknown[]) : [];
  const blockers = Array.isArray(preview.blockers) ? (preview.blockers as Record<string, unknown>[]) : [];
  const warnings = Array.isArray(preview.warnings) ? (preview.warnings as Record<string, unknown>[]) : [];
  return (
    <div className="stack">
      {blockers.length > 0 && (
        <div className="banner banner--warn" role="alert">
          No se puede ejecutar:
          <ul>
            {blockers.map((b, i) => (
              <li key={i}>{text(b.message ?? b.code)}</li>
            ))}
          </ul>
        </div>
      )}
      {effects.length > 0 && (
        <div>
          <h4 className="small">Qué haría</h4>
          <ul className="small">
            {effects.map((e, i) => (
              <li key={i}>{text(e)}</li>
            ))}
          </ul>
        </div>
      )}
      {warnings.length > 0 && (
        <ul className="small muted">
          {warnings.map((w, i) => (
            <li key={i}>{text(w.message ?? w.code)}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Cuerpo de una ejecución: vista previa, error o salida estructurada. */
export function ToolOutput({ execution }: { execution: ToolExecutionOut }) {
  const output = execution.output;
  return (
    <div className="stack tool-output">
      {execution.summary && <p>{execution.summary}</p>}
      {execution.error_code && (
        <div className="banner banner--warn" role="alert">
          {execution.error_message ?? execution.error_code} <span className="mono small">({execution.error_code})</span>
        </div>
      )}
      {output && "preview" in output && output.preview && typeof output.preview === "object" ? (
        <Preview preview={output.preview as Record<string, unknown>} />
      ) : (
        output && (
          <dl className="tool-output__fields">
            {Object.entries(output).map(([key, value]) => (
              <div key={key} className="field">
                <dt className="small muted">{key}</dt>
                <dd>
                  <Value name={key} value={value} />
                </dd>
              </div>
            ))}
          </dl>
        )
      )}
      <p className="small muted">
        {formatDateTime(execution.created_at)}
        {execution.duration_ms !== null && ` · ${execution.duration_ms} ms`}
        {execution.truncated && " · salida recortada al máximo de filas"}
        {execution.output_sha256 && (
          <>
            {" · SHA-256 "}
            <span className="mono" title={execution.output_sha256}>
              {execution.output_sha256.slice(0, 12)}…
            </span>
          </>
        )}
      </p>
    </div>
  );
}
