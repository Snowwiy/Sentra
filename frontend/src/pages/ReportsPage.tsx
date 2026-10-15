import { useCallback, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { reportsApi } from "../api/sentra";
import type { Report, ReportCatalog, ReportPreview, ReportStatus, ReportTypeInfo } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { CopyButton } from "../components/CopyButton";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../components/ListControls";
import { DownloadReportButton, ReportStatusBadge } from "../components/reports/ReportViews";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatBytes, formatDateTime, formatRelative } from "../lib/format";
import {
  buildReportRequest,
  CLASSIFICATION_LABELS,
  dayToUtcIso,
  effectiveFormat,
  FILTER_LABELS,
  FORMAT_LABELS,
  formatScope,
  formatUtc,
  ID_FILTERS,
  initialFormState,
  isActiveReport,
  MULTI_FILTERS,
  multiFilterValues,
  newReportKey,
  parsePrefill,
  RANGE_PRESETS,
  REPORT_STATUS_LABELS,
  REPORT_STATUSES,
  type ReportFormState,
  SCOPE_LABELS,
  shortHash,
  VALUE_LABELS,
} from "../lib/reports";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 25;
// Mientras haya informes pendientes o generándose, el historial se refresca más a menudo.
const ACTIVE_POLL_MS = 3_000;

function toError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

function PreviewPanel({ preview }: { preview: ReportPreview }) {
  const scope = Object.entries(preview.scope ?? {}).filter(([, v]) => typeof v !== "object" || v === null);
  return (
    <section className="panel panel--padded stack" aria-label="Vista previa">
      <h2 className="panel__title">Vista previa: {preview.name}</h2>
      <dl className="fields fields--inline">
        <div className="field">
          <dt>Formato</dt>
          <dd>{FORMAT_LABELS[preview.format] ?? preview.format}</dd>
        </div>
        <div className="field">
          <dt>Clasificación</dt>
          <dd>{CLASSIFICATION_LABELS[preview.classification] ?? preview.classification}</dd>
        </div>
        <div className="field">
          <dt>Rango ({preview.timezone || "UTC"})</dt>
          <dd>
            {preview.time_from || preview.time_to
              ? `${formatUtc(preview.time_from)} → ${formatUtc(preview.time_to)}`
              : "No aplica"}
          </dd>
        </div>
        <div className="field">
          <dt>Plantilla</dt>
          <dd>v{preview.template_version}</dd>
        </div>
      </dl>
      <div>
        <h3>Secciones</h3>
        {preview.sections.length ? (
          <ol>
            {preview.sections.map((s) => (
              <li key={s}>{s}</li>
            ))}
          </ol>
        ) : (
          <p className="muted small">Sin secciones.</p>
        )}
      </div>
      <div>
        <h3>Alcance aproximado</h3>
        {scope.length ? (
          <ul className="plain-list">
            {scope.map(([key, value]) => (
              <li key={key}>
                {SCOPE_LABELS[key] ?? key}: <span className="strong">{String(value)}</span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="muted small">Sin datos en el alcance.</p>
        )}
      </div>
      {preview.warnings.length > 0 && (
        <div className="banner banner--warn" role="note">
          <ul className="plain-list">
            {preview.warnings.map((w) => (
              <li key={`${w.code}-${w.message}`}>{w.message}</li>
            ))}
          </ul>
        </div>
      )}
      {!preview.can_generate && (
        <p className="muted small">Tu rol no permite generar este informe con estos filtros.</p>
      )}
    </section>
  );
}

function FilterFields({
  type,
  form,
  update,
}: {
  type: ReportTypeInfo;
  form: ReportFormState;
  update: (patch: Partial<ReportFormState>) => void;
}) {
  const allowed = new Set(type.filters);
  const required = new Set(type.required_filters);
  return (
    <>
      {ID_FILTERS.filter((key) => allowed.has(key)).map((key) => (
        <label key={key} className="form-field">
          <span className="muted small">
            {FILTER_LABELS[key]} (IDs){required.has(key) ? " · obligatorio" : ""}
          </span>
          <input
            className="input mono"
            type="text"
            aria-label={FILTER_LABELS[key]}
            value={form.ids[key] ?? ""}
            placeholder="IDs separados por comas"
            onChange={(e) => update({ ids: { ...form.ids, [key]: e.target.value } })}
          />
        </label>
      ))}
      {MULTI_FILTERS.filter((key) => allowed.has(key)).map((key) => {
        const values = multiFilterValues(type, key);
        if (!values.length) return null;
        const selected = new Set(form.multi[key] ?? []);
        return (
          <fieldset key={key} className="form-field">
            <legend className="muted small">
              {FILTER_LABELS[key]}
              {required.has(key) ? " · obligatorio" : " (vacío = todos)"}
            </legend>
            <div className="actions">
              {values.map((value) => (
                <label key={value} className="small">
                  <input
                    type="checkbox"
                    checked={selected.has(value)}
                    onChange={(e) => {
                      const next = new Set(selected);
                      if (e.target.checked) next.add(value);
                      else next.delete(value);
                      update({ multi: { ...form.multi, [key]: values.filter((v) => next.has(v)) } });
                    }}
                  />{" "}
                  {VALUE_LABELS[value] ?? value}
                </label>
              ))}
            </div>
          </fieldset>
        );
      })}
      {allowed.has("include_archived") && (
        <label className="small">
          <input
            type="checkbox"
            checked={form.includeArchived}
            onChange={(e) => update({ includeArchived: e.target.checked })}
          />{" "}
          {FILTER_LABELS.include_archived}
        </label>
      )}
    </>
  );
}

/** Formulario de generación: tipo del catálogo, rango UTC, filtros del tipo, formato y clasificación. */
function GenerateForm({ catalog, onCreated }: { catalog: ReportCatalog; onCreated: (report: Report) => void }) {
  const [params] = useSearchParams();
  const [prefill] = useState(() => parsePrefill(params));
  const [form, setForm] = useState<ReportFormState>(() => initialFormState(prefill));
  const [preview, setPreview] = useState<{ sig: string; data: ReportPreview }>();
  const [busy, setBusy] = useState<"preview" | "generate">();
  const [error, setError] = useState<string>();
  const [created, setCreated] = useState<Report>();
  // Clave de idempotencia de esta solicitud: se reutiliza en reintentos de la misma petición y
  // se renueva si cambia el formulario (otra petición) o tras crear el informe.
  const keyRef = useRef<{ sig: string; key: string } | undefined>(undefined);
  const busyRef = useRef(false);

  const items = catalog.items;
  const type = items.find((t) => t.id === form.reportType) ?? items[0];
  const unknownPrefill = prefill.type !== undefined && !items.some((t) => t.id === prefill.type);
  if (!type) return <EmptyState title="Sin tipos de informe disponibles" />;

  const { request, problems } = buildReportRequest(type, form);
  const sig = request ? JSON.stringify(request) : "";
  const shownPreview = preview && preview.sig === sig ? preview.data : undefined;
  const update = (patch: Partial<ReportFormState>) => {
    setForm((current) => ({ ...current, ...patch }));
    setError(undefined);
  };
  const disabled = !catalog.enabled || !request || busy !== undefined;

  const runPreview = async () => {
    if (!request || busyRef.current) return;
    busyRef.current = true;
    setBusy("preview");
    setError(undefined);
    try {
      const data = await reportsApi.preview(request);
      setPreview({ sig, data });
    } catch (err) {
      setError(errorMessage(toError(err)));
    } finally {
      busyRef.current = false;
      setBusy(undefined);
    }
  };

  const generate = async () => {
    if (!request || busyRef.current) return;
    busyRef.current = true;
    if (keyRef.current?.sig !== sig) keyRef.current = { sig, key: newReportKey() };
    const key = keyRef.current.key;
    setBusy("generate");
    setError(undefined);
    try {
      const report = await reportsApi.create({ ...request, idempotency_key: key });
      keyRef.current = undefined;
      setCreated(report);
      onCreated(report);
    } catch (err) {
      setError(errorMessage(toError(err)));
      // Clave usada con otra petición: la siguiente vez se genera una nueva.
      if (err instanceof ApiError && err.code === "report_conflict") keyRef.current = undefined;
    } finally {
      busyRef.current = false;
      setBusy(undefined);
    }
  };

  const format = effectiveFormat(type, form.format);
  return (
    <section className="panel panel--padded stack" aria-label="Generar informe">
      <h2 className="panel__title">Generar informe</h2>
      {!catalog.enabled && (
        <div className="banner banner--warn" role="alert">
          La generación de informes está desactivada en este servidor.
        </div>
      )}
      {unknownPrefill && (
        <div className="banner banner--warn" role="note">
          El tipo de informe indicado en el enlace no está disponible; se muestra el primero del catálogo.
        </div>
      )}
      <div className="detail-grid">
        <label className="form-field">
          <span className="muted small">Tipo de informe</span>
          <select
            className="input input--select"
            aria-label="Tipo de informe"
            value={type.id}
            onChange={(e) => update({ reportType: e.target.value })}
          >
            {items.map((t) => (
              <option key={t.id} value={t.id}>
                {t.name}
                {t.can_generate ? "" : " (sin permiso para generar)"}
              </option>
            ))}
          </select>
          {type.description && <span className="muted small">{type.description}</span>}
        </label>
        <label className="form-field">
          <span className="muted small">Formato</span>
          <select
            className="input input--select"
            aria-label="Formato"
            value={format}
            onChange={(e) => update({ format: e.target.value })}
          >
            {type.supported_formats.map((f) => (
              <option key={f} value={f}>
                {FORMAT_LABELS[f] ?? f}
              </option>
            ))}
          </select>
        </label>
        <label className="form-field">
          <span className="muted small">Clasificación</span>
          <select
            className="input input--select"
            aria-label="Clasificación"
            value={form.classification}
            onChange={(e) => update({ classification: e.target.value })}
          >
            {(catalog.classifications.length ? catalog.classifications : ["internal"]).map((c) => (
              <option key={c} value={c}>
                {CLASSIFICATION_LABELS[c] ?? c}
              </option>
            ))}
          </select>
        </label>
        {type.uses_range ? (
          <label className="form-field">
            <span className="muted small">Rango (UTC)</span>
            <select
              className="input input--select"
              aria-label="Rango"
              value={form.preset}
              onChange={(e) => update({ preset: e.target.value as ReportFormState["preset"] })}
            >
              {RANGE_PRESETS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
        ) : (
          <p className="muted small">Este tipo de informe no usa rango de fechas.</p>
        )}
      </div>
      {type.uses_range && form.preset === "custom" && (
        <div className="actions">
          <label className="form-field">
            <span className="muted small">Desde (UTC)</span>
            <input
              className="input"
              type="datetime-local"
              aria-label="Desde (UTC)"
              value={form.customFrom}
              onChange={(e) => update({ customFrom: e.target.value })}
            />
          </label>
          <label className="form-field">
            <span className="muted small">Hasta (UTC)</span>
            <input
              className="input"
              type="datetime-local"
              aria-label="Hasta (UTC)"
              value={form.customTo}
              onChange={(e) => update({ customTo: e.target.value })}
            />
          </label>
        </div>
      )}
      <FilterFields type={type} form={form} update={update} />
      {problems.length > 0 && (
        <ul className="plain-list muted small">
          {problems.map((p) => (
            <li key={p}>{p}</li>
          ))}
        </ul>
      )}
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      <div className="actions">
        <button type="button" className="button" disabled={disabled} onClick={() => void runPreview()}>
          {busy === "preview" ? "Calculando…" : "Vista previa"}
        </button>
        {type.can_generate && (
          <button type="button" className="button button--primary" disabled={disabled} onClick={() => void generate()}>
            {busy === "generate" ? "Solicitando…" : "Generar"}
          </button>
        )}
      </div>
      {created && (
        <div className="banner banner--ok" role="status">
          {created.deduplicated ? "Ya existía una solicitud idéntica: " : "Informe solicitado: "}
          <Link to={`/reports/${created.id}`}>{created.title || created.name}</Link> (
          {REPORT_STATUS_LABELS[created.status] ?? created.status}).
        </div>
      )}
      {shownPreview && <PreviewPanel preview={shownPreview} />}
    </section>
  );
}

/** Historial paginado en el servidor con filtros de tipo, estado, usuario y fechas. */
function ReportHistory({ catalog, reloadToken }: { catalog: ReportCatalog | undefined; reloadToken: number }) {
  const [reportType, setReportType] = useState("");
  const [status, setStatus] = useState("");
  const [user, setUser] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const requestedBy = useDebounced(user.trim());
  const [hasActive, setHasActive] = useState(false);

  const fetcher = useCallback(
    async (signal: AbortSignal) => {
      // reloadToken fuerza una recarga tras crear un informe.
      void reloadToken;
      const data = await reportsApi.list(
        {
          reportType: reportType || undefined,
          status: (status || undefined) as ReportStatus | undefined,
          requestedBy: requestedBy || undefined,
          createdFrom: dayToUtcIso(from),
          createdTo: dayToUtcIso(to, true),
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      );
      setHasActive(data.items.some((r) => isActiveReport(r.status)));
      return data;
    },
    [reportType, status, requestedBy, from, to, page, reloadToken],
  );
  const { data, error, loading, refresh } = usePolling(
    fetcher,
    hasActive ? ACTIVE_POLL_MS : config.refreshIntervalMs,
    true,
    true,
  );
  const names = new Map((catalog?.items ?? []).map((t) => [t.id, t.name]));
  const resetPage = <T,>(set: (v: T) => void) => (v: T) => {
    set(v);
    setPage(1);
  };

  return (
    <section className="panel stack" aria-label="Historial de informes">
      <h2 className="panel__title">Historial</h2>
      <Toolbar>
        <FilterSelect
          label="Tipo"
          value={reportType}
          options={(catalog?.items ?? []).map((t) => ({ value: t.id, label: t.name }))}
          onChange={resetPage(setReportType)}
        />
        <FilterSelect
          label="Estado"
          value={status}
          options={REPORT_STATUSES.map((s) => ({ value: s, label: REPORT_STATUS_LABELS[s] }))}
          onChange={resetPage(setStatus)}
        />
        <SearchInput value={user} onChange={resetPage(setUser)} placeholder="Solicitado por" label="Solicitado por" />
        <label className="form-field form-field--inline">
          <span className="muted small">Desde</span>
          <input
            className="input"
            type="date"
            aria-label="Creado desde"
            value={from}
            onChange={(e) => resetPage(setFrom)(e.target.value)}
          />
        </label>
        <label className="form-field form-field--inline">
          <span className="muted small">Hasta</span>
          <input
            className="input"
            type="date"
            aria-label="Creado hasta"
            value={to}
            onChange={(e) => resetPage(setTo)(e.target.value)}
          />
        </label>
      </Toolbar>
      {loading ? (
        <LoadingState label="Cargando informes…" />
      ) : !data ? (
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <EmptyState title="Sin informes">No hay informes con estos filtros.</EmptyState>
      ) : (
        <>
          {error && (
            <div className="banner banner--warn" role="alert">
              Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
            </div>
          )}
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Informe</th>
                  <th>Tipo</th>
                  <th>Formato</th>
                  <th>Alcance</th>
                  <th>Solicitado por</th>
                  <th>Creado</th>
                  <th>Estado</th>
                  <th>Tamaño</th>
                  <th>SHA-256</th>
                  <th>Descargar</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((r) => (
                  <tr key={r.id}>
                    <td>
                      <Link to={`/reports/${r.id}`}>{r.title || r.name}</Link>
                    </td>
                    <td>{names.get(r.report_type) ?? r.name ?? r.report_type}</td>
                    <td>{FORMAT_LABELS[r.format] ?? r.format}</td>
                    <td className="small">{formatScope(r.scope)}</td>
                    <td>{r.requested_by}</td>
                    <td title={formatDateTime(r.created_at)}>{formatRelative(r.created_at)}</td>
                    <td>
                      <ReportStatusBadge status={r.status} cancelRequested={r.cancel_requested} />
                    </td>
                    <td>{r.artifact ? formatBytes(r.artifact.size_bytes) : "—"}</td>
                    <td className="nowrap">
                      {r.artifact ? (
                        <>
                          <span className="mono small" title={r.artifact.sha256}>
                            {shortHash(r.artifact.sha256)}
                          </span>{" "}
                          <CopyButton text={r.artifact.sha256} />
                        </>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td>{r.status === "succeeded" && r.artifact ? <DownloadReportButton report={r} /> : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / PAGE_SIZE))}
            total={data.total}
            onPage={setPage}
            noun="informes"
          />
        </>
      )}
    </section>
  );
}

/** Informes y exportación de evidencias (Fase 5E). */
export function ReportsPage() {
  const auth = useAuth();
  const canGenerate = auth.can("reports:generate");
  const [params] = useSearchParams();
  const fetcher = useCallback((signal: AbortSignal) => reportsApi.catalog(signal), []);
  const catalog = usePolling(fetcher, config.refreshIntervalMs * 30);
  const [reloadToken, setReloadToken] = useState(0);

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Informes</h1>
          <p className="muted small">
            Informes y paquetes de evidencias generados en el servidor a partir de una instantánea de los datos. Todas
            las fechas se expresan en UTC; cada fichero lleva su SHA-256 para comprobar su integridad.
          </p>
        </div>
      </div>
      {canGenerate &&
        (catalog.loading ? (
          <LoadingState label="Cargando catálogo de informes…" />
        ) : !catalog.data ? (
          <ErrorState
            message={catalog.error ? errorMessage(catalog.error) : "Sin datos"}
            onRetry={catalog.refresh}
          />
        ) : (
          // La key reinicia el formulario si cambia el enlace de prefill (?type=…).
          <GenerateForm
            key={params.toString()}
            catalog={catalog.data}
            onCreated={() => setReloadToken((n) => n + 1)}
          />
        ))}
      <ReportHistory catalog={catalog.data} reloadToken={reloadToken} />
    </div>
  );
}
