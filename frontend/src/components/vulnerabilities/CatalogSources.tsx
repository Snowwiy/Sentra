import { useCallback, useState } from "react";
import type {
  CatalogStatus,
  OfficialVulnSource,
  VulnerabilitySource,
  VulnerabilitySourceList,
  VulnSourceImportResult,
  VulnSourcePreview,
  VulnSourceSyncRequested,
} from "../../api/types";
import { vulnSourcesApi, type SourceContent } from "../../api/vulnSources";
import { config } from "../../config";
import { errorMessage, formatBytes, formatDateTime, formatRelative } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import {
  ADAPTER_LABELS,
  FRESHNESS_CLASSES,
  FRESHNESS_LABELS,
  fileToSourceContent,
  isSyncDisabled,
  SKIPPED_REASON_LABELS,
  sourceErrorMessage,
  SYNC_KIND_LABELS,
  SYNC_STATUS_CLASSES,
  SYNC_STATUS_LABELS,
  TRIGGER_LABELS,
} from "../../lib/vulnSources";
import { Pager } from "../ListControls";
import { Modal } from "../Modal";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";

const OFFICIAL: OfficialVulnSource[] = ["nvd", "osv"];

function isOfficial(source: string): source is OfficialVulnSource {
  return (OFFICIAL as string[]).includes(source);
}

const STATE_LABELS: Record<CatalogStatus["state"], string> = {
  no_catalog: "Sin catálogo",
  stale: "Desactualizado",
  ready: "Al día",
};

const STATE_TONES: Record<CatalogStatus["state"], string> = {
  no_catalog: "stat--offline",
  stale: "stat--warn",
  ready: "stat--online",
};

/** Resumen del catálogo: estado global, registros y cobertura de la evaluación. */
export function CatalogStatusSummary({ status }: { status: CatalogStatus }) {
  const e = status.evaluation;
  return (
    <section className="stats stats--6" aria-label="Estado del catálogo">
      <div className={`stat ${STATE_TONES[status.state]}`}>
        <span className="stat__label">Catálogo</span>
        <span className="stat__value">{STATE_LABELS[status.state]}</span>
      </div>
      <div className="stat">
        <span className="stat__label">Registros</span>
        <span className="stat__value">{status.records}</span>
      </div>
      <div className="stat">
        <span className="stat__label">CVE distintos</span>
        <span className="stat__value">{status.cves}</span>
      </div>
      <div className="stat">
        <span className="stat__label">Activos evaluados</span>
        <span className="stat__value">{e.assets_evaluated}</span>
      </div>
      <div className="stat" title="Activos con algún componente que el catálogo describe">
        <span className="stat__label">Activos cubiertos</span>
        <span className="stat__value">{e.assets_covered}</span>
      </div>
      <div className={`stat${e.assets_pending > 0 ? " stat--warn" : ""}`}>
        <span className="stat__label">Pendientes de evaluar</span>
        <span className="stat__value">{e.assets_pending}</span>
      </div>
    </section>
  );
}

/** Avisos del estado global (sin catálogo, fuentes desactualizadas, KEV/EPSS ausentes). */
export function CatalogStatusBanners({ status }: { status: CatalogStatus }) {
  return (
    <>
      {status.state === "no_catalog" && (
        <div className="banner banner--warn" role="note">
          No hay catálogo de vulnerabilidades: Sentra no puede saber si el software inventariado es vulnerable. Un
          administrador debe importar un fichero de NVD, OSV o un catálogo local.
        </div>
      )}
      {status.state === "stale" && (
        <div className="banner banner--warn" role="note">
          Catálogo desactualizado: {status.stale_sources.join(", ") || "alguna fuente"} sin actualizar dentro del plazo.
          Sentra sigue evaluando con el último catálogo válido; las vulnerabilidades publicadas después no aparecen.
        </div>
      )}
      {status.state !== "no_catalog" && (!status.known_exploited_available || !status.epss_available) && (
        <p className="muted small">
          {!status.known_exploited_available && "Sin datos de explotación conocida (KEV). "}
          {!status.epss_available && "Sin datos de EPSS. "}
          Se configuran en Threat Intelligence.
        </p>
      )}
    </>
  );
}

/**
 * Aviso compacto del estado del catálogo para la lista de vulnerabilidades: sin catálogo,
 * desactualizado o con activos pendientes. Si la consulta falla no muestra nada (la lista
 * sigue siendo útil sin él).
 */
export function CatalogStatusNote() {
  const fetchStatus = useCallback((signal: AbortSignal) => vulnSourcesApi.status(signal), []);
  const { data } = usePolling(fetchStatus, config.refreshIntervalMs * 4);
  if (!data) return null;
  const e = data.evaluation;
  return (
    <>
      <CatalogStatusBanners status={data} />
      {data.state !== "no_catalog" && (
        <p className="muted small" aria-label="Cobertura del catálogo">
          Catálogo: {data.records} registros ({data.cves} CVE) de {data.sources}{" "}
          {data.sources === 1 ? "fuente" : "fuentes"}
          {data.last_success_at && `, actualizado ${formatRelative(data.last_success_at)}`} · {e.assets_evaluated}{" "}
          activos evaluados, {e.assets_covered} cubiertos por el catálogo
          {e.assets_pending > 0 && `, ${e.assets_pending} pendientes de evaluar`}
        </p>
      )}
    </>
  );
}

function SyncHistoryModal({ source, onClose }: { source: VulnerabilitySource; onClose: () => void }) {
  const PAGE = 20;
  const [page, setPage] = useState(1);
  const fetchSyncs = useCallback(
    (signal: AbortSignal) => vulnSourcesApi.syncs(source.source, { limit: PAGE, offset: (page - 1) * PAGE }, signal),
    [source.source, page],
  );
  const { data, error, loading, refresh } = usePolling(fetchSyncs, config.refreshIntervalMs * 2, true, true);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE));
  return (
    <Modal title={`Historial de ${source.name}`} onClose={onClose} wide>
      {loading ? (
        <LoadingState label="Cargando historial…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin importaciones ni sincronizaciones" />
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Inicio</th>
                  <th>Tipo</th>
                  <th>Resultado</th>
                  <th>Registros</th>
                  <th className="col-secondary">Activos en cola</th>
                  <th className="col-secondary">Por</th>
                  <th className="col-secondary">Huella</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((s) => (
                  <tr key={s.id}>
                    <td title={formatDateTime(s.started_at)}>
                      {formatRelative(s.started_at)}
                      {s.duration_ms != null && <div className="muted small">{(s.duration_ms / 1000).toFixed(1)} s</div>}
                    </td>
                    <td>
                      {SYNC_KIND_LABELS[s.kind] ?? s.kind}
                      <div className="muted small">{TRIGGER_LABELS[s.trigger] ?? s.trigger}</div>
                    </td>
                    <td>
                      <span className={`badge ${SYNC_STATUS_CLASSES[s.status] ?? ""}`}>
                        {SYNC_STATUS_LABELS[s.status] ?? s.status}
                      </span>
                      {s.error_code && (
                        <div className="muted small">
                          <span className="mono">{s.error_code}</span>
                          {s.error_message && `: ${s.error_message}`}
                        </div>
                      )}
                    </td>
                    <td className="small">
                      {s.records_new} nuevos · {s.records_updated} actualizados · {s.records_unchanged} sin cambios
                      {s.records_retired > 0 && ` · ${s.records_retired} retirados`}
                      {s.records_invalid > 0 && ` · ${s.records_invalid} inválidos`}
                      {s.records_skipped > 0 && ` · ${s.records_skipped} descartados`}
                    </td>
                    <td className="col-secondary">{s.assets_queued}</td>
                    <td className="col-secondary">{s.actor}</td>
                    <td className="col-secondary mono small" title={s.content_sha256 ?? undefined}>
                      {s.content_sha256 ? s.content_sha256.slice(0, 12) : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="ejecuciones" />
        </>
      )}
    </Modal>
  );
}

function networkText(source: VulnerabilitySource, list: VulnerabilitySourceList): string {
  if (source.category === "threat_intel") return "Threat Intelligence";
  // NVD y OSV siempre tienen descarga posible; con la red apagada el servidor marca
  // network=false, pero lo honesto es decir «desactivada», no «solo fichero».
  if (isOfficial(source.source) && !list.sync_enabled) return "Desactivada";
  if (!source.network) return "No aplica (solo fichero)";
  return source.auto_sync ? "Automática" : "A petición";
}

/**
 * Tabla de fuentes: NVD, OSV, catálogos locales y KEV/EPSS de Threat Intelligence. Solo el
 * admin ve «Sincronizar»; el historial lo puede consultar cualquier lector.
 */
export function SourcesTable({
  list,
  canAdmin,
  onChanged,
}: {
  list: VulnerabilitySourceList;
  canAdmin: boolean;
  onChanged: () => void;
}) {
  const [history, setHistory] = useState<VulnerabilitySource>();
  const [syncing, setSyncing] = useState<string>();
  const [syncResult, setSyncResult] = useState<VulnSourceSyncRequested>();
  const [syncError, setSyncError] = useState<{ message: string; disabled: boolean }>();

  const sync = async (key: OfficialVulnSource) => {
    setSyncing(key);
    setSyncResult(undefined);
    setSyncError(undefined);
    try {
      setSyncResult(await vulnSourcesApi.sync(key));
      onChanged();
    } catch (err) {
      setSyncError({ message: sourceErrorMessage(err), disabled: isSyncDisabled(err) });
    } finally {
      setSyncing(undefined);
    }
  };

  return (
    <section className="panel">
      <div className="panel__toolbar">
        <h2>Fuentes</h2>
        <span className="muted small">
          Descarga por red {list.sync_enabled ? "activada" : "desactivada"} en el servidor · obsoleta tras{" "}
          {list.stale_after_hours} h sin actualizar
          {list.nvd_api_key_configured ? " · API key de NVD configurada" : ""}
        </span>
      </div>
      {!list.sync_enabled && (
        <div className="banner" role="note">
          La descarga por red está desactivada (VULN_SOURCE_SYNC_ENABLED=false, valor por defecto): Sentra no se
          conecta a NVD ni a OSV y sigue evaluando con el último catálogo importado. Los ficheros se importan desde
          esta página o con la CLI.
        </div>
      )}
      {syncError && (
        <div className={`banner${syncError.disabled ? "" : " banner--warn"}`} role="alert">
          {syncError.message}
        </div>
      )}
      {syncResult && (
        <div className="banner banner--ok" role="status">
          Sincronización de {ADAPTER_LABELS[syncResult.source] ?? syncResult.source} en cola: el job
          vulnerability-sources la ejecutará en los próximos minutos.
        </div>
      )}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Fuente</th>
              <th>Estado</th>
              <th>Registros</th>
              <th>Última actualización</th>
              <th className="col-secondary">Descarga por red</th>
              <th aria-label="Acciones" />
            </tr>
          </thead>
          <tbody>
            {list.items.map((s) => (
              <tr key={s.source}>
                <td>
                  {s.name} <span className="muted mono small">({s.source})</span>
                  <div className="muted small">
                    {ADAPTER_LABELS[s.adapter] ?? s.adapter}
                    {s.category === "threat_intel" && " · Threat Intelligence (no se copia)"}
                  </div>
                </td>
                <td>
                  <span className={`badge ${FRESHNESS_CLASSES[s.freshness]}`}>{FRESHNESS_LABELS[s.freshness]}</span>
                  {!s.enabled && <span className="badge"> Desactivada</span>}
                  <div className="muted small mono">{s.status}</div>
                  {s.last_error && (
                    <div className="muted small">
                      <span className="mono">{s.last_error}</span>
                      {s.last_error_message && `: ${s.last_error_message}`}
                    </div>
                  )}
                </td>
                <td>
                  {s.records}
                  {s.revision > 0 && <div className="muted small">revisión {s.revision}</div>}
                </td>
                <td title={formatDateTime(s.last_success_at)}>
                  {s.last_success_at ? formatRelative(s.last_success_at) : "Nunca"}
                  {s.sync_requested_at && <div className="muted small">sincronización solicitada</div>}
                  {s.next_sync_at && (
                    <div className="muted small" title={formatDateTime(s.next_sync_at)}>
                      próxima {formatDateTime(s.next_sync_at)}
                    </div>
                  )}
                </td>
                <td className="col-secondary">
                  {networkText(s, list)}
                  {s.endpoint_host && <div className="muted small mono">{s.endpoint_host}</div>}
                </td>
                <td>
                  <span className="actions">
                    {s.category === "catalog" && (
                      <button type="button" className="button button--small" onClick={() => setHistory(s)}>
                        Historial
                      </button>
                    )}
                    {canAdmin && isOfficial(s.source) && (
                      <button
                        type="button"
                        className="button button--small"
                        disabled={syncing !== undefined}
                        title={
                          list.sync_enabled
                            ? "Pide una sincronización; la ejecuta el job en segundo plano"
                            : "La descarga por red está desactivada en el servidor"
                        }
                        onClick={() => void sync(s.source as OfficialVulnSource)}
                      >
                        {syncing === s.source ? "Solicitando…" : "Sincronizar"}
                      </button>
                    )}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {history && <SyncHistoryModal source={history} onClose={() => setHistory(undefined)} />}
    </section>
  );
}

/** Procedencia de cada atributo por tipo de fuente (ATTRIBUTE_SOURCES del servidor). */
export function AttributeSourcesTable({ sources }: { sources: Record<string, Record<string, string>> }) {
  const adapters = Object.keys(sources);
  const attributes = Array.from(new Set(adapters.flatMap((a) => Object.keys(sources[a] ?? {}))));
  if (attributes.length === 0) return null;
  return (
    <details className="panel panel--padded">
      <summary>
        <strong>Qué aporta cada fuente</strong>
      </summary>
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Atributo</th>
              {adapters.map((a) => (
                <th key={a}>{ADAPTER_LABELS[a] ?? a}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {attributes.map((attr) => (
              <tr key={attr}>
                <td className="mono small">{attr}</td>
                {adapters.map((a) => (
                  <td key={a} className="small">
                    {sources[a]?.[attr] ?? "—"}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}

// Límite orientativo: el servidor manda (MAX_REQUEST_BYTES, 4 MiB por defecto). Lo que no
// quepa se importa con la CLI, que no tiene ese límite.
const MAX_FILE_BYTES = 64 * 1024 * 1024;

/**
 * Importación de un fichero de NVD u OSV en dos pasos: previsualizar (el servidor no guarda
 * nada) y confirmar con la huella SHA-256 previsualizada. El contenido solo vive en memoria.
 */
export function SourceImportPanel({ onImported }: { onImported: () => void }) {
  const [source, setSource] = useState<OfficialVulnSource>("nvd");
  const [content, setContent] = useState<SourceContent>();
  const [fileName, setFileName] = useState<string>();
  const [preview, setPreview] = useState<VulnSourcePreview>();
  const [skipInvalid, setSkipInvalid] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState<VulnSourceImportResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [inputKey, setInputKey] = useState(0);

  const reset = () => {
    setPreview(undefined);
    setContent(undefined);
    setFileName(undefined);
    setSkipInvalid(false);
    setConfirming(false);
    setError(undefined);
    setInputKey((n) => n + 1);
  };

  const choose = async (file: File | undefined) => {
    setPreview(undefined);
    setResult(undefined);
    setSkipInvalid(false);
    setError(undefined);
    setContent(undefined);
    setFileName(file?.name);
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      setError(`El fichero ocupa ${formatBytes(file.size)}: impórtalo con la CLI (vuln-source-import).`);
      return;
    }
    setBusy(true);
    try {
      const body = await fileToSourceContent(file);
      setContent(body);
      setPreview(await vulnSourcesApi.preview(source, body));
    } catch (err) {
      setError(sourceErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!content || !preview) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(await vulnSourcesApi.import(source, content, preview.sha256, skipInvalid));
      reset();
      onImported();
    } catch (err) {
      setConfirming(false);
      setError(sourceErrorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const skipped = preview ? Object.entries(preview.skipped_reasons).filter(([, n]) => n > 0) : [];

  return (
    <section className="panel panel--padded">
      <h2>Importar fichero de NVD u OSV</h2>
      <p className="muted small">
        Respuesta de la API 2.0 o fichero de datos de NVD (.json, .json.gz, .zip) y registros o all.zip de OSV. La
        consola no admite URLs: el fichero se previsualiza (no se guarda nada) y solo se importa al confirmar. Importa
        NVD antes que OSV (OSV Debian toma la severidad de NVD). Los ficheros grandes, con la CLI.
      </p>
      <div className="form-grid">
        <label className="form-field">
          <span className="muted small">Fuente</span>
          <select
            className="input input--select"
            value={source}
            disabled={busy || !!preview}
            aria-label="Fuente oficial"
            onChange={(event) => setSource(event.target.value as OfficialVulnSource)}
          >
            <option value="nvd">NVD (CVE API 2.0)</option>
            <option value="osv">OSV (distribuciones Linux)</option>
          </select>
        </label>
        <label className="form-field">
          <span className="muted small">Fichero (.json, .json.gz o .zip)</span>
          <input
            key={inputKey}
            type="file"
            accept=".json,.gz,.zip,application/json,application/gzip,application/zip"
            disabled={busy}
            aria-label="Fichero de la fuente oficial"
            onChange={(event) => void choose(event.target.files?.[0])}
          />
        </label>
      </div>
      {busy && <LoadingState label={confirming ? "Importando…" : "Validando…"} />}
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      {preview && (
        <div className="stack" aria-label="Previsualización">
          <dl className="fields">
            <div className="field">
              <dt>Fuente</dt>
              <dd>
                {ADAPTER_LABELS[preview.source] ?? preview.source} · formato <span className="mono">{preview.format}</span>
                {preview.existing_source ? " · actualiza la fuente existente" : " · primera importación"}
              </dd>
            </div>
            <div className="field">
              <dt>Fichero</dt>
              <dd>
                {fileName} · {formatBytes(preview.size_bytes)}
              </dd>
            </div>
            <div className="field">
              <dt>SHA-256</dt>
              <dd className="mono small">{preview.sha256}</dd>
            </div>
            <div className="field">
              <dt>Registros</dt>
              <dd>
                {preview.total} leídos: {preview.new} nuevos, {preview.updated} actualizados, {preview.unchanged} sin
                cambios, {preview.retired} retirados, {preview.invalid} inválidos, {preview.skipped} descartados
              </dd>
            </div>
            <div className="field">
              <dt>Activos a reevaluar</dt>
              <dd>{preview.assets_to_evaluate}</dd>
            </div>
            {preview.cursor && (
              <div className="field">
                <dt>Cursor inicial (NVD)</dt>
                <dd>{formatDateTime(preview.cursor)}</dd>
              </div>
            )}
          </dl>
          {skipped.length > 0 && (
            <>
              <h3>Descartados (no son errores)</h3>
              <ul className="small">
                {skipped.map(([reason, count]) => (
                  <li key={reason}>
                    {SKIPPED_REASON_LABELS[reason] ?? reason} <span className="muted mono">({reason})</span>: {count}
                  </li>
                ))}
              </ul>
            </>
          )}
          {preview.invalid_records.length > 0 && (
            <>
              <h3>Errores de validación</h3>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Id</th>
                      <th>Código</th>
                      <th>Motivo</th>
                    </tr>
                  </thead>
                  <tbody>
                    {preview.invalid_records.map((record) => (
                      <tr key={record.index}>
                        <td>{record.index}</td>
                        <td className="mono">{record.record_id ?? "—"}</td>
                        <td className="mono small">{record.code}</td>
                        <td className="small">{record.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {preview.invalid > 0 && (
            <label className="form-field form-field--inline">
              <input type="checkbox" checked={skipInvalid} onChange={(e) => setSkipInvalid(e.target.checked)} />
              <span className="small">Importar solo los {preview.valid} registros válidos e ignorar los inválidos</span>
            </label>
          )}
          <div className="modal__actions">
            <button type="button" className="button" disabled={busy} onClick={reset}>
              Descartar
            </button>
            <button
              type="button"
              className="button button--primary"
              disabled={busy || preview.valid === 0 || (preview.invalid > 0 && !skipInvalid)}
              onClick={() => setConfirming(true)}
            >
              Importar…
            </button>
          </div>
        </div>
      )}
      {preview && confirming && (
        <Modal title="Confirmar importación" onClose={() => !busy && setConfirming(false)}>
          <div className="stack">
            <p>
              Se aplicarán {preview.new} registros nuevos, {preview.updated} actualizados y {preview.retired} retirados
              de {ADAPTER_LABELS[preview.source] ?? preview.source} en una sola transacción, y {preview.assets_to_evaluate}{" "}
              activos se reevaluarán.
            </p>
            <p className="muted small">
              Huella: <span className="mono">{preview.sha256}</span>. Si el fichero cambió desde la previsualización, el
              servidor rechaza la importación.
            </p>
            <div className="modal__actions">
              <button type="button" className="button" disabled={busy} onClick={() => setConfirming(false)}>
                Cancelar
              </button>
              <button type="button" className="button button--primary" disabled={busy} onClick={() => void confirm()}>
                {busy ? "Importando…" : "Confirmar importación"}
              </button>
            </div>
          </div>
        </Modal>
      )}
      {result && (
        <div className="banner banner--ok" role="status">
          {ADAPTER_LABELS[result.source] ?? result.source} importado en la revisión {result.revision}: {result.new} nuevos,{" "}
          {result.updated} actualizados, {result.unchanged} sin cambios, {result.retired} retirados, {result.invalid}{" "}
          inválidos ignorados. {result.assets_queued} activos en cola para reevaluar.
        </div>
      )}
    </section>
  );
}
