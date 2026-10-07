import { useCallback, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { threatIntelApi } from "../api/sentra";
import type {
  IndicatorClassification,
  IntelConfidence,
  IntelTrust,
  ThreatImportPreview,
  ThreatImportResult,
  ThreatSource,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../components/ListControls";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { MatchesTable } from "../components/threatintel/MatchesTable";
import {
  ClassificationBadge,
  SourceStateBadge,
  TrustBadge,
} from "../components/threatintel/IntelBadges";
import { errorMessage, formatBytes, formatDateTime, formatRelative } from "../lib/format";
import {
  CHANGE_LABELS,
  CLASSIFICATION_LABELS,
  CLASSIFICATION_ORDER,
  CONFIDENCE_LABELS,
  detectFormat,
  errorLabel,
  INDICATOR_STATE_LABELS,
  INDICATOR_TYPE_LABELS,
  MATCHING_LABELS,
  SYNC_STATUS_LABELS,
  TRUST_LABELS,
} from "../lib/threatIntel";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";

const PAGE_SIZE = 50;
// Límite del contenido enviado por la API (los ficheros grandes van por CLI).
const MAX_BYTES = 16 * 1024 * 1024;

const TABS = [
  { key: "overview", label: "Resumen" },
  { key: "sources", label: "Fuentes" },
  { key: "indicators", label: "Indicadores" },
  { key: "matches", label: "Coincidencias" },
  { key: "import", label: "Importar" },
] as const;
type Tab = (typeof TABS)[number]["key"];

function asError(err: unknown): string {
  return err instanceof Error ? errorMessage(err) : String(err);
}

const POLICY_LABELS: Record<string, string> = {
  off: "Nunca crea detecciones (solo contexto)",
  high_confidence_malicious: "Detección solo con indicador malicioso y coincidencia de confianza alta",
  malicious: "Detección con cualquier indicador malicioso",
};

/** Resumen: contadores y cambios recientes. Sin fuentes: estado neutro, no un error. */
function OverviewTab() {
  const fetcher = useCallback((signal: AbortSignal) => threatIntelApi.overview(signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  if (loading) return <LoadingState label="Cargando resumen…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  return (
    <div className="stack">
      {data.status === "none_configured" && (
        <div className="banner" role="note">
          No intelligence source configured. Sentra funciona igual sin inteligencia externa: un administrador puede
          activar CISA KEV o FIRST EPSS, o importar indicadores locales (JSON o STIX).
        </div>
      )}
      {data.status === "degraded" && (
        <div className="banner banner--warn" role="note">
          Hay fuentes desactualizadas o con errores: se siguen usando los últimos datos guardados y se marcan como
          desactualizados.
        </div>
      )}
      <section className="stats stats--6" aria-label="Resumen de inteligencia">
        <Link className="stat stat--crit" to="/vulnerabilities?kev=1">
          <span className="stat__label">Vulnerabilidades con explotación conocida (KEV)</span>
          <span className="stat__value">{data.kev_findings}</span>
        </Link>
        <div className="stat">
          <span className="stat__label">Activos con KEV</span>
          <span className="stat__value">{data.kev_assets}</span>
        </div>
        <div className="stat stat--offline">
          <span className="stat__label">EPSS alta (≥ 50 %)</span>
          <span className="stat__value">{data.high_epss_findings}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Indicadores vigentes</span>
          <span className="stat__value">
            {data.indicators_active}
            <span className="muted small"> / {data.indicators_total}</span>
          </span>
        </div>
        <div className="stat stat--offline">
          <span className="stat__label">Coincidencias activas</span>
          <span className="stat__value">{data.active_matches}</span>
        </div>
        <div className="stat">
          <span className="stat__label">Activos con coincidencias</span>
          <span className="stat__value">{data.matched_assets}</span>
        </div>
      </section>
      <section className="panel panel--padded">
        <dl className="fields">
          <div className="field">
            <dt>Fuentes activas</dt>
            <dd>
              {data.sources_enabled} de {data.sources_total}
              {data.sources_stale > 0 && ` · ${data.sources_stale} desactualizadas`}
              {data.sources_failing > 0 && ` · ${data.sources_failing} con errores`}
            </dd>
          </div>
          <div className="field">
            <dt>Sincronización por red</dt>
            <dd>{data.sync_enabled ? "Activada" : "Desactivada (instalación offline)"}</dd>
          </div>
          <div className="field">
            <dt>Política de detección</dt>
            <dd>{POLICY_LABELS[data.detection_policy] ?? data.detection_policy}</dd>
          </div>
          <div className="field">
            <dt>Último dato recibido</dt>
            <dd>{data.last_success_at ? formatRelative(data.last_success_at) : "Nunca"}</dd>
          </div>
        </dl>
        <p className="muted small">
          La inteligencia es contexto externo: KEV indica explotación conocida reportada en algún sitio y EPSS una
          probabilidad estadística. Ninguna de las dos indica que un activo esté comprometido.
        </p>
      </section>
      <section className="panel">
        <h2 className="panel__title">Cambios recientes</h2>
        {data.recent_changes.length === 0 ? (
          <EmptyState title="Sin cambios registrados" />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Fuente</th>
                  <th>Cambio</th>
                  <th>Dato</th>
                </tr>
              </thead>
              <tbody>
                {data.recent_changes.map((c, i) => (
                  <tr key={`${c.occurred_at}-${i}`}>
                    <td title={formatDateTime(c.occurred_at)}>{formatRelative(c.occurred_at)}</td>
                    <td>{c.source_name}</td>
                    <td>{CHANGE_LABELS[c.change] ?? c.change}</td>
                    <td className="mono">
                      {c.cve_id ? (
                        <Link to={`/vulnerabilities?q=${encodeURIComponent(c.cve_id)}`}>{c.cve_id}</Link>
                      ) : c.indicator_id ? (
                        <Link to={`/threat-intel/indicators/${c.indicator_id}`}>{c.indicator_value}</Link>
                      ) : (
                        "—"
                      )}
                    </td>
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

function SourceRow({ source, canManage, onChanged }: { source: ThreatSource; canManage: boolean; onChanged: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [showSyncs, setShowSyncs] = useState(false);
  const fetchSyncs = useCallback((signal: AbortSignal) => threatIntelApi.syncs(source.id, signal), [source.id]);
  const syncs = usePolling(fetchSyncs, config.refreshIntervalMs, showSyncs);

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      onChanged();
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <tr>
        <td>
          <div className="strong">{source.name}</div>
          <div className="muted small mono">{source.source_key}</div>
          {source.description && <div className="muted small">{source.description}</div>}
        </td>
        <td>
          {source.provider_title}
          {source.download_host && <div className="muted small mono">{source.download_host}</div>}
        </td>
        <td>
          <TrustBadge trust={source.trust} />
        </td>
        <td>
          <SourceStateBadge state={source.state} />
          {source.last_error && (
            <div className="muted small" title={source.last_error_message ?? undefined}>
              {errorLabel(source.last_error)}
            </div>
          )}
        </td>
        <td>{source.record_count}</td>
        <td title={formatDateTime(source.last_success_at)}>
          {source.last_success_at ? formatRelative(source.last_success_at) : "Nunca"}
          {source.sync_requested_at && <div className="muted small">Sincronización pedida</div>}
        </td>
        <td>
          <div className="actions">
            <button type="button" className="button button--small" onClick={() => setShowSyncs((v) => !v)}>
              {showSyncs ? "Ocultar historial" : "Historial"}
            </button>
            {canManage && !source.archived && (
              <>
                <button
                  type="button"
                  className="button button--small"
                  disabled={busy}
                  onClick={() =>
                    void run(() =>
                      threatIntelApi.sourceAction(source.id, source.enabled ? "disable" : "enable", source.revision),
                    )
                  }
                >
                  {source.enabled ? "Desactivar" : "Activar"}
                </button>
                {source.enabled && source.network_required && (
                  <button
                    type="button"
                    className="button button--small"
                    disabled={busy}
                    onClick={() => void run(() => threatIntelApi.requestSync(source.id))}
                  >
                    Sincronizar ahora
                  </button>
                )}
                {source.provider === "local_import" && source.source_key !== "local-iocs" && (
                  <button
                    type="button"
                    className="button button--small"
                    disabled={busy}
                    onClick={() => void run(() => threatIntelApi.sourceAction(source.id, "archive", source.revision))}
                  >
                    Archivar
                  </button>
                )}
              </>
            )}
          </div>
          {error && (
            <div className="banner banner--warn small" role="alert">
              {error}
            </div>
          )}
        </td>
      </tr>
      {showSyncs && (
        <tr className="table__row--detail">
          <td colSpan={7}>
            {!syncs.data ? (
              <LoadingState label="Cargando historial…" />
            ) : syncs.data.items.length === 0 ? (
              <span className="muted small">Sin sincronizaciones ni importaciones todavía.</span>
            ) : (
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Inicio</th>
                    <th>Tipo</th>
                    <th>Resultado</th>
                    <th>Registros</th>
                    <th>Duración</th>
                  </tr>
                </thead>
                <tbody>
                  {syncs.data.items.map((s) => (
                    <tr key={s.id}>
                      <td>{formatDateTime(s.started_at)}</td>
                      <td>
                        {s.kind} · {s.trigger} · {s.actor}
                      </td>
                      <td>
                        {SYNC_STATUS_LABELS[s.status] ?? s.status}
                        {s.error_code && <div className="muted small">{errorLabel(s.error_code)}</div>}
                      </td>
                      <td>
                        {s.records_new} nuevos, {s.records_updated} actualizados, {s.records_removed} retirados,{" "}
                        {s.records_invalid} inválidos
                      </td>
                      <td>{s.duration_ms != null ? `${(s.duration_ms / 1000).toFixed(1)} s` : "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

function NewSourceForm({ onCreated }: { onCreated: () => void }) {
  const [key, setKey] = useState("");
  const [name, setName] = useState("");
  const [trust, setTrust] = useState<IntelTrust>("local");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const submit = async () => {
    setBusy(true);
    setError(undefined);
    try {
      await threatIntelApi.createSource({ source_key: key.trim(), name: name.trim(), trust });
      setKey("");
      setName("");
      onCreated();
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className="panel panel--padded">
      <h2>Nueva fuente local de indicadores</h2>
      <p className="muted small">
        Para separar la procedencia de cada lista importada (equipo propio, CERT sectorial...). Las fuentes por red
        (espejos de KEV/EPSS) se configuran en el servidor con THREAT_INTEL_SOURCE_URLS: la web nunca envía URLs.
      </p>
      <div className="panel__toolbar">
        <input
          className="input"
          aria-label="Clave de la fuente"
          placeholder="clave (p. ej. cert-sector)"
          value={key}
          onChange={(e) => setKey(e.target.value)}
        />
        <input
          className="input"
          aria-label="Nombre de la fuente"
          placeholder="Nombre"
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        <FilterSelect
          label="Confianza"
          value={trust}
          options={(["trusted", "community", "local"] as const).map((value) => ({ value, label: TRUST_LABELS[value] }))}
          onChange={(value) => setTrust((value || "local") as IntelTrust)}
          allLabel="Local"
        />
        <button type="button" className="button" disabled={busy || key.trim().length < 2 || name.trim().length < 2} onClick={() => void submit()}>
          Crear
        </button>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
    </section>
  );
}

function SourcesTab({ canManage }: { canManage: boolean }) {
  const fetcher = useCallback((signal: AbortSignal) => threatIntelApi.sources(false, signal), []);
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs);
  if (loading) return <LoadingState label="Cargando fuentes…" />;
  if (!data) return <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />;
  return (
    <div className="stack">
      {!data.sync_enabled && (
        <div className="banner" role="note">
          Sincronización por red desactivada en el servidor (THREAT_INTEL_SYNC_ENABLED=false). KEV y EPSS pueden
          importarse sin red con <span className="mono">python -m app.cli threat-intel-import</span>.
        </div>
      )}
      <section className="panel">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Fuente</th>
                <th>Proveedor</th>
                <th>Confianza</th>
                <th>Estado</th>
                <th>Registros</th>
                <th>Último dato</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {data.items.map((source) => (
                <SourceRow key={source.id} source={source} canManage={canManage} onChanged={refresh} />
              ))}
            </tbody>
          </table>
        </div>
      </section>
      {canManage && <NewSourceForm onCreated={refresh} />}
    </div>
  );
}

function IndicatorsTab() {
  const navigate = useNavigate();
  const [filters, setFilters] = useState({ type: "", classification: "", confidence: "", state: "", matched: "" });
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const q = useDebounced(query);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      threatIntelApi.indicators(
        {
          type: filters.type || undefined,
          classification: (filters.classification || undefined) as IndicatorClassification | undefined,
          confidence: (filters.confidence || undefined) as IntelConfidence | undefined,
          state: filters.state || undefined,
          matched: filters.matched === "" ? undefined : filters.matched === "true",
          q,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [filters, q, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, config.refreshIntervalMs, true, true);
  const pages = Math.max(1, Math.ceil((data?.total ?? 0) / PAGE_SIZE));
  const set = (key: keyof typeof filters) => (value: string) => {
    setFilters((current) => ({ ...current, [key]: value }));
    setPage(1);
  };
  return (
    <section className="panel">
      <Toolbar>
        <FilterSelect
          label="Tipo"
          value={filters.type}
          options={Object.entries(INDICATOR_TYPE_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={set("type")}
        />
        <FilterSelect
          label="Clasificación"
          value={filters.classification}
          options={CLASSIFICATION_ORDER.map((value) => ({ value, label: CLASSIFICATION_LABELS[value] }))}
          onChange={set("classification")}
          allLabel="Todas"
        />
        <FilterSelect
          label="Confianza"
          value={filters.confidence}
          options={(["high", "medium", "low"] as const).map((value) => ({ value, label: CONFIDENCE_LABELS[value] }))}
          onChange={set("confidence")}
          allLabel="Todas"
        />
        <FilterSelect
          label="Vigencia"
          value={filters.state}
          options={Object.entries(INDICATOR_STATE_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={set("state")}
          allLabel="Todas"
        />
        <FilterSelect
          label="Con coincidencias"
          value={filters.matched}
          options={[
            { value: "true", label: "Sí" },
            { value: "false", label: "No" },
          ]}
          onChange={set("matched")}
        />
        <SearchInput
          value={query}
          onChange={(value) => {
            setQuery(value);
            setPage(1);
          }}
          placeholder="Valor (prefijo): 203.0.113. o evil."
          label="Buscar indicadores"
        />
      </Toolbar>
      {loading ? (
        <LoadingState label="Cargando indicadores…" />
      ) : !data && error ? (
        <ErrorState message={errorMessage(error)} onRetry={refresh} />
      ) : !data || data.items.length === 0 ? (
        <EmptyState title="Sin indicadores para este filtro">
          Los indicadores se importan desde un fichero JSON (sentra-ioc/1) o un bundle STIX 2.x.
        </EmptyState>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Indicador</th>
                  <th>Tipo</th>
                  <th>Clasificación</th>
                  <th>Confianza</th>
                  <th>Vigencia</th>
                  <th>Fuente</th>
                  <th>Coincidencias</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((i) => (
                  <tr
                    key={i.indicator_id}
                    className="table__row--link"
                    onClick={() => navigate(`/threat-intel/indicators/${i.indicator_id}`)}
                  >
                    <td className="mono">
                      <Link to={`/threat-intel/indicators/${i.indicator_id}`} onClick={(e) => e.stopPropagation()}>
                        {i.value}
                      </Link>
                      {i.tags.length > 0 && <div className="muted small">{i.tags.join(", ")}</div>}
                    </td>
                    <td>
                      {INDICATOR_TYPE_LABELS[i.indicator_type] ?? i.indicator_type}
                      {i.matching !== "supported" && (
                        <div className="muted small" title={MATCHING_LABELS[i.matching]}>
                          {i.matching === "unsupported" ? "No se busca" : "Visibilidad parcial"}
                        </div>
                      )}
                    </td>
                    <td>
                      <ClassificationBadge value={i.classification} />
                    </td>
                    <td>{CONFIDENCE_LABELS[i.confidence]}</td>
                    <td>{INDICATOR_STATE_LABELS[i.state] ?? i.state}</td>
                    <td>
                      {i.source.name} <TrustBadge trust={i.source.trust} />
                    </td>
                    <td>
                      {i.match_count}
                      {i.last_matched_at && <div className="muted small">{formatRelative(i.last_matched_at)}</div>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={Math.min(page, pages)} pages={pages} total={data.total} onPage={setPage} noun="indicadores" />
        </>
      )}
    </section>
  );
}

/** Importación en dos pasos: previsualizar (no escribe nada) y confirmar con la misma huella. */
function ImportTab() {
  const sourcesFetcher = useCallback((signal: AbortSignal) => threatIntelApi.sources(false, signal), []);
  const sources = usePolling(sourcesFetcher, config.refreshIntervalMs);
  const targets = (sources.data?.items ?? []).filter((s) => s.provider === "local_import" && s.enabled);
  const [sourceId, setSourceId] = useState<number>();
  const [content, setContent] = useState<string>();
  const [fileName, setFileName] = useState<string>();
  const [format, setFormat] = useState<"sentra-ioc" | "stix">("sentra-ioc");
  const [preview, setPreview] = useState<ThreatImportPreview>();
  const [skipInvalid, setSkipInvalid] = useState(false);
  const [result, setResult] = useState<ThreatImportResult>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const target = sourceId ?? targets[0]?.id;

  const choose = async (file: File | undefined) => {
    setPreview(undefined);
    setResult(undefined);
    setError(undefined);
    setContent(undefined);
    setFileName(file?.name);
    if (!file || target == null) return;
    if (file.size > MAX_BYTES) {
      setError(
        `El fichero ocupa ${formatBytes(file.size)}; por la web el máximo es ${formatBytes(MAX_BYTES)}. Usa la CLI.`,
      );
      return;
    }
    setBusy(true);
    try {
      const text = await file.text();
      const detected = detectFormat(text);
      setFormat(detected);
      setContent(text);
      setPreview(await threatIntelApi.importPreview(target, detected, text));
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  const confirm = async () => {
    if (!content || !preview || target == null) return;
    setBusy(true);
    setError(undefined);
    try {
      setResult(await threatIntelApi.importConfirm(target, format, content, preview.sha256, skipInvalid));
      setPreview(undefined);
      setContent(undefined);
    } catch (err) {
      setError(asError(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel panel--padded">
      <h2>Importar indicadores</h2>
      <p className="muted small">
        JSON de Sentra (sentra-ioc/1) o bundle STIX 2.x (subset seguro: igualdades simples). El fichero se valida
        entero, se previsualiza y solo se importa al confirmar. Una importación nunca borra indicadores de la fuente:
        para retirar uno, reimpórtalo con revoked o con valid_until en el pasado.
      </p>
      {targets.length === 0 ? (
        <EmptyState title="Ninguna fuente local activa">Activa o crea una fuente local en la pestaña Fuentes.</EmptyState>
      ) : (
        <>
          <div className="panel__toolbar">
            <FilterSelect
              label="Fuente"
              value={String(target ?? "")}
              options={targets.map((s) => ({ value: String(s.id), label: s.name }))}
              onChange={(value) => setSourceId(value ? Number(value) : undefined)}
              allLabel="Elegir"
            />
            <input
              type="file"
              accept=".json,application/json"
              disabled={busy}
              aria-label="Fichero de indicadores"
              onChange={(event) => void choose(event.target.files?.[0])}
            />
          </div>
          {busy && <LoadingState label={preview ? "Importando…" : "Validando…"} />}
          {error && (
            <div className="banner banner--warn" role="alert">
              {error}
            </div>
          )}
          {preview && (
            <div className="stack">
              <dl className="fields">
                <div className="field">
                  <dt>Fichero</dt>
                  <dd>
                    {fileName} · {formatBytes(preview.size_bytes)} · {preview.format === "stix" ? "STIX 2.x" : "sentra-ioc/1"}
                  </dd>
                </div>
                <div className="field">
                  <dt>SHA-256</dt>
                  <dd className="mono small">{preview.sha256}</dd>
                </div>
                <div className="field">
                  <dt>Indicadores</dt>
                  <dd>
                    {preview.total} en total: {preview.new} nuevos, {preview.updated} actualizados, {preview.unchanged}{" "}
                    sin cambios, {preview.invalid} inválidos
                  </dd>
                </div>
                <div className="field">
                  <dt>Por tipo</dt>
                  <dd>
                    {Object.entries(preview.by_type)
                      .map(([type, count]) => `${INDICATOR_TYPE_LABELS[type] ?? type}: ${count}`)
                      .join(" · ") || "—"}
                  </dd>
                </div>
                {preview.not_matchable > 0 && (
                  <div className="field">
                    <dt>Sin búsqueda en datos locales</dt>
                    <dd>
                      {preview.not_matchable} (hashes, URLs o emails: Sentra no recoge esos datos, quedan como
                      referencia)
                    </dd>
                  </div>
                )}
                {Object.keys(preview.unsupported).length > 0 && (
                  <div className="field">
                    <dt>Fuera del subset soportado</dt>
                    <dd>
                      {Object.entries(preview.unsupported)
                        .map(([reason, count]) => `${reason}: ${count}`)
                        .join(" · ")}
                    </dd>
                  </div>
                )}
              </dl>
              {preview.invalid_records.length > 0 && (
                <div className="table-wrap">
                  <table className="table table--compact">
                    <thead>
                      <tr>
                        <th>#</th>
                        <th>Referencia</th>
                        <th>Motivo</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.invalid_records.map((r) => (
                        <tr key={`${r.index}-${r.code}`}>
                          <td>{r.index}</td>
                          <td className="mono">{r.reference ?? "—"}</td>
                          <td>
                            {r.message} <span className="muted small mono">({r.code})</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
              {preview.invalid > 0 && (
                <label className="checkbox">
                  <input type="checkbox" checked={skipInvalid} onChange={(e) => setSkipInvalid(e.target.checked)} />{" "}
                  Importar los válidos y omitir los inválidos
                </label>
              )}
              <div className="actions">
                <button
                  type="button"
                  className="button button--primary"
                  disabled={busy || preview.valid === 0 || (preview.invalid > 0 && !skipInvalid)}
                  onClick={() => void confirm()}
                >
                  Confirmar importación
                </button>
              </div>
            </div>
          )}
          {result && (
            <div className="banner" role="status">
              Importado en {result.source_key}: {result.new} nuevos, {result.updated} actualizados, {result.unchanged} sin
              cambios. {result.pending_match} indicadores se buscarán en los datos existentes en la próxima vuelta.
            </div>
          )}
        </>
      )}
    </section>
  );
}

/** Threat Intelligence (Fase 5C): resumen, fuentes, indicadores, coincidencias e importación. */
export function ThreatIntelPage() {
  const auth = useAuth();
  const canManage = auth.can("threat_intel:manage");
  const [params, setParams] = useSearchParams();
  const tabs = TABS.filter((t) => t.key !== "import" || canManage);
  const requested = params.get("tab");
  const tab: Tab = tabs.some((t) => t.key === requested) ? (requested as Tab) : "overview";
  const [reevaluating, setReevaluating] = useState(false);
  const [notice, setNotice] = useState<string>();

  const reevaluate = async () => {
    setReevaluating(true);
    try {
      const result = await threatIntelApi.reevaluate();
      setNotice(`${result.indicators_queued} indicadores en cola para buscarse de nuevo en los datos existentes.`);
    } catch (err) {
      setNotice(asError(err));
    } finally {
      setReevaluating(false);
    }
  };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Inteligencia de amenazas</h1>
          <p className="muted small">
            Contexto externo (KEV, EPSS, indicadores) cruzado con datos que Sentra ya tiene. Una coincidencia no
            significa compromiso: requiere análisis.
          </p>
        </div>
        {canManage && (
          <div className="actions">
            <button type="button" className="button" disabled={reevaluating} onClick={() => void reevaluate()}>
              Reevaluar coincidencias
            </button>
          </div>
        )}
      </div>
      {notice && (
        <div className="banner" role="status">
          {notice}
        </div>
      )}
      <nav className="tabs" role="tablist" aria-label="Secciones de inteligencia">
        {tabs.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setParams(key === "overview" ? {} : { tab: key }, { replace: true })}
          >
            {label}
          </button>
        ))}
      </nav>
      <div role="tabpanel">
        {tab === "overview" && <OverviewTab />}
        {tab === "sources" && <SourcesTab canManage={canManage} />}
        {tab === "indicators" && <IndicatorsTab />}
        {tab === "matches" && <MatchesTable />}
        {tab === "import" && canManage && <ImportTab />}
      </div>
    </div>
  );
}
