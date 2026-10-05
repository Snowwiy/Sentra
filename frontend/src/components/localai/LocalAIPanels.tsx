// Paneles del gestor de modelos locales (Fase 4J.2).
//
// Solo muestran lo que devuelve la API: el motor de recomendación y las estimaciones viven
// en el backend (deterministas y documentadas). Las acciones de cambio aparecen solo con
// ai:manage, y la API lo vuelve a exigir igualmente.
import { useCallback, useState } from "react";
import { localAiApi } from "../../api/sentra";
import type {
  DiscoveredModel,
  LocalBenchmark,
  LocalHardware,
  LocalModel,
  LocalModelDetail,
  LocalRuntimeKind,
  LocalRuntimeStatus,
  ModelEstimate,
  ModelRecommendation,
  RecommendationProfile,
} from "../../api/types";
import { formatBytes, formatDateTime, errorMessage } from "../../lib/format";
import {
  COMPAT_LABELS,
  PERFORMANCE_LABELS,
  PLACEMENT_LABELS,
  PROFILE_LABELS,
  QUALITY_LABELS,
  RUNTIME_LABELS,
  SPEED_LABELS,
  STATE_LABELS,
  compatTone,
  formatContext,
  formatMs,
  formatParams,
  formatTps,
  gpuSummary,
  stateTone,
} from "../../lib/localAi";
import { usePolling } from "../../lib/usePolling";
import { ConfirmDialog, Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";

function message(err: unknown): string {
  return err instanceof Error ? errorMessage(err) : String(err);
}

// --- Cabecera ----------------------------------------------------------------------------

export function LocalAIHeader({ runtime }: { runtime: LocalRuntimeStatus }) {
  const health =
    runtime.reachable === null ? "Sin comprobar" : runtime.reachable ? "Disponible" : "No responde";
  return (
    <section className="panel panel--padded lai-header" aria-label="Estado de la IA local">
      <dl className="fields lai-header__fields">
        <div className="field">
          <dt>Local AI</dt>
          <dd>
            <span className={runtime.available && runtime.reachable ? "text-ok" : "text-warn"}>
              {runtime.available ? health : "No disponible"}
            </span>
          </dd>
        </div>
        <div className="field">
          <dt>Modelo</dt>
          <dd>{runtime.active_model?.name ?? runtime.effective_model ?? "—"}</dd>
        </div>
        <div className="field">
          <dt>Runtime</dt>
          <dd>
            {runtime.label}
            {runtime.version ? ` ${runtime.version}` : ""}
          </dd>
        </div>
        <div className="field">
          <dt>Contexto</dt>
          <dd>
            {runtime.configured_context ? `${formatContext(runtime.configured_context)} configurado` : "—"} ·{" "}
            {formatContext(runtime.default_context_tokens)} operativo
          </dd>
        </div>
        <div className="field">
          <dt>External AI</dt>
          <dd>
            <span className={runtime.external_ai === "blocked" ? "text-ok" : "text-warn"}>
              {runtime.external_ai === "blocked" ? "Blocked" : "Allowed"}
            </span>
          </dd>
        </div>
      </dl>
      {!runtime.available && runtime.reason && <p className="muted small">{runtime.reason}</p>}
      {runtime.available && runtime.reachable === false && (
        <p className="banner banner--warn" role="status">
          El runtime local no responde{runtime.health_detail ? ` (${runtime.health_detail})` : ""}. Sentra sigue
          funcionando; AI Insights mostrará el error y nunca usará un proveedor externo.
        </p>
      )}
    </section>
  );
}

// --- Hardware ----------------------------------------------------------------------------

export function HardwareCard({
  hardware,
  canManage,
  onRefresh,
}: {
  hardware: LocalHardware;
  canManage: boolean;
  onRefresh: () => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function refresh() {
    setBusy(true);
    setError(undefined);
    try {
      await onRefresh();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel panel--padded" aria-label="Hardware">
      <div className="lai-section-head">
        <h2>Hardware del servidor</h2>
        {canManage && (
          <button type="button" className="button button--small" disabled={busy} onClick={() => void refresh()}>
            {busy ? "Detectando…" : "Volver a detectar"}
          </button>
        )}
      </div>
      <dl className="fields lai-hardware">
        <div className="field">
          <dt>CPU</dt>
          <dd>
            {hardware.cpu.model ?? "Desconocida"}
            <div className="muted small">
              {hardware.cpu.physical_cores ?? "?"} núcleos físicos · {hardware.cpu.logical_cores ?? "?"} lógicos ·{" "}
              {hardware.architecture}
            </div>
          </dd>
        </div>
        <div className="field">
          <dt>RAM</dt>
          <dd>
            {formatBytes(hardware.ram_total_bytes)}
            <div className="muted small">{formatBytes(hardware.ram_available_bytes)} disponibles</div>
          </dd>
        </div>
        <div className="field">
          <dt>GPU</dt>
          <dd>{gpuSummary(hardware, (n) => formatBytes(n))}</dd>
        </div>
        <div className="field">
          <dt>VRAM</dt>
          <dd>
            {hardware.gpus.length === 0 && "—"}
            {hardware.gpus.map((gpu) => (
              <div key={gpu.index} className="small">
                {gpu.model ?? gpu.vendor}: {formatBytes(gpu.vram_total_bytes)}
                {gpu.vram_free_bytes != null && ` (${formatBytes(gpu.vram_free_bytes)} libres)`}
                {gpu.memory_kind !== "dedicated" && " · compartida/desconocida"}
              </div>
            ))}
          </dd>
        </div>
        <div className="field">
          <dt>Disco</dt>
          <dd>
            {formatBytes(hardware.disk_free_bytes)} libres
            <div className="muted small">
              {hardware.disk_scope === "model_directory" ? "en el directorio de modelos" : "en el servidor"}
            </div>
          </dd>
        </div>
        <div className="field">
          <dt>Sistema</dt>
          <dd>
            {hardware.os} {hardware.os_version ?? ""}
            <div className="muted small">Detectado {formatDateTime(hardware.detected_at)}</div>
          </dd>
        </div>
      </dl>
      {hardware.warnings.length > 0 && (
        <ul className="ai-warnings muted small">
          {hardware.warnings.map((w) => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      )}
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

// --- Runtime y configuración -------------------------------------------------------------

const RUNTIMES: LocalRuntimeKind[] = ["llama_cpp", "ollama", "vllm", "openai_compatible"];

export function RuntimePanel({
  runtime,
  canManage,
  onChange,
}: {
  runtime: LocalRuntimeStatus;
  canManage: boolean;
  onChange: (kind: LocalRuntimeKind) => Promise<unknown>;
}) {
  const [pending, setPending] = useState<LocalRuntimeKind>();
  const caps = runtime.capabilities;
  const yes = (v: boolean) => (v ? "Sí" : "No");
  return (
    <section className="panel panel--padded" aria-label="Runtime">
      <h2>Runtime</h2>
      <dl className="fields">
        <div className="field">
          <dt>Runtime configurado</dt>
          <dd>
            {runtime.label} <span className="muted small">({runtime.source === "env" ? "configuración del servidor" : "elegido en la UI"})</span>
          </dd>
        </div>
        <div className="field">
          <dt>Detectado en el endpoint</dt>
          <dd>{runtime.detected_kind ? RUNTIME_LABELS[runtime.detected_kind] : "—"}</dd>
        </div>
        <div className="field">
          <dt>Capacidades reales</dt>
          <dd className="small">
            Listar: {yes(caps.list_models)} · Cargar: {yes(caps.load_model)} · Descargar de memoria:{" "}
            {yes(caps.unload_model)} · Offload GPU→RAM: {yes(caps.gpu_offload)} · GGUF: {yes(caps.gguf_files)} ·
            Benchmark: {caps.benchmark === "runtime_timings" ? "medido por el runtime" : "extremo a extremo"}
          </dd>
        </div>
        <div className="field">
          <dt>Modelos cargados</dt>
          <dd>{runtime.loaded_models.length ? runtime.loaded_models.join(", ") : "—"}</dd>
        </div>
      </dl>
      <ul className="ai-warnings muted small">
        {caps.notes.map((n) => (
          <li key={n}>{n}</li>
        ))}
      </ul>
      {canManage && (
        <div className="actions">
          <label className="form-field form-field--inline">
            <span>Cambiar runtime</span>
            <select
              className="input input--select"
              aria-label="Runtime"
              value={runtime.kind}
              onChange={(e) => setPending(e.target.value as LocalRuntimeKind)}
            >
              {RUNTIMES.map((kind) => (
                <option key={kind} value={kind}>
                  {RUNTIME_LABELS[kind]}
                </option>
              ))}
            </select>
          </label>
          <span className="muted small">La URL del runtime solo se cambia en la configuración del servidor.</span>
        </div>
      )}
      {pending && pending !== runtime.kind && (
        <ConfirmDialog
          title="Cambiar runtime"
          confirmLabel="Cambiar"
          onConfirm={() => onChange(pending)}
          onClose={() => setPending(undefined)}
        >
          Cambiar a {RUNTIME_LABELS[pending]} desactiva el modelo activo actual (pertenece a otro runtime). Hasta
          seleccionar otro, AI Insights usará el modelo por defecto del servidor.
        </ConfirmDialog>
      )}
    </section>
  );
}

// --- Estimación de memoria ---------------------------------------------------------------

export function EstimateView({ estimate }: { estimate: ModelEstimate }) {
  return (
    <dl className="fields lai-estimate">
      <div className="field">
        <dt>Colocación</dt>
        <dd>{PLACEMENT_LABELS[estimate.placement]}</dd>
      </div>
      <div className="field">
        <dt>VRAM estimada</dt>
        <dd>
          {estimate.vram_bytes != null ? `~${formatBytes(estimate.vram_bytes)}` : "—"}
          <span className="muted small"> de {formatBytes(estimate.usable_vram_bytes)} utilizables</span>
        </dd>
      </div>
      <div className="field">
        <dt>RAM estimada</dt>
        <dd>
          {estimate.ram_bytes != null ? `~${formatBytes(estimate.ram_bytes)}` : "—"}
          <span className="muted small"> de {formatBytes(estimate.usable_ram_bytes)} utilizables</span>
        </dd>
      </div>
      <div className="field">
        <dt>Desglose (contexto {formatContext(estimate.context_tokens)})</dt>
        <dd className="small">
          Pesos {formatBytes(estimate.weights_bytes)}
          {estimate.weights_source === "quantization_estimate" ? " (estimado)" : ""} · KV cache{" "}
          {formatBytes(estimate.kv_cache_bytes)} ({estimate.kv_type}) · Runtime {formatBytes(estimate.overhead_bytes)}
          <div className="muted">
            Total ~{formatBytes(estimate.total_bytes)} · margen de seguridad {estimate.safety_margin_percent}% ·
            cifras estimadas
          </div>
        </dd>
      </div>
    </dl>
  );
}

// --- Recomendaciones ---------------------------------------------------------------------

export function RecommendationCard({ item }: { item: ModelRecommendation }) {
  return (
    <article className="lai-card" aria-label={item.name}>
      <header className="lai-card__head">
        <span className="strong">{item.name}</span>
        <span className={compatTone(item.status)}>{COMPAT_LABELS[item.status]}</span>
        {item.recommended_for_sentra && <span className="badge badge--info">Recommended for Sentra</span>}
        {item.origin === "catalog" && <span className="badge">Catálogo</span>}
      </header>
      <p className="muted small">
        {formatParams(item.parameter_count)} · {item.quantization ?? "cuantización desconocida"} · Calidad{" "}
        {item.quality ? QUALITY_LABELS[item.quality] : "—"} · Velocidad {SPEED_LABELS[item.speed]}
        {item.speed_source === "benchmark" && item.observed_tps != null
          ? ` (medida: ${formatTps(item.observed_tps)})`
          : " (estimada)"}{" "}
        · Contexto nativo {formatContext(item.native_context)}
      </p>
      <EstimateView estimate={item.estimate} />
      <ul className="lai-reasons small">
        {item.reasons.map((r) => (
          <li key={r}>{r}</li>
        ))}
        {item.warnings.map((w) => (
          <li key={w} className="text-warn">
            {w}
          </li>
        ))}
      </ul>
    </article>
  );
}

export function RecommendationsPanel({
  profile,
  context,
}: {
  profile: RecommendationProfile;
  context: number;
}) {
  const [showAll, setShowAll] = useState(false);
  const fetcher = useCallback(
    (signal: AbortSignal) => localAiApi.recommendations({ profile, context }, signal),
    [profile, context],
  );
  const state = usePolling(fetcher, 120_000);
  if (state.loading) return <LoadingState label="Calculando recomendaciones…" />;
  if (state.error && !state.data) return <ErrorState message={message(state.error)} onRetry={state.refresh} />;
  const data = state.data;
  if (!data) return null;
  const sentra = data.items.find((i) => i.key === data.sentra_pick);
  const pick = data.items.find((i) => i.key === data.profile_pick);
  const usable = data.items.filter((i) => i.status !== "not_recommended");
  const visible = showAll ? data.items : usable.slice(0, 12);
  return (
    <section className="panel panel--padded" aria-label="Recomendaciones">
      <h2>Recomendaciones · {PROFILE_LABELS[data.profile]} · contexto {formatContext(data.context_tokens)}</h2>
      <p className="muted small">
        Motor determinista (sin LLM): memoria estimada con pesos, KV cache y overhead del runtime; la medición de
        un benchmark pesa más que la estimación. Detection, Correlation y Risk Engine ya estructuran la evidencia,
        así que el modelo más grande no siempre es el mejor para Sentra.
      </p>
      {sentra ? (
        <div className="lai-pick">
          <h3>Recommended for Sentra</h3>
          <RecommendationCard item={sentra} />
        </div>
      ) : (
        <p className="banner banner--warn">Ningún modelo cumple los requisitos para Sentra en este hardware y contexto.</p>
      )}
      {pick && pick.key !== sentra?.key && (
        <div className="lai-pick">
          <h3>Mejor para «{PROFILE_LABELS[data.profile]}»</h3>
          <RecommendationCard item={pick} />
        </div>
      )}
      <h3>
        Todos los modelos ({usable.length} utilizables de {data.total})
      </h3>
      <div className="lai-grid">
        {visible.map((item) => (
          <RecommendationCard key={item.key} item={item} />
        ))}
      </div>
      {data.items.length > visible.length || showAll ? (
        <button type="button" className="button button--small" onClick={() => setShowAll(!showAll)}>
          {showAll ? "Ver solo utilizables" : "Ver también los no recomendados"}
        </button>
      ) : null}
    </section>
  );
}

// --- Modelos -----------------------------------------------------------------------------

function BenchmarkLine({ bench }: { bench: LocalBenchmark }) {
  if (bench.status === "running") return <span className="muted small">Benchmark en curso…</span>;
  if (bench.status !== "completed")
    return (
      <span className="muted small">
        Benchmark {bench.status === "cancelled" ? "cancelado" : `fallido (${bench.error ?? "error"})`}
      </span>
    );
  return (
    <span className="small">
      {formatTps(bench.generation_tps)}
      {bench.performance_class ? ` · ${PERFORMANCE_LABELS[bench.performance_class]}` : ""} · TTFT {formatMs(bench.ttft_ms)}
    </span>
  );
}

export function ModelCard({
  model,
  canManage,
  onSelect,
  onBenchmark,
  onDetails,
  onUnregister,
}: {
  model: LocalModel;
  canManage: boolean;
  onSelect: () => void;
  onBenchmark: () => void;
  onDetails: () => void;
  onUnregister: () => void;
}) {
  return (
    <article className={`lai-card${model.active ? " lai-card--active" : ""}`} aria-label={model.name}>
      <header className="lai-card__head">
        <span className="strong">{model.name}</span>
        <span className={stateTone(model.state)}>{STATE_LABELS[model.state]}</span>
        {model.compatibility && <span className={compatTone(model.compatibility)}>{COMPAT_LABELS[model.compatibility]}</span>}
        {model.recommended_for_sentra && <span className="badge badge--info">Recommended for Sentra</span>}
      </header>
      <dl className="lai-card__facts small">
        <div>
          <dt>Parámetros</dt>
          <dd>{formatParams(model.parameter_count)}</dd>
        </div>
        <div>
          <dt>Cuantización</dt>
          <dd>{model.quantization ?? "Desconocida"}</dd>
        </div>
        <div>
          <dt>Tamaño</dt>
          <dd>{formatBytes(model.file_size_bytes)}</dd>
        </div>
        <div>
          <dt>Contexto</dt>
          <dd>{formatContext(model.native_context)}</dd>
        </div>
        <div>
          <dt>Runtime</dt>
          <dd>{model.runtime}</dd>
        </div>
      </dl>
      {model.latest_benchmark && <BenchmarkLine bench={model.latest_benchmark} />}
      <div className="actions">
        <button type="button" className="button button--small" onClick={onDetails}>
          Detalles
        </button>
        {canManage && (
          <>
            <button
              type="button"
              className="button button--small button--primary"
              disabled={model.active || model.state === "unavailable"}
              onClick={onSelect}
            >
              {model.active ? "Activo" : "Seleccionar"}
            </button>
            <button
              type="button"
              className="button button--small"
              disabled={model.state === "unavailable" || model.latest_benchmark?.status === "running"}
              onClick={onBenchmark}
            >
              Benchmark
            </button>
            <button type="button" className="button button--small button--ghost" onClick={onUnregister}>
              Quitar registro
            </button>
          </>
        )}
      </div>
    </article>
  );
}

export function RegisterModelForm({
  discovered,
  onRegistered,
}: {
  discovered: DiscoveredModel[];
  onRegistered: () => void;
}) {
  const [path, setPath] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  async function register(action: () => Promise<unknown>) {
    setBusy(true);
    setError(undefined);
    try {
      await action();
      setPath("");
      onRegistered();
    } catch (err) {
      setError(message(err));
    } finally {
      setBusy(false);
    }
  }
  return (
    <section className="panel panel--padded" aria-label="Importar modelo">
      <h2>Importar modelo local</h2>
      <p className="muted small">
        Solo ficheros .gguf dentro de los directorios de modelos permitidos por el servidor. Sentra lee la cabecera (metadata, parámetros,
        cuantización) y calcula el SHA-256; nunca ejecuta el fichero ni descarga nada.
      </p>
      <form
        className="actions"
        onSubmit={(e) => {
          e.preventDefault();
          if (path.trim()) void register(() => localAiApi.registerPath(path.trim()));
        }}
      >
        <input
          className="input lai-path"
          value={path}
          maxLength={1024}
          placeholder="D:\\Models\\modelo-Q4_K_M.gguf"
          aria-label="Ruta del fichero GGUF"
          onChange={(e) => setPath(e.target.value)}
        />
        <button type="submit" className="button button--primary" disabled={busy || !path.trim()}>
          Registrar
        </button>
      </form>
      {discovered.length > 0 && (
        <>
          <h3>Encontrados sin registrar</h3>
          <ul className="plain-list">
            {discovered.map((d) => (
              <li key={`${d.kind}:${d.path ?? d.runtime_model_id}`} className="lai-discovered">
                <span>
                  <span className="strong">{d.file_name ?? d.name}</span>{" "}
                  <span className="badge">{d.state === "loaded" ? "Cargado en el runtime" : "Descargado"}</span>{" "}
                  <span className="muted small">{formatBytes(d.size_bytes)}</span>
                  {d.path && <div className="muted small mono">{d.path}</div>}
                </span>
                <button
                  type="button"
                  className="button button--small"
                  disabled={busy}
                  onClick={() =>
                    void register(() =>
                      d.kind === "file" && d.path
                        ? localAiApi.registerPath(d.path)
                        : localAiApi.registerRuntimeModel(d.runtime_model_id ?? d.name),
                    )
                  }
                >
                  Registrar
                </button>
              </li>
            ))}
          </ul>
        </>
      )}
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}

// --- Detalles ----------------------------------------------------------------------------

export function ModelDetailsModal({
  modelId,
  profile,
  context,
  onClose,
}: {
  modelId: string;
  profile: RecommendationProfile;
  context: number;
  onClose: () => void;
}) {
  const fetcher = useCallback(
    (signal: AbortSignal) => localAiApi.model(modelId, { profile, context }, signal),
    [modelId, profile, context],
  );
  const state = usePolling(fetcher, 10_000);
  const detail: LocalModelDetail | undefined = state.data;
  return (
    <Modal title={detail ? detail.model.name : "Detalles del modelo"} onClose={onClose} wide>
      {state.loading && <LoadingState />}
      {state.error && !detail && <ErrorState message={message(state.error)} onRetry={state.refresh} />}
      {detail && (
        <div className="stack">
          <dl className="fields">
            <div className="field">
              <dt>Metadata</dt>
              <dd className="small">
                {detail.model.metadata_source === "gguf" ? "Cabecera GGUF verificada" : "Informada por el runtime"} ·{" "}
                {detail.model.architecture ?? "arquitectura desconocida"} · {formatParams(detail.model.parameter_count)}
              </dd>
            </div>
            <div className="field">
              <dt>Fichero</dt>
              <dd className="small mono">
                {detail.model.local_path ?? detail.model.file_name ?? detail.model.runtime_model_id}
                {detail.model.split_count > 1 ? ` (${detail.model.split_count} partes)` : ""}
              </dd>
            </div>
            <div className="field">
              <dt>SHA-256</dt>
              <dd className="small mono">
                {detail.model.checksum_sha256 ??
                  (detail.model.checksum_status === "pending" ? "Calculando…" : detail.model.checksum_status)}
              </dd>
            </div>
            <div className="field">
              <dt>Licencia</dt>
              <dd>{detail.model.license ?? "No declarada"}</dd>
            </div>
          </dl>
          <h3>
            Evaluación ({COMPAT_LABELS[detail.evaluation.status]}) · contexto {formatContext(context)}
          </h3>
          <EstimateView estimate={detail.evaluation.estimate} />
          <ul className="lai-reasons small">
            {detail.evaluation.reasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
            {detail.evaluation.warnings.map((w) => (
              <li key={w} className="text-warn">
                {w}
              </li>
            ))}
          </ul>
          <h3>Implicaciones de contexto</h3>
          <p className="small muted">
            Contexto nativo declarado: {formatContext(detail.model.native_context)}. Un contexto mayor multiplica el
            KV cache y el tiempo de procesado del prompt: soportado no significa eficiente.
          </p>
          <h3>Limitaciones</h3>
          <ul className="small muted">
            {[...detail.evaluation.limitations, ...detail.runtime_notes].map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
          <h3>Historial de benchmarks</h3>
          <BenchmarkTable benchmarks={detail.benchmarks} />
        </div>
      )}
    </Modal>
  );
}

export function BenchmarkTable({ benchmarks }: { benchmarks: LocalBenchmark[] }) {
  if (!benchmarks.length) return <p className="muted small">Sin benchmarks todavía.</p>;
  return (
    <div className="table-wrap">
      <table className="table table--compact">
        <thead>
          <tr>
            <th>Fecha</th>
            <th>Estado</th>
            <th>Generación</th>
            <th>Prompt</th>
            <th>TTFT</th>
            <th>Carga</th>
            <th>RAM/VRAM pico (sistema)</th>
          </tr>
        </thead>
        <tbody>
          {benchmarks.map((b) => (
            <tr key={b.benchmark_id}>
              <td>{formatDateTime(b.started_at)}</td>
              <td>
                {b.status === "completed" && b.performance_class
                  ? PERFORMANCE_LABELS[b.performance_class]
                  : b.status === "failed"
                    ? `Fallido (${b.error ?? "error"})`
                    : b.status === "running"
                      ? "En curso"
                      : "Cancelado"}
              </td>
              <td>
                {formatTps(b.generation_tps)}
                {b.measurement === "end_to_end" && <span className="muted small"> (extremo a extremo)</span>}
              </td>
              <td>{formatTps(b.prompt_tps)}</td>
              <td>{formatMs(b.ttft_ms)}</td>
              <td>{formatMs(b.load_ms)}</td>
              <td>
                {formatBytes(b.peak_ram_bytes)} / {formatBytes(b.peak_vram_bytes)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// --- Benchmark en curso ------------------------------------------------------------------

export function RunningBenchmark({
  benchmarkId,
  canManage,
  onFinished,
}: {
  benchmarkId: string;
  canManage: boolean;
  onFinished: () => void;
}) {
  const [error, setError] = useState<string>();
  const fetcher = useCallback((signal: AbortSignal) => localAiApi.getBenchmark(benchmarkId, signal), [benchmarkId]);
  const state = usePolling(fetcher, 2_000);
  const bench = state.data;
  const running = !bench || bench.status === "running";
  return (
    <section className="panel panel--padded" aria-label="Benchmark en curso" role="status">
      <h2>Benchmark</h2>
      {running ? (
        <p>
          <span className="spinner spinner--inline" /> Midiendo rendimiento local (prompt fijo, sin datos de Sentra)…
        </p>
      ) : (
        <BenchmarkTable benchmarks={[bench]} />
      )}
      <div className="actions">
        {running && canManage && (
          <button
            type="button"
            className="button button--small"
            onClick={() => {
              localAiApi.cancelBenchmark(benchmarkId).catch((err: unknown) => setError(message(err)));
            }}
          >
            Cancelar
          </button>
        )}
        {!running && (
          <button type="button" className="button button--small" onClick={onFinished}>
            Cerrar
          </button>
        )}
      </div>
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
