// Configuración → IA local → Modelos (Fase 4J.2).
//
// Todo lo que se ve aquí sale de /ai/local/*: hardware detectado, runtime configurado,
// modelos registrados y recomendaciones deterministas. Ver y usar exige ai:use; cualquier
// cambio (seleccionar, registrar, benchmark, runtime) exige ai:manage, que solo tiene admin.
// La página funciona sin Internet: no hay descargas ni llamadas fuera del servidor.
import { useCallback, useState } from "react";
import { localAiApi } from "../api/sentra";
import type { LocalModel, RecommendationProfile } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import {
  BenchmarkTable,
  HardwareCard,
  LocalAIHeader,
  ModelCard,
  ModelDetailsModal,
  RecommendationsPanel,
  RegisterModelForm,
  RunningBenchmark,
  RuntimePanel,
} from "../components/localai/LocalAIPanels";
import { ConfirmDialog } from "../components/Modal";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage } from "../lib/format";
import { CONTEXT_OPTIONS, PROFILE_LABELS } from "../lib/localAi";
import { usePolling } from "../lib/usePolling";

const PROFILES: RecommendationProfile[] = ["sentra", "low_resource", "balanced", "quality", "max_speed"];

function message(err: unknown): string {
  return err instanceof Error ? errorMessage(err) : String(err);
}

export function LocalAIPage() {
  const auth = useAuth();
  const canManage = auth.can("ai:manage");
  const runtime = usePolling(useCallback((s: AbortSignal) => localAiApi.runtime(s), []), 30_000);
  const hardware = usePolling(useCallback((s: AbortSignal) => localAiApi.hardware(s), []), 300_000);
  const models = usePolling(useCallback((s: AbortSignal) => localAiApi.models(s), []), 15_000);

  const [profile, setProfile] = useState<RecommendationProfile>("sentra");
  // undefined = usar el contexto operativo que fija el servidor.
  const [contextChoice, setContextChoice] = useState<number>();
  const [detailsId, setDetailsId] = useState<string>();
  const [benchmarkId, setBenchmarkId] = useState<string>();
  const [unregister, setUnregister] = useState<LocalModel>();
  const [actionError, setActionError] = useState<string>();
  const [selecting, setSelecting] = useState<string>();

  const context = contextChoice ?? runtime.data?.default_context_tokens ?? 16384;

  function refreshAll() {
    runtime.refresh();
    models.refresh();
  }

  async function select(model: LocalModel) {
    setSelecting(model.model_id);
    setActionError(undefined);
    try {
      await localAiApi.select(model.model_id);
    } catch (err) {
      // El backend conserva el modelo anterior si este falla; solo lo contamos.
      setActionError(`No se pudo activar ${model.name}: ${message(err)} El modelo anterior sigue activo.`);
    } finally {
      setSelecting(undefined);
      refreshAll();
    }
  }

  async function benchmark(model: LocalModel) {
    setActionError(undefined);
    try {
      const started = await localAiApi.benchmark(model.model_id);
      setBenchmarkId(started.benchmark_id);
      models.refresh();
    } catch (err) {
      setActionError(message(err));
    }
  }

  if (runtime.loading) return <LoadingState label="Cargando IA local…" />;
  if (runtime.error && !runtime.data) return <ErrorState message={message(runtime.error)} onRetry={runtime.refresh} />;
  const status = runtime.data;
  if (!status) return null;
  const list = models.data;

  return (
    <div className="page stack">
      <header className="page__header">
        <div>
          <p className="muted small">Configuración → IA local</p>
          <h1>Modelos</h1>
        </div>
      </header>

      <LocalAIHeader runtime={status} />

      {actionError && (
        <p className="banner banner--warn" role="alert">
          {actionError}
        </p>
      )}
      {selecting && (
        <p className="muted" role="status">
          <span className="spinner spinner--inline" /> Comprobando el runtime y cargando el modelo…
        </p>
      )}

      {hardware.loading && <LoadingState label="Detectando hardware…" />}
      {hardware.error && !hardware.data && <ErrorState message={message(hardware.error)} onRetry={hardware.refresh} />}
      {hardware.data && (
        <HardwareCard
          hardware={hardware.data}
          canManage={canManage}
          onRefresh={async () => {
            await localAiApi.refreshHardware();
            hardware.refresh();
          }}
        />
      )}

      <RuntimePanel
        runtime={status}
        canManage={canManage}
        onChange={async (kind) => {
          await localAiApi.setRuntime(kind);
          refreshAll();
        }}
      />

      <section className="panel panel--padded" aria-label="Modelos registrados">
        <h2>Modelos</h2>
        {models.loading && <LoadingState />}
        {models.error && !list && <ErrorState message={message(models.error)} onRetry={models.refresh} />}
        {list && list.items.length === 0 && (
          <p className="muted">
            No hay modelos registrados.{" "}
            {canManage
              ? "Importa un .gguf de los directorios de modelos permitidos o registra un modelo que ya sirva el runtime."
              : "Un administrador puede registrarlos."}
          </p>
        )}
        {list && list.items.length > 0 && (
          <div className="lai-grid">
            {list.items.map((m) => (
              <ModelCard
                key={m.model_id}
                model={m}
                canManage={canManage && !selecting}
                onSelect={() => void select(m)}
                onBenchmark={() => void benchmark(m)}
                onDetails={() => setDetailsId(m.model_id)}
                onUnregister={() => setUnregister(m)}
              />
            ))}
          </div>
        )}
      </section>

      {benchmarkId && (
        <RunningBenchmark
          benchmarkId={benchmarkId}
          canManage={canManage}
          onFinished={() => {
            setBenchmarkId(undefined);
            models.refresh();
          }}
        />
      )}

      {canManage && list && <RegisterModelForm discovered={list.discovered} onRegistered={models.refresh} />}

      <section className="panel panel--padded" aria-label="Configuración de recomendaciones">
        <h2>Configuración</h2>
        <div className="actions">
          <div className="segmented" role="group" aria-label="Perfil">
            {PROFILES.map((p) => (
              <button
                key={p}
                type="button"
                className={`segmented__item${profile === p ? " segmented__item--active" : ""}`}
                aria-pressed={profile === p}
                onClick={() => setProfile(p)}
              >
                {PROFILE_LABELS[p]}
              </button>
            ))}
          </div>
          <label className="form-field form-field--inline">
            <span>Contexto objetivo</span>
            <select
              className="input input--select"
              aria-label="Contexto objetivo"
              value={context}
              onChange={(e) => setContextChoice(Number(e.target.value))}
            >
              {CONTEXT_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                  {o.value === status.default_context_tokens ? " (operativo)" : ""}
                </option>
              ))}
            </select>
          </label>
        </div>
        <p className="muted small">
          Más contexto aumenta el KV cache y la latencia; nunca se ofrece más del contexto nativo del modelo. El
          análisis normal de Sentra usa el contexto operativo; los grandes son para investigaciones concretas.
        </p>
      </section>

      <RecommendationsPanel profile={profile} context={context} />

      <section className="panel panel--padded" aria-label="Benchmarks">
        <h2>Benchmarks</h2>
        <BenchmarkTable
          benchmarks={(list?.items ?? []).flatMap((m) => (m.latest_benchmark ? [m.latest_benchmark] : []))}
        />
      </section>

      {detailsId && (
        <ModelDetailsModal
          modelId={detailsId}
          profile={profile}
          context={context}
          onClose={() => setDetailsId(undefined)}
        />
      )}
      {unregister && (
        <ConfirmDialog
          title="Quitar registro"
          confirmLabel="Quitar registro"
          danger
          onConfirm={async () => {
            await localAiApi.unregister(unregister.model_id);
            refreshAll();
          }}
          onClose={() => setUnregister(undefined)}
        >
          Se quita {unregister.name} de Sentra. El fichero del modelo no se borra.
        </ConfirmDialog>
      )}
    </div>
  );
}
