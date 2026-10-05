// Gestor de modelos locales (Fase 4J.2): etiquetas en español y formato de cifras.
//
// Las cifras de memoria vienen del motor del backend y son ESTIMACIONES; aquí solo se
// formatean. Nada en el frontend decide compatibilidad: si falta un dato se muestra "—".
import type {
  CompatibilityStatus,
  LocalHardware,
  LocalRuntimeKind,
  ModelPlacement,
  ModelState,
  PerformanceClass,
  QualityLabel,
  RecommendationProfile,
  SpeedClass,
} from "../api/types";

export const STATE_LABELS: Record<ModelState, string> = {
  available: "Disponible",
  downloaded: "Descargado",
  registered: "Registrado",
  loaded: "Cargado",
  active: "Activo",
  unavailable: "No disponible",
  incompatible: "Incompatible",
};

export const COMPAT_LABELS: Record<CompatibilityStatus, string> = {
  recommended: "Recomendado",
  compatible: "Compatible",
  compatible_with_offload: "Compatible con offload",
  slow: "Lento",
  not_recommended: "No recomendado",
};

export const PROFILE_LABELS: Record<RecommendationProfile, string> = {
  low_resource: "Menor uso de recursos",
  balanced: "Equilibrado",
  quality: "Mejor calidad",
  max_speed: "Máxima velocidad",
  sentra: "Sentra Security Analysis",
};

export const SPEED_LABELS: Record<SpeedClass, string> = {
  fast: "Rápido",
  moderate: "Moderado",
  slow: "Lento",
  unknown: "Desconocido",
};

export const PLACEMENT_LABELS: Record<ModelPlacement, string> = {
  full_gpu: "Todo en GPU",
  partial_offload: "GPU + RAM (offload)",
  cpu_only: "Solo CPU/RAM",
  does_not_fit: "No cabe",
  unknown: "Sin datos suficientes",
};

export const PERFORMANCE_LABELS: Record<PerformanceClass, string> = {
  excellent: "Excelente",
  good: "Bueno",
  usable: "Usable",
  slow: "Lento",
};

export const QUALITY_LABELS: Record<QualityLabel, string> = {
  basic: "Básica",
  medium: "Media",
  high: "Alta",
  very_high: "Muy alta",
};

export const RUNTIME_LABELS: Record<LocalRuntimeKind, string> = {
  llama_cpp: "llama.cpp",
  ollama: "Ollama",
  vllm: "vLLM",
  openai_compatible: "OpenAI-compatible (genérico)",
};

// Contextos objetivo que ofrece la UI. El análisis normal de Sentra usa el operativo del
// servidor; los grandes son para investigaciones concretas.
export const CONTEXT_OPTIONS: { value: number; label: string }[] = [
  { value: 8192, label: "8K" },
  { value: 16384, label: "16K" },
  { value: 32768, label: "32K" },
  { value: 65536, label: "64K" },
  { value: 102400, label: "100K" },
  { value: 131072, label: "128K" },
  { value: 262144, label: "256K" },
];

/** Badge según compatibilidad: verde lo que se puede usar, ámbar lo dudoso, rojo lo que no. */
export function compatTone(status: CompatibilityStatus | null): string {
  if (status === "recommended" || status === "compatible") return "badge badge--ok";
  if (status === "compatible_with_offload" || status === "slow") return "badge badge--warn";
  if (status === "not_recommended") return "badge badge--crit";
  return "badge";
}

export function stateTone(state: ModelState): string {
  if (state === "active") return "badge badge--ok";
  if (state === "unavailable" || state === "incompatible") return "badge badge--crit";
  if (state === "loaded") return "badge badge--info";
  return "badge";
}

/** 8030261248 -> "8.0B"; 770000000 -> "770M". */
export function formatParams(count: number | null | undefined): string {
  if (!count) return "—";
  if (count >= 1e9) return `${(count / 1e9).toFixed(1)}B`;
  return `${Math.round(count / 1e6)}M`;
}

/** 131072 -> "128K"; 102400 -> "100K"; 8192 -> "8K". */
export function formatContext(tokens: number | null | undefined): string {
  if (!tokens) return "—";
  const option = CONTEXT_OPTIONS.find((o) => o.value === tokens);
  if (option) return option.label;
  return tokens >= 1024 ? `${Math.round(tokens / 1024)}K` : String(tokens);
}

export function formatTps(value: number | null | undefined): string {
  return value == null ? "—" : `${value.toFixed(1)} tok/s`;
}

export function formatMs(value: number | null | undefined): string {
  if (value == null) return "—";
  return value >= 1000 ? `${(value / 1000).toFixed(1)} s` : `${value} ms`;
}

/** Resumen de GPU para la cabecera: "2 × NVIDIA (36.0 GB VRAM)" o "Sin GPU dedicada". */
export function gpuSummary(hardware: LocalHardware, formatBytes: (n: number) => string): string {
  const dedicated = hardware.gpus.filter((g) => g.memory_kind === "dedicated" && g.vram_total_bytes);
  if (!hardware.gpus.length) return "Sin GPU";
  const first = dedicated[0];
  if (!first) return "Sin GPU dedicada conocida";
  const total = dedicated.reduce((sum, g) => sum + (g.vram_total_bytes ?? 0), 0);
  const prefix = dedicated.length > 1 ? `${dedicated.length} × ` : "";
  return `${prefix}${first.model ?? first.vendor} (${formatBytes(total)} VRAM)`;
}
