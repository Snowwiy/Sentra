import type { AssetStatus, LifecycleState } from "../api/types";

const LABELS: Record<AssetStatus, string> = {
  online: "Online",
  offline: "Offline",
  unknown: "Unknown",
};

export function StatusBadge({ status }: { status: AssetStatus }) {
  return (
    <span className={`status status--${status}`}>
      <span className="status__dot" aria-hidden="true" />
      {LABELS[status]}
    </span>
  );
}

// Fase 5C.2: estado de ciclo de vida calculado por el servidor.
export const LIFECYCLE_LABELS: Record<LifecycleState, string> = {
  active: "Online",
  offline: "Offline",
  stale: "Stale",
  cleanup_candidate: "Candidato a limpieza",
  archived: "Archivado",
};

const LIFECYCLE_CLASSES: Record<LifecycleState, string> = {
  active: "status--online",
  offline: "status--offline",
  stale: "status--stale",
  cleanup_candidate: "status--cleanup",
  archived: "status--archived",
};

const LIFECYCLE_HELP: Record<LifecycleState, string> = {
  active: "Visto recientemente",
  offline: "No visto recientemente, pero aún dentro de la política de inactividad",
  stale: "Sin ver durante el umbral de inactividad (tiempo y escaneos completos perdidos)",
  cleanup_candidate: "Inactivo y pasada la ventana de purga: candidato a limpieza",
  archived: "Archivado: oculto por defecto, con todo su historial",
};

export function LifecycleBadge({ state, title }: { state: LifecycleState; title?: string }) {
  return (
    <span className={`status ${LIFECYCLE_CLASSES[state]}`} title={title ?? LIFECYCLE_HELP[state]}>
      <span className="status__dot" aria-hidden="true" />
      {LIFECYCLE_LABELS[state]}
    </span>
  );
}

/**
 * Estado visible de un activo: Stale, Candidato a limpieza y Archivado ganan a la conectividad;
 * si no, el estado de siempre (Online / Offline / Unknown).
 */
export function AssetStateBadge({
  asset,
}: {
  asset: {
    status: AssetStatus;
    lifecycle_state?: LifecycleState;
    archived_at?: string | null;
    archive_reason?: string | null;
  };
}) {
  // Un servidor anterior a 5C.2 no envía lifecycle_state: archived_at sigue marcando el archivado.
  const state = asset.lifecycle_state ?? (asset.archived_at ? "archived" : undefined);
  if (state === "stale" || state === "cleanup_candidate" || state === "archived") {
    return <LifecycleBadge state={state} title={state === "archived" ? (asset.archive_reason ?? undefined) : undefined} />;
  }
  return <StatusBadge status={asset.status} />;
}
