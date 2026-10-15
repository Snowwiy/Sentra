import type { SensorEnrollmentState, SensorJobStatus, SensorStatus, VersionStatus } from "../../api/types";

export const SENSOR_STATUS_LABELS: Record<SensorStatus, string> = {
  online: "Online",
  offline: "Offline",
  stale: "Stale",
  pending: "Pendiente",
  disabled: "Deshabilitado",
  revoked: "Revocado",
};

// Offline y Stale solo dicen que el sensor no reporta: nunca que esté comprometido o borrado.
export const SENSOR_STATUS_HELP: Record<SensorStatus, string> = {
  online: "Reporta con normalidad",
  offline: "Sin heartbeat reciente. No significa que esté comprometido ni borrado: puede estar apagado o sin red.",
  stale: "Sin contacto durante mucho tiempo. No significa que esté comprometido: revisa el equipo y su red.",
  pending: "Registrado, todavía sin primer heartbeat",
  disabled: "Deshabilitado por un administrador: no recibe trabajos",
  revoked: "Credencial revocada: no puede volver a conectarse",
};

const SENSOR_STATUS_CLASS: Record<SensorStatus, string> = {
  online: "status--online",
  offline: "status--sensor-offline",
  stale: "status--stale",
  pending: "status--pending",
  disabled: "status--disabled",
  revoked: "status--revoked",
};

export function SensorStatusBadge({ status }: { status: SensorStatus }) {
  return (
    <span className={`status ${SENSOR_STATUS_CLASS[status]}`} title={SENSOR_STATUS_HELP[status]}>
      <span className="status__dot" aria-hidden="true" />
      {SENSOR_STATUS_LABELS[status]}
    </span>
  );
}

export const VERSION_STATUS_LABELS: Record<VersionStatus, string> = {
  current: "al día",
  outdated: "desactualizada",
  unsupported: "no soportada",
  unknown: "desconocida",
};

const VERSION_STATUS_CLASS: Record<VersionStatus, string> = {
  current: "badge badge--ok",
  outdated: "badge badge--warn",
  unsupported: "badge badge--crit",
  unknown: "badge badge--muted",
};

export function VersionStatusBadge({ status }: { status: VersionStatus }) {
  return <span className={VERSION_STATUS_CLASS[status]}>{VERSION_STATUS_LABELS[status]}</span>;
}

export const SENSOR_JOB_STATUS_LABELS: Record<SensorJobStatus, string> = {
  pending: "En cola",
  leased: "Asignado",
  running: "En curso",
  succeeded: "Completado",
  failed: "Fallido",
  cancelled: "Cancelado",
  expired: "Expirado",
};

export const ENROLLMENT_STATE_LABELS: Record<SensorEnrollmentState, string> = {
  active: "Activo",
  consumed: "Usado",
  expired: "Expirado",
  revoked: "Revocado",
};
