import type {
  DeviceClassification,
  DeviceClassificationConfidence,
  EvidenceFreshness,
  MonitoringStatus,
} from "../../api/types";
import {
  CLASSIFICATION_LABELS,
  CONFIDENCE_LABELS,
  FRESHNESS_HELP,
  FRESHNESS_LABELS,
  MONITORING_STATUS_HELP,
  MONITORING_STATUS_LABELS,
  monitoringStatusClass,
} from "../../lib/network";

/** Estado de monitorización SNMP (nunca "online": solo el resultado de las consultas). */
export function MonitoringBadge({ status }: { status: MonitoringStatus }) {
  return (
    <span className={`status ${monitoringStatusClass(status)}`} title={MONITORING_STATUS_HELP[status]}>
      <span className="status__dot" aria-hidden="true" />
      {MONITORING_STATUS_LABELS[status] ?? status}
    </span>
  );
}

const FRESHNESS_CLASS: Record<EvidenceFreshness, string> = {
  recent: "badge badge--ok",
  historical: "badge badge--warn",
  none: "badge badge--muted",
};

export function FreshnessBadge({ freshness }: { freshness: EvidenceFreshness }) {
  return (
    <span className={FRESHNESS_CLASS[freshness] ?? "badge badge--muted"} title={FRESHNESS_HELP[freshness]}>
      {FRESHNESS_LABELS[freshness] ?? freshness}
    </span>
  );
}

export function ClassificationLabel({
  classification,
  confidence,
}: {
  classification: DeviceClassification;
  confidence: DeviceClassificationConfidence;
}) {
  return (
    <span>
      {CLASSIFICATION_LABELS[classification] ?? classification}
      <span className="muted small"> · {CONFIDENCE_LABELS[confidence] ?? confidence}</span>
    </span>
  );
}
