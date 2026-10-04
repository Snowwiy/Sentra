import type { AssetStatus } from "../api/types";

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
