import type {
  WlanApReportedStatus,
  WlanAuthorizationStatus,
  WlanConfigFinding,
  WlanFindingCode,
  WlanFreshness,
  WlanProtection,
} from "../../api/types";
import {
  AP_STATUS_LABELS,
  AUTHORIZATION_HELP,
  AUTHORIZATION_LABELS,
  FINDING_LABELS,
  FRESHNESS_HELP,
  FRESHNESS_LABELS,
  INSECURE_PROTECTIONS,
  PROTECTION_LABELS,
} from "../../lib/wlan";

const AUTHORIZATION_CLASS: Record<WlanAuthorizationStatus, string> = {
  authorized: "badge badge--ok",
  external: "badge badge--info",
  // "Sin clasificar" es neutro: no clasificado no significa hostil.
  unknown: "badge badge--muted",
};

export function AuthorizationBadge({ status }: { status: WlanAuthorizationStatus }) {
  return (
    <span className={AUTHORIZATION_CLASS[status] ?? "badge badge--muted"} title={AUTHORIZATION_HELP[status]}>
      {AUTHORIZATION_LABELS[status] ?? status}
    </span>
  );
}

const FRESHNESS_CLASS: Record<WlanFreshness, string> = {
  recent: "badge badge--ok",
  historical: "badge badge--warn",
};

/**
 * Frescura de la evidencia y, solo si la API lo marca (`present = false`), ausencia en la
 * última consulta completa. "Histórico" nunca se presenta como desaparecido.
 */
export function EvidenceBadges({ freshness, present }: { freshness: WlanFreshness; present: boolean }) {
  return (
    <span className="wlan-badges">
      <span className={FRESHNESS_CLASS[freshness] ?? "badge badge--muted"} title={FRESHNESS_HELP[freshness]}>
        {FRESHNESS_LABELS[freshness] ?? freshness}
      </span>
      {!present && (
        <span
          className="badge badge--muted"
          title="La última consulta completa de su fuente ya no lo informó. No se borra: queda como historial."
        >
          No visto en la última consulta completa
        </span>
      )}
    </span>
  );
}

const AP_STATUS_CLASS: Record<WlanApReportedStatus, string> = {
  up: "status status--online",
  down: "status status--offline",
  transitional: "status status--pending",
  unknown: "status status--unknown",
};

/** Estado que informa la controladora o el AP, no una comprobación propia de Sentra. */
export function ApStatusBadge({ status }: { status: WlanApReportedStatus }) {
  return (
    <span className={AP_STATUS_CLASS[status] ?? "status status--unknown"} title="Estado informado por el equipo por SNMP">
      <span className="status__dot" aria-hidden="true" />
      {AP_STATUS_LABELS[status] ?? status}
    </span>
  );
}

/** Protección normalizada; las inseguras llevan un aviso informativo (sin acción asociada). */
export function ProtectionLabel({
  protection,
  reported,
}: {
  protection: WlanProtection | null;
  reported?: string | null;
}) {
  if (!protection) return <span className="muted">no informada</span>;
  const insecure = INSECURE_PROTECTIONS.has(protection) || Boolean(reported && /tkip/i.test(reported));
  return (
    <span className="wlan-badges" title={reported ? `Informado: ${reported}` : undefined}>
      <span>{PROTECTION_LABELS[protection] ?? protection}</span>
      {insecure && <span className="badge badge--warn">Insegura</span>}
    </span>
  );
}

/** Lista de configuraciones inseguras como avisos informativos. */
export function FindingBadges({ findings }: { findings: (WlanConfigFinding | WlanFindingCode)[] }) {
  if (findings.length === 0) return null;
  return (
    <span className="wlan-badges">
      {findings.map((finding) => {
        const code = typeof finding === "string" ? finding : finding.code;
        const detail = typeof finding === "string" ? undefined : finding.detail;
        return (
          <span
            key={code}
            className="badge badge--warn"
            title={detail ? `${detail} (informativo, no afecta al riesgo)` : "Informativo, no afecta al riesgo"}
          >
            {FINDING_LABELS[code] ?? code}
          </span>
        );
      })}
    </span>
  );
}

/**
 * MAC (o BSSID) con el aviso de aleatoria: una MAC localmente administrada no identifica un
 * dispositivo, así que se marca y nunca se usa como nombre.
 */
export function MacText({ mac, randomized }: { mac: string | null; randomized: boolean }) {
  if (!mac) return <span className="muted">—</span>;
  return (
    <span className="wlan-badges">
      <span className="mono">{mac}</span>
      {randomized && (
        <span className="badge badge--muted" title="MAC localmente administrada (aleatoria): no identifica el dispositivo">
          MAC aleatoria
        </span>
      )}
    </span>
  );
}
