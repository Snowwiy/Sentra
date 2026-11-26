import { useCallback } from "react";
import { Link } from "react-router-dom";
import { siemApi } from "../../api/siem";
import type { SiemAttribution, SiemEventDetail, SiemEventLinkRead } from "../../api/types";
import { errorMessage, formatDateTime } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { Modal } from "../Modal";
import { ErrorState, LoadingState } from "../StateViews";
import { SiemInvestigation } from "./SiemInvestigation";

/**
 * Detalle de un evento SIEM normalizado (Fase 7F). Todo el contenido viene de una fuente
 * externa: se muestra como texto (React escapa); los valores que parecen URLs no se enlazan y
 * nada se interpreta. El extracto del registro original es evidencia, no instrucciones.
 */

const TIME_QUALITY: Record<string, string> = {
  source: "hora del propio evento",
  receiver: "el evento no traía hora: se usa la de recepción",
  clamped: "el evento decía estar en el futuro: recortada a la de recepción",
};

function Row({ label, value }: { label: string; value: string | number | null | undefined }) {
  if (value === null || value === undefined || value === "") return null;
  return (
    <>
      <dt>{label}</dt>
      <dd className="mono small">{String(value)}</dd>
    </>
  );
}

export function SiemEventFields({ event }: { event: SiemEventDetail }) {
  return (
    <dl className="fields">
      <Row label="Fuente" value={`${event.source_name} (${event.source_type})`} />
      <Row label="Tipo" value={`${event.event_type} · ${event.category}`} />
      <Row label="Hora del evento" value={`${formatDateTime(event.timestamp)} (${TIME_QUALITY[event.time_quality] ?? event.time_quality})`} />
      <Row label="Recibido" value={formatDateTime(event.received_at)} />
      <Row label="Severidad" value={`${event.severity}${event.source_severity ? ` (origen: ${event.source_severity})` : ""}`} />
      <Row label="Confianza" value={event.confidence} />
      <Row label="Equipo (según la fuente)" value={event.hostname} />
      <Row label="Origen" value={event.source_ip ? `${event.source_ip}${event.source_port !== null ? `:${event.source_port}` : ""}` : null} />
      <Row
        label="Destino"
        value={event.destination_ip ? `${event.destination_ip}${event.destination_port !== null ? `:${event.destination_port}` : ""}` : null}
      />
      <Row label="Protocolo" value={event.protocol} />
      <Row label="Usuario" value={event.username} />
      <Row label="Proceso" value={event.process_name} />
      <Row label="Acción" value={event.action} />
      <Row label="Resultado" value={event.outcome} />
      <Row label="Firma" value={event.signature_id} />
      <Row label="Regla de origen" value={event.rule_id} />
      <Row label="MITRE ATT&CK (según la fuente)" value={event.mitre_techniques.join(", ")} />
      <Row label="Etiquetas" value={event.tags.join(", ")} />
      <Row label="Id externo" value={event.external_id} />
      <Row label="Referencia de flujo" value={event.flow_ref} />
      <Row label="Activo" value={event.asset ? event.asset.name : "Sin atribuir (evidencia insuficiente)"} />
      <Row label="Mensaje" value={event.message} />
      <Row label="Referencia del registro" value={event.raw_reference} />
      <Row label="SHA-256 del registro" value={event.evidence_hash} />
      <Row label="Normalización" value={`${event.normalization_version} · esquema v${event.schema_version}`} />
    </dl>
  );
}

const VERDICTS: Record<string, string> = {
  attributed: "Atribuido a un activo",
  multiple: "Varios activos implicados (cada uno con su rol)",
  ambiguous: "Ambiguo: la IP la comparten varios activos",
  hostname_hint: "Sin atribuir: solo coincide el nombre de equipo (pista, no identidad)",
  insufficient_evidence: "Sin atribuir: evidencia insuficiente",
};
const ROLES: Record<string, string> = {
  source: "origen",
  destination: "destino",
  reporter: "emisor del registro",
  host: "nombre de equipo (pista débil)",
};
const LINK_KINDS: Record<string, string> = {
  ndr_flow: "Flujo NDR",
  ndr_anomaly: "Anomalía NDR",
  siem_event: "Evento SIEM",
  detection: "Detección nativa de Sentra",
};
const ORIGINS: Record<string, string> = {
  imported: "Importada: alerta externa con activo atribuido, sin corroborar",
  correlated: "Correlacionada: el NDR de Sentra vio la misma comunicación",
  probable_match: "Probablemente la misma que una detección nativa de Sentra: no se crea otra",
  insufficient_evidence: "Evidencia insuficiente: sin activo atribuible, no genera detección",
};

function text(value: unknown): string | null {
  if (typeof value === "string" || typeof value === "number") return String(value);
  if (Array.isArray(value)) return value.filter((v) => typeof v === "string").join(", ") || null;
  return null;
}

/** Procedencia de una alerta de Wazuh: lo que dice Wazuh, tal cual, sin reinterpretarlo. */
export function WazuhProvenance({ event }: { event: SiemEventDetail }) {
  if (event.source_type !== "wazuh_alerts" || !event.data) return null;
  const d = event.data;
  return (
    <section aria-label="Procedencia Wazuh">
      <h3 className="small">Según Wazuh</h3>
      <dl className="fields">
        <Row label="Id de la alerta" value={text(d.alert_id)} />
        <Row label="Regla" value={event.rule_id} />
        <Row label="Nivel" value={text(d.rule_level)} />
        <Row label="Grupos" value={text(d.rule_groups)} />
        <Row label="Agente" value={[text(d.agent_id), text(d.agent_name), text(d.agent_ip)].filter(Boolean).join(" · ") || null} />
        <Row label="Manager" value={text(d.manager)} />
        <Row label="Decoder" value={text(d.decoder)} />
        <Row label="Ubicación" value={text(d.location)} />
        <Row label="Táctica MITRE" value={text(d.mitre_tactic_names)} />
      </dl>
      <p className="muted small">El nombre del agente es una pista: no identifica el activo por sí solo.</p>
    </section>
  );
}

export function SiemAttributionView({ attribution }: { attribution: SiemAttribution | null }) {
  if (!attribution) return null;
  return (
    <section aria-label="Atribución">
      <h3 className="small">Atribución</h3>
      <p className="small">{VERDICTS[attribution.verdict] ?? attribution.verdict}</p>
      {attribution.origin && <p className="small">Origen de la alerta: {ORIGINS[attribution.origin] ?? attribution.origin}</p>}
      {attribution.candidates.length > 0 && (
        <ul className="small">
          {attribution.candidates.map((c, index) => (
            <li key={`${c.role}-${index}`}>
              {c.asset_id ? <Link to={`/assets/${c.asset_id}`}>{c.asset_name ?? c.asset_id}</Link> : "activo eliminado"}
              {` · ${ROLES[c.role] ?? c.role} · ${c.method} (${c.confidence}) · `}
              <span className="mono">{c.value}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function SiemLinksView({ links }: { links: SiemEventLinkRead[] }) {
  if (links.length === 0) return null;
  return (
    <section aria-label="Relacionado">
      <h3 className="small">Relacionado (no implica causalidad)</h3>
      <ul className="small">
        {links.map((link) => (
          <li key={`${link.kind}-${link.target_ref}`}>
            <strong>{LINK_KINDS[link.kind] ?? link.kind}</strong>{" "}
            {link.kind === "detection" ? (
              <Link className="mono" to={`/detections/${encodeURIComponent(link.target_ref)}`}>
                {link.target_ref}
              </Link>
            ) : (
              <span className="mono">{link.target_ref}</span>
            )}
            {` · ${link.method} · confianza ${link.confidence}`}
            <div className="muted">{link.explanation}</div>
          </li>
        ))}
      </ul>
    </section>
  );
}

export function SiemEventDetailModal({ eventId, onClose }: { eventId: string; onClose: () => void }) {
  const fetchEvent = useCallback((signal: AbortSignal) => siemApi.event(eventId, signal), [eventId]);
  const event = usePolling(fetchEvent, 0);
  return (
    <Modal title="Evento SIEM" onClose={onClose}>
      {event.loading ? (
        <LoadingState label="Cargando evento…" />
      ) : !event.data ? (
        <ErrorState message={event.error ? errorMessage(event.error) : ""} onRetry={event.refresh} />
      ) : (
        <div className="stack">
          <SiemEventFields event={event.data} />
          <WazuhProvenance event={event.data} />
          <SiemAttributionView attribution={event.data.attribution} />
          <SiemLinksView links={event.data.links} />
          {event.data.raw_excerpt && (
            <section aria-label="Extracto del registro original">
              <h3 className="small">Extracto del registro original (dato no confiable)</h3>
              <pre className="code-block small">{event.data.raw_excerpt}</pre>
            </section>
          )}
          <SiemInvestigation event={event.data} />
        </div>
      )}
    </Modal>
  );
}
