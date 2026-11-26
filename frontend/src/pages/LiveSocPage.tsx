import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { siemApi } from "../api/siem";
import { useAuth } from "../auth/AuthContext";
import { SOURCE_STATE_LABELS } from "./SiemPage";
import { formatDateTime, formatRelative } from "../lib/format";
import { BUFFER_SIZE, useLiveStream, type LiveChannel, type LiveItem, type LiveState } from "../lib/liveStream";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

/**
 * Live SOC (Fase 7F.7). Solo datos reales que llegan por el stream SSE: nada simulado ni
 * rellenado. Los contadores cuentan lo recibido desde que se abrió la página; el feed guarda
 * los últimos 200 mensajes. Todo el texto viene de fuentes no confiables y se pinta como texto.
 */

export const STATE_LABELS: Record<LiveState, string> = {
  connecting: "Conectando…",
  connected: "En directo",
  reconnecting: "Reconectando…",
  disconnected: "Desconectado",
  degraded: "Degradado",
  catching_up: "Recuperando eventos pendientes…",
};

const REASONS: Record<string, string> = {
  backlog_skipped: "Había demasiados eventos pendientes: se muestra desde ahora (consulte las listas para el resto).",
  session_ended: "La sesión terminó o cambió de permisos. Vuelva a iniciar sesión.",
  connection_closed: "Conexión cerrada; se reintentará automáticamente.",
  network: "Conexión interrumpida; el navegador reintenta.",
  max_duration: "Renovando la conexión.",
};

const CHANNEL_LABELS: Record<LiveChannel, string> = {
  detection: "Detecciones",
  alert: "Alertas",
  incident: "Actividad de casos",
  siem: "Alertas SIEM",
};

function stateClass(state: LiveState): string {
  if (state === "connected") return "badge badge--ok";
  if (state === "disconnected") return "badge badge--crit";
  return "badge badge--warn";
}

function text(value: unknown): string {
  return typeof value === "string" || typeof value === "number" ? String(value) : "";
}

function itemLink(item: LiveItem): string | null {
  const id = encodeURIComponent(text(item.data.id));
  if (!id) return null;
  switch (item.channel) {
    case "detection":
      return `/detections/${id}`;
    case "incident":
      return `/incidents/${id}`;
    case "alert":
      return "/alerts";
    case "siem":
      return `/siem?tab=hunt&event=${id}`;
  }
}

function itemTitle(item: LiveItem): string {
  const d = item.data;
  switch (item.channel) {
    case "detection":
      return `${text(d.rule_id)}: ${text(d.title)} · ${text(d.asset_name)}`;
    case "alert":
      return `${text(d.message)} · ${text(d.asset_name)}`;
    case "incident":
      return `INC-${text(d.number).padStart(6, "0")} ${text(d.title)} · ${text(d.summary)}`;
    case "siem":
      return `${text(d.source_name)} · ${text(d.event_type)} · ${text(d.message)}`;
  }
}

function SourceHealth({ scopeId }: { scopeId: string | undefined }) {
  const fetchOverview = useCallback((signal: AbortSignal) => siemApi.overview(scopeId, 24, signal), [scopeId]);
  const overview = usePolling(fetchOverview, 30_000);
  if (!overview.data) return null;
  const states = Object.entries(overview.data.sources_by_status).filter(([, n]) => n > 0);
  return (
    <section className="panel panel--padded" aria-label="Fuentes SIEM">
      <h2>Fuentes SIEM</h2>
      {states.length === 0 ? (
        <p className="muted small">Sin fuentes registradas.</p>
      ) : (
        <ul className="small">
          {states.map(([state, n]) => (
            <li key={state}>
              {SOURCE_STATE_LABELS[state as keyof typeof SOURCE_STATE_LABELS] ?? state}: {n}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function LiveSocPage() {
  const auth = useAuth();
  const { scopeId } = useSite();
  const live = useLiveStream(scopeId);
  const [filter, setFilter] = useState<LiveChannel | "">("");
  const shown = filter ? live.items.filter((i) => i.channel === filter) : live.items;
  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Live SOC</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Eventos en directo desde la base de Sentra. Nada simulado.</span>
          </p>
        </div>
        <span className={stateClass(live.state)} role="status" aria-label="Estado del stream">
          {STATE_LABELS[live.state]}
        </span>
      </div>
      {live.reason && REASONS[live.reason] && <p className="banner banner--warn">{REASONS[live.reason]}</p>}
      <section className="panel panel--padded" aria-label="Recibido desde que abrió la página">
        <div className="actions">
          {live.channels.map((channel) => (
            <button
              key={channel}
              type="button"
              className={filter === channel ? "button button--primary" : "button"}
              aria-pressed={filter === channel}
              onClick={() => setFilter(filter === channel ? "" : channel)}
            >
              {CHANNEL_LABELS[channel]}: {live.counts[channel]}
            </button>
          ))}
        </div>
        <p className="muted small">Contadores desde que abrió esta página. El feed guarda los últimos {BUFFER_SIZE} mensajes.</p>
      </section>
      <section className="panel" aria-label="Feed en directo">
        {shown.length === 0 ? (
          <p className="muted small panel--padded">Sin eventos nuevos todavía.</p>
        ) : (
          <ul className="live-feed">
            {shown.map((item) => {
              const link = itemLink(item);
              return (
                <li key={item.key} className="small">
                  <span className="mono" title={formatDateTime(text(item.data.at) || new Date(item.receivedAt).toISOString())}>
                    {formatRelative(text(item.data.at) || new Date(item.receivedAt).toISOString())}
                  </span>{" "}
                  <span className="badge badge--muted">{CHANNEL_LABELS[item.channel]}</span>{" "}
                  <span className="badge">{text(item.data.severity)}</span>{" "}
                  {link ? <Link to={link}>{itemTitle(item)}</Link> : itemTitle(item)}
                </li>
              );
            })}
          </ul>
        )}
      </section>
      {auth.can("siem:read") && <SourceHealth scopeId={scopeId} />}
    </div>
  );
}
