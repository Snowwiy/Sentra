import { useCallback, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { aiApi, incidentsApi } from "../../api/sentra";
import { siemApi } from "../../api/siem";
import type { SiemEventDetail } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage, formatDateTime } from "../../lib/format";
import { saveBlob } from "../../lib/reports";
import { usePolling } from "../../lib/usePolling";
import { AIAnalyzePanel } from "../ai/AIAnalyzePanel";

/**
 * Investigación de un evento SIEM (Fase 7F.6): relacionados con su explicación, línea de
 * tiempo del activo, añadir a un caso, exportar evidencia y resumen con IA local. Nada de esto
 * cambia el evento: el servidor no tiene ninguna operación que lo modifique.
 */

const TIMELINE_SPAN_MS = 60 * 60 * 1000;

export function exportFilename(now: Date): string {
  return `sentra-siem-evidence-${now.toISOString().replace(/[:.]/g, "-")}.json`;
}

/** Descarga el paquete de evidencia tal cual lo devolvió el servidor (con su SHA-256). */
export async function downloadEvidence(eventIds: string[], reason?: string): Promise<string> {
  const bundle = await siemApi.exportEvents(eventIds, reason);
  saveBlob(new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" }), exportFilename(new Date()));
  return bundle.events_sha256;
}

function RelatedView({ eventId }: { eventId: string }) {
  const fetchRelated = useCallback((signal: AbortSignal) => siemApi.related(eventId, signal), [eventId]);
  const related = usePolling(fetchRelated, 0);
  if (related.loading) return <p className="muted small">Buscando relacionados…</p>;
  if (!related.data) return <p className="muted small">{related.error ? errorMessage(related.error) : ""}</p>;
  const { events, detections, note, window_minutes } = related.data;
  return (
    <section aria-label="Relacionados">
      <h3 className="small">Relacionados</h3>
      <p className="muted small">{note}</p>
      {events.length === 0 && detections.length === 0 && <p className="small">Nada relacionado.</p>}
      {events.length > 0 && (
        <ul className="small">
          {events.map((e) => (
            <li key={`${e.direction}-${e.event_id}`}>
              <strong>{e.source_name}</strong> <span className="mono">{e.event_type}</span> · {formatDateTime(e.timestamp)}
              {` · ${e.method} · confianza ${e.confidence}`}
              <div className="muted">{e.explanation}</div>
            </li>
          ))}
        </ul>
      )}
      {detections.length > 0 && (
        <>
          <h4 className="small">Detecciones del activo (±{window_minutes} min)</h4>
          <ul className="small">
            {detections.map((d) => (
              <li key={d.detection_id}>
                <Link to={`/detections/${encodeURIComponent(d.detection_id)}`}>
                  {d.rule_id}: {d.title}
                </Link>
                {` · ${d.asset_name} · `}
                <strong>{d.match === "topic" ? "mismo tema" : "solo coincide el tiempo"}</strong>
                <div className="muted">{d.explanation}</div>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  );
}

function TimelineView({ assetId, at }: { assetId: string; at: string }) {
  const fetchTimeline = useCallback(
    (signal: AbortSignal) => {
      const center = new Date(at).getTime();
      return siemApi.timeline(
        assetId,
        new Date(center - TIMELINE_SPAN_MS).toISOString(),
        new Date(center + TIMELINE_SPAN_MS).toISOString(),
        signal,
      );
    },
    [assetId, at],
  );
  const timeline = usePolling(fetchTimeline, 0);
  if (!timeline.data) return null;
  return (
    <section aria-label="Línea de tiempo del activo">
      <h3 className="small">Línea de tiempo del activo (±1 h)</h3>
      <ol className="small">
        {timeline.data.items.map((item) => (
          <li key={`${item.kind}-${item.ref}`}>
            <span className="mono">{formatDateTime(item.at)}</span> · {item.kind === "detection" ? "Detección" : "Evento SIEM"} ·{" "}
            {item.severity} · {item.source} · {item.title}
          </li>
        ))}
      </ol>
      {timeline.data.truncated && <p className="muted small">Hay más elementos: acote la ventana.</p>}
    </section>
  );
}

function AddToCase({ eventId }: { eventId: string }) {
  const fetchCases = useCallback(
    (signal: AbortSignal) => incidentsApi.list({ active: true, limit: 50, sort: "last_activity", order: "desc" }, signal),
    [],
  );
  const cases = usePolling(fetchCases, 0);
  const [incidentId, setIncidentId] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string>();
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!incidentId) return;
    setBusy(true);
    setMessage(undefined);
    try {
      await siemApi.attachToIncident(eventId, incidentId, note.trim() || undefined);
      setMessage("Añadido al caso como evidencia (copia con hash).");
    } catch (err) {
      setMessage(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="stack" aria-label="Añadir a un caso" onSubmit={(e) => void submit(e)}>
      <h3 className="small">Añadir a un caso</h3>
      <label className="small">
        Caso
        <select value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
          <option value="">Elegir un caso abierto…</option>
          {(cases.data?.items ?? []).map((c) => (
            <option key={c.incident_id} value={c.incident_id}>
              {c.key} · {c.title}
            </option>
          ))}
        </select>
      </label>
      <label className="small">
        Nota (opcional)
        <input value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
      </label>
      <div className="actions">
        <button type="submit" className="button" disabled={busy || !incidentId}>
          Añadir al caso
        </button>
      </div>
      {message && (
        <p className="small" role="status">
          {message}
        </p>
      )}
    </form>
  );
}

export function SiemInvestigation({ event }: { event: SiemEventDetail }) {
  const auth = useAuth();
  const [exported, setExported] = useState<string>();
  const [exportError, setExportError] = useState<string>();
  const runAI = useCallback((refresh: boolean) => aiApi.analyzeSiemEvent(event.event_id, refresh), [event.event_id]);
  const exportOne = async () => {
    setExportError(undefined);
    try {
      setExported(await downloadEvidence([event.event_id]));
    } catch (err) {
      setExportError(err instanceof Error ? errorMessage(err) : String(err));
    }
  };
  return (
    <div className="stack">
      <RelatedView eventId={event.event_id} />
      {event.asset && <TimelineView assetId={event.asset.asset_id} at={event.timestamp} />}
      <section aria-label="Exportar evidencia" className="stack">
        <div className="actions">
          <button type="button" className="button" onClick={() => void exportOne()}>
            Exportar evidencia (JSON)
          </button>
        </div>
        {exported && <p className="small mono">SHA-256 del paquete: {exported}</p>}
        {exportError && (
          <p className="small" role="alert">
            {exportError}
          </p>
        )}
      </section>
      {auth.can("incidents:manage") && <AddToCase eventId={event.event_id} />}
      <AIAnalyzePanel
        title="IA · Resumir evento"
        buttonLabel="Resumir con IA"
        kind="siem_event_analysis"
        skipCached
        run={runAI}
      />
    </div>
  );
}
