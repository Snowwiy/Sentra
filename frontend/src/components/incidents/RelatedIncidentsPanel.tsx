// "Incidentes" en el detalle de una detección o alerta (Fase 4K): sugiere casos abiertos
// posiblemente relacionados y permite adjuntar o crear uno nuevo. La deduplicación es solo
// una sugerencia: nada se adjunta ni se fusiona sin que el analista lo pida.
import { useCallback, useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { incidentsApi } from "../../api/sentra";
import type { RelatedIncidentList } from "../../api/types";
import { useAuth } from "../../auth/AuthContext";
import { errorMessage } from "../../lib/format";
import { LEVEL_LABELS, linkedIncident, REASON_LABELS, STATUS_LABELS } from "../../lib/incidents";

export function RelatedIncidentsPanel({ source, id }: { source: "detection" | "alert"; id: string }) {
  const auth = useAuth();
  const navigate = useNavigate();
  const [data, setData] = useState<RelatedIncidentList>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [linked, setLinked] = useState<{ incidentId: string; key: string }>();
  const allowed = auth.can("incidents:read");
  const canManage = auth.can("incidents:manage");

  const load = useCallback(
    (signal?: AbortSignal) =>
      (source === "detection" ? incidentsApi.relatedToDetection(id, signal) : incidentsApi.relatedToAlert(id, signal))
        .then(setData)
        .catch((err: unknown) => {
          if (!signal?.aborted) setError(err instanceof Error ? errorMessage(err) : String(err));
        }),
    [source, id],
  );
  useEffect(() => {
    if (!allowed) return;
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [allowed, load]);

  async function act(action: () => Promise<{ incident_id: string }>) {
    setBusy(true);
    setError(undefined);
    try {
      const incident = await action();
      navigate(`/incidents/${incident.incident_id}`);
    } catch (err) {
      const existing = linkedIncident(err);
      if (existing) setLinked(existing);
      else setError(err instanceof Error ? errorMessage(err) : String(err));
      setBusy(false);
    }
  }

  if (!allowed) return null;
  const items = data?.items ?? [];
  const already = items.find((item) => item.reasons.includes("already_linked"));
  return (
    <section className="panel panel--padded" aria-label="Incidentes">
      <h2>Incidentes</h2>
      {already && (
        <p>
          Ya vinculada a{" "}
          <Link to={`/incidents/${already.incident.incident_id}`}>
            {already.incident.key} · {already.incident.title}
          </Link>
          .
        </p>
      )}
      {items.filter((item) => item !== already).length > 0 && (
        <>
          <p className="muted small">Posibles incidentes relacionados (sugerencia, no se adjunta nada solo):</p>
          <ul className="related-list">
            {items
              .filter((item) => item !== already)
              .map((item) => (
                <li key={item.incident.incident_id}>
                  <span>
                    <Link to={`/incidents/${item.incident.incident_id}`} className="incident-key">
                      {item.incident.key}
                    </Link>{" "}
                    {item.incident.title}{" "}
                    <span className="muted small">
                      ({STATUS_LABELS[item.incident.status]} ·{" "}
                      {item.reasons.map((r) => REASON_LABELS[r] ?? r).join(", ")})
                    </span>
                  </span>
                  {canManage && (
                    <button
                      type="button"
                      className="button button--small"
                      disabled={busy}
                      onClick={() =>
                        void act(() =>
                          source === "detection"
                            ? incidentsApi.attachDetection(item.incident.incident_id, id)
                            : incidentsApi.attachAlert(item.incident.incident_id, id),
                        )
                      }
                    >
                      Adjuntar
                    </button>
                  )}
                </li>
              ))}
          </ul>
        </>
      )}
      {data && items.length === 0 && <p className="muted small">No hay incidentes abiertos relacionados.</p>}
      {canManage && data && !already && (
        <div className="actions">
          <button
            type="button"
            className="button button--primary"
            disabled={busy}
            onClick={() =>
              void act(() => (source === "detection" ? incidentsApi.fromDetection(id) : incidentsApi.fromAlert(id)))
            }
          >
            Crear incidente
          </button>
          <span className="muted small">
            Prioridad sugerida: {LEVEL_LABELS[data.suggested_priority]} (severidad {LEVEL_LABELS[data.suggested_severity]}
            ).
          </span>
        </div>
      )}
      {linked && (
        <p className="banner banner--warn" role="alert">
          Ya está vinculada a <Link to={`/incidents/${linked.incidentId}`}>{linked.key}</Link>.
        </p>
      )}
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
    </section>
  );
}
