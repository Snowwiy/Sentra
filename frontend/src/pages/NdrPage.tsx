import { useCallback, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { ndrApi } from "../api/ndr";
import type {
  NdrAnomalyRead,
  NdrAnomalyStatus,
  NdrAnomalyVerdict,
  NdrCaptureState,
  NdrIncidentRef,
  NdrMitreRead,
  NdrObservationKind,
  NdrResponseSuggestion,
  NdrSensorRead,
  NdrSuggestionKind,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect, Pager, SearchInput, Toolbar } from "../components/ListControls";
import { Modal } from "../components/Modal";
import { RouteTabs } from "../components/RouteTabs";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatBytes, formatDateTime, formatRelative } from "../lib/format";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

/**
 * Network Detection & Response (Fase 7E). Sensores pasivos: qué capturan, qué ven y qué
 * anomalías de red han encontrado. La captura nunca empieza sola: un admin la aprueba por
 * sensor indicando el punto de observación (SPAN/TAP) y confirmando que es pasiva y está
 * autorizada. Flujos y metadatos exigen ndr:evidence; el triaje, ndr:triage.
 */

const PAGE_SIZE = 50;

export const VERDICT_LABELS: Record<NdrAnomalyVerdict, string> = {
  observed: "Observado",
  suspicious: "Sospechoso",
  probable: "Probable",
  confirmed: "Confirmado",
};

export const STATUS_LABELS: Record<NdrAnomalyStatus, string> = {
  open: "Abierta",
  acknowledged: "Reconocida",
  resolved: "Resuelta",
  false_positive: "Falso positivo",
};

const CAPTURE_LABELS: Record<NdrCaptureState, string> = {
  disabled: "Desactivada",
  not_configured: "Sin configurar",
  starting: "Arrancando",
  running: "Capturando",
  degraded: "Degradada",
  error: "Error",
};

const CATEGORY_LABELS: Record<string, string> = {
  arp: "ARP",
  mitm: "MITM",
  dns: "DNS",
  dhcp: "DHCP",
  scan: "Escaneo",
  protocol: "Protocolos",
  lateral: "Movimiento lateral",
  behavior: "Comportamiento",
  threat_intel: "Threat Intel",
};

const OBSERVATION_LABELS: Record<NdrObservationKind, string> = {
  arp: "ARP",
  dns: "DNS",
  dhcp: "DHCP",
  tls: "TLS (SNI)",
};

function verdictClass(verdict: NdrAnomalyVerdict): string {
  if (verdict === "confirmed" || verdict === "probable") return "badge badge--crit";
  if (verdict === "suspicious") return "badge badge--warn";
  return "badge badge--muted";
}

function captureClass(state: NdrCaptureState | null): string {
  if (state === "running") return "badge badge--ok";
  if (state === "degraded" || state === "starting") return "badge badge--warn";
  if (state === "error") return "badge badge--crit";
  return "badge badge--muted";
}

export function VerdictBadge({ verdict }: { verdict: NdrAnomalyVerdict }) {
  return <span className={verdictClass(verdict)}>{VERDICT_LABELS[verdict] ?? verdict}</span>;
}

function MitreText({ mitre }: { mitre: NdrMitreRead | null }) {
  if (!mitre) return <span className="muted">Sin técnica asociada</span>;
  return (
    <span className="mono">
      {mitre.tactic} · {mitre.subtechnique ?? mitre.technique}
    </span>
  );
}

function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

// --- Resumen y sensores ---------------------------------------------------------------------

/** Aprobar la captura de un sensor: aliases de interfaz, punto de observación y confirmación. */
function CaptureModal({ sensor, onClose, onDone }: { sensor: NdrSensorRead; onClose: () => void; onDone: () => void }) {
  const current = sensor.config;
  const reported = sensor.interfaces.map((i) => i.name);
  const [enabled, setEnabled] = useState(current?.enabled ?? true);
  const [interfaces, setInterfaces] = useState((current?.interfaces ?? reported).join(", "));
  const [point, setPoint] = useState(current?.observation_point ?? "");
  const [dns, setDns] = useState(current?.dns_metadata ?? false);
  const [tls, setTls] = useState(current?.tls_metadata ?? false);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const aliases = interfaces
    .split(",")
    .map((alias) => alias.trim())
    .filter(Boolean);
  const valid = !enabled || (aliases.length > 0 && point.trim().length >= 3 && confirmed);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(undefined);
    try {
      await ndrApi.updateConfig(sensor.sensor_id, {
        enabled,
        interfaces: aliases,
        observation_point: point.trim() || null,
        confirm_passive_authorized: confirmed,
        dns_metadata: dns,
        tls_metadata: tls,
        expected_revision: current?.revision ?? 0,
      });
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
      // Otro admin cambió la configuración: se recarga para que se vea la revisión actual.
      if (err instanceof ApiError && err.code === "ndr_config_changed") onDone();
    }
  };

  return (
    <Modal title={`Captura NDR de ${sensor.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p className="muted small">
          El sensor solo escucha copias del tráfico (puerto SPAN o TAP): nunca inyecta paquetes, ni guarda contenido,
          ni descifra TLS. Las interfaces se indican por su alias de <span className="mono">sensor.toml</span>; el
          nombre del dispositivo nunca sale del sensor.
        </p>
        <label className="checkbox">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} /> Captura habilitada
        </label>
        <label>
          <span>Interfaces (alias, separados por comas)</span>
          <input className="input" value={interfaces} onChange={(e) => setInterfaces(e.target.value)} />
        </label>
        <label>
          <span>Punto de observación</span>
          <input
            className="input"
            value={point}
            maxLength={200}
            placeholder="SPAN del switch core, puerto 24"
            onChange={(e) => setPoint(e.target.value)}
          />
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={dns} onChange={(e) => setDns(e.target.checked)} /> Metadatos DNS (nombres
          consultados)
        </label>
        <label className="checkbox">
          <input type="checkbox" checked={tls} onChange={(e) => setTls(e.target.checked)} /> Metadatos TLS (SNI del
          saludo, sin descifrar)
        </label>
        {enabled && (
          <label className="checkbox">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} /> Confirmo
            que la captura es pasiva y está autorizada en este segmento
          </label>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cancelar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !valid}>
            {busy ? "Guardando…" : "Guardar configuración"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

function OverviewTab({ scopeId }: { scopeId: string | undefined }) {
  const auth = useAuth();
  const canManage = auth.can("ndr:manage");
  const [hours, setHours] = useState(24);
  const fetchOverview = useCallback((signal: AbortSignal) => ndrApi.overview(scopeId, hours, signal), [scopeId, hours]);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs, true, true);
  const fetchSensors = useCallback((signal: AbortSignal) => ndrApi.sensors(scopeId, signal), [scopeId]);
  const sensors = usePolling(fetchSensors, config.refreshIntervalMs);
  const [editing, setEditing] = useState<NdrSensorRead>();

  if (overview.loading || sensors.loading) return <LoadingState label="Cargando NDR…" />;
  if (!overview.data && overview.error) return <ErrorState message={errorMessage(overview.error)} onRetry={overview.refresh} />;
  const data = overview.data;
  const items = sensors.data?.items ?? [];
  return (
    <>
      {data && (
        <section className="stats stats--6" aria-label="Resumen NDR">
          <div className="stat">
            <span className="stat__label">Sensores capturando</span>
            <span className="stat__value">
              {data.sensors_capturing}/{data.sensors_enabled}
            </span>
          </div>
          <div className="stat">
            <span className="stat__label">Degradados</span>
            <span className="stat__value">{data.sensors_degraded}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Flujos ({data.window_hours} h)</span>
            <span className="stat__value">{data.flows}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Volumen</span>
            <span className="stat__value">{formatBytes(data.bytes)}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Paquetes vistos</span>
            <span className="stat__value">{data.packets_seen}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Descartados</span>
            <span className="stat__value">{data.packets_dropped}</span>
          </div>
        </section>
      )}
      <section className="panel" aria-label="Sensores NDR">
        <div className="panel__toolbar">
          <h2>Sensores</h2>
          <FilterSelect
            label="Ventana"
            value={String(hours)}
            allLabel="24 h"
            options={[
              { value: "1", label: "1 h" },
              { value: "168", label: "7 días" },
            ]}
            onChange={(value) => setHours(Number(value) || 24)}
          />
        </div>
        {items.length === 0 ? (
          <EmptyState title="Ningún sensor declara captura NDR">
            Un sensor 0.8.0 o posterior con un bloque [ndr] en su sensor.toml aparece aquí para aprobar su captura.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Sensor</th>
                  <th>Site</th>
                  <th>Captura</th>
                  <th>Interfaces</th>
                  <th>Punto de observación</th>
                  <th>Último lote</th>
                  <th>Paquetes 24 h</th>
                  <th>Descartes 24 h</th>
                  {canManage && <th aria-label="Acciones" />}
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.sensor_id}>
                    <td>
                      {s.name}
                      {!s.capable && <span className="muted small"> · sin capacidad NDR</span>}
                    </td>
                    <td>{s.site_name}</td>
                    <td>
                      <span className={captureClass(s.capture_state)}>
                        {s.capture_state ? CAPTURE_LABELS[s.capture_state] : "Sin informar"}
                      </span>
                      {s.config && !s.config.enabled && <span className="muted small"> · no aprobada</span>}
                    </td>
                    <td className="mono small">
                      {s.interfaces.length > 0
                        ? s.interfaces.map((i) => `${i.name}${i.backend ? ` (${i.backend})` : ""}`).join(", ")
                        : (s.config?.interfaces.join(", ") ?? "—")}
                    </td>
                    <td className="small">{s.config?.observation_point ?? "—"}</td>
                    <td title={formatDateTime(s.last_batch_at)}>{formatRelative(s.last_batch_at)}</td>
                    <td>{s.packets_24h}</td>
                    <td>{s.dropped_24h}</td>
                    {canManage && (
                      <td>
                        <button
                          type="button"
                          className="button button--small"
                          disabled={!s.capable}
                          onClick={() => setEditing(s)}
                        >
                          {s.config?.enabled ? "Configurar" : "Aprobar captura"}
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {data && data.top_talkers.length > 0 && (
        <section className="panel" aria-label="Equipos con más tráfico">
          <div className="panel__toolbar">
            <h2>Equipos con más tráfico</h2>
          </div>
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Flujos</th>
                  <th>Volumen</th>
                </tr>
              </thead>
              <tbody>
                {data.top_talkers.map((t) => (
                  <tr key={t.ip}>
                    <td className="mono">{t.ip}</td>
                    <td>{t.flows}</td>
                    <td>{formatBytes(t.bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
      {editing && <CaptureModal sensor={editing} onClose={() => setEditing(undefined)} onDone={sensors.refresh} />}
    </>
  );
}

// --- Anomalías ------------------------------------------------------------------------------

function TriageForm({ anomaly, onDone }: { anomaly: NdrAnomalyRead; onDone: () => void }) {
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const closed = anomaly.status === "resolved" || anomaly.status === "false_positive";
  if (closed) return null;
  const act = async (status: Exclude<NdrAnomalyStatus, "open">) => {
    setBusy(true);
    setError(undefined);
    try {
      await ndrApi.setStatus(anomaly.anomaly_id, status, note);
      setNote("");
      onDone();
    } catch (err) {
      setError(errorMessage(asError(err)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="stack">
      <label>
        <span>Nota (obligatoria para cerrar)</span>
        <textarea className="input" value={note} maxLength={500} onChange={(e) => setNote(e.target.value)} />
      </label>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      <div className="modal__actions">
        {anomaly.status === "open" && (
          <button type="button" className="button" disabled={busy} onClick={() => void act("acknowledged")}>
            Reconocer
          </button>
        )}
        <button type="button" className="button" disabled={busy || !note.trim()} onClick={() => void act("false_positive")}>
          Falso positivo
        </button>
        <button
          type="button"
          className="button button--primary"
          disabled={busy || !note.trim()}
          onClick={() => void act("resolved")}
        >
          Resolver
        </button>
      </div>
    </div>
  );
}

const SUGGESTION_KIND_LABELS: Record<NdrSuggestionKind, string> = {
  network_control: "Solicitud de control",
  manual: "Paso manual",
  playbook: "Playbook",
};

function ControlRequestForm({
  anomalyId,
  suggestion,
  incidents,
}: {
  anomalyId: string;
  suggestion: NdrResponseSuggestion;
  incidents: NdrIncidentRef[];
}) {
  const [incidentId, setIncidentId] = useState(incidents[0]?.incident_id ?? "");
  const [justification, setJustification] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [done, setDone] = useState<string>();
  if (incidents.length === 0) {
    return (
      <p className="small muted">
        Para registrar la solicitud, la detección de la anomalía debe formar parte de un incidente.
      </p>
    );
  }
  if (done) {
    return (
      <p className="small" role="status">
        Solicitud registrada en el <Link to={`/incidents/${done}`}>incidente</Link>, pendiente de aprobación.
      </p>
    );
  }
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(undefined);
    try {
      await ndrApi.requestControl(anomalyId, {
        incident_id: incidentId,
        suggestion_id: suggestion.suggestion_id,
        justification: justification.trim(),
      });
      setDone(incidentId);
    } catch (err) {
      setError(errorMessage(asError(err)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <form className="stack" onSubmit={(e) => void submit(e)}>
      <label>
        <span>Incidente</span>
        <select className="input" value={incidentId} onChange={(e) => setIncidentId(e.target.value)}>
          {incidents.map((i) => (
            <option key={i.incident_id} value={i.incident_id}>
              #{i.number} {i.title}
            </option>
          ))}
        </select>
      </label>
      <label>
        <span>Justificación (mínimo 10 caracteres)</span>
        <textarea
          className="input"
          value={justification}
          maxLength={4000}
          onChange={(e) => setJustification(e.target.value)}
        />
      </label>
      {error && (
        <div className="banner banner--warn" role="alert">
          {error}
        </div>
      )}
      <div className="modal__actions">
        <button
          type="submit"
          className="button button--primary"
          disabled={busy || !incidentId || justification.trim().length < 10}
        >
          Registrar solicitud
        </button>
      </div>
    </form>
  );
}

function ResponsePlanSection({ anomalyId }: { anomalyId: string }) {
  const auth = useAuth();
  const fetchPlan = useCallback((signal: AbortSignal) => ndrApi.responsePlan(anomalyId, signal), [anomalyId]);
  // Mismo ritmo que el detalle: el plan cambia con la evidencia y los incidentes vinculados.
  const plan = usePolling(fetchPlan, config.refreshIntervalMs);
  const canRequest = auth.can("incidents:manage");
  return (
    <div className="stack" aria-label="Respuesta sugerida">
      <h3>Respuesta sugerida</h3>
      {plan.loading ? (
        <LoadingState label="Cargando plan de respuesta…" />
      ) : !plan.data ? (
        <ErrorState message={plan.error ? errorMessage(plan.error) : "Sin plan"} onRetry={plan.refresh} />
      ) : (
        <>
          <p className="small muted">{plan.data.note}</p>
          {plan.data.suggestions.length === 0 ? (
            <p className="small">La evidencia de esta anomalía no sugiere ninguna acción concreta.</p>
          ) : (
            plan.data.suggestions.map((s) => (
              <article key={s.suggestion_id} className="stack" aria-label={s.title}>
                <h4>
                  {s.title} <span className="badge">{SUGGESTION_KIND_LABELS[s.kind]}</span>
                </h4>
                <p className="small">{s.rationale}</p>
                {s.instructions.length > 0 && (
                  <ol className="small">
                    {s.instructions.map((step) => (
                      <li key={step}>{step}</li>
                    ))}
                  </ol>
                )}
                {s.kind === "network_control" && canRequest && (
                  <ControlRequestForm anomalyId={anomalyId} suggestion={s} incidents={plan.data!.incidents} />
                )}
                {s.kind === "playbook" && (
                  <p className="small">
                    Ejecútalo desde <Link to="/response">Respuesta</Link> sobre el activo atribuido.
                  </p>
                )}
              </article>
            ))
          )}
        </>
      )}
    </div>
  );
}

function AnomalyDetail({ anomalyId, onClose, onChanged }: { anomalyId: string; onClose: () => void; onChanged: () => void }) {
  const auth = useAuth();
  const fetchOne = useCallback((signal: AbortSignal) => ndrApi.anomaly(anomalyId, signal), [anomalyId]);
  const detail = usePolling(fetchOne, config.refreshIntervalMs);
  const anomaly = detail.data;
  const context = anomaly?.context;
  return (
    <section className="panel" aria-label="Detalle de la anomalía">
      <div className="panel__toolbar">
        <h2>{anomaly ? `${anomaly.rule_id} · ${anomaly.title}` : "Anomalía"}</h2>
        <button type="button" className="button button--small" onClick={onClose}>
          Cerrar detalle
        </button>
      </div>
      {detail.loading ? (
        <LoadingState label="Cargando anomalía…" />
      ) : !anomaly ? (
        <ErrorState message={detail.error ? errorMessage(detail.error) : "No encontrada"} onRetry={detail.refresh} />
      ) : (
        <div className="stack">
          <p>{anomaly.summary}</p>
          <dl className="fields fields--inline">
            <div className="field">
              <dt>Veredicto</dt>
              <dd>
                <VerdictBadge verdict={anomaly.verdict} />
              </dd>
            </div>
            <div className="field">
              <dt>Estado</dt>
              <dd>{STATUS_LABELS[anomaly.status]}</dd>
            </div>
            <div className="field">
              <dt>Ocurrencias</dt>
              <dd>{anomaly.occurrences}</dd>
            </div>
            <div className="field">
              <dt>MITRE ATT&amp;CK</dt>
              <dd>
                <MitreText mitre={anomaly.mitre} />
              </dd>
            </div>
            <div className="field">
              <dt>Primera vez</dt>
              <dd>{formatDateTime(anomaly.first_seen)}</dd>
            </div>
            <div className="field">
              <dt>Última vez</dt>
              <dd>{formatDateTime(anomaly.last_seen)}</dd>
            </div>
          </dl>
          {context && (
            <div className="stack" aria-label="Correlación">
              <h3>Correlación</h3>
              <p className="small">
                Activo:{" "}
                {context.asset ? (
                  <Link to={`/assets/${context.asset.asset_id}`}>
                    {context.asset.name} ({context.asset.primary_ip})
                  </Link>
                ) : (
                  <span className="muted">ninguno del inventario coincide (puede ser un equipo no gestionado)</span>
                )}
              </p>
              {context.switch_locations.length > 0 && (
                <ul className="small">
                  {context.switch_locations.map((loc) => (
                    <li key={`${loc.device_id}-${loc.interface ?? ""}`}>
                      Switch {loc.device_name ?? "sin nombre"}, puerto {loc.interface ?? "?"}
                      {loc.vlan != null && `, VLAN ${loc.vlan}`} ({loc.location})
                    </li>
                  ))}
                </ul>
              )}
              {context.detections.map((d) => (
                <p key={d.detection_id} className="small">
                  Detección <Link to={`/detections/${d.detection_id}`}>{d.rule_id}</Link> · {d.status}
                </p>
              ))}
              {context.incidents.map((i) => (
                <p key={i.incident_id} className="small">
                  Incidente <Link to={`/incidents/${i.incident_id}`}>#{i.number} {i.title}</Link> · {i.status}
                </p>
              ))}
            </div>
          )}
          <ResponsePlanSection anomalyId={anomaly.anomaly_id} />
          <details>
            <summary>Evidencia</summary>
            <pre className="mono small">{JSON.stringify(anomaly.evidence, null, 2)}</pre>
          </details>
          {anomaly.status_note && (
            <p className="small muted">
              {STATUS_LABELS[anomaly.status]} por {anomaly.status_by}: {anomaly.status_note}
            </p>
          )}
          {auth.can("ndr:triage") && (
            <TriageForm
              anomaly={anomaly}
              onDone={() => {
                detail.refresh();
                onChanged();
              }}
            />
          )}
        </div>
      )}
    </section>
  );
}

function AnomaliesTab({ scopeId }: { scopeId: string | undefined }) {
  const [params, setParams] = useSearchParams();
  const [verdict, setVerdict] = useState("");
  const [category, setCategory] = useState("");
  const [showClosed, setShowClosed] = useState(false);
  const [ipText, setIpText] = useState("");
  const ip = useDebounced(ipText, 300);
  const [page, setPage] = useState(1);
  const selected = params.get("anomaly") ?? undefined;
  const fetchList = useCallback(
    (signal: AbortSignal) =>
      ndrApi.anomalies(
        {
          siteId: scopeId,
          active: showClosed ? undefined : true,
          verdict: (verdict || undefined) as NdrAnomalyVerdict | undefined,
          category: category || undefined,
          ip: ip.length >= 2 ? ip : undefined,
          limit: PAGE_SIZE,
          offset: (page - 1) * PAGE_SIZE,
        },
        signal,
      ),
    [scopeId, showClosed, verdict, category, ip, page],
  );
  const list = usePolling(fetchList, config.refreshIntervalMs, true, true);
  const select = (id: string | undefined) => {
    const next = new URLSearchParams(params);
    if (id) next.set("anomaly", id);
    else next.delete("anomaly");
    setParams(next, { replace: true });
  };
  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  return (
    <>
      {selected && <AnomalyDetail anomalyId={selected} onClose={() => select(undefined)} onChanged={list.refresh} />}
      <section className="panel" aria-label="Anomalías de red">
        <Toolbar>
          <SearchInput value={ipText} onChange={setIpText} placeholder="IP" label="Filtrar por IP" />
          <FilterSelect
            label="Veredicto"
            value={verdict}
            options={Object.entries(VERDICT_LABELS).map(([value, label]) => ({ value, label }))}
            onChange={(value) => {
              setVerdict(value);
              setPage(1);
            }}
          />
          <FilterSelect
            label="Categoría"
            value={category}
            allLabel="Todas"
            options={Object.entries(CATEGORY_LABELS).map(([value, label]) => ({ value, label }))}
            onChange={(value) => {
              setCategory(value);
              setPage(1);
            }}
          />
          <label className="checkbox">
            <input type="checkbox" checked={showClosed} onChange={(e) => setShowClosed(e.target.checked)} /> Incluir
            cerradas
          </label>
        </Toolbar>
        {list.loading ? (
          <LoadingState label="Cargando anomalías…" />
        ) : !list.data && list.error ? (
          <ErrorState message={errorMessage(list.error)} onRetry={list.refresh} />
        ) : items.length === 0 ? (
          <EmptyState title="Sin anomalías de red">
            Las reglas NDR evalúan cada lote de los sensores aprobados; aquí aparece lo que encuentren.
          </EmptyState>
        ) : (
          <>
            <div className="table-wrap">
              <table className="table table--compact">
                <thead>
                  <tr>
                    <th>Última vez</th>
                    <th>Regla</th>
                    <th>Veredicto</th>
                    <th>Severidad</th>
                    <th>Sujeto</th>
                    <th>Activo</th>
                    <th>Estado</th>
                    <th>Ocurrencias</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((a) => (
                    <tr key={a.anomaly_id} className={a.anomaly_id === selected ? "row--selected" : undefined}>
                      <td title={formatDateTime(a.last_seen)}>{formatRelative(a.last_seen)}</td>
                      <td>
                        <button type="button" className="link-button" onClick={() => select(a.anomaly_id)}>
                          {a.rule_id}
                        </button>
                        <span className="muted small"> {a.title}</span>
                      </td>
                      <td>
                        <VerdictBadge verdict={a.verdict} />
                      </td>
                      <td>{a.severity}</td>
                      <td className="mono small">{[a.subject_ip, a.subject_mac].filter(Boolean).join(" · ") || "—"}</td>
                      <td>{a.asset_id ? <Link to={`/assets/${a.asset_id}`}>{a.asset_name}</Link> : "—"}</td>
                      <td>{STATUS_LABELS[a.status]}</td>
                      <td>{a.occurrences}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <Pager page={page} pages={Math.max(1, Math.ceil(total / PAGE_SIZE))} total={total} onPage={setPage} noun="anomalías" />
          </>
        )}
      </section>
    </>
  );
}

// --- Evidencia: flujos y metadatos ----------------------------------------------------------

function EvidenceTab({ scopeId }: { scopeId: string | undefined }) {
  const [ipText, setIpText] = useState("");
  const ip = useDebounced(ipText, 300);
  const [kind, setKind] = useState<NdrObservationKind>("dns");
  const fetchFlows = useCallback(
    (signal: AbortSignal) => ndrApi.flows({ siteId: scopeId, ip: ip.length >= 2 ? ip : undefined, limit: 100 }, signal),
    [scopeId, ip],
  );
  const flows = usePolling(fetchFlows, config.refreshIntervalMs, true, true);
  const fetchObservations = useCallback(
    (signal: AbortSignal) =>
      ndrApi.observations({ siteId: scopeId, kind, ip: ip.length >= 2 ? ip : undefined, limit: 100 }, signal),
    [scopeId, kind, ip],
  );
  const observations = usePolling(fetchObservations, config.refreshIntervalMs, true, true);
  return (
    <>
      <section className="panel" aria-label="Flujos">
        <Toolbar>
          <SearchInput value={ipText} onChange={setIpText} placeholder="IP" label="Filtrar evidencia por IP" />
          <span className="muted small">Solo cabeceras y contadores: el sensor nunca guarda contenido.</span>
        </Toolbar>
        {flows.loading ? (
          <LoadingState label="Cargando flujos…" />
        ) : !flows.data && flows.error ? (
          <ErrorState message={errorMessage(flows.error)} onRetry={flows.refresh} />
        ) : (flows.data?.items.length ?? 0) === 0 ? (
          <EmptyState title="Sin flujos en la retención" />
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Última vez</th>
                  <th>Origen</th>
                  <th>Destino</th>
                  <th>Transporte</th>
                  <th>Estado</th>
                  <th>Enviado</th>
                  <th>Recibido</th>
                  <th>Marcas</th>
                </tr>
              </thead>
              <tbody>
                {flows.data?.items.map((f) => (
                  <tr key={f.id}>
                    <td title={formatDateTime(f.last_seen)}>{formatRelative(f.last_seen)}</td>
                    <td className="mono small">
                      {f.src_ip}
                      {f.src_port != null && `:${f.src_port}`}
                    </td>
                    <td className="mono small">
                      {f.dst_ip}
                      {f.dst_port != null && `:${f.dst_port}`}
                    </td>
                    <td>{[f.transport, ...f.app_hints].join(" · ")}</td>
                    <td>{f.state}</td>
                    <td>{formatBytes(f.bytes_out)}</td>
                    <td>{formatBytes(f.bytes_in)}</td>
                    <td className="small">{f.flags.join(", ") || "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      <section className="panel" aria-label="Metadatos de protocolo">
        <div className="panel__toolbar">
          <h2>Metadatos de protocolo</h2>
          <select
            className="input input--select"
            aria-label="Tipo de metadato"
            value={kind}
            onChange={(e) => setKind(e.target.value as NdrObservationKind)}
          >
            {Object.entries(OBSERVATION_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </div>
        {observations.loading ? (
          <LoadingState label="Cargando metadatos…" />
        ) : !observations.data && observations.error ? (
          <ErrorState message={errorMessage(observations.error)} onRetry={observations.refresh} />
        ) : (observations.data?.items.length ?? 0) === 0 ? (
          <EmptyState title="Sin metadatos de este tipo">
            DNS y TLS solo se registran si el admin los habilitó en la captura del sensor.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Última vez</th>
                  <th>IP</th>
                  <th>Par</th>
                  <th>MAC</th>
                  <th>Nombre</th>
                  <th>Veces</th>
                </tr>
              </thead>
              <tbody>
                {observations.data?.items.map((o) => (
                  <tr key={o.id}>
                    <td title={formatDateTime(o.last_seen)}>{formatRelative(o.last_seen)}</td>
                    <td className="mono small">{o.ip ?? "—"}</td>
                    <td className="mono small">{o.peer_ip ?? "—"}</td>
                    <td className="mono small">{o.mac ?? "—"}</td>
                    <td className="mono small">{o.name ?? "—"}</td>
                    <td>{o.count}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}

// --- Reglas ---------------------------------------------------------------------------------

function RulesTab() {
  const fetchRules = useCallback((signal: AbortSignal) => ndrApi.rules(signal), []);
  const rules = usePolling(fetchRules, 0);
  if (rules.loading) return <LoadingState label="Cargando reglas…" />;
  if (!rules.data) return <ErrorState message={rules.error ? errorMessage(rules.error) : ""} onRetry={rules.refresh} />;
  return (
    <section className="panel" aria-label="Reglas NDR">
      <div className="stack">
        {rules.data.items.map((rule) => (
          <article key={rule.id} className="stack" aria-label={rule.id}>
            <h3>
              <span className="mono">{rule.id}</span> · {rule.title}
            </h3>
            <p className="small">{rule.description}</p>
            <p className="small muted">{rule.why}</p>
            <ul className="small">
              {Object.entries(rule.verdicts).map(([verdict, text]) => (
                <li key={verdict}>
                  <strong>{VERDICT_LABELS[verdict as NdrAnomalyVerdict] ?? verdict}:</strong> {text}
                </li>
              ))}
            </ul>
            <p className="small">
              MITRE ATT&amp;CK: <MitreText mitre={rule.mitre} />
            </p>
          </article>
        ))}
      </div>
    </section>
  );
}

export function NdrPage() {
  const auth = useAuth();
  const { scopeId } = useSite();
  const [params] = useSearchParams();
  const canEvidence = auth.can("ndr:evidence");
  const tabs = [
    { key: "overview", to: "/ndr", label: "Resumen" },
    { key: "anomalies", to: "/ndr?tab=anomalies", label: "Anomalías" },
    ...(canEvidence ? [{ key: "evidence", to: "/ndr?tab=evidence", label: "Flujos y metadatos" }] : []),
    { key: "rules", to: "/ndr?tab=rules", label: "Reglas" },
  ];
  const requested = params.get("tab") ?? "overview";
  const active = tabs.some((t) => t.key === requested) ? requested : "overview";
  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Red (NDR)</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Detección pasiva sobre copias del tráfico (SPAN/TAP) de los sensores aprobados.</span>
          </p>
        </div>
      </div>
      <RouteTabs tabs={tabs} active={active} label="Secciones de NDR" idPrefix="ndr" panelId="ndr-panel" />
      <div id="ndr-panel" role="tabpanel" aria-labelledby={`ndr-tab-${active}`} className="stack">
        {active === "overview" && <OverviewTab scopeId={scopeId} />}
        {active === "anomalies" && <AnomaliesTab scopeId={scopeId} />}
        {active === "evidence" && <EvidenceTab scopeId={scopeId} />}
        {active === "rules" && <RulesTab />}
      </div>
    </div>
  );
}
