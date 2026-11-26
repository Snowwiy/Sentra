import { useCallback, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { sensorsApi } from "../api/sentra";
import { siemApi } from "../api/siem";
import type {
  SiemBatchAccepted,
  SiemConnectorRead,
  SiemSourceRead,
  SiemSourceState,
  SiemTransport,
} from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect, Pager, Toolbar } from "../components/ListControls";
import { Modal } from "../components/Modal";
import { RouteTabs } from "../components/RouteTabs";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";
import { SiemEventDetailModal } from "../components/siem/SiemEventDetail";
import { HuntTab } from "../components/siem/HuntTab";
import { SEVERITY_LABELS, SiemEventsTable, SiemSeverityBadge, severityClass } from "../components/siem/SiemEventsTable";

// Reexportados: otras páginas y los tests los importan desde aquí.
export { SEVERITY_LABELS, SiemEventsTable, SiemSeverityBadge, severityClass };

/**
 * Integración SIEM (Fase 7F). Fuentes externas opcionales (Syslog, Suricata, Zeek, Wazuh o
 * el contrato propio) que llegan por un sensor del site o por importación de un fichero
 * exportado. Todo lo que muestran los eventos es texto no confiable: se pinta como texto
 * (React escapa) y nunca se sigue un enlace ni se ejecuta nada que contenga.
 */

const PAGE_SIZE = 50;

export const SOURCE_STATE_LABELS: Record<SiemSourceState, string> = {
  disabled: "Deshabilitada",
  configured: "Configurada (sin datos)",
  healthy: "Operativa",
  degraded: "Degradada",
  offline: "Sin conexión",
  error: "Error",
};


export function sourceStateClass(state: SiemSourceState): string {
  if (state === "healthy") return "badge badge--ok";
  if (state === "degraded" || state === "configured") return "badge badge--warn";
  if (state === "error" || state === "offline") return "badge badge--crit";
  return "badge badge--muted";
}



function asError(err: unknown): Error {
  return err instanceof Error ? err : new Error(String(err));
}

/** Lee un fichero como texto. jsdom antiguo no tiene File.text(): FileReader como respaldo. */
export function readFileText(file: Blob): Promise<string> {
  if (typeof file.text === "function") return file.text();
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result ?? ""));
    reader.onerror = () => reject(reader.error ?? new Error("No se pudo leer el fichero"));
    reader.readAsText(file);
  });
}

// --- Alta de fuente -------------------------------------------------------------------------

function SourceModal({
  connectors,
  siteId,
  onClose,
  onDone,
}: {
  connectors: SiemConnectorRead[];
  siteId: string | undefined;
  onClose: () => void;
  onDone: () => void;
}) {
  const { selectableSites } = useSite();
  const [site, setSite] = useState(siteId ?? selectableSites[0]?.site_id ?? "");
  const [name, setName] = useState("");
  const [type, setType] = useState(connectors[0]?.source_type ?? "");
  const connector = connectors.find((c) => c.source_type === type);
  const [transport, setTransport] = useState<SiemTransport>("upload");
  const [sensorId, setSensorId] = useState("");
  const [inputName, setInputName] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(site || undefined, signal), [site]);
  const sensors = usePolling(fetchSensors, 0, transport === "sensor" && Boolean(site));
  const capable = (sensors.data?.items ?? []).filter(
    (s) => s.status !== "revoked" && s.capabilities.includes("siem.ingest"),
  );
  const valid =
    site && name.trim() && connector && (transport === "upload" || (sensorId && /^[a-z0-9_-]{1,32}$/.test(inputName)));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!valid) return;
    setBusy(true);
    setError(undefined);
    try {
      await siemApi.createSource({
        site_id: site,
        name: name.trim(),
        source_type: type,
        transport,
        sensor_id: transport === "sensor" ? sensorId : null,
        input_name: transport === "sensor" ? inputName : null,
        enabled: false,
      });
      onDone();
      onClose();
    } catch (err) {
      setError(errorMessage(asError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Registrar fuente SIEM" onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p className="muted small">
          La fuente queda deshabilitada hasta que la habilites. Con un sensor, el alias debe coincidir con una entrada
          declarada en su <span className="mono">sensor.toml</span>: Sentra nunca envía puertos ni rutas al sensor.
        </p>
        <label>
          <span>Site</span>
          <select className="input" value={site} onChange={(e) => setSite(e.target.value)}>
            {selectableSites.map((s) => (
              <option key={s.site_id} value={s.site_id}>
                {s.name}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span>Nombre</span>
          <input className="input" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
        </label>
        <label>
          <span>Conector</span>
          <select
            className="input"
            value={type}
            onChange={(e) => {
              setType(e.target.value);
              setTransport("upload");
            }}
          >
            {connectors.map((c) => (
              <option key={c.source_type} value={c.source_type}>
                {c.title} ({c.version})
              </option>
            ))}
          </select>
        </label>
        {connector && <p className="small muted">{connector.description}</p>}
        <label>
          <span>Cómo llegan los registros</span>
          <select className="input" value={transport} onChange={(e) => setTransport(e.target.value as SiemTransport)}>
            {connector?.transports.includes("upload") && <option value="upload">Importación de ficheros</option>}
            {connector?.transports.includes("sensor") && <option value="sensor">Sensor del site</option>}
          </select>
        </label>
        {transport === "sensor" && (
          <>
            <label>
              <span>Sensor receptor</span>
              <select className="input" value={sensorId} onChange={(e) => setSensorId(e.target.value)}>
                <option value="">Elige un sensor con la capacidad SIEM</option>
                {capable.map((s) => (
                  <option key={s.sensor_id} value={s.sensor_id}>
                    {s.name}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Alias de la entrada en el sensor</span>
              <input
                className="input mono"
                value={inputName}
                maxLength={32}
                placeholder="firewall-syslog"
                onChange={(e) => setInputName(e.target.value.toLowerCase())}
              />
            </label>
          </>
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
            {busy ? "Guardando…" : "Registrar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// --- Importación -----------------------------------------------------------------------------

function ImportModal({ source, onClose, onDone }: { source: SiemSourceRead; onClose: () => void; onDone: () => void }) {
  const [file, setFile] = useState<File>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [result, setResult] = useState<SiemBatchAccepted>();

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(undefined);
    try {
      const content = await readFileText(file);
      const accepted = await siemApi.importFile(source.source_id, content, file.name);
      setResult(accepted);
      onDone();
    } catch (err) {
      setError(errorMessage(asError(err)));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Modal title={`Importar en ${source.name}`} onClose={busy ? () => undefined : onClose}>
      <form className="stack incident-form" onSubmit={(event) => void submit(event)}>
        <p className="muted small">
          Un registro por línea, en el formato del conector. Reimportar el mismo fichero no duplica nada. Lo que no se
          puede normalizar se rechaza y se cuenta por motivo.
        </p>
        <label>
          <span>Fichero exportado</span>
          <input
            className="input"
            type="file"
            accept=".json,.jsonl,.ndjson,.log,.txt"
            onChange={(e) => setFile(e.target.files?.[0])}
          />
        </label>
        {result && (
          <div className="banner" role="status">
            {result.duplicate
              ? "Este fichero ya se había importado: no se añadió nada."
              : `${result.accepted} aceptados, ${result.duplicates} duplicados, ${result.rejected} rechazados de ${result.records}.`}
            {Object.keys(result.reject_reasons).length > 0 && (
              <span className="small mono">
                {" "}
                {Object.entries(result.reject_reasons)
                  .map(([reason, count]) => `${reason}: ${count}`)
                  .join(", ")}
              </span>
            )}
          </div>
        )}
        {error && (
          <div className="banner banner--warn" role="alert">
            {error}
          </div>
        )}
        <div className="modal__actions">
          <button type="button" className="button" onClick={onClose} disabled={busy}>
            Cerrar
          </button>
          <button type="submit" className="button button--primary" disabled={busy || !file}>
            {busy ? "Importando…" : "Importar"}
          </button>
        </div>
      </form>
    </Modal>
  );
}

// --- Fuentes ---------------------------------------------------------------------------------

function SourcesTab({ scopeId }: { scopeId: string | undefined }) {
  const auth = useAuth();
  const canManage = auth.can("siem:manage");
  const fetchOverview = useCallback((signal: AbortSignal) => siemApi.overview(scopeId, 24, signal), [scopeId]);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs, true, true);
  const fetchSources = useCallback((signal: AbortSignal) => siemApi.sources(scopeId, signal), [scopeId]);
  const sources = usePolling(fetchSources, config.refreshIntervalMs, true, true);
  const fetchConnectors = useCallback((signal: AbortSignal) => siemApi.connectors(signal), []);
  const connectors = usePolling(fetchConnectors, 0);
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState<SiemSourceRead>();
  const [actionError, setActionError] = useState<string>();

  const toggle = async (source: SiemSourceRead) => {
    setActionError(undefined);
    try {
      await siemApi.updateSource(source.source_id, { expected_revision: source.revision, enabled: !source.enabled });
    } catch (err) {
      setActionError(errorMessage(asError(err)));
      if (!(err instanceof ApiError)) throw err;
    }
    sources.refresh();
  };

  if (sources.loading) return <LoadingState label="Cargando fuentes…" />;
  if (!sources.data && sources.error) return <ErrorState message={errorMessage(sources.error)} onRetry={sources.refresh} />;
  const items = sources.data?.items ?? [];
  const data = overview.data;
  return (
    <>
      {data && (
        <section className="stats stats--6" aria-label="Resumen SIEM">
          <div className="stat">
            <span className="stat__label">Fuentes operativas</span>
            <span className="stat__value">
              {data.sources_by_status.healthy ?? 0}/{data.sources_total}
            </span>
          </div>
          <div className="stat">
            <span className="stat__label">Con problemas</span>
            <span className="stat__value">
              {(data.sources_by_status.degraded ?? 0) +
                (data.sources_by_status.offline ?? 0) +
                (data.sources_by_status.error ?? 0)}
            </span>
          </div>
          <div className="stat">
            <span className="stat__label">Eventos (24 h)</span>
            <span className="stat__value">{data.events}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Rechazados</span>
            <span className="stat__value">{data.rejected}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Duplicados</span>
            <span className="stat__value">{data.duplicates}</span>
          </div>
          <div className="stat">
            <span className="stat__label">Con retraso</span>
            <span className="stat__value">{data.lagging_sources}</span>
          </div>
        </section>
      )}
      <section className="panel" aria-label="Fuentes SIEM">
        <div className="panel__toolbar">
          <h2>Fuentes</h2>
          {canManage && (
            <button
              type="button"
              className="button button--primary button--small"
              disabled={!connectors.data}
              onClick={() => setCreating(true)}
            >
              Registrar fuente
            </button>
          )}
        </div>
        {actionError && (
          <div className="banner banner--warn" role="alert">
            {actionError}
          </div>
        )}
        {items.length === 0 ? (
          <EmptyState title="Ninguna fuente SIEM registrada">
            Sentra funciona sin fuentes externas. Registra una para recibir Syslog, Suricata, Zeek o Wazuh a través de
            un sensor del site o importando un fichero exportado.
          </EmptyState>
        ) : (
          <div className="table-wrap">
            <table className="table table--compact">
              <thead>
                <tr>
                  <th>Fuente</th>
                  <th>Conector</th>
                  <th>Site</th>
                  <th>Recepción</th>
                  <th>Estado</th>
                  <th>Último lote</th>
                  <th>Aceptados</th>
                  <th>Rechazados</th>
                  <th>Duplicados</th>
                  {canManage && <th aria-label="Acciones" />}
                </tr>
              </thead>
              <tbody>
                {items.map((s) => (
                  <tr key={s.source_id}>
                    <td>{s.name}</td>
                    <td className="small">
                      {s.connector_title ?? s.source_type}
                      <span className="muted"> · {s.connector_version}</span>
                    </td>
                    <td>{s.site_name}</td>
                    <td className="small">
                      {s.transport === "sensor" ? (
                        <>
                          {s.sensor_name ?? "Sin sensor"} · <span className="mono">{s.input_name}</span>
                        </>
                      ) : (
                        "Importación"
                      )}
                    </td>
                    <td>
                      <span className={sourceStateClass(s.status)}>{SOURCE_STATE_LABELS[s.status]}</span>
                      {s.status_reasons.length > 0 && (
                        <span className="muted small mono"> · {s.status_reasons.join(", ")}</span>
                      )}
                    </td>
                    <td title={formatDateTime(s.last_success_at)}>{formatRelative(s.last_success_at)}</td>
                    <td>{s.events_accepted}</td>
                    <td>{s.events_rejected}</td>
                    <td>{s.events_duplicate}</td>
                    {canManage && (
                      <td className="row-actions">
                        <button type="button" className="button button--small" onClick={() => void toggle(s)}>
                          {s.enabled ? "Deshabilitar" : "Habilitar"}
                        </button>
                        {s.transport === "upload" && s.enabled && (
                          <button type="button" className="button button--small" onClick={() => setImporting(s)}>
                            Importar
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {creating && connectors.data && (
        <SourceModal
          connectors={connectors.data.items}
          siteId={scopeId}
          onClose={() => setCreating(false)}
          onDone={sources.refresh}
        />
      )}
      {importing && (
        <ImportModal source={importing} onClose={() => setImporting(undefined)} onDone={sources.refresh} />
      )}
    </>
  );
}

// --- Eventos ---------------------------------------------------------------------------------


function EventsTab({ scopeId }: { scopeId: string | undefined }) {
  const [page, setPage] = useState(1);
  const [sourceId, setSourceId] = useState("");
  const [opened, setOpened] = useState<string>();
  const fetchSources = useCallback((signal: AbortSignal) => siemApi.sources(scopeId, signal), [scopeId]);
  const sources = usePolling(fetchSources, 0);
  const fetchEvents = useCallback(
    (signal: AbortSignal) =>
      siemApi.events(
        { siteId: scopeId, sourceId: sourceId || undefined, limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE },
        signal,
      ),
    [scopeId, sourceId, page],
  );
  const events = usePolling(fetchEvents, config.refreshIntervalMs, true, true);
  const total = events.data?.total ?? 0;
  return (
    <section className="panel" aria-label="Eventos SIEM">
      <Toolbar>
        <FilterSelect
          label="Fuente"
          value={sourceId}
          allLabel="Todas las fuentes"
          options={(sources.data?.items ?? []).map((s) => ({ value: s.source_id, label: s.name }))}
          onChange={(value) => {
            setSourceId(value);
            setPage(1);
          }}
        />
      </Toolbar>
      {events.loading ? (
        <LoadingState label="Cargando eventos…" />
      ) : !events.data && events.error ? (
        <ErrorState message={errorMessage(events.error)} onRetry={events.refresh} />
      ) : (events.data?.items.length ?? 0) === 0 ? (
        <EmptyState title="Sin eventos">Los eventos aparecen aquí cuando una fuente habilitada envía o se importa.</EmptyState>
      ) : (
        <>
          <SiemEventsTable items={events.data?.items ?? []} onOpen={(e) => setOpened(e.event_id)} />
          <Pager page={page} pages={Math.max(1, Math.ceil(total / PAGE_SIZE))} total={total} onPage={setPage} noun="eventos" />
        </>
      )}
      {opened && <SiemEventDetailModal eventId={opened} onClose={() => setOpened(undefined)} />}
    </section>
  );
}

// --- Conectores ------------------------------------------------------------------------------

function ConnectorsTab() {
  const fetchConnectors = useCallback((signal: AbortSignal) => siemApi.connectors(signal), []);
  const connectors = usePolling(fetchConnectors, 0);
  if (connectors.loading) return <LoadingState label="Cargando conectores…" />;
  if (!connectors.data)
    return <ErrorState message={connectors.error ? errorMessage(connectors.error) : ""} onRetry={connectors.refresh} />;
  return (
    <section className="panel" aria-label="Conectores SIEM">
      <div className="stack">
        {connectors.data.items.map((c) => (
          <article key={c.source_type} className="stack" aria-label={c.source_type}>
            <h3>
              {c.title} <span className="muted small mono">{c.source_type} · {c.version}</span>
            </h3>
            <p className="small">{c.description}</p>
            <p className="small">
              Recepción: {c.transports.map((t) => (t === "sensor" ? "sensor del site" : "importación")).join(", ")}
            </p>
            <p className="small muted">{c.severity_policy_doc}</p>
            {Object.keys(c.severity_policy).length > 0 && (
              <p className="small mono">
                {Object.entries(c.severity_policy)
                  .map(([key, value]) => `${key} → ${value}`)
                  .join(" · ")}
              </p>
            )}
            <p className="small muted">Validación: {c.validation}</p>
          </article>
        ))}
      </div>
    </section>
  );
}

export function SiemPage() {
  const auth = useAuth();
  const { scopeId } = useSite();
  const [params] = useSearchParams();
  const canEvidence = auth.can("siem:evidence");
  const tabs = [
    { key: "sources", to: "/siem", label: "Fuentes" },
    ...(canEvidence
      ? [
          { key: "events", to: "/siem?tab=events", label: "Eventos" },
          { key: "hunt", to: "/siem?tab=hunt", label: "Búsqueda" },
        ]
      : []),
    { key: "connectors", to: "/siem?tab=connectors", label: "Conectores" },
  ];
  const requested = params.get("tab") ?? "sources";
  const active = tabs.some((t) => t.key === requested) ? requested : "sources";
  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>SIEM</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Fuentes externas opcionales normalizadas al contrato de Sentra.</span>
          </p>
        </div>
      </div>
      <RouteTabs tabs={tabs} active={active} label="Secciones de SIEM" idPrefix="siem" panelId="siem-panel" />
      <div id="siem-panel" role="tabpanel" aria-labelledby={`siem-tab-${active}`} className="stack">
        {active === "sources" && <SourcesTab scopeId={scopeId} />}
        {active === "events" && <EventsTab scopeId={scopeId} />}
        {active === "hunt" && <HuntTab scopeId={scopeId} />}
        {active === "connectors" && <ConnectorsTab />}
      </div>
    </div>
  );
}
