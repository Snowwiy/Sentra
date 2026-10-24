import { useCallback, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { sensorsApi } from "../api/sentra";
import { dhcpApi } from "../api/sentra6e";
import type { DhcpFormat, DhcpLeaseMatch, DhcpSource, DhcpSourceKind } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect, Pager, SearchInput } from "../components/ListControls";
import { ConfirmDialog, Modal } from "../components/Modal";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import {
  DHCP_FORMAT_LABELS,
  DHCP_IMPORT_MAX_CHARS,
  DHCP_KIND_LABELS,
  DHCP_SOURCE_NAME,
  DHCP_STATUS_BADGES,
  DHCP_STATUS_LABELS,
  LEASE_MATCH_LABELS,
  LEASE_STATE_LABELS,
  SENSOR_SOURCE_NAME,
} from "../lib/dhcp";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { useDebounced } from "../lib/useDebounced";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";

const LEASE_PAGE = 100;
const REFRESH_MS = 60_000;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

function readText(file: Blob): Promise<string> {
  // FileReader en vez de Blob.text(): jsdom (tests) no siempre lo implementa y en los
  // navegadores soportados el resultado es el mismo.
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result));
    reader.onerror = () => reject(reader.error ?? new Error("No se pudo leer el fichero"));
    reader.readAsText(file);
  });
}

/**
 * Fuentes DHCP y concesiones (Fase 6E.2). Las concesiones dan nombre a los equipos solo con
 * coincidencia alta (MAC e IP en la ventana de la concesión) y nunca fusionan activos. Ver es
 * monitoring:read; declarar fuentes, importar ficheros y pedir lecturas a un sensor exige
 * dhcp:manage (admin), porque una fuente decide qué nombre ven todos.
 */
export function DhcpPage() {
  const auth = useAuth();
  const canManage = auth.can("dhcp:manage");
  const site = useSite();
  const fetchSources = useCallback((signal: AbortSignal) => dhcpApi.sources(site.scopeId, signal), [site.scopeId]);
  const sources = usePolling(fetchSources, REFRESH_MS);
  const [creating, setCreating] = useState(false);
  const [leaseRefresh, setLeaseRefresh] = useState(0);

  const reload = () => {
    sources.refresh();
    setLeaseRefresh((n) => n + 1);
  };

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>DHCP</h1>
          <p className="muted small">
            Concesiones DHCP como fuente de identidad: una concesión con MAC e IP coincidentes da nombre al equipo (salvo que
            tenga una etiqueta personalizada, que siempre prevalece). Sin APIs de routers: se importan ficheros o los lee un
            sensor.
          </p>
        </div>
        {canManage && (
          <div className="actions">
            <button type="button" className="button button--primary" onClick={() => setCreating(true)}>
              Nueva fuente
            </button>
          </div>
        )}
      </div>

      <section className="panel" aria-label="Fuentes DHCP">
        <div className="panel__toolbar">
          <h2>Fuentes</h2>
        </div>
        {sources.loading ? (
          <LoadingState label="Cargando fuentes…" />
        ) : !sources.data ? (
          <ErrorState message={errorMessage(sources.error ?? new Error("Sin datos"))} onRetry={sources.refresh} />
        ) : sources.data.items.length === 0 ? (
          <EmptyState title="Sin fuentes DHCP">
            {canManage
              ? "Crea una fuente para importar un fichero de concesiones o para que un sensor lo lea."
              : "Un administrador debe declarar las fuentes DHCP de cada site."}
          </EmptyState>
        ) : (
          <SourcesTable sources={sources.data.items} canManage={canManage} onChanged={reload} />
        )}
      </section>

      <LeasesPanel siteId={site.scopeId} sources={sources.data?.items ?? []} refreshKey={leaseRefresh} />

      {creating && (
        <CreateSourceDialog
          defaultSiteId={site.scopeId}
          sites={site.selectableSites.map((s) => ({ id: s.site_id, name: s.name }))}
          onClose={() => setCreating(false)}
          onCreated={() => {
            setCreating(false);
            reload();
          }}
        />
      )}
    </div>
  );
}

function SourcesTable({
  sources,
  canManage,
  onChanged,
}: {
  sources: DhcpSource[];
  canManage: boolean;
  onChanged: () => void;
}) {
  const [notice, setNotice] = useState<{ tone: "ok" | "warn"; text: string }>();
  const [deleting, setDeleting] = useState<DhcpSource>();
  const [busy, setBusy] = useState<string>();
  const fileInput = useRef<HTMLInputElement>(null);
  const importTarget = useRef<DhcpSource | null>(null);

  const run = async (source: DhcpSource, action: () => Promise<string>) => {
    setBusy(source.id);
    setNotice(undefined);
    try {
      setNotice({ tone: "ok", text: await action() });
    } catch (err) {
      setNotice({ tone: "warn", text: errorMessage(toError(err)) });
    } finally {
      setBusy(undefined);
      onChanged();
    }
  };

  const chooseFile = (source: DhcpSource) => {
    importTarget.current = source;
    fileInput.current?.click();
  };

  const onFile = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    const source = importTarget.current;
    event.target.value = "";
    if (!file || !source) return;
    void run(source, async () => {
      const content = await readText(file);
      if (!content) throw new Error("El fichero está vacío.");
      if (content.length > DHCP_IMPORT_MAX_CHARS) throw new Error("El fichero supera los 3 MB que admite la importación.");
      const result = await dhcpApi.importLeases(source.id, content, source.version);
      return (
        `Importadas ${result.parsed} concesiones de ${result.lines} registros (${result.skipped} descartados` +
        `${result.truncated ? ", fichero recortado" : ""}). ${result.matched} asociadas a equipos, ${result.named} dan nombre` +
        `${result.ambiguous ? `, ${result.ambiguous} ambiguas` : ""}.`
      );
    });
  };

  return (
    <>
      {notice && (
        <div className={`banner${notice.tone === "warn" ? " banner--warn" : " banner--ok"}`} role={notice.tone === "warn" ? "alert" : "status"}>
          {notice.text}
        </div>
      )}
      <input ref={fileInput} type="file" hidden accept=".leases,.csv,.txt,.conf,text/*" onChange={onFile} aria-label="Fichero de concesiones" />
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th>Nombre</th>
              <th>Tipo</th>
              <th>Estado</th>
              <th>Concesiones</th>
              <th className="col-secondary">Última importación</th>
              {canManage && <th>Acciones</th>}
            </tr>
          </thead>
          <tbody>
            {sources.map((s) => (
              <tr key={s.id}>
                <td>
                  {s.name}
                  <div className="muted small">
                    {s.site.name} · {DHCP_FORMAT_LABELS[s.format] ?? s.format}
                  </div>
                </td>
                <td>
                  {DHCP_KIND_LABELS[s.kind] ?? s.kind}
                  {s.kind === "sensor_file" && (
                    <div className="muted small">
                      {s.sensor_name ?? "sensor"} · <span className="mono">{s.sensor_source_name}</span>
                      {s.poll_interval_minutes > 0 && ` · cada ${s.poll_interval_minutes} min`}
                    </div>
                  )}
                </td>
                <td>
                  <span className={DHCP_STATUS_BADGES[s.status] ?? "badge"}>{DHCP_STATUS_LABELS[s.status] ?? s.status}</span>
                  {s.last_error_code && <div className="small text-crit mono">{s.last_error_code}</div>}
                </td>
                <td>{s.lease_count}</td>
                <td className="col-secondary" title={formatDateTime(s.last_import_at)}>
                  {s.last_import_at ? formatRelative(s.last_import_at) : "Nunca"}
                </td>
                {canManage && (
                  <td>
                    <span className="actions">
                      {s.kind === "lease_import" && s.status !== "disabled" && (
                        <button type="button" className="button button--small" disabled={busy === s.id} onClick={() => chooseFile(s)}>
                          Importar fichero
                        </button>
                      )}
                      {s.kind === "sensor_file" && s.status !== "disabled" && (
                        <button
                          type="button"
                          className="button button--small"
                          disabled={busy === s.id}
                          onClick={() =>
                            void run(s, async () => {
                              await dhcpApi.requestRead(s.id);
                              return `Lectura pedida al sensor ${s.sensor_name ?? ""}. Las concesiones aparecerán al terminar.`;
                            })
                          }
                        >
                          Leer ahora
                        </button>
                      )}
                      <button
                        type="button"
                        className="button button--small"
                        disabled={busy === s.id}
                        onClick={() =>
                          void run(s, async () => {
                            const enable = s.status === "disabled";
                            await dhcpApi.update(s.id, { version: s.version, enabled: enable });
                            return enable ? `Fuente ${s.name} habilitada.` : `Fuente ${s.name} deshabilitada.`;
                          })
                        }
                      >
                        {s.status === "disabled" ? "Habilitar" : "Deshabilitar"}
                      </button>
                      <button type="button" className="button button--small button--danger" disabled={busy === s.id} onClick={() => setDeleting(s)}>
                        Borrar
                      </button>
                    </span>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {deleting && (
        <ConfirmDialog
          title="Borrar fuente DHCP"
          confirmLabel="Borrar"
          danger
          onClose={() => setDeleting(undefined)}
          onConfirm={async () => {
            await dhcpApi.remove(deleting.id, deleting.version);
            onChanged();
          }}
        >
          Se borrarán la fuente <strong>{deleting.name}</strong> y sus {deleting.lease_count} concesiones. Los equipos que
          tomaban el nombre de ella se volverán a identificar sin él.
        </ConfirmDialog>
      )}
    </>
  );
}

function LeasesPanel({ siteId, sources, refreshKey }: { siteId: string | undefined; sources: DhcpSource[]; refreshKey: number }) {
  const [search, setSearch] = useState("");
  const q = useDebounced(search.trim(), 300);
  const [match, setMatch] = useState<DhcpLeaseMatch | "">("");
  const [sourceId, setSourceId] = useState("");
  const [page, setPage] = useState(1);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      dhcpApi.leases(
        {
          siteId,
          sourceId: sourceId || undefined,
          match: match || undefined,
          search: q.slice(0, 64) || undefined,
          limit: LEASE_PAGE,
          offset: (page - 1) * LEASE_PAGE,
        },
        signal,
      ),
    // refreshKey: tras importar o leer, se vuelve a pedir la página actual.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [siteId, sourceId, match, q, page, refreshKey],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS, true, true);

  return (
    <section className="panel" aria-label="Concesiones DHCP">
      <div className="panel__toolbar panel__toolbar--filters">
        <h2>Concesiones</h2>
        <SearchInput
          value={search}
          onChange={(v) => {
            setSearch(v);
            setPage(1);
          }}
          placeholder="IP, MAC o hostname"
          label="Buscar concesiones"
        />
        <FilterSelect
          label="Asociación"
          value={match}
          allLabel="todas"
          options={Object.entries(LEASE_MATCH_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={(v) => {
            setMatch(v as DhcpLeaseMatch | "");
            setPage(1);
          }}
        />
        {sources.length > 1 && (
          <FilterSelect
            label="Fuente"
            value={sourceId}
            allLabel="todas"
            options={sources.map((s) => ({ value: s.id, label: s.name }))}
            onChange={(v) => {
              setSourceId(v);
              setPage(1);
            }}
          />
        )}
      </div>
      {loading ? (
        <LoadingState label="Cargando concesiones…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <p className="muted small panel--padded">Sin concesiones con este filtro.</p>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Hostname</th>
                  <th>IP</th>
                  <th>MAC</th>
                  <th>Estado</th>
                  <th>Asociación</th>
                  <th className="col-secondary">Equipo</th>
                  <th className="col-secondary">Vence</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((l) => (
                  <tr key={`${l.source_id}:${l.ip}:${l.mac}`}>
                    <td>
                      {l.hostname ?? <span className="muted">—</span>}
                      {l.hostname && !l.hostname_usable && <span className="badge badge--muted">no utilizable</span>}
                    </td>
                    <td className="mono">{l.ip}</td>
                    <td className="mono">
                      {l.mac}
                      {l.mac_randomized && <span className="badge badge--warn">aleatoria</span>}
                    </td>
                    <td>{LEASE_STATE_LABELS[l.state] ?? l.state}</td>
                    <td>{LEASE_MATCH_LABELS[l.match] ?? l.match}</td>
                    <td className="col-secondary">
                      {l.asset_id ? (
                        <Link to={`/assets/${encodeURIComponent(l.asset_id)}?tab=identity`}>{l.asset_name ?? "equipo"}</Link>
                      ) : (
                        "—"
                      )}
                    </td>
                    <td className="col-secondary">{l.ends_at ? formatDateTime(l.ends_at) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager
            page={page}
            pages={Math.max(1, Math.ceil(data.total / LEASE_PAGE))}
            total={data.total}
            onPage={setPage}
            noun="concesiones"
          />
        </>
      )}
    </section>
  );
}

function CreateSourceDialog({
  defaultSiteId,
  sites,
  onClose,
  onCreated,
}: {
  defaultSiteId: string | undefined;
  sites: { id: string; name: string }[];
  onClose: () => void;
  onCreated: () => void;
}) {
  const [name, setName] = useState("");
  const [siteId, setSiteId] = useState(defaultSiteId ?? "");
  const [kind, setKind] = useState<DhcpSourceKind>("lease_import");
  const [format, setFormat] = useState<DhcpFormat>("dnsmasq");
  const [sensorId, setSensorId] = useState("");
  const [sensorSource, setSensorSource] = useState("");
  const [interval, setIntervalMinutes] = useState("0");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const fetchSensors = useCallback((signal: AbortSignal) => sensorsApi.list(siteId || undefined, signal), [siteId]);
  const sensors = usePolling(fetchSensors, 3_600_000, kind === "sensor_file");
  // Solo sensores que anuncian la capacidad de leer ficheros DHCP (sensor 0.6.0 o posterior).
  const capable = (sensors.data?.items ?? []).filter((s) => s.capabilities.includes("dhcp.leases.file"));

  const errors: string[] = [];
  if (!DHCP_SOURCE_NAME.test(name)) errors.push("Nombre: letras, números, espacio, punto, guion o guion bajo (máx. 64).");
  if (kind === "sensor_file") {
    if (!sensorId) errors.push("Elige el sensor que leerá el fichero.");
    if (!SENSOR_SOURCE_NAME.test(sensorSource)) {
      errors.push("Nombre del fichero en el sensor: minúsculas, números, guion o guion bajo (como en sensor.toml).");
    }
  }
  const minutes = Number(interval);
  if (!Number.isInteger(minutes) || minutes < 0) errors.push("El intervalo debe ser un número entero de minutos (0 = solo a demanda).");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (errors.length) return;
    setBusy(true);
    setError(undefined);
    try {
      await dhcpApi.create({
        name,
        site_id: siteId || null,
        kind,
        format,
        sensor_id: kind === "sensor_file" ? sensorId : null,
        sensor_source_name: kind === "sensor_file" ? sensorSource : null,
        poll_interval_minutes: kind === "sensor_file" ? minutes : 0,
      });
      onCreated();
    } catch (err) {
      setError(errorMessage(toError(err)));
      setBusy(false);
    }
  };

  return (
    <Modal title="Nueva fuente DHCP" onClose={busy ? () => undefined : onClose}>
      <form className="stack" onSubmit={(e) => void submit(e)} noValidate>
        <label className="form-field">
          <span>Nombre</span>
          <input className="input" value={name} maxLength={64} onChange={(e) => setName(e.target.value)} disabled={busy} />
        </label>
        {sites.length > 1 && (
          <label className="form-field">
            <span>Site</span>
            <select className="input input--select" value={siteId} onChange={(e) => setSiteId(e.target.value)} disabled={busy}>
              <option value="">Site por defecto</option>
              {sites.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.name}
                </option>
              ))}
            </select>
          </label>
        )}
        <label className="form-field">
          <span>Tipo</span>
          <select className="input input--select" value={kind} onChange={(e) => setKind(e.target.value as DhcpSourceKind)} disabled={busy}>
            {Object.entries(DHCP_KIND_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        <label className="form-field">
          <span>Formato</span>
          <select className="input input--select" value={format} onChange={(e) => setFormat(e.target.value as DhcpFormat)} disabled={busy}>
            {Object.entries(DHCP_FORMAT_LABELS).map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
        </label>
        {kind === "sensor_file" && (
          <>
            <label className="form-field">
              <span>Sensor</span>
              <select className="input input--select" value={sensorId} onChange={(e) => setSensorId(e.target.value)} disabled={busy}>
                <option value="">Elige un sensor</option>
                {capable.map((s) => (
                  <option key={s.sensor_id} value={s.sensor_id}>
                    {s.name} ({s.site_name})
                  </option>
                ))}
              </select>
            </label>
            {sensors.data && capable.length === 0 && (
              <p className="muted small">Ningún sensor de este site lee ficheros DHCP (requiere el sensor 0.6.0).</p>
            )}
            <label className="form-field">
              <span>Nombre del fichero en sensor.toml ([[dhcp_lease_files]] name)</span>
              <input
                className="input mono"
                value={sensorSource}
                maxLength={64}
                onChange={(e) => setSensorSource(e.target.value)}
                disabled={busy}
              />
            </label>
            <p className="muted small">El servidor nunca envía rutas: el sensor solo lee los ficheros declarados en su configuración.</p>
            <label className="form-field">
              <span>Leer cada (minutos, 0 = solo a demanda)</span>
              <input
                className="input"
                type="number"
                min={0}
                value={interval}
                onChange={(e) => setIntervalMinutes(e.target.value)}
                disabled={busy}
              />
            </label>
          </>
        )}
        {errors.length > 0 && (name || sensorSource) && (
          <ul className="plain-list small text-crit">
            {errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
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
          <button type="submit" className="button button--primary" disabled={busy || errors.length > 0}>
            {busy ? "Creando…" : "Crear fuente"}
          </button>
        </div>
      </form>
    </Modal>
  );
}
