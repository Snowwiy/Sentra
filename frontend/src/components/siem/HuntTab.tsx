import { useCallback, useState, type FormEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { siemApi } from "../../api/siem";
import type { SiemEventRead, SiemSavedSearchRead, SiemSearchFilter } from "../../api/types";
import { errorMessage } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { EmptyState } from "../StateViews";
import { SiemEventDetailModal } from "./SiemEventDetail";
import { downloadEvidence } from "./SiemInvestigation";
import { SiemEventsTable } from "./SiemEventsTable";

/**
 * Hunting (Fase 7F.6): filtro tipado con ventana obligatoria. Lo escrito aquí nunca se
 * interpreta como consulta: cada campo va a un filtro fijo del servidor, que además limita la
 * ventana, el tamaño de página y el tiempo de la consulta.
 */

const PAGE = 50;

interface FormState {
  hours: string;
  eventType: string;
  sourceType: string;
  ip: string;
  port: string;
  username: string;
  hostname: string;
  ruleId: string;
  mitre: string;
  text: string;
}

const EMPTY: FormState = {
  hours: "24",
  eventType: "",
  sourceType: "",
  ip: "",
  port: "",
  username: "",
  hostname: "",
  ruleId: "",
  mitre: "",
  text: "",
};

/** Formulario → filtro de la API (solo los campos rellenos; la ventana acaba "ahora"). */
export function buildFilter(form: FormState, siteId: string | undefined, now: Date): SiemSearchFilter {
  const hours = Math.min(Math.max(Number(form.hours) || 24, 1), 24 * 31);
  const filter: SiemSearchFilter = {
    since: new Date(now.getTime() - hours * 3600 * 1000).toISOString(),
    until: now.toISOString(),
  };
  if (siteId) filter.site_id = siteId;
  if (form.eventType.trim()) filter.event_types = [form.eventType.trim()];
  if (form.sourceType) filter.source_types = [form.sourceType];
  if (form.ip.trim()) filter.ip = form.ip.trim();
  if (form.port.trim() && Number.isInteger(Number(form.port))) filter.port = Number(form.port);
  if (form.username.trim()) filter.username = form.username.trim();
  if (form.hostname.trim()) filter.hostname = form.hostname.trim();
  if (form.ruleId.trim()) filter.rule_id = form.ruleId.trim();
  if (form.mitre.trim()) filter.mitre_technique = form.mitre.trim().toUpperCase();
  if (form.text.trim()) filter.text = form.text.trim();
  return filter;
}

/** Búsqueda guardada → formulario (los campos desconocidos se ignoran). */
export function formFromSaved(query: Record<string, unknown>): FormState {
  const first = (value: unknown) => (Array.isArray(value) && typeof value[0] === "string" ? value[0] : "");
  const str = (value: unknown) => (typeof value === "string" ? value : typeof value === "number" ? String(value) : "");
  const since = Date.parse(str(query.since));
  const until = Date.parse(str(query.until));
  const hours = Number.isFinite(since) && Number.isFinite(until) ? Math.round((until - since) / 3600_000) : 24;
  return {
    hours: String(Math.max(hours, 1)),
    eventType: first(query.event_types),
    sourceType: first(query.source_types),
    ip: str(query.ip),
    port: str(query.port),
    username: str(query.username),
    hostname: str(query.hostname),
    ruleId: str(query.rule_id),
    mitre: str(query.mitre_technique),
    text: str(query.text),
  };
}

export function HuntTab({ scopeId }: { scopeId: string | undefined }) {
  const [params, setParams] = useSearchParams();
  const [form, setForm] = useState<FormState>(EMPTY);
  const [filter, setFilter] = useState<SiemSearchFilter>();
  const [items, setItems] = useState<SiemEventRead[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [count, setCount] = useState<{ value: number; capped: boolean; ms: number }>();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();
  const [info, setInfo] = useState<string>();
  const [saveName, setSaveName] = useState("");
  const [picked, setOpened] = useState<string>();
  // Un enlace (p. ej. una referencia de la IA) puede abrir un evento con ?event=<id>.
  const opened = picked ?? params.get("event") ?? undefined;
  const fetchSaved = useCallback((signal: AbortSignal) => siemApi.savedSearches(signal), []);
  const saved = usePolling(fetchSaved, 0);

  const run = async (next: SiemSearchFilter, after: string | null) => {
    setBusy(true);
    setError(undefined);
    try {
      const page = await siemApi.search({ ...next, limit: PAGE, cursor: after, count: after === null });
      setItems((current) => (after === null ? page.items : [...current, ...page.items]));
      setCursor(page.next_cursor);
      if (page.count !== null) setCount({ value: page.count, capped: page.count_capped, ms: page.took_ms });
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    } finally {
      setBusy(false);
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const next = buildFilter(form, scopeId, new Date());
    setFilter(next);
    setCount(undefined);
    void run(next, null);
  };

  const save = async () => {
    const name = saveName.trim();
    if (!name) return;
    try {
      await siemApi.saveSearch(name, buildFilter(form, scopeId, new Date()));
      setSaveName("");
      setInfo("Búsqueda guardada.");
      saved.refresh();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    }
  };

  const remove = async (search: SiemSavedSearchRead) => {
    try {
      await siemApi.deleteSearch(search.search_id);
      saved.refresh();
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    }
  };

  const exportShown = async () => {
    setError(undefined);
    try {
      const digest = await downloadEvidence(items.map((i) => i.event_id));
      setInfo(`Evidencia exportada. SHA-256 del paquete: ${digest}`);
    } catch (err) {
      setError(err instanceof Error ? errorMessage(err) : String(err));
    }
  };

  const field = (key: keyof FormState, label: string, extra: Record<string, unknown> = {}) => (
    <label className="small">
      {label}
      <input value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} {...extra} />
    </label>
  );

  return (
    <section className="panel" aria-label="Búsqueda SIEM">
      <form className="stack" aria-label="Filtros de búsqueda" onSubmit={submit}>
        <div className="form-grid">
          <label className="small">
            Últimas horas
            <input type="number" min={1} max={744} value={form.hours} onChange={(e) => setForm({ ...form, hours: e.target.value })} />
          </label>
          <label className="small">
            Tipo de fuente
            <select value={form.sourceType} onChange={(e) => setForm({ ...form, sourceType: e.target.value })}>
              <option value="">Todas</option>
              <option value="syslog">Syslog</option>
              <option value="suricata_eve">Suricata</option>
              <option value="zeek_json">Zeek</option>
              <option value="wazuh_alerts">Wazuh</option>
              <option value="sentra_json">Contrato Sentra</option>
            </select>
          </label>
          {field("eventType", "Tipo de evento", { placeholder: "ids.alert", pattern: "[a-z0-9_.]{1,48}" })}
          {field("ip", "IP o CIDR", { placeholder: "10.0.0.0/24" })}
          {field("port", "Puerto", { inputMode: "numeric" })}
          {field("username", "Usuario (exacto)")}
          {field("hostname", "Equipo (exacto)")}
          {field("ruleId", "Regla de origen")}
          {field("mitre", "Técnica MITRE", { placeholder: "T1110" })}
          {field("text", "Texto en el mensaje", { minLength: 3, maxLength: 100 })}
        </div>
        <div className="actions">
          <button type="submit" className="button button--primary" disabled={busy}>
            {busy ? "Buscando…" : "Buscar"}
          </button>
          <input
            aria-label="Nombre de la búsqueda"
            placeholder="Nombre para guardar"
            value={saveName}
            maxLength={100}
            onChange={(e) => setSaveName(e.target.value)}
          />
          <button type="button" className="button" disabled={!saveName.trim()} onClick={() => void save()}>
            Guardar búsqueda
          </button>
          {items.length > 0 && (
            <button type="button" className="button" onClick={() => void exportShown()}>
              Exportar evidencia ({items.length})
            </button>
          )}
        </div>
      </form>
      {(saved.data?.items.length ?? 0) > 0 && (
        <ul className="small" aria-label="Búsquedas guardadas">
          {saved.data?.items.map((s) => (
            <li key={s.search_id}>
              <button type="button" className="link-button" onClick={() => setForm(formFromSaved(s.query))}>
                {s.name}
              </button>{" "}
              <button type="button" className="link-button muted" aria-label={`Borrar ${s.name}`} onClick={() => void remove(s)}>
                borrar
              </button>
            </li>
          ))}
        </ul>
      )}
      {error && (
        <p className="banner banner--warn" role="alert">
          {error}
        </p>
      )}
      {info && (
        <p className="small" role="status">
          {info}
        </p>
      )}
      {count && (
        <p className="muted small">
          {count.capped ? `Más de ${count.value}` : count.value} eventos · {count.ms} ms
        </p>
      )}
      {filter && items.length === 0 && !busy && !error ? (
        <EmptyState title="Sin resultados">Pruebe con una ventana mayor o menos filtros.</EmptyState>
      ) : (
        items.length > 0 && <SiemEventsTable items={items} onOpen={(e) => setOpened(e.event_id)} />
      )}
      {cursor && filter && (
        <div className="actions">
          <button type="button" className="button" disabled={busy} onClick={() => void run(filter, cursor)}>
            Cargar más
          </button>
        </div>
      )}
      {opened && (
        <SiemEventDetailModal
          eventId={opened}
          onClose={() => {
            setOpened(undefined);
            if (params.get("event")) {
              const next = new URLSearchParams(params);
              next.delete("event");
              setParams(next, { replace: true });
            }
          }}
        />
      )}
    </section>
  );
}
