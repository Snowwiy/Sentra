import { useCallback, useState } from "react";
import { Link } from "react-router-dom";
import { topologyHistoryApi } from "../../api/sentra6e";
import type { NetworkChange, NetworkChangeStatus, NetworkChangeType, TopologyDiff } from "../../api/types";
import { describeDownloadError, verifyDownload } from "../../lib/download";
import { errorMessage, formatDateTime } from "../../lib/format";
import { safeFilename, saveBlob } from "../../lib/reports";
import {
  CHANGE_STATUS_LABELS,
  CHANGE_TYPE_LABELS,
  plainValue,
  SNAPSHOT_QUALITY_LABELS,
} from "../../lib/topologyHistory";
import { usePolling } from "../../lib/usePolling";
import { FilterSelect, Pager } from "../ListControls";
import { ErrorState, LoadingState } from "../StateViews";

const REFRESH_MS = 120_000;
const CHANGE_PAGE = 50;

const toError = (err: unknown) => (err instanceof Error ? err : new Error(String(err)));

/**
 * Historial de la topología (Fase 6E.1): snapshots confirmados, diferencias entre dos de ellos
 * (con exportación verificada por SHA-256), cambios de red detectados y el historial de un nodo
 * o enlace. Revisar un cambio exige topology:manage; el resto es monitoring:read.
 */
export function TopologyHistoryPanel({ siteId, canManage }: { siteId: string | undefined; canManage: boolean }) {
  const [subject, setSubject] = useState<{ type: "node" | "link"; key: string; label: string }>();
  return (
    <div className="stack">
      <SnapshotsAndDiff siteId={siteId} />
      <ChangesPanel siteId={siteId} canManage={canManage} onSubject={setSubject} />
      {subject && <SubjectHistory key={`${subject.type}:${subject.key}`} siteId={siteId} subject={subject} onClose={() => setSubject(undefined)} />}
    </div>
  );
}

function SnapshotsAndDiff({ siteId }: { siteId: string | undefined }) {
  const fetcher = useCallback(
    (signal: AbortSignal) => topologyHistoryApi.snapshots({ siteId, limit: 50 }, signal),
    [siteId],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS);
  const [from, setFrom] = useState<string>();
  const [to, setTo] = useState<string>();
  const [diff, setDiff] = useState<TopologyDiff>();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<{ tone: "ok" | "warn"; text: string }>();

  const items = data?.items ?? [];
  // Por defecto: el penúltimo frente al último (la lista llega del más reciente al más antiguo).
  const fromId = from ?? items[1]?.id;
  const toId = to ?? items[0]?.id;

  const compare = async () => {
    if (!fromId || !toId) return;
    setBusy(true);
    setNotice(undefined);
    try {
      setDiff(await topologyHistoryApi.diff({ siteId, fromSnapshot: fromId, toSnapshot: toId }));
    } catch (err) {
      setNotice({ tone: "warn", text: errorMessage(toError(err)) });
    } finally {
      setBusy(false);
    }
  };

  const exportDiff = async (format: "json" | "csv") => {
    if (!fromId || !toId) return;
    setBusy(true);
    setNotice(undefined);
    try {
      const file = await topologyHistoryApi.exportDiff({ siteId, fromSnapshot: fromId, toSnapshot: toId }, format);
      const rejected = await verifyDownload(file);
      if (rejected) {
        setNotice({ tone: "warn", text: rejected });
        return;
      }
      saveBlob(file.blob, safeFilename(file.filename, `sentra-topology-diff.${format}`));
      setNotice({ tone: "ok", text: "Diferencias exportadas (SHA-256 verificado)." });
    } catch (err) {
      const message = describeDownloadError(err, "la exportación");
      if (message) setNotice({ tone: "warn", text: message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="panel" aria-label="Snapshots de topología">
      <div className="panel__toolbar">
        <h2>Snapshots</h2>
        <span className="actions">
          <button type="button" className="button button--small" disabled={busy || !fromId || !toId || fromId === toId} onClick={() => void compare()}>
            Comparar
          </button>
          <button type="button" className="button button--small" disabled={busy || !fromId || !toId || fromId === toId} onClick={() => void exportDiff("json")}>
            Exportar JSON
          </button>
          <button type="button" className="button button--small" disabled={busy || !fromId || !toId || fromId === toId} onClick={() => void exportDiff("csv")}>
            Exportar CSV
          </button>
        </span>
      </div>
      {notice && (
        <div className={`banner${notice.tone === "warn" ? " banner--warn" : " banner--ok"}`} role={notice.tone === "warn" ? "alert" : "status"}>
          {notice.text}
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando snapshots…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : items.length === 0 ? (
        <p className="muted small panel--padded">
          Aún no hay snapshots: se guardan al reconstruir la topología cuando el resultado se confirma.
        </p>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Desde</th>
                <th>Hasta</th>
                <th>#</th>
                <th>Tomado</th>
                <th>Nodos / enlaces</th>
                <th>Calidad</th>
              </tr>
            </thead>
            <tbody>
              {items.map((s) => (
                <tr key={s.id}>
                  <td>
                    <input
                      type="radio"
                      name="topo-from"
                      aria-label={`Desde el snapshot ${s.sequence}`}
                      checked={fromId === s.id}
                      onChange={() => setFrom(s.id)}
                    />
                  </td>
                  <td>
                    <input
                      type="radio"
                      name="topo-to"
                      aria-label={`Hasta el snapshot ${s.sequence}`}
                      checked={toId === s.id}
                      onChange={() => setTo(s.id)}
                    />
                  </td>
                  <td>
                    {s.sequence}
                    {s.preserved && <span className="badge badge--info">conservado</span>}
                  </td>
                  <td>{formatDateTime(s.taken_at)}</td>
                  <td>
                    {s.node_count} / {s.link_count}
                  </td>
                  <td title={s.quality_reasons.join(", ")}>
                    <span className={s.quality === "complete" ? "badge badge--ok" : "badge badge--warn"}>
                      {SNAPSHOT_QUALITY_LABELS[s.quality] ?? s.quality}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {diff && <DiffView diff={diff} />}
    </section>
  );
}

function DiffView({ diff }: { diff: TopologyDiff }) {
  const types = Object.entries(diff.summary.by_type);
  return (
    <div className="panel--padded stack" aria-label="Diferencias">
      <h3 className="small strong">
        Diferencias entre el snapshot {diff.from_snapshot.sequence} y el {diff.to_snapshot.sequence}: {diff.summary.total}
      </h3>
      {types.length > 0 && (
        <ul className="plain-list small">
          {types.map(([type, count]) => (
            <li key={type}>
              {CHANGE_TYPE_LABELS[type as NetworkChangeType] ?? type}: {count}
            </li>
          ))}
        </ul>
      )}
      {diff.changes.length === 0 ? (
        <p className="muted small">Sin cambios entre los dos snapshots.</p>
      ) : (
        <ul className="plain-list small mono" aria-label="Cambios del diff">
          {diff.changes.slice(0, 200).map((change, i) => {
            const type = typeof change["change_type"] === "string" ? (change["change_type"] as NetworkChangeType) : undefined;
            const label = change["subject_label"] ?? change["subject_key"];
            return (
              <li key={i}>
                {type ? (CHANGE_TYPE_LABELS[type] ?? type) : "cambio"} · {plainValue(label)}
                {change["before"] !== undefined && ` · ${plainValue(change["before"])} → ${plainValue(change["after"])}`}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

function ChangesPanel({
  siteId,
  canManage,
  onSubject,
}: {
  siteId: string | undefined;
  canManage: boolean;
  onSubject: (subject: { type: "node" | "link"; key: string; label: string }) => void;
}) {
  const [status, setStatus] = useState<NetworkChangeStatus | "">("detected");
  const [type, setType] = useState<NetworkChangeType | "">("");
  const [page, setPage] = useState(1);
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      topologyHistoryApi.changes(
        {
          siteId,
          status: status || undefined,
          changeType: type || undefined,
          limit: CHANGE_PAGE,
          offset: (page - 1) * CHANGE_PAGE,
        },
        signal,
      ),
    [siteId, status, type, page],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS, true, true);
  const [busy, setBusy] = useState<string>();
  const [notice, setNotice] = useState<string>();

  const review = async (change: NetworkChange, next: NetworkChangeStatus) => {
    setBusy(change.id);
    setNotice(undefined);
    try {
      await topologyHistoryApi.reviewChange(change.id, { status: next, note: null, version: change.version }, siteId);
    } catch (err) {
      setNotice(errorMessage(toError(err)));
    } finally {
      setBusy(undefined);
      // También tras 409 network_change_conflict: se recarga para ver la revisión ajena.
      refresh();
    }
  };

  return (
    <section className="panel" aria-label="Cambios de red">
      <div className="panel__toolbar panel__toolbar--filters">
        <h2>Cambios de red</h2>
        <FilterSelect
          label="Estado"
          value={status}
          allLabel="todos"
          options={Object.entries(CHANGE_STATUS_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={(v) => {
            setStatus(v as NetworkChangeStatus | "");
            setPage(1);
          }}
        />
        <FilterSelect
          label="Tipo"
          value={type}
          allLabel="todos"
          options={Object.entries(CHANGE_TYPE_LABELS).map(([value, label]) => ({ value, label }))}
          onChange={(v) => {
            setType(v as NetworkChangeType | "");
            setPage(1);
          }}
        />
      </div>
      {notice && (
        <div className="banner banner--warn" role="alert">
          {notice}
        </div>
      )}
      {loading ? (
        <LoadingState label="Cargando cambios…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.items.length === 0 ? (
        <p className="muted small panel--padded">Sin cambios con este filtro.</p>
      ) : (
        <>
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Cuándo</th>
                  <th>Cambio</th>
                  <th>Elemento</th>
                  <th>Antes → después</th>
                  <th>Estado</th>
                  {canManage && <th />}
                </tr>
              </thead>
              <tbody>
                {data.items.map((c) => (
                  <tr key={c.id}>
                    <td>{formatDateTime(c.detected_at)}</td>
                    <td>
                      {CHANGE_TYPE_LABELS[c.change_type] ?? c.change_type}
                      <div className="muted small">
                        {c.source} · confianza {c.confidence}
                      </div>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="link-button"
                        onClick={() => onSubject({ type: c.subject_type, key: c.subject_key, label: c.subject_label ?? c.subject_key })}
                      >
                        {c.subject_label ?? c.subject_key}
                      </button>
                      {c.asset_id && (
                        <>
                          {" "}
                          <Link className="small" to={`/assets/${encodeURIComponent(c.asset_id)}`}>
                            ficha
                          </Link>
                        </>
                      )}
                    </td>
                    <td className="mono small">
                      {plainValue(c.before)} → {plainValue(c.after)}
                    </td>
                    <td>
                      {CHANGE_STATUS_LABELS[c.status] ?? c.status}
                      {c.reviewed_by && <div className="muted small">{c.reviewed_by}</div>}
                    </td>
                    {canManage && (
                      <td>
                        <span className="actions">
                          {c.status !== "confirmed" && (
                            <button type="button" className="button button--small" disabled={busy === c.id} onClick={() => void review(c, "confirmed")}>
                              Confirmar
                            </button>
                          )}
                          {c.status !== "dismissed" && (
                            <button type="button" className="button button--small" disabled={busy === c.id} onClick={() => void review(c, "dismissed")}>
                              Descartar
                            </button>
                          )}
                        </span>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} pages={Math.max(1, Math.ceil(data.total / CHANGE_PAGE))} total={data.total} onPage={setPage} noun="cambios" />
        </>
      )}
    </section>
  );
}

function SubjectHistory({
  siteId,
  subject,
  onClose,
}: {
  siteId: string | undefined;
  subject: { type: "node" | "link"; key: string; label: string };
  onClose: () => void;
}) {
  const fetcher = useCallback(
    (signal: AbortSignal) =>
      subject.type === "node"
        ? topologyHistoryApi.nodeHistory(subject.key, siteId, signal)
        : topologyHistoryApi.linkHistory(subject.key, siteId, signal),
    [subject, siteId],
  );
  const { data, error, loading, refresh } = usePolling(fetcher, REFRESH_MS);
  return (
    <section className="panel" aria-label="Historial del elemento">
      <div className="panel__toolbar">
        <h2>
          Historial de {subject.type === "node" ? "nodo" : "enlace"}: {subject.label}
        </h2>
        <button type="button" className="button button--small" onClick={onClose}>
          Cerrar
        </button>
      </div>
      {loading ? (
        <LoadingState label="Cargando historial…" />
      ) : !data ? (
        <ErrorState message={errorMessage(error ?? new Error("Sin datos"))} onRetry={refresh} />
      ) : data.entries.length === 0 ? (
        <p className="muted small panel--padded">Sin historial en los snapshots conservados.</p>
      ) : (
        <div className="table-wrap">
          <table className="table table--compact">
            <thead>
              <tr>
                <th>Snapshots</th>
                <th>Desde</th>
                <th>Hasta</th>
                <th>Presente</th>
                <th>Valor</th>
              </tr>
            </thead>
            <tbody>
              {data.entries.map((e) => (
                <tr key={e.snapshot_id}>
                  <td>{e.sequence}</td>
                  <td>{formatDateTime(e.since)}</td>
                  <td>{formatDateTime(e.until)}</td>
                  <td>{e.present ? "Sí" : "No"}</td>
                  <td className="mono small">{plainValue(e.value)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
