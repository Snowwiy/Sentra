import { useCallback, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { aiApi, incidentsApi } from "../api/sentra";
import type { IncidentDetail, IncidentTask, IncidentUserRef, InsightKind } from "../api/types";
import { useAuth } from "../auth/AuthContext";
import { config } from "../config";
import { AIAnalyzePanel } from "../components/ai/AIAnalyzePanel";
import { IncidentActions, type RunAction } from "../components/incidents/IncidentActions";
import { IncidentStatusBadge, LevelBadge } from "../components/incidents/IncidentBadges";
import {
  AssetsTab,
  AuditTab,
  DetectionsTab,
  EvidenceTab,
  NotesTab,
  RiskContributionsTable,
  TimelineTab,
} from "../components/incidents/IncidentTabs";
import { ErrorState, LoadingState } from "../components/StateViews";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import {
  CONFIDENCE_LABELS,
  conflictInfo,
  formatDuration,
  RESOLUTION_LABELS,
  STATUS_LABELS,
  type ConflictInfo,
} from "../lib/incidents";
import { usePolling } from "../lib/usePolling";

type Tab = "overview" | "timeline" | "evidence" | "detections" | "assets" | "notes" | "ai" | "audit";

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Resumen" },
  { key: "timeline", label: "Timeline" },
  { key: "evidence", label: "Evidencia" },
  { key: "detections", label: "Detecciones" },
  { key: "assets", label: "Activos" },
  { key: "notes", label: "Notas" },
  { key: "ai", label: "AI Insights" },
  { key: "audit", label: "Auditoría" },
];

const AI_TASKS: { task: IncidentTask; kind: InsightKind; label: string }[] = [
  { task: "summary", kind: "incident_summary", label: "Resumen" },
  { task: "timeline", kind: "incident_timeline", label: "Explicar timeline" },
  { task: "evidence", kind: "incident_evidence", label: "Explicar evidencia" },
  { task: "next_steps", kind: "incident_next_steps", label: "Siguientes pasos" },
];

function UserName({ user }: { user: IncidentUserRef | null }) {
  if (!user) return <span className="muted">—</span>;
  return (
    <span className={user.active ? "" : "muted"}>
      {user.username}
      {!user.active && " (desactivado)"}
    </span>
  );
}

function Overview({ incident }: { incident: IncidentDetail }) {
  const snapshot = incident.risk.snapshot;
  return (
    <>
      <section className="panel panel--padded">
        <h2>Descripción</h2>
        <p className="note-body">{incident.description || <span className="muted">Sin descripción.</span>}</p>
        <dl className="fields">
          <div className="field">
            <dt>Responsable</dt>
            <dd>
              <UserName user={incident.owner} />
              {incident.assigned_by && (
                <span className="muted small">
                  {" "}
                  · asignado por {incident.assigned_by.username} {formatRelative(incident.assigned_at)}
                </span>
              )}
            </dd>
          </div>
          <div className="field">
            <dt>Creado</dt>
            <dd>
              {formatDateTime(incident.created_at)} · <UserName user={incident.created_by} />
            </dd>
          </div>
          <div className="field">
            <dt>Última modificación</dt>
            <dd>
              {formatDateTime(incident.updated_at)} · <UserName user={incident.updated_by} />
            </dd>
          </div>
          <div className="field">
            <dt>Confianza</dt>
            <dd>
              {incident.confidence ? (
                CONFIDENCE_LABELS[incident.confidence]
              ) : (
                <span className="muted">Sin evidencia suficiente</span>
              )}
            </dd>
          </div>
          <div className="field">
            <dt>Primera / última señal</dt>
            <dd>
              {formatDateTime(incident.first_seen_at)} · {formatDateTime(incident.last_seen_at)}
            </dd>
          </div>
          <div className="field">
            <dt>Edad</dt>
            <dd>{formatDuration(incident.metrics.age_seconds)}</dd>
          </div>
          <div className="field">
            <dt>Tiempo hasta triage</dt>
            <dd>{formatDuration(incident.metrics.time_to_triage_seconds)}</dd>
          </div>
          <div className="field">
            <dt>Tiempo hasta resolución</dt>
            <dd>{formatDuration(incident.metrics.time_to_resolve_seconds)}</dd>
          </div>
          {incident.resolution_category && (
            <div className="field">
              <dt>Resolución</dt>
              <dd>
                {RESOLUTION_LABELS[incident.resolution_category]} · {formatDateTime(incident.resolved_at)} ·{" "}
                <UserName user={incident.resolved_by} />
                {incident.resolution_summary && <div className="note-body muted">{incident.resolution_summary}</div>}
              </dd>
            </div>
          )}
          {incident.duplicate_of && (
            <div className="field">
              <dt>Duplicado de</dt>
              <dd>
                <Link to={`/incidents/${incident.duplicate_of.incident_id}`}>
                  {incident.duplicate_of.key} · {incident.duplicate_of.title}
                </Link>
              </dd>
            </div>
          )}
          {incident.merged_into && (
            <div className="field">
              <dt>Fusionado en</dt>
              <dd>
                <Link to={`/incidents/${incident.merged_into.incident_id}`}>
                  {incident.merged_into.key} · {incident.merged_into.title}
                </Link>{" "}
                <span className="muted small">{formatDateTime(incident.merged_at)}</span>
              </dd>
            </div>
          )}
          {incident.merged_from.length > 0 && (
            <div className="field">
              <dt>Incidentes fusionados</dt>
              <dd>
                {incident.merged_from.map((link, index) => (
                  <span key={link.incident_id}>
                    {index > 0 && ", "}
                    <Link to={`/incidents/${link.incident_id}`}>{link.key}</Link>
                  </span>
                ))}
              </dd>
            </div>
          )}
        </dl>
      </section>

      <section className="panel panel--padded" aria-label="Riesgo">
        <h2>Riesgo</h2>
        <p className="muted small">
          Leído del Risk Engine (no se recalcula aquí). Snapshot del caso:{" "}
          {snapshot.score !== null
            ? `${snapshot.score} (${snapshot.level ?? "—"}, confianza ${snapshot.confidence ?? "—"}) · ${formatDateTime(snapshot.taken_at)}`
            : "sin riesgo evaluado al crear/resolver"}
        </p>
        {incident.risk.assets.length === 0 ? (
          <p className="muted">Sin activos con riesgo evaluado.</p>
        ) : (
          incident.risk.assets.map((asset) => (
            <div key={asset.asset_id}>
              <h3 className="small">
                <Link to={`/assets/${asset.asset_id}?tab=risk`}>{asset.name}</Link>{" "}
                {asset.evaluated ? (
                  <span className="muted">
                    · {asset.score} ({asset.level}, confianza {asset.confidence}) · calculado{" "}
                    {formatRelative(asset.calculated_at)}
                  </span>
                ) : (
                  <span className="muted">· aún no evaluado</span>
                )}
              </h3>
              {asset.evaluated && <RiskContributionsTable items={asset.top_contributors} assetId={asset.asset_id} />}
            </div>
          ))
        )}
      </section>
    </>
  );
}

function IncidentAI({ incident }: { incident: IncidentDetail }) {
  const [task, setTask] = useState<IncidentTask>("summary");
  const current = AI_TASKS.find((t) => t.task === task) ?? { task: "summary", kind: "incident_summary", label: "Resumen" };
  return (
    <>
      <div className="segmented" role="group" aria-label="Tipo de análisis">
        {AI_TASKS.map((t) => (
          <button
            key={t.task}
            type="button"
            className={`segmented__item${task === t.task ? " segmented__item--active" : ""}`}
            aria-pressed={task === t.task}
            onClick={() => setTask(t.task)}
          >
            {t.label}
          </button>
        ))}
      </div>
      <AIAnalyzePanel
        key={current.task}
        title={`IA · ${current.label}`}
        buttonLabel="Analizar con IA"
        kind={current.kind}
        incidentId={incident.incident_id}
        run={(refresh) => aiApi.analyzeIncident(incident.incident_id, current.task, refresh)}
      />
      <p className="muted small">
        La IA solo lee el caso: no cambia estado, responsable, severidad, prioridad ni resolución.
      </p>
    </>
  );
}

function ConflictBanner({ info, onReload }: { info: ConflictInfo; onReload: () => void }) {
  return (
    <div className="banner banner--warn" role="alert">
      Otro operador{info.updatedBy ? ` (${info.updatedBy})` : ""} modificó este incidente
      {info.status ? ` (ahora ${STATUS_LABELS[info.status as keyof typeof STATUS_LABELS] ?? info.status})` : ""}. Tu
      cambio no se aplicó.{" "}
      <button type="button" className="button button--small" onClick={onReload}>
        Recargar
      </button>
    </div>
  );
}

export function IncidentDetailPage() {
  const { incidentId = "" } = useParams();
  const auth = useAuth();
  const [params, setParams] = useSearchParams();
  const requested = (params.get("tab") ?? "overview") as Tab;
  const tabs = TABS.filter((t) => t.key !== "ai" || auth.can("ai:use"));
  const tab: Tab = tabs.some((t) => t.key === requested) ? requested : "overview";
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState<string>();
  const [conflict, setConflict] = useState<ConflictInfo>();

  const fetchIncident = useCallback((signal: AbortSignal) => incidentsApi.get(incidentId, signal), [incidentId]);
  const { data: incident, error, loading, refresh } = usePolling(fetchIncident, config.refreshIntervalMs);

  const run: RunAction = useCallback(
    async (action) => {
      setBusy(true);
      setActionError(undefined);
      setConflict(undefined);
      try {
        await action();
        refresh();
        return true;
      } catch (err) {
        const info = conflictInfo(err);
        // 409 incident_conflict: nunca se reintenta solo ni se pisa el cambio del otro.
        if (info) setConflict(info);
        else setActionError(err instanceof Error ? errorMessage(err) : String(err));
        return false;
      } finally {
        setBusy(false);
      }
    },
    [refresh],
  );

  if (loading) return <LoadingState label="Cargando incidente…" />;
  if (!incident) {
    return (
      <div className="page">
        <Link to="/incidents" className="muted">
          ← Incidentes
        </Link>
        <ErrorState message={error ? errorMessage(error) : "Sin datos"} onRetry={refresh} />
      </div>
    );
  }

  const counts: Partial<Record<Tab, number>> = {
    detections: incident.detections_total,
    assets: incident.asset_refs.length,
    notes: incident.notes_total,
  };
  return (
    <div className="page">
      <Link to="/incidents" className="muted">
        ← Incidentes
      </Link>
      <div className="page__header">
        <div>
          <h1>
            <span className="incident-key">{incident.key}</span> · {incident.title}
          </h1>
          <div className="detection-badges">
            <LevelBadge level={incident.severity} kind="severity" />
            <LevelBadge level={incident.priority} kind="priority" />
            <IncidentStatusBadge status={incident.status} />
            <span className="muted small">
              Responsable: <UserName user={incident.owner} />
            </span>
          </div>
        </div>
      </div>
      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}
      {conflict && (
        <ConflictBanner
          info={conflict}
          onReload={() => {
            setConflict(undefined);
            refresh();
          }}
        />
      )}
      {actionError && (
        <div className="banner banner--warn" role="alert">
          {actionError}
        </div>
      )}
      {incident.status === "merged" && incident.merged_into && (
        <div className="banner" role="note">
          Este incidente se fusionó en{" "}
          <Link to={`/incidents/${incident.merged_into.incident_id}`}>{incident.merged_into.key}</Link>. Continúa el
          trabajo allí.
        </div>
      )}

      <IncidentActions incident={incident} run={run} busy={busy} />

      <nav className="tabs" role="tablist" aria-label="Secciones del incidente">
        {tabs.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => setParams(key === "overview" ? {} : { tab: key }, { replace: true })}
          >
            {label}
            {counts[key] !== undefined && <span className="tabs__count">{counts[key]}</span>}
          </button>
        ))}
      </nav>
      <div role="tabpanel">
        {tab === "overview" && <Overview incident={incident} />}
        {tab === "timeline" && <TimelineTab incident={incident} />}
        {tab === "evidence" && <EvidenceTab incident={incident} />}
        {tab === "detections" && <DetectionsTab incident={incident} />}
        {tab === "assets" && <AssetsTab incident={incident} />}
        {tab === "notes" && <NotesTab incident={incident} run={run} />}
        {tab === "ai" && <IncidentAI incident={incident} />}
        {tab === "audit" && <AuditTab incident={incident} />}
      </div>
    </div>
  );
}
