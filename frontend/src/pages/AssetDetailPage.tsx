import { useCallback, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { sentraApi } from "../api/sentra";
import { AlertTable } from "../components/AlertTable";
import { EventTable } from "../components/EventTable";
import { InventoryPanel } from "../components/InventoryPanel";
import { MetricBar } from "../components/MetricBar";
import { Sparkline } from "../components/Sparkline";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { StatusBadge } from "../components/StatusBadge";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative, formatUptime } from "../lib/format";
import { usePolling } from "../lib/usePolling";

function Field({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{children}</dd>
    </div>
  );
}

// At the agent's default 30 s interval this covers the last hour.
const HISTORY_SAMPLES = 120;

const backLink = (
  <Link to="/" className="back">
    ← Activos
  </Link>
);

export function AssetDetailPage() {
  const { assetId = "" } = useParams();
  const fetchAsset = useCallback(
    (signal: AbortSignal) => sentraApi.getAsset(assetId, signal),
    [assetId],
  );
  const { data: asset, error, loading, refresh } = usePolling(fetchAsset, config.refreshIntervalMs);
  // History and alerts are secondary: their failures must not hide the asset itself.
  const fetchHistory = useCallback(
    (signal: AbortSignal) => sentraApi.getTelemetry(assetId, HISTORY_SAMPLES, signal),
    [assetId],
  );
  const history = usePolling(fetchHistory, config.refreshIntervalMs);
  const fetchAlerts = useCallback(
    (signal: AbortSignal) => sentraApi.listAlerts({ assetId, limit: 20 }, signal),
    [assetId],
  );
  const alerts = usePolling(fetchAlerts, config.refreshIntervalMs);
  const fetchEvents = useCallback(
    (signal: AbortSignal) => sentraApi.listEvents({ assetId, limit: 50 }, signal),
    [assetId],
  );
  const events = usePolling(fetchEvents, config.refreshIntervalMs);

  if (loading) return <LoadingState label="Cargando activo…" />;

  if (!asset) {
    // 422 means the id in the URL is not a valid UUID.
    const notFound = error instanceof ApiError && (error.status === 404 || error.status === 422);
    return (
      <div className="page">
        {backLink}
        {notFound || !error ? (
          <EmptyState title="Activo no encontrado">
            El identificador no corresponde a ningún activo registrado.
          </EmptyState>
        ) : (
          <ErrorState message={errorMessage(error)} onRetry={refresh} />
        )}
      </div>
    );
  }

  const t = asset.latest_telemetry;

  return (
    <div className="page">
      {backLink}
      <div className="page__header">
        <div>
          <h1 className="detail__title">
            {asset.hostname} <StatusBadge status={asset.status} />
          </h1>
          <p className="muted small mono">{asset.asset_id}</p>
        </div>
      </div>

      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <div className="detail-grid">
        <section className="panel">
          <div className="panel__toolbar">
            <h2>Información del sistema</h2>
          </div>
          <dl className="fields">
            <Field label="Hostname">{asset.hostname}</Field>
            <Field label="Estado">
              <StatusBadge status={asset.status} />
            </Field>
            <Field label="Sistema operativo">{asset.os_name}</Field>
            <Field label="Versión">{asset.os_version}</Field>
            <Field label="Arquitectura">{asset.architecture}</Field>
            <Field label="IP" mono>
              {asset.primary_ip}
            </Field>
            <Field label="Versión del agente" mono>
              {asset.agent_version}
            </Field>
            <Field label="First seen">{formatDateTime(asset.first_seen_at)}</Field>
            <Field label="Last seen">
              {formatDateTime(asset.last_seen_at)}
              {asset.last_seen_at && (
                <span className="muted"> ({formatRelative(asset.last_seen_at)})</span>
              )}
            </Field>
          </dl>
        </section>

        <section className="panel">
          <div className="panel__toolbar">
            <h2>Últimas métricas</h2>
            {t && (
              <span className="muted small" title={formatDateTime(t.recorded_at)}>
                {formatRelative(t.recorded_at)}
              </span>
            )}
          </div>
          {t ? (
            <dl className="fields">
              <Field label="CPU">
                <MetricBar value={t.cpu_percent} label="CPU" />
              </Field>
              <Field label="RAM">
                <MetricBar value={t.ram_percent} label="RAM" />
              </Field>
              <Field label="Disco">
                <MetricBar value={t.disk_percent} label="Disco" />
              </Field>
              <Field label="Uptime">{formatUptime(t.uptime_seconds)}</Field>
              <Field label="Medido">{formatDateTime(t.recorded_at)}</Field>
            </dl>
          ) : (
            <EmptyState title="Sin telemetría">Este activo todavía no ha enviado métricas.</EmptyState>
          )}
        </section>
      </div>

      <div className="detail-grid">
        <section className="panel">
          <div className="panel__toolbar">
            <h2>Tendencia</h2>
            <span className="muted small">últimas {history.data?.items.length ?? 0} muestras</span>
          </div>
          {history.data && history.data.items.length > 0 ? (
            <div className="sparks">
              <Sparkline label="CPU" values={history.data.items.map((i) => i.cpu_percent)} />
              <Sparkline label="RAM" values={history.data.items.map((i) => i.ram_percent)} />
              <Sparkline label="Disco" values={history.data.items.map((i) => i.disk_percent)} />
            </div>
          ) : history.loading ? (
            <LoadingState label="Cargando histórico…" />
          ) : history.error ? (
            <ErrorState message={errorMessage(history.error)} onRetry={history.refresh} />
          ) : (
            <EmptyState title="Sin histórico" />
          )}
        </section>

        <section className="panel">
          <div className="panel__toolbar">
            <h2>Alertas del activo</h2>
          </div>
          {alerts.data && alerts.data.items.length > 0 ? (
            <AlertTable alerts={alerts.data.items} showAsset={false} />
          ) : alerts.loading ? (
            <LoadingState label="Cargando alertas…" />
          ) : alerts.error ? (
            <ErrorState message={errorMessage(alerts.error)} onRetry={alerts.refresh} />
          ) : (
            <EmptyState title="Sin alertas para este activo" />
          )}
        </section>
      </div>

      <section className="panel">
        <div className="panel__toolbar">
          <h2>Eventos del sistema</h2>
          <span className="muted small">Visor de eventos: advertencias, errores y críticos</span>
        </div>
        {events.data && events.data.items.length > 0 ? (
          <EventTable events={events.data.items} showAsset={false} />
        ) : events.loading ? (
          <LoadingState label="Cargando eventos…" />
        ) : events.error ? (
          <ErrorState message={errorMessage(events.error)} onRetry={events.refresh} />
        ) : (
          <EmptyState title="Sin eventos reportados" />
        )}
      </section>

      <InventoryPanel assetId={asset.asset_id} />
    </div>
  );
}
