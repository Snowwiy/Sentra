import { useCallback, type ReactNode } from "react";
import { sentraApi } from "../../api/sentra";
import type { Asset } from "../../api/types";
import { config } from "../../config";
import { errorMessage, formatDateTime, formatRelative, formatUptime } from "../../lib/format";
import { usePolling } from "../../lib/usePolling";
import { AlertTable } from "../AlertTable";
import { MetricBar } from "../MetricBar";
import { Sparkline } from "../Sparkline";
import { EmptyState, ErrorState, LoadingState } from "../StateViews";
import { StatusBadge } from "../StatusBadge";
import { ChangesList } from "./ChangesList";

// At the agent's default 30 s interval this covers the last hour.
const HISTORY_SAMPLES = 120;

function Field({ label, children, mono }: { label: string; children: ReactNode; mono?: boolean }) {
  return (
    <div className="field">
      <dt>{label}</dt>
      <dd className={mono ? "mono" : undefined}>{children}</dd>
    </div>
  );
}

export function OverviewTab({ asset }: { asset: Asset }) {
  const assetId = asset.asset_id;
  // Secondary panels: their failures must not hide the asset itself.
  const fetchHistory = useCallback(
    (signal: AbortSignal) => sentraApi.getTelemetry(assetId, HISTORY_SAMPLES, signal),
    [assetId],
  );
  const history = usePolling(fetchHistory, config.refreshIntervalMs);
  const fetchAlerts = useCallback(
    (signal: AbortSignal) => sentraApi.listAlerts({ assetId, active: true, limit: 10 }, signal),
    [assetId],
  );
  const alerts = usePolling(fetchAlerts, config.refreshIntervalMs);
  const t = asset.latest_telemetry;

  return (
    <div className="stack">
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
              {asset.last_seen_at && <span className="muted"> ({formatRelative(asset.last_seen_at)})</span>}
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
            <h2>Alertas activas</h2>
          </div>
          {alerts.data && alerts.data.items.length > 0 ? (
            <AlertTable alerts={alerts.data.items} showAsset={false} />
          ) : alerts.loading ? (
            <LoadingState label="Cargando alertas…" />
          ) : alerts.error ? (
            <ErrorState message={errorMessage(alerts.error)} onRetry={alerts.refresh} />
          ) : (
            <EmptyState title="Sin alertas activas" />
          )}
        </section>
      </div>

      <ChangesList assetId={assetId} limit={10} />
    </div>
  );
}
