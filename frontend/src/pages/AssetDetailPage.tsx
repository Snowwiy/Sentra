import { lazy, Suspense, useCallback, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { ApiError } from "../api/client";
import { aiApi, sentraApi, vulnerabilitiesApi } from "../api/sentra";
import { useAuth } from "../auth/AuthContext";
import { AlertsView } from "../components/AlertsView";
import { GenerateReportLink } from "../components/reports/GenerateReportLink";
import { AgentPanel } from "../components/asset/AgentPanel";
import { AssetLabelDialog } from "../components/asset/AssetLabelDialog";
import { AIAnalyzePanel } from "../components/ai/AIAnalyzePanel";
import { ChangesList } from "../components/asset/ChangesList";
import { ContextTab } from "../components/asset/ContextTab";
import { EventsTab } from "../components/asset/EventsTab";
import { ExposureTab } from "../components/asset/ExposureTab";
import { LifecyclePanel } from "../components/asset/LifecyclePanel";
import { NetworkTab } from "../components/asset/NetworkTab";
import { OverviewTab } from "../components/asset/OverviewTab";
import { RiskPanel } from "../components/risk/RiskPanel";
import { ProcessesTab } from "../components/asset/ProcessesTab";
import { ServicesTab } from "../components/asset/ServicesTab";
import { SoftwareTab } from "../components/asset/SoftwareTab";
import { UsersTab } from "../components/asset/UsersTab";
import { countBySoftware, VulnerabilitiesTab } from "../components/asset/VulnerabilitiesTab";
import { EmptyState, ErrorState, LoadingState } from "../components/StateViews";
import { MatchesTable } from "../components/threatintel/MatchesTable";
import { MethodBadge } from "../components/NetworkBadges";
import { AssetStateBadge } from "../components/StatusBadge";
import { config } from "../config";
import { errorMessage, formatDateTime, formatRelative } from "../lib/format";
import { assetTitle, automaticTitle, typeWithConfidence } from "../lib/identity";
import { usePolling } from "../lib/usePolling";

// Fase 5D: la sección Response va en su propio chunk (no pesa en el bundle principal).
const AssetResponseTab = lazy(() =>
  import("../components/response/AssetResponseTab").then((m) => ({ default: m.AssetResponseTab })),
);

// Fase 6E: identidad y DHCP, telemetría y árbol de procesos, investigaciones y aislamiento,
// cada uno en su propio chunk: solo se descargan al abrir su pestaña.
const IdentityTab = lazy(() => import("../components/dhcp/IdentityTab").then((m) => ({ default: m.IdentityTab })));
const EndpointTelemetryTab = lazy(() =>
  import("../components/endpoint/EndpointTelemetryTab").then((m) => ({ default: m.EndpointTelemetryTab })),
);
const AssetInvestigationsTab = lazy(() =>
  import("../components/forensics/AssetInvestigationsTab").then((m) => ({ default: m.AssetInvestigationsTab })),
);
const IsolationTab = lazy(() => import("../components/isolation/IsolationTab").then((m) => ({ default: m.IsolationTab })));

const TABS = [
  { key: "overview", label: "Overview" },
  { key: "identity", label: "Identidad" },
  { key: "risk", label: "Riesgo" },
  { key: "context", label: "Contexto" },
  { key: "processes", label: "Procesos" },
  { key: "services", label: "Services" },
  { key: "software", label: "Software" },
  { key: "network", label: "Network" },
  { key: "users", label: "Users" },
  { key: "events", label: "Events" },
  { key: "exposure", label: "Exposure" },
  { key: "vulnerabilities", label: "Vulnerabilidades" },
  { key: "intel", label: "Inteligencia" },
  { key: "alerts", label: "Alerts" },
  { key: "response", label: "Response" },
  { key: "investigations", label: "Investigaciones" },
  { key: "isolation", label: "Aislamiento" },
] as const;

type Tab = (typeof TABS)[number]["key"];

// Without an agent only what the network shows exists: no inventory, telemetry or events.
// Fase 5B: la pestaña de vulnerabilidades también aparece sin agente (explica por qué no hay
// evaluación) pero solo con vulnerabilities:read.
// Fase 5C: "Inteligencia" (coincidencias de IOCs) también sin agente: la IP o el nombre del
// activo pueden coincidir con un indicador.
// Fase 5D: "Response" también sin agente (hay acciones de servidor, como recalcular riesgo).
// Fase 6E: "Identidad" (nombres, DHCP) e "Investigaciones" también sin agente; "Aislamiento"
// también, para explicar que no está disponible y dar las recomendaciones manuales.
const NETWORK_TABS: Tab[] = [
  "overview",
  "identity",
  "risk",
  "context",
  "exposure",
  "vulnerabilities",
  "intel",
  "alerts",
  "response",
  "investigations",
  "isolation",
];
const tabFallback = <LoadingState label="Cargando…" />;

// Tabs fed by the inventory snapshot (sent every 15 min): polled only while one is visible.
const INVENTORY_TABS: Tab[] = ["processes", "services", "software", "network", "users"];
const INVENTORY_REFRESH_MS = Math.max(config.refreshIntervalMs, 60_000);

const backLink = (
  <Link to="/" className="back">
    ← Activos
  </Link>
);

function isTab(value: string | null): value is Tab {
  return TABS.some((tab) => tab.key === value);
}

export function AssetDetailPage() {
  const { assetId = "" } = useParams();
  const auth = useAuth();
  const canVulns = auth.can("vulnerabilities:read");
  const canLabel = auth.can("assets:manage");
  const [editingLabel, setEditingLabel] = useState(false);
  const [params, setParams] = useSearchParams();
  const raw = params.get("tab");
  const requested: Tab = isTab(raw) ? raw : "overview";

  const fetchAsset = useCallback(
    (signal: AbortSignal) => sentraApi.getAsset(assetId, signal),
    [assetId],
  );
  const { data: asset, error, loading, refresh } = usePolling(fetchAsset, config.refreshIntervalMs);
  // 404, or 422 when the id in the URL is not a valid UUID. Such an asset does not appear later
  // (ids are generated by the server), so nothing else is fetched for it.
  const notFound =
    !asset && error instanceof ApiError && (error.status === 404 || error.status === 422);
  const managed = asset ? asset.monitoring_method === "agent" : true;
  const tabs = (managed ? TABS : TABS.filter((t) => NETWORK_TABS.includes(t.key))).filter(
    (t) =>
      (t.key !== "vulnerabilities" || canVulns) &&
      (t.key !== "intel" || auth.can("threat_intel:read")) &&
      (t.key !== "response" || auth.can("response:read")) &&
      (t.key !== "investigations" || auth.can("forensics:read")) &&
      (t.key !== "isolation" || auth.can("containment:preview")),
  );
  const tab: Tab = tabs.some((t) => t.key === requested) ? requested : "overview";

  const fetchInventory = useCallback(
    (signal: AbortSignal) => sentraApi.getInventory(assetId, signal),
    [assetId],
  );
  const inventory = usePolling(
    fetchInventory,
    INVENTORY_REFRESH_MS,
    Boolean(asset) && managed && INVENTORY_TABS.includes(tab),
  );
  const noInventory = inventory.error instanceof ApiError && inventory.error.status === 404;
  // Fase 5B: "Vulnerabilidades conocidas" por programa en la pestaña Software.
  const fetchKnown = useCallback(
    (signal: AbortSignal) => vulnerabilitiesApi.asset(assetId, { active: true, limit: 200 }, signal),
    [assetId],
  );
  const known = usePolling(fetchKnown, INVENTORY_REFRESH_MS, Boolean(asset) && canVulns && tab === "software");

  if (loading) return <LoadingState label="Cargando activo…" />;

  if (!asset) {
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

  const selectTab = (key: Tab) =>
    setParams(key === "overview" ? {} : { tab: key }, { replace: true });
  const inv = inventory.data;

  const inventoryContent = () => {
    if (tab === "processes") {
      // Has its own snapshot endpoint; the inventory list is only a fallback for older agents.
      // Fase 6E.4: con telemetry:read, encima el árbol de procesos con carga diferida.
      return (
        <div className="stack">
          {auth.can("telemetry:read") && (
            <Suspense fallback={tabFallback}>
              <EndpointTelemetryTab assetId={asset.asset_id} />
            </Suspense>
          )}
          <ProcessesTab assetId={asset.asset_id} inventoryProcesses={inv?.processes} />
        </div>
      );
    }
    if (inventory.loading) return <LoadingState label="Cargando inventario…" />;
    if (!inv && noInventory) {
      return (
        <EmptyState title="Sin inventario">
          El agente envía el inventario al arrancar y cada 15 minutos.
        </EmptyState>
      );
    }
    if (!inv) {
      return (
        <ErrorState
          message={inventory.error ? errorMessage(inventory.error) : "Sin datos"}
          onRetry={inventory.refresh}
        />
      );
    }
    const collected = (
      <p className="muted small inventory-age" title={formatDateTime(inv.collected_at)}>
        Inventario recogido {formatRelative(inv.collected_at)}
      </p>
    );
    switch (tab) {
      case "services":
        return (
          <div className="stack">
            <section className="panel">
              <ServicesTab services={inv.services} />
            </section>
            {collected}
            <ChangesList assetId={asset.asset_id} category="service" title="Cambios en servicios" />
          </div>
        );
      case "software":
        return (
          <div className="stack">
            <section className="panel">
              <SoftwareTab software={inv.software} known={known.data ? countBySoftware(known.data.items) : undefined} />
            </section>
            {collected}
            <ChangesList assetId={asset.asset_id} category="software" title="Cambios de software" />
          </div>
        );
      case "network":
        return (
          <div className="stack">
            <NetworkTab
              interfaces={inv.interfaces}
              connections={inv.connections ?? []}
              summary={inv.network}
            />
            {collected}
          </div>
        );
      case "users":
        return (
          <div className="stack">
            <UsersTab sessions={inv.users} accounts={inv.accounts} />
            {collected}
            <ChangesList assetId={asset.asset_id} category="account" title="Cambios en cuentas" />
          </div>
        );
      default:
        return null;
    }
  };

  return (
    <div className="page">
      {backLink}
      <div className="page__header">
        <div>
          <h1 className="detail__title">
            {assetTitle(asset)} <AssetStateBadge asset={asset} />{" "}
            <MethodBadge method={asset.monitoring_method} />
          </h1>
          <p className="muted small">
            <span className="mono">{asset.primary_ip}</span> · {typeWithConfidence(asset)}
            {asset.device_vendor && ` · ${asset.device_vendor}`}
            {/* Fase 5F: site del activo. */}
            {asset.site_name && (
              <>
                {" · "}
                <span className="badge badge--info" title="Site del activo">
                  Site: {asset.site_name}
                </span>
              </>
            )}
          </p>
          {asset.custom_label && (
            <p className="muted small">
              Etiqueta personalizada · nombre automático: {automaticTitle(asset)}
            </p>
          )}
          <p className="muted small mono">{asset.asset_id}</p>
        </div>
        <div className="actions">
          {canLabel && (
            <button type="button" className="button" onClick={() => setEditingLabel(true)}>
              {asset.custom_label ? "Editar etiqueta" : "Poner etiqueta"}
            </button>
          )}
          <GenerateReportLink type="asset" ids={{ asset_id: asset.asset_id }} />
        </div>
      </div>

      {editingLabel && (
        <AssetLabelDialog asset={asset} onClose={() => setEditingLabel(false)} onSaved={() => refresh()} />
      )}

      {error && (
        <div className="banner banner--warn" role="alert">
          Fallo al actualizar: {errorMessage(error)}. Se muestran los últimos datos recibidos.
        </div>
      )}

      <nav className="tabs" role="tablist" aria-label="Secciones del activo">
        {tabs.map(({ key, label }) => (
          <button
            key={key}
            type="button"
            role="tab"
            aria-selected={tab === key}
            className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
            onClick={() => selectTab(key)}
          >
            {label}
          </button>
        ))}
      </nav>

      <div role="tabpanel">
        {tab === "overview" && (
          <div className="stack">
            <LifecyclePanel asset={asset} onChanged={refresh} />
            <OverviewTab asset={asset} />
            <AIAnalyzePanel
              title="AI Insights del activo"
              buttonLabel="Analizar con IA"
              kind="asset_summary"
              assetId={asset.asset_id}
              run={(refresh) => aiApi.analyzeAsset(asset.asset_id, refresh)}
            />
            {managed && <AgentPanel assetId={asset.asset_id} />}
          </div>
        )}
        {INVENTORY_TABS.includes(tab) && inventoryContent()}
        {tab === "events" && <EventsTab asset={asset} />}
        {tab === "exposure" && <ExposureTab assetId={asset.asset_id} managed={managed} />}
        {tab === "risk" && <RiskPanel assetId={asset.asset_id} />}
        {tab === "context" && <ContextTab assetId={asset.asset_id} />}
        {tab === "vulnerabilities" && <VulnerabilitiesTab assetId={asset.asset_id} />}
        {tab === "intel" && (
          <div className="stack">
            <p className="muted small">
              Datos de este activo que coinciden con indicadores de inteligencia. Una coincidencia no confirma un
              compromiso: requiere análisis.
            </p>
            <MatchesTable assetId={asset.asset_id} />
          </div>
        )}
        {tab === "alerts" && <AlertsView assetId={asset.asset_id} />}
        {tab === "identity" && (
          <Suspense fallback={tabFallback}>
            <IdentityTab assetId={asset.asset_id} />
          </Suspense>
        )}
        {tab === "investigations" && (
          <Suspense fallback={tabFallback}>
            <AssetInvestigationsTab assetId={asset.asset_id} managed={managed} />
          </Suspense>
        )}
        {tab === "isolation" && (
          <Suspense fallback={tabFallback}>
            <IsolationTab assetId={asset.asset_id} />
          </Suspense>
        )}
        {tab === "response" && (
          <Suspense fallback={<LoadingState label="Cargando response…" />}>
            <AssetResponseTab assetId={asset.asset_id} assetLabel={assetTitle(asset)} />
          </Suspense>
        )}
      </div>
    </div>
  );
}
