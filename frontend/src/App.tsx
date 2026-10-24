import { lazy, Suspense, type ReactNode } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { LoginPage } from "./auth/LoginPage";
import { RequireAuth, RequirePermission } from "./auth/RequireAuth";
import { Layout } from "./components/Layout";
import { DashboardPage } from "./pages/DashboardPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { LoadingState } from "./components/StateViews";

// Fase 6E: el bundle principal solo lleva la sesión, el layout y el dashboard (la página de
// entrada). El resto de páginas, que antes se importaban siempre, va en su propio chunk y se
// descarga al abrirlas por primera vez.
const AIInsightsPage = lazy(() => import("./pages/AIInsightsPage").then((m) => ({ default: m.AIInsightsPage })));
const AgentsPage = lazy(() => import("./pages/AgentsPage").then((m) => ({ default: m.AgentsPage })));
const AlertsPage = lazy(() => import("./pages/AlertsPage").then((m) => ({ default: m.AlertsPage })));
const AssetDetailPage = lazy(() => import("./pages/AssetDetailPage").then((m) => ({ default: m.AssetDetailPage })));
const DetectionDetailPage = lazy(() =>
  import("./pages/DetectionDetailPage").then((m) => ({ default: m.DetectionDetailPage })),
);
const DetectionsPage = lazy(() => import("./pages/DetectionsPage").then((m) => ({ default: m.DetectionsPage })));
const LocalAIPage = lazy(() => import("./pages/LocalAIPage").then((m) => ({ default: m.LocalAIPage })));
const NetworkPage = lazy(() => import("./pages/NetworkPage").then((m) => ({ default: m.NetworkPage })));
const RiskPage = lazy(() => import("./pages/RiskPage").then((m) => ({ default: m.RiskPage })));
const SettingsPage = lazy(() => import("./pages/SettingsPage").then((m) => ({ default: m.SettingsPage })));
const UsersPage = lazy(() => import("./pages/UsersPage").then((m) => ({ default: m.UsersPage })));
// Fase 6E: DHCP, excepciones de reglas, investigaciones forenses y aislamiento.
const DhcpPage = lazy(() => import("./pages/DhcpPage").then((m) => ({ default: m.DhcpPage })));
const DetectionExclusionsPage = lazy(() =>
  import("./pages/DetectionExclusionsPage").then((m) => ({ default: m.DetectionExclusionsPage })),
);
const InvestigationsPage = lazy(() =>
  import("./pages/InvestigationsPage").then((m) => ({ default: m.InvestigationsPage })),
);
const InvestigationDetailPage = lazy(() =>
  import("./pages/InvestigationDetailPage").then((m) => ({ default: m.InvestigationDetailPage })),
);
const ContainmentPage = lazy(() => import("./pages/ContainmentPage").then((m) => ({ default: m.ContainmentPage })));

const pageFallback = <LoadingState label="Cargando…" />;

/** Página cargada con React.lazy dentro de su Suspense. */
function page(node: ReactNode, fallback: ReactNode = pageFallback) {
  return <Suspense fallback={fallback}>{node}</Suspense>;
}

// Incidentes (Fase 4K) en su propio chunk: el bundle principal no crece para quien no los usa.
const IncidentsPage = lazy(() => import("./pages/IncidentsPage").then((m) => ({ default: m.IncidentsPage })));
const IncidentDetailPage = lazy(() =>
  import("./pages/IncidentDetailPage").then((m) => ({ default: m.IncidentDetailPage })),
);
const incidentsFallback = <LoadingState label="Cargando incidentes…" />;
// Reglas de detección (Fase 5A): también en su propio chunk (editor e importación Sigma).
// Vulnerabilidades (Fase 5B) en su propio chunk.
const VulnerabilitiesPage = lazy(() =>
  import("./pages/VulnerabilitiesPage").then((m) => ({ default: m.VulnerabilitiesPage })),
);
const VulnerabilityDetailPage = lazy(() =>
  import("./pages/VulnerabilityDetailPage").then((m) => ({ default: m.VulnerabilityDetailPage })),
);
const VulnerabilityCatalogPage = lazy(() =>
  import("./pages/VulnerabilityCatalogPage").then((m) => ({ default: m.VulnerabilityCatalogPage })),
);
const CveDetailPage = lazy(() => import("./pages/CveDetailPage").then((m) => ({ default: m.CveDetailPage })));
// Fase 5C: Threat Intelligence en su propio chunk.
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntelPage").then((m) => ({ default: m.ThreatIntelPage })));
const ThreatIndicatorDetailPage = lazy(() =>
  import("./pages/ThreatIndicatorDetailPage").then((m) => ({ default: m.ThreatIndicatorDetailPage })),
);
const ThreatMatchDetailPage = lazy(() =>
  import("./pages/ThreatMatchDetailPage").then((m) => ({ default: m.ThreatMatchDetailPage })),
);
const ExposurePage = lazy(() => import("./pages/ExposurePage").then((m) => ({ default: m.ExposurePage })));
const RulesPage = lazy(() => import("./pages/RulesPage").then((m) => ({ default: m.RulesPage })));
const RuleDetailPage = lazy(() => import("./pages/RuleDetailPage").then((m) => ({ default: m.RuleDetailPage })));
const RuleEditorPage = lazy(() => import("./pages/RuleEditorPage").then((m) => ({ default: m.RuleEditorPage })));
const rulesFallback = <LoadingState label="Cargando reglas…" />;
// Fase 5C.2: administración del ciclo de vida (solo admin) en su propio chunk.
// Fase 5D: Response Engine y Playbooks en su propio chunk.
const ResponsePage = lazy(() => import("./pages/ResponsePage").then((m) => ({ default: m.ResponsePage })));
const PlaybooksPage = lazy(() => import("./pages/PlaybooksPage").then((m) => ({ default: m.PlaybooksPage })));
// Fase 5E: informes y exportación de evidencias en su propio chunk.
const ReportsPage = lazy(() => import("./pages/ReportsPage").then((m) => ({ default: m.ReportsPage })));
const ReportDetailPage = lazy(() =>
  import("./pages/ReportDetailPage").then((m) => ({ default: m.ReportDetailPage })),
);
const reportsFallback = <LoadingState label="Cargando informes…" />;
// Fase 5F: sites y sensores distribuidos en su propio chunk.
const SitesPage = lazy(() => import("./pages/SitesPage").then((m) => ({ default: m.SitesPage })));
const SensorsPage = lazy(() => import("./pages/SensorsPage").then((m) => ({ default: m.SensorsPage })));
// Fase 6B: infraestructura de red (SNMP / LLDP / CDP) en su propio chunk.
const InfrastructurePage = lazy(() =>
  import("./pages/InfrastructurePage").then((m) => ({ default: m.InfrastructurePage })),
);
const InfrastructureDevicePage = lazy(() =>
  import("./pages/InfrastructureDevicePage").then((m) => ({ default: m.InfrastructureDevicePage })),
);
// Fase 6C.3: inventario Wi-Fi / AP / WLAN en su propio chunk.
const WlanPage = lazy(() => import("./pages/WlanPage").then((m) => ({ default: m.WlanPage })));
const infrastructureFallback = <LoadingState label="Cargando infraestructura…" />;
// Topología de red (Fase 6D): su propio chunk (lienzo SVG y exportación).
const TopologyPage = lazy(() => import("./pages/TopologyPage").then((m) => ({ default: m.TopologyPage })));
const LifecyclePage = lazy(() => import("./pages/LifecyclePage").then((m) => ({ default: m.LifecyclePage })));

export function AppRoutes() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="login" element={<LoginPage />} />
        {/* Todo lo demás exige sesión; sin ella, /login. */}
        <Route
          element={
            <RequireAuth>
              <Layout />
            </RequireAuth>
          }
        >
          <Route index element={<DashboardPage />} />
          <Route path="assets/:assetId" element={page(<AssetDetailPage />)} />
          <Route path="agents" element={page(<AgentsPage />)} />
          <Route path="network" element={page(<NetworkPage />)} />
          <Route path="risk" element={page(<RiskPage />)} />
          <Route path="alerts" element={page(<AlertsPage />)} />
          <Route path="detections" element={page(<DetectionsPage />)} />
          <Route
            path="detections/rules"
            element={
              <RequirePermission permission="rules:read">
                <Suspense fallback={rulesFallback}>
                  <RulesPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="detections/rules/new"
            element={
              <RequirePermission permission="rules:manage">
                <Suspense fallback={rulesFallback}>
                  <RuleEditorPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="detections/rules/:ruleId"
            element={
              <RequirePermission permission="rules:read">
                <Suspense fallback={rulesFallback}>
                  <RuleDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="detections/rules/:ruleId/edit"
            element={
              <RequirePermission permission="rules:manage">
                <Suspense fallback={rulesFallback}>
                  <RuleEditorPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="detections/exclusions"
            element={<RequirePermission permission="rules:read">{page(<DetectionExclusionsPage />, rulesFallback)}</RequirePermission>}
          />
          <Route path="detections/:detectionId" element={page(<DetectionDetailPage />)} />
          <Route
            path="vulnerabilities"
            element={
              <RequirePermission permission="vulnerabilities:read">
                <Suspense fallback={incidentsFallback}>
                  <VulnerabilitiesPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="vulnerabilities/exposure"
            element={
              <RequirePermission permission="vulnerabilities:read">
                <Suspense fallback={incidentsFallback}>
                  <ExposurePage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="vulnerabilities/catalog"
            element={
              // Fase 6C.4: el estado del catálogo lo ve cualquier lector; las acciones de
              // importación y sincronización se ocultan sin vulnerabilities:admin.
              <RequirePermission permission="vulnerabilities:read">
                <Suspense fallback={incidentsFallback}>
                  <VulnerabilityCatalogPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="vulnerabilities/catalog/cves/:cveId"
            element={
              <RequirePermission permission="vulnerabilities:read">
                <Suspense fallback={incidentsFallback}>
                  <CveDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="vulnerabilities/:findingId"
            element={
              <RequirePermission permission="vulnerabilities:read">
                <Suspense fallback={incidentsFallback}>
                  <VulnerabilityDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="threat-intel"
            element={
              <RequirePermission permission="threat_intel:read">
                <Suspense fallback={incidentsFallback}>
                  <ThreatIntelPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="threat-intel/indicators/:indicatorId"
            element={
              <RequirePermission permission="threat_intel:read">
                <Suspense fallback={incidentsFallback}>
                  <ThreatIndicatorDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="threat-intel/matches/:matchId"
            element={
              <RequirePermission permission="threat_intel:read">
                <Suspense fallback={incidentsFallback}>
                  <ThreatMatchDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="incidents"
            element={
              <RequirePermission permission="incidents:read">
                <Suspense fallback={incidentsFallback}>
                  <IncidentsPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="incidents/:incidentId"
            element={
              <RequirePermission permission="incidents:read">
                <Suspense fallback={incidentsFallback}>
                  <IncidentDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="response"
            element={
              <RequirePermission permission="response:read">
                <Suspense fallback={incidentsFallback}>
                  <ResponsePage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="playbooks"
            element={
              <RequirePermission permission="response:read">
                <Suspense fallback={incidentsFallback}>
                  <PlaybooksPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="reports"
            element={
              <RequirePermission permission="reports:read">
                <Suspense fallback={reportsFallback}>
                  <ReportsPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="reports/:reportId"
            element={
              <RequirePermission permission="reports:read">
                <Suspense fallback={reportsFallback}>
                  <ReportDetailPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="ai"
            element={
              <RequirePermission permission="ai:use">
                {page(<AIInsightsPage />)}
              </RequirePermission>
            }
          />
          <Route path="settings" element={page(<SettingsPage />)} />
          <Route
            path="settings/ai"
            element={
              <RequirePermission permission="ai:use">
                {page(<LocalAIPage />)}
              </RequirePermission>
            }
          />
          <Route
            path="settings/sites"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={incidentsFallback}>
                  <SitesPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="sensors"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={incidentsFallback}>
                  <SensorsPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="infrastructure"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={infrastructureFallback}>
                  <InfrastructurePage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="infrastructure/devices/:deviceId"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={infrastructureFallback}>
                  <InfrastructureDevicePage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="wlan"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={<LoadingState label="Cargando Wi-Fi…" />}>
                  <WlanPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="topology"
            element={
              <RequirePermission permission="monitoring:read">
                <Suspense fallback={<LoadingState label="Cargando topología…" />}>
                  <TopologyPage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route
            path="dhcp"
            element={<RequirePermission permission="monitoring:read">{page(<DhcpPage />, infrastructureFallback)}</RequirePermission>}
          />
          <Route
            path="investigations"
            element={<RequirePermission permission="forensics:read">{page(<InvestigationsPage />)}</RequirePermission>}
          />
          <Route
            path="investigations/:investigationId"
            element={<RequirePermission permission="forensics:read">{page(<InvestigationDetailPage />)}</RequirePermission>}
          />
          <Route
            path="containment"
            element={<RequirePermission permission="containment:preview">{page(<ContainmentPage />)}</RequirePermission>}
          />
          <Route
            path="admin/users"
            element={
              <RequirePermission permission="users:manage">
                {page(<UsersPage />)}
              </RequirePermission>
            }
          />
          <Route
            path="admin/lifecycle"
            element={
              <RequirePermission permission="assets:manage">
                <Suspense fallback={incidentsFallback}>
                  <LifecyclePage />
                </Suspense>
              </RequirePermission>
            }
          />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </AuthProvider>
  );
}

export function App() {
  return (
    <BrowserRouter>
      <AppRoutes />
    </BrowserRouter>
  );
}
