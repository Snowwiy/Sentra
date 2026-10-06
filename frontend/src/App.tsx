import { lazy, Suspense } from "react";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { AuthProvider } from "./auth/AuthContext";
import { LoginPage } from "./auth/LoginPage";
import { RequireAuth, RequirePermission } from "./auth/RequireAuth";
import { Layout } from "./components/Layout";
import { AIInsightsPage } from "./pages/AIInsightsPage";
import { AgentsPage } from "./pages/AgentsPage";
import { AlertsPage } from "./pages/AlertsPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { DashboardPage } from "./pages/DashboardPage";
import { DetectionDetailPage } from "./pages/DetectionDetailPage";
import { DetectionsPage } from "./pages/DetectionsPage";
import { LocalAIPage } from "./pages/LocalAIPage";
import { NetworkPage } from "./pages/NetworkPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { RiskPage } from "./pages/RiskPage";
import { UsersPage } from "./pages/UsersPage";
import { LoadingState } from "./components/StateViews";

// Incidentes (Fase 4K) en su propio chunk: el bundle principal no crece para quien no los usa.
const IncidentsPage = lazy(() => import("./pages/IncidentsPage").then((m) => ({ default: m.IncidentsPage })));
const IncidentDetailPage = lazy(() =>
  import("./pages/IncidentDetailPage").then((m) => ({ default: m.IncidentDetailPage })),
);
const incidentsFallback = <LoadingState label="Cargando incidentes…" />;
// Reglas de detección (Fase 5A): también en su propio chunk (editor e importación Sigma).
const RulesPage = lazy(() => import("./pages/RulesPage").then((m) => ({ default: m.RulesPage })));
const RuleDetailPage = lazy(() => import("./pages/RuleDetailPage").then((m) => ({ default: m.RuleDetailPage })));
const RuleEditorPage = lazy(() => import("./pages/RuleEditorPage").then((m) => ({ default: m.RuleEditorPage })));
const rulesFallback = <LoadingState label="Cargando reglas…" />;

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
          <Route path="assets/:assetId" element={<AssetDetailPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="risk" element={<RiskPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="detections" element={<DetectionsPage />} />
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
          <Route path="detections/:detectionId" element={<DetectionDetailPage />} />
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
            path="ai"
            element={
              <RequirePermission permission="ai:use">
                <AIInsightsPage />
              </RequirePermission>
            }
          />
          <Route
            path="settings/ai"
            element={
              <RequirePermission permission="ai:use">
                <LocalAIPage />
              </RequirePermission>
            }
          />
          <Route
            path="admin/users"
            element={
              <RequirePermission permission="users:manage">
                <UsersPage />
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
