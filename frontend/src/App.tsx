import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AgentsPage } from "./pages/AgentsPage";
import { AlertsPage } from "./pages/AlertsPage";
import { AssetDetailPage } from "./pages/AssetDetailPage";
import { DashboardPage } from "./pages/DashboardPage";
import { NetworkPage } from "./pages/NetworkPage";
import { NotFoundPage } from "./pages/NotFoundPage";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<DashboardPage />} />
          <Route path="assets/:assetId" element={<AssetDetailPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="network" element={<NetworkPage />} />
          <Route path="alerts" element={<AlertsPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
