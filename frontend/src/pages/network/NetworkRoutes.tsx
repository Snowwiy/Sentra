import { lazy, type ComponentType, type LazyExoticComponent } from "react";
import { Navigate, Route, useLocation } from "react-router-dom";
import { RequirePermission } from "../../auth/RequireAuth";
import { NotFoundPage } from "../NotFoundPage";
import { NETWORK_TABS, type NetworkTabKey } from "./tabs";

// Cada pestaña va en su propio chunk: abrir Red no descarga la topología (lienzo SVG y
// exportación) ni la tabla de dispositivos si no se visitan. El Suspense lo pone el hub
// alrededor del panel, así la barra de pestañas no parpadea al cambiar de pestaña.
const TAB_COMPONENTS: Record<NetworkTabKey, LazyExoticComponent<ComponentType>> = {
  overview: lazy(() => import("./OverviewTab").then((m) => ({ default: m.OverviewTab }))),
  devices: lazy(() => import("./DevicesTab").then((m) => ({ default: m.DevicesTab }))),
  discovery: lazy(() => import("./DiscoveryTab").then((m) => ({ default: m.DiscoveryTab }))),
  topology: lazy(() => import("./TopologyTab").then((m) => ({ default: m.TopologyTab }))),
  services: lazy(() => import("./ServicesTab").then((m) => ({ default: m.ServicesTab }))),
  changes: lazy(() => import("./ChangesTab").then((m) => ({ default: m.ChangesTab }))),
  identity: lazy(() => import("./IdentityEvidenceTab").then((m) => ({ default: m.IdentityEvidenceTab }))),
  telemetry: lazy(() => import("./TelemetryTab").then((m) => ({ default: m.TelemetryTab }))),
};

/**
 * Rutas hijas de /network, generadas desde NETWORK_TABS: la pestaña que exige un permiso lleva
 * su RequirePermission, de modo que abrir la URL a mano no se salta lo que oculta la barra.
 * Se llama como función (no como componente) porque <Routes> solo acepta <Route> como hijos.
 */
export function networkTabRoutes() {
  return (
    <>
      {NETWORK_TABS.map((tab) => {
        const Tab = TAB_COMPONENTS[tab.key];
        const element = tab.permission ? (
          <RequirePermission permission={tab.permission}>
            <Tab />
          </RequirePermission>
        ) : (
          <Tab />
        );
        return tab.path ? (
          <Route key={tab.key} path={tab.path} element={element} />
        ) : (
          <Route key={tab.key} index element={element} />
        );
      })}
      <Route path="*" element={<NotFoundPage />} />
    </>
  );
}

/**
 * Redirección que conserva la query y el fragmento: los enlaces guardados a las páginas
 * antiguas (/dhcp, /topology?node=...) siguen abriendo lo mismo dentro del hub Red.
 */
export function RedirectKeepingQuery({ to }: { to: string }) {
  const location = useLocation();
  return <Navigate to={{ pathname: to, search: location.search, hash: location.hash }} replace />;
}
