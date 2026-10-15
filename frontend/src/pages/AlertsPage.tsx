import { AlertsView } from "../components/AlertsView";
import { SiteScopeChip } from "../site/SiteSelector";

export function AlertsPage() {
  return (
    <div className="page">
      <div className="page__header">
        <h1>Alertas</h1>
        <SiteScopeChip />
      </div>
      <AlertsView />
    </div>
  );
}
