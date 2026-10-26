import { useState } from "react";
import { useAuth } from "../../auth/AuthContext";
import { FilterSelect } from "../../components/ListControls";
import { TopologyHistoryPanel } from "../../components/topology/TopologyHistoryPanel";
import { useSite } from "../../site/SiteContext";
import { useNetworkHub } from "./hubContext";

/**
 * Red › Historial de cambios (Fase 7A.5): cambios de red detectados (equipos que aparecen o
 * desaparecen, cambios de IP, MAC, nombre, tipo y enlaces), con su revisión (topology:manage),
 * snapshots de topología y sus diferencias exportables. El historial es siempre de UN site:
 * sin alcance elegido, el que se elija aquí o el site por defecto.
 */
export function ChangesTab() {
  const hub = useNetworkHub();
  const site = useSite();
  const canManage = useAuth().can("topology:manage");
  const [siteFilter, setSiteFilter] = useState("");
  const siteId = hub.scopeId ?? (siteFilter || undefined);
  const showSiteFilter = !hub.scopeId && site.selectableSites.length > 1;
  return (
    <div className="stack">
      {showSiteFilter && (
        <div className="panel__toolbar panel__toolbar--filters">
          <FilterSelect
            label="Site"
            value={siteFilter}
            allLabel="por defecto"
            options={site.selectableSites.map((s) => ({ value: s.site_id, label: s.name }))}
            onChange={setSiteFilter}
          />
        </div>
      )}
      <TopologyHistoryPanel key={siteId ?? "default"} siteId={siteId} canManage={canManage} />
    </div>
  );
}
