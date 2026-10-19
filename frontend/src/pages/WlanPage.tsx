import { useCallback, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { wlanApi } from "../api/sentra";
import { useAuth } from "../auth/AuthContext";
import { FilterSelect } from "../components/ListControls";
import { ErrorState, LoadingState } from "../components/StateViews";
import { AccessPointPanel } from "../components/wlan/AccessPointPanel";
import { AccessPointsTab, BssTab, ClientsTab, SsidsTab, type WlanListScope } from "../components/wlan/WlanLists";
import { overviewIsEmpty, WlanOverviewPanel, type WlanTab } from "../components/wlan/WlanOverviewPanel";
import { config } from "../config";
import { errorMessage } from "../lib/format";
import { usePolling } from "../lib/usePolling";
import { useSite } from "../site/SiteContext";
import { SiteScopeChip } from "../site/SiteSelector";

const TABS: { key: WlanTab; label: string }[] = [
  { key: "access-points", label: "Puntos de acceso" },
  { key: "ssids", label: "Redes (SSID)" },
  { key: "bss", label: "BSS" },
  { key: "clients", label: "Clientes" },
];

function isTab(value: string | null): value is WlanTab {
  return TABS.some((t) => t.key === value);
}

/**
 * Inventario Wi-Fi / AP / WLAN (Fase 6C.3): resumen con la disponibilidad de cada fuente,
 * puntos de acceso, redes, BSS y clientes, y el detalle de un AP en un panel lateral.
 *
 * La pestaña y el AP abierto viven en la URL (?tab=, ?ap=) para poder compartir el enlace.
 * Solo quien tiene network:manage ve las acciones de clasificación y vínculo; la API vuelve
 * a comprobarlo y audita cada cambio.
 */
export function WlanPage() {
  const auth = useAuth();
  const canManage = auth.can("network:manage");
  const site = useSite();
  const [params, setParams] = useSearchParams();
  const tabParam = params.get("tab");
  const tab: WlanTab = isTab(tabParam) ? tabParam : "access-points";
  const openAp = params.get("ap") ?? undefined;
  // Valores con los que se abre la pestaña BSS desde el resumen o desde un SSID.
  const [bssPreset, setBssPreset] = useState<{ ssid?: string; insecure?: boolean; n: number }>({ n: 0 });
  const [reloadKey, setReloadKey] = useState(0);
  const [siteFilter, setSiteFilter] = useState("");

  const siteId = site.scopeId ?? (siteFilter || undefined);
  const showSiteFilter = !site.scopeId && site.selectableSites.length > 1;
  const scope: WlanListScope = {
    siteId,
    showSite: !siteId && site.sites.length > 1,
    siteFilter: showSiteFilter ? (
      <FilterSelect
        label="Site"
        value={siteFilter}
        options={site.selectableSites.map((s) => ({ value: s.site_id, label: s.name }))}
        onChange={setSiteFilter}
      />
    ) : null,
  };

  const fetchOverview = useCallback((signal: AbortSignal) => wlanApi.overview(siteId, signal), [siteId]);
  const overview = usePolling(fetchOverview, config.refreshIntervalMs * 2, true, true);

  const update = (changes: Record<string, string | undefined>) => {
    const next = new URLSearchParams(params);
    for (const [key, value] of Object.entries(changes)) {
      if (value === undefined) next.delete(key);
      else next.set(key, value);
    }
    setParams(next, { replace: true });
  };
  const selectTab = (next: WlanTab) => update({ tab: next === "access-points" ? undefined : next });
  const openTab = (next: WlanTab, preset?: { insecure?: boolean; ssid?: string }) => {
    if (next === "bss") setBssPreset((p) => ({ ...preset, n: p.n + 1 }));
    selectTab(next);
  };
  const closeAp = useCallback(() => {
    const next = new URLSearchParams(params);
    next.delete("ap");
    setParams(next, { replace: true });
  }, [params, setParams]);
  const refreshOverview = overview.refresh;
  const apChanged = useCallback(() => {
    setReloadKey((n) => n + 1);
    refreshOverview();
  }, [refreshOverview]);

  const data = overview.data;
  // Sin ningún dato en el ámbito, las pestañas vacías no aportan: el resumen explica qué falta.
  // Hasta tener el resumen no se piden las listas (si falla, se muestran igualmente).
  const showTabs = data ? !overviewIsEmpty(data) || siteFilter !== "" : Boolean(overview.error);

  return (
    <div className="page">
      <div className="page__header">
        <div>
          <h1>Wi-Fi</h1>
          <p className="muted small page__scope">
            <SiteScopeChip />
            <span>Puntos de acceso, redes, BSS y clientes observados por SNMP y por los agentes.</span>
          </p>
        </div>
      </div>
      <div className="banner" role="note">
        Inventario pasivo: Sentra no escanea, no desautentica ni cambia nada en la red Wi-Fi. Los estados son los que
        informan los equipos y los agentes, con su procedencia. La clasificación de un AP o BSS es manual y no existe la
        categoría «rogue». Las configuraciones inseguras se muestran como aviso y no afectan al riesgo.
      </div>
      {showSiteFilter && !showTabs && <div className="panel__toolbar panel__toolbar--filters">{scope.siteFilter}</div>}

      {!data ? (
        overview.error ? (
          <ErrorState message={errorMessage(overview.error)} onRetry={overview.refresh} />
        ) : (
          <LoadingState label="Cargando resumen Wi-Fi…" />
        )
      ) : (
        <>
          {overview.error && (
            <div className="banner banner--warn" role="alert">
              Fallo al actualizar el resumen: {errorMessage(overview.error)}. Se muestran los últimos datos.
            </div>
          )}
          <WlanOverviewPanel overview={data} onOpenTab={openTab} />
        </>
      )}

      {showTabs && (
        <>
          <nav className="tabs" role="tablist" aria-label="Secciones Wi-Fi">
            {TABS.map(({ key, label }) => (
              <button
                key={key}
                type="button"
                role="tab"
                id={`wlan-tab-${key}`}
                aria-selected={tab === key}
                aria-controls={`wlan-panel-${key}`}
                className={`tabs__item${tab === key ? " tabs__item--active" : ""}`}
                onClick={() => selectTab(key)}
              >
                {label}
              </button>
            ))}
          </nav>
          <div role="tabpanel" id={`wlan-panel-${tab}`} aria-labelledby={`wlan-tab-${tab}`}>
            {tab === "access-points" && (
              <AccessPointsTab scope={scope} onOpen={(id) => update({ ap: id })} reloadKey={reloadKey} />
            )}
            {tab === "ssids" && <SsidsTab scope={scope} onOpenSsid={(ssid) => openTab("bss", { ssid })} />}
            {tab === "bss" && (
              <BssTab
                key={bssPreset.n}
                scope={scope}
                canManage={canManage}
                initialSsid={bssPreset.ssid}
                initialInsecure={bssPreset.insecure}
                onOpenAp={(id) => update({ ap: id })}
              />
            )}
            {tab === "clients" && <ClientsTab scope={scope} />}
          </div>
        </>
      )}

      {openAp && <AccessPointPanel key={openAp} accessPointId={openAp} onClose={closeAp} onChanged={apChanged} />}
    </div>
  );
}
