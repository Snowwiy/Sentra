import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { sitesApi } from "../api/sentra";
import type { Site } from "../api/types";

/** "all" = todos los sites; si no, el site_id elegido. */
export type SiteSelection = "all" | string;

export interface SiteValue {
  /** Selección validada contra el catálogo ("all" mientras no hay catálogo). */
  selection: SiteSelection;
  /** site_id para la query (`site_id=`) o undefined para todos los sites. */
  scopeId: string | undefined;
  /** Site elegido (undefined con "all"). */
  current: Site | undefined;
  /** Catálogo completo, incluidos los archivados (la UI decide qué ocultar). */
  sites: Site[];
  /** Sites que se pueden elegir en el selector (no archivados). */
  selectableSites: Site[];
  /** El site por defecto, si el catálogo lo trae. */
  defaultSite: Site | undefined;
  loading: boolean;
  error: Error | undefined;
  setSelection: (value: SiteSelection) => void;
  refresh: () => void;
}

/** Clave del navegador para recordar el alcance elegido (solo una preferencia de vista). */
export const SITE_STORAGE_KEY = "sentra.site";

function readStored(): string | undefined {
  try {
    return window.localStorage.getItem(SITE_STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

function writeStored(value: SiteSelection): void {
  try {
    if (value === "all") window.localStorage.removeItem(SITE_STORAGE_KEY);
    else window.localStorage.setItem(SITE_STORAGE_KEY, value);
  } catch {
    // Almacenamiento bloqueado (modo privado, política): la selección vive solo en memoria.
  }
}

/** Un site solo es válido como alcance si existe en el catálogo y no está archivado. */
export function validSelection(value: string | undefined, sites: Site[]): SiteSelection {
  if (!value || value === "all") return "all";
  const site = sites.find((s) => s.site_id === value);
  return site && site.status !== "archived" ? site.site_id : "all";
}

const FALLBACK: SiteValue = {
  selection: "all",
  scopeId: undefined,
  current: undefined,
  sites: [],
  selectableSites: [],
  defaultSite: undefined,
  loading: false,
  error: undefined,
  setSelection: () => undefined,
  refresh: () => undefined,
};

const SiteContext = createContext<SiteValue | undefined>(undefined);

/**
 * Alcance de site global del dashboard (Fase 5F).
 *
 * Carga GET /sites y expone la selección ("all" o un site_id). Lo guardado en el navegador
 * nunca se usa tal cual: hasta que llega el catálogo el alcance es "all" y, después, solo se
 * acepta un site que exista y no esté archivado. Así un id viejo o manipulado no filtra nada
 * por error. El servidor vuelve a validar el site_id (404 site_not_found).
 *
 * La normalización ocurre en el mismo callback que acepta el catálogo, antes de publicarlo:
 * cuando un render muestra "all" por un id inválido, el navegador ya lo ha olvidado. Un
 * efecto posterior dejaba un render intermedio con la selección corregida pero el id viejo
 * aún guardado.
 */
export function SiteProvider({ children }: { children: ReactNode }) {
  const [sites, setSites] = useState<Site[] | undefined>(undefined);
  const [error, setError] = useState<Error | undefined>(undefined);
  const [requested, setRequested] = useState<string | undefined>(() => readStored());
  const [attempt, setAttempt] = useState(0);
  // Última selección pedida, leída desde los callbacks asíncronos. Así la respuesta del
  // catálogo valida la elección más reciente (aunque llegue durante la petición) sin que
  // `requested` sea dependencia del efecto: cambiar de site no repite GET /sites.
  const requestedRef = useRef(requested);
  // Catálogo aceptado, para validar en setSelection sin esperar a otro render.
  const sitesRef = useRef<Site[] | undefined>(undefined);

  useEffect(() => {
    const controller = new AbortController();
    sitesApi
      .list(controller.signal)
      .then((list) => {
        // Una respuesta de una petición cancelada (desmontaje o refresh) no se publica.
        if (controller.signal.aborted) return;
        const latest = requestedRef.current;
        if (latest && latest !== "all" && validSelection(latest, list.items) === "all") {
          // Borrado o archivado: se olvida antes de publicar el estado que provoca el render.
          writeStored("all");
          requestedRef.current = "all";
          setRequested("all");
        }
        sitesRef.current = list.items;
        setSites(list.items);
        setError(undefined);
      })
      .catch((err: unknown) => {
        if (controller.signal.aborted) return;
        setError(err instanceof Error ? err : new Error(String(err)));
      });
    return () => controller.abort();
  }, [attempt]);

  const setSelection = useCallback((value: SiteSelection) => {
    // Con catálogo, un id que no vale como alcance se guarda como "all"; sin catálogo se
    // guarda tal cual y lo valida la respuesta de GET /sites.
    const catalog = sitesRef.current;
    const next = catalog === undefined ? value : validSelection(value, catalog);
    requestedRef.current = next;
    setRequested(next);
    writeStored(next);
  }, []);

  const refresh = useCallback(() => setAttempt((n) => n + 1), []);

  const value = useMemo<SiteValue>(() => {
    const catalog = sites ?? [];
    const selection = validSelection(requested, catalog);
    const current = selection === "all" ? undefined : catalog.find((s) => s.site_id === selection);
    return {
      selection,
      scopeId: current?.site_id,
      current,
      sites: catalog,
      selectableSites: catalog.filter((s) => s.status !== "archived"),
      defaultSite: catalog.find((s) => s.is_default),
      loading: sites === undefined && error === undefined,
      error,
      setSelection,
      refresh,
    };
  }, [sites, requested, error, setSelection, refresh]);

  return <SiteContext.Provider value={value}>{children}</SiteContext.Provider>;
}

/** Alcance actual. Fuera de un SiteProvider (tests de páginas aisladas) equivale a "all". */
export function useSite(): SiteValue {
  return useContext(SiteContext) ?? FALLBACK;
}
