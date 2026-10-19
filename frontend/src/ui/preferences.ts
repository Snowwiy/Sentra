import { useSyncExternalStore } from "react";

/**
 * Preferencias de interfaz del navegador (Fase 6C).
 *
 * Solo se guardan aquí ajustes de presentación sin valor de seguridad (estilo de navegación,
 * menú compacto, grupos plegados). Nunca sesiones, tokens ni datos del servidor: la sesión
 * sigue en su cookie HttpOnly. El almacenamiento puede no existir o lanzar (modo privado,
 * cuotas, políticas del navegador): toda lectura y escritura está protegida y, ante un fallo,
 * la UI sigue funcionando con los valores por defecto durante esa pestaña.
 *
 * Un valor guardado que no es válido se trata como el valor por defecto al LEER, sin
 * borrarlo después del render: un efecto que limpia el almacenamiento tras pintar compite con
 * otras pestañas y con la propia escritura del usuario (carrera vista en SiteContext, 6B).
 */

export type NavigationStyle = "auto" | "sidebar" | "topbar";

export const NAVIGATION_STYLES: readonly NavigationStyle[] = ["auto", "sidebar", "topbar"];

export const NAVIGATION_STYLE_LABELS: Record<NavigationStyle, string> = {
  auto: "Automático",
  sidebar: "Menú lateral",
  topbar: "Barra superior",
};

export const STORAGE_KEYS = {
  navigation: "sentra.ui.navigation",
  sidebarCompact: "sentra.ui.sidebarCompact",
  collapsedGroups: "sentra.ui.collapsedGroups",
} as const;

type Key = (typeof STORAGE_KEYS)[keyof typeof STORAGE_KEYS];

// Copia en memoria: si el almacenamiento falla, la preferencia elegida dura al menos hasta
// recargar la pestaña en lugar de perderse en el siguiente render.
const memory = new Map<Key, string | null>();
const listeners = new Set<() => void>();

function storage(): Storage | null {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}

export function readRaw(key: Key): string | null {
  if (memory.has(key)) return memory.get(key) ?? null;
  try {
    return storage()?.getItem(key) ?? null;
  } catch {
    return null;
  }
}

/** Escribe y avisa a los suscriptores. Devuelve false si el navegador no permitió guardarlo. */
export function writeRaw(key: Key, value: string | null): boolean {
  memory.set(key, value);
  let persisted = false;
  try {
    const store = storage();
    if (store) {
      if (value === null) store.removeItem(key);
      else store.setItem(key, value);
      persisted = true;
    }
  } catch {
    persisted = false;
  }
  for (const listener of listeners) listener();
  return persisted;
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  // Otra pestaña cambió la preferencia: se descarta la copia en memoria de esa clave para
  // leer el valor nuevo.
  const onStorage = (event: StorageEvent) => {
    if (event.key === null) memory.clear();
    else if ((Object.values(STORAGE_KEYS) as string[]).includes(event.key)) memory.delete(event.key as Key);
    listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

export function parseNavigationStyle(raw: string | null): NavigationStyle {
  return raw === "sidebar" || raw === "topbar" || raw === "auto" ? raw : "auto";
}

export function parseCollapsedGroups(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const value: unknown = JSON.parse(raw);
    if (!Array.isArray(value)) return [];
    return value.filter((item): item is string => typeof item === "string" && item.length <= 32).slice(0, 16);
  } catch {
    return [];
  }
}

function useRaw(key: Key): string | null {
  return useSyncExternalStore(
    subscribe,
    () => readRaw(key),
    () => null,
  );
}

export function useNavigationStyle(): [NavigationStyle, (value: NavigationStyle) => boolean] {
  const style = parseNavigationStyle(useRaw(STORAGE_KEYS.navigation));
  return [style, (value) => writeRaw(STORAGE_KEYS.navigation, value)];
}

export function useSidebarCompact(): [boolean, (value: boolean) => void] {
  const compact = useRaw(STORAGE_KEYS.sidebarCompact) === "true";
  return [compact, (value) => void writeRaw(STORAGE_KEYS.sidebarCompact, value ? "true" : "false")];
}

export function useCollapsedGroups(): [string[], (groups: string[]) => void] {
  const raw = useRaw(STORAGE_KEYS.collapsedGroups);
  return [parseCollapsedGroups(raw), (groups) => void writeRaw(STORAGE_KEYS.collapsedGroups, JSON.stringify(groups))];
}

/** Solo para tests: olvida la copia en memoria. */
export function resetPreferencesForTests(): void {
  memory.clear();
}
