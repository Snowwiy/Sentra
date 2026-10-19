import { useSyncExternalStore } from "react";

/**
 * Puntos de corte de la UI (Fase 6C). Deben coincidir con las media queries de index.css:
 * las variables CSS no pueden usarse dentro de @media, así que el valor vive en los dos sitios.
 */
export const BREAKPOINTS = {
  /** Por debajo: móvil (menú ≡ en drawer). */
  tablet: 768,
  /** Por debajo: tablet (menú compacto); desde aquí, escritorio. */
  desktop: 1200,
} as const;

export type Viewport = "mobile" | "tablet" | "desktop";

function query(media: string): MediaQueryList | null {
  // jsdom y navegadores muy antiguos no tienen matchMedia: se asume escritorio.
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return null;
  return window.matchMedia(media);
}

export function useMediaQuery(media: string, fallback = false): boolean {
  return useSyncExternalStore(
    (onChange) => {
      const list = query(media);
      if (!list) return () => undefined;
      list.addEventListener("change", onChange);
      return () => list.removeEventListener("change", onChange);
    },
    () => query(media)?.matches ?? fallback,
    () => fallback,
  );
}

export function useViewport(): Viewport {
  const isMobile = useMediaQuery(`(max-width: ${BREAKPOINTS.tablet - 0.02}px)`);
  const isTablet = useMediaQuery(`(max-width: ${BREAKPOINTS.desktop - 0.02}px)`);
  if (isMobile) return "mobile";
  if (isTablet) return "tablet";
  return "desktop";
}
