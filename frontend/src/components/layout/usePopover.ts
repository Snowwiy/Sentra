import { useEffect, useState, type RefObject } from "react";
import { useLocation } from "react-router-dom";

/**
 * Estado de un menú desplegable dentro de `rootRef`: se cierra con Escape (devolviendo el
 * foco al botón que lo abrió), al pulsar fuera y al cambiar de ruta. El cierre por ruta se
 * deriva de la ruta en la que se abrió, en lugar de un efecto que lo cierre después de
 * pintar: así no hay un render con el menú abierto sobre la página nueva.
 */
export function usePopover<T extends string = string>(rootRef: RefObject<HTMLElement | null>) {
  const location = useLocation();
  const [state, setState] = useState<{ id: T; path: string }>();
  const open = state && state.path === location.pathname ? state.id : undefined;

  useEffect(() => {
    if (!open) return;
    const onPointer = (event: PointerEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setState(undefined);
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      rootRef.current?.querySelector<HTMLElement>('[aria-expanded="true"]')?.focus();
      setState(undefined);
    };
    document.addEventListener("pointerdown", onPointer);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      document.removeEventListener("keydown", onKey);
    };
  }, [open, rootRef]);

  return {
    open,
    toggle: (id: T) => setState(open === id ? undefined : { id, path: location.pathname }),
    close: () => setState(undefined),
  };
}
