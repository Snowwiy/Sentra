import { useEffect, useRef, type KeyboardEvent } from "react";
import { Link } from "react-router-dom";

export interface RouteTab {
  key: string;
  /** Ruta de la pestaña (con la query que deba conservar, si alguna). */
  to: string;
  label: string;
}

/**
 * Pestañas que son rutas (Fase 7A.5): cada pestaña es un enlace real, así se puede abrir en
 * otra pestaña del navegador, guardar como marcador y volver con «atrás».
 *
 * Teclado (patrón tablist de WAI-ARIA con activación manual): las flechas, Inicio y Fin mueven
 * el foco entre pestañas y Enter o Espacio abren la enfocada. No se navega al mover el foco
 * porque cada pestaña carga sus datos: recorrerlas con las flechas no debe lanzar una petición
 * por cada una. Solo la activa entra en el orden de tabulación.
 *
 * En pantallas estrechas la barra se desplaza dentro de sí misma (.tabs--scroll), nunca la página.
 */
export function RouteTabs({
  tabs,
  active,
  label,
  idPrefix,
  panelId,
}: {
  tabs: RouteTab[];
  active: string | undefined;
  label: string;
  idPrefix: string;
  /** id del tabpanel que muestra el contenido de la pestaña activa. */
  panelId: string;
}) {
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    // La pestaña activa a la vista dentro de la barra (p. ej. al abrir un enlace a la última).
    const current = listRef.current?.querySelector<HTMLElement>('[aria-selected="true"]');
    current?.scrollIntoView?.({ block: "nearest", inline: "nearest" });
  }, [active]);

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = Array.from(listRef.current?.querySelectorAll<HTMLAnchorElement>('[role="tab"]') ?? []);
    const index = items.indexOf(document.activeElement as HTMLAnchorElement);
    if (index < 0) return;
    let target: number | undefined;
    if (event.key === "ArrowRight") target = (index + 1) % items.length;
    else if (event.key === "ArrowLeft") target = (index - 1 + items.length) % items.length;
    else if (event.key === "Home") target = 0;
    else if (event.key === "End") target = items.length - 1;
    else if (event.key === " ") {
      // Un enlace no se activa con Espacio; una pestaña sí.
      event.preventDefault();
      items[index]?.click();
      return;
    }
    if (target === undefined) return;
    event.preventDefault();
    items[target]?.focus();
  };

  return (
    <div ref={listRef} className="tabs tabs--scroll" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {tabs.map((tab, index) => {
        const selected = tab.key === active;
        // Sin pestaña activa (ruta desconocida) la primera sigue siendo alcanzable con Tab.
        const focusable = selected || (index === 0 && !tabs.some((t) => t.key === active));
        return (
          <Link
            key={tab.key}
            to={tab.to}
            role="tab"
            id={`${idPrefix}-tab-${tab.key}`}
            aria-selected={selected}
            aria-controls={panelId}
            tabIndex={focusable ? 0 : -1}
            className={`tabs__item${selected ? " tabs__item--active" : ""}`}
          >
            {tab.label}
          </Link>
        );
      })}
    </div>
  );
}
