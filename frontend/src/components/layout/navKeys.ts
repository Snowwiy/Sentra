import type { KeyboardEvent } from "react";

/**
 * Flechas arriba/abajo (o izquierda/derecha en la barra horizontal), Inicio y Fin mueven el
 * foco entre los elementos de un menú, además de Tab. No sustituye a Tab: solo lo acelera
 * cuando hay muchas entradas.
 */
export function moveFocusWithArrows(event: KeyboardEvent<HTMLElement>, orientation: "vertical" | "horizontal") {
  const next = orientation === "vertical" ? "ArrowDown" : "ArrowRight";
  const prev = orientation === "vertical" ? "ArrowUp" : "ArrowLeft";
  if (![next, prev, "Home", "End"].includes(event.key)) return;
  const items = Array.from(
    event.currentTarget.querySelectorAll<HTMLElement>("a[href], button:not([disabled])"),
  ).filter((el) => el.offsetParent !== null || el === document.activeElement);
  if (items.length === 0) return;
  const index = items.indexOf(document.activeElement as HTMLElement);
  let target: number;
  if (event.key === "Home") target = 0;
  else if (event.key === "End") target = items.length - 1;
  else if (event.key === next) target = index < 0 ? 0 : (index + 1) % items.length;
  else target = index <= 0 ? items.length - 1 : index - 1;
  event.preventDefault();
  items[target]?.focus();
}

/** Mantiene el foco dentro de un diálogo (drawer, modal) mientras está abierto. */
export function trapTab(event: KeyboardEvent<HTMLElement>) {
  if (event.key !== "Tab") return;
  const focusables = Array.from(
    event.currentTarget.querySelectorAll<HTMLElement>(
      'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  );
  if (focusables.length === 0) {
    event.preventDefault();
    return;
  }
  const first = focusables[0] as HTMLElement;
  const last = focusables[focusables.length - 1] as HTMLElement;
  if (event.shiftKey && (document.activeElement === first || document.activeElement === event.currentTarget)) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}
