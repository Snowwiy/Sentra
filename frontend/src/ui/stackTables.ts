/**
 * Etiquetas de columna para las tablas apiladas en móvil (Fase 6C).
 *
 * En pantallas estrechas cada fila de una tabla pasa a mostrarse como tarjeta con
 * "COLUMNA: valor" (styles/components.css). Para eso cada celda necesita el nombre de su
 * columna en data-label. Hay decenas de tablas en los módulos; en lugar de repetir la
 * etiqueta a mano en cada <td> (y que se desincronice al cambiar una cabecera), se copia del
 * <thead> real en el DOM.
 *
 * Es seguro hacerlo fuera de React porque ningún componente renderiza data-label: React solo
 * actualiza los atributos que él mismo pinta, así que no lo pisa ni lo considera un cambio.
 * Las tablas con la clase table--nostack se excluyen (rejillas que ya caben).
 */

const SELECTOR = "table.table:not(.table--nostack)";

export function labelTable(table: HTMLTableElement): void {
  const headRow = table.tHead?.rows[0];
  if (!headRow) return;
  // Índice de columna -> texto de cabecera, respetando colspan de las cabeceras.
  const labels: string[] = [];
  for (const th of Array.from(headRow.cells)) {
    const text = (th.textContent ?? "").replace(/\s+/g, " ").trim();
    for (let i = 0; i < Math.max(1, th.colSpan); i++) labels.push(text);
  }
  for (const body of Array.from(table.tBodies)) {
    for (const row of Array.from(body.rows)) {
      let column = 0;
      for (const cell of Array.from(row.cells)) {
        const label = cell.colSpan > 1 ? "" : (labels[column] ?? "");
        // Una celda que ocupa toda la fila (detalle expandido) no lleva etiqueta.
        if (label) {
          if (cell.getAttribute("data-label") !== label) cell.setAttribute("data-label", label);
        } else if (cell.hasAttribute("data-label")) {
          cell.removeAttribute("data-label");
        }
        column += Math.max(1, cell.colSpan);
      }
    }
  }
}

export function labelTablesIn(root: ParentNode): void {
  root.querySelectorAll<HTMLTableElement>(SELECTOR).forEach(labelTable);
}

/** Observa `root` y etiqueta las tablas nuevas o cambiadas. Devuelve la función de parada. */
export function observeTables(root: HTMLElement): () => void {
  if (typeof MutationObserver === "undefined") return () => undefined;
  let scheduled = false;
  const run = () => {
    scheduled = false;
    labelTablesIn(root);
  };
  labelTablesIn(root);
  const observer = new MutationObserver((records) => {
    // Los cambios de data-label hechos aquí no vuelven a disparar el trabajo: solo se
    // observan nodos añadidos/quitados y texto, no atributos.
    if (scheduled || records.length === 0) return;
    scheduled = true;
    (typeof requestAnimationFrame === "function" ? requestAnimationFrame : (cb: () => void) => setTimeout(cb, 0))(run);
  });
  observer.observe(root, { childList: true, subtree: true, characterData: true });
  return () => observer.disconnect();
}
