// @vitest-environment jsdom
// Fase 6C: etiquetas de columna para tablas apiladas en móvil.
import { describe, expect, it } from "vitest";
import { labelTablesIn } from "./stackTables";

describe("stackTables", () => {
  it("copia la cabecera a cada celda, respeta colspan y excluye table--nostack", () => {
    document.body.innerHTML = `
      <div id="root">
        <table class="table"><thead><tr><th>Nombre</th><th colspan="2">Uso <b>CPU</b></th><th></th></tr></thead>
          <tbody>
            <tr><td>a</td><td>1</td><td>2</td><td><button>x</button></td></tr>
            <tr><td colspan="4">detalle</td></tr>
          </tbody></table>
        <table class="table table--nostack"><thead><tr><th>X</th></tr></thead><tbody><tr><td>y</td></tr></tbody></table>
      </div>`;
    labelTablesIn(document.getElementById("root")!);
    const cells = Array.from(document.querySelectorAll("table.table:not(.table--nostack) td"));
    expect(cells.map((c) => c.getAttribute("data-label"))).toEqual(["Nombre", "Uso CPU", "Uso CPU", null, null]);
    expect(document.querySelector(".table--nostack td")!.hasAttribute("data-label")).toBe(false);
  });
});
