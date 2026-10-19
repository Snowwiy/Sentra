// @vitest-environment jsdom
// Fase 6C: el modal retiene el foco, bloquea el scroll del fondo y lo devuelve al cerrar.
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { useState } from "react";
import { afterEach, describe, expect, it } from "vitest";
import { Modal } from "./Modal";

function Harness() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button onClick={() => setOpen(true)}>Abrir</button>
      {open && (
        <Modal title="Registrar equipo" onClose={() => setOpen(false)}>
          <input aria-label="Nombre" />
          <button>Guardar</button>
        </Modal>
      )}
    </>
  );
}

afterEach(cleanup);

describe("Modal", () => {
  it("Tab no sale del diálogo, Escape cierra y el foco vuelve al botón que lo abrió", () => {
    render(<Harness />);
    const opener = screen.getByRole("button", { name: "Abrir" });
    opener.focus();
    fireEvent.click(opener);
    const dialog = screen.getByRole("dialog", { name: "Registrar equipo" });
    expect(document.body.style.overflow).toBe("hidden");
    const save = screen.getByRole("button", { name: "Guardar" });
    save.focus();
    fireEvent.keyDown(dialog, { key: "Tab" });
    expect(screen.getByRole("button", { name: "Cerrar" })).toHaveFocus();
    fireEvent.keyDown(dialog, { key: "Tab", shiftKey: true });
    expect(save).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.body.style.overflow).toBe("");
    expect(opener).toHaveFocus();
  });
});
