// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import "@testing-library/jest-dom/vitest";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PortList } from "./NetworkBadges";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("PortList con servicios", () => {
  it("HTTP/HTTPS: enlace a la IP en pestaña nueva sin opener ni referer", () => {
    render(<PortList ports={[443, 8080]} address="192.168.50.1" />);
    const links = screen.getAllByRole("link");
    expect(links.map((a) => a.getAttribute("href"))).toEqual(["https://192.168.50.1/", "http://192.168.50.1:8080/"]);
    for (const link of links) {
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
    }
    // El 8080 es una inferencia y se dice.
    expect(screen.getByText("8080/HTTP?")).toBeInTheDocument();
    expect(links[1]).toHaveAccessibleName(/HTTP probable/);
  });

  it("SSH, DNS y SMB no enlazan: se nombra el protocolo y se copia el destino", async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal("navigator", { clipboard: { writeText } });
    const onRow = vi.fn();
    render(
      <div onClick={onRow}>
        <PortList ports={[22, 53, 445]} address="192.168.50.20" />
      </div>,
    );
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("22/SSH")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Copiar destino SSH 192.168.50.20:22" }));
    expect(writeText).toHaveBeenCalledWith("192.168.50.20:22");
    // Copiar dentro de una fila clicable no navega.
    expect(onRow).not.toHaveBeenCalled();
  });

  it("el detalle ofrece abrir por nombre solo con un nombre confirmado", () => {
    render(<PortList ports={[443]} address="192.168.50.5" hostname="nas.casa.lan" detailed />);
    expect(screen.getByRole("link", { name: /por el nombre nas.casa.lan/ })).toHaveAttribute(
      "href",
      "https://nas.casa.lan/",
    );
    cleanup();
    render(<PortList ports={[443]} address="192.168.50.5" detailed />);
    expect(screen.getAllByRole("link")).toHaveLength(1);
  });

  it("sin IP válida solo hay números, y se respeta el límite", () => {
    render(<PortList ports={[80, 443]} address="no-es-una-ip" />);
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
    expect(screen.getByText("80, 443")).toBeInTheDocument();
    cleanup();
    render(<PortList ports={[22, 80, 443, 445]} address="10.0.0.1" limit={2} />);
    expect(screen.getAllByRole("listitem")).toHaveLength(2);
    expect(screen.getByText("+2")).toBeInTheDocument();
  });
});
