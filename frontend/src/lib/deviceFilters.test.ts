// Fase 7A.5: filtros de Red › Dispositivos en la URL.
import { describe, expect, it } from "vitest";
import {
  DEFAULT_DEVICE_FILTERS,
  deviceSearch,
  devicesLink,
  isFiltered,
  readDeviceFilters,
  toAssetQuery,
} from "./deviceFilters";

describe("deviceFilters", () => {
  it("sin filtros el enlace es la ruta limpia y la consulta no lleva nada", () => {
    expect(devicesLink()).toBe("/network/devices");
    expect(deviceSearch(DEFAULT_DEVICE_FILTERS)).toBe("");
    expect(Object.values(toAssetQuery(DEFAULT_DEVICE_FILTERS)).every((v) => v === undefined)).toBe(true);
    expect(isFiltered(DEFAULT_DEVICE_FILTERS)).toBe(false);
  });

  it("ida y vuelta por la URL conserva cada filtro", () => {
    const link = devicesLink({ q: "10.0.0.5", status: "offline", type: "ip_camera", archived: true, sort: "first", dir: "desc" });
    const params = new URLSearchParams(link.split("?")[1]);
    const filters = readDeviceFilters(params);
    expect(filters).toMatchObject({ q: "10.0.0.5", status: "offline", type: "ip_camera", archived: true, sort: "first", dir: "desc" });
    expect(params.get("archived")).toBe("include");
    expect(toAssetQuery(filters)).toMatchObject({
      q: "10.0.0.5",
      status: "offline",
      deviceType: "ip_camera",
      archived: "include",
      sort: "first_seen",
      order: "desc",
    });
  });

  it("valores no válidos de la URL vuelven al valor por defecto", () => {
    const filters = readDeviceFilters(
      new URLSearchParams("status=hacked&method=x&type=DROP%20TABLE&sort=password&dir=sideways&criticality=extreme&internet=maybe"),
    );
    expect(filters).toEqual(DEFAULT_DEVICE_FILTERS);
  });

  it("los textos se recortan al límite del servidor", () => {
    const filters = readDeviceFilters(new URLSearchParams(`q=${"a".repeat(500)}&tag=${"b".repeat(100)}`));
    expect(filters.q).toHaveLength(200);
    expect(filters.tag).toHaveLength(64);
  });
});
