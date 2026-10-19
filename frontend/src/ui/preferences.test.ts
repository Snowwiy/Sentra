// @vitest-environment jsdom
// Fase 6C: preferencias de interfaz con almacenamiento que puede fallar.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  parseCollapsedGroups,
  parseNavigationStyle,
  readRaw,
  resetPreferencesForTests,
  STORAGE_KEYS,
  writeRaw,
} from "./preferences";

beforeEach(() => {
  localStorage.clear();
  resetPreferencesForTests();
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("preferencias de navegación", () => {
  it("valores desconocidos o manipulados se leen como Automático", () => {
    expect(parseNavigationStyle(null)).toBe("auto");
    expect(parseNavigationStyle("sidebar")).toBe("sidebar");
    expect(parseNavigationStyle("topbar")).toBe("topbar");
    expect(parseNavigationStyle("<script>")).toBe("auto");
    expect(parseNavigationStyle("SIDEBAR")).toBe("auto");
  });

  it("persiste en localStorage y sobrevive a recargar (nueva lectura sin memoria)", () => {
    expect(writeRaw(STORAGE_KEYS.navigation, "topbar")).toBe(true);
    resetPreferencesForTests();
    expect(readRaw(STORAGE_KEYS.navigation)).toBe("topbar");
  });

  it("si el navegador bloquea el almacenamiento, la preferencia vale para la pestaña", () => {
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new DOMException("QuotaExceededError");
    });
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("SecurityError");
    });
    expect(writeRaw(STORAGE_KEYS.navigation, "sidebar")).toBe(false);
    expect(readRaw(STORAGE_KEYS.navigation)).toBe("sidebar");
  });

  it("una lectura que lanza no rompe: devuelve null", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new DOMException("SecurityError");
    });
    expect(readRaw(STORAGE_KEYS.navigation)).toBeNull();
  });

  it("los grupos plegados aceptan solo una lista acotada de textos", () => {
    expect(parseCollapsedGroups('["general","admin"]')).toEqual(["general", "admin"]);
    expect(parseCollapsedGroups("{")).toEqual([]);
    expect(parseCollapsedGroups('{"a":1}')).toEqual([]);
    expect(parseCollapsedGroups('[1,"ok",null]')).toEqual(["ok"]);
    expect(parseCollapsedGroups(JSON.stringify(Array(50).fill("x")))).toHaveLength(16);
  });

  it("un cambio en otra pestaña invalida la copia en memoria", () => {
    writeRaw(STORAGE_KEYS.navigation, "sidebar");
    localStorage.setItem(STORAGE_KEYS.navigation, "topbar");
    // Sin evento, sigue la copia en memoria de esta pestaña.
    expect(readRaw(STORAGE_KEYS.navigation)).toBe("sidebar");
  });
});
