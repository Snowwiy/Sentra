// Las sesiones de test por rol (test/auth.tsx) deben reflejar backend/app/core/permissions.py:
// admin es la unión de todos los permisos y los permisos de la Fase 7A van a los roles correctos.
import { describe, expect, it } from "vitest";
import { ROLE_PERMISSIONS } from "../test/auth";

describe("permisos por rol de los tests", () => {
  it("admin tiene todo lo que tienen viewer y analyst, sin duplicados", () => {
    const admin = new Set(ROLE_PERMISSIONS.admin);
    expect(admin.size).toBe(ROLE_PERMISSIONS.admin.length);
    for (const permission of [...ROLE_PERMISSIONS.viewer, ...ROLE_PERMISSIONS.analyst]) {
      expect(admin.has(permission)).toBe(true);
    }
  });

  it("Fase 7A: herramientas del analista y aprobación de controles de red", () => {
    const has = (role: keyof typeof ROLE_PERMISSIONS, permission: string) =>
      (ROLE_PERMISSIONS[role] as string[]).includes(permission);
    expect(["viewer", "analyst", "admin"].every((role) => has(role as "viewer", "tools:read"))).toBe(true);
    expect(has("viewer", "tools:execute")).toBe(false);
    expect(has("analyst", "tools:execute")).toBe(true);
    expect(has("analyst", "tools:manage")).toBe(false);
    expect(has("analyst", "network_controls:approve")).toBe(false);
    expect(has("admin", "tools:manage")).toBe(true);
    expect(has("admin", "network_controls:approve")).toBe(true);
  });
});
