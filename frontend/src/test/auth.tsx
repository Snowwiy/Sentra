// Utilidades de test: una sesión fija por rol, sin pasar por /auth/me. Solo la importan los
// *.test.tsx; no forma parte del bundle de la aplicación.
import type { ReactNode } from "react";
import type { Permission, Role } from "../api/types";
import { AuthContext, type AuthValue } from "../auth/AuthContext";

// Igual que backend/app/core/permissions.py (ROLE_PERMISSIONS).
export const ROLE_PERMISSIONS: Record<Role, Permission[]> = {
  viewer: ["monitoring:read", "ai:use", "incidents:read", "rules:read", "vulnerabilities:read", "threat_intel:read"],
  analyst: [
    "monitoring:read",
    "alerts:manage",
    "detections:manage",
    "discovery:run",
    "ai:use",
    "incidents:read",
    "incidents:manage",
    "rules:read",
    "rules:test",
    "vulnerabilities:read",
    "vulnerabilities:manage",
    "threat_intel:read",
    "threat_intel:triage",
    "assets:duplicates_read",
  ],
  admin: [
    "monitoring:read",
    "alerts:manage",
    "detections:manage",
    "assets:manage",
    "assets:duplicates_read",
    "discovery:run",
    "agents:manage",
    "enrollment:manage",
    "users:manage",
    "audit:read",
    "ai:use",
    "ai:manage",
    "incidents:read",
    "incidents:manage",
    "incidents:admin",
    "rules:read",
    "rules:test",
    "rules:manage",
    "vulnerabilities:read",
    "vulnerabilities:manage",
    "vulnerabilities:admin",
    "threat_intel:read",
    "threat_intel:triage",
    "threat_intel:manage",
  ],
};

export function authValue(role: Role): AuthValue {
  const permissions = new Set(ROLE_PERMISSIONS[role]);
  return {
    status: "authenticated",
    user: { user_id: "00000000-0000-0000-0000-000000000001", username: role, role, last_login_at: null },
    serverVersion: "test",
    error: undefined,
    notice: undefined,
    can: (permission) => permissions.has(permission),
    login: async () => undefined,
    logout: async () => undefined,
    retry: () => undefined,
  };
}

export function WithRole({ role, children }: { role: Role; children: ReactNode }) {
  return <AuthContext.Provider value={authValue(role)}>{children}</AuthContext.Provider>;
}
