// Guards for the agent management UI: no admin credential can reach the browser bundle, and
// the one-time token is never persisted or logged by the code that handles it.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const FRONTEND = join(__dirname, "..");
const SRC = join(FRONTEND, "src");

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return sources(path);
    return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) ? [path] : [];
  });
}

describe("frontend security", () => {
  it("contains no admin key, header or variable anywhere in the app source", () => {
    for (const file of sources(SRC)) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(/X-Admin-Key|ADMIN_API_KEY|admin_api_key/i);
    }
  });

  it("only exposes VITE_* variables to the bundle (no envPrefix override, no define)", () => {
    const vite = readFileSync(join(FRONTEND, "vite.config.ts"), "utf8");
    expect(vite).not.toMatch(/envPrefix|define\s*:/);
    const env = readFileSync(join(FRONTEND, ".env.example"), "utf8");
    expect(env).not.toMatch(/ADMIN/i);
  });

  it("agent management code never persists or logs anything", () => {
    const files = sources(SRC).filter((f) =>
      /components[\\/]agents|AgentsPage|AgentPanel|lib[\\/]install|CopyButton|Modal/.test(f),
    );
    expect(files.length).toBeGreaterThanOrEqual(8);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(
        /localStorage|sessionStorage|indexedDB|document\.cookie|console\.(log|info|debug|warn|error)|history\.(push|replace)State/,
      );
    }
  });

  // Fase 4D: iniciar/cancelar descubrimientos usa la misma consola local; tampoco aquí se
  // persiste ni se registra nada en el navegador.
  it("network discovery code never persists or logs anything", () => {
    const files = sources(SRC).filter((f) =>
      /components[\\/]discovery|NetworkPage|lib[\\/]discovery|useConsole/.test(f),
    );
    expect(files.length).toBeGreaterThanOrEqual(5);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(
        /localStorage|sessionStorage|indexedDB|document\.cookie|console\.(log|info|debug|warn|error)/,
      );
    }
  });

  // Fase 4G: la sesión vive solo en una cookie HttpOnly; el frontend no guarda ni registra
  // contraseñas, IDs de sesión ni el token CSRF, y no queda rastro de la consola local.
  it("auth code never persists, logs or reads cookies", () => {
    const files = sources(SRC).filter((f) => /[\\/]auth[\\/]|api[\\/]client|UsersPage|AlertsView/.test(f));
    expect(files.length).toBeGreaterThanOrEqual(6);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(
        /localStorage|sessionStorage|indexedDB|document\.cookie|console\.(log|info|debug|warn|error)/,
      );
    }
  });

  // Fase 4J: el texto del modelo nunca se interpreta como HTML, la UI de IA no persiste ni
  // registra nada y ninguna clave o URL de proveedor de IA llega al bundle.
  it("AI insights code renders text only and never persists, logs or holds AI secrets", () => {
    const files = sources(SRC).filter((f) => /components[\\/]ai|AIInsightsPage|lib[\\/]ai/.test(f));
    expect(files.length).toBeGreaterThanOrEqual(4);
    for (const file of files) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(
        /dangerouslySetInnerHTML|innerHTML|localStorage|sessionStorage|indexedDB|console\.(log|info|debug|warn|error)|window\.open|navigator\.clipboard|eval\(/,
      );
    }
    for (const file of sources(SRC)) {
      expect(readFileSync(file, "utf8"), relative(FRONTEND, file)).not.toMatch(/AI_API_KEY|AI_BASE_URL|AI_MODEL|\bapi_key\b|ai_base_url/i);
    }
  });

  it("no longer uses the temporary local console marker", () => {
    for (const file of sources(SRC)) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(/X-Sentra-Console|DASHBOARD_ADMIN_ENABLED|console_not_local/);
    }
  });

  it("never puts credentials in URLs", () => {
    for (const file of sources(SRC)) {
      const text = readFileSync(file, "utf8");
      expect(text, relative(FRONTEND, file)).not.toMatch(/[?&](password|token|session|csrf)=/i);
    }
  });

  // Si existe un build (npm run build), el bundle tampoco contiene la clave de administración.
  it("built bundle (if present) contains no admin key", () => {
    const dist = join(FRONTEND, "dist", "assets");
    let files: string[];
    try {
      files = readdirSync(dist).filter((name) => name.endsWith(".js"));
    } catch {
      return;
    }
    for (const name of files) {
      expect(readFileSync(join(dist, name), "utf8"), name).not.toMatch(/X-Admin-Key|ADMIN_API_KEY|X-Sentra-Console/);
    }
  });
});
