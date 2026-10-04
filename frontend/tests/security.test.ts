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
});
