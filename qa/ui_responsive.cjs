/*
 * Matriz responsive de la UI (Fase 6C).
 *
 * Abre cada ruta del dashboard en varios tamaños de ventana con Chromium y comprueba que no
 * haya scroll horizontal GLOBAL (document.scrollWidth > ancho de la ventana). Un scroll
 * horizontal dentro de un contenedor propio (tabla con overflow-x: auto) es intencionado y no
 * cuenta. Para cada fallo informa de los elementos que salen del viewport sin estar
 * contenidos, que es la causa real a corregir (no se oculta con overflow-x: hidden).
 *
 * También redimensiona la ventana de forma progresiva durante la navegación, prueba los dos
 * estilos de navegación y el zoom al 200 % (equivale a un viewport de la mitad de CSS px).
 *
 * Uso (contra una instancia QA, nunca la base real):
 *   SENTRA_UI_URL=http://127.0.0.1:5173 SENTRA_QA_ADMIN_USER=qaadmin \
 *   SENTRA_QA_ADMIN_PASSWORD=... node qa/ui_responsive.cjs [--out carpeta] [--only /ruta]
 * Requiere el paquete playwright (npm install --no-save playwright) y un Chromium.
 */
"use strict";
const fs = require("node:fs");
const path = require("node:path");
const { chromium } = require("playwright");

const BASE = (process.env.SENTRA_UI_URL || "http://127.0.0.1:5173").replace(/\/+$/, "");
const USER = process.env.SENTRA_QA_ADMIN_USER || "qaadmin";
const PASSWORD = process.env.SENTRA_QA_ADMIN_PASSWORD || "";
const args = process.argv.slice(2);
const argValue = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const OUT = argValue("--out") || path.join(process.cwd(), "ui-responsive-report");
const ONLY = argValue("--only");
const NAV_MODES = (argValue("--nav") || "sidebar,topbar").split(",");

const VIEWPORTS = [
  [320, 568],
  [360, 800],
  [390, 844],
  [768, 1024],
  [1024, 768],
  [1366, 768],
  [1440, 900],
  [1920, 1080],
  [2560, 1440],
  [3440, 1440],
];

// Rutas estáticas; las de detalle se completan con identificadores reales de la API.
const STATIC_ROUTES = [
  "/",
  "/agents",
  "/network",
  "/infrastructure",
  "/wlan",
  "/risk",
  "/vulnerabilities",
  "/vulnerabilities/exposure",
  "/vulnerabilities/catalog",
  "/vulnerabilities/catalog/cves/CVE-2024-6387",
  "/threat-intel",
  "/detections",
  "/detections/rules",
  "/detections/rules/new",
  "/incidents",
  "/alerts",
  "/response",
  "/playbooks",
  "/reports",
  "/ai",
  "/sensors",
  "/settings",
  "/settings/sites",
  "/settings/ai",
  "/admin/users",
  "/admin/lifecycle",
];

async function detailRoutes(page) {
  // Usa la sesión del navegador: mismas cookies y permisos que la UI.
  return page.evaluate(async () => {
    const out = [];
    const get = async (url) => {
      try {
        const r = await fetch(url, { credentials: "same-origin" });
        return r.ok ? await r.json() : null;
      } catch {
        return null;
      }
    };
    const assets = await get("/api/v1/assets?limit=1");
    const first = assets && (assets.items || assets)[0];
    const id = first && (first.asset_id || first.id);
    if (id) out.push(`/assets/${id}`);
    return out;
  });
}

async function measure(page) {
  return page.evaluate(() => {
    const vw = window.innerWidth;
    const doc = document.documentElement;
    const overflow = Math.max(doc.scrollWidth, document.body.scrollWidth) - vw;
    const culprits = [];
    if (overflow > 1) {
      // Un elemento solo es culpable si sale del viewport y ningún ancestro lo contiene con
      // overflow propio (scroll interno intencionado o recorte del propio componente).
      const contained = (el) => {
        for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
          const ox = getComputedStyle(p).overflowX;
          if (ox === "auto" || ox === "scroll" || ox === "hidden" || ox === "clip") return true;
        }
        return false;
      };
      const describe = (el) => {
        const cls = typeof el.className === "string" ? el.className.trim().split(/\s+/).slice(0, 3).join(".") : "";
        return `${el.tagName.toLowerCase()}${el.id ? "#" + el.id : ""}${cls ? "." + cls : ""}`;
      };
      for (const el of document.body.querySelectorAll("*")) {
        const r = el.getBoundingClientRect();
        if (r.width === 0 || r.right <= vw + 1) continue;
        if (contained(el)) continue;
        const parent = el.parentElement;
        // Se informa el elemento más externo que sobresale: su padre todavía cabe.
        if (parent && parent !== document.body && parent.getBoundingClientRect().right > vw + 1 && !contained(parent))
          continue;
        culprits.push({ el: describe(el), right: Math.round(r.right), width: Math.round(r.width) });
        if (culprits.length >= 6) break;
      }
    }
    // Contenido recortado: un control o texto que sobresale de un ancestro con overflow
    // hidden/clip queda fuera del alcance del usuario aunque la página no desborde. Se
    // excluyen los elementos que se recortan a sí mismos (puntos suspensivos intencionados).
    const clipped = [];
    const controls = document.body.querySelectorAll("a, button, input, select, textarea, label, h1, h2, td, th, p, span");
    for (const el of controls) {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) continue;
      const own = getComputedStyle(el);
      if (own.overflowX === "hidden" || own.textOverflow === "ellipsis") continue;
      for (let p = el.parentElement; p && p !== document.body; p = p.parentElement) {
        const st = getComputedStyle(p);
        if (st.overflowX === "auto" || st.overflowX === "scroll") break;
        // Ocultación accesible intencionada (patrón sr-only, p. ej. thead de tablas apiladas).
        if (st.clip && st.clip !== "auto") break;
        if (st.overflowX === "hidden" || st.overflowX === "clip") {
          if (st.textOverflow === "ellipsis") break;
          const pr = p.getBoundingClientRect();
          if (r.right > pr.right + 2 || r.left < pr.left - 2) {
            const cls = typeof el.className === "string" ? el.className.trim().split(/\s+/).slice(0, 2).join(".") : "";
            const pcls = typeof p.className === "string" ? p.className.trim().split(/\s+/).slice(0, 2).join(".") : "";
            clipped.push(`${el.tagName.toLowerCase()}${cls ? "." + cls : ""} en ${p.tagName.toLowerCase()}.${pcls} (+${Math.round(r.right - pr.right)}px)`);
          }
          break;
        }
      }
      if (clipped.length >= 6) break;
    }
    return { overflow: Math.round(overflow), culprits, clipped };
  });
}

async function setNav(page, mode) {
  await page.evaluate((m) => {
    try {
      localStorage.setItem("sentra.ui.navigation", m);
    } catch {
      /* ignorado: sin almacenamiento se usa el modo automático */
    }
  }, mode);
}

async function main() {
  fs.mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch(
    process.env.PLAYWRIGHT_CHROMIUM_PATH ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH } : {},
  );
  const context = await browser.newContext({ viewport: { width: 1366, height: 768 } });
  const page = await context.newPage();
  const consoleErrors = [];
  page.on("pageerror", (err) => consoleErrors.push(String(err)));

  await page.goto(`${BASE}/login`);
  await page.getByLabel(/usuario/i).fill(USER);
  await page.getByLabel(/contraseña/i).fill(PASSWORD);
  await page.getByRole("button", { name: /entrar|iniciar/i }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 15000 });

  let routes = [...STATIC_ROUTES, ...(await detailRoutes(page))];
  // --only acepta también rutas fuera de la lista (detalles con identificador concreto).
  if (ONLY) routes = [ONLY];
  const results = [];
  for (const mode of NAV_MODES) {
    await setNav(page, mode);
    for (const route of routes) {
      for (const [w, h] of VIEWPORTS) {
        await page.setViewportSize({ width: w, height: h });
        await page.goto(`${BASE}${route}`, { waitUntil: "networkidle" });
        await page.waitForTimeout(150);
        const m = await measure(page);
        const ok = m.overflow <= 1 && m.clipped.length === 0;
        results.push({ mode, route, viewport: `${w}x${h}`, ...m, ok });
        if (!ok) {
          const name = `${mode}_${route.replace(/[^a-z0-9]+/gi, "_")}_${w}x${h}.png`;
          await page.screenshot({ path: path.join(OUT, name), fullPage: false });
        }
      }
      // Redimensionado progresivo sin recargar: detecta layouts que solo se calculan al montar.
      for (let w = 1600; w >= 320; w -= 80) {
        await page.setViewportSize({ width: w, height: 800 });
        await page.waitForTimeout(40);
        const m = await measure(page);
        if (m.overflow > 1 || m.clipped.length) {
          results.push({ mode, route, viewport: `resize-${w}`, ...m, ok: false });
          break;
        }
      }
    }
  }
  // Zoom 200 % sobre 1366x768 equivale a 683x384 CSS px.
  for (const route of routes) {
    await page.setViewportSize({ width: 683, height: 384 });
    await page.goto(`${BASE}${route}`, { waitUntil: "networkidle" });
    const m = await measure(page);
    results.push({ mode: "auto", route, viewport: "zoom200", ...m, ok: m.overflow <= 1 && m.clipped.length === 0 });
  }
  await browser.close();

  const failed = results.filter((r) => !r.ok);
  fs.writeFileSync(path.join(OUT, "results.json"), JSON.stringify({ results, consoleErrors }, null, 2));
  const lines = [`Comprobaciones: ${results.length}; fallos: ${failed.length}; errores JS: ${consoleErrors.length}`];
  for (const f of failed) {
    lines.push(
      `FAIL ${f.mode} ${f.route} ${f.viewport} +${f.overflow}px ${f.culprits.map((c) => c.el).join(" | ")}${f.clipped.length ? " RECORTADO: " + f.clipped.join(" | ") : ""}`,
    );
  }
  for (const e of consoleErrors.slice(0, 20)) lines.push(`JS ${e}`);
  fs.writeFileSync(path.join(OUT, "summary.txt"), lines.join("\n") + "\n");
  console.log(lines.join("\n"));
  process.exitCode = failed.length || consoleErrors.length ? 1 : 0;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 2;
});
