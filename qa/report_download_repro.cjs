// Reproducción de la Fase 6D.6: descarga de un informe PDF a través del proxy de Vite.
//
// Inicia sesión en la consola (Vite en BASE con su proxy /api), genera un informe PDF por la
// API, abre su detalle y pulsa «Descargar». Registra cada respuesta /api, los avisos visibles
// (role=alert) y el resultado de la descarga. Con --stop-api-after-ms N detiene la descarga a
// mitad simulando un corte (solo bloquea la ruta en el navegador, no toca el servidor).
//
// Uso (sin datos reales: solo una instancia de desarrollo o pruebas):
//   NODE_PATH=/ruta/node_modules SENTRA_QA_ADMIN_PASSWORD=... node qa/report_download_repro.cjs \
//     [--base http://127.0.0.1:5173] [--user qaadmin] [--format pdf] [--abort-body]
const { chromium } = require("playwright");

const args = process.argv.slice(2);
function arg(name, fallback) {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : fallback;
}
const BASE = arg("base", "http://127.0.0.1:5173");
const USER = arg("user", "qaadmin");
const FORMAT = arg("format", "pdf");
const ABORT_BODY = args.includes("--abort-body");
const GATEWAY = arg("gateway", ""); // "502" o "504": simula la respuesta del proxy sin sobre
// Pausa antes de pulsar «Descargar» (para detener o reiniciar la API a mano y ver el aviso real).
const WAIT_MS = Number(arg("wait-before-download-ms", "0"));
const PASSWORD = process.env.SENTRA_QA_ADMIN_PASSWORD;
if (!PASSWORD) {
  console.error("Falta SENTRA_QA_ADMIN_PASSWORD");
  process.exit(2);
}

(async () => {
  const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined });
  const context = await browser.newContext({ acceptDownloads: true });
  const page = await context.newPage();
  const log = [];
  page.on("response", (r) => {
    if (r.url().includes("/api/")) log.push(`${r.request().method()} ${new URL(r.url()).pathname} -> ${r.status()}`);
  });
  page.on("requestfailed", (r) => log.push(`FAILED ${r.method()} ${new URL(r.url()).pathname}: ${r.failure()?.errorText}`));
  page.on("pageerror", (e) => log.push(`PAGEERROR ${e.message}`));
  page.on("console", (m) => {
    if (m.type() === "error") log.push(`CONSOLE ${m.text()}`);
  });

  await page.goto(`${BASE}/login`);
  await page.getByLabel(/usuario/i).fill(USER);
  await page.getByLabel(/contraseña/i).fill(PASSWORD);
  await page.getByRole("button", { name: /^entrar$/i }).click();
  await page.waitForURL((u) => !u.pathname.startsWith("/login"), { timeout: 15000 });

  // Informe por la API con el token CSRF de /auth/me (solo en memoria de este script).
  const report = await page.evaluate(async (format) => {
    const me = await (await fetch("/api/v1/auth/me", { credentials: "include" })).json();
    const catalog = await (await fetch("/api/v1/reports/catalog", { credentials: "include" })).json();
    const type = catalog.items.find((t) => t.supported_formats.includes(format)) || catalog.items[0];
    const body = {
      report_type: type.id,
      format,
      classification: "internal",
      range: { preset: "7d" },
      filters: {},
      idempotency_key: crypto.randomUUID(),
    };
    const r = await fetch("/api/v1/reports", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": me.csrf_token },
      body: JSON.stringify(body),
    });
    return { status: r.status, body: await r.json() };
  }, FORMAT);
  console.log("POST /reports", report.status, report.body.status || report.body.error?.code);
  const id = report.body.id;
  await page.goto(`${BASE}/reports/${id}`);
  await page.getByRole("button", { name: "Descargar" }).waitFor({ timeout: 120000 });
  console.log("informe listo; descargando");

  if (ABORT_BODY || GATEWAY) {
    await page.route("**/artifact", async (route) => {
      if (GATEWAY) {
        await route.fulfill({ status: Number(GATEWAY), contentType: "text/plain", body: "" });
      } else {
        await route.abort("connectionreset");
      }
    });
  }
  if (WAIT_MS) {
    console.log(`esperando ${WAIT_MS} ms antes de descargar`);
    await page.waitForTimeout(WAIT_MS);
  }
  const downloadPromise = page.waitForEvent("download", { timeout: 20000 }).catch(() => null);
  await page.getByRole("button", { name: "Descargar" }).click();
  const download = await downloadPromise;
  await page.waitForTimeout(1500);
  const alerts = await page.getByRole("alert").allTextContents();
  const health = await page.locator(".health").first().getAttribute("title").catch(() => null);
  const busy = await page.getByRole("button", { name: /Descargar|Descargando/ }).first().textContent();
  console.log(JSON.stringify({ download: download ? download.suggestedFilename() : null, alerts, health, button: busy, log }, null, 2));
  await browser.close();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
