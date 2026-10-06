"""QA e2e de producción (Fase 4M) contra Sentra real detrás de Caddy con HTTPS.

Complementa qa/e2e_api.py (contrato de la API en modo desarrollo). Aquí la API corre con
ENVIRONMENT=production en 127.0.0.1 y Caddy la publica por HTTPS, como en un servidor
central. Solo stdlib. Escenarios (se eligen con --scenario, por defecto proxy):

- proxy: redirección HTTP->HTTPS, cabeceras y CSP del frontend, sin source maps, métricas
  no publicadas, readiness, login con cookie __Host- Secure/HttpOnly/Strict, Origin ajeno
  rechazado, IP real tras el proxy (X-Forwarded-For del cliente ignorado), HTTPS exigido y
  cabeceras falsas ignoradas en conexión directa, y un agente que se inscribe por HTTPS
  confiando en la CA (y que rechaza el servidor sin ella).
- ai-down: IA activada pero el runtime local caído -> Sentra sigue ready y el resto funciona.
- db-down / db-up: con PostgreSQL parado, liveness 200, readiness 503 y 503 reintentables;
  al volver, todo se recupera sin reiniciar la API.
- workers: con --workers 2, el rate limiting del login se comparte entre procesos.

Variables:
    SENTRA_QA_PUBLIC_URL   https://localhost:8443      (Caddy)
    SENTRA_QA_HTTP_URL     http://localhost:8080        (Caddy, solo redirección)
    SENTRA_QA_CA_FILE      raíz de la CA que firmó el certificado de Caddy
    SENTRA_QA_DIRECT_URL   http://<ip no loopback>:8100 (API directa, para spoofing; opcional)
    SENTRA_QA_ADMIN_USER / SENTRA_QA_ADMIN_PASSWORD
    SENTRA_QA_AGENT_PYTHON python con sentra_agent instalado (opcional, prueba del agente)

Uso:  python qa/e2e_production.py --scenario proxy
"""

import argparse
import json
import os
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
import uuid
from email.message import Message
from typing import Any
from urllib.parse import urlsplit

PUBLIC = os.environ.get("SENTRA_QA_PUBLIC_URL", "https://localhost:8443").rstrip("/")
HTTP = os.environ.get("SENTRA_QA_HTTP_URL", "http://localhost:8080").rstrip("/")
DIRECT = os.environ.get("SENTRA_QA_DIRECT_URL", "").rstrip("/")
CA_FILE = os.environ.get("SENTRA_QA_CA_FILE", "")
ADMIN_USER = os.environ.get("SENTRA_QA_ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("SENTRA_QA_ADMIN_PASSWORD", "")
AGENT_PYTHON = os.environ.get("SENTRA_QA_AGENT_PYTHON", "")

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: Any = "") -> None:
    RESULTS.append((name, ok, "" if ok else str(detail)[:300]))
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + ("" if ok else f"  -> {str(detail)[:300]}"))


class Response:
    def __init__(self, status: int, body: bytes, headers: Message) -> None:
        self.status = status
        self.raw = body
        self.headers = headers

    def json(self) -> Any:
        try:
            return json.loads(self.raw or b"null")
        except ValueError:
            return None

    def header(self, name: str) -> str:
        return self.headers.get(name) or ""

    def cookies(self) -> list[str]:
        return self.headers.get_all("Set-Cookie") or []


def _context() -> ssl.SSLContext:
    # Verificación estricta, como un navegador o el agente: solo se añade la CA de la prueba.
    context = ssl.create_default_context()
    if CA_FILE:
        context.load_verify_locations(CA_FILE)
    return context


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_context()), _NoRedirect())


def request(
    method: str,
    url: str,
    body: Any = None,
    headers: dict[str, str] | None = None,
) -> Response:
    data = None if body is None else json.dumps(body).encode()
    all_headers = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        all_headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=all_headers, method=method)  # noqa: S310
    try:
        with OPENER.open(req, timeout=30) as response:
            return Response(response.status, response.read(), response.headers)
    except urllib.error.HTTPError as error:
        return Response(error.code, error.read(), error.headers)


def api(path: str) -> str:
    return f"{PUBLIC}/api/v1{path}"


def login(user: str, password: str, extra: dict[str, str] | None = None) -> Response:
    return request(
        "POST",
        api("/auth/login"),
        {"username": user, "password": password},
        {"Origin": PUBLIC, **(extra or {})},
    )


def session_headers(response: Response) -> dict[str, str]:
    cookie = next((c for c in response.cookies() if c.startswith("__Host-sentra_session=")), "")
    return {
        "Cookie": cookie.split(";", 1)[0],
        "X-CSRF-Token": (response.json() or {}).get("csrf_token", ""),
        "Origin": PUBLIC,
    }


# --- Escenarios ---------------------------------------------------------------------------


def scenario_proxy() -> None:
    r = request("GET", f"{HTTP}/")
    check(
        "HTTP redirige a HTTPS",
        r.status in (301, 308) and r.header("Location").startswith("https://"),
        (r.status, r.header("Location")),
    )

    page = request("GET", f"{PUBLIC}/", headers={"Accept": "text/html"})
    csp = page.header("Content-Security-Policy")
    check(
        "frontend servido por HTTPS", page.status == 200 and b'id="root"' in page.raw, page.status
    )
    check(
        "CSP estricta del dashboard",
        "script-src 'self'" in csp and "frame-ancestors 'none'" in csp,
        csp,
    )
    check("HSTS", page.header("Strict-Transport-Security").startswith("max-age="), page.headers)
    check(
        "nosniff, DENY, no-referrer, Permissions-Policy",
        page.header("X-Content-Type-Options") == "nosniff"
        and page.header("X-Frame-Options") == "DENY"
        and page.header("Referrer-Policy") == "no-referrer"
        and "camera=()" in page.header("Permissions-Policy"),
        page.headers,
    )
    check(
        "index.html sin caché",
        page.header("Cache-Control") == "no-cache",
        page.header("Cache-Control"),
    )
    script = next(
        (p.split('"')[0] for p in page.raw.decode().split('src="')[1:] if p.startswith("/assets/")),
        "",
    )
    asset = request("GET", f"{PUBLIC}{script}", headers={"Accept": "*/*"})
    check(
        "assets con hash: caché inmutable",
        asset.status == 200 and "immutable" in asset.header("Cache-Control"),
        (script, asset.status, asset.header("Cache-Control")),
    )
    check("sin source maps publicados", request("GET", f"{PUBLIC}{script}.map").status == 404)
    deep = request("GET", f"{PUBLIC}/incidents/xyz", headers={"Accept": "text/html"})
    check("rutas de la SPA sirven index.html", deep.status == 200 and b'id="root"' in deep.raw)

    check("métricas no publicadas por el proxy", request("GET", api("/metrics")).status == 404)
    live = request("GET", api("/health"))
    check("liveness", live.status == 200 and live.json() == {"status": "ok"}, live.raw)
    ready = request("GET", api("/health/ready"))
    check("readiness", ready.status == 200 and ready.json()["status"] == "ready", ready.raw)
    check(
        "health sin versión ni hosts",
        not any(
            word in ready.raw.lower() for word in (b"version", b"postgres", b"5433", b"127.0.0.1")
        ),
        ready.raw,
    )
    check("cabeceras de seguridad de la API", live.header("Cache-Control") == "no-store")

    foreign = request(
        "POST",
        api("/auth/login"),
        {"username": ADMIN_USER, "password": ADMIN_PASSWORD},
        {"Origin": "https://evil.example"},
    )
    check("login desde otro origen -> 403", foreign.status == 403, foreign.status)

    # El cliente intenta colar otra IP: Caddy la sustituye por la real.
    spoof_ip = "203.0.113.77"
    ok = login(ADMIN_USER, ADMIN_PASSWORD, {"X-Forwarded-For": spoof_ip})
    check("login por HTTPS", ok.status == 200, (ok.status, ok.raw[:200]))
    cookie = next((c for c in ok.cookies() if "sentra_session" in c), "")
    check(
        "cookie __Host- Secure HttpOnly SameSite=Strict",
        cookie.startswith("__Host-sentra_session=")
        and "Secure" in cookie
        and "HttpOnly" in cookie
        and "SameSite=strict" in cookie
        and "Domain" not in cookie,
        cookie,
    )
    check("el token de sesión no va en el cuerpo", b"sentra_s_" not in ok.raw)
    admin = session_headers(ok)
    me = request("GET", api("/auth/me"), headers=admin)
    check(
        "versión visible con sesión",
        me.status == 200 and me.json().get("server_version"),
        me.raw[:200],
    )
    audit = request("GET", api("/audit?limit=5"), headers=admin)
    clients = {item.get("client_ip") for item in (audit.json() or {}).get("items", [])}
    check(
        "auditoría con la IP real, no la inventada",
        audit.status == 200 and spoof_ip not in clients and bool(clients),
        (audit.status, clients),
    )

    summary = request("GET", api("/dashboard/summary"), headers=admin)
    page_assets = request("GET", api("/assets?limit=50"), headers=admin)
    check(
        "dashboard: resumen agregado y página de activos",
        summary.status == 200
        and page_assets.status == 200
        and page_assets.json()["limit"] == 50
        and summary.json()["assets"]["total"] == page_assets.json()["total"],
        (summary.status, page_assets.status),
    )

    if DIRECT:
        direct = request("GET", f"{DIRECT}/api/v1/auth/me")
        check(
            "conexión directa por HTTP -> 403 https_required",
            direct.status == 403
            and (direct.json() or {}).get("error", {}).get("code") == "https_required",
            (direct.status, direct.raw[:200]),
        )
        forged = request(
            "GET",
            f"{DIRECT}/api/v1/auth/me",
            headers={"X-Forwarded-Proto": "https", "X-Forwarded-For": "10.0.0.1"},
        )
        check(
            "X-Forwarded-Proto falso desde fuera del proxy -> 403",
            forged.status == 403,
            forged.status,
        )
        probe = request("GET", f"{DIRECT}/api/v1/health/ready")
        check("sondas locales exentas de HTTPS", probe.status == 200, probe.status)

    if AGENT_PYTHON:
        token = request("POST", api("/console/enrollment-tokens"), {"max_uses": 1}, admin)
        check("token de inscripción creado", token.status == 201, token.raw[:200])
        _agent_over_https(token.json()["token"])


_AGENT_SNIPPET = """
import json, sys, uuid
from sentra_agent.client import SentraClient, TransportError
client = SentraClient(sys.argv[1], timeout=10)
agent_id = uuid.uuid4()
host = {"hostname": "qa-tls-agent", "os_name": "Linux", "os_version": "qa",
        "architecture": "x86_64", "primary_ip": "192.0.2.50", "agent_version": "0.2.0"}
try:
    reg = client.register(agent_id, host, enrollment_token=sys.argv[2])
    beat = client.heartbeat(agent_id, reg["agent_token"])
    print(json.dumps({"ok": True, "status": beat.get("status")}))
except TransportError as exc:
    print(json.dumps({"ok": False, "error": str(exc)}))
"""


def _agent_over_https(token: str) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("SSL_CERT_FILE", "SSL_CERT_DIR")}
    # Sin la CA de la prueba en el almacén de confianza: el agente debe negarse.
    untrusted = subprocess.run(  # noqa: S603
        [AGENT_PYTHON, "-c", _AGENT_SNIPPET, PUBLIC, token],
        capture_output=True, text=True, env=env, timeout=60, check=False,
    )  # fmt: skip
    result = json.loads(untrusted.stdout or "{}")
    check(
        "agente sin la CA instalada -> rechaza el certificado",
        result.get("ok") is False and "CERTIFICATE_VERIFY_FAILED" in result.get("error", ""),
        untrusted.stdout + untrusted.stderr[-300:],
    )
    # "Instalar la CA": aquí, apuntando el almacén de OpenSSL a ella (en Windows/Linux real se
    # instala en el almacén del sistema, docs/network-security.md).
    trusted = subprocess.run(  # noqa: S603
        [AGENT_PYTHON, "-c", _AGENT_SNIPPET, PUBLIC, token],
        capture_output=True, text=True, env={**env, "SSL_CERT_FILE": CA_FILE}, timeout=60,
        check=False,
    )  # fmt: skip
    result = json.loads(trusted.stdout or "{}")
    check(
        "agente con la CA: inscripción y heartbeat por HTTPS",
        result.get("ok") is True and result.get("status") == "online",
        trusted.stdout + trusted.stderr[-300:],
    )


def scenario_ai_down() -> None:
    ok = login(ADMIN_USER, ADMIN_PASSWORD)
    admin = session_headers(ok)
    ready = request("GET", api("/health/ready"))
    check("IA caída: Sentra sigue ready", ready.status == 200, ready.raw)
    status = request("GET", api("/ai/status"), headers=admin).json() or {}
    check(
        "IA caída: /ai/status lo explica sin URL ni clave",
        status.get("enabled") is True and status.get("reachable") is False
        and "127.0.0.1" not in json.dumps(status),
        status,
    )  # fmt: skip
    analysis = request("POST", api("/ai/soc/analyze"), {}, admin)
    code = ((analysis.json() or {}).get("error") or {}).get("code")
    check(
        "IA caída: análisis -> error controlado, sin fallback",
        analysis.status in (502, 503) and code is not None,
        (analysis.status, analysis.raw[:200]),
    )
    check(
        "IA caída: el dashboard funciona",
        request("GET", api("/dashboard/summary"), headers=admin).status == 200,
    )


def scenario_db_down() -> None:
    check("BD caída: liveness 200", request("GET", api("/health")).status == 200)
    ready = request("GET", api("/health/ready"))
    body = ready.json() or {}
    check(
        "BD caída: readiness 503 database=error",
        ready.status == 503 and body.get("checks", {}).get("database") == "error",
        ready.raw,
    )
    r = login(ADMIN_USER, ADMIN_PASSWORD)
    code = ((r.json() or {}).get("error") or {}).get("code")
    check(
        "BD caída: login -> 503 database_unavailable (reintentable)",
        r.status == 503 and code == "database_unavailable" and "request_id" in r.json()["error"],
        r.raw[:300],
    )
    check("BD caída: sin trazas ni SQL", b"Traceback" not in r.raw and b"psycopg" not in r.raw)


def scenario_db_up() -> None:
    ready = request("GET", api("/health/ready"))
    check("BD recuperada: ready sin reiniciar la API", ready.status == 200, ready.raw)
    r = login(ADMIN_USER, ADMIN_PASSWORD)
    check("BD recuperada: login", r.status == 200, r.status)
    check(
        "BD recuperada: dashboard",
        request("GET", api("/dashboard/summary"), headers=session_headers(r)).status == 200,
    )


def scenario_workers() -> None:
    # Cuenta nueva (no existe): cada intento fallido cuenta igual en cualquier worker.
    user = f"qa-nobody-{uuid.uuid4().hex[:6]}"
    statuses = [login(user, "intento-equivocado-123").status for _ in range(8)]
    check(
        "2 workers: el límite de login se comparte (5 fallos y luego 429)",
        statuses[:5] == [401] * 5 and all(s == 429 for s in statuses[5:]),
        statuses,
    )
    blocked = login(user, "intento-equivocado-123")
    check("429 con Retry-After", blocked.status == 429 and blocked.header("Retry-After").isdigit())


SCENARIOS = {
    "proxy": scenario_proxy,
    "ai-down": scenario_ai_down,
    "db-down": scenario_db_down,
    "db-up": scenario_db_up,
    "workers": scenario_workers,
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", choices=sorted(SCENARIOS), default="proxy")
    args = parser.parse_args()
    if not ADMIN_USER or not ADMIN_PASSWORD:
        print("SENTRA_QA_ADMIN_USER and SENTRA_QA_ADMIN_PASSWORD are required", file=sys.stderr)
        return 2
    if urlsplit(PUBLIC).scheme != "https":
        print("SENTRA_QA_PUBLIC_URL must be https://", file=sys.stderr)
        return 2
    try:
        SCENARIOS[args.scenario]()
    except Exception as exc:
        check(f"{args.scenario} crashed", False, repr(exc))
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)}/{len(RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
