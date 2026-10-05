"""Dashboard console guard: agent administration without ADMIN_API_KEY in the browser.

Fase 4D reutiliza esta misma guarda para iniciar y cancelar descubrimientos de red
(routes/console_discovery.py): son operaciones activas sobre la red y, sin login, solo el
operador sentado en el servidor puede lanzarlas. La lectura (GET /discovery/*) sigue
abierta como el resto del dashboard.

TEMPORARY, until the dashboard has login and roles (RBAC). Replace `require_local_console`
with a session/role check then; the routes in routes/console.py stay the same.

Why: the administration API (X-Admin-Key) must not be called from the browser, because the
key would have to live in the JavaScript bundle, in storage or in every page. Instead the
API performs the operation itself (backend-for-frontend), using the same services, and only
for a caller that is very likely the operator sitting at the Sentra server:

1. DASHBOARD_ADMIN_ENABLED=true (off by default: fail closed);
2. the TCP peer is loopback (127.0.0.1/::1). Behind a reverse proxy uvicorn takes the client
   from X-Forwarded-For only when the proxy runs on this machine, so remote browsers stay
   remote; the Vite dev server (bound to localhost) forwards as loopback, as intended;
3. the Host header is a loopback name, which defeats DNS rebinding (a hostile page whose
   name resolves to 127.0.0.1 still sends its own name);
4. a browser Origin, when sent, is listed in CORS_ORIGINS (the dashboard's own origin, e.g.
   http://localhost:5173) or is the API's own origin, so another site open in the
   operator's browser, even another local one, cannot drive the console (CSRF);
5. the custom X-Sentra-Console header is present: HTML forms and simple cross-site requests
   cannot set it, and a cross-origin fetch with it needs a CORS preflight that only the
   configured origins pass.

What it does not protect against: other users or malware on the server machine itself
(they can reach loopback; they could usually also read .env). Documented in
docs/agent-management.md; that is why it is opt-in and temporary.
"""

import ipaddress
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Header, Request

from app.api.deps import AppSettings
from app.core.exceptions import ConsoleDisabledError, ConsoleNotLocalError

CONSOLE_HEADER = "X-Sentra-Console"


def _is_loopback_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _host_header_name(value: str | None) -> str | None:
    if not value:
        return None
    try:
        return urlsplit(f"//{value}").hostname
    except ValueError:
        return None


def _origin_allowed(origin: str, request: Request, allowed: list[str]) -> bool:
    # Same origin as the API itself (dashboard served by the same host:port), or a
    # configured dashboard origin. "null" (sandboxed frames, file://) is never allowed.
    own = f"{request.url.scheme}://{request.headers.get('host', '')}"
    return origin in allowed or origin == own


def require_local_console(
    request: Request,
    settings: AppSettings,
    marker: Annotated[str | None, Header(alias=CONSOLE_HEADER)] = None,
) -> None:
    if not settings.dashboard_admin_enabled:
        raise ConsoleDisabledError(
            "Administration from the dashboard (agents, network discovery) is disabled: set"
            " DASHBOARD_ADMIN_ENABLED=true on the server"
        )
    peer = request.client.host if request.client else None
    origin = request.headers.get("origin")
    if (
        marker != "1"
        or not _is_loopback_host(peer)
        or not _is_loopback_host(_host_header_name(request.headers.get("host")))
        or (origin is not None and not _origin_allowed(origin, request, settings.cors_origin_list))
    ):
        raise ConsoleNotLocalError(
            "Administration from the dashboard is only available from a browser on the Sentra"
            " server (http://localhost)"
        )
