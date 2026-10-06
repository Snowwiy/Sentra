import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

from app.core.metrics import REGISTRY
from app.core.request_context import request_id_var

logger = logging.getLogger("sentra.request")

# A client-supplied request id is echoed back and written into every log line of the request,
# so only short, plain tokens are trusted. Anything else (huge values, spaces, odd characters
# that could confuse log tooling) is replaced by a fresh id instead of being copied around.
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")

# Added to every response. The API only serves JSON (plus /docs in development):
# - nosniff stops a browser from reinterpreting a JSON body as another content type;
# - no-store keeps credentials (enrollment answers with the agent token in clear) and live
#   monitoring data out of browser and intermediary caches.
# Fase 4M: la API tampoco se puede enmarcar (clickjacking), no filtra la URL como Referer y
# su CSP prohíbe cargar o ejecutar nada: una respuesta JSON abierta en el navegador por error
# no puede convertirse en documento activo. El frontend recibe su propia CSP del reverse
# proxy (deploy/caddy/Caddyfile.example).
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}
# /docs (solo fuera de producción) carga Swagger UI desde un CDN: sin la CSP restrictiva.
_DOCS_PATHS = ("/docs", "/openapi.json")


def request_id_from(request: Request) -> str:
    incoming = request.headers.get("X-Request-ID")
    if incoming and _REQUEST_ID.fullmatch(incoming):
        return incoming
    return str(uuid.uuid4())


async def request_logging_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = request_id_from(request)
    # Visible para cualquier log de la petición y para el manejador de errores 500/503.
    request_id_var.set(request_id)
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        docs = request.url.path.startswith(_DOCS_PATHS)
        for name, value in SECURITY_HEADERS.items():
            if docs and name == "Content-Security-Policy":
                continue
            # setdefault: an endpoint that deliberately sets its own value keeps it.
            response.headers.setdefault(name, value)
        return response
    finally:
        elapsed = time.perf_counter() - start
        # Plantilla de la ruta (cardinalidad acotada), nunca la URL con ids.
        route = getattr(request.scope.get("route"), "path", None) or "unmatched"
        REGISTRY.observe_request(request.method, route, status_code, elapsed)
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                # Dirección del cliente: el par TCP o, detrás de un proxy de TRUSTED_PROXIES,
                # la IP real validada (core/proxy.py).
                "client": request.client.host if request.client else None,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": round(elapsed * 1000, 2),
            },
        )
