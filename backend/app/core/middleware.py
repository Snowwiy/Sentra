import logging
import re
import time
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

logger = logging.getLogger("sentra.request")

# A client-supplied request id is echoed back and written into every log line of the request,
# so only short, plain tokens are trusted. Anything else (huge values, spaces, odd characters
# that could confuse log tooling) is replaced by a fresh id instead of being copied around.
_REQUEST_ID = re.compile(r"[A-Za-z0-9._:-]{1,128}")

# Added to every response. The API only serves JSON (plus /docs in development):
# - nosniff stops a browser from reinterpreting a JSON body as another content type;
# - no-store keeps credentials (enrollment answers with the agent token in clear) and live
#   monitoring data out of browser and intermediary caches.
SECURITY_HEADERS = {"X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"}


def request_id_from(request: Request) -> str:
    incoming = request.headers.get("X-Request-ID")
    if incoming and _REQUEST_ID.fullmatch(incoming):
        return incoming
    return str(uuid.uuid4())


async def request_logging_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = request_id_from(request)
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        for name, value in SECURITY_HEADERS.items():
            # setdefault: an endpoint that deliberately sets its own value keeps it.
            response.headers.setdefault(name, value)
        return response
    finally:
        logger.info(
            "request",
            extra={
                "request_id": request_id,
                # Peer address, so failed enrollments or token errors can be traced to a host.
                # Behind a reverse proxy this is the proxy's address.
                "client": request.client.host if request.client else None,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": round((time.perf_counter() - start) * 1000, 2),
            },
        )
