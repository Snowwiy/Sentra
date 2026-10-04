"""Request body size limit (pure ASGI middleware).

Without a limit, any client (even unauthenticated: the body is read before the token is
checked) can make the API buffer arbitrarily large payloads in memory. The limit applies to
both declared (Content-Length) and streamed (chunked) bodies, because a client can omit or lie
about Content-Length.
"""

import json

from starlette.types import ASGIApp, Message, Receive, Scope, Send


def _too_large_body(limit: int) -> bytes:
    return json.dumps(
        {
            "error": {
                "code": "payload_too_large",
                "message": f"Request body exceeds {limit} bytes",
            }
        }
    ).encode()


class BodySizeLimitMiddleware:
    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None:
            try:
                too_large = int(declared) > self.max_bytes
            except ValueError:
                too_large = False  # malformed header: let the server/framework reject it
            if too_large:
                await self._reject(send)
                return

        received = 0
        rejected = False
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received, rejected
            if rejected:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    # Answer 413 ourselves and tell the app the client went away. Raising
                    # instead would be swallowed by the framework's body parser as a generic
                    # 400, hiding the real reason from the client.
                    rejected = True
                    if not response_started:
                        await self._reject(send)
                    return {"type": "http.disconnect"}
            return message

        async def guarded_send(message: Message) -> None:
            nonlocal response_started
            if rejected:
                return  # our 413 already went out; drop whatever the app tries to send
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        await self.app(scope, limited_receive, guarded_send)

    async def _reject(self, send: Send) -> None:
        body = _too_large_body(self.max_bytes)
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                    # Same as SECURITY_HEADERS (core/middleware.py): this answer is sent
                    # before that middleware runs.
                    (b"x-content-type-options", b"nosniff"),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
