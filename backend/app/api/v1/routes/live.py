"""Live SOC: stream SSE de detecciones, alertas, actividad de casos y alertas SIEM (Fase 7F.7).

`GET /api/v1/live/stream` con la cookie de sesión del dashboard (EventSource la envía sola;
es una lectura, así que no lleva CSRF). Exige monitoring:read; cada canal exige además su
propio permiso (app/live/stream.py) y se revalida durante la conexión. Ver
docs/fase-7f-live-soc.md.
"""

import time
from collections.abc import AsyncIterator
from typing import Annotated
from uuid import UUID

import anyio
from fastapi import APIRouter, Depends, Header, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.api.auth import client_ip, require_permission
from app.api.deps import AppSettings, DbSession
from app.api.responses import error_responses
from app.core.exceptions import LiveStreamLimitError
from app.core.permissions import Permission
from app.live.stream import (
    Cursor,
    LiveReader,
    StreamSlots,
    allowed_channels,
    sse,
)
from app.services.auth_service import AuthContext, AuthService, SessionPolicy
from app.services.site_service import resolve_site

router = APIRouter(prefix="/live", tags=["live"], responses=error_responses(401, 403))

Reader = Annotated[AuthContext, Depends(require_permission(Permission.MONITORING_READ))]


def _slots(request: Request) -> StreamSlots:
    slots: StreamSlots | None = getattr(request.app.state, "live_slots", None)
    if slots is None:
        slots = StreamSlots()
        request.app.state.live_slots = slots
    return slots


@router.get(
    "/stream",
    responses={
        200: {"content": {"text/event-stream": {}}, "description": "Stream SSE"},
        **error_responses(404, 429),
    },
)
def live_stream(
    request: Request,
    ctx: Reader,
    session: DbSession,
    settings: AppSettings,
    site_id: Annotated[UUID | None, Query()] = None,
    last_event_id: Annotated[str | None, Header(alias="Last-Event-ID", max_length=100)] = None,
    resume: Annotated[str | None, Query(max_length=100)] = None,
) -> StreamingResponse:
    """Eventos `detection`, `alert`, `incident` y `siem`; `status` con el estado del stream
    (live, catching_up, degraded) y `reconnect` al cumplir la duración máxima.

    `Last-Event-ID` (o `resume`, para clientes que no pueden fijar cabeceras) reanuda desde
    los cursores de ese mensaje. Un valor mal formado se ignora: se empieza en el presente.
    """
    site = resolve_site(session, site_id)
    # Solo se conserva el motor: cada consulta del stream abre y cierra su propia sesión y la
    # de la petición no se usa después de la respuesta.
    engine = session.get_bind()
    token = ctx.token
    ip = client_ip(request)
    policy = SessionPolicy.from_settings(settings)
    slots = _slots(request)
    user_id = ctx.user.id
    if not slots.acquire(user_id, settings.live_max_streams_per_user, settings.live_max_streams):
        raise LiveStreamLimitError(
            "Too many live streams open; close another Live SOC tab", 30, "live_stream"
        )
    channels = allowed_channels(ctx.permissions)
    reader = LiveReader(engine, site)  # type: ignore[arg-type]
    resumed = Cursor.decode(last_event_id or resume)
    poll_seconds = settings.live_poll_interval_ms / 1000

    def revalidate() -> tuple[str, ...] | None:
        with Session(bind=engine) as check:
            fresh = AuthService(check, policy).recheck(token, ip)
            if fresh is None or not fresh.has(Permission.MONITORING_READ):
                return None
            return allowed_channels(fresh.permissions)

    async def events() -> AsyncIterator[str]:
        nonlocal channels
        started = last_beat = last_check = time.monotonic()
        try:
            # El navegador espera 3 s antes de reconectar (con Last-Event-ID).
            yield "retry: 3000\n\n"
            cursor = await anyio.to_thread.run_sync(reader.heads)
            state = "live"
            if resumed is not None:
                behind = await anyio.to_thread.run_sync(
                    reader.backlog, resumed, channels, settings.live_backlog_limit
                )
                if behind:
                    # Demasiado atraso: se avisa y se sigue en el presente, sin acumularlo.
                    yield sse("status", {"state": "degraded", "reason": "backlog_skipped"})
                    state = "degraded"
                else:
                    cursor = resumed
                    state = "catching_up"
            yield sse(
                "status",
                {"state": state, "channels": list(channels)},
                cursor.encode(),
            )
            while True:
                now = time.monotonic()
                if getattr(request.app.state, "draining", False) or (
                    now - started >= settings.live_max_stream_seconds
                ):
                    yield sse("reconnect", {"reason": "max_duration"}, cursor.encode())
                    return
                if await request.is_disconnected():
                    return
                if now - last_check >= settings.live_revalidate_seconds:
                    last_check = now
                    renewed = await anyio.to_thread.run_sync(revalidate)
                    if renewed is None:
                        yield sse("session_ended", {"reason": "session_invalid"})
                        return
                    channels = renewed
                result = await anyio.to_thread.run_sync(reader.poll, cursor, channels)
                for item in result.items:
                    cursor.set(item.channel, max(cursor.get(item.channel), item.id))
                    yield sse(item.channel, item.payload, cursor.encode())
                for channel, value in result.advance.items():
                    cursor.set(channel, max(cursor.get(channel), value))
                if result.more:
                    if state != "catching_up":
                        state = "catching_up"
                        yield sse("status", {"state": state}, cursor.encode())
                    continue
                if state != "live":
                    state = "live"
                    yield sse("status", {"state": state}, cursor.encode())
                if time.monotonic() - last_beat >= settings.live_heartbeat_seconds:
                    last_beat = time.monotonic()
                    # Comentario SSE: mantiene viva la conexión en proxies sin crear eventos.
                    yield ": ping\n\n"
                await anyio.sleep(poll_seconds)
        finally:
            slots.release(user_id)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-store",
            # Caddy/nginx: no almacenar en buffer el stream.
            "X-Accel-Buffering": "no",
        },
    )
