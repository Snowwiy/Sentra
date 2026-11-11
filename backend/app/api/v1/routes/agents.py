import ipaddress
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status

from app.api.auth import READ, client_ip
from app.api.deps import (
    AgentToken,
    AppSettings,
    DbSession,
    EnrollmentKey,
    EnrollmentTokenHeader,
    get_agent_management_service,
    get_agent_service,
)
from app.api.ingest import Guard
from app.api.responses import error_responses
from app.core.exceptions import RateLimitedError
from app.core.rate_limit import Limiter
from app.schemas.agent import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentRotateRequest,
    AgentRotateResponse,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.schemas.agent_management import AgentList
from app.schemas.response import (
    CommandPollRequest,
    CommandPollResponse,
    CommandResultRequest,
    CommandResultResponse,
)
from app.services.agent_management_service import AgentManagementService
from app.services.agent_service import (
    TRANSPORT_HTTP_LOOPBACK,
    TRANSPORT_HTTP_REMOTE,
    TRANSPORT_HTTPS,
    AgentService,
)
from app.services.response_service import ResponseService
from app.services.site_service import resolve_site

router = APIRouter(prefix="/agents", tags=["agents"])
Service = Annotated[AgentService, Depends(get_agent_service)]


def agent_transport(request: Request) -> str:
    """Transporte por el que llegó la petición del agente (Fase 7D.1, H04).

    El esquema ya es el del proxy de TRUSTED_PROXIES cuando lo hay (TrustedProxyMiddleware).
    HTTP solo se considera aceptable en loopback (agente y servidor en la misma máquina, o
    un proxy local que no envía X-Forwarded-Proto); cualquier otro origen es "http_remote":
    la credencial viajó en claro por la red.
    """
    if request.url.scheme == "https":
        return TRANSPORT_HTTPS
    host = client_ip(request)
    try:
        loopback = host is not None and ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = False
    return TRANSPORT_HTTP_LOOPBACK if loopback else TRANSPORT_HTTP_REMOTE


Transport = Annotated[str, Depends(agent_transport)]


def limit_registration(request: Request) -> None:
    """Límite de POST /agents/register por dirección (AGENT_REGISTER_MAX_PER_MINUTE).

    Frena la prueba masiva de tokens y claves de enrollment. Solo este endpoint: heartbeat,
    telemetría, inventario y eventos no se limitan, para no dejar sin datos a agentes
    legítimos. El agente trata 429 como temporal y reintenta respetando Retry-After.
    Desde la Fase 7D.2 el resto de rutas de agente tienen cuotas por identidad autenticada
    (core/ingest_quota.py); el alta sigue limitada por dirección porque aún no hay identidad.
    """
    limiter: Limiter = request.app.state.register_limiter
    key = client_ip(request) or "unknown"
    wait = limiter.acquire(key)
    if wait > 0:
        raise RateLimitedError("Too many enrollment attempts, retry later", wait, "agent_register")


@router.post(
    "/register",
    response_model=AgentRegisterResponse,
    status_code=status.HTTP_201_CREATED,
    responses={
        status.HTTP_200_OK: {
            "model": AgentRegisterResponse,
            "description": (
                "Existing agent recovered with an admin recovery authorization, token "
                "replaced (same body as 201). An ordinary enrollment token or the shared key "
                "never re-enrolls an existing agent_id: 403 agent_recovery_required."
            ),
        },
        **error_responses(401, 403, 409, 413, 429),
    },
    dependencies=[Depends(limit_registration)],
)
def register_agent(
    payload: AgentRegisterRequest,
    service: Service,
    response: Response,
    request: Request,
    transport: Transport,
    enrollment_key: EnrollmentKey = None,
    # Recommended credential: a one-time token (see /agent-enrollment-tokens). When sent,
    # the shared key is not consulted. A recovery authorization (sentra_et_rec_...) travels
    # in this same header so that installed agents can use it without changes.
    enrollment_token: EnrollmentTokenHeader = None,
) -> AgentRegisterResponse:
    result, created = service.register(
        payload, enrollment_key, enrollment_token, transport=transport, client_ip=client_ip(request)
    )
    if not created:
        response.status_code = status.HTTP_200_OK
    return result


@router.post(
    "/heartbeat", response_model=HeartbeatResponse, responses=error_responses(401, 413, 429)
)
def heartbeat(
    payload: HeartbeatRequest,
    service: Service,
    token: AgentToken,
    transport: Transport,
    guard: Guard,
) -> HeartbeatResponse:
    # Fase 7D.2: clase "control", con cubo propio y fuera de los globales: un agente que
    # agota su cupo de datos sigue latiendo y no aparece offline por estar limitado.
    with guard.admit("control", payload.agent_id, token):
        return service.heartbeat(payload, token, transport=transport)


@router.post(
    "/credentials/rotate",
    response_model=AgentRotateResponse,
    responses=error_responses(401, 403, 409, 413, 429),
)
def rotate_credential(
    payload: AgentRotateRequest,
    service: Service,
    token: AgentToken,
    request: Request,
    transport: Transport,
    guard: Guard,
) -> AgentRotateResponse:
    """Fase 7D.1: credencial nueva a cambio de la vigente (Bearer), nunca con la de instalación.

    La nueva queda pendiente hasta su primer uso; la anterior sigue valiendo hasta entonces,
    así que una respuesta perdida no deja al agente fuera. Solo por HTTPS (o HTTP en
    loopback): 403 https_required en otro caso.
    """
    with guard.admit("control", payload.agent_id, token):
        return service.rotate(payload.agent_id, token, transport, client_ip(request))


def get_agent_response_service(session: DbSession, settings: AppSettings) -> ResponseService:
    return ResponseService(session, settings)


AgentResponse = Annotated[ResponseService, Depends(get_agent_response_service)]


@router.post(
    "/commands/poll",
    response_model=CommandPollResponse,
    responses=error_responses(401, 409, 429),
)
def poll_commands(
    payload: CommandPollRequest, service: AgentResponse, token: AgentToken, guard: Guard
) -> CommandPollResponse:
    """Fase 5D: comandos de Response en cola para ESTE agente (token propio, nunca otro).

    Solo tipos allowlisted con parámetros estructurados; cada entrega tiene un lease y el
    comando un TTL. El agente lo llama solo cuando el heartbeat indica pending_commands > 0.
    """
    with guard.admit("control", payload.agent_id, token):
        commands = service.poll(payload.agent_id, token, payload.max_commands)
    return CommandPollResponse(commands=commands)


@router.post(
    "/commands/{request_id}/result",
    response_model=CommandResultResponse,
    responses=error_responses(401, 404, 409, 413, 429),
)
def command_result(
    request_id: UUID,
    payload: CommandResultRequest,
    service: AgentResponse,
    token: AgentToken,
    guard: Guard,
) -> CommandResultResponse:
    """Resultado estructurado de un comando entregado a este agente.

    404 si el comando no existe o es de otro agente/activo (no se distingue); 409 si nunca
    se entregó; repetirlo devuelve duplicate=true sin cambiar nada (idempotente).
    """
    with guard.admit("control", payload.agent_id, token):
        return service.complete(request_id, token, payload)


@router.get("", response_model=AgentList, dependencies=[READ])
def list_agents(
    service: Annotated[AgentManagementService, Depends(get_agent_management_service)],
    session: DbSession,
    site_id: Annotated[UUID | None, Query()] = None,
) -> AgentList:
    """Enrolled agents with liveness and credential state (read-only, like /assets).

    Never returns tokens, hashes or enrollment tokens. Fase 5F: `site_id` filtra por site.
    """
    return service.list_agents(resolve_site(session, site_id))
