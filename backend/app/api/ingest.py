"""Puerta de las rutas legacy de ingesta de agentes (Fase 7D.2, H06).

Orden de cada petición, de lo más barato a lo más caro:
1. hueco de concurrencia global de este worker (sin tocar la base);
2. autenticación del agente con su credencial (un 401 no gasta el cupo de nadie);
3. hueco de concurrencia del agente y cupo en los cubos de tokens;
4. solo entonces, el trabajo del servicio (escrituras, alertas, motor de detección).

Los servicios vuelven a autenticar al agente dentro de su propia lógica: es una consulta por
clave primaria en la misma sesión y evita cambiar las firmas de cinco servicios que usan
también los tests y la CLI.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request

from app.api.deps import DbSession
from app.core.ingest_quota import IngestQuota, RouteClass
from app.models.asset import Asset
from app.repositories.asset_repository import AssetRepository
from app.services.agent_service import authenticate_agent


class IngestGuard:
    def __init__(self, quota: IngestQuota, session: DbSession, body_bytes: int) -> None:
        self._quota = quota
        self._session = session
        self._body_bytes = body_bytes

    @contextmanager
    def admit(
        self, route: RouteClass, agent_id: UUID, token: str | None, *, events: int = 0
    ) -> Iterator[Asset]:
        with self._quota.slot():
            asset = authenticate_agent(AssetRepository(self._session), agent_id, token)
            with self._quota.admit(agent_id, route, events=events, body_bytes=self._body_bytes):
                yield asset


async def get_ingest_guard(request: Request, session: DbSession) -> IngestGuard:
    # El cuerpo ya está leído y en caché (FastAPI lo lee antes de resolver dependencias) y
    # acotado por MAX_REQUEST_BYTES: se cobra lo que de verdad llegó, no Content-Length, que
    # un cliente podría omitir (transferencia por trozos) para no gastar cupo de bytes.
    body = await request.body()
    return IngestGuard(request.app.state.ingest_quota, session, len(body))


Guard = Annotated[IngestGuard, Depends(get_ingest_guard)]
