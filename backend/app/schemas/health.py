from typing import Literal

from app.schemas.common import ResponseModel

CheckStatus = Literal["ok", "error"]


class LivenessRead(ResponseModel):
    """GET /health (Fase 4M): el proceso responde. Público y mínimo a propósito.

    Sin versión, base de datos, rutas ni IPs: cualquiera que alcance el puerto puede pedirlo,
    y esos datos solo ayudan a quien busca una versión vulnerable o la topología interna.
    """

    status: Literal["ok"]


class ReadinessRead(ResponseModel):
    """GET /health/ready: puede atender tráfico (base de datos y esquema al día).

    Solo "ok"/"error" por dependencia, nunca versiones, revisiones ni hosts. La IA y el
    discovery no cuentan: la plataforma funciona sin ellos (la IA tiene su /ai/status).
    """

    status: Literal["ready", "not_ready"]
    checks: dict[str, CheckStatus]
