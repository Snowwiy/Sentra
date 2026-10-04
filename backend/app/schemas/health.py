from typing import Literal

from app.schemas.common import ResponseModel

CheckStatus = Literal["ok", "error"]


class HealthRead(ResponseModel):
    status: Literal["ok", "degraded"]
    version: str
    checks: dict[str, CheckStatus]
