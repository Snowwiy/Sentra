from fastapi import APIRouter

from app.api.responses import error_responses
from app.api.v1.routes import (
    agents,
    alerts,
    assets,
    events,
    health,
    inventory,
    processes,
    telemetry,
)

# Statuses every route with input can answer. FastAPI would otherwise document 422 with its
# own `{"detail": [...]}` model instead of Sentra's error envelope. Health takes no input and
# documents its own 503 (with the health body), so it is left out. GET /assets takes no input
# either but shares its router with the detail routes; documenting 422 there is harmless.
# Route-specific statuses (401, 404...) are declared next to each route.
_COMMON = error_responses(422, 503)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(agents.router, responses=_COMMON)
api_router.include_router(assets.router, responses=_COMMON)
api_router.include_router(telemetry.router, responses=_COMMON)
api_router.include_router(alerts.router, responses=_COMMON)
api_router.include_router(inventory.router, responses=_COMMON)
api_router.include_router(events.router, responses=_COMMON)
api_router.include_router(processes.router, responses=_COMMON)
