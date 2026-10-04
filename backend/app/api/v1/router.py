from fastapi import APIRouter

from app.api.v1.routes import agents, alerts, assets, events, health, inventory, telemetry

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(agents.router)
api_router.include_router(assets.router)
api_router.include_router(telemetry.router)
api_router.include_router(alerts.router)
api_router.include_router(inventory.router)
api_router.include_router(events.router)
