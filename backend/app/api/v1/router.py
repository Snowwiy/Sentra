from fastapi import APIRouter

from app.api.responses import error_responses
from app.api.v1.routes import (
    agents,
    ai,
    ai_local,
    alerts,
    assets,
    audit,
    auth,
    case_operations,
    console,
    console_discovery,
    dashboard,
    detection_rules,
    detections,
    dhcp,
    discovery,
    endpoint,
    enrollment_tokens,
    events,
    forensics,
    health,
    incidents,
    inventory,
    isolation,
    metrics,
    network,
    processes,
    reports,
    response,
    risk,
    sensor_protocol,
    sensors,
    sites,
    telemetry,
    threat_intel,
    tools,
    topology,
    topology_history,
    users,
    vulnerabilities,
    vulnerability_sources,
    wlan,
)

# Statuses every route with input can answer. FastAPI would otherwise document 422 with its
# own `{"detail": [...]}` model instead of Sentra's error envelope. Health takes no input and
# documents its own 503 (with the health body), so it is left out. GET /assets takes no input
# either but shares its router with the detail routes; documenting 422 there is harmless.
# Route-specific statuses (401, 404...) are declared next to each route.
_COMMON = error_responses(422, 503)

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(metrics.router)
api_router.include_router(dashboard.router, responses=_COMMON)
api_router.include_router(auth.router, responses=_COMMON)
api_router.include_router(users.router, responses=_COMMON)
api_router.include_router(audit.router, responses=_COMMON)
api_router.include_router(agents.router, responses=_COMMON)
api_router.include_router(assets.router, responses=_COMMON)
api_router.include_router(telemetry.router, responses=_COMMON)
api_router.include_router(alerts.router, responses=_COMMON)
api_router.include_router(detections.router, responses=_COMMON)
api_router.include_router(detection_rules.router, responses=_COMMON)
api_router.include_router(risk.router, responses=_COMMON)
api_router.include_router(incidents.router, responses=_COMMON)
api_router.include_router(case_operations.router, responses=_COMMON)
api_router.include_router(response.router, responses=_COMMON)
api_router.include_router(tools.router, responses=_COMMON)
api_router.include_router(reports.router, responses=_COMMON)
api_router.include_router(vulnerabilities.router, responses=_COMMON)
api_router.include_router(vulnerability_sources.router, responses=_COMMON)
api_router.include_router(threat_intel.router, responses=_COMMON)
api_router.include_router(ai.router, responses=_COMMON)
api_router.include_router(ai_local.router, responses=_COMMON)
api_router.include_router(inventory.router, responses=_COMMON)
api_router.include_router(events.router, responses=_COMMON)
api_router.include_router(processes.router, responses=_COMMON)
api_router.include_router(discovery.router, responses=_COMMON)
api_router.include_router(enrollment_tokens.router, responses=_COMMON)
api_router.include_router(console.router, responses=_COMMON)
api_router.include_router(console_discovery.router, responses=_COMMON)
api_router.include_router(sites.router, responses=_COMMON)
api_router.include_router(sensors.router, responses=_COMMON)
api_router.include_router(sensor_protocol.router, responses=_COMMON)
api_router.include_router(network.router, responses=_COMMON)
api_router.include_router(wlan.router, responses=_COMMON)
api_router.include_router(topology.router, responses=_COMMON)
api_router.include_router(topology_history.router, responses=_COMMON)
api_router.include_router(dhcp.router, responses=_COMMON)
api_router.include_router(dhcp.identity_router, responses=_COMMON)
api_router.include_router(endpoint.agent_router, responses=_COMMON)
api_router.include_router(endpoint.asset_router, responses=_COMMON)
api_router.include_router(endpoint.metrics_router, responses=_COMMON)
api_router.include_router(endpoint.exclusion_router, responses=_COMMON)
api_router.include_router(forensics.router, responses=_COMMON)
api_router.include_router(isolation.router, responses=_COMMON)
api_router.include_router(isolation.overview_router, responses=_COMMON)
