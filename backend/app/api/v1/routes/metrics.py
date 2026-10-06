"""GET /metrics en formato de texto de Prometheus (Fase 4M, docs/observability.md).

No es una ruta del dashboard: la consume un recolector (Prometheus, Grafana Agent...). Se
protege por capas y está apagada por defecto:
1. METRICS_ENABLED=false (por defecto): 404, como si no existiera;
2. la IP del cliente (ya resuelta desde TRUSTED_PROXIES) debe estar en
   METRICS_ALLOWED_NETWORKS (por defecto solo loopback): desde Internet, a través del
   reverse proxy, la IP real no está ahí;
3. con METRICS_TOKEN, además, Authorization: Bearer <token> (comparación en tiempo constante).
El reverse proxy de referencia tampoco la publica (deploy/caddy/Caddyfile.example).
"""

import hmac
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select

from app.api.deps import AppSettings, DbSession
from app.core.exceptions import NotFoundError, UnauthorizedError
from app.core.metrics import REGISTRY, gauge
from app.core.proxy import is_trusted, parse_ip
from app.db.session import get_engine
from app.models.detection import DetectionSignal
from app.models.risk import AssetRisk
from app.services.dashboard_service import DashboardService

router = APIRouter(tags=["metrics"])


def _authorize(request: Request, settings: AppSettings) -> None:
    if not settings.metrics_enabled:
        raise NotFoundError("Not found")
    client = parse_ip(request.client.host) if request.client else None
    if not is_trusted(client, settings.metrics_networks):
        # 404 y no 403: fuera de la red autorizada el endpoint no "existe".
        raise NotFoundError("Not found")
    token = settings.metrics_token
    if token is not None:
        header = request.headers.get("authorization", "")
        scheme, _, provided = header.partition(" ")
        expected = token.get_secret_value().encode()
        if scheme.lower() != "bearer" or not hmac.compare_digest(provided.encode(), expected):
            raise UnauthorizedError("Metrics token required")


@router.get("/metrics", include_in_schema=False, response_class=PlainTextResponse)
def metrics(request: Request, settings: AppSettings, session: DbSession) -> PlainTextResponse:
    _authorize(request, settings)
    lines = REGISTRY.render()
    pool = get_engine().pool
    status = getattr(pool, "status", None)
    lines += gauge(
        "sentra_db_pool_connections",
        "Conexiones del pool de este proceso por estado.",
        [
            ({"state": "checked_out"}, float(getattr(pool, "checkedout", lambda: 0)())),
            ({"state": "idle"}, float(getattr(pool, "checkedin", lambda: 0)())),
            ({"state": "overflow"}, float(max(getattr(pool, "overflow", lambda: 0)(), 0))),
        ]
        if status is not None
        else [],
    )
    # Valores globales de la base (iguales en todos los workers), agregados en SQL.
    summary = DashboardService(
        session, timedelta(seconds=settings.heartbeat_timeout_seconds)
    ).summary(include_incidents=True)
    assets = summary.assets
    lines += gauge(
        "sentra_assets",
        "Activos por estado efectivo.",
        [
            ({"status": "online"}, assets.online),
            ({"status": "offline"}, assets.offline),
            ({"status": "unknown"}, assets.unknown),
        ],
    )
    lines += gauge(
        "sentra_assets_by_method",
        "Activos por método (agent = gestionados con agente).",
        [({"method": m}, float(c)) for m, c in assets.by_method.items()],
    )
    lines += gauge(
        "sentra_detections_active",
        "Detecciones activas por severidad.",
        [({"severity": s}, float(c)) for s, c in summary.detections.by_severity.items()],
    )
    if summary.incidents is not None:
        lines += gauge(
            "sentra_incidents_active",
            "Incidentes activos y críticos.",
            [
                ({"kind": "active"}, summary.incidents.active),
                ({"kind": "critical"}, summary.incidents.critical),
            ],
        )
    lines += gauge("sentra_alerts_active", "Alertas activas.", [({}, summary.active_alerts)])
    risk_queue = session.scalar(
        select(func.count()).select_from(AssetRisk).where(AssetRisk.dirty_at.is_not(None))
    )
    signals = session.scalar(
        select(func.count())
        .select_from(DetectionSignal)
        .where(DetectionSignal.evaluated_at.is_(None))
    )
    lines += gauge(
        "sentra_queue_pending",
        "Trabajo pendiente de los motores (riesgo por recalcular, señales por evaluar).",
        [
            ({"queue": "risk"}, float(risk_queue or 0)),
            ({"queue": "detection"}, float(signals or 0)),
        ],
    )
    lines += gauge(
        "sentra_metrics_generated_timestamp_seconds",
        "Momento de esta respuesta.",
        [({}, datetime.now(UTC).timestamp())],
    )
    return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
