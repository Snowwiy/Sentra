"""Rendimiento de AI Security Insights (Fase 4J) con datos SINTÉTICOS y un proveedor falso.

No mide la velocidad de ningún modelo real (depende del hardware y del proveedor): mide lo
que Sentra añade alrededor, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Context builder: activo, detección y flota, en ms y sentencias SQL por contexto, y el
   tamaño del prompt resultante (caracteres) con el límite AI_MAX_CONTEXT_ITEMS.
2. API sin inferencia: estado y listado de insights con el cálculo de stale.
3. Análisis completo con un proveedor falso instantáneo (contexto + validación + grounding +
   persistencia + auditoría) y respuesta desde caché.

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_ai.py [--assets 1000] [--detections 20000]

Reutiliza los datos sintéticos de perf_risk.py (activos "perf-risk-…") y los borra al final,
junto con el usuario temporal, sus insights y su auditoría. No toca otros datos.
"""

import argparse
import json
import sys
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, func, select

sys.path.insert(0, str(Path(__file__).resolve().parent))

from perf_risk import count_statements, seed, timed

from app.ai.config import AIConfig
from app.ai.context import ContextBuilder
from app.ai.prompts import TEMPLATES, InsightKind
from app.ai.provider import AIRequest, AIResponse
from app.ai.redaction import Redactor
from app.core.config import get_settings
from app.db.session import get_engine, get_sessionmaker
from app.models.ai import AIInsight
from app.models.asset import Asset
from app.models.audit import AuditEvent
from app.models.detection import Detection
from app.models.user import User
from app.risk.config import RiskConfig
from app.risk.engine import RiskEngine
from app.services.ai_service import AIInsightService, AIRuntime, Requester
from app.services.audit_service import Actor

USER = "perf-ai-user"


class InstantProvider:
    """Proveedor falso: responde al instante citando las primeras referencias del contexto."""

    name = "perf-fake"
    model = "perf-fake-model"

    def complete(self, request: AIRequest) -> AIResponse:
        data = json.loads(request.user)["sentra_data"]
        refs: list[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, dict):
                if isinstance(value.get("ref"), str):
                    refs.append(value["ref"])
                for item in value.values():
                    walk(item)
            elif isinstance(value, list):
                for item in value:
                    walk(item)

        walk(data)
        content = json.dumps(
            {
                "summary": "perf",
                "key_findings": [{"text": "x", "certainty": "detected", "evidence": refs[:3]}],
                "evidence_refs": refs[:5],
            }
        )
        return AIResponse(content=content, model=self.model, latency_ms=0)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assets", type=int, default=1000)
    parser.add_argument("--detections", type=int, default=20_000)
    args = parser.parse_args()

    base = get_settings()
    settings = base.model_copy(
        update={"ai_enabled": True, "ai_base_url": "http://127.0.0.1:9/v1", "ai_model": "perf"}
    )
    config = AIConfig.from_settings(settings)
    engine = get_engine()
    session = get_sessionmaker()()
    ids: list[int] = []
    user_id: int | None = None
    try:
        start = time.perf_counter()
        ids = seed(session, args.assets, args.detections)
        risk = RiskEngine(session, RiskConfig.from_settings(settings))
        risk.seed_missing(limit=len(ids) + 10_000)
        risk.process_dirty(max_batches=10_000)
        print(f"[seed] {len(ids)} assets + risk in {time.perf_counter() - start:.1f} s")
        now = datetime.now(UTC)
        user = User(
            username=USER,
            # Sin contraseña utilizable: el usuario temporal nunca puede iniciar sesión.
            password_hash="!",  # noqa: S106
            role="viewer",
            is_active=False,
            created_at=now,
            updated_at=now,
            password_changed_at=now,
        )
        session.add(user)
        session.commit()
        user_id = user.id

        # Activo con más detecciones activas (peor caso del contexto de activo).
        target_pk = session.scalar(
            select(Detection.asset_id)
            .where(Detection.asset_id.in_(ids), Detection.status != "resolved")
            .group_by(Detection.asset_id)
            .order_by(func.count().desc())
            .limit(1)
        )
        target = session.scalar(select(Asset.public_id).where(Asset.id == target_pk))
        detection = session.scalar(
            select(Detection.public_id)
            .where(Detection.asset_id == target_pk, Detection.kind == "correlation")
            .limit(1)
        ) or session.scalar(select(Detection.public_id).where(Detection.asset_id == target_pk))
        if target is None or detection is None:
            raise RuntimeError("no synthetic data found")

        def builder() -> ContextBuilder:
            return ContextBuilder(
                session,
                RiskConfig.from_settings(settings),
                timedelta(seconds=settings.heartbeat_timeout_seconds),
                config.max_context_items,
                Redactor(config.redact),
            )

        cases = {
            "asset": (InsightKind.ASSET_SUMMARY, lambda: builder().asset(target)),
            "detection": (InsightKind.DETECTION_ANALYSIS, lambda: builder().detection(detection)),
            "fleet 24h": (InsightKind.SOC_SUMMARY, lambda: builder().fleet("24h")),
            "fleet 30d": (InsightKind.SOC_SUMMARY, lambda: builder().fleet("30d")),
        }
        for name, (kind, fn) in cases.items():
            with count_statements(engine) as statements:
                ms, ctx = timed(fn)
            size = len(TEMPLATES[kind].system()) + len(TEMPLATES[kind].user(ctx.data, None))
            print(
                f"[context] {name:<10} {ms:7.1f} ms  sql={len(statements) // 5:<3} "
                f"items={ctx.items:<3} prompt_chars={size}"
            )
        session.rollback()

        service = AIInsightService(
            session,
            settings,
            # Sin límites de frecuencia: aquí se mide el coste, no la protección anti-spam.
            AIRuntime(replace(config, rate_per_user=10_000, rate_global=10_000)),
            lambda _: InstantProvider(),
            Requester(Actor(USER, user_id), user_id),
        )
        ms, insight = timed(lambda: service.analyze_asset(target, refresh=True))
        print(f"[analyze] asset (fake provider, persist+audit) {ms:7.1f} ms")
        ms, _ = timed(lambda: service.analyze_detection(detection, refresh=True))
        print(f"[analyze] detection (fake provider)              {ms:7.1f} ms")
        ms, cached = timed(lambda: service.analyze_asset(target, refresh=False))
        print(
            f"[analyze] asset from cache                       {ms:7.1f} ms  cached={cached.cached}"
        )
        ms, _ = timed(service.status)
        print(f"[api] status                                     {ms:7.1f} ms")
        with count_statements(engine) as statements:
            ms, listed = timed(lambda: service.list(None, None, None, 25, 0))
        print(
            f"[api] list 25 insights with stale               {ms:7.1f} ms  "
            f"sql/request={len(statements) // 5} items={len(listed.items)}"
        )
        ms, _ = timed(lambda: service.get(insight.insight_id))
        print(f"[api] get insight                                {ms:7.1f} ms")
        return 0
    finally:
        session.rollback()
        if user_id is not None:
            session.execute(delete(AIInsight).where(AIInsight.requested_by_user_id == user_id))
            session.execute(delete(AuditEvent).where(AuditEvent.actor == USER))
            session.execute(delete(User).where(User.id == user_id))
        if ids:
            session.execute(delete(Asset).where(Asset.id.in_(ids)))
        session.commit()
        session.close()


if __name__ == "__main__":
    sys.exit(main())
