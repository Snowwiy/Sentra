"""Rendimiento de las reglas personalizadas (Fase 5A) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Carga del índice de reglas activas (lo que hace cada worker al detectar un cambio).
2. Coste en la ingesta de registrar los eventos crudos de canales con reglas activas.
3. Rendimiento del job del motor 4H con N reglas personalizadas activas (por defecto 1000:
   simples, de umbral, con regex segura y con contexto del activo) sobre M señales de
   evento (por defecto 100 000), más las built-in. Informa de errores y de las reglas más
   lentas (detection_rule_stats).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_custom_rules.py [--rules 1000] [--signals 100000] [--assets 100]

Crea activos "perf-…" y reglas "perf-rule-…" y lo borra todo al final. Ejecútalo con la API
QA PARADA (su job del motor se adelantaría) y en una base QA propia, nunca en `sentra`.
"""

import argparse
import statistics
import sys
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, func, select, text
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.detection.config import DetectionConfig
from app.detection.custom import runtime
from app.detection.custom.catalog import AGENT_EVENT_CODES
from app.detection.engine import DetectionEngine
from app.detection.recorder import SignalRecorder
from app.detection.signals import SECURITY
from app.models.asset import Asset, MonitoringMethod
from app.models.audit import AuditEvent
from app.models.detection import DetectionSignal
from app.models.detection_rule import DetectionRuleRecord, DetectionRuleStats
from app.models.event import EventLevel, SystemEvent
from app.schemas.detection_rule import RuleCreate
from app.services.audit_service import Actor
from app.services.detection_rule_service import DetectionRuleService

PREFIX = "perf-"
RULE_PREFIX = "perf-rule-"
CODES = list(AGENT_EVENT_CODES[SECURITY])
ACTOR = Actor("perf")


def definition(i: int) -> dict[str, Any]:
    """Mezcla de reglas: 60 % simples, 20 % umbral, 10 % regex, 10 % con contexto.

    Repartidas entre los ids de Security que recoge el agente (~67 reglas por id). Las
    condiciones son selectivas, como en un despliegue real: cada regla busca un usuario
    concreto, así que casi todas las candidatas se descartan en memoria y solo una pequeña
    parte coincide (y paga la escritura de la detección).
    """
    code = CODES[i % len(CODES)]
    name = f"u{i % 60}_{i % 7}"
    user = {"field": "event.data.TargetUserName", "op": "equals", "value": name}
    is_code = {"field": "event.code", "op": "equals", "value": code}
    base: dict[str, Any] = {"logsource": "windows_security"}
    kind = i % 10
    if kind < 6:
        base["condition"] = {"all": [is_code, user]}
    elif kind < 8:
        base["condition"] = {"all": [is_code, user]}
        base["threshold"] = {"count": 5, "window_minutes": 10}
        base["group_by"] = ["event.data.IpAddress"]
    elif kind == 8:
        regex = {
            "field": "event.data.TargetUserName",
            "op": "regex",
            "value": rf"^u{i % 60}_[0-{i % 7}]$",
        }
        base["condition"] = {"all": [is_code, regex]}
    else:
        asset = {"field": "asset.hostname", "op": "starts_with", "value": "perf-00"}
        base["condition"] = {"all": [is_code, user, asset]}
    return base


def create_rules(session: Session, count: int) -> list[str]:
    service = DetectionRuleService(session, get_settings())
    uids = []
    for i in range(count):
        rule = service.create(
            RuleCreate(
                title=f"{RULE_PREFIX}{i:04d}",
                category="authentication",
                definition=definition(i),
            ),
            ACTOR,
        )
        rule = service.set_state(rule.rule_id, "enable", rule.revision or 1, False, ACTOR)
        uids.append(rule.rule_id)
    return uids


def create_assets(session: Session, count: int) -> list[int]:
    ids = []
    now = datetime.now(UTC)
    for i in range(count):
        asset = Asset(
            agent_id=uuid.uuid4(),
            monitoring_method=MonitoringMethod.AGENT,
            hostname=f"{PREFIX}{i:04d}",
            os_name="Windows",
            primary_ip=f"10.251.{i // 250}.{i % 250 + 1}",
            first_seen_at=now,
            last_seen_at=now,
        )
        session.add(asset)
        session.flush()
        ids.append(asset.id)
    session.commit()
    return ids


def seed_signals(session: Session, asset_ids: list[int], total: int) -> None:
    """Señales de evento como las que deja la ingesta (data con code, channel y data.*).

    6000 usuarios distintos: solo ~1 % de las señales lleva un usuario que alguna regla
    busca, una tasa de coincidencia más cercana a la real que "todo coincide".
    """
    session.execute(
        text(
            """
            INSERT INTO detection_signals (asset_id, kind, subject, occurred_at, source_type,
                source_id, data, created_at)
            SELECT (:ids)[1 + g % cardinality(:ids)], 'event',
                'Security:' || c.code, now() - ((g % 600) || ' seconds')::interval, 'event', NULL,
                jsonb_build_object('channel', 'Security', 'code', c.code,
                    'provider', 'Microsoft-Windows-Security-Auditing', 'level', 'info',
                    'data.TargetUserName', 'u' || (g % 6000) || '_' || (g % 7),
                    'data.LogonType', '3', 'data.IpAddress', '10.9.9.' || (g % 200)),
                now()
            FROM generate_series(1, :total) AS g
            CROSS JOIN LATERAL (SELECT (:codes)[1 + (g * 7) % cardinality(:codes)] AS code) c
            """
        ),
        {"ids": asset_ids, "total": total, "codes": CODES},
    )
    session.commit()
    session.execute(text("ANALYZE detection_signals"))
    session.commit()


def ingest_overhead(session: Session, config: DetectionConfig, asset_id: int) -> list[float]:
    recorder = SignalRecorder(session, config)
    samples = []
    now = datetime.now(UTC)
    for batch in range(20):
        events = [
            SystemEvent(
                public_id=uuid.uuid4(),
                asset_id=asset_id,
                source="windows_eventlog",
                channel="Security",
                record_id=batch * 100 + i + 1,
                event_code=CODES[i % len(CODES)],
                provider="Microsoft-Windows-Security-Auditing",
                level=EventLevel.INFO,
                message="perf",
                data={"TargetUserName": f"u{i}", "LogonType": "3"},
                occurred_at=now - timedelta(seconds=i),
            )
            for i in range(50)
        ]
        session.add_all(events)
        session.flush()
        start = time.perf_counter()
        recorder.record_events(asset_id, events)
        samples.append((time.perf_counter() - start) * 1000)
    session.commit()
    return samples


def cleanup(uids: list[str], asset_ids: list[int]) -> None:
    with get_sessionmaker()() as session:
        if asset_ids:
            session.execute(delete(Asset).where(Asset.id.in_(asset_ids)))
        session.execute(
            delete(DetectionRuleRecord).where(DetectionRuleRecord.title.like(f"{RULE_PREFIX}%"))
        )
        if uids:
            session.execute(delete(DetectionRuleStats).where(DetectionRuleStats.rule_uid.in_(uids)))
            session.execute(
                delete(AuditEvent).where(
                    AuditEvent.target_type == "detection_rule", AuditEvent.target_id.in_(uids)
                )
            )
        session.commit()
        left = session.scalar(
            select(func.count())
            .select_from(DetectionRuleRecord)
            .where(DetectionRuleRecord.title.like(f"{RULE_PREFIX}%"))
        )
        print(f"cleanup: {left} perf rules left")
    runtime.reset_caches()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", type=int, default=1000)
    parser.add_argument("--signals", type=int, default=100_000)
    parser.add_argument("--assets", type=int, default=100)
    args = parser.parse_args()

    config = DetectionConfig.from_settings(get_settings())
    session = get_sessionmaker()()
    uids: list[str] = []
    asset_ids: list[int] = []
    errors = 0
    try:
        start = time.perf_counter()
        uids = create_rules(session, args.rules)
        took = time.perf_counter() - start
        print(f"[rules] {len(uids)} active custom rules created in {took:.1f} s")

        runtime.reset_caches()
        start = time.perf_counter()
        index = runtime.load_index(session)
        took = (time.perf_counter() - start) * 1000
        skipped = len(index.skipped)
        print(f"[index] loaded {len(index.rules)} rules in {took:.0f} ms (skipped {skipped})")
        sample = {"channel": "Security", "code": 4625}
        start = time.perf_counter()
        for _ in range(10_000):
            index.candidates("event", sample)
        per_lookup = (time.perf_counter() - start) / 10_000 * 1e6
        print(
            f"[index] candidates for 4625: {len(index.candidates('event', sample))}"
            f" (of {len(index.rules)}), lookup {per_lookup:.2f} µs"
        )

        asset_ids = create_assets(session, args.assets)
        samples = ingest_overhead(session, config, asset_ids[0])
        print(
            f"[ingest] batches of 50 events with raw-event recording: "
            f"median {statistics.median(samples):.1f} ms, max {max(samples):.1f} ms"
        )
        # Las señales de la prueba de ingesta no cuentan para el job.
        session.execute(delete(DetectionSignal).where(DetectionSignal.asset_id == asset_ids[0]))
        session.commit()

        start = time.perf_counter()
        seed_signals(session, asset_ids, args.signals)
        print(f"[seed] {args.signals} event signals in {time.perf_counter() - start:.1f} s")

        detector = DetectionEngine(session, config)
        start = time.perf_counter()
        total = created = updated = 0
        while True:
            run = detector.process_pending()
            total, created = total + run.signals, created + run.created
            updated, errors = updated + run.updated, errors + run.rule_errors
            if run.signals == 0:
                break
        elapsed = time.perf_counter() - start
        print(
            f"[engine] {total} signals x {len(uids)} custom rules in {elapsed:.1f} s "
            f"({total / elapsed if elapsed else 0:.0f} signals/s); "
            f"detections created {created}, updated {updated}, rule errors {errors}"
        )
        stats = session.execute(
            select(DetectionRuleStats)
            .where(DetectionRuleStats.rule_uid.in_(uids))
            .order_by(DetectionRuleStats.eval_time_us.desc())
            .limit(5)
        ).scalars()
        for row in stats:
            avg = row.eval_time_us / row.evaluations if row.evaluations else 0
            print(
                f"[slowest] {row.rule_uid}: {row.evaluations} evals, avg {avg:.1f} µs,"
                f" slow {row.slow_evaluations}, errors {row.errors}"
            )
        totals = session.execute(
            select(
                func.sum(DetectionRuleStats.evaluations),
                func.sum(DetectionRuleStats.matches),
                func.sum(DetectionRuleStats.errors),
            ).where(DetectionRuleStats.rule_uid.in_(uids))
        ).one()
        print(f"[stats] evaluations {totals[0]}, matches {totals[1]}, errors {totals[2]}")
        return 0 if errors == 0 else 1
    finally:
        session.rollback()
        session.close()
        cleanup(uids, asset_ids)


if __name__ == "__main__":
    sys.exit(main())
