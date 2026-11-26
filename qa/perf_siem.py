"""Rendimiento de la integración SIEM (Fase 7F) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Ingesta: eventos por segundo por el mismo camino que una importación (normalización,
   deduplicación, atribución, correlación y señales), en lotes de 1000.
2. Hunting (7F.6): latencia p50/p95 de búsquedas típicas sobre el histórico creado.
3. Live SOC (7F.7): coste de una consulta del stream (LiveReader.poll) desde el presente y
   con atraso.

Uso (desde backend/, con el entorno del backend activo):

    PYTHONPATH=. python ../qa/perf_siem.py [--events 20000] [--runs 20]

Crea una fuente "perf-siem-…" en el site por defecto y la borra al final (los eventos, enlaces
y recibos se borran con ella; las señales de detección que generen sus alertas también se
limpian). No toca otras fuentes ni otros datos.
"""

import argparse
import json
import random
import statistics
import time
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import delete, select

from app.core.config import get_settings
from app.core.permissions import Role, permissions_for
from app.db.session import get_engine, get_sessionmaker
from app.live.stream import Cursor, LiveReader, allowed_channels
from app.models.detection import DetectionSignal
from app.models.siem import SiemBatch, SiemEvent, SiemSource
from app.models.site import Site
from app.schemas.siem import SiemImportRequest
from app.schemas.siem_hunting import SiemSearchRequest
from app.services.audit_service import Actor
from app.siem.analysis import siem_analyzers
from app.siem.investigation import SiemInvestigationService

PREFIX = "perf-siem-"
# Datos sintéticos reproducibles; no es criptografía.
rng = random.Random(7)  # noqa: S311


def eve(i: int, now: datetime) -> dict[str, Any]:
    at = now - timedelta(seconds=rng.randint(0, 6 * 3600))
    alert = i % 10 == 0
    record: dict[str, Any] = {
        "timestamp": at.strftime("%Y-%m-%dT%H:%M:%S.%f+0000"),
        "flow_id": 10_000_000 + i,
        "event_type": "alert" if alert else "flow",
        "src_ip": f"10.{rng.randint(80, 89)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}",
        "src_port": rng.randint(1024, 65000),
        "dest_ip": f"198.51.100.{rng.randint(1, 254)}",
        "dest_port": rng.choice([22, 53, 80, 443, 445, 3389]),
        "proto": "TCP",
        "community_id": f"1:{uuid.uuid4().hex[:27]}=",
    }
    if alert:
        record["alert"] = {
            "gid": 1,
            "signature_id": 2_000_000 + i % 50,
            "rev": 1,
            "signature": f"PERF synthetic signature {i % 50}",
            "category": "Misc activity",
            "severity": rng.choice([1, 2, 3]),
        }
    else:
        record["flow"] = {"pkts_toserver": 5, "pkts_toclient": 4, "bytes_toserver": 300}
    return record


def percentile(values: list[float], pct: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round(pct / 100 * (len(ordered) - 1)))]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", type=int, default=20_000)
    parser.add_argument("--runs", type=int, default=20)
    args = parser.parse_args()
    settings = get_settings()
    factory = get_sessionmaker()
    engine = get_engine()
    now = datetime.now(UTC)
    with factory() as session:
        site = session.scalar(select(Site).order_by(Site.id).limit(1))
        if site is None:
            raise SystemExit("No hay site por defecto: ejecute las migraciones")
        source = SiemSource(
            site_id=site.id,
            source_type="suricata_eve",
            name=f"{PREFIX}{uuid.uuid4().hex[:8]}",
            transport="upload",
            connector_version="1.0.0",
            enabled=True,
            config={},
            max_events_per_minute=10_000_000,
            created_by="perf",
        )
        session.add(source)
        session.commit()
        source_public, source_pk, site_public = source.public_id, source.id, site.public_id
    actor = Actor("perf")
    try:
        # 1. Ingesta
        batch_times: list[float] = []
        total = 0
        for start in range(0, args.events, 1000):
            lines = [json.dumps(eve(i, now)) for i in range(start, min(start + 1000, args.events))]
            with factory() as session:
                service = SiemInvestigationService(session, settings)
                began = time.perf_counter()
                result = service.import_records(
                    source_public,
                    SiemImportRequest(content="\n".join(lines), filename="perf.json"),
                    actor,
                    siem_analyzers(),
                )
                batch_times.append(time.perf_counter() - began)
                total += result.accepted
        ingest_seconds = sum(batch_times)
        rate = total / ingest_seconds
        print(f"ingesta: {total} eventos en {ingest_seconds:.1f} s = {rate:.0f} ev/s")
        print(
            f"  lote de 1000: p50 {percentile(batch_times, 50) * 1000:.0f} ms,"
            f" p95 {percentile(batch_times, 95) * 1000:.0f} ms"
        )

        # 2. Hunting
        window = {"since": now - timedelta(hours=24), "until": now + timedelta(minutes=5)}
        queries: dict[str, dict[str, Any]] = {
            "ventana 24 h, página 50": {},
            "ventana + recuento": {"count": True},
            "alertas (event_types)": {"event_types": ["ids.alert"]},
            "IP exacta": {"ip": "198.51.100.7"},
            "CIDR /16": {"ip": "10.85.0.0/16"},
            "puerto 3389": {"port": 3389},
            "texto en mensaje": {"text": "signature 7"},
        }
        for label, extra in queries.items():
            times: list[float] = []
            for _ in range(args.runs):
                with factory() as session:
                    service = SiemInvestigationService(session, settings)
                    began = time.perf_counter()
                    service.search(
                        SiemSearchRequest(**window, site_id=site_public, **extra), site.id
                    )
                    times.append((time.perf_counter() - began) * 1000)
                    session.rollback()
            print(
                f"búsqueda [{label}]: p50 {statistics.median(times):.1f} ms,"
                f" p95 {percentile(times, 95):.1f} ms"
            )

        # 3. Live SOC
        reader = LiveReader(engine, None)
        channels = allowed_channels(permissions_for(Role.ANALYST))
        for label, cursor in (
            ("desde el presente", reader.heads()),
            ("con atraso (cursor 0)", Cursor()),
        ):
            times = []
            for _ in range(args.runs):
                began = time.perf_counter()
                reader.poll(cursor, channels)
                times.append((time.perf_counter() - began) * 1000)
            print(
                f"live poll [{label}]: p50 {statistics.median(times):.1f} ms,"
                f" p95 {percentile(times, 95):.1f} ms"
            )
    finally:
        with factory() as session:
            event_ids = [
                str(e)
                for e in session.scalars(
                    select(SiemEvent.event_id).where(SiemEvent.source_id == source_pk)
                )
            ]
            for start in range(0, len(event_ids), 5000):
                session.execute(
                    delete(DetectionSignal).where(
                        DetectionSignal.source_type == "siem",
                        DetectionSignal.source_id.in_(event_ids[start : start + 5000]),
                    )
                )
            session.execute(delete(SiemEvent).where(SiemEvent.source_id == source_pk))
            session.execute(delete(SiemBatch).where(SiemBatch.source_id == source_pk))
            session.execute(delete(SiemSource).where(SiemSource.id == source_pk))
            session.commit()
        print("limpieza: fuente y eventos de prueba borrados")


if __name__ == "__main__":
    main()
