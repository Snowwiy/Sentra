"""Rendimiento de la telemetría de endpoint y del árbol de procesos (Fase 6E) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción):

1. Ingesta: lotes de 1000 eventos de proceso (el máximo de POST /agents/activity) por la misma
   ruta de servicio que usa la API, sin la parte HTTP. Lotes por segundo y eventos por segundo.
2. Árbol de procesos con muchas instancias: raíces, un nivel de hijos y búsqueda, con la
   mediana de varias repeticiones.
3. Listado de actividad con cursor.

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_endpoint.py [--batches 20] [--children 50] [--repeat 20]

Crea un activo "perf-endpoint-…" y lo borra al final (ON DELETE CASCADE se lleva actividad e
instancias). No toca otros activos.
"""

import argparse
import statistics
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import delete

from app.core.config import get_settings
from app.db.session import get_sessionmaker
from app.endpoint.service import ActivityIngest, EndpointReadService
from app.models.asset import Asset, MonitoringMethod
from app.schemas.endpoint import ActivityBatchIn

BOOT = "perf-boot"


def _event(key: str, name: str, pid: int, parent: str | None) -> dict[str, Any]:
    data: dict[str, Any] = {"pid": pid, "name": name, "exe": f"C:\\Program Files\\{name}"}
    if parent:
        data["parent_instance_key"] = parent
        data["parent_relation"] = "observed"
    data["cmdline"] = f'"C:\\Program Files\\{name}" --token=abc{pid} --flag'
    return {
        "event_uid": str(uuid.uuid4()),
        "seq": pid,
        "category": "process",
        "action": "start",
        "occurred_at": datetime.now(UTC).isoformat(),
        "source": "psutil_poll",
        "instance_key": key,
        "data": data,
    }


def _median_ms(fn: Callable[[], Any], repeat: int) -> float:
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batches", type=int, default=20)
    parser.add_argument("--children", type=int, default=50, help="hijos por proceso raíz")
    parser.add_argument("--repeat", type=int, default=20)
    args = parser.parse_args()

    settings = get_settings()
    factory = get_sessionmaker()
    with factory() as session:
        asset = Asset(
            agent_id=uuid.uuid4(),
            monitoring_method=MonitoringMethod.AGENT,
            hostname=f"perf-endpoint-{uuid.uuid4().hex[:8]}",
            os_name="Windows",
            primary_ip="10.251.0.1",
            first_seen_at=datetime.now(UTC),
            last_seen_at=datetime.now(UTC),
        )
        session.add(asset)
        session.commit()
        asset_pk, public_id, agent_id = asset.id, asset.public_id, asset.agent_id
    if agent_id is None:
        raise SystemExit("el activo de prueba no tiene agent_id")

    try:
        # Cada lote: 1000 procesos repartidos en raíces con `children` hijos cada una.
        per_root = args.children + 1
        roots_per_batch = 1000 // per_root
        durations = []
        first_root = ""
        pid = 1000
        for _ in range(args.batches):
            events = []
            for _r in range(roots_per_batch):
                root = uuid.uuid4().hex
                first_root = first_root or root
                pid += 1
                events.append(_event(root, "explorer.exe", pid, None))
                for _c in range(args.children):
                    pid += 1
                    events.append(_event(uuid.uuid4().hex, "child.exe", pid, root))
            batch = ActivityBatchIn.model_validate(
                {"agent_id": agent_id, "batch_id": uuid.uuid4(), "boot_id": BOOT, "events": events}
            )
            with factory() as session:
                target = session.get(Asset, asset_pk)
                if target is None:
                    raise SystemExit("el activo de prueba ha desaparecido")
                start = time.perf_counter()
                ActivityIngest(session, settings).ingest(batch, target)
                durations.append(time.perf_counter() - start)
        total_events = args.batches * roots_per_batch * per_root
        print(f"Ingesta: {args.batches} lotes, {total_events} eventos")
        print(
            f"  lote mediano {statistics.median(durations) * 1000:.0f} ms,"
            f" p95 {sorted(durations)[int(len(durations) * 0.95) - 1] * 1000:.0f} ms"
        )
        print(f"  {total_events / sum(durations):.0f} eventos/s")

        with factory() as session:
            reader = EndpointReadService(session, settings)
            roots = _median_ms(
                lambda: reader.process_tree(public_id, None, None, None, 100), args.repeat
            )
            children = _median_ms(
                lambda: reader.process_tree(public_id, first_root, None, None, 100), args.repeat
            )
            search = _median_ms(
                lambda: reader.process_tree(public_id, None, None, "explorer", 100), args.repeat
            )
            activity = _median_ms(
                lambda: reader.activity(public_id, "process", None, None, None, None, None, 100),
                args.repeat,
            )
        print(f"Árbol con {total_events} instancias (mediana de {args.repeat}):")
        print(
            f"  raíces (100) {roots:.1f} ms, hijos de una raíz {children:.1f} ms,"
            f" búsqueda {search:.1f} ms"
        )
        print(f"Actividad, página de 100: {activity:.1f} ms")
    finally:
        with factory() as session:
            session.execute(delete(Asset).where(Asset.id == asset_pk))
            session.commit()


if __name__ == "__main__":
    main()
