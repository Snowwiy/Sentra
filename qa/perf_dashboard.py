"""Rendimiento del dashboard paginado (Fase 4M) con datos SINTÉTICOS.

Antes de la Fase 4M el dashboard y la página Red descargaban TODOS los activos en cada
refresco y contaban y filtraban en el navegador. Ahora piden GET /dashboard/summary
(agregados en SQL) y una página de GET /assets con filtros y orden en PostgreSQL.

Dos pasos, contra el PostgreSQL de DATABASE_URL (una base QA, nunca producción):

1. Sembrar (desde backend/, con el entorno del backend activo):
       PYTHONPATH=. python ../qa/perf_dashboard.py seed [--assets 10000] [--incidents 10000]
   10 000 activos (60 % con agente, parte sin contacto reciente; 30 % descubiertos con
   puertos; 10 % agentless), 10 000 incidentes y 20 000 detecciones, con prefijo "perf-dash-".
2. Medir por HTTP contra una API en marcha con esa base (solo stdlib):
       SENTRA_QA_API_URL=http://127.0.0.1:8100 SENTRA_QA_ADMIN_USER=... \\
       SENTRA_QA_ADMIN_PASSWORD=... python qa/perf_dashboard.py measure [--label nuevo]
   Mediana de 5 peticiones (ms) y tamaño de la respuesta de cada lectura del dashboard.
   Con una API anterior a la 4M (sin /dashboard/summary) mide el listado completo antiguo.
3. Limpiar: PYTHONPATH=. python ../qa/perf_dashboard.py cleanup
"""

import argparse
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from typing import Any

PREFIX = "perf-dash-"


def seed(assets: int, incidents: int) -> None:
    from datetime import UTC, datetime

    from app.db.session import get_sessionmaker
    from sqlalchemy import text

    now = datetime.now(UTC)
    with get_sessionmaker()() as session:
        session.execute(
            text(
                """
                INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, device_name,
                    os_name, primary_ip, status, network_status, device_type, first_seen_at,
                    last_seen_at, last_network_seen_at, created_at, updated_at, criticality)
                SELECT gen_random_uuid(),
                    CASE WHEN g % 10 < 6 THEN gen_random_uuid() END,
                    (CASE WHEN g % 10 < 6 THEN 'agent' WHEN g % 10 < 9 THEN 'discovered'
                          ELSE 'agentless' END)::asset_monitoring_method,
                    CASE WHEN g % 10 < 6 THEN :prefix || lpad(g::text, 5, '0') END,
                    CASE WHEN g % 10 >= 6 THEN :prefix || 'dev-' || g END,
                    CASE WHEN g % 10 < 6 THEN 'Windows' END,
                    '10.' || (40 + g / 62500) || '.' || (g / 250 % 250) || '.' || (g % 250 + 1),
                    'online',
                    CASE WHEN g % 10 >= 6 THEN
                        (CASE WHEN g % 7 = 0 THEN 'offline' ELSE 'online' END)::asset_status END,
                    (ARRAY['pc','server','printer','phone','router', NULL])[1 + g % 6],
                    :now - ((g % 9000) || ' minutes')::interval,
                    CASE WHEN g % 10 < 6 THEN
                        CASE WHEN g % 5 = 0 THEN :now - interval '2 hours' ELSE :now END END,
                    CASE WHEN g % 10 >= 6 THEN :now END,
                    :now, :now,
                    (ARRAY['low','medium','high','critical'])[1 + g % 4]::asset_criticality
                FROM generate_series(1, :n) AS g
                """
            ),
            {"prefix": PREFIX, "now": now, "n": assets},
        )
        session.execute(
            text(
                """
                INSERT INTO asset_ports (asset_id, protocol, port, state, first_seen_at,
                    opened_at, last_seen_at)
                SELECT a.id, 'tcp', p, 'open', :now, :now, :now
                FROM assets a, unnest(ARRAY[22, 80, 443]) AS p
                WHERE a.device_name LIKE :like AND a.monitoring_method = 'discovered'
                """
            ),
            {"like": f"{PREFIX}dev-%", "now": now},
        )
        session.execute(
            text(
                """
                INSERT INTO detections (public_id, asset_id, rule_id, rule_version, kind,
                    dedup_key, severity, confidence, status, title, summary, occurrence_count,
                    first_seen_at, last_seen_at, created_at, updated_at)
                SELECT gen_random_uuid(), a.id, 'AUTH-001', 1, 'single',
                    :prefix || a.id || '-' || k,
                    (ARRAY['low','medium','high','critical'])[1 + (a.id + k) % 4]
                        ::detection_severity,
                    'medium', (ARRAY['open','acknowledged','resolved'])[1 + (a.id + k) % 3]
                        ::detection_status,
                    'Detección perf', 'sintética', 1, :now, :now, :now, :now
                FROM (SELECT id FROM assets WHERE hostname LIKE :like OR device_name LIKE :like
                      ORDER BY id LIMIT :n) a, generate_series(1, 2) AS k
                """
            ),
            {"prefix": PREFIX, "like": f"{PREFIX}%", "now": now, "n": assets},
        )
        session.execute(
            text(
                """
                INSERT INTO incidents (public_id, title, severity, priority, status, created_at,
                    updated_at, last_activity_at, first_seen_at, last_seen_at, version)
                SELECT gen_random_uuid(), :prefix || g,
                    (ARRAY['low','medium','high','critical'])[1 + g % 4]::incident_level,
                    (ARRAY['low','medium','high','critical'])[1 + (g / 3) % 4]::incident_level,
                    (ARRAY['open','triage','investigating','contained','resolved','closed'])
                        [1 + g % 6]::incident_status,
                    :now - ((g % 40000) || ' minutes')::interval, :now,
                    :now - ((g % 30000) || ' minutes')::interval,
                    :now - ((g % 40000) || ' minutes')::interval, :now, 1
                FROM generate_series(1, :n) AS g
                """
            ),
            {"prefix": PREFIX, "now": now, "n": incidents},
        )
        session.commit()
        session.execute(text("ANALYZE assets; ANALYZE asset_ports; ANALYZE incidents"))
        session.commit()
    print(f"seeded {assets} assets and {incidents} incidents ({PREFIX}*)")


def cleanup() -> None:
    from app.db.session import get_sessionmaker
    from sqlalchemy import text

    with get_sessionmaker()() as session:
        incidents = session.scalar(
            text(
                "WITH d AS (DELETE FROM incidents WHERE title LIKE :like RETURNING 1)"
                " SELECT count(*) FROM d"
            ),
            {"like": f"{PREFIX}%"},
        )
        # ON DELETE CASCADE se lleva puertos y detecciones.
        assets = session.scalar(
            text(
                "WITH d AS (DELETE FROM assets WHERE hostname LIKE :like OR device_name LIKE :like"
                " RETURNING 1) SELECT count(*) FROM d"
            ),
            {"like": f"{PREFIX}%"},
        )
        session.commit()
    print(f"deleted {assets} assets and {incidents} incidents")


# --- Medición por HTTP --------------------------------------------------------------------

API = os.environ.get("SENTRA_QA_API_URL", "http://127.0.0.1:8100").rstrip("/") + "/api/v1"
HEADERS: dict[str, str] = {}


def call(method: str, path: str, body: Any = None) -> tuple[int, bytes, dict[str, str]]:
    data = None if body is None else json.dumps(body).encode()
    headers = {"Accept": "application/json", **HEADERS}
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API + path, data=data, headers=headers, method=method)  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
            return response.status, response.read(), dict(response.headers)
    except urllib.error.HTTPError as error:
        return error.code, error.read(), dict(error.headers)


def login() -> None:
    status, raw, headers = call(
        "POST",
        "/auth/login",
        {
            "username": os.environ["SENTRA_QA_ADMIN_USER"],
            "password": os.environ["SENTRA_QA_ADMIN_PASSWORD"],
        },
    )
    if status != 200:
        sys.exit(f"login failed: {status} {raw[:200]!r}")
    cookie = headers.get("set-cookie") or headers.get("Set-Cookie") or ""
    HEADERS["Cookie"] = cookie.split(";", 1)[0]
    HEADERS["X-CSRF-Token"] = json.loads(raw)["csrf_token"]


def timed(path: str, repeat: int = 5) -> tuple[float, int, int]:
    samples, size, status = [], 0, 0
    for _ in range(repeat):
        start = time.perf_counter()
        status, raw, _ = call("GET", path)
        samples.append((time.perf_counter() - start) * 1000)
        size = len(raw)
    return statistics.median(samples), size, status


def measure(label: str) -> None:
    login()
    has_summary = call("GET", "/dashboard/summary")[0] == 200
    reads: list[tuple[str, str]]
    if has_summary:
        reads = [
            ("Dashboard: resumen (agregados SQL)", "/dashboard/summary"),
            ("Dashboard: página 1 de activos (50)", "/assets?limit=50"),
            ("Dashboard: filtro offline", "/assets?status=offline&limit=50"),
            ("Dashboard: búsqueda de texto", "/assets?q=dev-77&limit=50"),
            ("Red: orden por IP", "/assets?sort=ip&limit=50"),
            (
                "Red: subred /16 + orden por puertos",
                "/assets?subnet=10.40.0.0/16&sort=ports&order=desc&limit=50",
            ),
            ("Red: última página (offset 9950)", "/assets?sort=ip&limit=50&offset=9950"),
            ("Selector de activos (búsqueda)", "/assets?q=perf-dash-001&sort=name&limit=50"),
            ("Todos los activos en páginas de 500 (export)", "__all_pages__"),
        ]
    else:
        reads = [("Dashboard antiguo: GET /assets completo", "/assets")]
    reads += [
        ("Incidentes: página 1", "/incidents?limit=50"),
        ("Detecciones: página 1", "/detections?limit=50"),
        ("Riesgo: resumen", "/risk/overview"),
        ("Riesgo: página 1", "/risk/assets?limit=50"),
    ]
    print(f"\n## {label} ({API})\n")
    print("| Lectura | Mediana (ms) | Tamaño | HTTP |")
    print("| --- | ---: | ---: | ---: |")
    for name, path in reads:
        if path == "__all_pages__":
            start, size, offset = time.perf_counter(), 0, 0
            while True:
                status, raw, _ = call("GET", f"/assets?sort=ip&limit=500&offset={offset}")
                size += len(raw)
                body = json.loads(raw)
                offset += 500
                if offset >= body["total"]:
                    break
            ms, code = (time.perf_counter() - start) * 1000, status
        else:
            ms, size, code = timed(path)
        print(f"| {name} | {ms:,.0f} | {size / 1024:,.0f} KB | {code} |")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["seed", "measure", "cleanup"])
    parser.add_argument("--assets", type=int, default=10_000)
    parser.add_argument("--incidents", type=int, default=10_000)
    parser.add_argument("--label", default="Fase 4M")
    args = parser.parse_args()
    if args.command == "seed":
        seed(args.assets, args.incidents)
    elif args.command == "cleanup":
        cleanup()
    else:
        measure(args.label)
    return 0


if __name__ == "__main__":
    sys.exit(main())
