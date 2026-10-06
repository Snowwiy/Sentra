"""Rendimiento de Vulnerability & Exposure Management (Fase 5B) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción), con los valores por defecto:
10 000 activos con agente, 100 000 programas inventariados (10 por activo), un catálogo de
100 000 registros (500 afectan a productos instalados) y ~50 000 findings resultantes.

1. importación del catálogo por la ruta de la CLI (fichero, por lotes);
2. evaluación completa de la cola (activos/s);
3. reevaluación sin cambios (huella: debe ser mucho más rápida);
4. lecturas de la UI: resumen, listado con filtros, búsqueda y orden, findings de un activo y
   exposición; mediana en ms y sentencias SQL por petición (constantes: sin N+1).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_vulnerabilities.py [--assets 10000] [--records 100000]

Crea activos "perf-vuln-…" y la fuente de catálogo "perf-vuln" y lo borra todo al final. No
toca otros datos. Úsalo en una base QA. Los CVE son del rango ficticio CVE-2099-*.
"""

import argparse
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, event, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_engine, get_sessionmaker
from app.models.asset import Asset
from app.models.vulnerability import Vulnerability, VulnerabilityFinding, VulnerabilitySource
from app.services import audit_service
from app.services.vulnerability_catalog_service import VulnerabilityCatalogService
from app.services.vulnerability_service import FindingFilter, VulnerabilityService
from app.vulnerabilities.engine import VulnerabilityConfig, VulnerabilityEngine, VulnerabilityRun
from app.vulnerabilities.queue import mark_dirty

PREFIX = "perf-vuln-"
SOURCE = "perf-vuln"
PRODUCTS = 1000
SOFTWARE_PER_ASSET = 10
SERVICE_PORT = 8443


@contextmanager
def count_statements(engine: Engine) -> Iterator[list[str]]:
    statements: list[str] = []

    def before(_conn: Any, _cursor: Any, statement: str, *_args: Any) -> None:
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", before)
    try:
        yield statements
    finally:
        event.remove(engine, "before_cursor_execute", before)


def timed(fn: Callable[[], Any], repeat: int = 5) -> tuple[float, Any]:
    """Mediana en milisegundos de `repeat` ejecuciones."""
    samples, result = [], None
    for _ in range(repeat):
        start = time.perf_counter()
        result = fn()
        samples.append((time.perf_counter() - start) * 1000)
    return statistics.median(samples), result


def seed_assets(session: Session, assets: int) -> list[int]:
    """Activos Windows con agente e inventario: 10 programas contiguos del catálogo de
    productos, así cada activo tiene exactamente 5 productos vulnerables (los pares)."""
    now = datetime.now(UTC)
    session.execute(
        text(
            """
            INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, os_name,
                os_version, primary_ip, status, first_seen_at, last_seen_at, created_at,
                updated_at, criticality)
            SELECT gen_random_uuid(), gen_random_uuid(), 'agent', :prefix || lpad(g::text, 5, '0'),
                'Windows', '11 (build 10.0.26200)',
                '10.252.' || (g / 250) || '.' || (g % 250 + 1), 'online', :now, :now, :now, :now,
                (ARRAY['low','medium','medium','high','critical'])[1 + g % 5]::asset_criticality
            FROM generate_series(1, :n) AS g
            """
        ),
        {"prefix": PREFIX, "now": now, "n": assets},
    )
    ids = list(
        session.scalars(
            select(Asset.id).where(Asset.hostname.like(f"{PREFIX}%")).order_by(Asset.id)
        )
    )
    session.execute(
        text(
            """
            INSERT INTO asset_inventories (asset_id, collected_at, received_at, data)
            SELECT a.id, :now, :now, jsonb_build_object(
                'software_source', 'windows_registry',
                'incomplete_sections', '[]'::jsonb,
                'software', (
                    SELECT jsonb_agg(jsonb_build_object(
                        'name', 'PerfApp ' || ((a.rn * :per + k) % :products),
                        'version', '1.' || k || '.0',
                        'publisher', 'Perf Vendor ' || ((a.rn * :per + k) % :products % 50)))
                    FROM generate_series(0, :per - 1) AS k))
            FROM (SELECT id, row_number() OVER (ORDER BY id) AS rn
                  FROM assets WHERE id = ANY(:ids)) AS a
            """
        ),
        {"ids": ids, "now": now, "per": SOFTWARE_PER_ASSET, "products": PRODUCTS},
    )
    # El 20 % de los activos tiene observado el puerto de servicio de los registros.
    session.execute(
        text(
            """
            INSERT INTO asset_ports (asset_id, protocol, port, state, service_hint,
                first_seen_at, opened_at, last_seen_at, misses)
            SELECT id, 'tcp', :port, 'open', 'https-alt', :now, :now, :now, 0
            FROM assets WHERE id = ANY(:ids) AND id % 5 = 0
            """
        ),
        {"ids": ids, "now": now, "port": SERVICE_PORT},
    )
    session.commit()
    return ids


def write_catalog(path: Path, records: int) -> None:
    """Catálogo sintético: los productos pares instalados son vulnerables (< 2.0); el resto
    de registros afecta a productos que nadie tiene."""
    vulnerable = [p for p in range(PRODUCTS) if p % 2 == 0]
    items: list[dict[str, Any]] = []
    for n in range(records):
        if n < len(vulnerable):
            product = f"PerfApp {vulnerable[n]}"
            publisher = f"Perf Vendor {vulnerable[n] % 50}"
            ports = [SERVICE_PORT]
        else:
            product = f"PerfOther {n}"
            publisher = "Perf Other Corp"
            ports = []
        items.append(
            {
                "id": f"CVE-2099-{100000 + n}",
                "title": f"{product}: vulnerabilidad sintética {n}",
                "severity": ("critical", "high", "medium", "low")[n % 4],
                "cvss": {"version": "3.1", "score": (9.8, 7.5, 5.3, 3.1)[n % 4]},
                "references": [f"https://example.org/perf/{n}"],
                "affected": [
                    {
                        "product": product,
                        "vendor": publisher,
                        "names": [product],
                        "publishers": [publisher],
                        "ranges": [{"lt": "2.0"}],
                        "fixed_version": "2.0",
                        "service_ports": ports,
                    }
                ],
            }
        )
    document = {
        "format": "sentra-vuln-catalog/1",
        "source": {"id": SOURCE, "name": "Perf sintético", "version": "1"},
        "vulnerabilities": items,
    }
    path.write_text(json.dumps(document), encoding="utf-8")


def cleanup(session: Session) -> None:
    ids = list(session.scalars(select(Asset.id).where(Asset.hostname.like(f"{PREFIX}%"))))
    if ids:
        # ON DELETE CASCADE: inventario, puertos, findings, historial, estado y riesgo.
        session.execute(delete(Asset).where(Asset.id.in_(ids)))
    source = session.scalar(
        select(VulnerabilitySource.id).where(VulnerabilitySource.source_key == SOURCE)
    )
    if source is not None:
        session.execute(
            delete(VulnerabilityFinding).where(
                VulnerabilityFinding.vulnerability_id.in_(
                    select(Vulnerability.id).where(Vulnerability.source_id == source)
                )
            )
        )
        session.execute(delete(Vulnerability).where(Vulnerability.source_id == source))
        session.execute(delete(VulnerabilitySource).where(VulnerabilitySource.id == source))
    session.commit()


def evaluate_all(session: Session, config: VulnerabilityConfig) -> tuple[float, VulnerabilityRun]:
    engine = VulnerabilityEngine(session, config)
    engine.seed_missing(limit=1_000_000)
    total = VulnerabilityRun()
    start = time.perf_counter()
    while True:
        run = engine.process_dirty()
        total.add(run)
        if run.assets == 0 or run.errors == run.assets:
            break
    return time.perf_counter() - start, total


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--assets", type=int, default=10_000)
    parser.add_argument("--records", type=int, default=100_000)
    args = parser.parse_args()
    if args.records < PRODUCTS // 2:
        parser.error(f"--records must be at least {PRODUCTS // 2}")

    settings = get_settings()
    if settings.environment == "production":
        print("refusing to run against a production environment", file=sys.stderr)
        return 2
    engine = get_engine()
    # Sin alertas: se mide el motor, no AlertService.
    config = replace(VulnerabilityConfig.from_settings(settings), alert_enabled=False)
    session = get_sessionmaker()()
    try:
        cleanup(session)
        start = time.perf_counter()
        ids = seed_assets(session, args.assets)
        print(
            f"seed: {len(ids)} activos, {len(ids) * SOFTWARE_PER_ASSET} programas"
            f" en {time.perf_counter() - start:.1f} s"
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "catalog.json"
            write_catalog(path, args.records)
            size_mb = path.stat().st_size / 1024 / 1024
            catalog = VulnerabilityCatalogService(session, settings)
            start = time.perf_counter()
            result, _ = catalog.import_file(
                path,
                audit_service.CLI,
                skip_invalid=False,
                batch_size=settings.vuln_import_batch_size,
            )
            elapsed = time.perf_counter() - start
        print(
            f"import: {result.new} registros ({size_mb:.1f} MiB) en {elapsed:.1f} s"
            f" ({result.new / elapsed:.0f} registros/s), {result.assets_queued} activos en cola"
        )

        mark_dirty(session, ids, "manual")
        session.commit()
        elapsed, run = evaluate_all(session, config)
        findings = session.scalar(
            select(func.count())
            .select_from(VulnerabilityFinding)
            .where(VulnerabilityFinding.asset_id.in_(ids))
        )
        print(
            f"evaluación completa: {run.assets} activos en {elapsed:.1f} s"
            f" ({run.assets / elapsed:.0f} activos/s), {findings} findings, {run.errors} errores"
        )

        mark_dirty(session, ids, "manual")
        session.commit()
        elapsed, run = evaluate_all(session, config)
        print(
            f"reevaluación sin cambios: {run.assets} activos en {elapsed:.1f} s"
            f" ({run.assets / elapsed:.0f} activos/s), {run.updated} actualizados"
        )

        service = VulnerabilityService(session, config)
        asset_public = session.scalar(select(Asset.public_id).where(Asset.id == ids[len(ids) // 2]))
        if asset_public is None:
            raise RuntimeError("asset not found")

        def page(f: FindingFilter, sort: Any = "priority", offset: int = 0) -> Any:
            return service.list_findings(f, sort, True, 50, offset)

        def exposure() -> Any:
            return service.exposure(
                sensitive_only=False,
                new_only=False,
                with_vulnerabilities=True,
                asset_public_id=None,
                port=None,
                limit=50,
                offset=0,
            )

        active = FindingFilter(active=True)
        reads: list[tuple[str, Callable[[], Any]]] = [
            ("overview", service.overview),
            ("lista activas, prioridad", lambda: page(active)),
            ("lista página 100", lambda: page(active, offset=5000)),
            (
                "lista críticas por CVSS",
                lambda: page(FindingFilter(active=True, severity="critical"), "cvss"),
            ),
            (
                "lista expuestas",
                lambda: page(FindingFilter(exposure_state="observed"), "asset_risk"),
            ),
            ("búsqueda CVE", lambda: page(FindingFilter(search="CVE-2099-100042"))),
            ("búsqueda hostname", lambda: page(FindingFilter(search=f"{PREFIX}05000"))),
            (
                "findings de un activo",
                lambda: service.asset_findings(asset_public, active, "priority", True, 50, 0),
            ),
            ("exposición", exposure),
        ]
        print(f"{'lectura':32} {'ms':>8} {'SQL':>5}")
        for name, fn in reads:
            with count_statements(engine) as statements:
                fn()
            ms, _ = timed(fn)
            session.rollback()
            print(f"{name:32} {ms:8.1f} {len(statements):5}")
        return 0
    finally:
        session.rollback()
        start = time.perf_counter()
        cleanup(session)
        print(f"limpieza: {time.perf_counter() - start:.1f} s")
        session.close()


if __name__ == "__main__":
    sys.exit(main())
