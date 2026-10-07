"""Rendimiento de Threat Intelligence (Fase 5C) con datos SINTÉTICOS.

Mide, contra el PostgreSQL de DATABASE_URL (nunca producción), con los valores por defecto:

1. feed KEV sintético de 2 000 entradas y feed EPSS de 300 000 filas (gzip) por la ruta de la
   CLI (staging + COPY + SQL por conjuntos); reimportación idéntica (debe ser barata);
2. importación de 100 000 IOCs (IPs, redes, dominios y hashes) en UNA transacción;
3. matching retroactivo contra 2 000 activos con 50 000 eventos de inicio de sesión y
   conexiones establecidas en el inventario; vuelta incremental sin datos nuevos;
4. lecturas de la UI: resumen, listado de indicadores (filtro y prefijo), coincidencias e
   inteligencia de explotación para 50 000 CVE; mediana en ms y sentencias SQL (sin N+1).

Uso (desde backend/, con el entorno del backend activo):

    $env:PYTHONPATH = "."   # (Linux: PYTHONPATH=. delante del comando)
    python ../qa/perf_threat_intel.py [--indicators 100000] [--epss 300000] [--assets 2000]

Crea fuentes "perf-ti-…" y activos "perf-ti-…" y lo borra todo al final. No toca otros datos
ni descarga nada. Úsalo en una base QA. CVE ficticios (CVE-2099-*) e IPs de documentación.
"""

import argparse
import gzip
import json
import statistics
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import delete, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.db.session import get_engine, get_sessionmaker
from app.models.asset import Asset
from app.models.threat_intel import (
    ThreatIndicator,
    ThreatIntelChange,
    ThreatIntelMatch,
    ThreatIntelSource,
    ThreatIntelSync,
    VulnerabilityIntel,
)
from app.services import audit_service
from app.services.threat_intel_service import (
    IndicatorFilter,
    MatchFilter,
    ThreatIntelService,
)
from app.threat_intel.config import ThreatIntelConfig
from app.threat_intel.lookup import load_exploitation
from app.threat_intel.matching import ThreatIntelMatcher
from app.threat_intel.sync import ThreatIntelSyncer

PREFIX = "perf-ti-"
SOURCES = {
    "perf-ti-kev": ("cisa_kev", "exploitation", "official"),
    "perf-ti-epss": ("first_epss", "exploitation", "official"),
    "perf-ti-iocs": ("local_import", "ioc", "local"),
}


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


def create_sources(session: Session) -> dict[str, int]:
    now = datetime.now(UTC)
    ids: dict[str, int] = {}
    for key, (provider, category, trust) in SOURCES.items():
        source = ThreatIntelSource(
            source_key=key,
            name=f"Perf {key}",
            provider=provider,
            category=category,
            trust=trust,
            enabled=True,
            network_required=provider != "local_import",
            status="never",
            created_by="perf",
            created_at=now,
            updated_at=now,
        )
        session.add(source)
        session.flush()
        ids[key] = source.id
    session.commit()
    return ids


def write_kev(path: Path, entries: int) -> None:
    items = [
        {
            "cveID": f"CVE-2099-{100000 + n}",
            "vendorProject": "Perf Vendor",
            "product": f"PerfApp {n}",
            "vulnerabilityName": f"PerfApp {n} issue",
            "dateAdded": "2099-01-01",
            "shortDescription": "Synthetic.",
            "requiredAction": "Apply updates.",
            "dueDate": "2099-01-22",
            "knownRansomwareCampaignUse": "Unknown" if n % 7 else "Known",
            "notes": "",
            "cwes": ["CWE-78"],
        }
        for n in range(entries)
    ]
    document = {"catalogVersion": "2099.01.01", "dateReleased": "2099-01-01T00:00:00Z"}
    path.write_text(json.dumps({**document, "vulnerabilities": items}), encoding="utf-8")


def write_epss(path: Path, rows: int, shift: float = 0.0) -> None:
    lines = [
        "#model_version:v2099.01.01,score_date:2099-01-02T00:00:00+0000",
        "cve,epss,percentile",
    ]
    for n in range(rows):
        score = min(1.0, ((n * 7919) % 100000) / 100000 + shift)
        lines.append(f"CVE-2099-{100000 + n},{score:.5f},{min(1.0, n / rows):.5f}")
    path.write_bytes(gzip.compress(("\n".join(lines) + "\n").encode()))


def ioc_document(count: int) -> bytes:
    indicators: list[dict[str, Any]] = []
    for n in range(count):
        kind = n % 10
        if kind < 6:
            # 198.18.0.0/15 (pruebas de rendimiento, RFC 2544): nunca son IPs reales.
            item = {
                "type": "ipv4",
                "value": f"198.{18 + (n >> 16) % 2}.{(n >> 8) % 256}.{n % 256}",
            }
        elif kind == 6:
            item = {"type": "cidr", "value": f"198.19.{n % 256}.0/24"}
        elif kind < 9:
            item = {"type": "domain", "value": f"perf-{n}.example.net"}
        else:
            item = {"type": "sha256", "value": f"{n:064x}"}
        item["classification"] = ("malicious", "suspicious", "unknown")[n % 3]
        item["confidence"] = ("high", "medium", "low")[n % 3]
        indicators.append(item)
    return json.dumps({"format": "sentra-ioc/1", "indicators": indicators}).encode()


def seed_assets(session: Session, assets: int, events: int) -> None:
    """Activos con agente, conexiones establecidas en el inventario y eventos 4625 con IP."""
    now = datetime.now(UTC)
    session.execute(
        text(
            """
            INSERT INTO assets (public_id, agent_id, monitoring_method, hostname, os_name,
                os_version, primary_ip, status, first_seen_at, last_seen_at, created_at,
                updated_at, criticality)
            SELECT gen_random_uuid(), gen_random_uuid(), 'agent', :prefix || lpad(g::text, 5, '0'),
                'Windows', '11', '10.251.' || (g / 250) || '.' || (g % 250 + 1), 'online',
                :now, :now, :now, :now, 'medium'::asset_criticality
            FROM generate_series(1, :n) AS g
            """
        ),
        {"prefix": PREFIX, "now": now, "n": assets},
    )
    session.execute(
        text(
            """
            INSERT INTO asset_inventories (asset_id, collected_at, received_at, data)
            SELECT a.id, :now, :now, jsonb_build_object('connections', (
                SELECT jsonb_agg(jsonb_build_object(
                    'protocol', 'tcp', 'status', 'established',
                    'local_address', a.primary_ip, 'local_port', 50000 + k,
                    'remote_address', '198.18.' || ((a.id + k) % 256) || '.' || (k * 13 % 256),
                    'remote_port', 443))
                FROM generate_series(1, 20) AS k))
            FROM assets a WHERE a.hostname LIKE :like
            """
        ),
        {"now": now, "like": f"{PREFIX}%"},
    )
    session.execute(
        text(
            """
            INSERT INTO system_events (public_id, asset_id, source, channel, record_id,
                event_code, provider, level, message, data, occurred_at, received_at)
            SELECT gen_random_uuid(), a.id, 'windows_eventlog', 'Security', g, 4625,
                'Microsoft-Windows-Security-Auditing', 'warning', 'failed logon',
                jsonb_build_object('IpAddress', '198.18.' || (g % 256) || '.' || (g / 256 % 256),
                                   'LogonType', '3', 'TargetUserName', 'perf'),
                :now - (g || ' seconds')::interval, :now
            FROM generate_series(1, :events) AS g
            JOIN LATERAL (SELECT id FROM assets WHERE hostname LIKE :like
                          ORDER BY id OFFSET (g % :assets) LIMIT 1) a ON true
            """
        ),
        {"now": now, "like": f"{PREFIX}%", "events": events, "assets": assets},
    )
    session.commit()


def cleanup(session: Session) -> None:
    ids = list(session.scalars(select(Asset.id).where(Asset.hostname.like(f"{PREFIX}%"))))
    if ids:
        # ON DELETE CASCADE: eventos, inventario, coincidencias y riesgo de esos activos.
        session.execute(delete(Asset).where(Asset.id.in_(ids)))
    sources = list(
        session.scalars(
            select(ThreatIntelSource.id).where(ThreatIntelSource.source_key.like(f"{PREFIX}%"))
        )
    )
    if sources:
        indicators = select(ThreatIndicator.id).where(ThreatIndicator.source_id.in_(sources))
        session.execute(
            delete(ThreatIntelMatch).where(ThreatIntelMatch.indicator_id.in_(indicators))
        )
        session.execute(delete(ThreatIntelChange).where(ThreatIntelChange.source_id.in_(sources)))
        session.execute(delete(ThreatIndicator).where(ThreatIndicator.source_id.in_(sources)))
        session.execute(delete(VulnerabilityIntel).where(VulnerabilityIntel.source_id.in_(sources)))
        session.execute(delete(ThreatIntelSync).where(ThreatIntelSync.source_id.in_(sources)))
        session.execute(delete(ThreatIntelSource).where(ThreatIntelSource.id.in_(sources)))
    session.execute(text("DELETE FROM threat_intel_cursors"))
    session.commit()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--indicators", type=int, default=100_000)
    parser.add_argument("--kev", type=int, default=2_000)
    parser.add_argument("--epss", type=int, default=300_000)
    parser.add_argument("--assets", type=int, default=2_000)
    parser.add_argument("--events", type=int, default=50_000)
    args = parser.parse_args()

    settings = get_settings()
    if settings.is_production:
        print("refusing to run against a production configuration", file=sys.stderr)
        return 2
    config = ThreatIntelConfig.from_settings(settings)
    engine = get_engine()
    factory = get_sessionmaker()
    report: list[tuple[str, str]] = []

    with factory() as session:
        cleanup(session)
        ids = create_sources(session)
    try:
        with tempfile.TemporaryDirectory() as tmp:
            kev_file, epss_file, epss_next = (
                Path(tmp) / "kev.json",
                Path(tmp) / "epss.csv.gz",
                Path(tmp) / "epss2.csv.gz",
            )
            write_kev(kev_file, args.kev)
            write_epss(epss_file, args.epss)
            write_epss(epss_next, args.epss, shift=0.2)
            with factory() as session:
                syncer = ThreatIntelSyncer(session, config, lock_engine=get_engine)
                for label, key, path in (
                    (f"KEV import ({args.kev})", "perf-ti-kev", kev_file),
                    (
                        f"EPSS import ({args.epss} rows, gzip)",
                        "perf-ti-epss",
                        epss_file,
                    ),
                    ("EPSS reimport (identical)", "perf-ti-epss", epss_file),
                    ("EPSS next day (material changes)", "perf-ti-epss", epss_next),
                ):
                    start = time.perf_counter()
                    outcome = syncer.import_feed_file(ids[key], path, audit_service.CLI)
                    seconds = time.perf_counter() - start
                    report.append((label, f"{seconds:.2f} s ({outcome.status}, {outcome.counts})"))

        raw = ioc_document(args.indicators)
        with factory() as session:
            syncer = ThreatIntelSyncer(session, config, lock_engine=get_engine)
            start = time.perf_counter()
            preview = syncer.preview_import(ids["perf-ti-iocs"], "sentra-ioc", raw)
            report.append(
                (
                    f"IOC preview ({args.indicators})",
                    f"{time.perf_counter() - start:.2f} s",
                )
            )
            start = time.perf_counter()
            result = syncer.import_indicators(
                ids["perf-ti-iocs"],
                "sentra-ioc",
                raw,
                audit_service.CLI,
                expected_sha256=preview.sha256,
                skip_invalid=True,
                trigger="cli",
            )
            session.commit()
            report.append(
                (
                    f"IOC import ({args.indicators}, {len(raw) // 1024} KiB)",
                    f"{time.perf_counter() - start:.2f} s ({result.new} new)",
                )
            )

        with factory() as session:
            seed_assets(session, args.assets, args.events)
        with factory() as session:
            matcher = ThreatIntelMatcher(session, config)
            start = time.perf_counter()
            totals = {"created": 0, "retro": 0}
            # Varias vueltas: el retroactivo va por lotes acotados, como en el job.
            for _ in range(200):
                run = matcher.run()
                totals["created"] += run.created
                totals["retro"] += run.retro_indicators
                if run.retro_indicators == 0 and run.events == 0 and run.inventories == 0:
                    break
            report.append(
                (
                    f"matching retro ({args.assets} assets, {args.events} events)",
                    f"{time.perf_counter() - start:.2f} s ({totals['created']} matches)",
                )
            )
            ms, _ = timed(lambda: matcher.run(datetime.now(UTC) + timedelta(seconds=1)), repeat=3)
            report.append(("matching incremental (no new data)", f"{ms:.0f} ms"))

        with factory() as session:
            service = ThreatIntelService(session, config)
            cves = [f"CVE-2099-{100000 + n}" for n in range(50_000)]
            reads: list[tuple[str, Callable[[], Any]]] = [
                ("overview", service.overview),
                (
                    "indicators (malicious, page 1)",
                    lambda: service.indicators(
                        IndicatorFilter(classification="malicious"),
                        "retrieved_at",
                        True,
                        50,
                        0,
                    ),
                ),
                (
                    "indicators (prefix 198.18.1)",
                    lambda: service.indicators(
                        IndicatorFilter(search="198.18.1"), "retrieved_at", True, 50, 0
                    ),
                ),
                (
                    "matches (active, page 1)",
                    lambda: service.matches(
                        MatchFilter(active=True), "last_observed_at", True, 50, 0
                    ),
                ),
                (
                    "exploitation for 50 000 CVE",
                    lambda: load_exploitation(session, cves, datetime.now(UTC)),
                ),
            ]
            for label, fn in reads:
                with count_statements(engine) as statements:
                    ms, _ = timed(fn)
                report.append((label, f"{ms:.0f} ms, {len(statements) // 5} SQL/request"))
    finally:
        with factory() as session:
            cleanup(session)

    width = max(len(label) for label, _ in report)
    for label, value in report:
        print(f"{label.ljust(width)}  {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
