"""Informe de capacidad y retención, de solo lectura (Fase 7D.2, H06).

Responde a "¿cuánto ocupa cada histórico, desde cuándo, y qué borraría la retención
configurada?" sin borrar nada. Sirve para decidir los plazos de retención con datos reales
antes de activarlos (la mayoría están desactivados por defecto: borrar historial de
monitorización es decisión del operador).

Por defecto solo usa estadísticas del catálogo de PostgreSQL (tamaño en disco y filas
estimadas), que no recorren las tablas. Con `exact=True` calcula además la fila más antigua y
cuántas filas superan la retención: consultas de solo lectura que pueden recorrer tablas
grandes, para ejecutar fuera de horas punta.
"""

from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.core.config import Settings


@dataclass(frozen=True)
class RetainedTable:
    table: str
    # Columna de antigüedad que usa la purga (None: tabla sin retención por antigüedad).
    column: str | None
    # Ajuste que fija la retención (None: sin ajuste, crece o se acota por otra vía).
    setting: str | None
    # Condición adicional de la purga (p. ej. solo alertas resueltas). Texto fijo del código.
    condition: str | None = None
    note: str = ""


# Lista fija: los nombres de tabla y columna nunca vienen de la entrada del usuario.
TABLES: tuple[RetainedTable, ...] = (
    RetainedTable("telemetry_samples", "recorded_at", "telemetry_retention_days"),
    RetainedTable("system_events", "occurred_at", "event_retention_days"),
    RetainedTable("asset_changes", "detected_at", "change_retention_days"),
    RetainedTable(
        "alerts", "resolved_at", "alert_retention_days", "status = 'resolved'", "solo resueltas"
    ),
    RetainedTable(
        "detections",
        "resolved_at",
        "detection_retention_days",
        "status = 'resolved'",
        "solo resueltas, con su evidencia",
    ),
    RetainedTable("risk_snapshots", "calculated_at", "risk_history_retention_days"),
    RetainedTable("discovery_observations", "observed_at", "discovery_observation_retention_days"),
    RetainedTable("endpoint_activity", "received_at", "telemetry_activity_retention_days"),
    RetainedTable(
        "tool_executions",
        "created_at",
        "analyst_tools_retention_days",
        note="nunca las vinculadas a un caso",
    ),
    RetainedTable("reports", "created_at", "report_retention_days"),
    RetainedTable("audit_events", "created_at", None, note="sin retención automática"),
    RetainedTable("rate_limit_hits", None, None, note="efímera: se purga sola por ventana"),
    RetainedTable("ingest_quota_buckets", None, None, note="efímera: cubos sin uso en 1 día"),
)


@dataclass
class TableCapacity:
    table: str
    total_bytes: int
    estimated_rows: int
    retention_setting: str | None
    retention_days: int | None
    note: str
    oldest_at: str | None = None
    rows_beyond_retention: int | None = None


def capacity_report(session: Session, settings: Settings, exact: bool = False) -> dict[str, Any]:
    now = datetime.now(UTC)
    items: list[TableCapacity] = []
    for spec in TABLES:
        exists = session.execute(
            text("SELECT to_regclass(:name) IS NOT NULL"), {"name": spec.table}
        ).scalar_one()
        if not exists:
            continue
        size, rows = session.execute(
            text(
                "SELECT pg_total_relation_size(c.oid), GREATEST(c.reltuples, 0)::bigint"
                " FROM pg_class c WHERE c.oid = to_regclass(:name)"
            ),
            {"name": spec.table},
        ).one()
        days = getattr(settings, spec.setting) if spec.setting else None
        item = TableCapacity(
            table=spec.table,
            total_bytes=int(size),
            estimated_rows=int(rows),
            retention_setting=spec.setting.upper() if spec.setting else None,
            retention_days=days,
            note=spec.note,
        )
        if exact and spec.column is not None:
            # Identificadores de la lista fija de arriba, nunca de la entrada.
            where = f" WHERE {spec.condition}" if spec.condition else ""
            oldest = session.execute(
                text(f"SELECT min({spec.column}) FROM {spec.table}{where}")  # noqa: S608
            ).scalar()
            item.oldest_at = oldest.isoformat() if oldest is not None else None
            if days is not None:
                extra = f" AND {spec.condition}" if spec.condition else ""
                item.rows_beyond_retention = int(
                    session.execute(
                        text(
                            f"SELECT count(*) FROM {spec.table}"  # noqa: S608
                            f" WHERE {spec.column} < :cutoff{extra}"
                        ),
                        {"cutoff": now - timedelta(days=days)},
                    ).scalar_one()
                )
        items.append(item)
    database_bytes = session.execute(
        text("SELECT pg_database_size(current_database())")
    ).scalar_one()
    # Solo lectura: nada que confirmar, pero se cierra la transacción explícitamente.
    session.rollback()
    return {
        "generated_at": now.isoformat(),
        "exact": exact,
        "database_bytes": int(database_bytes),
        "tables": [asdict(item) for item in items],
    }
