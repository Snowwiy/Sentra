"""Telemetría avanzada de endpoint y árbol de procesos (Fase 6E.3/6E.4).

- endpoint_activity: eventos que envía el agente 0.5.0 por POST /agents/activity (procesos,
  conexiones, servicios, tareas, persistencia, autenticación, protección, firewall, DNS).
  (asset_id, event_uid) es único: un reenvío del mismo lote es inocuo. `data` ya viene
  acotado y filtrado por el esquema de la categoría (app/endpoint/schema.py).
- process_instances: una fila por instancia de proceso. La clave es `instance_key`
  (sha256 de boot_id|pid|create_time_ms): un PID reutilizado tras un reinicio o tras terminar
  el proceso es OTRA instancia, así que el árbol nunca cuelga hijos del padre equivocado.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

ACTIVITY_CATEGORIES = (
    "process",
    "network",
    "service",
    "scheduled_task",
    "persistence",
    "auth",
    "dns",
    "protection",
    "firewall",
    "agent_health",
)
PARENT_RELATIONS = ("observed", "inferred", "missing", "pid_reused")


def _in(column: str, values: tuple[str, ...]) -> str:
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


class EndpointActivity(Base):
    __tablename__ = "endpoint_activity"
    __table_args__ = (
        UniqueConstraint("asset_id", "event_uid", name="uq_endpoint_activity_event"),
        Index("ix_endpoint_activity_asset_time", "asset_id", "occurred_at"),
        Index("ix_endpoint_activity_asset_category", "asset_id", "category", "occurred_at"),
        Index("ix_endpoint_activity_instance", "asset_id", "instance_key"),
        # Retención y métricas de latencia: barrido por fecha de recepción.
        Index("ix_endpoint_activity_received", "received_at"),
        CheckConstraint(_in("category", ACTIVITY_CATEGORIES), name="ck_endpoint_activity_category"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    event_uid: Mapped[uuid.UUID] = mapped_column(Uuid)
    boot_id: Mapped[str] = mapped_column(String(64))
    seq: Mapped[int] = mapped_column(BigInteger)
    category: Mapped[str] = mapped_column(String(24))
    action: Mapped[str] = mapped_column(String(24))
    source: Mapped[str] = mapped_column(String(24))
    instance_key: Mapped[str | None] = mapped_column(String(32))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ProcessInstance(Base):
    __tablename__ = "process_instances"
    __table_args__ = (
        UniqueConstraint("asset_id", "instance_key", name="uq_process_instances_key"),
        Index("ix_process_instances_parent", "asset_id", "parent_instance_key"),
        Index("ix_process_instances_started", "asset_id", "started_at"),
        Index("ix_process_instances_seen", "last_seen_at"),
        CheckConstraint(
            "parent_relation IS NULL OR " + _in("parent_relation", PARENT_RELATIONS),
            name="ck_process_instances_parent_relation",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    instance_key: Mapped[str] = mapped_column(String(32))
    boot_id: Mapped[str] = mapped_column(String(64))
    pid: Mapped[int] = mapped_column(Integer)
    ppid: Mapped[int | None] = mapped_column(Integer)
    parent_instance_key: Mapped[str | None] = mapped_column(String(32))
    # Cómo se supo el padre: observado (el agente vio al padre vivo con su create_time),
    # inferido (padre ya terminado pero conocido), ausente o PID reutilizado (el PID del
    # padre pertenece ya a otro proceso más nuevo que el hijo: no se enlaza).
    parent_relation: Mapped[str | None] = mapped_column(String(16))
    name: Mapped[str | None] = mapped_column(String(255))
    exe: Mapped[str | None] = mapped_column(String(1024))
    # Ya redactada según TELEMETRY_CMDLINE_POLICY (la más restrictiva entre agente y servidor).
    cmdline: Mapped[str | None] = mapped_column(Text)
    username: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str | None] = mapped_column(String(64))
    signer: Mapped[str | None] = mapped_column(String(255))
    integrity: Mapped[str | None] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(24))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


EXCLUSION_FIELDS = (
    "exe",
    "name",
    "sha256",
    "signer",
    "parent_name",
    "remote_address",
    # Fase 7A.8: ruta y hash del script de un 4104 (agente 0.6.0).
    "script_path",
    "script_sha256",
)


class DetectionExclusion(Base):
    """Fase 6E.5: excepción explícita de una regla para un valor concreto.

    Siempre la crea un admin con motivo, puede caducar y se revoca (no se borra), para que la
    auditoría muestre por qué una detección no se abrió. Compara el valor exacto de un campo
    de la señal (en minúsculas): nunca patrones, para no excluir más de lo que se ve.
    """

    __tablename__ = "detection_exclusions"
    __table_args__ = (
        Index("ix_detection_exclusions_rule", "rule_id"),
        Index("ix_detection_exclusions_asset", "asset_id"),
        CheckConstraint(_in("field", EXCLUSION_FIELDS), name="ck_detection_exclusions_field"),
        CheckConstraint(
            "require_sha256 IS NULL OR require_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_detection_exclusions_require_sha256",
        ),
        CheckConstraint(
            "port IS NULL OR port BETWEEN 1 AND 65535", name="ck_detection_exclusions_port"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    rule_id: Mapped[str] = mapped_column(String(64))
    # Null = en todos los activos.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    field: Mapped[str] = mapped_column(String(16))
    value: Mapped[str] = mapped_column(String(1024))
    reason: Mapped[str] = mapped_column(String(500))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[str | None] = mapped_column(String(64))
    # Cuántas veces evitó una detección (lo actualiza el motor) y la última.
    hits: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Fase 7A.8: condiciones adicionales que también deben cumplirse. `require_sha256` ata
    # una excepción de ruta a un contenido concreto (si el fichero cambia, la detección
    # vuelve); `port` limita una excepción de proceso a un puerto.
    require_sha256: Mapped[str | None] = mapped_column(String(64))
    port: Mapped[int | None] = mapped_column(Integer)
