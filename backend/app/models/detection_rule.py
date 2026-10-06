"""Reglas de detección personalizadas y Sigma (Fase 5A). Ver docs/custom-detection-rules.md.

Las reglas built-in siguen en código (app/detection/rules.py). Aquí solo viven las reglas
que crea un administrador o que se importan desde Sigma:

- DetectionRuleRecord: estado administrativo actual de la regla (draft/active/disabled/
  retired), su versión vigente y una copia de los campos de filtrado del listado;
- DetectionRuleVersion: cada versión completa e inmutable (definición, textos, MITRE, YAML
  Sigma original). Una detección guarda (rule_id, rule_version) y su explicación sale de aquí
  aunque la regla cambie o se retire después;
- DetectionRuleStats: contadores del motor por regla (también las built-in), en tabla
  aparte para que el motor no toque la fila de la regla ni su `revision` en cada lote;
- DetectionRuleMatch: estado temporal de las reglas con umbral (count/ventana), purgado con
  las señales. Permite contar coincidencias por grupo sin reevaluar la ventana entera.

La base de datos es la fuente de verdad: cada worker recarga su caché de reglas al cambiar
la huella de esta tabla (app/detection/custom/runtime.py), sin Redis ni estado de proceso.
"""

import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
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
from app.models.detection import DetectionConfidence, DetectionSeverity, _enum


class RuleSource(enum.StrEnum):
    BUILTIN = "builtin"
    CUSTOM = "custom"
    SIGMA = "sigma"


class RuleStatus(enum.StrEnum):
    """Estado administrativo, separado del resultado de compilación (CompileStatus)."""

    # Creada o importada, nunca activada. Las importaciones Sigma siempre empiezan aquí.
    DRAFT = "draft"
    # Se evalúa en el motor.
    ACTIVE = "active"
    DISABLED = "disabled"
    # Retirada: no se evalúa y no se puede activar sin "unretire" explícito. Nunca se borra
    # para que las detecciones históricas sigan siendo explicables.
    RETIRED = "retired"


class CompileStatus(enum.StrEnum):
    VALID = "valid"
    # Compila, pero Sentra solo cubre parte de lo que la regla pretende (p. ej. Sigma
    # process_creation sobre snapshots de procesos). Activarla exige confirmación explícita.
    PARTIAL = "partial"
    # Usa campos, logsources o construcciones que Sentra no evalúa: nunca se activa.
    UNSUPPORTED = "unsupported"
    # Definición rota (solo posible si una versión futura del catálogo deja de aceptarla).
    INVALID = "invalid"


class DetectionRuleRecord(Base):
    __tablename__ = "detection_rules"
    __table_args__ = (
        Index("ix_detection_rules_status", "status"),
        Index("ix_detection_rules_updated", "updated_at"),
        Index("ix_detection_rules_logsource", "logsource"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Identificador estable (SENTRA-CUSTOM-000001, SENTRA-SIGMA-000002). Nunca el título.
    # Cabe en detections.rule_id (32): por eso el `id` de Sigma va aparte (sigma_id).
    rule_uid: Mapped[str] = mapped_column(String(32), unique=True)
    source: Mapped[str] = mapped_column(String(16))
    # `id` de la regla Sigma original (UUID): detecta reimportaciones de la misma regla.
    sigma_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, unique=True)

    status: Mapped[str] = mapped_column(String(16))
    compile_status: Mapped[str] = mapped_column(String(16))
    current_version: Mapped[int] = mapped_column(Integer)
    # Concurrencia optimista: sube con CADA cambio (versión, activar, desactivar, retirar).
    # Una edición con una revisión obsoleta recibe 409 en vez de pisar la de otro admin.
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")

    # Copia de la versión vigente para filtrar y ordenar el listado sin leer versiones.
    title: Mapped[str] = mapped_column(String(200))
    logsource: Mapped[str] = mapped_column(String(32))
    severity: Mapped[DetectionSeverity] = mapped_column(
        _enum(DetectionSeverity, "detection_severity")
    )
    confidence: Mapped[DetectionConfidence] = mapped_column(
        _enum(DetectionConfidence, "detection_confidence")
    )
    category: Mapped[str] = mapped_column(String(32))
    mitre_technique: Mapped[str | None] = mapped_column(String(16))

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_by: Mapped[str] = mapped_column(String(64))
    last_compiled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @property
    def enabled(self) -> bool:
        return self.status == RuleStatus.ACTIVE


class DetectionRuleVersion(Base):
    """Una versión completa e inmutable de una regla. Nunca se actualiza ni se borra."""

    __tablename__ = "detection_rule_versions"
    __table_args__ = (UniqueConstraint("rule_id", "version", name="uq_detection_rule_version"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64))
    # Motivo del cambio ("created", "updated", "restored from v1", "sigma import").
    change_note: Mapped[str] = mapped_column(String(200))

    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(2000))
    why: Mapped[str] = mapped_column(String(1000))
    recommendations: Mapped[list[str]] = mapped_column(JSONB)
    severity: Mapped[DetectionSeverity] = mapped_column(
        _enum(DetectionSeverity, "detection_severity")
    )
    confidence: Mapped[DetectionConfidence] = mapped_column(
        _enum(DetectionConfidence, "detection_confidence")
    )
    category: Mapped[str] = mapped_column(String(32))
    mitre_tactic: Mapped[str | None] = mapped_column(String(16))
    mitre_technique: Mapped[str | None] = mapped_column(String(16))
    mitre_subtechnique: Mapped[str | None] = mapped_column(String(16))
    tags: Mapped[list[str]] = mapped_column(JSONB)

    # Definición declarativa normalizada (formato sentra-rule/1). Es DATO: se valida y se
    # compila a predicados en memoria; nunca se ejecuta como código.
    definition: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Resumen de la compilación (campos usados, complejidad, avisos). Informativo: el motor
    # siempre recompila desde `definition`, nunca confía en este JSON.
    compiled: Mapped[dict[str, Any]] = mapped_column(JSONB)
    compile_status: Mapped[str] = mapped_column(String(16))
    # Motivos de unsupported/partial e incidencias de compilación (lista de {code, message}).
    compile_issues: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    # Hash del contenido funcional: detecta reimportaciones idénticas y ediciones sin cambios.
    content_hash: Mapped[str] = mapped_column(String(64))

    # Solo Sigma: YAML original tal cual (texto; nunca se interpreta fuera del parser seguro)
    # y metadatos Sigma (autor, referencias, status...), tratados como datos no confiables.
    sigma_yaml: Mapped[str | None] = mapped_column(Text)
    sigma_metadata: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class DetectionRuleStats(Base):
    """Contadores del motor por regla (built-in o custom), acumulados por lote."""

    __tablename__ = "detection_rule_stats"

    # Sin FK: también cubre reglas built-in (que no tienen fila en detection_rules).
    rule_uid: Mapped[str] = mapped_column(String(32), primary_key=True)
    evaluations: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    matches: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    errors: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    # Errores seguidos sin una evaluación correcta: indica una regla rota de forma
    # persistente (se muestra en la UI; ver por qué no se desactiva sola en la doc).
    consecutive_errors: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    slow_evaluations: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    eval_time_us: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    last_evaluated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Categoría del error (nombre de la excepción), nunca datos del evento.
    last_error: Mapped[str | None] = mapped_column(String(200))


class DetectionRuleMatch(Base):
    """Coincidencia de una regla con umbral: base del conteo por grupo y ventana."""

    __tablename__ = "detection_rule_matches"
    __table_args__ = (
        # Reevaluar una señal (DetectionEngine.reevaluate) no cuenta dos veces.
        UniqueConstraint("rule_id", "rule_version", "signal_id", name="uq_rule_match_signal"),
        # Conteo del umbral: siempre por regla, versión, activo, grupo y ventana.
        Index(
            "ix_rule_matches_window",
            "rule_id",
            "rule_version",
            "asset_id",
            "group_key",
            "occurred_at",
        ),
        Index("ix_rule_matches_created", "created_at"),
        # FK hacia assets (ON DELETE CASCADE al borrar un activo).
        Index("ix_rule_matches_asset", "asset_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    rule_id: Mapped[int] = mapped_column(ForeignKey("detection_rules.id", ondelete="CASCADE"))
    rule_version: Mapped[int] = mapped_column(Integer)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    group_key: Mapped[str] = mapped_column(String(255))
    # Sin FK: la señal se purga con su retención; esta fila también.
    signal_id: Mapped[int] = mapped_column(BigInteger)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
