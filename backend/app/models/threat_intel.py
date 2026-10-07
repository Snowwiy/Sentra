"""Threat Intelligence & Exploitability Context (Fase 5C). Ver docs/threat-intelligence.md.

La inteligencia de amenazas es CONTEXTO EXTERNO, nunca evidencia local. Cada concepto vive
en su tabla y no se mezcla con lo que Sentra observa:
- fuente (threat_intel_sources): de dónde viene la inteligencia, su confianza (trust),
  cuándo se sincronizó por última vez con éxito y si está caducada (stale). Se archivan,
  nunca se borran: hay matches e historial que las referencian;
- inteligencia de vulnerabilidades (vulnerability_intel): una observación por (fuente,
  tipo, CVE). CISA KEV ("explotación conocida según CISA") y FIRST EPSS ("probabilidad de
  explotación") enriquecen los findings 5B por CVE; no cambian su match técnico;
- indicador (threat_indicators): IOC normalizado de una fuente con su clasificación y
  confianza TAL CUAL la declara la fuente. Estar en el catálogo no afecta a ningún activo;
- match (threat_intel_matches): coincidencia EXACTA entre un indicador y un dato que Sentra
  YA tenía (evento, conexión del inventario, dirección o nombre del activo). Es lo único que
  relaciona inteligencia con un activo, y aun así no afirma un compromiso;
- cambios (threat_intel_changes): historial acotado de cambios materiales (alta o baja en
  KEV, salto de EPSS, revocación de un IOC). No es una copia de cada descarga.

Dos fuentes que discrepan conviven en filas separadas: nunca se sobrescriben entre sí.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import CIDR, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class ThreatIntelSource(Base):
    __tablename__ = "threat_intel_sources"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    # Identificador estable dentro de Sentra ("cisa-kev", "first-epss", "lab-iocs").
    source_key: Mapped[str] = mapped_column(String(64), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(String(500))
    # Adapter que la sincroniza o importa (app/threat_intel/providers.py).
    provider: Mapped[str] = mapped_column(String(32))
    # vulnerability | ioc | advisory | exploitation | reputation | campaign | other.
    category: Mapped[str] = mapped_column(String(16))
    # official | trusted | community | local. Solo display, confianza y prioridad: nunca
    # decide qué fuente "tiene razón" ni borra discrepancias.
    trust: Mapped[str] = mapped_column(String(16))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # True si el adapter descarga por red (KEV, EPSS). Las fuentes locales solo importan.
    network_required: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    # Intervalo de sincronización y caducidad esperada. Null en fuentes manuales: una fuente
    # local no caduca sola (no hay "próxima sincronización" que se pueda perder).
    sync_interval_hours: Mapped[int | None] = mapped_column(Integer)
    stale_after_hours: Mapped[int | None] = mapped_column(Integer)
    # never | ok | error | unavailable | syncing (resultado del último intento).
    status: Mapped[str] = mapped_column(String(16), default="never", server_default="never")
    last_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_success_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Código y texto acotado del último error: nunca URLs con credenciales ni el contenido.
    last_error: Mapped[str | None] = mapped_column(String(64))
    last_error_message: Mapped[str | None] = mapped_column(String(300))
    record_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Peticiones condicionales (ETag / If-Modified-Since) y huella del último contenido.
    etag: Mapped[str | None] = mapped_column(String(256))
    last_modified: Mapped[str | None] = mapped_column(String(64))
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    next_sync_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # "Sincronizar ahora": la API solo lo marca; el job lo ejecuta (nunca dentro de la
    # petición: una descarga lenta no bloquea un worker de la API).
    sync_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sync_requested_by: Mapped[str | None] = mapped_column(String(64))
    # Opciones NO secretas del adapter. Los secretos de fuentes autenticadas futuras irían en
    # variables de entorno o ficheros del servidor, nunca aquí (la API devuelve esta fila).
    config: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    revision: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    archived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ThreatIntelSync(Base):
    """Historial técnico de sincronizaciones e importaciones (separado de la auditoría)."""

    __tablename__ = "threat_intel_syncs"
    __table_args__ = (Index("ix_threat_intel_syncs_source", "source_id", "started_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("threat_intel_sources.id"))
    # sync (descarga del adapter) | import (fichero local).
    kind: Mapped[str] = mapped_column(String(8))
    # scheduled | manual | api | cli.
    trigger: Mapped[str] = mapped_column(String(16))
    # running | success | not_modified | failed.
    status: Mapped[str] = mapped_column(String(16))
    actor: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
    records_seen: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_new: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_updated: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_unchanged: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_removed: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    records_invalid: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    content_sha256: Mapped[str | None] = mapped_column(String(64))
    error_code: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(String(300))


class VulnerabilityIntel(Base):
    """Inteligencia de explotabilidad de un CVE según UNA fuente (KEV o EPSS)."""

    __tablename__ = "vulnerability_intel"
    __table_args__ = (
        UniqueConstraint("source_id", "kind", "cve_id", name="uq_vulnerability_intel_record"),
        # Enriquecimiento de findings y filtros: siempre por CVE.
        Index("ix_vulnerability_intel_cve", "cve_id"),
        # "EPSS alto" del resumen y del filtro por umbral.
        Index(
            "ix_vulnerability_intel_epss",
            "epss_score",
            postgresql_where=text("kind = 'epss' AND active"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("threat_intel_sources.id"))
    # kev | epss.
    kind: Mapped[str] = mapped_column(String(8))
    cve_id: Mapped[str] = mapped_column(String(32))
    # Presente en el último estado de la fuente. Un CVE que desaparece del feed se marca
    # inactive (con removed_at), nunca se borra: el historial lo explica.
    active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    # Solo EPSS: probabilidad (0-1) de explotación en 30 días según el modelo de FIRST y su
    # percentil. NO es severidad ni probabilidad de que el activo esté comprometido.
    epss_score: Mapped[float | None] = mapped_column(Float)
    epss_percentile: Mapped[float | None] = mapped_column(Float)
    # Campos propios del tipo (KEV: dateAdded, dueDate, requiredAction, knownRansomware...;
    # EPSS: model_version, score_date, previous). Texto de la fuente: dato no confiable.
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    # Procedencia.
    external_id: Mapped[str | None] = mapped_column(String(64))
    source_url: Mapped[str | None] = mapped_column(String(500))
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    content_hash: Mapped[str] = mapped_column(String(64))
    record_version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")


class ThreatIndicator(Base):
    """Indicador (IOC) normalizado de una fuente."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        # La misma fuente no duplica un indicador; dos fuentes sí pueden tenerlo (conflictos).
        UniqueConstraint(
            "source_id", "indicator_type", "value_normalized", name="uq_threat_indicator"
        ),
        # Matching exacto y búsqueda por prefijo con el mismo índice (text_pattern_ops sirve
        # para = y LIKE 'abc%'). Nunca un bucle de indicadores en Python.
        Index(
            "ix_threat_indicators_value",
            "value_normalized",
            postgresql_ops={"value_normalized": "text_pattern_ops"},
        ),
        Index("ix_threat_indicators_type", "indicator_type", "id"),
        Index("ix_threat_indicators_source", "source_id", "id"),
        # CIDR: "¿qué red contiene esta IP?" (operador >>=) con GiST, no comparando en Python.
        Index(
            "ix_threat_indicators_network",
            "network",
            postgresql_using="gist",
            postgresql_ops={"network": "inet_ops"},
            postgresql_where=text("network IS NOT NULL"),
        ),
        # Cola del matching retroactivo (indicadores nuevos o cambiados).
        Index(
            "ix_threat_indicators_pending",
            "id",
            postgresql_where=text("pending_match"),
        ),
        Index("ix_threat_indicators_tags", "tags", postgresql_using="gin"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    source_id: Mapped[int] = mapped_column(ForeignKey("threat_intel_sources.id"))
    # ipv4 | ipv6 | cidr | domain | hostname | url | sha256 | sha1 | md5 | email.
    indicator_type: Mapped[str] = mapped_column(String(16))
    # Valor canónico (ver app/threat_intel/indicators.py): ASCII y como mucho 1024 caracteres.
    value_normalized: Mapped[str] = mapped_column(String(1024))
    # Valor tal como llegó (acotado), para mostrarlo sin perder la forma original.
    value_original: Mapped[str] = mapped_column(String(2048))
    # Solo indicadores cidr.
    network: Mapped[str | None] = mapped_column(CIDR)
    # malicious | suspicious | benign | unknown: lo que DECLARA la fuente o la importación.
    classification: Mapped[str] = mapped_column(String(16))
    # low | medium | high, más el valor numérico original (STIX 0-100) si existía.
    confidence: Mapped[str] = mapped_column(String(8))
    confidence_score: Mapped[int | None] = mapped_column(SmallInteger)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    first_seen_external: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_external: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    description: Mapped[str | None] = mapped_column(String(1000))
    # Solo URLs http/https validadas. Metadatos: Sentra nunca las abre.
    references: Mapped[list[str]] = mapped_column(JSONB, default=list, server_default="[]")
    # Contexto STIX opcional: [{"type": "malware", "name": "..."}]. Sin grafo.
    related: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")
    external_id: Mapped[str | None] = mapped_column(String(128))
    # Patrón STIX original (solo para mostrarlo; nunca se ejecuta).
    pattern: Mapped[str | None] = mapped_column(String(1024))
    content_hash: Mapped[str] = mapped_column(String(64))
    # Pendiente de buscar en datos locales ya existentes (matching retroactivo).
    pending_match: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    match_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ThreatIntelMatch(Base):
    """Un indicador visto en datos LOCALES de un activo (coincidencia exacta)."""

    __tablename__ = "threat_intel_matches"
    __table_args__ = (
        # Deduplicación: el mismo indicador, activo, tipo de observación y valor es UN match
        # (las repeticiones suben observation_count y last_observed_at).
        UniqueConstraint(
            "indicator_id",
            "asset_id",
            "observation_type",
            "observed_value",
            name="uq_threat_intel_match",
        ),
        Index("ix_threat_intel_matches_asset", "asset_id", "last_observed_at"),
        Index("ix_threat_intel_matches_status", "status", "last_observed_at"),
        Index("ix_threat_intel_matches_last_observed", "last_observed_at", "id"),
        Index(
            "ix_threat_intel_matches_detection",
            "detection_id",
            postgresql_where=text("detection_id IS NOT NULL"),
        ),
        Index(
            "ix_threat_intel_matches_event",
            "event_id",
            postgresql_where=text("event_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    indicator_id: Mapped[int] = mapped_column(ForeignKey("threat_indicators.id"))
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    # auth_source_ip | connection_remote_ip | asset_address | asset_name.
    observation_type: Mapped[str] = mapped_column(String(24))
    observed_value: Mapped[str] = mapped_column(String(1024))
    # Campo local que lo contenía ("system_events.data.IpAddress", ...).
    observed_field: Mapped[str] = mapped_column(String(64))
    # Evento concreto (si lo hay). SET NULL si la retención lo purga: el match conserva su
    # id público y los datos mínimos en `evidence`.
    event_id: Mapped[int | None] = mapped_column(
        ForeignKey("system_events.id", ondelete="SET NULL")
    )
    event_public_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    detection_id: Mapped[int | None] = mapped_column(
        ForeignKey("detections.id", ondelete="SET NULL")
    )
    first_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observation_count: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # Copia de la clasificación/confianza del indicador y de la fuente al casar (la fuente
    # puede cambiarlas después; el match explica lo que se sabía entonces).
    classification: Mapped[str] = mapped_column(String(16))
    indicator_confidence: Mapped[str] = mapped_column(String(8))
    source_trust: Mapped[str] = mapped_column(String(16))
    # Confianza del match: la del indicador, rebajada para coincidencias de red (CIDR) o de
    # visibilidad parcial (nombres de activo).
    match_confidence: Mapped[str] = mapped_column(String(8))
    # open | acknowledged | dismissed (falso positivo: no aporta riesgo).
    status: Mapped[str] = mapped_column(String(16), default="open", server_default="open")
    status_reason: Mapped[str | None] = mapped_column(String(1000))
    status_changed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_changed_by: Mapped[str] = mapped_column(String(64))
    # Última señal enviada al motor de detección (deduplicación con cooldown).
    signal_emitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Datos mínimos y acotados de la observación (puerto, proceso, tipo de logon...).
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB)
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    matched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class ThreatIntelChange(Base):
    """Cambio material de la inteligencia (solo se añaden filas; acotado en el tiempo)."""

    __tablename__ = "threat_intel_changes"
    __table_args__ = (
        Index("ix_threat_intel_changes_occurred", "occurred_at", "id"),
        # Borrar o archivar una fuente y "cambios de esta sincronización" sin barrer la tabla.
        Index("ix_threat_intel_changes_source", "source_id", "occurred_at"),
        Index(
            "ix_threat_intel_changes_sync",
            "sync_id",
            postgresql_where=text("sync_id IS NOT NULL"),
        ),
        Index(
            "ix_threat_intel_changes_cve",
            "cve_id",
            "occurred_at",
            postgresql_where=text("cve_id IS NOT NULL"),
        ),
        Index(
            "ix_threat_intel_changes_indicator",
            "indicator_id",
            postgresql_where=text("indicator_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    source_id: Mapped[int] = mapped_column(ForeignKey("threat_intel_sources.id"))
    sync_id: Mapped[int | None] = mapped_column(
        ForeignKey("threat_intel_syncs.id", ondelete="SET NULL")
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # vulnerability | indicator.
    record_kind: Mapped[str] = mapped_column(String(16))
    cve_id: Mapped[str | None] = mapped_column(String(32))
    indicator_id: Mapped[int | None] = mapped_column(
        ForeignKey("threat_indicators.id", ondelete="SET NULL")
    )
    # kev_added | kev_removed | kev_updated | epss_material_change | indicator_revoked...
    change: Mapped[str] = mapped_column(String(32))
    details: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class ThreatIntelCursor(Base):
    """Posición del matching incremental sobre datos locales (eventos, inventarios)."""

    __tablename__ = "threat_intel_cursors"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    position: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    position_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
