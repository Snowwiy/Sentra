"""Motor de topología de red (Fase 6D, docs/topology-engine.md).

Principios del modelo:

- Los nodos NO se guardan: son referencias al inventario existente (activos, equipos de red,
  puntos de acceso WLAN) o identidades remotas sin resolver ("external", p. ej. un vecino LLDP
  que no es ningún activo conocido). Así la topología nunca duplica el inventario de Sentra:
  el nombre, el riesgo o la etiqueta de un nodo se leen siempre del activo.
- Lo único persistente son los ENLACES derivados de evidencia verificable, cada uno con su
  clase (physical, logical, observed, candidate, unknown), su confianza y su evidencia
  acotada. Compartir subred o gateway nunca crea un enlace físico.
- Todo pertenece a un site: los dos extremos de un enlace son del mismo site que el enlace
  (lo garantiza el constructor); una MAC o una IP privada repetidas en dos sites no se cruzan.
- Sin borrados por ausencia: un enlace que deja de derivarse en una reconstrucción queda con
  present=false y conserva first/last_seen (base del historial temporal de la Fase 6E). La
  revisión humana (accepted/rejected) sobrevive a las reconstrucciones.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

# Clase del enlace (qué demuestra la evidencia, no lo que "parece"):
# - physical: adyacencia física informada por un protocolo de enlace (LLDP/CDP);
# - logical: relación de capa 3 o de gestión informada por una fuente (gateway configurado en
#   un agente, controladora WLAN que gestiona un AP); no implica cable directo;
# - observed: un equipo de red ve al otro extremo directamente (MAC en un puerto de acceso con
#   una sola MAC, cliente WLAN asociado a un AP);
# - candidate: evidencia compatible con un enlace pero no concluyente (puerto de acceso con
#   varias MACs);
# - unknown: hay evidencia de relación pero no de su naturaleza (MAC vista en un puerto que no
#   se puede resolver).
LINK_KINDS = ("physical", "logical", "observed", "candidate", "unknown")
LINK_MEDIA = ("wired", "wireless", "unknown")
LINK_CONFIDENCES = ("high", "medium", "low")
REVIEW_STATES = ("unreviewed", "accepted", "rejected")
BUILD_STATUSES = ("running", "succeeded", "failed")
# Tipos de extremo. "external" = identidad remota sin activo ni equipo en Sentra.
ENDPOINT_KINDS = ("asset", "network_device", "wlan_ap", "external")


class TopologyLink(Base):
    """Enlace derivado entre dos nodos de un site, con su evidencia.

    Cada extremo es exactamente uno de: activo, equipo de red, punto de acceso WLAN o
    identidad externa (clave + etiqueta). Se guarda la clave de nodo ya calculada
    (`source_node`, `target_node`) para filtrar sin recomponerla, y las FK para que borrar el
    activo o el equipo borre el enlace (es dato derivado: la siguiente reconstrucción lo
    recalcula si aún hay evidencia).
    """

    __tablename__ = "topology_links"
    __table_args__ = (
        # Clave natural: misma relación entre los mismos extremos = misma fila. Se calcula de
        # forma determinista en el constructor (relación + extremos ordenados + puertos).
        UniqueConstraint("site_id", "link_key", name="uq_topology_links_site_key"),
        Index("ix_topology_links_site_present", "site_id", "present", "kind"),
        Index("ix_topology_links_source_node", "site_id", "source_node"),
        Index("ix_topology_links_target_node", "site_id", "target_node"),
        Index("ix_topology_links_source_asset", "source_asset_id"),
        Index("ix_topology_links_target_asset", "target_asset_id"),
        Index("ix_topology_links_source_device", "source_device_id"),
        Index("ix_topology_links_target_device", "target_device_id"),
        Index("ix_topology_links_source_ap", "source_ap_id"),
        Index("ix_topology_links_target_ap", "target_ap_id"),
        Index("ix_topology_links_source_interface", "source_interface_id"),
        CheckConstraint(
            "kind IN ('physical', 'logical', 'observed', 'candidate', 'unknown')",
            name="ck_topology_links_kind",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')", name="ck_topology_links_confidence"
        ),
        CheckConstraint(
            "review_state IN ('unreviewed', 'accepted', 'rejected')",
            name="ck_topology_links_review_state",
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    link_key: Mapped[str] = mapped_column(String(64))
    kind: Mapped[str] = mapped_column(String(16))
    medium: Mapped[str] = mapped_column(String(16), default="unknown", server_default="unknown")
    # Relación concreta que originó el enlace: lldp, cdp, fdb_edge, fdb_shared, fdb_unmapped,
    # wlan_association, wlan_managed_by, default_gateway (catálogo cerrado en el constructor).
    relation: Mapped[str] = mapped_column(String(32))
    confidence: Mapped[str] = mapped_column(String(8))
    # --- extremo origen ---
    source_node: Mapped[str] = mapped_column(String(96))
    source_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    source_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="CASCADE")
    )
    source_ap_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_access_points.id", ondelete="CASCADE")
    )
    source_interface_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="SET NULL")
    )
    source_port: Mapped[str | None] = mapped_column(String(255))
    # --- extremo destino ---
    target_node: Mapped[str] = mapped_column(String(96))
    target_asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"))
    target_device_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_devices.id", ondelete="CASCADE")
    )
    target_ap_id: Mapped[int | None] = mapped_column(
        ForeignKey("wlan_access_points.id", ondelete="CASCADE")
    )
    target_port: Mapped[str | None] = mapped_column(String(255))
    # Identidad remota sin resolver (vecino LLDP/CDP desconocido): etiqueta visible y datos
    # informados (chasis, sysName, plataforma, dirección de gestión). Solo evidencia.
    target_external_label: Mapped[str | None] = mapped_column(String(255))
    target_external: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    # [{"source", "detail", "observed_at"}], como mucho 8 (lo acota el constructor).
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    evidence_sources: Mapped[list[str]] = mapped_column(JSONB)
    present: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Hora de la evidencia más reciente (no de la reconstrucción): vigencia real del enlace.
    last_evidence_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # Fase 6E.1: reconstrucciones seguidas sin derivar el enlace y desde cuándo. Un enlace
    # ausente solo se da por eliminado (link_removed) tras varias ausencias con su fuente de
    # evidencia sana; `removed_at` evita registrar la misma eliminación dos veces.
    absent_builds: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    absent_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # --- revisión humana (sobrevive a las reconstrucciones) ---
    review_state: Mapped[str] = mapped_column(
        String(16), default="unreviewed", server_default="unreviewed"
    )
    review_note: Mapped[str | None] = mapped_column(String(500))
    reviewed_by: Mapped[str | None] = mapped_column(String(64))
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TopologyBuild(Base):
    """Una reconstrucción de la topología de un site (historial corto y estado).

    Sirve para saber cuándo y con qué resultado se derivó el grafo, y para impedir dos
    reconstrucciones simultáneas del mismo site (índice único parcial sobre running).
    """

    __tablename__ = "topology_builds"
    __table_args__ = (
        Index("ix_topology_builds_site", "site_id", "started_at"),
        Index(
            "uq_topology_builds_running",
            "site_id",
            unique=True,
            postgresql_where=text("status = 'running'"),
        ),
        CheckConstraint(
            "status IN ('running', 'succeeded', 'failed')", name="ck_topology_builds_status"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    # manual | scheduled
    trigger: Mapped[str] = mapped_column(String(16))
    requested_by: Mapped[str | None] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(16))
    # {"links_created", "links_updated", "links_absent", "links_present", "nodes",
    #  "ambiguous_macs", "skipped_cross_site"}: enteros con claves fijas.
    counts: Mapped[dict[str, int] | None] = mapped_column(JSONB)
    error_code: Mapped[str | None] = mapped_column(String(32))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int | None] = mapped_column(Integer)
