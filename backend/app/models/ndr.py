"""Network Detection & Response: observación pasiva de red (Fase 7E, docs/fase-7e.md).

Los datos llegan de sensores 0.8.0+ que capturan EN MODO PASIVO en interfaces que el operador
del sensor declaró en su sensor.toml y que un admin de Sentra aprobó por alias
(`ndr_capture_configs`). Principios:

- Solo metadatos: flujos (5-tupla, contadores, banderas TCP) y metadatos de protocolo (ARP,
  DNS, DHCP, SNI de TLS). Nunca payloads, credenciales ni contenido descifrado.
- Todo pertenece a UN site, el del sensor que lo observó (sale de su credencial, nunca del
  cuerpo). Una IP privada repetida en dos sites son dos entidades distintas.
- Lo observado es evidencia, no verdad: un flujo visto a medias (`midstream`, `asymmetric`)
  se guarda con esas banderas y nunca se completa por inferencia.
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base

OBSERVATION_KINDS = ("arp", "dns", "dhcp", "tls")


class NdrCaptureConfig(Base):
    """Captura aprobada para un sensor: qué alias puede capturar y con qué límites.

    Sin fila, o con `enabled = false`, el sensor no captura nada aunque lo tenga declarado en
    local. `revision` sube con cada cambio para que el sensor reconfigure de forma idempotente.
    `observation_point` es la confirmación explícita del admin de DÓNDE está conectada la
    interfaz (puerto SPAN, TAP, segmento propio): sin ella no se puede habilitar.
    """

    __tablename__ = "ndr_capture_configs"
    __table_args__ = (
        UniqueConstraint("sensor_id", name="uq_ndr_capture_configs_sensor_id"),
        Index("ix_ndr_capture_configs_site_id", "site_id"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    revision: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    # Alias aprobados (^[a-z0-9_-]{1,32}$, como mucho 4). Nunca nombres de dispositivo.
    interfaces: Mapped[list[str]] = mapped_column(JSONB, default=list)
    observation_point: Mapped[str | None] = mapped_column(String(200))
    promiscuous: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    snaplen: Mapped[int] = mapped_column(Integer, default=512, server_default="512")
    max_flows: Mapped[int] = mapped_column(Integer, default=20_000, server_default="20000")
    max_packets_per_second: Mapped[int] = mapped_column(
        Integer, default=20_000, server_default="20000"
    )
    max_cpu_percent: Mapped[int] = mapped_column(SmallInteger, default=40, server_default="40")
    export_interval_seconds: Mapped[int] = mapped_column(Integer, default=60, server_default="60")
    flow_idle_timeout_seconds: Mapped[int] = mapped_column(
        Integer, default=120, server_default="120"
    )
    flow_active_timeout_seconds: Mapped[int] = mapped_column(
        Integer, default=300, server_default="300"
    )
    # Metadatos de protocolo. DNS y SNI revelan qué consulta cada equipo: apagados por defecto.
    arp_metadata: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    dhcp_metadata: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    dns_metadata: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    tls_metadata: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    updated_by: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NdrBatch(Base):
    """Recibo de un lote de un sensor: deduplicación (at-least-once) y salud de la captura.

    Se guarda solo el recuento y las estadísticas saneadas de la ventana (paquetes vistos,
    descartes del kernel, CPU...), nunca los registros: esos van a sus tablas.
    """

    __tablename__ = "ndr_batches"
    __table_args__ = (
        UniqueConstraint("sensor_id", "batch_id", name="uq_ndr_batches_sensor_batch"),
        Index("ix_ndr_batches_site_received", "site_id", "received_at"),
        Index("ix_ndr_batches_received_at", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    batch_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    interface: Mapped[str] = mapped_column(String(32))
    config_revision: Mapped[int] = mapped_column(Integer)
    backend: Mapped[str | None] = mapped_column(String(16))
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    part: Mapped[int] = mapped_column(Integer)
    parts: Mapped[int] = mapped_column(Integer)
    flows: Mapped[int] = mapped_column(Integer, default=0)
    observations: Mapped[int] = mapped_column(Integer, default=0)
    stats: Mapped[dict[str, Any] | None] = mapped_column(JSONB)


class NdrFlow(Base):
    """Flujo bidireccional observado. `uid` lo genera el sensor y es estable entre los
    segmentos de un flujo largo: los contadores llegan acumulados y se guardan con GREATEST,
    así que un reenvío o un segmento desordenado nunca resta ni duplica."""

    __tablename__ = "ndr_flows"
    __table_args__ = (
        UniqueConstraint("sensor_id", "uid", name="uq_ndr_flows_sensor_uid"),
        Index("ix_ndr_flows_site_last_seen", "site_id", "last_seen"),
        Index("ix_ndr_flows_site_src", "site_id", "src_ip", "last_seen"),
        Index("ix_ndr_flows_site_dst", "site_id", "dst_ip", "last_seen"),
        Index("ix_ndr_flows_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    interface: Mapped[str] = mapped_column(String(32))
    uid: Mapped[str] = mapped_column(String(32))
    ip_version: Mapped[int] = mapped_column(SmallInteger)
    transport: Mapped[str] = mapped_column(String(8))
    src_ip: Mapped[str] = mapped_column(String(45))
    src_port: Mapped[int | None] = mapped_column(Integer)
    dst_ip: Mapped[str] = mapped_column(String(45))
    dst_port: Mapped[int | None] = mapped_column(Integer)
    vlan: Mapped[int | None] = mapped_column(SmallInteger)
    src_mac: Mapped[str | None] = mapped_column(String(17))
    dst_mac: Mapped[str | None] = mapped_column(String(17))
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    packets_out: Mapped[int] = mapped_column(BigInteger, default=0)
    packets_in: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_out: Mapped[int] = mapped_column(BigInteger, default=0)
    bytes_in: Mapped[int] = mapped_column(BigInteger, default=0)
    tcp_flags_out: Mapped[int] = mapped_column(SmallInteger, default=0)
    tcp_flags_in: Mapped[int] = mapped_column(SmallInteger, default=0)
    state: Mapped[str] = mapped_column(String(16))
    final: Mapped[bool] = mapped_column(Boolean, default=False)
    segments: Mapped[int] = mapped_column(Integer, default=1)
    # midstream / asymmetric / fragmented / retransmissions / no_handshake_reply
    flags: Mapped[list[str]] = mapped_column(JSONB, default=list)
    retransmissions: Mapped[int] = mapped_column(Integer, default=0)
    fragments: Mapped[int] = mapped_column(Integer, default=0)
    icmp_type: Mapped[int | None] = mapped_column(SmallInteger)
    app_hints: Mapped[list[str]] = mapped_column(JSONB, default=list)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NdrProtocolObservation(Base):
    """Metadato de protocolo agregado por clave natural (ARP, DNS, DHCP, TLS SNI).

    Una fila por (sensor, tipo, clave): las ventanas sucesivas suman `count` y extienden
    `last_seen`, así que la tabla crece con la diversidad de la red y no con el tráfico.
    `key_hash` es el SHA-256 de la clave natural (los campos que la forman varían por tipo).
    """

    __tablename__ = "ndr_protocol_observations"
    __table_args__ = (
        UniqueConstraint("sensor_id", "kind", "key_hash", name="uq_ndr_protocol_observations_key"),
        Index("ix_ndr_protocol_observations_site_kind", "site_id", "kind", "last_seen"),
        Index("ix_ndr_protocol_observations_site_ip", "site_id", "ip"),
        Index("ix_ndr_protocol_observations_site_mac", "site_id", "mac"),
        Index("ix_ndr_protocol_observations_last_seen", "last_seen"),
        CheckConstraint("kind IN ('arp', 'dns', 'dhcp', 'tls')", name="kind"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    sensor_id: Mapped[int] = mapped_column(ForeignKey("sensors.id", ondelete="CASCADE"))
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    interface: Mapped[str] = mapped_column(String(32))
    kind: Mapped[str] = mapped_column(String(8))
    key_hash: Mapped[str] = mapped_column(String(64))
    # IP principal: emisor ARP, cliente DNS/TLS, IP ofrecida DHCP.
    ip: Mapped[str | None] = mapped_column(String(45))
    # IP del otro extremo: destino ARP, resolvedor DNS, servidor DHCP/TLS.
    peer_ip: Mapped[str | None] = mapped_column(String(45))
    mac: Mapped[str | None] = mapped_column(String(17))
    # Nombre consultado (DNS) o SNI (TLS), ya saneado por el sensor y revalidado aquí.
    name: Mapped[str | None] = mapped_column(String(253))
    vlan: Mapped[int | None] = mapped_column(SmallInteger)
    count: Mapped[int] = mapped_column(BigInteger, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    # Detalle propio del tipo (rcodes y respuestas DNS, routers DHCP, operación ARP...).
    data: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)


# --- Fase 7E.2: anomalías de red y asociaciones IP-MAC ----------------------------------------

ANOMALY_VERDICTS = ("observed", "suspicious", "probable", "confirmed")
ANOMALY_STATUSES = ("open", "acknowledged", "resolved", "false_positive")
ACTIVE_ANOMALY_STATUSES = ("open", "acknowledged")


class NdrAnomaly(Base):
    """Hallazgo de una regla NDR (NDR-ARP-001, NDR-MITM-001, NDR-DNS-001...).

    Vive a nivel de site porque la red no siempre se puede atribuir a un activo inventariado
    (un intruso con una MAC nueva no es un activo). `verdict` expresa cuánto respalda la
    evidencia la conclusión: observed (hecho sin juicio), suspicious, probable y confirmed,
    este último SOLO cuando la regla reúne indicios independientes suficientes (cada regla
    documenta los suyos en docs/fase-7e-ndr-detections.md). Mientras está activa (open o
    acknowledged) absorbe nuevas ocurrencias de la misma clave en vez de duplicarse.
    """

    __tablename__ = "ndr_anomalies"
    __table_args__ = (
        Index(
            "uq_ndr_anomalies_active_key",
            "site_id",
            "rule_id",
            "dedup_key",
            unique=True,
            postgresql_where=text("status IN ('open', 'acknowledged')"),
        ),
        Index("ix_ndr_anomalies_site_last_seen", "site_id", "last_seen"),
        Index("ix_ndr_anomalies_status_last_seen", "status", "last_seen"),
        Index("ix_ndr_anomalies_sensor_id", "sensor_id"),
        Index("ix_ndr_anomalies_subject_ip", "site_id", "subject_ip"),
        Index("ix_ndr_anomalies_asset_id", "asset_id"),
        CheckConstraint(
            "verdict IN ('observed', 'suspicious', 'probable', 'confirmed')", name="verdict"
        ),
        CheckConstraint(
            "status IN ('open', 'acknowledged', 'resolved', 'false_positive')", name="status"
        ),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    sensor_id: Mapped[int | None] = mapped_column(ForeignKey("sensors.id", ondelete="SET NULL"))
    rule_id: Mapped[str] = mapped_column(String(24))
    rule_version: Mapped[int] = mapped_column(SmallInteger, default=1)
    category: Mapped[str] = mapped_column(String(16))
    verdict: Mapped[str] = mapped_column(String(12))
    severity: Mapped[str] = mapped_column(String(16))
    status: Mapped[str] = mapped_column(String(16), default="open", server_default="open")
    dedup_key: Mapped[str] = mapped_column(String(160))
    subject_ip: Mapped[str | None] = mapped_column(String(45))
    subject_mac: Mapped[str | None] = mapped_column(String(17))
    # Fase 7E.4: activo inventariado del site al que se atribuye (por MAC del sujeto o, sin
    # MAC, por su IP). Null si no hay ninguno: un intruso con MAC nueva no es un activo.
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    # Rango de veredicto (app/ndr/rules.py: VERDICT_RANK) para el que ya se emitió una señal
    # al motor de detección: solo se vuelve a emitir si el veredicto sube.
    signaled_rank: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")
    title: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(String(1000))
    # Evidencia acotada (IPs, MACs, contadores, nombres ya saneados); nunca payloads.
    evidence: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    occurrences: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status_by: Mapped[str | None] = mapped_column(String(64))
    status_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status_note: Mapped[str | None] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class NdrIpMacBinding(Base):
    """Asociación IP-MAC vista en la red de un site (respuestas ARP y concesiones DHCP).

    Es la base de las reglas ARP: un cambio de MAC para una IP con una asociación activa es
    lo que se analiza. `vlan_key` es la VLAN o 0 (sin etiqueta), para no tener NULL en el
    único. `gateway` se marca cuando un servidor DHCP anuncia esa IP como router (opción 3).
    """

    __tablename__ = "ndr_ip_mac_bindings"
    __table_args__ = (
        UniqueConstraint("site_id", "vlan_key", "ip", "mac", name="uq_ndr_ip_mac_bindings_key"),
        Index("ix_ndr_ip_mac_bindings_site_ip", "site_id", "ip", "last_seen"),
        Index("ix_ndr_ip_mac_bindings_site_mac", "site_id", "mac"),
        Index("ix_ndr_ip_mac_bindings_last_seen", "last_seen"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    vlan_key: Mapped[int] = mapped_column(Integer, default=0)
    ip: Mapped[str] = mapped_column(String(45))
    mac: Mapped[str] = mapped_column(String(17))
    # arp / dhcp: la fuente más reciente que confirmó la asociación.
    source: Mapped[str] = mapped_column(String(8))
    gateway: Mapped[bool] = mapped_column(Boolean, default=False, server_default="false")
    count: Mapped[int] = mapped_column(BigInteger, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True))


# --- Fase 7E.3: líneas base de comportamiento --------------------------------------------------


class NdrBaseline(Base):
    """Línea base horaria de una métrica de un equipo del site (algoritmo de Welford).

    Se alimenta con las horas con actividad (una hora sin tráfico no es una muestra) y solo
    con valores no anómalos, para que una exfiltración larga no "normalice" su propio
    volumen. Con menos de NDR_BASELINE_MIN_SAMPLES muestras la regla no evalúa: aprende.
    """

    __tablename__ = "ndr_baselines"
    __table_args__ = (
        UniqueConstraint("site_id", "entity_ip", "metric", name="uq_ndr_baselines_key"),
        Index("ix_ndr_baselines_updated_at", "updated_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    site_id: Mapped[int] = mapped_column(ForeignKey("sites.id", ondelete="RESTRICT"))
    entity_ip: Mapped[str] = mapped_column(String(45))
    metric: Mapped[str] = mapped_column(String(32))
    samples: Mapped[int] = mapped_column(Integer, default=0)
    mean: Mapped[float] = mapped_column(Float, default=0.0)
    m2: Mapped[float] = mapped_column(Float, default=0.0)
    last_value: Mapped[float | None] = mapped_column(Float)
    last_bucket: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class NdrEngineCursor(Base):
    """Posición del job ndr-engine por tarea (p. ej. la última hora agregada)."""

    __tablename__ = "ndr_engine_cursors"

    name: Mapped[str] = mapped_column(String(32), primary_key=True)
    position: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
