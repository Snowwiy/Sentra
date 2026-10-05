"""Gestor de modelos locales (Fase 4J.2). Ver docs/local-model-manager.md.

Qué se persiste y por qué:
- ai_local_models: modelos registrados (fichero GGUF o modelo del runtime) con la metadata
  verificada. Debe sobrevivir a reinicios; recalcularla exigiría releer ficheros de GB.
- ai_model_benchmarks: mediciones reales. La recomendación da más peso a lo medido que a lo
  estimado, así que el historial no puede perderse al reiniciar.
- ai_local_settings: una sola fila con el runtime elegido y el modelo activo.

Lo que NO se persiste: el perfil de hardware (se detecta en memoria y se refresca a mano; no
hace falta un historial del equipo), prompts ni respuestas del benchmark.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Uuid,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class AILocalModel(Base):
    __tablename__ = "ai_local_models"
    __table_args__ = (
        # Un modelo del runtime se registra una vez (mismo runtime y mismo nombre).
        Index("uq_ai_local_models_runtime_model", "runtime", "runtime_model_id", unique=True),
        # Un fichero se registra una vez.
        Index(
            "uq_ai_local_models_path",
            "local_path",
            unique=True,
            postgresql_where=text("local_path IS NOT NULL"),
        ),
        Index("ix_ai_local_models_installed", "installed_at"),
    )

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(256))
    family: Mapped[str | None] = mapped_column(String(64))
    architecture: Mapped[str | None] = mapped_column(String(64))
    # Exacto (suma de tensores del GGUF o general.parameter_count) o aproximado del runtime.
    parameter_count: Mapped[int | None] = mapped_column(BigInteger)
    quantization: Mapped[str | None] = mapped_column(String(32))
    file_size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    # Contexto que el modelo DECLARA (nunca se supone uno mayor).
    native_context: Mapped[int | None] = mapped_column(Integer)
    # Datos para estimar el KV cache; sin ellos no se recomienda (no se inventan).
    layer_count: Mapped[int | None] = mapped_column(Integer)
    kv_head_count: Mapped[int | None] = mapped_column(Integer)
    head_dim: Mapped[int | None] = mapped_column(Integer)
    expert_count: Mapped[int | None] = mapped_column(Integer)
    # llama_cpp, ollama, vllm u openai_compatible: el runtime que lo sirve.
    runtime: Mapped[str] = mapped_column(String(24))
    # Nombre que se envía al runtime en "model" (nombre de Ollama, id de /v1/models o el
    # nombre del fichero GGUF para llama.cpp).
    runtime_model_id: Mapped[str] = mapped_column(String(256))
    # Ruta real (tras resolver symlinks) dentro de AI_MODEL_DIRECTORIES. Solo la ven admins.
    local_path: Mapped[str | None] = mapped_column(String(1024))
    split_count: Mapped[int] = mapped_column(SmallInteger, default=1, server_default="1")
    # gguf (cabecera verificada) o runtime (informado por el runtime).
    metadata_source: Mapped[str] = mapped_column(String(16))
    source: Mapped[str | None] = mapped_column(String(256))
    license: Mapped[str | None] = mapped_column(String(64))
    # SHA-256 del fichero, calculado en segundo plano (pending -> ok/failed).
    checksum_sha256: Mapped[str | None] = mapped_column(String(64))
    checksum_status: Mapped[str] = mapped_column(String(16), default="none", server_default="none")
    registered_by: Mapped[str] = mapped_column(String(64))
    installed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_selected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AIModelBenchmark(Base):
    __tablename__ = "ai_model_benchmarks"
    __table_args__ = (Index("ix_ai_model_benchmarks_model", "model_id", "started_at"),)

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True)
    public_id: Mapped[uuid.UUID] = mapped_column(Uuid, unique=True, default=uuid.uuid4)
    # CASCADE: quitar el registro de un modelo quita sus mediciones (no el fichero).
    model_id: Mapped[int] = mapped_column(ForeignKey("ai_local_models.id", ondelete="CASCADE"))
    # running, completed, failed o cancelled.
    status: Mapped[str] = mapped_column(String(16))
    runtime: Mapped[str] = mapped_column(String(24))
    # runtime_timings (medido por el runtime) o end_to_end (medido por Sentra).
    measurement: Mapped[str | None] = mapped_column(String(16))
    max_tokens: Mapped[int] = mapped_column(Integer)
    configured_context: Mapped[int | None] = mapped_column(Integer)
    load_ms: Mapped[int | None] = mapped_column(Integer)
    ttft_ms: Mapped[int | None] = mapped_column(Integer)
    prompt_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    prompt_tps: Mapped[float | None] = mapped_column(Float)
    generation_tps: Mapped[float | None] = mapped_column(Float)
    # Picos observados de TODO el sistema durante la prueba (no atribuidos al runtime).
    peak_ram_bytes: Mapped[int | None] = mapped_column(BigInteger)
    peak_vram_bytes: Mapped[int | None] = mapped_column(BigInteger)
    performance_class: Mapped[str | None] = mapped_column(String(16))
    error: Mapped[str | None] = mapped_column(String(64))
    requested_by: Mapped[str] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AILocalSettings(Base):
    __tablename__ = "ai_local_settings"
    # Una única fila (id = 1): configuración del gestor, no un historial.
    __table_args__ = (CheckConstraint("id = 1", name="single_row"),)

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    # None = usar AI_RUNTIME del entorno.
    runtime: Mapped[str | None] = mapped_column(String(24))
    # Modelo activo (slot "default"). SET NULL: quitar su registro deja a Sentra con AI_MODEL.
    active_model_id: Mapped[int | None] = mapped_column(
        ForeignKey("ai_local_models.id", ondelete="SET NULL"), index=True
    )
    updated_by: Mapped[str | None] = mapped_column(String(64))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
