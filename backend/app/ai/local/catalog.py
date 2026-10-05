"""Catálogo extensible de modelos conocidos (Fase 4J.2).

El catálogo NO es la única fuente: solo da recomendaciones de partida para modelos que aún
no están en el servidor ("Available"). Cualquier GGUF compatible se puede importar, y los
modelos del runtime se pueden registrar aunque no aparezcan aquí. Ninguna familia tiene
trato especial: Qwen, Llama, Mistral... se evalúan con el mismo motor.

AI_MODEL_CATALOG_FILE (opcional, configuración del servidor) añade entradas o reemplaza las
de igual `id`: así el catálogo se actualiza sin tocar el código. Un fichero inválido se
ignora con un aviso en lugar de tumbar la página.
"""

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.ai.local.engine import ModelSpec
from app.ai.local.quant import BITS_PER_WEIGHT, normalize_quantization

logger = logging.getLogger("sentra.ai")

BUILTIN = Path(__file__).with_name("catalog.json")
MAX_CATALOG_BYTES = 1024 * 1024
MAX_ENTRIES = 500


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    name: str
    family: str | None
    architecture: str | None
    parameter_count: int
    native_context: int | None
    layer_count: int | None
    kv_head_count: int | None
    head_dim: int | None
    license: str | None
    source: str | None
    quantizations: tuple[str, ...]

    def specs(self) -> list[ModelSpec]:
        """Una variante por cuantización, con tamaño estimado (aún no está en disco)."""
        return [
            ModelSpec(
                key=f"catalog:{self.id}:{quant}",
                name=f"{self.name} {quant}",
                family=self.family,
                parameter_count=self.parameter_count,
                quantization=quant,
                file_size_bytes=None,
                native_context=self.native_context,
                layer_count=self.layer_count,
                kv_head_count=self.kv_head_count,
                head_dim=self.head_dim,
                on_disk=False,
            )
            for quant in self.quantizations
        ]


def _entry(raw: Any) -> CatalogEntry | None:
    if not isinstance(raw, dict):
        return None

    def pos(key: str) -> int | None:
        value = raw.get(key)
        return (
            value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None
        )

    def text(key: str, limit: int = 128) -> str | None:
        value = raw.get(key)
        return value.strip()[:limit] or None if isinstance(value, str) else None

    ident, name, params = text("id", 64), text("name"), pos("parameter_count")
    quants = raw.get("quantizations")
    if not ident or not name or not params or not isinstance(quants, list):
        return None
    # Solo cuantizaciones con bits por peso conocidos: sin ellos no hay tamaño estimable.
    known = tuple(
        q for q in (normalize_quantization(str(v)) for v in quants[:16]) if q in BITS_PER_WEIGHT
    )
    if not known:
        return None
    return CatalogEntry(
        id=ident,
        name=name,
        family=text("family", 64),
        architecture=text("architecture", 64),
        parameter_count=params,
        native_context=pos("native_context"),
        layer_count=pos("layer_count"),
        kv_head_count=pos("kv_head_count"),
        head_dim=pos("head_dim"),
        license=text("license", 64),
        source=text("source", 256),
        quantizations=known,
    )


def _read(path: Path) -> list[CatalogEntry]:
    try:
        if path.stat().st_size > MAX_CATALOG_BYTES:
            raise ValueError("catalog file too large")
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("ignoring invalid AI model catalog", extra={"catalog": path.name})
        return []
    models = data.get("models") if isinstance(data, dict) else None
    if not isinstance(models, list):
        return []
    return [e for e in (_entry(m) for m in models[:MAX_ENTRIES]) if e is not None]


def load_catalog(extra_file: str | None = None) -> list[CatalogEntry]:
    entries = {e.id: e for e in _read(BUILTIN)}
    if extra_file:
        # El fichero del admin reemplaza entradas con el mismo id (actualizaciones).
        entries.update({e.id: e for e in _read(Path(extra_file))})
    return sorted(entries.values(), key=lambda e: (e.parameter_count, e.id))
