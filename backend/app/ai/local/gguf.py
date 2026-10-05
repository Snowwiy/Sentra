"""Lectura de la cabecera de un fichero GGUF (solo stdlib, nunca se ejecuta nada).

Qué se lee: la metadata clave/valor y la tabla de tensores (nombre, dimensiones y tipo). Los
pesos NO se leen: el número de parámetros se obtiene sumando las dimensiones de cada tensor,
así que no depende del nombre del fichero ni de lo que diga general.size_label.

Por qué con límites: el fichero lo eligió un admin, pero su contenido puede estar corrupto o
manipulado. Cada cantidad (número de claves, de tensores, longitud de cadenas, tamaño total
de la cabecera) se acota antes de reservar memoria o avanzar, y cualquier inconsistencia es
InvalidGGUFError. Un fichero así se rechaza en vez de registrarse con datos inventados.

Formato: https://github.com/ggml-org/ggml/blob/master/docs/gguf.md (versiones 2 y 3).
"""

import os
import re
import struct
from dataclasses import dataclass, field
from typing import Any, BinaryIO

from app.ai.local.quant import GGML_TENSOR_TYPES, GGUF_FILE_TYPES

GGUF_MAGIC = b"GGUF"
# Una cabecera real (vocabulario de ~150k tokens incluido) ocupa unos pocos MB.
MAX_HEADER_BYTES = 128 * 1024 * 1024
MAX_KV_COUNT = 100_000
MAX_TENSOR_COUNT = 1_000_000
MAX_STRING_BYTES = 16 * 1024 * 1024
MAX_ARRAY_ITEMS = 50_000_000
MAX_DIMS = 8

# Tipos de valor GGUF: tamaño fijo en bytes (strings y arrays aparte).
_FIXED = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_FORMAT = {0: "<B", 1: "<b", 2: "<H", 3: "<h", 4: "<I", 5: "<i", 6: "<f", 7: "<?",
           10: "<Q", 11: "<q", 12: "<d"}  # fmt: skip
_STRING = 8
_ARRAY = 9

# Partes de un modelo dividido: "modelo-00001-of-00003.gguf".
SPLIT_PATTERN = re.compile(r"^(?P<prefix>.+)-(?P<index>\d{5})-of-(?P<count>\d{5})\.gguf$", re.I)


class InvalidGGUFError(ValueError):
    """El fichero no es un GGUF válido o su cabecera es inconsistente."""


@dataclass(frozen=True)
class GGUFInfo:
    version: int
    architecture: str | None
    name: str | None
    basename: str | None
    size_label: str | None
    license: str | None
    file_type: int | None
    # Cuantización según general.file_type; si falta, la del tipo de tensor dominante.
    quantization: str | None
    quantization_source: str | None
    parameter_count: int
    tensor_count: int
    context_length: int | None
    block_count: int | None
    head_count: int | None
    head_count_kv: int | None
    embedding_length: int | None
    key_length: int | None
    value_length: int | None
    expert_count: int | None
    split_count: int
    split_index: int
    # Bytes de tensores por tipo (para explicar la cuantización real del fichero).
    tensor_types: dict[str, int] = field(default_factory=dict)

    @property
    def head_dim(self) -> int | None:
        """Dimensión por cabeza para el KV cache (key_length o embedding/heads)."""
        if self.key_length:
            return self.key_length
        if self.embedding_length and self.head_count:
            return self.embedding_length // self.head_count
        return None


class _Reader:
    def __init__(self, handle: BinaryIO, limit: int) -> None:
        self._f = handle
        self._limit = limit

    def _check(self, size: int) -> None:
        if self._f.tell() + size > self._limit:
            raise InvalidGGUFError("GGUF header is larger than the allowed limit")

    def read(self, size: int) -> bytes:
        self._check(size)
        data = self._f.read(size)
        if len(data) != size:
            raise InvalidGGUFError("GGUF file is truncated")
        return data

    def skip(self, size: int) -> None:
        self._check(size)
        self._f.seek(size, os.SEEK_CUR)

    def u32(self) -> int:
        return int(struct.unpack("<I", self.read(4))[0])

    def u64(self) -> int:
        return int(struct.unpack("<Q", self.read(8))[0])

    def string(self, keep: bool = True) -> str | None:
        length = self.u64()
        if length > MAX_STRING_BYTES:
            raise InvalidGGUFError("GGUF string is too long")
        if not keep:
            self.skip(length)
            return None
        return self.read(length).decode("utf-8", errors="replace")

    def value(self, kind: int, keep: bool) -> Any:
        if kind in _FIXED:
            raw = self.read(_FIXED[kind])
            return struct.unpack(_FORMAT[kind], raw)[0] if keep else None
        if kind == _STRING:
            return self.string(keep)
        if kind == _ARRAY:
            item_kind = self.u32()
            count = self.u64()
            if count > MAX_ARRAY_ITEMS:
                raise InvalidGGUFError("GGUF array is too long")
            if item_kind in _FIXED:
                # Arrays numéricos (scores del tokenizer...): se saltan sin leerlos.
                self.skip(_FIXED[item_kind] * count)
                return None
            if item_kind == _STRING:
                for _ in range(count):
                    self.string(keep=False)
                return None
            raise InvalidGGUFError("GGUF array has an unsupported item type")
        raise InvalidGGUFError(f"GGUF value has an unknown type ({kind})")


def _int(value: Any) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


def _str(value: Any, limit: int = 128) -> str | None:
    return value.strip()[:limit] or None if isinstance(value, str) else None


def read_gguf(path: str, max_header_bytes: int = MAX_HEADER_BYTES) -> GGUFInfo:
    """Lee la cabecera de `path`. Lanza InvalidGGUFError si no es un GGUF válido."""
    try:
        with open(path, "rb") as handle:
            return _parse(handle, max_header_bytes)
    except OSError as exc:
        raise InvalidGGUFError(f"GGUF file cannot be read ({type(exc).__name__})") from None
    except struct.error:
        raise InvalidGGUFError("GGUF header is malformed") from None


def _parse(handle: BinaryIO, max_header_bytes: int) -> GGUFInfo:
    reader = _Reader(handle, max_header_bytes)
    if reader.read(4) != GGUF_MAGIC:
        raise InvalidGGUFError("Not a GGUF file (bad magic)")
    version = reader.u32()
    if version not in (2, 3):
        raise InvalidGGUFError(f"Unsupported GGUF version ({version})")
    tensor_count = reader.u64()
    kv_count = reader.u64()
    if tensor_count > MAX_TENSOR_COUNT or kv_count > MAX_KV_COUNT:
        raise InvalidGGUFError("GGUF header declares too many entries")

    meta: dict[str, Any] = {}
    for _ in range(kv_count):
        key = reader.string() or ""
        kind = reader.u32()
        # Solo se conservan las claves que usa Sentra; el resto (vocabulario incluido) se salta.
        keep = (
            key.startswith("general.")
            or key.startswith("split.")
            or (
                "." in key
                and (
                    key.split(".", 1)[1]
                    in {
                        "context_length",
                        "block_count",
                        "embedding_length",
                        "attention.head_count",
                        "attention.head_count_kv",
                        "attention.key_length",
                        "attention.value_length",
                        "expert_count",
                    }
                )
            )
        )
        value = reader.value(kind, keep)
        if keep:
            meta[key] = value

    parameters = 0
    by_type: dict[str, int] = {}
    for _ in range(tensor_count):
        reader.string(keep=False)
        n_dims = reader.u32()
        if not 1 <= n_dims <= MAX_DIMS:
            raise InvalidGGUFError("GGUF tensor has an invalid number of dimensions")
        elements = 1
        for _ in range(n_dims):
            elements *= reader.u64()
        tensor_type = reader.u32()
        reader.skip(8)  # offset de los datos: no se leen pesos
        parameters += elements
        type_name = GGML_TENSOR_TYPES.get(tensor_type, f"type_{tensor_type}")
        by_type[type_name] = by_type.get(type_name, 0) + elements

    arch = _str(meta.get("general.architecture"), 64)

    def arch_int(suffix: str) -> int | None:
        return _int(meta.get(f"{arch}.{suffix}")) if arch else None

    file_type = meta.get("general.file_type")
    file_type = (
        file_type if isinstance(file_type, int) and not isinstance(file_type, bool) else None
    )
    quantization = GGUF_FILE_TYPES.get(file_type) if file_type is not None else None
    source = "general.file_type" if quantization else None
    if quantization is None and by_type:
        # Sin file_type: el tipo con más elementos (excluye F32 de normas y sesgos).
        weights = {k: v for k, v in by_type.items() if k != "F32"} or by_type
        dominant = max(sorted(weights), key=lambda k: weights[k])
        if not dominant.startswith("type_"):
            quantization, source = dominant, "tensor_types"

    split_count = _int(meta.get("split.count")) or 1
    split_index = meta.get("split.no")
    return GGUFInfo(
        version=version,
        architecture=arch,
        name=_str(meta.get("general.name")),
        basename=_str(meta.get("general.basename")),
        size_label=_str(meta.get("general.size_label"), 32),
        license=_str(meta.get("general.license"), 64),
        file_type=file_type,
        quantization=quantization,
        quantization_source=source,
        parameter_count=parameters,
        tensor_count=tensor_count,
        context_length=arch_int("context_length"),
        block_count=arch_int("block_count"),
        head_count=arch_int("attention.head_count"),
        head_count_kv=arch_int("attention.head_count_kv") or arch_int("attention.head_count"),
        embedding_length=arch_int("embedding_length"),
        key_length=arch_int("attention.key_length"),
        value_length=arch_int("attention.value_length"),
        expert_count=arch_int("expert_count"),
        split_count=split_count,
        split_index=split_index if isinstance(split_index, int) else 0,
        tensor_types=by_type,
    )


def split_parts(path: str) -> list[str] | None:
    """Rutas de todas las partes si `path` es la primera de un GGUF dividido; si no, None.

    Solo mira el mismo directorio y el patrón exacto de llama.cpp (gguf-split): nunca busca
    ficheros fuera de la carpeta del modelo.
    """
    directory, filename = os.path.split(path)
    match = SPLIT_PATTERN.match(filename)
    if not match:
        return None
    count = int(match.group("count"))
    if int(match.group("index")) != 1 or not 1 < count <= 256:
        return None
    width = len(match.group("index"))
    return [
        os.path.join(
            directory, f"{match.group('prefix')}-{i:0{width}d}-of-{match.group('count')}.gguf"
        )
        for i in range(1, count + 1)
    ]
