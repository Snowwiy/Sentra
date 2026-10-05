"""Rutas de modelos: solo dentro de AI_MODEL_DIRECTORIES (Fase 4J.2).

Riesgo que se evita: que la API se convierta en un lector de ficheros arbitrarios del
servidor (path traversal, symlinks hacia fuera, rutas UNC). Reglas:
- la ruta debe ser absoluta y quedar DENTRO de una raíz autorizada, primero de forma léxica
  y después tras resolver symlinks (realpath): un enlace dentro de la raíz que apunte fuera
  se rechaza;
- la comprobación de raíz va ANTES de mirar si el fichero existe, y el error es el mismo,
  así la API no sirve para averiguar qué ficheros hay fuera de las raíces;
- solo ficheros regulares .gguf con tamaño acotado. Nunca se ejecutan: solo se lee la
  cabecera (gguf.py) y, en segundo plano, se calcula el SHA-256.

El descubrimiento de ficheros solo recorre las raíces con profundidad y número de entradas
acotados: nunca escanea el disco completo.
"""

import os
import stat
from dataclasses import dataclass

from fastapi import status

from app.ai.local.gguf import SPLIT_PATTERN
from app.core.exceptions import SentraError

MAX_PATH_CHARS = 1024
MIN_GGUF_BYTES = 32
DISCOVERY_MAX_DEPTH = 2
DISCOVERY_MAX_ENTRIES = 5000
DISCOVERY_MAX_FILES = 500


class ModelPathError(SentraError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT
    code = "local_model_path_rejected"


@dataclass(frozen=True)
class LocalModelFile:
    path: str
    file_name: str
    size_bytes: int


def _norm(path: str) -> str:
    # normcase: en Windows las rutas no distinguen mayúsculas (D:\Models == d:\models).
    return os.path.normcase(os.path.normpath(path))


def _inside(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([_norm(path), _norm(root)]) == _norm(root)
    except ValueError:
        # Unidades distintas en Windows (C: frente a D:).
        return False


def resolve_model_path(raw: str, roots: tuple[str, ...], max_bytes: int) -> LocalModelFile:
    """Valida la ruta pedida por el admin y devuelve el fichero real. Lanza ModelPathError."""
    outside = ModelPathError(
        "The path is not inside an allowed model directory (AI_MODEL_DIRECTORIES)"
    )
    if not roots:
        raise ModelPathError("No model directories are configured (AI_MODEL_DIRECTORIES)")
    path = raw.strip()
    if not path or len(path) > MAX_PATH_CHARS or "\x00" in path or not os.path.isabs(path):
        raise ModelPathError("The path must be an absolute path to a .gguf file")
    if path.startswith(("\\\\", "//")):
        # UNC o rutas de dispositivo (\\?\, \\server\share): nunca son una raíz local.
        raise outside
    lexical = os.path.normpath(path)
    if not any(_inside(lexical, root) for root in roots):
        raise outside
    real = os.path.realpath(lexical)
    real_roots = [os.path.realpath(root) for root in roots]
    if not any(_inside(real, root) for root in real_roots):
        raise outside
    if not real.lower().endswith(".gguf"):
        raise ModelPathError("Only .gguf model files can be registered")
    try:
        info = os.stat(real)
    except OSError:
        raise ModelPathError("The model file does not exist") from None
    if not stat.S_ISREG(info.st_mode):
        raise ModelPathError("The path is not a regular file")
    if info.st_size < MIN_GGUF_BYTES:
        raise ModelPathError("The model file is too small to be a GGUF model")
    if info.st_size > max_bytes:
        raise ModelPathError("The model file exceeds AI_MODEL_MAX_FILE_GB")
    return LocalModelFile(real, os.path.basename(real), info.st_size)


def discover_model_files(roots: tuple[str, ...]) -> list[LocalModelFile]:
    """Ficheros .gguf dentro de las raíces (profundidad y entradas acotadas)."""
    found: list[LocalModelFile] = []
    visited = 0

    def walk(directory: str, depth: int) -> None:
        nonlocal visited
        try:
            entries = sorted(os.scandir(directory), key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            visited += 1
            if visited > DISCOVERY_MAX_ENTRIES or len(found) >= DISCOVERY_MAX_FILES:
                return
            try:
                if entry.is_dir(follow_symlinks=False):
                    if depth < DISCOVERY_MAX_DEPTH:
                        walk(entry.path, depth + 1)
                    continue
                if not entry.name.lower().endswith(".gguf") or not entry.is_file():
                    continue
                split = SPLIT_PATTERN.match(entry.name)
                if split and int(split.group("index")) != 1:
                    # Solo la primera parte de un modelo dividido representa al modelo.
                    continue
                size = entry.stat().st_size
            except OSError:
                continue
            real = os.path.realpath(entry.path)
            # Un symlink dentro de la raíz que apunte fuera no se lista (ni se podrá registrar).
            if any(_inside(real, root) for root in real_roots):
                found.append(LocalModelFile(real, entry.name, size))

    real_roots = [os.path.realpath(root) for root in roots]
    for root in roots:
        if os.path.isdir(root):
            walk(root, 0)
    return found
