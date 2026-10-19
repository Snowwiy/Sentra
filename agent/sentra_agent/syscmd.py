"""Ejecución acotada de herramientas del sistema (Fase 6C.5).

Todos los colectores nuevos (macOS y Wi-Fi en las tres plataformas) llaman a herramientas
del propio sistema operativo. Reglas comunes, aplicadas aquí una sola vez:

- ruta absoluta conocida, nunca una búsqueda en PATH ni en el directorio de trabajo (un
  binario plantado antes en PATH no se ejecuta como root);
- lista de argumentos fija y `shell=False`: ningún texto se interpreta;
- stdin cerrado (/dev/null): una herramienta que pidiese algo interactivo no bloquea;
- plazo máximo: un vigilante mata el proceso al vencer, aunque no escriba nada;
- salida acotada en bytes: al llenar el cupo se detiene el proceso y se marca `truncated`,
  así un equipo con una salida enorme no agota la memoria del agente;
- stderr a un fichero temporal (se leen como mucho 8 KiB) para no bloquear el proceso.
"""

import contextlib
import os
import subprocess
import tempfile
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

# Cupo por defecto de stdout: holgado para las salidas reales (system_profiler, launchctl).
DEFAULT_MAX_BYTES = 4 * 1024 * 1024
DEFAULT_TIMEOUT = 30.0
_CHUNK = 64 * 1024
_STDERR_MAX = 8192


class CommandUnavailableError(OSError):
    """La herramienta no existe en este equipo (o no es ejecutable)."""


class CommandTimeoutError(OSError):
    """La herramienta no terminó dentro del plazo y se detuvo."""


@dataclass(frozen=True)
class CommandOutput:
    stdout: bytes
    stderr: str
    returncode: int
    # True si Sentra detuvo el proceso al llenar el cupo: `returncode` no es entonces de la
    # herramienta y la última línea puede estar cortada.
    truncated: bool = False

    def text(self, encoding: str = "utf-8") -> str:
        return self.stdout.decode(encoding, "replace")


def first_existing(candidates: Iterable[str]) -> str | None:
    """Primera ruta absoluta que existe y es ejecutable (nunca se consulta PATH)."""
    for path in candidates:
        if os.path.isabs(path) and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def run_bounded(
    argv: list[str],
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    env: Mapping[str, str] | None = None,
) -> CommandOutput:
    """Ejecuta `argv` (ruta absoluta + argumentos fijos) con plazo y cupo de salida.

    Lanza CommandUnavailableError si el ejecutable no existe y CommandTimeoutError si vence
    el plazo. Un código de salida distinto de 0 no es una excepción: cada colector decide
    qué significa (sin adaptador, sin permiso...).
    """
    if not argv or not os.path.isabs(argv[0]):
        # Defensa en profundidad: ningún llamador debe pasar un nombre relativo.
        raise CommandUnavailableError(f"not an absolute path: {argv[:1]!r}")
    if not os.path.isfile(argv[0]):
        raise CommandUnavailableError(f"{argv[0]} not found")
    chunks: list[bytes] = []
    size = 0
    truncated = False
    with open(os.devnull, "rb") as stdin, tempfile.TemporaryFile() as err:
        try:
            process = subprocess.Popen(  # noqa: S603  (ruta absoluta, sin shell, argumentos fijos)
                argv,
                stdin=stdin,
                stdout=subprocess.PIPE,
                stderr=err,
                close_fds=True,
                shell=False,
                env=dict(env) if env is not None else None,
            )
        except (FileNotFoundError, PermissionError) as exc:
            raise CommandUnavailableError(str(exc)) from exc
        assert process.stdout is not None  # noqa: S101
        expired = threading.Event()

        def _expire() -> None:
            expired.set()
            _kill(process)

        watchdog = threading.Timer(timeout, _expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            while True:
                chunk = process.stdout.read(_CHUNK)
                if not chunk:
                    break
                remaining = max_bytes - size
                if len(chunk) > remaining:
                    chunks.append(chunk[:remaining])
                    size = max_bytes
                    truncated = True
                    break
                chunks.append(chunk)
                size += len(chunk)
            if not truncated:
                process.wait()
        finally:
            watchdog.cancel()
            if process.poll() is None:
                _kill(process)
            try:
                returncode = process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                returncode = -9
            process.stdout.close()
        err.seek(0)
        stderr = err.read(_STDERR_MAX).decode("utf-8", "replace")
    if expired.is_set():
        raise CommandTimeoutError(f"{os.path.basename(argv[0])} timed out after {timeout:.0f}s")
    return CommandOutput(b"".join(chunks), stderr, 0 if truncated else returncode, truncated)


def _kill(process: "subprocess.Popen[bytes]") -> None:
    # OSError: ya había terminado (carrera entre poll y kill).
    with contextlib.suppress(OSError):
        process.kill()
