"""Logs JSON estructurados con rotación y redacción de secretos."""

import json
import logging
import re
import sys
import threading
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentra_sensor")

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message"}

# Defensa en profundidad: ningún camino del código loggea la credencial ni el token de
# enrollment, pero un mensaje de excepción, el cuerpo de un error del servidor o una línea de
# depuración futura podrían. Cada línea se limpia de los secretos conocidos (registrados en
# cuanto se cargan) y de todo lo que parezca una cabecera Authorization o un token.
_PATTERNS = (
    re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"(Authorization[\"']?\s*[:=]\s*[\"']?)[^\"',}\s]+", re.IGNORECASE),
    re.compile(r"(X-Sensor-Enrollment-Token[\"']?\s*[:=]\s*[\"']?)[^\"',}\s]+", re.IGNORECASE),
    re.compile(r"([\"']?(?:credential|token)[\"']?\s*[:=]\s*[\"'])[^\"']+", re.IGNORECASE),
)
REDACTED = "[REDACTED]"
_secrets: set[str] = set()
_secrets_lock = threading.Lock()


def register_secret(value: str | None) -> None:
    """A partir de ahora `value` nunca aparecerá en la salida de logs."""
    # Valores muy cortos redactarían palabras normales; los secretos reales son largos.
    if value and len(value) >= 8:
        with _secrets_lock:
            _secrets.add(value)


def redact(text: str) -> str:
    with _secrets_lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    for pattern in _PATTERNS:
        text = pattern.sub(lambda match: match.group(1) + REDACTED, text)
    return text


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        payload.update(
            {
                k: v
                for k, v in record.__dict__.items()
                if k not in _RESERVED and not k.startswith("_")
            }
        )
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return redact(json.dumps(payload, default=str))


def configure_logging(log_dir: Path, level: str, console: bool = True) -> Path:
    """Consola + fichero rotado (5 x 1 MB): acotado para meses de ejecución desatendida."""
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_file = log_dir / "sensor.log"
    formatter = JsonFormatter()
    handlers: list[logging.Handler] = [
        RotatingFileHandler(log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
    ]
    if console and sys.stderr is not None:
        handlers.append(logging.StreamHandler(sys.stderr))
    for handler in handlers:
        handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(level.upper())
    return log_file
