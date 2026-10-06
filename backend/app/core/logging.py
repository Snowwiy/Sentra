import json
import logging
import logging.handlers
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.redaction import is_sensitive_key, redact_text, redact_value
from app.core.request_context import current_request_id

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message"}


def _extras(record: logging.LogRecord) -> dict[str, Any]:
    return {
        key: value
        for key, value in record.__dict__.items()
        if key not in _RESERVED and not key.startswith("_")
    }


def _clean_extras(record: logging.LogRecord) -> dict[str, Any]:
    # Fase 4M: los campos `extra=` pasan por la redacción central (core/redaction.py).
    redacted = redact_value(_extras(record))
    return redacted if isinstance(redacted, dict) else {}


class RequestContextFilter(logging.Filter):
    """Añade el request_id de la petición en curso a cada registro que no lo traiga."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            request_id = current_request_id()
            if request_id is not None:
                record.request_id = request_id
        return True


class JsonFormatter(logging.Formatter):
    """Formats records as single-line JSON. Fields passed through `extra=` are included.

    Campos estables (Fase 4M): timestamp (UTC), level, logger, event (el mensaje), request_id
    cuando lo hay y los extras. Mensaje, extras y traza de la excepción se redactan.
    """

    def format(self, record: logging.LogRecord) -> str:
        message = redact_text(record.getMessage())
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            # "event" y "message" llevan lo mismo: "message" se mantiene por compatibilidad
            # con quien ya filtra por él.
            "event": message,
            "message": message,
        }
        payload.update(_clean_extras(record))
        if record.exc_info:
            payload["exception"] = redact_text(self.formatException(record.exc_info))
        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Una línea legible (consola de desarrollo), con los extras como clave=valor."""

    def format(self, record: logging.LogRecord) -> str:
        stamp = datetime.fromtimestamp(record.created, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        extras = " ".join(
            f"{key}={'[REDACTED]' if is_sensitive_key(key) else value}"
            for key, value in _clean_extras(record).items()
        )
        line = f"{stamp} {record.levelname:<7} {record.name}: {redact_text(record.getMessage())}"
        if extras:
            line = f"{line} {extras}"
        if record.exc_info:
            line = f"{line}\n{redact_text(self.formatException(record.exc_info))}"
        return line


def configure_logging(
    level: str,
    log_format: str = "json",
    log_file: str | None = None,
    max_mb: int = 50,
    backups: int = 10,
) -> None:
    formatter: logging.Formatter = TextFormatter() if log_format == "text" else JsonFormatter()
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    if log_file:
        # Rotación propia por tamaño (Windows Server no tiene journald): nunca logs infinitos.
        # En Linux con systemd basta stdout, que journald rota según su configuración.
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            logging.handlers.RotatingFileHandler(
                log_file, maxBytes=max_mb * 1024 * 1024, backupCount=backups, encoding="utf-8"
            )
        )
    context = RequestContextFilter()
    for handler in handlers:
        handler.setFormatter(formatter)
        handler.addFilter(context)

    root = logging.getLogger()
    root.handlers = handlers
    root.setLevel(level.upper())

    # Uvicorn installs its own handlers; route everything through the JSON handler instead.
    for name in ("uvicorn", "uvicorn.error"):
        logger = logging.getLogger(name)
        logger.handlers = []
        logger.propagate = True
    # Requests are already logged by the request middleware.
    logging.getLogger("uvicorn.access").disabled = True
