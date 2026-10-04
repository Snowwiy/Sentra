"""Structured JSON logging with rotation and secret redaction."""

import json
import logging
import re
import sys
import threading
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", None, None).__dict__) | {"message"}

# Defense in depth: no code path should log a credential, but an exception message, a
# server error body or a future debug line could. Every formatted line is scrubbed of the
# known secrets (token, enrollment key) and of anything shaped like a bearer header.
_BEARER = re.compile(r"(Bearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_REDACTED = "[REDACTED]"
_secrets: set[str] = set()
_secrets_lock = threading.Lock()


def register_secret(value: str | None) -> None:
    """Make sure `value` never appears in log output from now on."""
    # Very short values would redact ordinary words; real secrets here are >= 24 chars.
    if value and len(value) >= 8:
        with _secrets_lock:
            _secrets.add(value)


def redact(text: str) -> str:
    with _secrets_lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        text = text.replace(secret, _REDACTED)
    return _BEARER.sub(lambda match: match.group(1) + _REDACTED, text)


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


def configure_logging(state_dir: Path, level: str) -> Path:
    """Log to the console and to a size-capped local file.

    Rotation (5 x 1 MB) bounds disk usage on hosts where the agent runs for months unattended.
    """
    log_dir = state_dir / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "agent.log"

    formatter = JsonFormatter()
    file_handler = RotatingFileHandler(
        log_file, maxBytes=1_000_000, backupCount=5, encoding="utf-8"
    )
    console_handler = logging.StreamHandler(sys.stderr)
    for handler in (file_handler, console_handler):
        handler.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers = [file_handler, console_handler]
    root.setLevel(level.upper())
    return log_file
