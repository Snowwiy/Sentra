"""Redacción de secretos en logs y rotación."""

import logging
from pathlib import Path

from sentra_sensor.logs import JsonFormatter, configure_logging, redact, register_secret


def test_redacts_registered_secrets_and_headers() -> None:
    register_secret("super-secret-credential-value")
    text = redact(
        "boom super-secret-credential-value Authorization: Bearer abc.def-123 "
        '{"credential": "zzz-other", "X-Sensor-Enrollment-Token": "tok-999"}'
    )
    assert "super-secret-credential-value" not in text
    assert "abc.def-123" not in text
    assert "zzz-other" not in text
    assert "tok-999" not in text


def test_formatter_redacts_extra_fields() -> None:
    register_secret("another-secret-12345")
    record = logging.LogRecord("x", logging.INFO, "f", 1, "msg %s", ("another-secret-12345",), None)
    record.header = "Bearer qwerty123456"
    line = JsonFormatter().format(record)
    assert "another-secret-12345" not in line and "qwerty123456" not in line


def test_configure_logging_rotates(tmp_path: Path) -> None:
    log_file = configure_logging(tmp_path / "logs", "INFO", console=False)
    handler = logging.getLogger().handlers[0]
    assert log_file.parent.is_dir()
    assert getattr(handler, "maxBytes", 0) == 1_000_000
    assert getattr(handler, "backupCount", 0) == 5
    logging.getLogger().handlers = []
