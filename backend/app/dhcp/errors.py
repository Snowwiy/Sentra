"""Errores de las fuentes DHCP (Fase 6E.2). El manejador global les da el sobre de Sentra."""

from typing import Any

from fastapi import status

from app.core.exceptions import ConflictError, NotFoundError, SentraError


class DhcpSourceNotFoundError(NotFoundError):
    # También para una fuente de otro site o un identificador inexistente (anti-IDOR).
    code = "dhcp_source_not_found"


class DhcpSourceConflictError(ConflictError):
    def __init__(self, code: str, message: str, details: list[dict[str, Any]] | None = None):
        super().__init__(message, details)
        self.code = code


class DhcpImportError(SentraError):
    status_code = status.HTTP_422_UNPROCESSABLE_CONTENT

    def __init__(self, code: str, message: str, details: list[dict[str, Any]] | None = None):
        super().__init__(message, details)
        self.code = code
