"""Identificador de la petición en curso, visible para cualquier log que se emita dentro.

Lo fija el middleware de peticiones (core/middleware.py); el filtro de logging lo añade a
cada línea y el manejador de errores lo devuelve en el cuerpo de un 500/503, así un operador
puede ir del error que ve el usuario a la traza del servidor y al log del reverse proxy.
"""

from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar("sentra_request_id", default=None)


def current_request_id() -> str | None:
    return request_id_var.get()
