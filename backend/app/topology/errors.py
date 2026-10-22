"""Errores propios del motor de topología.

Viven aquí y no en app/core/exceptions.py para que el paquete sea autocontenido; el manejador
global de SentraError les da el sobre de error de Sentra igual que a los demás.
"""

from app.core.exceptions import NotFoundError, SentraError


class TopologyLinkNotFoundError(NotFoundError):
    # También para un enlace de otro site o un identificador mal formado (anti-IDOR).
    code = "topology_link_not_found"


class TopologyNodeNotFoundError(NotFoundError):
    # Clave mal formada, nodo de otro site, archivado o inexistente: misma respuesta, así no
    # se puede enumerar qué existe en otros sites.
    code = "topology_node_not_found"


class TopologyBuildFailedError(SentraError):
    # La reconstrucción falló por un error interno. Queda registrada como failed con un
    # código propio; la respuesta nunca incluye la traza ni el texto de la excepción.
    code = "topology_build_failed"
