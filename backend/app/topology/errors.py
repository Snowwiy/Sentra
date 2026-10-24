"""Errores propios del motor de topología.

Viven aquí y no en app/core/exceptions.py para que el paquete sea autocontenido; el manejador
global de SentraError les da el sobre de error de Sentra igual que a los demás.
"""

from app.core.exceptions import ConflictError, NotFoundError, RateLimitedError, SentraError


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


# --- Fase 6E.1: historial ---------------------------------------------------------------------


class TopologySnapshotNotFoundError(NotFoundError):
    # Snapshot inexistente, de otro site o ningún snapshot anterior al instante pedido.
    code = "topology_snapshot_not_found"


class TopologyHistoryNotFoundError(NotFoundError):
    # El nodo o enlace no aparece en ningún snapshot del site.
    code = "topology_history_not_found"


class NetworkChangeNotFoundError(NotFoundError):
    code = "network_change_not_found"


class NetworkChangeConflictError(ConflictError):
    # La revisión cambió desde que el cliente la leyó (`version` obsoleta).
    code = "network_change_conflict"


class TopologyRebuildCooldownError(RateLimitedError):
    # Reconstrucción manual demasiado seguida (TOPOLOGY_MANUAL_REBUILD_COOLDOWN_SECONDS).
    # 429 con Retry-After: el admin sabe cuándo puede repetir.
    code = "topology_rebuild_cooldown"
