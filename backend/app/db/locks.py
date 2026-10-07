"""Exclusión mutua entre procesos con advisory locks de PostgreSQL (Fase 4M).

Con varios workers de uvicorn, o una segunda instancia de la API arrancada por error, cada
proceso lanza sus propios jobs periódicos (offline sweeper, detección, riesgo, retención,
discovery programado). Repetirlos no corrompe datos (índices únicos, idempotencia), pero
duplica carga, alertas en carrera y scans de red. Un advisory lock por job garantiza que en
cada momento solo una ejecución trabaja; las demás se saltan esa vuelta.

Se eligió PostgreSQL y no Redis: ya es obligatorio, el lock muere con la conexión si el
proceso cae (no hay "lock huérfano" que limpiar) y no añade otro servicio.
"""

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, text

logger = logging.getLogger(__name__)

# Espacio de claves propio de Sentra (bigint). Cada job tiene la suya, fija: cambiarla
# permitiría que una versión vieja y una nueva corriesen el mismo job a la vez.
_BASE = 0x53_45_4E_54_00_00_00  # "SENT"
JOB_LOCK_KEYS: dict[str, int] = {
    "offline-sweeper": _BASE + 1,
    "detection-engine": _BASE + 2,
    "risk-engine": _BASE + 3,
    "retention": _BASE + 4,
    "discovery": _BASE + 5,
    # Fase 5B: evaluación de vulnerabilidades (_BASE + 6 es el lock de pruebas de reglas).
    "vulnerability-engine": _BASE + 7,
    # Fase 5C: sincronizaciones debidas de Threat Intelligence y matching incremental.
    "threat-intel": _BASE + 9,
}
# Prueba histórica de reglas (Fase 5A): lock de transacción, no de job. Limita a una sola
# prueba histórica concurrente en todo el despliegue para no saturar la base de datos.
RULE_TEST_LOCK_KEY = _BASE + 6
# Fase 5B: importación del catálogo de vulnerabilidades (lock de transacción): una sola
# importación a la vez, también entre la API y la CLI.
VULN_CATALOG_LOCK_KEY = _BASE + 8
# Fase 5C: una sincronización o importación a la vez POR FUENTE (lock de transacción). La
# clave es base + id de la fuente: fuentes distintas pueden sincronizar en paralelo.
THREAT_SOURCE_LOCK_BASE = _BASE + 0x10_000


def threat_source_lock_key(source_id: int) -> int:
    return THREAT_SOURCE_LOCK_BASE + source_id


@contextmanager
def singleton_lock(engine: Callable[[], Engine], key: int) -> Iterator[bool]:
    """True si este proceso obtuvo el lock `key` (y lo mantiene durante el bloque).

    Lock de sesión en una conexión dedicada: se libera al salir. Si la liberación falla, la
    conexión se invalida (se cierra de verdad) para que el lock no viaje al pool.
    """
    conn = engine().connect()
    try:
        acquired = bool(conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key}).scalar())
        conn.commit()
        try:
            yield acquired
        finally:
            if acquired:
                try:
                    conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                    conn.commit()
                except Exception:
                    logger.warning("could not release job lock; dropping connection", exc_info=True)
                    conn.invalidate()
    finally:
        conn.close()
