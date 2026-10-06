"""Cola de evaluación de vulnerabilidades: lo único que necesitan los productores de cambios.

Igual que app/risk/queue.py: módulo mínimo (solo el modelo) para que la ingesta de
inventario, el heartbeat (cambio de SO), discovery (puertos), el contexto de negocio o la
importación del catálogo avisen sin importar el motor y sin ciclos de imports.

Marcar es barato (un INSERT ... ON CONFLICT) y nunca evalúa en la petición: el job
`vulnerability-engine` procesa la cola por lotes. Nunca se marca en cada heartbeat: solo
cuando cambia algo que puede cambiar el resultado.
"""

import logging
from collections.abc import Iterable, Sequence
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.vulnerability import AssetVulnerabilityState, VulnerabilityFinding

logger = logging.getLogger(__name__)

DirtyReason = Literal[
    "initial",
    "inventory",
    "os_change",
    "exposure",
    "context",
    "catalog",
    "manual",
    "refresh",
    "merge",
]


# Activos por sentencia al encolar (3 parámetros por fila).
MARK_CHUNK = 1000


def _upsert(ids: Sequence[int], now: datetime, reason: DirtyReason) -> Any:
    stmt = insert(AssetVulnerabilityState).values(
        [{"asset_id": asset_id, "dirty_at": now, "dirty_reason": reason} for asset_id in ids]
    )
    return stmt.on_conflict_do_update(
        index_elements=[AssetVulnerabilityState.asset_id],
        set_={
            "dirty_at": func.coalesce(AssetVulnerabilityState.dirty_at, stmt.excluded.dirty_at),
            # El motivo más reciente gana salvo "inventory", que obliga a comparar la huella.
            "dirty_reason": func.coalesce(
                func.nullif(AssetVulnerabilityState.dirty_reason, "inventory"),
                stmt.excluded.dirty_reason,
            ),
        },
    )


def mark_dirty(session: Session, asset_ids: Iterable[int], reason: DirtyReason) -> None:
    """Encola la evaluación de estos activos (sin commit; en la transacción de quien llama).

    Conserva el `dirty_at` más antiguo (un activo con avisos continuos no se queda siempre
    al final). Va en un SAVEPOINT y nunca lanza: si falla, el refresco periódico del job lo
    evaluará igualmente.
    """
    ids = sorted({asset_id for asset_id in asset_ids if asset_id is not None})
    if not ids:
        return
    now = datetime.now(UTC)
    try:
        with session.begin_nested():
            # Por trozos: un único INSERT con todos los activos ("Reevaluar todo" con 10 000)
            # superaría el máximo de 65 535 parámetros por sentencia de PostgreSQL.
            for start in range(0, len(ids), MARK_CHUNK):
                session.execute(_upsert(ids[start : start + MARK_CHUNK], now, reason))
    except Exception:
        logger.exception("could not queue vulnerability evaluation", extra={"assets": len(ids)})


def mark_catalog_change(
    session: Session, keys: Sequence[str], vulnerability_ids: Sequence[int]
) -> int:
    """Catálogo actualizado: encola SOLO los activos afectados (sin commit).

    - activos cuyo inventario tiene alguna de las claves de producto cambiadas (índice GIN
      sobre product_keys, operador &&);
    - activos con findings de los registros cambiados (un rango que deja de afectar o una
      entrada eliminada resuelve findings aunque la clave ya no esté en el registro).
    """
    now = datetime.now(UTC)
    total = 0
    if keys:
        result = session.execute(
            update(AssetVulnerabilityState)
            .where(AssetVulnerabilityState.product_keys.overlap(sorted(set(keys))))
            .values(
                dirty_at=func.coalesce(AssetVulnerabilityState.dirty_at, now),
                dirty_reason="catalog",
            )
        )
        total += int(getattr(result, "rowcount", 0) or 0)
    if vulnerability_ids:
        assets = (
            select(VulnerabilityFinding.asset_id)
            .where(VulnerabilityFinding.vulnerability_id.in_(sorted(set(vulnerability_ids))))
            .distinct()
            .scalar_subquery()
        )
        result = session.execute(
            update(AssetVulnerabilityState)
            .where(
                AssetVulnerabilityState.asset_id.in_(assets),
                AssetVulnerabilityState.dirty_at.is_(None),
            )
            .values(dirty_at=now, dirty_reason="catalog")
        )
        total += int(getattr(result, "rowcount", 0) or 0)
    return total
