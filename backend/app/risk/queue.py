"""Cola de recálculo de riesgo: lo único que necesitan los productores de cambios.

Módulo mínimo (solo el modelo) para que el motor de detección, discovery o el flujo del
analista puedan avisar sin importar el Risk Engine completo ni crear ciclos de imports.
"""

import logging
from collections.abc import Iterable
from datetime import UTC, datetime

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.risk import AssetRisk

logger = logging.getLogger(__name__)


def request_recalculation(session: Session, asset_ids: Iterable[int]) -> None:
    """Encola el recálculo de estos activos (sin commit; va en la transacción de quien llama).

    Barato a propósito (un INSERT ... ON CONFLICT): se llama desde el motor de detección,
    el flujo del analista y discovery. Conserva el `dirty_at` más antiguo para que un activo
    que recibe avisos continuos no se quede siempre al final de la cola. Va en un SAVEPOINT
    y nunca lanza: si falla, el refresco periódico del job lo recalculará igualmente.
    """
    ids = sorted({asset_id for asset_id in asset_ids if asset_id is not None})
    if not ids:
        return
    now = datetime.now(UTC)
    stmt = insert(AssetRisk).values([{"asset_id": asset_id, "dirty_at": now} for asset_id in ids])
    stmt = stmt.on_conflict_do_update(
        index_elements=[AssetRisk.asset_id],
        set_={"dirty_at": func.coalesce(AssetRisk.dirty_at, stmt.excluded.dirty_at)},
    )
    try:
        with session.begin_nested():
            session.execute(stmt)
    except Exception:
        logger.exception("could not queue risk recalculation", extra={"assets": len(ids)})
