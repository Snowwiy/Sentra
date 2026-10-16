"""Spool durable (SQLite) de envíos pendientes: lotes de resultados y cierres de job.

Por qué SQLite y no un JSON que crece: escrituras transaccionales (un corte de luz no deja
el fichero a medias), borrado eficiente de lo ya entregado y consultas por job sin cargar
todo en memoria. El sensor puede pasar horas sin servidor (WAN caída en el site) y lo
observado no debe perderse, pero tampoco puede llenar el disco del host: el spool está
acotado en elementos, bytes y antigüedad, y al llenarse descarta lo más antiguo (y lo
registra en el log y en un contador).

Semántica at-least-once: cada elemento lleva un batch_id estable que se reenvía idéntico en
cada reintento; el servidor deduplica. El orden es FIFO por job: un "complete" nunca se
envía antes que los lotes de su job.
"""

import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentra_sensor.fsperm import make_private_dir, make_private_file

logger = logging.getLogger("sentra_sensor.spool")

KIND_RESULTS = "results"
KIND_COMPLETE = "complete"
KINDS = frozenset({KIND_RESULTS, KIND_COMPLETE})

_SCHEMA = """
CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    batch_id TEXT,
    payload BLOB NOT NULL,
    size INTEGER NOT NULL,
    created_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt_at REAL NOT NULL DEFAULT 0,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS items_job ON items (job_id, id);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL);
"""


@dataclass(frozen=True)
class SpoolItem:
    id: int
    job_id: str
    kind: str
    batch_id: str | None
    payload: dict[str, Any]
    size: int
    created_at: float
    attempts: int
    next_attempt_at: float


@dataclass(frozen=True)
class SpoolStats:
    items: int
    bytes: int
    dropped_total: int
    oldest_created_at: float | None


class Spool:
    def __init__(
        self,
        path: Path,
        max_bytes: int,
        max_items: int,
        max_age_seconds: float,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.max_items = max_items
        self.max_age_seconds = max_age_seconds
        self._clock = clock
        self._lock = threading.Lock()
        make_private_dir(path.parent)
        if not path.exists():
            # Se crea con 0600 antes de que SQLite lo abra: las observaciones describen la red
            # interna del site y no deben ser legibles por otros usuarios del host.
            os.close(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600))
        # También si ya existía (más abierto) y en Windows, donde lo que protege es la DACL.
        make_private_file(path)
        # check_same_thread=False: el hilo del scan encola y el bucle principal envía; el
        # acceso se serializa con self._lock.
        self._db = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        try:
            self._db.execute("PRAGMA auto_vacuum=INCREMENTAL")
            self._db.execute("PRAGMA journal_mode=WAL")
            # FULL: un lote confirmado en el spool sobrevive a un corte de luz.
            self._db.execute("PRAGMA synchronous=FULL")
            self._db.executescript(_SCHEMA)
            # -wal y -shm contienen las mismas observaciones. SQLite los crea con el modo del
            # fichero principal (POSIX) o heredando la DACL del directorio (Windows); se
            # comprueban igualmente de forma explícita.
            for suffix in ("-wal", "-shm"):
                aux = path.with_name(path.name + suffix)
                if aux.exists():
                    make_private_file(aux)
        except BaseException:
            # Un spool corrupto o no protegible hace fallar el arranque; la conexión ya
            # abierta se cierra aquí porque nadie recibirá el objeto para cerrarla.
            self._db.close()
            raise

    def close(self) -> None:
        # Idempotente: sqlite3 admite cerrar dos veces y no pierde nada confirmado (cada
        # enqueue/ack es una transacción autocommit con synchronous=FULL).
        with self._lock:
            self._db.close()

    # --- escritura --------------------------------------------------------------------

    def enqueue(
        self, job_id: str, kind: str, payload: dict[str, Any], batch_id: str | None = None
    ) -> int | None:
        """Guarda un envío pendiente. Devuelve su id, o None si no cabe nunca."""
        if kind not in KINDS:
            raise ValueError(f"unknown spool kind {kind!r}")
        data = json.dumps(payload, separators=(",", ":")).encode()
        if len(data) > self.max_bytes:
            logger.error(
                "spool item larger than the whole spool, dropped",
                extra={"job_id": job_id, "kind": kind, "size": len(data)},
            )
            self._bump_dropped(1)
            return None
        now = self._clock()
        with self._lock:
            cursor = self._db.execute(
                "INSERT INTO items (job_id, kind, batch_id, payload, size, created_at,"
                " next_attempt_at) VALUES (?, ?, ?, ?, ?, ?, 0)",
                (job_id, kind, batch_id, data, len(data), now),
            )
            item_id = cursor.lastrowid
        self.enforce_limits()
        return int(item_id) if item_id is not None else None

    def enforce_limits(self) -> int:
        """Aplica edad, nº de elementos y bytes. Devuelve cuántos elementos descartó."""
        now = self._clock()
        dropped = 0
        with self._lock:
            cursor = self._db.execute(
                "DELETE FROM items WHERE created_at < ?", (now - self.max_age_seconds,)
            )
            expired = cursor.rowcount
            if expired:
                logger.warning(
                    "spool items expired by age, dropped",
                    extra={"dropped": expired, "max_age_seconds": self.max_age_seconds},
                )
            dropped += expired
            while True:
                count, total = self._db.execute(
                    "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM items"
                ).fetchone()
                if count <= self.max_items and total <= self.max_bytes:
                    break
                # Lo más antiguo primero: lo reciente describe mejor el estado actual de la red.
                row = self._db.execute(
                    "SELECT id, job_id, kind FROM items ORDER BY id LIMIT 1"
                ).fetchone()
                self._db.execute("DELETE FROM items WHERE id = ?", (row[0],))
                dropped += 1
                logger.warning(
                    "spool full, oldest item dropped",
                    extra={"job_id": row[1], "kind": row[2], "items": count, "bytes": total},
                )
            if dropped:
                self._db.execute("PRAGMA incremental_vacuum")
        if dropped:
            self._bump_dropped(dropped)
        return dropped

    def _bump_dropped(self, count: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO meta (key, value) VALUES ('dropped_total', ?)"
                " ON CONFLICT(key) DO UPDATE SET value = value + excluded.value",
                (count,),
            )

    def ack(self, item_id: int) -> None:
        """Entregado (o duplicado ya conocido por el servidor): se borra."""
        with self._lock:
            self._db.execute("DELETE FROM items WHERE id = ?", (item_id,))

    def discard(self, item: SpoolItem, reason: str) -> None:
        """Descartado sin entregar (job terminado/caducado/inexistente). Queda en el log."""
        logger.warning(
            "spool item discarded",
            extra={"job_id": item.job_id, "kind": item.kind, "reason": reason},
        )
        self.ack(item.id)
        self._bump_dropped(1)

    def defer(self, item_id: int, delay: float, error: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE items SET attempts = attempts + 1, next_attempt_at = ?, last_error = ?"
                " WHERE id = ?",
                (self._clock() + delay, error[:200], item_id),
            )

    def reset_backoff(self) -> None:
        with self._lock:
            self._db.execute("UPDATE items SET next_attempt_at = 0 WHERE next_attempt_at > 0")

    # --- lectura ----------------------------------------------------------------------

    def heads(self) -> list[SpoolItem]:
        """Primer elemento pendiente de cada job, en orden de llegada (FIFO por job)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, job_id, kind, batch_id, payload, size, created_at, attempts,"
                " next_attempt_at FROM items"
                " WHERE id IN (SELECT MIN(id) FROM items GROUP BY job_id) ORDER BY id"
            ).fetchall()
        return [
            SpoolItem(
                id=row[0],
                job_id=row[1],
                kind=row[2],
                batch_id=row[3],
                payload=json.loads(row[4]),
                size=row[5],
                created_at=row[6],
                attempts=row[7],
                next_attempt_at=row[8],
            )
            for row in rows
        ]

    def next_due(self, skip_jobs: set[str] | None = None) -> SpoolItem | None:
        now = self._clock()
        for item in self.heads():
            if skip_jobs and item.job_id in skip_jobs:
                continue
            if item.next_attempt_at <= now:
                return item
        return None

    def next_attempt_time(self) -> float | None:
        heads = self.heads()
        return min((h.next_attempt_at for h in heads), default=None)

    def items_for_job(self, job_id: str) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM items WHERE job_id = ?", (job_id,))
            return int(row.fetchone()[0])

    def stats(self) -> SpoolStats:
        with self._lock:
            count, total, oldest = self._db.execute(
                "SELECT COUNT(*), COALESCE(SUM(size), 0), MIN(created_at) FROM items"
            ).fetchone()
            row = self._db.execute("SELECT value FROM meta WHERE key = 'dropped_total'").fetchone()
        return SpoolStats(int(count), int(total), int(row[0]) if row else 0, oldest)
