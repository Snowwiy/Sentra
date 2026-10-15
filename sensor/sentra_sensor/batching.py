"""Construcción de lotes de resultados respetando los límites del servidor.

Cada lote cumple a la vez max_observations_per_batch y max_batch_bytes (medidos sobre el
JSON compacto exacto que se enviará), así el servidor nunca tiene que responder 413 y no
se reintenta para siempre algo que jamás cabría. El batch_id se genera UNA vez al encolar
y viaja en el payload guardado: los reintentos reenvían el mismo id (idempotencia).
"""

import json
import logging
import threading
import uuid
from collections.abc import Callable
from typing import Any

from sentra_sensor.spool import KIND_COMPLETE, KIND_RESULTS, Spool

logger = logging.getLogger("sentra_sensor.batching")

_SEPARATORS = (",", ":")


def _dumps(value: Any) -> str:
    return json.dumps(value, separators=_SEPARATORS)


class BatchBuilder:
    def __init__(
        self,
        spool: Spool,
        job_id: str,
        attempt: int,
        max_observations: int,
        max_bytes: int,
        on_enqueue: Callable[[], None] | None = None,
    ) -> None:
        self._spool = spool
        self._job_id = job_id
        self._attempt = attempt
        self._max_observations = max_observations
        self._max_bytes = max_bytes
        self._on_enqueue = on_enqueue
        self._current: list[dict[str, Any]] = []
        self._current_bytes = 0
        # Tamaño del sobre vacío con un batch_id real (36 caracteres) y el attempt de verdad.
        self._overhead = len(
            _dumps({"batch_id": str(uuid.UUID(int=0)), "attempt": attempt, "observations": []})
        )
        self._lock = threading.Lock()
        self.batches_enqueued = 0
        self.observations_enqueued = 0
        self.errors: list[str] = []

    def add(self, observations: list[dict[str, Any]]) -> None:
        with self._lock:
            for observation in observations:
                size = len(_dumps(observation).encode())
                if self._overhead + size > self._max_bytes:
                    # Una sola observación no cabe ni sola: se descarta en vez de bloquear el job.
                    self.errors.append(f"observation too large: {observation.get('address')}")
                    continue
                extra = size + (1 if self._current else 0)  # coma separadora
                if self._current and (
                    len(self._current) >= self._max_observations
                    or self._overhead + self._current_bytes + extra > self._max_bytes
                ):
                    self._flush_locked()
                    extra = size
                self._current.append(observation)
                self._current_bytes += extra

    def flush(self) -> None:
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        if not self._current:
            return
        batch_id = str(uuid.uuid4())
        payload = {"batch_id": batch_id, "attempt": self._attempt, "observations": self._current}
        if self._spool.enqueue(self._job_id, KIND_RESULTS, payload, batch_id) is not None:
            self.batches_enqueued += 1
            self.observations_enqueued += len(self._current)
        self._current = []
        self._current_bytes = 0
        if self._on_enqueue is not None:
            self._on_enqueue()


def enqueue_complete(
    spool: Spool,
    job_id: str,
    attempt: int,
    outcome: str,
    *,
    hosts_scanned: int = 0,
    hosts_checked: int = 0,
    probes: int = 0,
    unprobed: list[str] | None = None,
    errors: list[str] | None = None,
    batches_sent: int = 0,
) -> int | None:
    # Límites del contrato: unprobed ≤ 4096 y errors ≤ 50 (cada error, corto).
    payload = {
        "attempt": attempt,
        "outcome": outcome,
        "hosts_scanned": hosts_scanned,
        "hosts_checked": hosts_checked,
        "probes": probes,
        "unprobed": (unprobed or [])[:4096],
        "errors": [e[:200] for e in (errors or [])][:50],
        "batches_sent": batches_sent,
    }
    return spool.enqueue(job_id, KIND_COMPLETE, payload)
