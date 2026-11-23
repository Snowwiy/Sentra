"""Cuotas de ingesta por identidad de agente autenticada (Fase 7D.2, hallazgo H06).

Problema: un agente comprometido o defectuoso podía enviar eventos, telemetría, inventario o
procesos sin límite y llenar la base, el motor de detección o el pool de conexiones. Solo el
alta de agentes y el lote de actividad tenían límite.

Diseño:
- Cubos de tokens (tasa sostenida + ráfaga acotada). Cada petición gasta, en una única
  transacción y de forma atómica, de varios cubos a la vez: peticiones del agente por clase
  de ruta, eventos y bytes del agente, y los mismos tres globales. Si cualquiera no alcanza,
  no se gasta de ninguno y se responde 429 con el Retry-After del cubo que más tarda.
- La clave es el agent_id DESPUÉS de autenticar su credencial (ver IngestGuard): sin token
  válido no se gasta el cupo de nadie, así que conocer un agent_id no permite dejar a ese
  agente sin cupo. Tampoco se usa la IP: varios agentes tras un NAT no comparten cuota.
- Dos almacenes con la misma interfaz, elegidos por RATE_LIMIT_BACKEND como el resto de
  limitadores: MemoryBucketStore (un único worker, desarrollo) y DatabaseBucketStore
  (tabla ingest_quota_buckets, migración 0052), compartido entre workers y procesos. Con
  varios workers el almacén en memoria NO es una garantía global: cada uno tendría su cupo.
- La concurrencia (peticiones simultáneas por agente y totales) se limita POR WORKER en
  memoria: su propósito es proteger los hilos y el pool de conexiones de ese proceso, que son
  locales por naturaleza. El tope global entre workers lo dan los cubos compartidos.
- El 429 llega antes de cualquier escritura de la petición: la idempotencia de siempre
  (sample_id, record_id, event_id) hace que el reenvío posterior del agente se procese
  normalmente, sin duplicados ni pérdidas.
"""

import math
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import UUID

from sqlalchemy import Engine, text

from app.core.config import Settings
from app.core.exceptions import RateLimitedError
from app.core.metrics import REGISTRY

# Clases de ruta con cubo de peticiones propio por agente. "control" agrupa heartbeat,
# rotación de credencial y comandos de Response: va aparte para que un agente que agota su
# cupo de datos siga latiendo y no aparezca offline por ello.
RouteClass = Literal["control", "telemetry", "events", "inventory", "processes", "activity"]
ROUTE_CLASSES: tuple[RouteClass, ...] = (
    "control",
    "telemetry",
    "events",
    "inventory",
    "processes",
    "activity",
)
# Las rutas de control no gastan de los cubos de eventos y bytes del agente ni de los globales
# (ver el comentario de RouteClass); sí del suyo de peticiones y de la concurrencia.
_CONTROL: RouteClass = "control"

# Espera sugerida cuando se rechaza por concurrencia: la petición en curso suele durar
# milisegundos, pero el agente aplica además su backoff con jitter.
CONCURRENCY_RETRY_AFTER = 2.0
# Claves vigiladas como máximo en memoria; por encima se descartan las más antiguas.
MAX_MEMORY_KEYS = 50_000
# Un cubo sin uso en este tiempo ya está lleno: su fila no aporta nada y se purga.
IDLE_PURGE_SECONDS = 86_400.0
PURGE_EVERY_SECONDS = 300.0


@dataclass(frozen=True)
class BucketSpec:
    """Tasa sostenida (unidades por segundo) y capacidad máxima (ráfaga) de un cubo."""

    rate: float
    capacity: float

    @classmethod
    def per_minute(cls, amount: int, burst_minutes: float) -> "BucketSpec | None":
        # 0 desactiva la dimensión: el operador puede quitar un límite sin quitar los demás.
        if amount <= 0:
            return None
        return cls(rate=amount / 60.0, capacity=amount * burst_minutes)


@dataclass(frozen=True)
class Charge:
    """Coste de una petición en un cubo. `reason` es la etiqueta del rechazo (métricas)."""

    key: str
    spec: BucketSpec
    cost: float
    reason: str

    @property
    def effective_cost(self) -> float:
        # Una petición mayor que la ráfaga entera nunca cabría: se cobra la capacidad
        # completa (solo pasa con el cubo lleno). El tamaño ya lo acotan MAX_REQUEST_BYTES y
        # los esquemas (500 eventos por lote).
        return min(self.cost, self.spec.capacity)


@dataclass(frozen=True)
class Decision:
    wait: float
    reason: str | None = None

    @property
    def allowed(self) -> bool:
        return self.reason is None


@dataclass(frozen=True)
class ThrottleState:
    """Rechazos recientes de un agente, para el panel (sin datos sensibles)."""

    rejected_total: int
    last_rejected_at: datetime


class BucketStore(Protocol):
    def consume(self, charges: Sequence[Charge]) -> Decision: ...

    def throttled(self, agent_ids: Sequence[UUID]) -> dict[UUID, ThrottleState]: ...


def _wait_for(charge: Charge, available: float) -> float:
    return max((charge.effective_cost - available) / charge.spec.rate, 0.0)


def _agent_from_key(key: str) -> UUID | None:
    # Claves "agent:<uuid>:<dimensión>"; las globales no tienen agente.
    parts = key.split(":")
    if len(parts) != 3 or parts[0] != "agent":
        return None
    try:
        return UUID(parts[1])
    except ValueError:
        return None


class MemoryBucketStore:
    """Cubos en la memoria del proceso: desarrollo y un único worker."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        # clave -> [tokens, instante de la última actualización]
        self._buckets: dict[str, list[float]] = {}
        self._throttle: dict[UUID, ThrottleState] = {}

    def _available(self, charge: Charge, now: float) -> float:
        state = self._buckets.get(charge.key)
        if state is None:
            return charge.spec.capacity
        tokens, updated = state
        return min(charge.spec.capacity, tokens + (now - updated) * charge.spec.rate)

    def consume(self, charges: Sequence[Charge]) -> Decision:
        with self._lock:
            now = self._clock()
            available = {charge.key: self._available(charge, now) for charge in charges}
            worst: Decision = Decision(0.0)
            for charge in charges:
                wait = _wait_for(charge, available[charge.key])
                if wait > worst.wait:
                    worst = Decision(wait, charge.reason)
            if worst.allowed:
                for charge in charges:
                    self._store(charge.key, available[charge.key] - charge.effective_cost, now)
            else:
                self._note_rejection(charges)
            return worst

    def _store(self, key: str, tokens: float, now: float) -> None:
        if key not in self._buckets and len(self._buckets) >= MAX_MEMORY_KEYS:
            # dict conserva el orden de inserción: se descarta el cubo más antiguo, que en el
            # peor caso vuelve lleno (más permisivo, nunca bloquea a un agente sano).
            self._buckets.pop(next(iter(self._buckets)))
        self._buckets[key] = [tokens, now]

    def _note_rejection(self, charges: Sequence[Charge]) -> None:
        agent = next((a for a in map(_agent_from_key, (c.key for c in charges)) if a), None)
        if agent is None:
            return
        previous = self._throttle.pop(agent, None)
        if len(self._throttle) >= MAX_MEMORY_KEYS:
            self._throttle.pop(next(iter(self._throttle)))
        total = previous.rejected_total + 1 if previous else 1
        self._throttle[agent] = ThrottleState(total, datetime.now(UTC))

    def throttled(self, agent_ids: Sequence[UUID]) -> dict[UUID, ThrottleState]:
        with self._lock:
            return {a: self._throttle[a] for a in agent_ids if a in self._throttle}


class DatabaseBucketStore:
    """Cubos en PostgreSQL (tabla ingest_quota_buckets): compartidos entre workers.

    - Una transacción corta y propia, independiente de la de la petición: lo gastado cuenta
      aunque la petición falle después (si no, un agente podría reintentar gratis peticiones
      que hacen trabajo y acaban en error).
    - Las filas se bloquean con FOR UPDATE en orden de clave: dos workers no pueden gastar a
      la vez el mismo cupo y no hay interbloqueos entre peticiones con cubos en común.
    - El tiempo es el de PostgreSQL (now()), igual para todos los workers.
    - Si PostgreSQL no responde, OperationalError se propaga (503): se falla cerrado.
    - Cada agente tiene como mucho 8 filas; las que llevan un día sin uso (cubo lleno) se
      purgan de forma oportunista, sin job aparte.
    """

    _ENSURE_SQL = text(
        "INSERT INTO ingest_quota_buckets (bucket_key, agent_id, tokens, updated_at)"
        " SELECT k.key, k.agent_id, k.capacity, now()"
        " FROM unnest(CAST(:keys AS text[]), CAST(:agents AS uuid[]),"
        " CAST(:capacities AS double precision[])) AS k(key, agent_id, capacity)"
        " ORDER BY k.key ON CONFLICT (bucket_key) DO NOTHING"
    )
    _LOCK_SQL = text(
        "SELECT bucket_key, tokens, GREATEST(EXTRACT(EPOCH FROM (now() - updated_at)), 0)"
        " FROM ingest_quota_buckets WHERE bucket_key = ANY(CAST(:keys AS text[]))"
        " ORDER BY bucket_key FOR UPDATE"
    )
    _SPEND_SQL = text(
        "UPDATE ingest_quota_buckets SET tokens = :tokens, updated_at = now()"
        " WHERE bucket_key = :key"
    )
    _REJECT_SQL = text(
        "UPDATE ingest_quota_buckets SET rejected_total = rejected_total + 1,"
        " last_rejected_at = now() WHERE bucket_key = :key"
    )

    def __init__(
        self, engine: Callable[[], Engine], clock: Callable[[], float] = time.monotonic
    ) -> None:
        self._engine = engine
        self._clock = clock
        self._last_purge: float | None = None
        self._purge_lock = threading.Lock()

    def consume(self, charges: Sequence[Charge]) -> Decision:
        by_key = {charge.key: charge for charge in charges}
        keys = sorted(by_key)
        with self._engine().begin() as conn:
            conn.execute(
                self._ENSURE_SQL,
                {
                    "keys": keys,
                    "agents": [_agent_from_key(k) for k in keys],
                    "capacities": [by_key[k].spec.capacity for k in keys],
                },
            )
            rows = conn.execute(self._LOCK_SQL, {"keys": keys}).all()
            available: dict[str, float] = {}
            for key, tokens, elapsed in rows:
                spec = by_key[key].spec
                available[key] = min(spec.capacity, float(tokens) + float(elapsed) * spec.rate)
            worst = Decision(0.0)
            worst_key: str | None = None
            for key in keys:
                charge = by_key[key]
                wait = _wait_for(charge, available.get(key, charge.spec.capacity))
                if wait > worst.wait:
                    worst, worst_key = Decision(wait, charge.reason), key
            if worst.allowed:
                conn.execute(
                    self._SPEND_SQL,
                    [
                        {
                            "key": k,
                            "tokens": available.get(k, by_key[k].spec.capacity)
                            - by_key[k].effective_cost,
                        }
                        for k in keys
                    ],
                )
            else:
                # Solo se anota el rechazo en el cubo que lo causó (estado para el panel);
                # los tokens no cambian: un rechazo no gasta.
                conn.execute(self._REJECT_SQL, {"key": worst_key})
        self._maybe_purge()
        return worst

    def throttled(self, agent_ids: Sequence[UUID]) -> dict[UUID, ThrottleState]:
        if not agent_ids:
            return {}
        with self._engine().connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT agent_id, SUM(rejected_total), MAX(last_rejected_at)"
                    " FROM ingest_quota_buckets WHERE agent_id = ANY(CAST(:ids AS uuid[]))"
                    " AND last_rejected_at IS NOT NULL GROUP BY agent_id"
                ),
                {"ids": list(agent_ids)},
            ).all()
        return {row[0]: ThrottleState(int(row[1]), row[2]) for row in rows}

    def _maybe_purge(self) -> None:
        now = self._clock()
        with self._purge_lock:
            if self._last_purge is not None and now - self._last_purge < PURGE_EVERY_SECONDS:
                return
            self._last_purge = now
        with self._engine().begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM ingest_quota_buckets"
                    " WHERE updated_at < now() - make_interval(secs => :idle)"
                    " AND (last_rejected_at IS NULL"
                    " OR last_rejected_at < now() - make_interval(secs => :idle))"
                ),
                {"idle": IDLE_PURGE_SECONDS},
            )


class ConcurrencyGate:
    """Peticiones de ingesta simultáneas por agente y totales, en ESTE worker.

    No espera: si no hay hueco, rechaza al momento (esperar retendría un hilo del pool, que
    es justo lo que se quiere proteger).
    """

    def __init__(self, per_agent: int, total: int) -> None:
        self._per_agent = per_agent
        self._total = total
        self._lock = threading.Lock()
        self._active: dict[UUID, int] = {}
        self._in_flight = 0

    @property
    def in_flight(self) -> int:
        return self._in_flight

    def enter_global(self) -> bool:
        with self._lock:
            if self._in_flight >= self._total:
                return False
            self._in_flight += 1
            return True

    def leave_global(self) -> None:
        with self._lock:
            self._in_flight = max(self._in_flight - 1, 0)

    def enter_agent(self, agent_id: UUID) -> bool:
        with self._lock:
            current = self._active.get(agent_id, 0)
            if current >= self._per_agent:
                return False
            self._active[agent_id] = current + 1
            return True

    def leave_agent(self, agent_id: UUID) -> None:
        with self._lock:
            current = self._active.get(agent_id, 0) - 1
            if current > 0:
                self._active[agent_id] = current
            else:
                # Sin entradas a cero: el diccionario solo crece con agentes activos ahora.
                self._active.pop(agent_id, None)


@dataclass(frozen=True)
class QuotaPolicy:
    enabled: bool
    agent_requests: BucketSpec | None
    agent_events: BucketSpec | None
    agent_bytes: BucketSpec | None
    global_requests: BucketSpec | None
    global_events: BucketSpec | None
    global_bytes: BucketSpec | None
    agent_max_concurrent: int
    global_max_concurrent: int

    @classmethod
    def from_settings(cls, settings: Settings) -> "QuotaPolicy":
        burst = settings.agent_quota_burst_minutes
        global_burst = settings.ingest_global_burst_minutes
        return cls(
            enabled=settings.agent_quota_enabled,
            agent_requests=BucketSpec.per_minute(settings.agent_quota_requests_per_minute, burst),
            agent_events=BucketSpec.per_minute(settings.agent_quota_events_per_minute, burst),
            agent_bytes=BucketSpec.per_minute(settings.agent_quota_bytes_per_minute, burst),
            global_requests=BucketSpec.per_minute(
                settings.ingest_global_requests_per_minute, global_burst
            ),
            global_events=BucketSpec.per_minute(
                settings.ingest_global_events_per_minute, global_burst
            ),
            global_bytes=BucketSpec.per_minute(
                settings.ingest_global_bytes_per_minute, global_burst
            ),
            agent_max_concurrent=settings.agent_quota_max_concurrent,
            global_max_concurrent=settings.ingest_max_concurrent,
        )

    def charges(
        self, agent_id: UUID, route: RouteClass, events: int, body_bytes: int
    ) -> list[Charge]:
        """Cubos de los que gasta una petición, con su coste en cada uno."""
        planned: list[tuple[str, BucketSpec | None, float, str]] = [
            (f"agent:{agent_id}:{route}", self.agent_requests, 1, "agent_requests")
        ]
        if route != _CONTROL:
            planned += [
                (f"agent:{agent_id}:events", self.agent_events, events, "agent_events"),
                (f"agent:{agent_id}:bytes", self.agent_bytes, body_bytes, "agent_bytes"),
                ("global:requests", self.global_requests, 1, "global_requests"),
                ("global:events", self.global_events, events, "global_events"),
                ("global:bytes", self.global_bytes, body_bytes, "global_bytes"),
            ]
        # Coste 0 (un lote sin eventos) no consulta el cubo: no hay nada que gastar.
        return [Charge(k, spec, c, r) for k, spec, c, r in planned if spec is not None and c > 0]


class IngestQuota:
    """Estado de cuotas de una aplicación (uno por create_app, en app.state.ingest_quota)."""

    def __init__(self, policy: QuotaPolicy, store: BucketStore) -> None:
        self.policy = policy
        self.store = store
        self.gate = ConcurrencyGate(policy.agent_max_concurrent, policy.global_max_concurrent)

    @classmethod
    def from_settings(
        cls, settings: Settings, backend: str, engine: Callable[[], Engine]
    ) -> "IngestQuota":
        store: BucketStore = (
            DatabaseBucketStore(engine) if backend == "database" else MemoryBucketStore()
        )
        return cls(QuotaPolicy.from_settings(settings), store)

    @contextmanager
    def slot(self) -> Iterator[None]:
        """Hueco global de este worker; se toma antes de autenticar (lo más barato primero)."""
        if not self.policy.enabled:
            yield
            return
        if not self.gate.enter_global():
            _reject("ingest", "global_concurrency", CONCURRENCY_RETRY_AFTER)
        try:
            yield
        finally:
            self.gate.leave_global()

    @contextmanager
    def admit(
        self, agent_id: UUID, route: RouteClass, *, events: int = 0, body_bytes: int = 0
    ) -> Iterator[None]:
        """Gasta el cupo de un agente YA autenticado o lanza 429 (RateLimitedError)."""
        if not self.policy.enabled:
            yield
            return
        if not self.gate.enter_agent(agent_id):
            _reject(route, "agent_concurrency", CONCURRENCY_RETRY_AFTER)
        try:
            decision = self.store.consume(self.policy.charges(agent_id, route, events, body_bytes))
            if not decision.allowed:
                _reject(route, decision.reason or "quota", decision.wait)
            yield
        finally:
            self.gate.leave_agent(agent_id)


def _reject(route: str, reason: str, wait: float) -> None:
    REGISTRY.ingest_rejected(route, reason)
    raise RateLimitedError(
        "Agent ingest quota exceeded, retry later",
        # Hacia arriba: Retry-After es un entero y un valor corto haría reintentar antes de
        # que el cubo tenga margen (RateLimitedError ya suma 1 s de colchón).
        math.ceil(wait),
        f"ingest_{reason}",
        details=[{"reason": reason}],
    )
