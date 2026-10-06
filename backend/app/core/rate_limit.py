"""Limitadores de intentos (ventana deslizante por clave).

Se usan para el login (fuerza bruta de contraseñas), POST /agents/register (prueba de tokens
y claves de enrollment), la IA y, desde la Fase 4M, para las mutaciones y búsquedas del
dashboard por usuario.

Dos implementaciones con la misma interfaz:
- RateLimiter (memoria del proceso): desarrollo y un único worker. Reiniciar la API vacía
  los contadores y con N workers cada uno lleva el suyo (el límite efectivo se multiplica).
- DatabaseRateLimiter (Fase 4M, tabla rate_limit_hits): compartido entre workers y
  persistente tras reiniciar. Es la opción de producción (RATE_LIMIT_BACKEND=database o
  auto con ENVIRONMENT=production). Se eligió PostgreSQL en vez de Redis porque ya es una
  dependencia obligatoria, el volumen es mínimo (intentos de login, registros, llamadas a la
  IA) y así no se añade otro servicio que asegurar, respaldar y vigilar.
"""

import hashlib
import threading
import time
from collections import deque
from collections.abc import Callable
from typing import Protocol

from sqlalchemy import Engine, text

# Claves vigiladas como máximo; por encima se descartan las más antiguas para que un
# atacante que rota direcciones o usuarios no pueda agotar la memoria del servidor.
MAX_KEYS = 10_000


class Limiter(Protocol):
    max_events: int
    window: float

    def blocked_for(self, key: str) -> float:
        """Segundos hasta que la clave vuelva a tener margen (0 si no está bloqueada)."""
        ...

    def hit(self, key: str) -> None: ...

    def acquire(self, key: str) -> float:
        """Comprueba y cuenta en un solo paso: 0 si se contó, o los segundos a esperar."""
        ...

    def reset(self, key: str) -> None: ...


class RateLimiter:
    def __init__(
        self,
        max_events: int,
        window_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_events = max_events
        self.window = window_seconds
        self._clock = clock
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _prune(self, key: str, now: float) -> deque[float]:
        events = self._events.get(key)
        if events is None:
            return deque()
        while events and now - events[0] >= self.window:
            events.popleft()
        if not events:
            del self._events[key]
        return events

    def _wait(self, events: deque[float], now: float) -> float:
        if len(events) < self.max_events:
            return 0.0
        # Hay que esperar a que salga de la ventana el evento que deja margen para uno más.
        oldest_blocking = events[len(events) - self.max_events]
        return max(self.window - (now - oldest_blocking), 0.0)

    def blocked_for(self, key: str) -> float:
        with self._lock:
            now = self._clock()
            return self._wait(self._prune(key, now), now)

    def _record(self, key: str, events: deque[float], now: float) -> None:
        if key not in self._events:
            if len(self._events) >= MAX_KEYS:
                # dict conserva el orden de inserción: se descarta la clave más antigua.
                self._events.pop(next(iter(self._events)))
            self._events[key] = events
        events.append(now)

    def hit(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            self._record(key, self._prune(key, now), now)

    def acquire(self, key: str) -> float:
        with self._lock:
            now = self._clock()
            events = self._prune(key, now)
            wait = self._wait(events, now)
            if wait <= 0:
                self._record(key, events, now)
            return wait

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


# Cada cuánto (por proceso y ámbito) se borran las filas que ya salieron de la ventana.
PURGE_EVERY_SECONDS = 300.0


class DatabaseRateLimiter:
    """Ventana deslizante en PostgreSQL (tabla rate_limit_hits, migración 0024).

    - Una fila por intento; la clave se guarda como SHA-256 (usuarios e IPs no quedan en
      claro en una tabla operativa que nadie revisa).
    - La hora es la de PostgreSQL (now()), igual para todos los workers aunque sus relojes
      difieran.
    - `acquire` toma un advisory lock de transacción por clave: dos workers no pueden contar
      a la vez el mismo intento "con margen" y superar el límite.
    - Conexión propia y transacción corta, independiente de la petición: un intento fallido
      cuenta aunque la petición haga rollback.
    - Si PostgreSQL no responde se propaga OperationalError (503): se falla cerrado, nunca
      se deja pasar sin límite.
    """

    def __init__(
        self,
        scope: str,
        max_events: int,
        window_seconds: float,
        engine: Callable[[], Engine],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.scope = scope[:32]
        self.max_events = max_events
        self.window = window_seconds
        self._engine = engine
        self._clock = clock
        self._last_purge: float | None = None
        self._purge_lock = threading.Lock()

    def _key(self, key: str) -> str:
        return hashlib.sha256(f"{self.scope}\x00{key}".encode()).hexdigest()

    _WAIT_SQL = text(
        # Segundos hasta que salga de la ventana el intento que deja margen para uno más.
        "SELECT GREATEST(EXTRACT(EPOCH FROM (hit_at + make_interval(secs => :window)"
        " - now())), 0) FROM rate_limit_hits"
        " WHERE scope = :scope AND key_hash = :key"
        " AND hit_at > now() - make_interval(secs => :window)"
        " ORDER BY hit_at DESC OFFSET :offset LIMIT 1"
    )
    _INSERT_SQL = text("INSERT INTO rate_limit_hits (scope, key_hash) VALUES (:scope, :key)")

    def _params(self, key: str) -> dict[str, object]:
        return {
            "scope": self.scope,
            "key": self._key(key),
            "window": float(self.window),
            "offset": self.max_events - 1,
        }

    def blocked_for(self, key: str) -> float:
        with self._engine().connect() as conn:
            wait = conn.execute(self._WAIT_SQL, self._params(key)).scalar()
        return float(wait or 0.0)

    def hit(self, key: str) -> None:
        with self._engine().begin() as conn:
            conn.execute(self._INSERT_SQL, self._params(key))
        self._maybe_purge()

    def acquire(self, key: str) -> float:
        params = self._params(key)
        with self._engine().begin() as conn:
            conn.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope || :key, 0))"), params
            )
            wait = float(conn.execute(self._WAIT_SQL, params).scalar() or 0.0)
            if wait <= 0:
                conn.execute(self._INSERT_SQL, params)
        if wait <= 0:
            self._maybe_purge()
        return wait

    def reset(self, key: str) -> None:
        with self._engine().begin() as conn:
            conn.execute(
                text("DELETE FROM rate_limit_hits WHERE scope = :scope AND key_hash = :key"),
                self._params(key),
            )

    def _maybe_purge(self) -> None:
        # Sin job aparte: quien escribe limpia lo caducado de su ámbito como mucho cada
        # PURGE_EVERY_SECONDS por proceso. La tabla queda acotada al tráfico de una ventana.
        now = self._clock()
        with self._purge_lock:
            if self._last_purge is not None and now - self._last_purge < PURGE_EVERY_SECONDS:
                return
            self._last_purge = now
        with self._engine().begin() as conn:
            conn.execute(
                text(
                    "DELETE FROM rate_limit_hits WHERE scope = :scope"
                    " AND hit_at < now() - make_interval(secs => :window)"
                ),
                {"scope": self.scope, "window": float(self.window)},
            )


def make_limiter(
    backend: str,
    scope: str,
    max_events: int,
    window_seconds: float,
    engine: Callable[[], Engine],
) -> Limiter:
    """Limitador del backend configurado (memory o database) para un ámbito."""
    if backend == "database":
        return DatabaseRateLimiter(scope, max_events, window_seconds, engine)
    return RateLimiter(max_events, window_seconds)
