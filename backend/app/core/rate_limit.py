"""Limitador de intentos en memoria (ventana deslizante por clave).

Se usa para el login (fuerza bruta de contraseñas) y para POST /agents/register (prueba
de tokens/claves de enrollment). En memoria del proceso a propósito: Sentra corre como un
único proceso de API y no usa Redis; si algún día corre con varios workers, cada uno lleva
su propio contador (el límite efectivo se multiplica) y habría que moverlo a PostgreSQL.

Reiniciar la API vacía los contadores. Es aceptable: un atacante no puede reiniciar el
servidor, y el operador bloqueado por error puede hacerlo.
"""

import threading
import time
from collections import deque
from collections.abc import Callable

# Claves vigiladas como máximo; por encima se descartan las más antiguas para que un
# atacante que rota direcciones o usuarios no pueda agotar la memoria del servidor.
MAX_KEYS = 10_000


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

    def blocked_for(self, key: str) -> float:
        """Segundos hasta que la clave vuelva a tener margen (0 si no está bloqueada)."""
        with self._lock:
            now = self._clock()
            events = self._prune(key, now)
            if len(events) < self.max_events:
                return 0.0
            return max(self.window - (now - events[0]), 0.0)

    def hit(self, key: str) -> None:
        with self._lock:
            now = self._clock()
            events = self._prune(key, now)
            if key not in self._events:
                if len(self._events) >= MAX_KEYS:
                    # dict conserva el orden de inserción: se descarta la clave más antigua.
                    self._events.pop(next(iter(self._events)))
                self._events[key] = events
            events.append(now)

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)
