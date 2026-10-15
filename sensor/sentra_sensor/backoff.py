"""Backoff exponencial con jitter.

El jitter evita que muchos sensores que perdieron el servidor a la vez (corte de la WAN del
servidor, reinicio) vuelvan todos en el mismo segundo y lo tumben de nuevo.
"""

import random

_rng = random.SystemRandom()


def backoff_delay(
    attempts: int,
    base: float,
    cap: float,
    retry_after: float | None = None,
    rng: random.Random | None = None,
) -> float:
    """Espera antes del reintento número `attempts` (1 = primer reintento).

    "Equal jitter": la mitad fija garantiza que el retraso crece de verdad, la otra mitad
    aleatoria desincroniza a los sensores. Nunca supera `cap`; si el servidor pidió
    Retry-After se respeta como mínimo (también acotado por `cap`).
    """
    exponent = max(0, min(attempts - 1, 30))
    delay = min(cap, base * (2**exponent))
    jittered = delay / 2 + (rng or _rng).uniform(0, delay / 2)
    if retry_after is not None:
        jittered = max(jittered, min(retry_after, cap))
    return float(min(jittered, cap))
