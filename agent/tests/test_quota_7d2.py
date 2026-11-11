"""Fase 7D.2 (H06): el agente frente a las cuotas de ingesta del servidor (429).

Un 429 es temporal: el agente conserva el buffer persistente y el cursor de eventos, espera
lo que pide Retry-After (con jitter y sin pasar de su tope), no se vuelve a enrolar y no
descarta su credencial. Cuando la cuota vuelve a tener margen, todo lo pendiente se entrega.
"""

import random
from typing import Any

import pytest

from sentra_agent.buffer import BUFFER_FILE
from sentra_agent.client import TransportError
from sentra_agent.runner import retry_delay
from tests.conftest import FakeApiState
from tests.test_runner import FakeEvents, build_agent, sample


def event(record_id: int) -> dict[str, Any]:
    return {
        "source": "windows_eventlog",
        "channel": "System",
        "record_id": record_id,
        "event_code": 7034,
        "provider": "Service Control Manager",
        "level": "error",
        "message": "service crashed",
        "occurred_at": "2026-11-09T00:00:00+00:00",
    }


def test_429_keeps_buffer_and_credential_and_recovers_later(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    config = make_config(url)
    cpus = iter([1.0, 2.0, 3.0])
    agent = build_agent(config, metrics=lambda: sample(next(cpus)))
    agent.cycle()
    token = agent.identity.token
    state.throttle_paths["/telemetry"] = "30"

    with pytest.raises(TransportError) as throttled:
        agent.cycle()

    assert throttled.value.status == 429
    assert throttled.value.retry_after == 30
    # La muestra sigue en el buffer (en memoria y en disco) y la credencial es la misma.
    assert len(agent.buffer) == 1
    agent.buffer.persist()
    assert (config.state_dir / BUFFER_FILE).exists()
    assert agent.identity.token == token
    assert state.paths().count("/agents/register") == 1

    # La cuota vuelve a tener margen: lo pendiente sale en orden y sin pérdidas.
    del state.throttle_paths["/telemetry"]
    agent.cycle()
    assert [t["cpu_percent"] for t in state.telemetry] == [1.0, 2.0, 3.0]
    assert not agent.buffer
    assert agent.identity.token == token


def test_429_on_events_does_not_advance_the_cursor(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    events = FakeEvents()
    agent = build_agent(make_config(url), events=events)
    agent.cycle()
    events.queue = [event(1), event(2)]
    state.throttle_paths["/events"] = "5"

    with pytest.raises(TransportError):
        agent._send_events(agent.identity.token or "", force=True)

    # Nada confirmado: los mismos eventos se vuelven a leer y enviar en el siguiente intento.
    assert events.committed == {}
    del state.throttle_paths["/events"]
    agent._send_events(agent.identity.token or "", force=True)
    assert [e["record_id"] for e in state.events] == [1, 2]
    assert events.committed == {"System": 2}


def test_heartbeat_still_works_while_data_routes_are_throttled(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    state.throttle_paths["/telemetry"] = "60"
    before = state.paths().count("/agents/heartbeat")

    with pytest.raises(TransportError):
        agent.cycle()

    # El heartbeat va primero y entra: el equipo no aparece offline por estar limitado.
    assert state.paths().count("/agents/heartbeat") == before + 1


def test_retry_delay_honors_retry_after_with_jitter_and_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(random, "uniform", lambda low, high: high)
    # Sin Retry-After: el backoff de siempre (intervalo 30 s, primer fallo).
    assert retry_delay(1, 30, 900, None) == pytest.approx(36.0)
    # Retry-After 120: al menos 120 s y como mucho un 25 % más, para no volver en bloque.
    assert retry_delay(1, 30, 900, 120) == pytest.approx(150.0)
    monkeypatch.setattr(random, "uniform", lambda low, high: low)
    assert retry_delay(1, 30, 900, 120) == pytest.approx(120.0)
    # Nunca por encima del tope del agente, pida lo que pida el servidor.
    assert retry_delay(1, 30, 900, 3600) == 900


def test_run_loop_waits_at_least_retry_after_on_429(
    fake_api: tuple[str, FakeApiState], make_config: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url))
    agent.cycle()
    state.throttle_paths["/telemetry"] = "200"
    waits: list[float] = []

    def fake_wait(delay: float) -> bool:
        waits.append(delay)
        agent.stop_event.set()
        return True

    monkeypatch.setattr(agent.stop_event, "wait", fake_wait)
    agent.run()

    assert len(waits) == 1
    assert 200 <= waits[0] <= min(250, agent.config.max_backoff_seconds)
    assert len(agent.buffer) == 1
