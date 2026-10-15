"""Spool durable: límites, orden FIFO por job, persistencia, backoff."""

import logging
import random
from pathlib import Path

import pytest

from sentra_sensor.backoff import backoff_delay
from sentra_sensor.spool import KIND_COMPLETE, KIND_RESULTS, Spool
from tests.conftest import FakeClock
from tests.privacy import assert_private


def make_spool(path: Path, clock: FakeClock, **limits: float) -> Spool:
    return Spool(
        path,
        max_bytes=int(limits.get("max_bytes", 1_000_000)),
        max_items=int(limits.get("max_items", 1000)),
        max_age_seconds=limits.get("max_age", 3600),
        clock=clock,
    )


def test_fifo_per_job_and_persistence(tmp_path: Path) -> None:
    clock = FakeClock()
    path = tmp_path / "spool.db"
    spool = make_spool(path, clock)
    spool.enqueue("job-a", KIND_RESULTS, {"n": 1}, "b1")
    spool.enqueue("job-b", KIND_RESULTS, {"n": 2}, "b2")
    spool.enqueue("job-a", KIND_COMPLETE, {"n": 3})
    spool.close()

    reopened = make_spool(path, clock)  # "reinicio" del proceso
    heads = reopened.heads()
    assert [(h.job_id, h.payload["n"]) for h in heads] == [("job-a", 1), ("job-b", 2)]
    first = reopened.next_due()
    assert first is not None and first.batch_id == "b1"
    reopened.ack(first.id)
    assert [h.payload["n"] for h in reopened.heads()] == [2, 3]
    assert reopened.stats().items == 2


def test_deferred_head_blocks_its_job_only(tmp_path: Path) -> None:
    clock = FakeClock()
    spool = make_spool(tmp_path / "s.db", clock)
    a1 = spool.enqueue("a", KIND_RESULTS, {"n": 1})
    spool.enqueue("a", KIND_COMPLETE, {"n": 2})
    spool.enqueue("b", KIND_RESULTS, {"n": 3})
    assert a1 is not None
    spool.defer(a1, 30, "boom")
    item = spool.next_due()
    assert item is not None and item.job_id == "b"  # "a" espera; su complete no adelanta
    assert spool.next_attempt_time() == 0  # b sigue vencido
    spool.ack(item.id)
    assert spool.next_due() is None
    assert spool.next_attempt_time() == clock.now + 30
    clock.advance(31)
    item = spool.next_due()
    assert item is not None and item.payload == {"n": 1} and item.attempts == 1


def test_max_items_drops_oldest(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    spool = make_spool(tmp_path / "s.db", FakeClock(), max_items=3)
    with caplog.at_level(logging.WARNING):
        for n in range(5):
            spool.enqueue("j", KIND_RESULTS, {"n": n})
    assert [h.payload["n"] for h in spool.heads()] == [2]
    assert spool.stats().items == 3 and spool.stats().dropped_total == 2
    assert "oldest item dropped" in caplog.text


def test_max_bytes_bound(tmp_path: Path) -> None:
    spool = make_spool(tmp_path / "s.db", FakeClock(), max_bytes=2000)
    for n in range(20):
        spool.enqueue("j", KIND_RESULTS, {"n": n, "pad": "x" * 300})
    stats = spool.stats()
    assert stats.bytes <= 2000 and stats.dropped_total > 0
    # Un elemento mayor que todo el spool no se guarda (nunca podría caber).
    assert spool.enqueue("j", KIND_RESULTS, {"pad": "y" * 5000}) is None


def test_max_age(tmp_path: Path) -> None:
    clock = FakeClock()
    spool = make_spool(tmp_path / "s.db", clock, max_age=60)
    spool.enqueue("j", KIND_RESULTS, {"n": 1})
    clock.advance(61)
    spool.enqueue("j", KIND_RESULTS, {"n": 2})
    assert [h.payload["n"] for h in spool.heads()] == [2]
    assert spool.stats().items == 1


def test_spool_file_is_private(tmp_path: Path) -> None:
    spool = make_spool(tmp_path / "s.db", FakeClock())
    spool.enqueue("j", KIND_RESULTS, {"n": 1})
    assert_private(spool.path)
    # Los ficheros auxiliares de WAL contienen las mismas observaciones.
    for suffix in ("-wal", "-shm"):
        assert_private(spool.path.with_name(spool.path.name + suffix))
    spool.close()


def test_reset_backoff(tmp_path: Path) -> None:
    clock = FakeClock()
    spool = make_spool(tmp_path / "s.db", clock)
    item_id = spool.enqueue("j", KIND_RESULTS, {"n": 1})
    assert item_id is not None
    spool.defer(item_id, 300, "down")
    assert spool.next_due() is None
    spool.reset_backoff()
    assert spool.next_due() is not None


def test_unknown_kind_rejected(tmp_path: Path) -> None:
    spool = make_spool(tmp_path / "s.db", FakeClock())
    with pytest.raises(ValueError):
        spool.enqueue("j", "exec", {})


def test_backoff_grows_with_jitter_and_cap() -> None:
    rng = random.Random(7)  # noqa: S311  (determinista para el test)
    delays = [backoff_delay(n, 5, 300, rng=rng) for n in range(1, 12)]
    assert 2.5 <= delays[0] <= 5
    assert 5 <= delays[1] <= 10
    assert all(d <= 300 for d in delays)
    assert delays[-1] >= 150  # alcanzó el tope (mitad fija)
    assert backoff_delay(1, 5, 300, retry_after=120, rng=rng) >= 120
    assert backoff_delay(1, 5, 300, retry_after=10_000, rng=rng) == 300
    # Jitter: dos sensores con el mismo número de fallos no reintentan a la vez.
    assert len({round(backoff_delay(6, 5, 300), 6) for _ in range(20)}) > 1
