"""Fase 6E.3: identidad de procesos, política de línea de comandos y cola de actividad."""

import json
from pathlib import Path

import pytest

from sentra_agent.activity import (
    QUEUE_FILE,
    QUEUE_META_FILE,
    REDACTED,
    ActivityQueue,
    create_time_ms,
    instance_key,
    make_event,
    read_boot_id,
    redact_cmdline,
)


def event(n: int) -> dict[str, object]:
    return make_event(
        "process", "start", "psutil_poll", {"pid": n}, "2026-10-22T10:00:00.000+00:00"
    )


def test_instance_key_is_the_contract_hash() -> None:
    import hashlib

    expected = hashlib.sha256(b"boot-1|4242|1700000000123").hexdigest()[:32]
    assert instance_key("boot-1", 4242, 1700000000123) == expected
    assert len(expected) == 32
    # Mismo PID, otro arranque u otro create_time: otra clave (PID reutilizado).
    assert instance_key("boot-2", 4242, 1700000000123) != expected
    assert instance_key("boot-1", 4242, 1700000000124) != expected


def test_create_time_is_truncated_to_milliseconds() -> None:
    assert create_time_ms(1700000000.1239) == 1700000000123


def test_boot_id_reads_linux_file_or_falls_back(tmp_path: Path) -> None:
    path = tmp_path / "boot_id"
    path.write_text("aeb882b6-0929-4030-8e74-adc92a9b1952\n")
    assert read_boot_id(path) == "aeb882b6-0929-4030-8e74-adc92a9b1952"
    assert read_boot_id(tmp_path / "missing").startswith("boot-")


@pytest.mark.parametrize(
    ("argv", "secret"),
    [
        (["mysql", "-u", "root", "-p", "hunter2"], "hunter2"),
        (["app", "--password", "s3cr3t!"], "s3cr3t!"),
        (["app", "--password=s3cr3t!"], "s3cr3t!"),
        (["net", "use", "x:", "\\\\srv\\share", "/p", "Pa55"], "Pa55"),
        (["net", "use", "/p:Pa55word"], "Pa55word"),
        (["curl", "https://api/x?token=abcdef&x=1"], "abcdef"),
        (["tool", "api_key=K123"], "K123"),
        (["tool", "client_secret=CS9"], "CS9"),
        (["curl", "-H", "Authorization: Bearer eyJhbGciOi"], "eyJhbGciOi"),
        (["git", "clone", "https://user:ghp_xyz@github.com/r.git"], "ghp_xyz"),
    ],
)
def test_redacted_policy_removes_secret_values(argv: list[str], secret: str) -> None:
    text = redact_cmdline(argv, "redacted")
    assert text is not None
    assert secret not in text
    assert REDACTED in text


def test_cmdline_policies() -> None:
    argv = ["python", "-m", "http.server", "--password", "x"]
    assert redact_cmdline(argv, "off") is None
    assert redact_cmdline(argv, "full") == "python -m http.server --password x"
    assert redact_cmdline(None, "full") is None
    long = ["a" * 3000]
    assert len(redact_cmdline(long, "redacted") or "") == 1024
    assert len(redact_cmdline(long, "full") or "") == 1024
    # Lo que no es secreto se conserva (útil para la detección conductual).
    assert redact_cmdline(["powershell", "-enc", "AAA"], "redacted") == "powershell -enc AAA"


def test_make_event_rejects_unknown_category_or_source() -> None:
    with pytest.raises(ValueError):
        make_event("keylogger", "start", "psutil_poll", {}, "x")
    with pytest.raises(ValueError):
        make_event("process", "start", "magic", {}, "x")


def test_queue_numbers_events_and_survives_restart(tmp_path: Path) -> None:
    queue = ActivityQueue(100, tmp_path)
    queue.extend([event(1), event(2), event(3)])
    queue.persist()
    queue.ack(1)
    queue.persist()

    restored = ActivityQueue(100, tmp_path)
    assert [e["data"]["pid"] for e in restored.peek(10)] == [2, 3]
    assert [e["seq"] for e in restored.peek(10)] == [1, 2]
    restored.extend([event(4)])
    assert restored.peek(10)[-1]["seq"] == 3  # seq sigue creciendo tras reiniciar


def test_queue_drops_oldest_and_counts(tmp_path: Path) -> None:
    queue = ActivityQueue(3, tmp_path)
    queue.extend([event(n) for n in range(5)])
    assert [e["data"]["pid"] for e in queue.peek(10)] == [2, 3, 4]
    assert queue.dropped_total == 2 and queue.dropped_since_last == 2
    queue.persist()
    queue.reset_dropped_since_last()
    assert queue.dropped_since_last == 0

    restored = ActivityQueue(3, tmp_path)
    assert restored.dropped_total == 2  # el total se conserva entre ejecuciones
    assert [e["data"]["pid"] for e in restored.peek(10)] == [2, 3, 4]


def test_queue_restart_with_smaller_cap_keeps_newest(tmp_path: Path) -> None:
    queue = ActivityQueue(10, tmp_path)
    queue.extend([event(n) for n in range(6)])
    queue.persist()
    smaller = ActivityQueue(4, tmp_path)
    assert [e["data"]["pid"] for e in smaller.peek(10)] == [2, 3, 4, 5]
    assert smaller.dropped_total == 2


def test_queue_ack_of_unwritten_events_and_compaction(tmp_path: Path) -> None:
    queue = ActivityQueue(5000, tmp_path)
    queue.extend([event(n) for n in range(3)])
    queue.persist()
    queue.extend([event(n) for n in range(3, 6)])  # aún no escritas
    queue.ack(4)  # incluye una que solo estaba en memoria
    queue.persist()
    restored = ActivityQueue(5000, tmp_path)
    assert [e["data"]["pid"] for e in restored.peek(10)] == [4, 5]

    # Muchos confirmados: el fichero se compacta en lugar de crecer sin fin.
    queue = ActivityQueue(5000, tmp_path / "big")
    queue.extend([event(n) for n in range(2500)])
    queue.persist()
    queue.ack(2400)
    queue.persist()
    lines = (tmp_path / "big" / QUEUE_FILE).read_text().splitlines()
    assert len(lines) == 100
    assert json.loads((tmp_path / "big" / QUEUE_META_FILE).read_text())["skip"] == 0


def test_corrupt_queue_lines_are_skipped(tmp_path: Path) -> None:
    queue = ActivityQueue(10, tmp_path)
    queue.extend([event(1)])
    queue.persist()
    with (tmp_path / QUEUE_FILE).open("a") as handle:
        handle.write('{"half": \n')  # corte de luz a mitad de línea
    restored = ActivityQueue(10, tmp_path)
    assert len(restored) == 1
    assert restored.oldest_occurred_at() == "2026-10-22T10:00:00.000+00:00"
