"""Fase 6C.5: eventos de macOS desde el Unified Logging (`log show --style ndjson`).

Salidas guardadas como fixture (macOS 15, sshd-session de OpenSSH 9.8, sudo, su, Compartir
pantalla y authd con datos privados). Comprueba la clasificación, el saneado, el cursor
persistente, la cobertura y que nunca se ejecuta otra cosa que el predicado fijo.
"""

import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import macos_events
from sentra_agent.macos_events import MacUnifiedLogCollector, build_args, parse_ndjson
from sentra_agent.runner import default_event_source
from sentra_agent.syscmd import CommandOutput, CommandTimeoutError, CommandUnavailableError

FIXTURE = Path(__file__).parent / "fixtures" / "macos" / "log_show.ndjson"
NOW = datetime(2026, 10, 16, 8, 30, tzinfo=UTC)


class FakeLog:
    def __init__(self, *outputs: CommandOutput | Exception) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[str]] = []

    def __call__(self, argv: list[str]) -> CommandOutput:
        self.calls.append(argv)
        value = self.outputs.pop(0) if self.outputs else CommandOutput(b"", "", 0)
        if isinstance(value, Exception):
            raise value
        return value


def output(data: bytes | None = None, **kwargs: Any) -> CommandOutput:
    return CommandOutput(FIXTURE.read_bytes() if data is None else data, **{
        "stderr": "", "returncode": 0, **kwargs,
    })  # fmt: skip


def collector(tmp_path: Path, log: FakeLog) -> MacUnifiedLogCollector:
    return MacUnifiedLogCollector(tmp_path, runner=log, clock=lambda: NOW)


def test_classifies_security_messages_and_drops_the_rest(tmp_path: Path) -> None:
    events, _ = collector(tmp_path, FakeLog(output())).pending()
    kinds = [e["event_type"] for e in events]
    # "Connection closed" no se reconoce y no sale del equipo; el primer arranque se queda
    # con los 50 más recientes (aquí hay menos).
    assert kinds == [
        "auth_failure",
        "pam_auth_failure",
        "auth_success",
        "sudo_command",
        "sudo_auth_failure",
        "su_auth_failure",
        "screen_sharing_auth_failure",
        "local_auth_failure",
    ]
    by_type = {e["event_type"]: e for e in events}
    failure = by_type["auth_failure"]
    assert failure["source"] == "macos_unified_log"
    assert failure["channel"] == "unified_log"
    assert failure["provider"] == "sshd-session"
    assert failure["data"] == {
        "auth_method": "password", "user": "admin", "source_ip": "203.0.113.9",
        "source_port": "50124", "invalid_user": "true",
    }  # fmt: skip
    assert failure["occurred_at"] == "2026-10-16T08:21:31.200002+00:00"
    assert by_type["auth_success"]["data"]["user"] == "alice"
    assert by_type["sudo_auth_failure"]["data"]["user"] == "bob"
    assert by_type["screen_sharing_auth_failure"]["data"] == {
        "user": "carol",
        "source_ip": "192.168.1.77",
    }
    # Dato privado de macOS: no se envía ni se intenta reconstruir.
    assert "data" not in by_type["local_auth_failure"]
    # Ningún evento se hace pasar por uno de Windows.
    assert all(e.get("event_code") is None for e in events)


def test_sudo_command_secrets_are_redacted(tmp_path: Path) -> None:
    events, _ = collector(tmp_path, FakeLog(output())).pending()
    sudo = next(e for e in events if e["event_type"] == "sudo_command")
    assert "abcdefghijklmnopqrstuvwxyz0123456789" not in json.dumps(sudo)
    assert "[REDACTED]" in sudo["data"]["command"]
    assert sudo["data"]["target_user"] == "root"


def test_only_the_fixed_predicate_is_run(tmp_path: Path) -> None:
    log = FakeLog(output())
    collector(tmp_path, log).pending()
    argv = log.calls[0]
    assert argv[0] == "/usr/bin/log"
    assert argv[1:5] == ["show", "--style", "ndjson", "--info"]
    assert argv[argv.index("--predicate") + 1] == macos_events.PREDICATE
    assert argv[-2:] == ["--last", "1h"]  # primer arranque: solo la última hora


def test_cursor_resumes_without_resending(tmp_path: Path) -> None:
    log = FakeLog(output(), output())
    source = collector(tmp_path, log)
    events, cursor = source.pending()
    assert events
    source.commit(cursor)
    state = json.loads((tmp_path / macos_events.STATE_FILE).read_text())
    assert state["last"] == "2026-10-16T08:23:30.000500+00:00"

    # Siguiente ciclo: desde el segundo de la última entrada, en UTC con desplazamiento.
    again, _ = source.pending()
    assert again == []
    assert log.calls[1][-2:] == ["--start", "2026-10-16 08:23:30+0000"]


def test_resend_after_lost_commit_gives_identical_record_ids(tmp_path: Path) -> None:
    first, _ = collector(tmp_path, FakeLog(output())).pending()
    second, _ = collector(tmp_path, FakeLog(output())).pending()  # sin commit
    assert [e["record_id"] for e in first] == [e["record_id"] for e in second]
    assert len({e["record_id"] for e in first}) == len(first)


def test_new_entries_in_the_same_second_are_not_lost(tmp_path: Path) -> None:
    lines = FIXTURE.read_bytes().splitlines()
    last = json.loads(lines[-1])
    source = collector(tmp_path, FakeLog(output(), output()))
    _, cursor = source.pending()
    source.commit(cursor)
    sibling = dict(last, machTimestamp=last["machTimestamp"] + 1, threadID=1)
    data = b"\n".join([lines[-1], json.dumps(sibling).encode()]) + b"\n"
    source._runner = FakeLog(output(data))
    events, _ = source.pending()
    assert len(events) == 1 and events[0]["event_type"] == "local_auth_failure"


def test_long_outage_reads_at_most_the_last_24_hours(tmp_path: Path) -> None:
    (tmp_path / macos_events.STATE_FILE).write_text(
        json.dumps({"version": 1, "last": (NOW - timedelta(days=5)).isoformat(), "seen": []})
    )
    log = FakeLog(output(b""))
    collector(tmp_path, log).pending()
    assert log.calls[0][-1] == (NOW - timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S+0000")


def test_truncated_output_drops_the_partial_last_line() -> None:
    data = FIXTURE.read_bytes()
    cut = data[: len(data) - 40]
    full = parse_ndjson(data, truncated=False)
    partial = parse_ndjson(cut, truncated=True)
    assert len(partial) == len(full) - 1


def test_batch_limit_advances_the_cursor_to_the_last_read_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(macos_events, "BATCH_MAX", 3)
    source = collector(tmp_path, FakeLog(output()))
    events, cursor = source.pending()
    # 3 entradas leídas (una no se envía); el cursor queda en la tercera.
    assert len(events) == 2
    assert cursor["last"] == "2026-10-16T08:21:32.300003+00:00"


@pytest.mark.parametrize(
    ("result", "state"),
    [
        (CommandOutput(b"", "log: Must be admin to run this command", 64), "no_permission"),
        (CommandOutput(b"", "log: Could not open log archive", 70), "error"),
        (CommandUnavailableError("/usr/bin/log not found"), "unavailable"),
        (CommandTimeoutError("log timed out after 60s"), "error"),
    ],
)
def test_failures_become_coverage_and_never_raise(
    tmp_path: Path, result: CommandOutput | Exception, state: str
) -> None:
    source = collector(tmp_path, FakeLog(result))
    events, cursor = source.pending()
    assert events == []
    assert source.coverage() == {"unified_log": state}
    source.commit(cursor)  # el cursor sigue siendo válido


def test_active_coverage_and_first_run_without_entries_starts_from_now(tmp_path: Path) -> None:
    source = collector(tmp_path, FakeLog(output(b"")))
    events, cursor = source.pending()
    assert events == [] and source.coverage() == {"unified_log": "active"}
    assert cursor["last"] == NOW.isoformat()


def test_build_args_never_takes_text_from_outside() -> None:
    argv = build_args(datetime(2026, 1, 2, 3, 4, 5, 999, tzinfo=UTC))
    assert argv[-1] == "2026-01-02 03:04:05+0000"
    assert all("\n" not in arg for arg in argv)


def test_default_event_source_on_macos(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert isinstance(default_event_source(tmp_path), MacUnifiedLogCollector)
