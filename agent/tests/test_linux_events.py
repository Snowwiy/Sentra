"""Fase 5C.1: colector del journal de Linux (sin journal real: journalctl simulado)."""

import json
import subprocess
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import linux_events as le
from sentra_agent.linux_events import JournalRead, LinuxJournalCollector, build_args, redact

BOOT = "4f1c2a9d0b6e4c1fa0b1c2d3e4f5a6b7"
USEC = 1_780_000_000_000_000


def entry(
    message: Any,
    ident: str = "sshd",
    seq: int = 1,
    priority: int = 6,
    realtime: int | None = None,
    **extra: Any,
) -> dict[str, Any]:
    return {
        "__CURSOR": f"s=abc;i={seq:x};b={BOOT};m={seq:x};t={seq:x};x={seq:x}",
        "__REALTIME_TIMESTAMP": str(realtime if realtime is not None else USEC + seq * 1000),
        "MESSAGE": message,
        "PRIORITY": str(priority),
        "SYSLOG_IDENTIFIER": ident,
        "_HOSTNAME": "mint",
        "_BOOT_ID": BOOT,
        **extra,
    }


def source(key: str) -> le.JournalSource:
    return next(s for s in le.SOURCES if s.key == key)


def classify(key: str, message: str, **extra: Any) -> dict[str, Any] | None:
    return le.to_event(source(key), entry(message, **extra))


class FakeJournal:
    """journalctl simulado: devuelve entradas por fuente y registra los argumentos."""

    def __init__(self) -> None:
        self.by_source: dict[str, list[dict[str, Any]]] = {}
        self.stderr: dict[str, str] = {}
        self.returncode: dict[str, int] = {}
        self.calls: list[list[str]] = []
        self.fail: set[str] = set()

    @staticmethod
    def key_of(argv: list[str]) -> str:
        for candidate in le.SOURCES:
            if candidate.matches[0] in argv:
                return candidate.key
        raise AssertionError(argv)

    def __call__(self, argv: list[str], limit: int, timeout: float) -> JournalRead:
        self.calls.append(argv)
        key = self.key_of(argv)
        if key in self.fail:
            raise OSError("boom")
        entries = list(self.by_source.get(key, []))
        cursor = next((a.split("=", 1)[1] for a in argv if a.startswith("--after-cursor=")), None)
        if cursor is not None:
            cursors = [e["__CURSOR"] for e in entries]
            entries = entries[cursors.index(cursor) + 1 :] if cursor in cursors else entries
        return JournalRead(entries[:limit], self.stderr.get(key, ""), self.returncode.get(key, 0))


def collector(
    tmp_path: Path, journal: FakeJournal, present: bool = True, boot: str = BOOT
) -> LinuxJournalCollector:
    def exists(paths: Iterable[str]) -> bool:
        return present

    return LinuxJournalCollector(
        tmp_path,
        runner=journal,
        journalctl=lambda: "/usr/bin/journalctl",
        exists=exists,
        boot_id=lambda: boot,
        journal_files=lambda: True,
    )


# --- Clasificación -------------------------------------------------------------------------


def test_ssh_failed_password_is_an_auth_failure_with_neutral_fields() -> None:
    event = classify("sshd", "Failed password for ana from 203.0.113.9 port 51234 ssh2")
    assert event is not None
    assert event["source"] == "linux_journal"
    assert event["event_type"] == "auth_failure"
    assert event["level"] == "warning"
    assert event["data"] == {
        "auth_method": "password",
        "user": "ana",
        "source_ip": "203.0.113.9",
        "source_port": "51234",
    }
    # Linux no tiene Event ID de Windows.
    assert "event_code" not in event


def test_ssh_invalid_user_failure_is_flagged() -> None:
    event = classify(
        "sshd", "Failed password for invalid user admin from 198.51.100.4 port 22 ssh2"
    )
    assert event is not None and event["data"]["invalid_user"] == "true"
    assert event["data"]["user"] == "admin"


def test_ssh_success_session_and_pubkey() -> None:
    accepted = classify(
        "sshd", "Accepted publickey for ana from 10.0.0.5 port 4242 ssh2: ED25519 SHA256:abc"
    )
    assert accepted is not None and accepted["event_type"] == "auth_success"
    assert accepted["data"]["auth_method"] == "publickey"
    opened = classify(
        "sshd", "pam_unix(sshd:session): session opened for user ana(uid=1000) by (uid=0)"
    )
    closed = classify("sshd", "pam_unix(sshd:session): session closed for user ana")
    assert opened is not None and opened["event_type"] == "session_opened"
    assert closed is not None and closed["event_type"] == "session_closed"


def test_ssh_invalid_user_line_and_pam_duplicate_are_events_without_double_counting() -> None:
    invalid = classify("sshd", "Invalid user oracle from 198.51.100.7 port 4000")
    pam = classify(
        "sshd",
        "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser="
        " rhost=198.51.100.7  user=ana",
    )
    assert invalid is not None and invalid["event_type"] == "ssh_invalid_user"
    assert pam is not None and pam["event_type"] == "pam_auth_failure"


def test_ssh_unknown_origin_is_not_invented() -> None:
    event = classify("sshd", "Failed password for ana from UNKNOWN port 0 ssh2")
    assert event is not None and "source_ip" not in event["data"]


def test_sudo_command_is_sanitized() -> None:
    event = classify(
        "sudo",
        "ana : TTY=pts/0 ; PWD=/home/ana ; USER=root ; COMMAND=/usr/bin/mysql -u root"
        " -pS3cretoLargo --password=otra https://u:clave@example.com/x token=abc123",
        ident="sudo",
    )
    assert event is not None and event["event_type"] == "sudo_command"
    command = event["data"]["command"]
    for secret in ("S3cretoLargo", "otra", "clave", "abc123"):
        assert secret not in command
        assert secret not in event["message"]
    assert event["data"]["user"] == "ana" and event["data"]["target_user"] == "root"


def test_sudo_auth_failure_and_not_allowed() -> None:
    wrong = classify(
        "sudo",
        "ana : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
        ident="sudo",
    )
    denied = classify(
        "sudo",
        "eve : user NOT in sudoers ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash",
        ident="sudo",
    )
    pam = classify(
        "sudo",
        "pam_unix(sudo:auth): authentication failure; logname=ana uid=1000 euid=0 tty=/dev/pts/0"
        " ruser=ana rhost=  user=ana",
        ident="sudo",
    )
    assert wrong is not None and wrong["event_type"] == "sudo_auth_failure"
    assert denied is not None and denied["event_type"] == "sudo_not_allowed"
    assert pam is not None and pam["event_type"] == "auth_failure"
    assert pam["data"]["user"] == "ana"


def test_sudo_unrelated_lines_are_ignored() -> None:
    assert classify("sudo", "some random text", ident="sudo") is None


def test_account_and_group_changes() -> None:
    created = classify(
        "accounts", "new user: name=backdoor, UID=0, GID=0, home=/root", ident="useradd"
    )
    added = classify("accounts", "add 'eve' to group 'sudo'", ident="usermod")
    shadow = classify("accounts", "add 'eve' to shadow group 'sudo'", ident="usermod")
    gpasswd = classify("accounts", "user eve added by root to group wheel", ident="gpasswd")
    deleted = classify("accounts", "delete user 'eve'", ident="userdel")
    locked = classify("accounts", "lock user 'bob' password", ident="usermod")
    assert created is not None and created["event_type"] == "account_created"
    assert created["data"] == {"user": "backdoor", "uid": "0"}
    assert added is not None and added["event_type"] == "group_member_added"
    assert shadow is None  # la copia de gshadow del mismo cambio no es otro evento
    assert gpasswd is not None and gpasswd["data"]["group"] == "wheel"
    assert deleted is not None and deleted["event_type"] == "account_deleted"
    assert locked is not None and locked["event_type"] == "account_locked"


def test_systemd_unit_lifecycle() -> None:
    failed = classify("systemd", "nginx.service: Failed with result 'exit-code'.", ident="systemd")
    started = classify(
        "systemd", "Started nginx.service - nginx.", ident="systemd", UNIT="nginx.service"
    )
    stopped = classify("systemd", "Stopped nginx.service.", ident="systemd", UNIT="nginx.service")
    clean_exit = classify(
        "systemd",
        "foo.service: Main process exited, code=exited, status=0/SUCCESS",
        ident="systemd",
    )
    reload_ = classify(
        "systemd", "Reloading requested from client PID 1234 ('systemctl')", ident="systemd"
    )
    assert failed is not None and failed["event_type"] == "service_failed"
    assert failed["level"] == "error" and failed["data"]["unit"] == "nginx.service"
    assert started is not None and started["event_type"] == "service_started"
    assert stopped is not None and stopped["event_type"] == "service_stopped"
    assert clean_exit is None
    assert reload_ is not None and reload_["event_type"] == "systemd_reload"


def test_kernel_classification_and_noise() -> None:
    oom = classify(
        "kernel",
        "Out of memory: Killed process 4242 (java) total-vm:1234kB",
        ident="kernel",
        priority=3,
    )
    fs = classify(
        "kernel",
        "EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2",
        ident="kernel",
        priority=2,
    )
    hw = classify(
        "kernel", "mce: [Hardware Error]: Machine check events logged", ident="kernel", priority=4
    )
    noise = classify(
        "kernel", "usb 1-1: device descriptor read/64, error -71", ident="kernel", priority=4
    )
    assert oom is not None and oom["event_type"] == "oom_kill"
    assert oom["provider"] == "kernel" and oom["data"]["process"] == "java"
    assert fs is not None and fs["event_type"] == "filesystem_error"
    assert fs["data"]["device"] == "sda1"
    assert hw is not None and hw["event_type"] == "hardware_error"
    assert noise is None  # avisos sin clasificar no salen del equipo


def test_auditd_only_failed_authentications() -> None:
    ok = classify(
        "auditd",
        'pid=1 uid=0 msg=\'op=PAM:authentication acct="ana" exe="/usr/bin/sudo" res=success\'',
        _AUDIT_TYPE_NAME="USER_AUTH",
    )
    failed = classify(
        "auditd",
        'pid=1 uid=0 msg=\'op=PAM:authentication acct="ana" exe="/usr/bin/su" res=failed\'',
        _AUDIT_TYPE_NAME="USER_AUTH",
    )
    other = classify("auditd", "whatever", _AUDIT_TYPE_NAME="SYSCALL")
    assert ok is None and other is None
    assert failed is not None and failed["event_type"] == "audit_user_auth"
    assert failed["data"]["user"] == "ana"


def test_malformed_and_missing_fields_are_skipped() -> None:
    sshd = source("sshd")
    assert le.to_event(sshd, {"MESSAGE": "Failed password for a from 1.2.3.4 port 1 ssh2"}) is None
    assert le.to_event(sshd, entry(None)) is None
    assert le.to_event(sshd, entry("")) is None
    assert le.to_event(sshd, entry("x", realtime=-5)) is None
    assert le.to_event(
        sshd, {**entry("Failed password for a from 1.2.3.4 port 1 ssh2"), "PRIORITY": "x"}
    )


def test_unicode_binary_messages_and_control_characters() -> None:
    raw = list("Failed password for josé from 10.0.0.1 port 1 ssh2".encode())
    event = le.to_event(source("sshd"), entry(raw))
    assert event is not None and event["data"]["user"] == "josé"
    hostile = classify("sshd", "Failed password for a\x1b[31mb from 10.0.0.1 port 1 ssh2")
    assert hostile is not None and "\x1b" not in hostile["message"]


def test_message_is_bounded() -> None:
    event = classify("sshd", "Failed password for ana from 10.0.0.1 port 1 ssh2 " + "x" * 5000)
    assert event is not None and len(event["message"]) <= le.MESSAGE_MAX


def test_record_id_is_stable_positive_and_cursor_based() -> None:
    a = classify("sshd", "Failed password for ana from 10.0.0.1 port 1 ssh2", seq=7)
    b = classify("sshd", "Failed password for ana from 10.0.0.1 port 1 ssh2", seq=7)
    c = classify("sshd", "Failed password for ana from 10.0.0.1 port 1 ssh2", seq=8)
    assert a is not None and b is not None and c is not None
    assert a["record_id"] == b["record_id"] != c["record_id"]
    assert 0 <= a["record_id"] < 2**63


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("curl -H 'Authorization: Bearer abcdefghijklmnop'", "abcdefghijklmnop"),
        ("psql postgresql://sentra:hunter2@db/x", "hunter2"),
        ("tool --api-key ZXCVBNMASDF", "ZXCVBNMASDF"),
        ("export AWS_SECRET_ACCESS_KEY=AKIAxyz", "AKIAxyz"),
        ("x " + "a1" * 30, "a1" * 30),
    ],
)
def test_redaction(text: str, secret: str) -> None:
    assert secret not in redact(text)


# --- Lectura y argumentos ------------------------------------------------------------------


def test_args_are_fixed_without_shell_and_first_run_is_bounded() -> None:
    args = build_args("/usr/bin/journalctl", source("kernel"), None)
    assert args[0] == "/usr/bin/journalctl"
    assert "--output=json" in args and "--priority=warning" in args
    assert "--since=-1h" in args and f"--lines={le.FIRST_RUN_MAX}" in args
    assert "_TRANSPORT=kernel" in args
    resumed = build_args("/usr/bin/journalctl", source("sshd"), "s=1;i=2")
    assert "--after-cursor=s=1;i=2" in resumed and "--since=-1h" not in resumed


def fake_journalctl(
    tmp_path: Path,
    count: int,
    *,
    exit_code: int = 0,
    stderr: str = "",
    garbage: bool = False,
    hang: bool = False,
) -> Path:
    """Script Python que hace de journalctl: `count` entradas JSON y luego sale o se cuelga."""
    script = tmp_path / f"fake_{count}_{exit_code}_{int(hang)}.py"
    lines = [
        json.dumps(entry(f"Failed password for u{i} from 10.0.0.1 port 1 ssh2", seq=i))
        for i in range(count)
    ]
    body = ["import sys, time"]
    body += [f"print({line!r})" for line in lines]
    if garbage:
        body.append("print('not json')")
    if stderr:
        body.append(f"sys.stderr.write({stderr!r})")
    body.append("sys.stdout.flush()")
    if hang:
        # Sigue vivo con más que contar: solo termina si Sentra lo detiene.
        body.append("time.sleep(60)")
    body.append(f"sys.exit({exit_code})")
    script.write_text("\n".join(body) + "\n")
    return script


def test_run_journalctl_uses_no_shell_and_respects_the_limit(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 10, stderr="aviso", garbage=True)
    read = le.run_journalctl([sys.executable, str(script), "; rm -rf /"], limit=4, timeout=10)
    # Con cupo lleno el resultado es correcto tanto si Sentra paró el proceso como si ya había
    # salido solo con 0; nunca el código que provoca la parada (1 en Windows, -9 en POSIX).
    assert len(read.entries) == 4 and read.returncode == 0
    full = le.run_journalctl([sys.executable, str(script)], limit=100, timeout=10)
    assert len(full.entries) == 10  # la línea corrupta se salta
    assert "aviso" in full.stderr and full.returncode == 0 and full.outcome == "completed"


def test_run_journalctl_normal_exit(tmp_path: Path) -> None:
    read = le.run_journalctl([sys.executable, str(fake_journalctl(tmp_path, 3))], 10, 10)
    assert (len(read.entries), read.returncode, read.outcome, read.stderr) == (
        3,
        0,
        "completed",
        "",
    )


def test_run_journalctl_stops_a_live_process_at_the_limit(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 10, hang=True)
    read = le.run_journalctl([sys.executable, str(script)], limit=4, timeout=30)
    # El proceso seguía vivo: lo detuvo Sentra, no es un fallo de journalctl.
    assert len(read.entries) == 4
    assert read.outcome == "limit" and read.returncode == 0


def test_run_journalctl_exact_limit_then_normal_exit(tmp_path: Path) -> None:
    read = le.run_journalctl([sys.executable, str(fake_journalctl(tmp_path, 4))], 4, 10)
    assert len(read.entries) == 4 and read.returncode == 0


def test_run_journalctl_benign_stderr_is_not_a_failure(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 2, stderr="Journal file uses a different format")
    read = le.run_journalctl([sys.executable, str(script)], 10, 10)
    assert read.returncode == 0 and read.outcome == "completed" and len(read.entries) == 2
    assert "different format" in read.stderr


def test_run_journalctl_keeps_a_real_error(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 0, exit_code=1, stderr="Failed to seek to cursor")
    read = le.run_journalctl([sys.executable, str(script)], 10, 10)
    assert read.returncode == 1 and read.outcome == "completed" and read.entries == []
    # Error con algunas entradas (por debajo del cupo): el código se conserva igual.
    partial = fake_journalctl(tmp_path, 2, exit_code=3, stderr="boom")
    read = le.run_journalctl([sys.executable, str(partial)], 10, 10)
    assert read.returncode == 3 and read.outcome == "completed" and len(read.entries) == 2


def test_run_journalctl_timeout_kills_a_silent_process(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 0, hang=True)
    with pytest.raises(subprocess.TimeoutExpired):
        le.run_journalctl([sys.executable, str(script)], 10, 0.5)
    partial = fake_journalctl(tmp_path, 2, hang=True)
    with pytest.raises(subprocess.TimeoutExpired):
        le.run_journalctl([sys.executable, str(partial)], 10, 0.5)


def test_run_journalctl_only_garbage_is_an_empty_read(tmp_path: Path) -> None:
    script = fake_journalctl(tmp_path, 0, garbage=True)
    read = le.run_journalctl([sys.executable, str(script)], 10, 10)
    assert read.entries == [] and read.returncode == 0


def test_run_journalctl_never_interprets_arguments(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "pwned"
    script = tmp_path / "argv.py"
    seen = tmp_path / "argv.json"
    script.write_text(
        f"import json, sys\nopen({str(seen)!r}, 'w').write(json.dumps(sys.argv[1:]))\n"
    )
    calls: list[tuple[Any, dict[str, Any]]] = []
    real_popen = subprocess.Popen

    def spy(args: Any, **kwargs: Any) -> Any:
        calls.append((args, kwargs))
        return real_popen(args, **kwargs)

    monkeypatch.setattr(subprocess, "Popen", spy)
    hostile = [f"; touch {marker}", f"$(touch {marker})", f"& echo x > {marker}", "| id"]
    le.run_journalctl([sys.executable, str(script), *hostile], 10, 10)
    (args, kwargs) = calls[0]
    assert isinstance(args, list) and kwargs["shell"] is False
    assert json.loads(seen.read_text()) == hostile  # llegan literales, uno por argumento
    assert not marker.exists()


class _FakeStdout:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = lines

    def __iter__(self) -> Any:
        return iter(self._lines)

    def close(self) -> None:
        pass


class _FakeProcess:
    """Popen simulado: qué código da la parada según la plataforma, sin depender del SO."""

    def __init__(self, lines: list[bytes], kill_code: int, exited: int | None = None) -> None:
        self.stdout = _FakeStdout(lines)
        self.kill_code = kill_code
        self.returncode = exited
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def kill(self) -> None:
        self.killed = True
        self.returncode = self.kill_code

    def wait(self, timeout: float | None = None) -> int:
        assert self.returncode is not None
        return self.returncode


def _lines(count: int) -> list[bytes]:
    return [
        json.dumps(entry("Failed password for x", seq=i)).encode() + b"\n" for i in range(count)
    ]


@pytest.mark.parametrize(
    ("platform_name", "kill_code"),
    [("windows", 1), ("posix", -9)],  # TerminateProcess(handle, 1) / SIGKILL
)
def test_run_journalctl_limit_stop_code_is_not_an_error_on_any_platform(
    monkeypatch: pytest.MonkeyPatch, platform_name: str, kill_code: int
) -> None:
    process = _FakeProcess(_lines(10), kill_code)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    read = le.run_journalctl(["/usr/bin/journalctl"], limit=4, timeout=10)
    assert process.killed, platform_name
    assert (len(read.entries), read.returncode, read.outcome) == (4, 0, "limit")


@pytest.mark.parametrize("exit_code", [1, 2, -11])
def test_run_journalctl_own_exit_is_kept_even_with_a_full_batch(
    monkeypatch: pytest.MonkeyPatch, exit_code: int
) -> None:
    # journalctl ya había salido solo (con error o señal): Sentra no lo paró, así que su código
    # se conserva aunque el lote esté lleno. No se convierte cualquier código en éxito.
    process = _FakeProcess(_lines(10), kill_code=99, exited=exit_code)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: process)
    read = le.run_journalctl(["/usr/bin/journalctl"], limit=4, timeout=10)
    assert not process.killed
    assert (read.returncode, read.outcome) == (exit_code, "completed")


# --- Colector ------------------------------------------------------------------------------


def ssh_failures(n: int, start: int = 1) -> list[dict[str, Any]]:
    return [
        entry(f"Failed password for ana from 203.0.113.9 port {1000 + i} ssh2", seq=i)
        for i in range(start, start + n)
    ]


def test_collector_reads_commits_and_resumes_from_cursor(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.by_source["sshd"] = ssh_failures(3)
    events, state = collector(tmp_path, journal).pending()
    assert [e["event_type"] for e in events] == ["auth_failure"] * 3

    # Sin commit (envío fallido) se vuelve a leer lo mismo.
    again, _ = collector(tmp_path, journal).pending()
    assert len(again) == 3

    collector(tmp_path, journal).commit(state)
    saved = json.loads((tmp_path / le.STATE_FILE).read_text())
    assert saved["sources"]["sshd"]["cursor"] == journal.by_source["sshd"][-1]["__CURSOR"]
    journal.by_source["sshd"] += ssh_failures(2, start=4)
    fresh, _ = collector(tmp_path, journal).pending()
    assert len(fresh) == 2


def test_cursor_survives_reboot(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.by_source["sshd"] = ssh_failures(2)
    first = collector(tmp_path, journal)
    _, state = first.pending()
    first.commit(state)
    journal.by_source["sshd"] += ssh_failures(1, start=3)
    after_reboot = collector(tmp_path, journal, boot="0" * 31 + "1")
    events, state = after_reboot.pending()
    assert len(events) == 1 and state["boot_id"] == "0" * 31 + "1"


def test_lost_cursor_after_rotation_restarts_from_recent_window(tmp_path: Path) -> None:
    journal = FakeJournal()
    (tmp_path / le.STATE_FILE).write_text(
        json.dumps({"version": 1, "sources": {"sshd": {"cursor": "s=gone", "realtime": USEC}}})
    )
    journal.stderr["sshd"] = "Failed to seek to cursor: Invalid argument"
    journal.returncode["sshd"] = 1
    c = collector(tmp_path, journal)
    events, state = c.pending()
    assert events == [] and state["sources"]["sshd"]["cursor"] is None
    assert (c.coverage() or {}).get("sshd") == "active"


def test_old_entries_after_reset_are_not_replayed(tmp_path: Path) -> None:
    journal = FakeJournal()
    old = entry("Failed password for ana from 1.1.1.1 port 1 ssh2", seq=50, realtime=USEC - 10**9)
    journal.by_source["sshd"] = [old, *ssh_failures(1, start=60)]
    (tmp_path / le.STATE_FILE).write_text(
        json.dumps({"version": 1, "sources": {"sshd": {"cursor": None, "realtime": USEC}}})
    )
    events, _ = collector(tmp_path, journal).pending()
    assert len(events) == 1


def test_corrupt_state_file_starts_over(tmp_path: Path) -> None:
    (tmp_path / le.STATE_FILE).write_text("{no json")
    journal = FakeJournal()
    journal.by_source["sshd"] = ssh_failures(1)
    events, _ = collector(tmp_path, journal).pending()
    assert len(events) == 1


def test_duplicate_entries_in_one_read_are_sent_once(tmp_path: Path) -> None:
    journal = FakeJournal()
    dup = ssh_failures(1)
    journal.by_source["sshd"] = [dup[0], dict(dup[0])]
    events, _ = collector(tmp_path, journal).pending()
    assert len(events) == 1


def test_kernel_flood_is_capped(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.by_source["kernel"] = [
        entry(
            "EXT4-fs error (device sda1): ext4_lookup: bad inode", ident="kernel", seq=i, priority=3
        )
        for i in range(20)
    ]
    events, _ = collector(tmp_path, journal).pending()
    assert len(events) == le.KERNEL_DUPLICATES_MAX


def test_permission_denied_is_reported_as_coverage_not_as_zero_events(tmp_path: Path) -> None:
    journal = FakeJournal()
    hint = (
        "Hint: You are currently not seeing messages from other users and the system.\n"
        "      Users in groups 'adm', 'systemd-journal' can see all messages."
    )
    for s in le.SOURCES:
        journal.stderr[s.key] = hint
    c = collector(tmp_path, journal)
    events, _ = c.pending()
    coverage = c.coverage()
    assert events == [] and coverage is not None
    assert coverage["journal"] == "no_permission" and coverage["sshd"] == "no_permission"


def test_missing_journalctl_and_missing_services_are_unavailable(tmp_path: Path) -> None:
    c = LinuxJournalCollector(tmp_path, runner=FakeJournal(), journalctl=lambda: None)
    assert c.pending()[0] == []
    assert (c.coverage() or {}).get("journal") == "unavailable"

    journal = FakeJournal()
    c2 = collector(tmp_path, journal, present=False)
    c2.pending()
    coverage = c2.coverage()
    assert coverage is not None
    assert coverage["sshd"] == "unavailable" and coverage["auditd"] == "unavailable"
    assert coverage["systemd"] == "active"  # no depende de un binario opcional


def test_auditd_without_records_in_journal_is_unavailable_not_an_error(tmp_path: Path) -> None:
    c = collector(tmp_path, FakeJournal())
    c.pending()
    coverage = c.coverage()
    assert coverage is not None and coverage["auditd"] == "unavailable"
    assert coverage["journal"] == "active"


def test_one_failing_source_does_not_stop_the_others(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.fail.add("sudo")
    journal.by_source["sshd"] = ssh_failures(2)
    c = collector(tmp_path, journal)
    events, _ = c.pending()
    assert len(events) == 2
    coverage = c.coverage()
    assert coverage is not None and coverage["sudo"] == "error"


def test_journalctl_error_exit_without_entries_is_error(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.stderr["systemd"] = "Failed to open journal"
    journal.returncode["systemd"] = 1
    c = collector(tmp_path, journal)
    c.pending()
    coverage = c.coverage()
    assert coverage is not None and coverage["systemd"] == "error"
    assert coverage["journal"] == "error"


def test_old_journalctl_without_output_fields_is_retried(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.by_source["sshd"] = ssh_failures(1)
    calls: list[list[str]] = []

    def runner(argv: list[str], limit: int, timeout: float) -> JournalRead:
        calls.append(argv)
        if any(a.startswith("--output-fields") for a in argv):
            return JournalRead([], "journalctl: unrecognized option '--output-fields'", 1)
        return journal(argv, limit, timeout)

    c = LinuxJournalCollector(
        tmp_path,
        runner=runner,
        journalctl=lambda: "/x",
        exists=lambda p: True,
        boot_id=lambda: BOOT,
        journal_files=lambda: True,
    )
    events, _ = c.pending()
    assert len(events) == 1
    assert not any(a.startswith("--output-fields") for a in calls[-1])


def test_batch_limit_per_source(tmp_path: Path) -> None:
    journal = FakeJournal()
    journal.by_source["sshd"] = ssh_failures(le.BATCH_MAX + 50)
    events, _ = collector(tmp_path, journal).pending()
    assert len(events) == le.BATCH_MAX


def test_no_windows_event_ids_and_platform_source() -> None:
    for message, key, ident in [
        ("Failed password for a from 10.0.0.1 port 1 ssh2", "sshd", "sshd"),
        ("ana : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls", "sudo", "sudo"),
        ("x.service: Failed with result 'timeout'.", "systemd", "systemd"),
    ]:
        event = classify(key, message, ident=ident)
        assert event is not None
        assert event["source"] == "linux_journal" and "event_code" not in event


def test_no_journal_files_is_unavailable_not_zero_events(tmp_path: Path) -> None:
    journal = FakeJournal()
    c = LinuxJournalCollector(
        tmp_path, runner=journal, journalctl=lambda: "/x", journal_files=lambda: False
    )
    assert c.pending()[0] == [] and journal.calls == []
    assert (c.coverage() or {}).get("journal") == "unavailable"


def test_journal_file_detection(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert le._journal_files((str(empty), str(tmp_path / "missing"))) is False
    machine = tmp_path / "var" / "0123"
    machine.mkdir(parents=True)
    (machine / "system.journal").write_bytes(b"")
    assert le._journal_files((str(tmp_path / "var"),)) is True
