"""Linux distribution: installer, uninstaller, systemd unit, build, and `--enroll`.

The installer runs for real (bash) under SENTRA_ROOT=<tmp>, with fake `id`, `useradd`,
`userdel`, `getent`, `chown`, `runuser` and `systemctl` that record their calls, against the
fake Sentra API of conftest.py. The real agent code enrolls through the generated launcher.
Nothing outside the temporary directory is touched. Real-root validation (real useradd,
runuser, dpkg) is documented in docs/agent-linux-installation.md.
"""

import hashlib
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import psutil
import pytest

from sentra_agent.__main__ import (
    EXIT_ENROLLED,
    EXIT_NO_CREDENTIAL,
    EXIT_REJECTED,
    EXIT_UNREACHABLE,
    main,
)
from tests.conftest import FakeApiState

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or shutil.which("bash") is None, reason="Linux packaging"
)

AGENT_DIR = Path(__file__).resolve().parents[1]
PACKAGING = AGENT_DIR / "packaging" / "linux"
TOKEN = "sentra_et_" + "P" * 43
BASH = shutil.which("bash") or "/bin/bash"

SHIMS = {
    "id": "echo 0",
    "getent": '[ -f "$SHIM_STATE/user" ] && echo "sentra-agent:x:999:999::/x:/usr/sbin/nologin"',
    "useradd": 'echo "useradd $*" >> "$SHIM_LOG"; touch "$SHIM_STATE/user"',
    "userdel": 'echo "userdel $*" >> "$SHIM_LOG"; rm -f "$SHIM_STATE/user"',
    "chown": 'echo "chown $*" >> "$SHIM_LOG"',
    # Drop "-u <user> --" and run the command as the current (test) user.
    # Also records the mode of the one-time token copy handed to the agent.
    "runuser": (
        'echo "runuser $1 $2" >> "$SHIM_LOG"; shift 3\n'
        'for a in "$@"; do case "$a" in *enrollment.token) '
        'stat -c %a "$a" >> "$SHIM_STATE/token_mode" ;; esac; done\n'
        'exec "$@"'
    ),
    "systemctl": (
        'echo "systemctl $*" >> "$SHIM_LOG"\n'
        'case "$*" in *is-active*) grep -q "systemctl restart" "$SHIM_LOG" ;; esac'
    ),
}


class Host:
    """A fake Linux host: a root directory and the record of privileged commands."""

    def __init__(self, tmp: Path) -> None:
        self.root = tmp / "root"
        self.root.mkdir()
        self.bin = tmp / "shims"
        self.bin.mkdir()
        self.state = tmp / "shim-state"
        self.state.mkdir()
        self.log = tmp / "shim.log"
        self.log.touch()
        for name, body in SHIMS.items():
            path = self.bin / name
            path.write_text(f"#!/bin/sh\n{body}\n", encoding="utf-8")
            path.chmod(0o755)
        self.package = tmp / "package"
        self._make_package()

    def _make_package(self) -> None:
        lib = self.package / "payload" / "lib"
        lib.mkdir(parents=True)
        shutil.copytree(AGENT_DIR / "sentra_agent", lib / "sentra_agent")
        shutil.copytree(Path(psutil.__file__).parent, lib / "psutil")
        for name in ("install-sentra-agent.sh", "uninstall-sentra-agent.sh"):
            shutil.copy2(PACKAGING / name, self.package / name)
        shutil.copy2(PACKAGING / "sentra-agent.service", self.package / "sentra-agent.service")
        machine = platform.machine().replace("amd64", "x86_64").replace("arm64", "aarch64")
        (self.package / "VERSION").write_text(f"version=0.0.0\narch={machine}\n")

    def run(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "SENTRA_ROOT": str(self.root),
            "SHIM_LOG": str(self.log),
            "SHIM_STATE": str(self.state),
        }
        env.pop("SENTRA_AGENT_ENROLLMENT_KEY", None)
        env.pop("SENTRA_AGENT_ENROLLMENT_TOKEN", None)
        return subprocess.run(  # noqa: S603  (our own scripts, fixed arguments)
            [BASH, str(self.package / script), *args],
            capture_output=True,
            text=True,
            env=env,
            timeout=120,
            check=False,
        )

    def install(self, *args: str) -> subprocess.CompletedProcess[str]:
        return self.run("install-sentra-agent.sh", "--python", sys.executable, *args)

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def path(self, relative: str) -> Path:
        return self.root / relative

    def identity(self) -> dict[str, Any]:
        data: dict[str, Any] = json.loads(
            self.path("var/lib/sentra-agent/identity.json").read_text()
        )
        return data

    def all_text(self) -> str:
        parts = []
        for file in self.root.rglob("*"):
            if file.is_file() and "/lib/" not in str(file.relative_to(self.root)):
                parts.append(file.read_text(errors="replace"))
        return "\n".join(parts)


@pytest.fixture
def host(tmp_path: Path) -> Host:
    return Host(tmp_path)


def _token_file(tmp_path: Path) -> Path:
    path = tmp_path / "enrollment.token"
    path.write_text(TOKEN + "\n")
    path.chmod(0o600)
    return path


def test_install_enrolls_configures_and_starts(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    token_file = _token_file(tmp_path)

    result = host.install("--server", url, "--token-file", str(token_file))

    assert result.returncode == 0, result.stderr
    assert "enrolled: agent_id=" in result.stdout
    # One-time token: used once, deleted, never written anywhere, never printed.
    assert not token_file.exists()
    assert not host.path("var/lib/sentra-agent/enrollment.token").exists()
    assert TOKEN not in host.all_text()
    assert TOKEN not in result.stdout + result.stderr
    assert [h.get("X-Enrollment-Token") for h in state.headers] == [TOKEN]
    # While it existed, the copy for the agent was readable by its owner only.
    assert (host.state / "token_mode").read_text().split() == ["600"]
    # The agent holds its own token, private to the service user.
    identity = host.identity()
    assert identity["token"] == {"scheme": "plain", "value": state.tokens[identity["agent_id"]]}
    identity_mode = host.path("var/lib/sentra-agent/identity.json").stat().st_mode
    assert stat.S_IMODE(identity_mode) == 0o600
    assert stat.S_IMODE(host.path("var/lib/sentra-agent").stat().st_mode) == 0o700
    # Configuration: server URL and paths, nothing secret.
    config = host.path("etc/sentra-agent/agent.toml").read_text()
    assert f'api_url = "{url}"' in config
    assert f'state_dir = "{host.root}/var/lib/sentra-agent"' in config
    assert "token" not in config.lower().replace("# ", "")
    assert stat.S_IMODE(host.path("etc/sentra-agent/agent.toml").stat().st_mode) == 0o640
    # Runtime, launcher and unit.
    launcher = host.path("opt/sentra-agent/bin/sentra-agent").read_text()
    assert f"exec {sys.executable} -s -m sentra_agent" in launcher
    unit = host.path("etc/systemd/system/sentra-agent.service").read_text()
    assert unit == (PACKAGING / "sentra-agent.service").read_text()
    assert host.path("opt/sentra-agent/uninstall-sentra-agent.sh").exists()
    # Privileged steps, in order, with least privilege.
    calls = host.calls()
    useradd = next(c for c in calls if c.startswith("useradd"))
    for flag in ("--system", "--no-create-home", "nologin", "sentra-agent"):
        assert flag in useradd
    assert any(c.startswith("chown sentra-agent:sentra-agent") and "var/lib" in c for c in calls)
    assert "runuser -u sentra-agent" in calls
    systemctl = [c for c in calls if c.startswith("systemctl")]
    assert systemctl[-4:] == [
        "systemctl daemon-reload",
        "systemctl enable sentra-agent",
        "systemctl restart sentra-agent",
        "systemctl is-active --quiet sentra-agent",
    ]


def test_inline_token_warns_and_leaves_no_trace(
    host: Host, fake_api: tuple[str, FakeApiState]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)

    result = host.install("--server", url, "--token", TOKEN)

    assert result.returncode == 0, result.stderr
    assert "shell history" in result.stderr
    assert TOKEN not in host.all_text()
    assert TOKEN not in result.stdout


def test_unreachable_server_keeps_the_token_file_for_a_retry(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    token_file = _token_file(tmp_path)

    failed = host.install("--server", "http://127.0.0.1:9", "--token-file", str(token_file))

    assert failed.returncode != 0
    assert "cannot reach the server" in failed.stderr
    assert token_file.exists()  # the user can run the same command again
    assert not host.path("var/lib/sentra-agent/enrollment.token").exists()
    assert not any("restart" in c for c in host.calls())  # nothing started

    retried = host.install("--server", url, "--token-file", str(token_file))
    assert retried.returncode == 0, retried.stderr
    assert not token_file.exists()


def test_rejected_token_fails_clearly_and_starts_nothing(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, _ = fake_api  # the server does not know the token (expired, used, revoked)
    result = host.install("--server", url, "--token-file", str(_token_file(tmp_path)))

    assert result.returncode != 0
    assert "refused the enrollment token" in result.stderr
    assert not host.path("var/lib/sentra-agent/enrollment.token").exists()
    assert not any("restart" in c for c in host.calls())


def test_upgrade_and_reinstall_keep_the_identity(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert host.install("--server", url, "--token-file", str(_token_file(tmp_path))).returncode == 0
    first = host.identity()

    upgraded = host.install("--upgrade")
    reinstalled = host.install("--server", url)

    assert upgraded.returncode == 0, upgraded.stderr
    assert "keeping existing configuration" in upgraded.stdout
    assert "already enrolled" in upgraded.stdout and "already enrolled" in reinstalled.stdout
    assert host.identity() == first
    assert state.paths().count("/agents/register") == 1  # never enrolled again
    assert any("systemctl stop" in c for c in host.calls())  # stopped before replacing


def test_upgrade_without_installation_is_refused(host: Host) -> None:
    result = host.install("--upgrade")
    assert result.returncode != 0 and "existing installation" in result.stderr


@pytest.mark.parametrize(
    ("args", "message"),
    [
        ([], "--server is required"),
        (["--server", "ftp://x"], "must start with http"),
        (["--server", "http://a b"], "not a valid URL"),
        (["--server", "http://x;reboot"], "not a valid URL"),
        (["--server", "http://x", "--token", "abc"], "not a Sentra enrollment token"),
        (["--server", "http://x", "--token-file", "/nonexistent"], "token file not found"),
        (["--server", "http://x", "--token", TOKEN, "--token-file", "/x"], "not both"),
        (["--bogus"], "unknown option"),
    ],
)
def test_invalid_input_is_refused_before_anything_changes(
    host: Host, args: list[str], message: str
) -> None:
    result = host.install(*args)

    assert result.returncode != 0
    assert message in result.stderr
    assert not host.path("etc/sentra-agent/agent.toml").exists()


def test_uninstall_keeps_identity_and_purge_removes_everything(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert host.install("--server", url, "--token-file", str(_token_file(tmp_path))).returncode == 0
    identity = host.identity()

    removed = host.run("uninstall-sentra-agent.sh")

    assert removed.returncode == 0, removed.stderr
    assert not host.path("opt/sentra-agent").exists()
    assert not host.path("etc/systemd/system/sentra-agent.service").exists()
    assert host.identity() == identity  # kept: a reinstall is the same asset
    assert host.path("etc/sentra-agent/agent.toml").exists()
    assert "systemctl disable --now sentra-agent" in host.calls()

    purged = host.run("uninstall-sentra-agent.sh", "--purge")

    assert purged.returncode == 0, purged.stderr
    for gone in ("etc/sentra-agent", "var/lib/sentra-agent", "var/log/sentra-agent"):
        assert not host.path(gone).exists()
    assert "userdel sentra-agent" in host.calls()


def test_systemd_unit() -> None:
    text = (PACKAGING / "sentra-agent.service").read_text()
    unit, service = text.split("[Service]")
    service = service.split("[Install]")[0]
    lines = {line.split("=", 1)[0]: line.split("=", 1)[1] for line in service.splitlines()
             if "=" in line and not line.startswith("#")}  # fmt: skip

    assert lines["User"] == lines["Group"] == "sentra-agent"
    assert lines["ExecStart"] == (
        "/opt/sentra-agent/bin/sentra-agent --config /etc/sentra-agent/agent.toml"
    )
    assert lines["Restart"] == "on-failure" and lines["RestartSec"] == "10"
    assert lines["NoNewPrivileges"] == "true" and lines["CapabilityBoundingSet"] == ""
    assert lines["ProtectSystem"] == "strict"
    assert lines["ReadWritePaths"] == "/var/lib/sentra-agent /var/log/sentra-agent"
    assert "StartLimitBurst=5" in unit  # [Unit], where systemd reads it
    assert "ProtectProc=invisible" not in service.replace("#   ProtectProc", "")
    assert "WantedBy=multi-user.target" in text
    analyze = shutil.which("systemd-analyze")
    if analyze:
        result = subprocess.run(  # noqa: S603
            [analyze, "verify", str(PACKAGING / "sentra-agent.service")],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        problems = [line for line in result.stderr.splitlines() if "is not executable" not in line]
        assert problems == [], problems


def _fake_psutil_wheel(path: Path) -> Path:
    wheel = path / "psutil-7.2.2-cp36-abi3-manylinux2014_x86_64.whl"
    source = Path(psutil.__file__).parent
    with zipfile.ZipFile(wheel, "w") as zf:
        for file in sorted(source.rglob("*")):
            if file.is_file() and "__pycache__" not in file.parts:
                zf.write(file, f"psutil/{file.relative_to(source)}")
    return wheel


def test_build_is_reproducible_and_ships_only_the_agent(tmp_path: Path) -> None:
    wheel = _fake_psutil_wheel(tmp_path)
    outputs = []
    for run in ("a", "b"):
        out = tmp_path / run
        env = {**os.environ, "SOURCE_DATE_EPOCH": "1790000000", "PYTHON": sys.executable}
        subprocess.run(  # noqa: S603
            [BASH, str(PACKAGING / "build.sh"), "--psutil-wheel", str(wheel), "--out", str(out)],
            check=True, capture_output=True, env=env, timeout=300,
        )  # fmt: skip
        outputs.append(out)

    tarballs = [next(o.glob("*.tar.gz")) for o in outputs]
    digests = [hashlib.sha256(t.read_bytes()).hexdigest() for t in tarballs]
    assert digests[0] == digests[1]
    assert (outputs[0] / f"{tarballs[0].name}.sha256").read_text().split()[0] == digests[0]
    with tarfile.open(tarballs[0]) as tar:
        names = tar.getnames()
    top = names[0].split("/")[0]
    assert f"{top}/install-sentra-agent.sh" in names
    assert f"{top}/payload/lib/sentra_agent/runner.py" in names
    assert f"{top}/payload/lib/psutil/__init__.py" in names
    for forbidden in ("backend", "frontend", "alembic", ".env", "tests", "__pycache__", ".git"):
        assert not any(f"/{forbidden}" in name for name in names), forbidden
    debs = list(outputs[0].glob("*.deb"))
    if shutil.which("dpkg-deb"):
        assert len(debs) == 1
        dpkg_deb = shutil.which("dpkg-deb") or "dpkg-deb"
        listing = subprocess.run(  # noqa: S603
            [dpkg_deb, "-c", str(debs[0])], capture_output=True, text=True, check=True
        ).stdout
        assert "./lib/systemd/system/sentra-agent.service" in listing
        assert "./usr/sbin/sentra-agent-setup" in listing


# --- `sentra-agent --enroll` (used by the installer) ------------------------------------


def _enroll(url: str, tmp_path: Path, *extra: str) -> int:
    return main(["--api-url", url, "--state-dir", str(tmp_path / "state"), "--enroll", *extra])


def test_enroll_exit_codes(
    fake_api: tuple[str, FakeApiState], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, state = fake_api
    monkeypatch.delenv("SENTRA_AGENT_ENROLLMENT_KEY", raising=False)
    monkeypatch.delenv("SENTRA_AGENT_ENROLLMENT_TOKEN", raising=False)
    token_file = _token_file(tmp_path)

    assert _enroll(url, tmp_path) == EXIT_NO_CREDENTIAL
    assert _enroll(url, tmp_path, "--enrollment-token-file", str(token_file)) == EXIT_REJECTED
    other = tmp_path / "unreachable"
    other.mkdir()
    assert _enroll(
        "http://127.0.0.1:9", other, "--enrollment-token-file", str(_token_file(other))
    ) == (EXIT_UNREACHABLE)
    state.enrollment_tokens.add(TOKEN)
    assert _enroll(url, tmp_path, "--enrollment-token-file", str(_token_file(tmp_path))) == (
        EXIT_ENROLLED
    )
    before = len(state.requests)
    assert _enroll(url, tmp_path) == EXIT_ENROLLED  # already enrolled: no API call
    assert len(state.requests) == before


def test_log_dir_setting(
    fake_api: tuple[str, FakeApiState], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = tmp_path / "agent.toml"
    config.write_text(
        f'api_url = "{url}"\nstate_dir = "{tmp_path / "state"}"\nlog_dir = "{tmp_path / "logs"}"\n'
    )

    code = main(["--config", str(config), "--enroll", "--enrollment-token-file",
                 str(_token_file(tmp_path))])  # fmt: skip

    assert code == EXIT_ENROLLED
    log = (tmp_path / "logs" / "agent.log").read_text()
    assert "agent enrolled" in log and TOKEN not in log
    assert not (tmp_path / "state" / "logs").exists()
