"""Fase 6C.5: distribución macOS (instalador, desinstalador, diagnóstico, plist, .pkg).

El instalador se ejecuta de verdad (bash) bajo SENTRA_ROOT=<tmp>, con `uname`, `sw_vers`,
`sysctl`, `id`, `chown`, `launchctl`, `security`, `pkgutil` y `curl` falsos que registran sus
llamadas, contra la API falsa de conftest.py. El código real del agente se enrola a través
del lanzador generado. Nada fuera del directorio temporal se toca. En un Mac real quedan por
validar launchd, el keychain del sistema y el .pkg (docs/agent-macos-installation.md).
"""

import json
import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import psutil
import pytest

from tests.conftest import FakeApiState

pytestmark = pytest.mark.skipif(
    sys.platform not in ("linux", "darwin") or shutil.which("bash") is None,
    reason="POSIX packaging",
)

AGENT_DIR = Path(__file__).resolve().parents[1]
PACKAGING = AGENT_DIR / "packaging" / "macos"
TOKEN = "sentra_et_" + "M" * 43
BASH = shutil.which("bash") or "/bin/bash"
LABEL = "com.sentra.agent"

SHIMS = {
    "id": "echo 0",
    "uname": 'case "$1" in -s) echo "${FAKE_UNAME:-Darwin}" ;; '
    "-m) echo arm64 ;; *) echo Darwin ;; esac",
    "sw_vers": 'if [ "$1" = -productVersion ]; then echo "${FAKE_MACOS:-15.1}"; '
    'else printf "ProductName:\\tmacOS\\nProductVersion:\\t15.1\\n"; fi',
    "sysctl": 'case "$*" in *hw.optional.arm64*) echo "${FAKE_ARM64:-1}" ;; *) exit 1 ;; esac',
    "chown": 'echo "chown $*" >> "$SHIM_LOG"',
    "launchctl": (
        'echo "launchctl $*" >> "$SHIM_LOG"\n'
        'case "$1" in\n'
        '  print) [ -f "$SHIM_STATE/loaded" ] || exit 113; '
        'echo "  state = running"; echo "  pid = 4242" ;;\n'
        '  bootstrap) touch "$SHIM_STATE/loaded" ;;\n'
        '  bootout) rm -f "$SHIM_STATE/loaded" ;;\n'
        "esac"
    ),
    "security": (
        'echo "security $*" >> "$SHIM_LOG"\n'
        'case "$1" in\n'
        '  delete-generic-password) [ -f "$SHIM_STATE/item" ] || exit 44; '
        'rm -f "$SHIM_STATE/item" ;;\n'
        '  find-generic-password) [ -f "$SHIM_STATE/item" ] || exit 44 ;;\n'
        "esac"
    ),
    "pkgutil": 'echo "pkgutil $*" >> "$SHIM_LOG"',
    "curl": 'echo "curl $*" >> "$SHIM_LOG"; printf 200',
}


class Mac:
    """Un Mac falso: un directorio raíz y el registro de las órdenes privilegiadas."""

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
        lib = self.package / "payload" / "lib"
        lib.mkdir(parents=True)
        shutil.copytree(AGENT_DIR / "sentra_agent", lib / "sentra_agent")
        shutil.copytree(Path(psutil.__file__).parent, lib / "psutil")
        for item in PACKAGING.iterdir():
            if item.is_file():
                shutil.copy2(item, self.package / item.name)
        (self.package / "VERSION").write_text("version=0.4.0\narch=arm64\n")

    def run(self, script: str, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        full_env = {
            **os.environ,
            "PATH": f"{self.bin}:{os.environ['PATH']}",
            "SENTRA_ROOT": str(self.root),
            "SHIM_LOG": str(self.log),
            "SHIM_STATE": str(self.state),
            **env,
        }
        full_env.pop("SENTRA_AGENT_ENROLLMENT_KEY", None)
        full_env.pop("SENTRA_AGENT_ENROLLMENT_TOKEN", None)
        return subprocess.run(  # noqa: S603  (nuestros scripts, argumentos fijos)
            [BASH, str(self.package / script), *args],
            capture_output=True,
            text=True,
            env=full_env,
            timeout=120,
            check=False,
        )

    def install(self, *args: str, **env: str) -> subprocess.CompletedProcess[str]:
        return self.run(
            "install-sentra-agent.sh",
            "--python", sys.executable, "--credential-store", "file", *args, **env,
        )  # fmt: skip

    def path(self, relative: str) -> Path:
        return self.root / relative

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines()

    def token_file(self, tmp: Path) -> Path:
        path = tmp / "enrollment.token"
        path.write_text(TOKEN + "\n")
        path.chmod(0o600)
        return path


@pytest.fixture
def mac(tmp_path: Path) -> Mac:
    return Mac(tmp_path)


PREFIX = "Library/Sentra/Agent"


def test_plist_is_a_valid_root_launch_daemon() -> None:
    data = plistlib.loads((PACKAGING / f"{LABEL}.plist").read_bytes())
    assert data["Label"] == LABEL
    assert data["ProgramArguments"] == [
        "/Library/Sentra/Agent/bin/sentra-agent",
        "--config",
        "/Library/Sentra/Agent/agent.toml",
        "--no-console-log",
    ]
    assert data["RunAtLoad"] is True
    assert data["KeepAlive"] == {"SuccessfulExit": False}  # reinicio solo tras un fallo
    assert data["ThrottleInterval"] >= 10
    assert data["UserName"] == "root"
    assert data["Umask"] == 0o077
    assert data["StandardErrorPath"].startswith("/Library/Logs/Sentra/")


def test_install_enrolls_from_a_token_file_and_starts_the_daemon(
    mac: Mac, tmp_path: Path, fake_api: tuple[str, FakeApiState]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    token_file = mac.token_file(tmp_path)

    result = mac.install("--server", url, "--token-file", str(token_file))

    assert result.returncode == 0, result.stderr
    assert "enrolled: agent_id=" in result.stdout
    assert not token_file.exists()  # token de un solo uso borrado
    assert not mac.path(f"{PREFIX}/state/enrollment.token").exists()
    register = next(body for path, body in state.requests if path == "/agents/register")
    assert register["installation_method"] == "macos_launchd"
    config = mac.path(f"{PREFIX}/agent.toml").read_text()
    assert f'api_url = "{url}"' in config and 'credential_store = "file"' in config
    assert TOKEN not in config
    assert (mac.path(f"{PREFIX}/state").stat().st_mode & 0o777) == 0o700
    identity = json.loads(mac.path(f"{PREFIX}/state/identity.json").read_text())
    assert identity["asset_id"] == state.agents[identity["agent_id"]]
    assert mac.path(f"Library/LaunchDaemons/{LABEL}.plist").is_file()
    assert mac.path(f"etc/newsyslog.d/{LABEL}.conf").is_file()
    calls = mac.calls()
    assert f"launchctl bootstrap system {mac.path(f'Library/LaunchDaemons/{LABEL}.plist')}" in calls
    assert "chown root:wheel " + str(mac.path(f"Library/LaunchDaemons/{LABEL}.plist.new")) in calls
    # Lanzador aislado: -I -S y el runtime de root, nunca site-packages ni PYTHONPATH.
    launcher = mac.path(f"{PREFIX}/bin/sentra-agent").read_text()
    assert f'exec "{sys.executable}" -I -S -c' in launcher
    # El token nunca aparece en ningún fichero instalado ni en las órdenes ejecutadas.
    for file in mac.root.rglob("*"):
        if file.is_file() and "/lib/" not in str(file):
            assert TOKEN not in file.read_text(errors="replace"), file
    assert TOKEN not in mac.log.read_text()


def test_token_is_never_accepted_on_the_command_line(mac: Mac) -> None:
    result = mac.run("install-sentra-agent.sh", "--server", "https://s", "--token", TOKEN)
    assert result.returncode != 0
    assert "--token-file" in result.stderr


def test_rejected_token_and_unreachable_server(
    mac: Mac, tmp_path: Path, fake_api: tuple[str, FakeApiState]
) -> None:
    url, _ = fake_api
    rejected = mac.install("--server", url, "--token-file", str(mac.token_file(tmp_path)))
    assert rejected.returncode == 1 and "refused the enrollment token" in rejected.stderr
    unreachable = mac.install(
        "--server", "http://127.0.0.1:9", "--token-file", str(mac.token_file(tmp_path))
    )
    assert unreachable.returncode == 1 and "cannot reach the server" in unreachable.stderr
    assert (tmp_path / "enrollment.token").exists()  # se conserva para reintentar


def test_platform_checks(mac: Mac, tmp_path: Path) -> None:
    token = str(mac.token_file(tmp_path))
    linux = mac.install("--server", "https://s", "--token-file", token, FAKE_UNAME="Linux")
    assert "for macOS" in linux.stderr
    old = mac.install("--server", "https://s", "--token-file", token, FAKE_MACOS="12.7.4")
    assert "not supported" in old.stderr
    intel = mac.install("--server", "https://s", "--token-file", token, FAKE_ARM64="0")
    assert "this package is for arm64, this Mac is x86_64" in intel.stderr


def test_unsafe_python_is_refused(mac: Mac, tmp_path: Path) -> None:
    # Un intérprete en un directorio que cualquiera puede modificar no sirve para root.
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir()
    unsafe.chmod(0o777)
    copy = unsafe / "python3"
    copy.symlink_to(sys.executable)
    check = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-S", str(PACKAGING / "check-python.py")],
        capture_output=True, text=True, check=False,
    )  # fmt: skip
    if check.returncode != 0:
        pytest.skip(f"el Python de pruebas no es de root: {check.stdout[:200]}")
    result = mac.run(
        "install-sentra-agent.sh", "--python", "/nonexistent/python3", "--server", "https://s"
    )
    assert result.returncode != 0 and "not an executable" in result.stderr


def test_check_python_flags_writable_files(tmp_path: Path) -> None:
    sys.path.insert(0, str(PACKAGING))
    try:
        import importlib

        module: Any = importlib.import_module("check-python".replace("-", "_"))
    except ImportError:
        import importlib.util

        spec = importlib.util.spec_from_file_location("check_python", PACKAGING / "check-python.py")
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(PACKAGING))
    target = tmp_path / "lib.py"
    target.write_text("")
    target.chmod(0o666)
    if sys.platform == "win32":  # permisos POSIX; también acota el tipo para mypy --platform win32
        pytest.skip("permisos POSIX")
    uid = os.getuid()
    assert module._problem(str(target), uid, False) == "writable by any user"
    target.chmod(0o664)
    assert module._problem(str(target), uid, False).startswith("writable by group")
    target.chmod(0o644)
    assert module._problem(str(target), uid, False) is None
    assert "not root" in module._problem(str(target), uid + 1, False)


def test_upgrade_keeps_identity_and_restarts(
    mac: Mac, tmp_path: Path, fake_api: tuple[str, FakeApiState]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert (
        mac.install("--server", url, "--token-file", str(mac.token_file(tmp_path))).returncode == 0
    )
    identity = mac.path(f"{PREFIX}/state/identity.json").read_text()
    registrations = state.paths().count("/agents/register")

    upgraded = mac.install("--upgrade")

    assert upgraded.returncode == 0, upgraded.stderr
    assert "already enrolled" in upgraded.stdout
    assert mac.path(f"{PREFIX}/state/identity.json").read_text() == identity
    assert state.paths().count("/agents/register") == registrations
    calls = mac.calls()
    assert "launchctl bootout system/com.sentra.agent" in calls
    assert (
        calls.count(
            f"launchctl bootstrap system {mac.path(f'Library/LaunchDaemons/{LABEL}.plist')}"
        )
        == 2
    )


def test_pkg_postinstall_without_configuration_waits_for_setup(mac: Mac) -> None:
    # El .pkg ya dejó el runtime en su sitio; postinstall no enrola (no hay token).
    lib = mac.path(f"{PREFIX}/lib")
    shutil.copytree(mac.package / "payload" / "lib", lib)
    share = mac.path(f"{PREFIX}/share")
    share.mkdir(parents=True)
    for item in PACKAGING.iterdir():
        if item.is_file():
            shutil.copy2(item, share / item.name)
    result = subprocess.run(  # noqa: S603
        [BASH, str(share / "install-sentra-agent.sh"), "--package-postinstall",
         "--python", sys.executable],
        capture_output=True, text=True, check=False, timeout=120,
        env={**os.environ, "PATH": f"{mac.bin}:{os.environ['PATH']}",
             "SENTRA_ROOT": str(mac.root), "SHIM_LOG": str(mac.log),
             "SHIM_STATE": str(mac.state)},
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    assert "sentra-agent-setup --server URL --token-file FILE" in result.stdout
    assert mac.path(f"{PREFIX}/bin/sentra-agent-setup").is_file()
    assert not any(c.startswith("launchctl bootstrap") for c in mac.calls())


def test_diagnose_never_prints_the_token(
    mac: Mac, tmp_path: Path, fake_api: tuple[str, FakeApiState]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert (
        mac.install("--server", url, "--token-file", str(mac.token_file(tmp_path))).returncode == 0
    )
    identity = json.loads(mac.path(f"{PREFIX}/state/identity.json").read_text())
    agent_token = state.tokens[identity["agent_id"]]

    report = mac.run("diagnose-sentra-agent.sh")

    assert report.returncode == 0, report.stderr
    assert f"agent_id: {identity['agent_id']}" in report.stdout
    assert "scheme: plain" in report.stdout
    assert "state = running" in report.stdout
    assert f"GET {url}/api/v1/health -> 200" in report.stdout
    assert agent_token not in report.stdout + report.stderr
    assert TOKEN not in report.stdout


def test_uninstall_keeps_identity_and_purge_removes_everything(
    mac: Mac, tmp_path: Path, fake_api: tuple[str, FakeApiState]
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    assert (
        mac.install("--server", url, "--token-file", str(mac.token_file(tmp_path))).returncode == 0
    )
    (mac.state / "item").touch()  # un elemento en el keychain del sistema (falso)
    shutil.copy2(PACKAGING / "uninstall-sentra-agent.sh", tmp_path / "uninstall.sh")
    mac.package = tmp_path

    kept = mac.run("uninstall.sh")
    assert kept.returncode == 0, kept.stderr
    assert not mac.path(f"Library/LaunchDaemons/{LABEL}.plist").exists()
    assert not mac.path(f"{PREFIX}/lib").exists()
    assert mac.path(f"{PREFIX}/state/identity.json").is_file()
    assert "launchctl bootout system/com.sentra.agent" in mac.calls()

    purged = mac.run("uninstall.sh", "--purge")
    assert purged.returncode == 0, purged.stderr
    assert not mac.path(PREFIX).exists() and not mac.path("Library/Logs/Sentra").exists()
    assert "1 keychain item(s)" in purged.stdout
    # El borrado del Keychain nunca lleva el secreto (-w) en la línea de órdenes.
    assert all(" -w" not in c for c in mac.calls() if c.startswith("security"))


def test_build_pkg_refuses_to_run_outside_macos(tmp_path: Path) -> None:
    if sys.platform == "darwin":
        pytest.skip("en macOS el build real lo prueba el job de CI")
    result = subprocess.run(  # noqa: S603
        [BASH, str(PACKAGING / "build-pkg.sh")], capture_output=True, text=True, check=False
    )
    assert result.returncode == 1
    assert "only works on macOS" in result.stderr


def test_scripts_are_bash_3_2_compatible() -> None:
    # macOS trae bash 3.2: nada de arrays asociativos, ${var,,}, mapfile ni readarray.
    for script in PACKAGING.glob("*.sh"):
        source = script.read_text()
        for construct in ("declare -A", ",,}", "^^}", "mapfile", "readarray", "|&"):
            assert construct not in source, (script.name, construct)
        subprocess.run([BASH, "-n", str(script)], check=True)  # noqa: S603
    for script in (PACKAGING / "scripts").iterdir():
        subprocess.run([BASH, "-n", str(script)], check=True)  # noqa: S603
