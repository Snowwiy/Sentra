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
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import warnings
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
    "getent": (
        'if [ "$1" = group ]; then [ "$2" = systemd-journal ] && echo "systemd-journal:x:101:"'
        "; exit; fi\n"
        '[ -f "$SHIM_STATE/user" ] && echo "sentra-agent:x:999:999::/x:/usr/sbin/nologin"'
    ),
    "usermod": 'echo "usermod $*" >> "$SHIM_LOG"',
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


def test_upgrade_over_an_http_config_is_refused_before_touching_the_agent(host: Host) -> None:
    # Fase 7D.1: un agente 0.6.x configurado con http:// hacia otro equipo sigue funcionando;
    # el instalador 0.7.0 se detiene antes de parar el servicio y explica la migración.
    config = host.path("etc/sentra-agent/agent.toml")
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text('api_url = "http://192.168.50.201:8000"\n')

    result = host.install("--upgrade")

    assert result.returncode != 0
    assert "outside loopback" in result.stderr and "https://" in result.stderr
    assert config.read_text() == 'api_url = "http://192.168.50.201:8000"\n'


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
        # Fase 7D.1 (H04): http:// solo hacia loopback.
        (["--server", "http://10.0.0.5:8000"], "outside loopback"),
        (["--server", "http://sentra.lan"], "docs/agent-https-migration.md"),
        (["--server", "https://x", "--token", "abc"], "not a Sentra enrollment token"),
        (["--server", "https://x", "--token-file", "/nonexistent"], "token file not found"),
        (["--server", "https://x", "--token", TOKEN, "--token-file", "/x"], "not both"),
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
        own, foreign = _verify_unit(analyze, PACKAGING / "sentra-agent.service")
        assert own == [], own
        _report_foreign(foreign)


# --- systemd-analyze verify: problemas propios frente a unidades ajenas (7D.2-CI-Fix2) ---------
#
# `systemd-analyze verify` carga también las unidades de las que depende la nuestra
# (multi-user.target, network-online.target y lo que arrastran) y avisa de problemas en ellas.
# En el runner ubuntu-latest, con un systemd reciente, aparecen avisos como
# "/usr/lib/systemd/system/walinuxagent.service:21: Support for option CPUAccounting= has been
# removed" que no dependen de Sentra. Antes cualquier línea de stderr hacía fallar el test.
#
# Ahora cada línea se atribuye a su origen por el prefijo que systemd pone delante:
#   "<ruta del fichero>:<línea>: ..."  (aviso de sintaxis de una unidad concreta)
#   "<nombre de unidad>: ..."          (aviso semántico de esa unidad)
# Una línea es ajena solo si nombra OTRA ruta u OTRA unidad. Lo que no se puede atribuir se
# trata como propio (falla cerrado): un formato nuevo de systemd hará fallar el test en lugar de
# ocultar un error. No depende de la versión de systemd ni de una lista de opciones concretas.

# Único aviso propio aceptado: el ejecutable instalado no existe en la máquina de pruebas (el
# paquete no está instalado). Se limita a los comandos bajo /opt/sentra-agent/: un ExecStart
# que apunte a otro sitio sigue fallando.
_MISSING_INSTALLED_BINARY = re.compile(r"Command /opt/sentra-agent/\S+ is not executable\b")
# "<ruta absoluta>:<línea>:" o "<unidad>.<tipo>:" al principio de la línea.
_FILE_PREFIX = re.compile(r"^(?P<path>/[^:]+):\d+: ")
_UNIT_PREFIX = re.compile(
    r"^(?P<unit>[\w@\-.\\]+\.(?:service|socket|target|slice|timer|path|mount|automount|"
    r"swap|scope|device)): "
)


def _classify_verify_output(stderr: str, unit_file: Path) -> tuple[list[str], list[str]]:
    """Separa la salida de `systemd-analyze verify` en problemas propios y avisos ajenos."""
    own: list[str] = []
    foreign: list[str] = []
    unit_path = os.path.realpath(unit_file)
    for line in stderr.splitlines():
        if not line.strip():
            continue
        file_match = _FILE_PREFIX.match(line)
        unit_match = _UNIT_PREFIX.match(line)
        if file_match:
            mine = os.path.realpath(file_match["path"]) == unit_path
        elif unit_match:
            mine = unit_match["unit"] == unit_file.name
        else:
            mine = True  # sin atribución posible: se trata como propio
        if not mine:
            foreign.append(line)
        elif not _MISSING_INSTALLED_BINARY.search(line):
            own.append(line)
    return own, foreign


def _verify_unit(
    analyze: str, unit_file: Path, env: dict[str, str] | None = None
) -> tuple[list[str], list[str]]:
    result = subprocess.run(  # noqa: S603  (binario del sistema, argumentos fijos)
        [analyze, "verify", str(unit_file)],
        capture_output=True, text=True, check=False, env=env,
    )  # fmt: skip
    return _classify_verify_output(result.stderr, unit_file)


def _report_foreign(foreign: list[str]) -> None:
    # Visibles en el resumen de pytest pero sin hacer fallar el test: no son defectos de Sentra
    # y no se pueden corregir desde este repositorio.
    for line in foreign:
        warnings.warn(f"systemd-analyze (unidad ajena a Sentra): {line}", stacklevel=2)


_UNIT = "/x/packaging/linux/sentra-agent.service"


@pytest.mark.parametrize(
    ("stderr", "own", "foreign"),
    [
        # Avisos reales del runner ubuntu-latest (PR #13): ajenos, no fallan.
        (
            "/usr/lib/systemd/system/xfs_scrub_all.service:26: Support for option "
            "CPUAccounting= has been removed and it is ignored\n"
            "/usr/lib/systemd/system/system-xfs_scrub.slice:15: Support for option "
            "CPUAccounting= has been removed and it is ignored\n"
            "/usr/lib/systemd/system/walinuxagent.service:21: Support for option "
            "CPUAccounting= has been removed and it is ignored\n"
            "sentra-agent.service: Command /opt/sentra-agent/bin/sentra-agent is not "
            "executable: No such file or directory\n",
            0,
            3,
        ),
        # Errores en nuestro fichero: fallan, aunque el mensaje sea el mismo que en otra unidad.
        (f"{_UNIT}:23: Failed to parse service restart specifier, ignoring: sometimes\n", 1, 0),
        (
            f"{_UNIT}:26: Support for option CPUAccounting= has been removed and it is ignored\n",
            1,
            0,
        ),
        (f"{_UNIT}:57: Unknown key name 'Bogus' in section 'Install', ignoring.\n", 1, 0),
        # Aviso semántico de nuestra unidad por nombre: falla.
        ("sentra-agent.service: Service has no ExecStart=, ExecStop=, or SuccessAction=.\n", 1, 0),
        # Ejecutable fuera de /opt/sentra-agent: no se acepta como "paquete no instalado".
        ("sentra-agent.service: Command /usr/bin/evil is not executable: No such file\n", 1, 0),
        # Línea sin atribución posible: se trata como propia (falla cerrado).
        ("Failed to load something unexpected\n", 1, 0),
        # Otra unidad por nombre: ajena.
        ("walinuxagent.service: Some semantic warning\n", 0, 1),
        ("", 0, 0),
    ],
)
def test_systemd_verify_output_is_attributed_to_its_unit(
    stderr: str, own: int, foreign: int
) -> None:
    mine, others = _classify_verify_output(stderr, Path(_UNIT))
    assert (len(mine), len(others)) == (own, foreign), (mine, others)


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze no instalado")
def test_systemd_verify_still_fails_on_real_errors_in_our_unit(tmp_path: Path) -> None:
    """Regresión con systemd real: un fallo en nuestra unidad sigue haciendo fallar el test."""
    analyze = shutil.which("systemd-analyze")
    assert analyze is not None
    broken = tmp_path / "sentra-agent.service"
    text = (PACKAGING / "sentra-agent.service").read_text()
    assert "Restart=on-failure" in text
    broken.write_text(text.replace("Restart=on-failure", "Restart=sometimes") + "Bogus=1\n")
    own, _ = _verify_unit(analyze, broken)
    # Se comprueba por fichero y número de línea, no por el texto del mensaje, que cambia
    # entre versiones de systemd.
    lines = broken.read_text().splitlines()
    restart_line = lines.index("Restart=sometimes") + 1
    bogus_line = lines.index("Bogus=1") + 1
    assert any(line.startswith(f"{broken}:{restart_line}:") for line in own), own
    assert any(line.startswith(f"{broken}:{bogus_line}:") for line in own), own


@pytest.mark.skipif(shutil.which("systemd-analyze") is None, reason="systemd-analyze no instalado")
def test_systemd_verify_ignores_warnings_from_other_units(tmp_path: Path) -> None:
    """Regresión con systemd real: un aviso de una dependencia ajena no hace fallar el test.

    Se sustituye network-online.target (de la que depende la unidad) por una copia con una
    clave desconocida, anteponiendo un directorio propio a la ruta de búsqueda de systemd; el
    ":" final conserva las rutas del sistema para el resto de dependencias.
    """
    analyze = shutil.which("systemd-analyze")
    assert analyze is not None
    units = tmp_path / "units"
    units.mkdir()
    (units / "network-online.target").write_text(
        "[Unit]\nDescription=Ajena de prueba\n[Target]\nBogusForeignKey=1\n"
    )
    env = {**os.environ, "SYSTEMD_UNIT_PATH": f"{units}:"}
    own, foreign = _verify_unit(analyze, PACKAGING / "sentra-agent.service", env)
    assert own == [], own
    assert any("BogusForeignKey" in line for line in foreign), foreign


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
    # Fase 6E.7: el helper de aislamiento viaja en el paquete pero no se habilita solo.
    assert f"{top}/sentra-isolation.service" in names
    assert f"{top}/isolation.toml.example" in names
    assert f"{top}/payload/lib/sentra_agent/isolation_helper.py" in names
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
        assert "./lib/systemd/system/sentra-isolation.service" in listing
        assert "./opt/sentra-agent/share/isolation.toml.example" in listing


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


# --- Fase 5C.1: acceso al journal y finales de línea -----------------------------------------


def test_install_grants_read_only_journal_access_once(
    host: Host, fake_api: tuple[str, FakeApiState], tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    result = host.install("--server", url, "--token-file", str(_token_file(tmp_path)))
    assert result.returncode == 0, result.stderr
    grants = [c for c in host.calls() if c.startswith("usermod")]
    # systemd-journal (solo lectura del journal), nunca adm si existe el primero, nunca root.
    assert grants == ["usermod -a -G systemd-journal sentra-agent"]
    assert "systemd-journal" in result.stdout


def test_repository_forces_lf_on_linux_packaging_files() -> None:
    git = shutil.which("git")
    repo = AGENT_DIR.parent
    if git is None or not (repo / ".git").exists():
        pytest.skip("not a git checkout")
    files = [
        "agent/packaging/linux/build.sh",
        "agent/packaging/linux/install-sentra-agent.sh",
        "agent/packaging/linux/sentra-agent.service",
        "agent/packaging/linux/debian/postinst",
        "agent/packaging/linux/debian/control.in",
        "deploy/systemd/sentra.service",
    ]
    out = subprocess.run(  # noqa: S603
        [git, "-C", str(repo), "check-attr", "eol", "--", *files],
        capture_output=True, text=True, check=True,
    ).stdout  # fmt: skip
    assert out.count("eol: lf") == len(files), out


def test_build_from_a_crlf_checkout_produces_lf_packages(tmp_path: Path) -> None:
    """Clon en Windows con autocrlf: el paquete no debe llevar CR (bash/systemd/dpkg)."""
    repo = tmp_path / "repo"
    agent = repo / "agent"
    shutil.copytree(AGENT_DIR / "sentra_agent", agent / "sentra_agent")
    shutil.copytree(PACKAGING, agent / "packaging" / "linux")
    shutil.copy2(AGENT_DIR / "pyproject.toml", agent / "pyproject.toml")
    (repo / "docs").mkdir()
    shutil.copy2(
        AGENT_DIR.parent / "docs" / "agent-linux-installation.md",
        repo / "docs" / "agent-linux-installation.md",
    )
    linux = agent / "packaging" / "linux"
    crlf = [agent / "pyproject.toml", *(p for p in linux.rglob("*") if p.is_file())]
    for path in crlf:
        if path.name == "build.sh":
            continue  # .gitattributes lo mantiene en LF; con CRLF bash ni arrancaría
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
    out = tmp_path / "out"
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1790000000", "PYTHON": sys.executable}
    subprocess.run(  # noqa: S603
        [BASH, str(linux / "build.sh"), "--psutil-wheel", str(_fake_psutil_wheel(tmp_path)),
         "--out", str(out)],
        check=True, capture_output=True, env=env, timeout=300,
    )  # fmt: skip
    from sentra_agent import __version__

    tarball = next(out.glob("*.tar.gz"))
    assert tarball.name == f"sentra-agent-{__version__}-linux-x86_64.tar.gz"
    with tarfile.open(tarball) as tar:
        for member in tar.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name in ("install-sentra-agent.sh", "uninstall-sentra-agent.sh",
                        "sentra-agent.service", "VERSION"):  # fmt: skip
                data = tar.extractfile(member)
                assert data is not None
                content = data.read()
                assert b"\r" not in content, member.name
                if name == "VERSION":
                    assert content.startswith(f"version={__version__}\n".encode())
    dpkg_deb = shutil.which("dpkg-deb")
    if dpkg_deb:
        deb = next(out.glob("*.deb"))
        assert "\r" not in deb.name
        control = subprocess.run(  # noqa: S603
            [dpkg_deb, "-f", str(deb)], capture_output=True, check=True
        ).stdout
        assert b"\r" not in control and f"Version: {__version__}".encode() in control
        extract = tmp_path / "deb"
        subprocess.run([dpkg_deb, "-e", str(deb), str(extract)], check=True)  # noqa: S603
        for script in ("preinst", "postinst", "prerm", "postrm"):
            assert b"\r" not in (extract / script).read_bytes()


@pytest.mark.parametrize(
    ("script", "shell"),
    [
        ("agent/packaging/linux/debian/preinst", "sh"),
        ("agent/packaging/macos/scripts/preinstall", "bash"),
    ],
)
@pytest.mark.parametrize(
    ("api_url", "allowed"),
    [
        ("https://sentra.lan", True),
        ("http://127.0.0.1:8000", True),
        ("http://localhost:8000", True),
        ("http://[::1]:8000", True),
        ("http://192.168.50.201:8000", False),
        ("http://localhost.evil.example", False),
        ("http://127.evil.example", False),
    ],
)
def test_package_upgrade_with_http_config_is_cancelled_before_replacing_the_agent(
    tmp_path: Path, script: str, shell: str, api_url: str, allowed: bool
) -> None:
    """Fase 7D.1 (H04): el .deb (preinst) y el .pkg (preinstall) cancelan la actualización
    si el agente instalado usa http:// fuera de loopback: dpkg / Installer dejan la versión
    anterior funcionando en lugar de instalar una que no arrancaría."""
    executable = shutil.which(shell)
    if executable is None:
        pytest.skip(f"{shell} not available")
    config = tmp_path / "agent.toml"
    config.write_text(f'api_url = "{api_url}"\ninterval_seconds = 30\n')
    result = subprocess.run(  # noqa: S603
        [executable, str(AGENT_DIR.parent / script), "upgrade"],
        capture_output=True,
        text=True,
        env={"PATH": os.environ.get("PATH", ""), "SENTRA_AGENT_PREINST_CONFIG": str(config)},
        check=False,
    )
    assert (result.returncode == 0) is allowed, result.stderr
    if not allowed:
        assert "https" in result.stderr
