"""Servicio Windows (Fase 4F): plan de instalación, enrolamiento por el servicio, SCM y DPAPI.

Todo corre en cualquier plataforma: las rutas son PureWindowsPath, el SCM se sustituye por una
función que registra los estados y DPAPI por un cifrado falso. Nada toca el sistema real; lo
que solo puede comprobarse en un Windows físico está en docs/agent-windows-installation.md.
"""

import json
import logging
import re
import sys
import threading
import time
import uuid
from pathlib import Path, PureWindowsPath
from typing import Any

import pytest

from sentra_agent import credentials, winsetup
from sentra_agent.__main__ import main
from sentra_agent.config import AgentConfig, load_config
from sentra_agent.enrollment import (
    STATUS_FILE,
    bootstrap_service_enrollment,
)
from sentra_agent.identity import IdentityStore
from sentra_agent.logs import configure_logging
from sentra_agent.winservice import (
    ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_SERVICE_SPECIFIC_ERROR,
    NO_ERROR,
    SERVICE_ACCEPT_SHUTDOWN,
    SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN,
    SERVICE_CONTROL_STOP,
    SERVICE_RUNNING,
    SERVICE_START_PENDING,
    SERVICE_STOP_PENDING,
    SERVICE_STOPPED,
    ServiceStatus,
    StatusReporter,
    run_service_body,
)
from tests.conftest import FakeApiState
from tests.test_runner import build_agent

TOKEN = "sentra_et_" + "W" * 43
PROGRAM_FILES = r"C:\Program Files"
PROGRAM_DATA = r"C:\ProgramData"


def layout() -> winsetup.WindowsLayout:
    return winsetup.make_layout(PROGRAM_FILES, PROGRAM_DATA)


def service_config(make_config: Any, url: str, tmp_path: Path, **overrides: Any) -> AgentConfig:
    """Configuración como la del servicio: token de un solo uso en state\\enrollment.token."""
    overrides.setdefault("enrollment_key", None)
    overrides.setdefault("installation_method", "windows_service")
    config: AgentConfig = make_config(
        url, enrollment_token_file=tmp_path / "state" / "enrollment.token", **overrides
    )
    return config


def drop_token(config: AgentConfig, value: str = TOKEN) -> Path:
    path = config.enrollment_token_file
    assert path is not None
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    return path


def read_status(config: AgentConfig) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((config.state_dir / STATUS_FILE).read_text("utf-8"))
    return data


# --- Rutas, línea del servicio y agent.toml -------------------------------------------------


def test_layout_separates_binaries_config_state_and_logs() -> None:
    paths = layout()
    assert paths.install_dir == PureWindowsPath(r"C:\Program Files\Sentra Agent")
    assert paths.runtime_python == PureWindowsPath(
        r"C:\Program Files\Sentra Agent\runtime\python.exe"
    )
    assert paths.config_file == PureWindowsPath(r"C:\ProgramData\Sentra\Agent\config\agent.toml")
    assert paths.state_dir == PureWindowsPath(r"C:\ProgramData\Sentra\Agent\state")
    assert paths.log_dir == PureWindowsPath(r"C:\ProgramData\Sentra\Agent\logs")
    assert paths.token_file.parent == paths.state_dir
    # Nada en carpetas del repositorio ni del usuario.
    for path in (paths.install_dir, paths.state_dir, paths.log_dir, paths.config_file):
        assert "Users" not in str(path) and "Sentra\\agent" not in str(path)


def test_service_binary_path_is_always_quoted() -> None:
    binary = winsetup.service_binary_path(layout())
    assert binary == (
        r'"C:\Program Files\Sentra Agent\runtime\python.exe" -I -m sentra_agent --service'
        r' --config "C:\ProgramData\Sentra\Agent\config\agent.toml"'
    )
    # El ejecutable completo, con espacios, va entre comillas: sin ellas el SCM probaría
    # C:\Program.exe (unquoted service path).
    first = re.match(r'^"([^"]+)"', binary)
    assert first is not None and first.group(1).endswith(r"\runtime\python.exe")


@pytest.mark.parametrize(
    "program_files",
    [r"D:\Archivos de programa", r"C:\Program Files (x86)\Otra carpeta"],
)
def test_service_binary_path_with_unusual_folders(program_files: str) -> None:
    binary = winsetup.service_binary_path(winsetup.make_layout(program_files, r"E:\Data Dir"))
    assert binary.startswith(f'"{program_files}\\Sentra Agent\\runtime\\python.exe" ')
    assert binary.endswith(r'--config "E:\Data Dir\Sentra\Agent\config\agent.toml"')


@pytest.mark.parametrize(
    "folder", ["relative\\path", "C:\\it's", 'C:\\"quoted"', "C:\\line\nbreak", ""]
)
def test_layout_rejects_paths_that_could_break_quoting(folder: str) -> None:
    with pytest.raises(winsetup.SetupError):
        winsetup.make_layout(folder, PROGRAM_DATA)


def test_rendered_config_is_valid_toml_for_the_agent_and_has_no_secrets(tmp_path: Path) -> None:
    server = winsetup.normalize_server_url("http://192.168.50.201:8000/")
    text = winsetup.render_config(layout(), server)
    config_file = tmp_path / "agent.toml"
    config_file.write_text(text, encoding="utf-8")

    config = load_config(config_file)

    assert config.api_url == "http://192.168.50.201:8000"
    assert str(config.state_dir) == r"C:\ProgramData\Sentra\Agent\state"
    assert str(config.log_dir) == r"C:\ProgramData\Sentra\Agent\logs"
    assert (
        str(config.enrollment_token_file) == r"C:\ProgramData\Sentra\Agent\state\enrollment.token"
    )
    assert config.installation_method == "windows_service"
    assert config.enrollment_key is None and config.enrollment_token is None
    assert "sentra_et_" not in text and "enrollment_key" not in text


def test_upgrade_keeps_admin_settings_and_only_changes_what_is_asked() -> None:
    existing = (
        'api_url = "http://old:8000"\ninterval_seconds = 15\nlog_level = "DEBUG"\n'
        "state_dir = 'C:\\ProgramData\\Sentra\\Agent\\state'\n"
    )
    kept = winsetup.update_config(existing, None)
    assert "interval_seconds = 15" in kept and 'log_level = "DEBUG"' in kept
    assert 'installation_method = "windows_service"' in kept  # añadido a una config antigua
    moved = winsetup.update_config(kept, winsetup.normalize_server_url("https://sentra.lan"))
    assert 'api_url = "https://sentra.lan"' in moved and "old:8000" not in moved
    assert moved.count("api_url") == 1 and "interval_seconds = 15" in moved


def test_plan_first_install_needs_a_server_and_upgrade_does_not(tmp_path: Path) -> None:
    with pytest.raises(winsetup.SetupError, match="-Server"):
        winsetup.plan(PROGRAM_FILES, PROGRAM_DATA, None)
    config_file = tmp_path / "agent.toml"
    config_file.write_text(
        winsetup.render_config(layout(), winsetup.normalize_server_url("http://10.0.0.5:8000")),
        encoding="utf-8",
    )
    upgrade = winsetup.plan(PROGRAM_FILES, PROGRAM_DATA, None, config_file)
    assert upgrade["config_text"] is None  # nada que reescribir
    assert upgrade["api_url"] == "http://10.0.0.5:8000"
    assert upgrade["virtual_account"] == "NT SERVICE\\SentraAgent"
    assert upgrade["failure_actions"].startswith("restart/")


@pytest.mark.parametrize(
    ("raw", "url", "insecure", "loopback"),
    [
        ("http://192.168.1.10:8000/", "http://192.168.1.10:8000", True, False),
        ("https://sentra.example.lan", "https://sentra.example.lan", False, False),
        ("http://localhost:8000", "http://localhost:8000", True, True),
        ("http://[::1]:8000", "http://[::1]:8000", True, True),
        ("http://[fd00::5]:8000", "http://[fd00::5]:8000", True, False),
    ],
)
def test_server_url(raw: str, url: str, insecure: bool, loopback: bool) -> None:
    assert winsetup.normalize_server_url(raw) == winsetup.ServerUrl(url, insecure, loopback)


@pytest.mark.parametrize(
    "raw",
    ["", "192.168.1.2:8000", "ftp://x", "http://x'; Remove-Item C:\\", 'http://x"', "http://a b"],
)
def test_server_url_rejects_anything_unsafe(raw: str) -> None:
    with pytest.raises(winsetup.SetupError):
        winsetup.normalize_server_url(raw)


def test_service_sid_matches_windows() -> None:
    # Valor conocido de Windows: NT SERVICE\TrustedInstaller.
    assert (
        winsetup.service_sid("TrustedInstaller")
        == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
    )
    assert winsetup.service_sid("SentraAgent") == winsetup.service_sid("sentraagent")


# --- Token de instalación -------------------------------------------------------------------


@pytest.mark.parametrize(
    "content",
    [
        TOKEN.encode(),
        (TOKEN + "\r\n").encode(),
        b"\xef\xbb\xbf" + TOKEN.encode(),  # Bloc de notas
        b"\xff\xfe" + (TOKEN + "\r\n").encode("utf-16-le"),  # Out-File de PowerShell 5.1
    ],
)
def test_token_file_is_normalized(tmp_path: Path, content: bytes) -> None:
    source = tmp_path / "enrollment.token"
    source.write_bytes(content)
    dest = tmp_path / "state" / "enrollment.token"

    winsetup.stage_token(source, dest)

    assert dest.read_bytes() == TOKEN.encode()


def test_invalid_token_file_is_rejected_without_echoing_it(tmp_path: Path) -> None:
    source = tmp_path / "enrollment.token"
    source.write_text("ADMIN_API_KEY=super-secret-value", encoding="utf-8")
    with pytest.raises(winsetup.SetupError) as error:
        winsetup.read_enrollment_token(source)
    assert "super-secret" not in str(error.value)
    assert main_winsetup(["check-token", "--file", str(source)])[0] == 2


def main_winsetup(argv: list[str]) -> tuple[int, str]:
    import contextlib
    import io

    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = winsetup.main(argv)
    return code, out.getvalue()


def test_cli_plan_prints_json(tmp_path: Path) -> None:
    code, out = main_winsetup(
        [
            "plan",
            "--program-files",
            PROGRAM_FILES,
            "--program-data",
            PROGRAM_DATA,
            "--server",
            "http://192.168.1.10:8000",
            "--existing-config",
            str(tmp_path / "missing.toml"),
        ]
    )
    plan = json.loads(out)
    assert code == 0
    assert plan["binary_path"] == winsetup.service_binary_path(layout())
    assert plan["service_sid"] == winsetup.service_sid("SentraAgent")
    assert plan["event_log_readers_sid"] == "S-1-5-32-573"
    assert 'api_url = "http://192.168.1.10:8000"' in plan["config_text"]


# --- Importar la identidad de una ejecución manual ------------------------------------------


def test_manual_identity_keeps_the_agent_id_but_never_the_token(tmp_path: Path) -> None:
    manual = IdentityStore(tmp_path / "manual")
    identity = manual.load_or_create()
    identity.token = "manual-agent-token-0123456789abcdef"
    identity.asset_id = uuid.uuid4()
    manual.save(identity)
    dest = tmp_path / "service" / "identity.json"

    imported = winsetup.import_identity(manual.path, dest)

    assert imported == {"agent_id": str(identity.agent_id), "asset_id": str(identity.asset_id)}
    assert "manual-agent-token" not in dest.read_text("utf-8")
    loaded = IdentityStore(dest.parent).load_or_create()
    assert loaded.agent_id == identity.agent_id and loaded.token is None
    with pytest.raises(winsetup.SetupError):
        winsetup.import_identity(manual.path, dest)  # nunca pisa una identidad del servicio


def test_unusable_manual_identity_is_reported(tmp_path: Path) -> None:
    source = tmp_path / "identity.json"
    source.write_text('{"agent_id": "nope"}', encoding="utf-8")
    with pytest.raises(winsetup.SetupError):
        winsetup.import_identity(source, tmp_path / "dest.json")


# --- Enrolamiento por el servicio ------------------------------------------------------------


def test_service_enrolls_with_the_token_file_and_deletes_it(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path)
    token_file = drop_token(config)
    agent = build_agent(config)

    outcome = bootstrap_service_enrollment(agent, threading.Event())

    assert outcome is not None and outcome.state == "enrolled"
    assert not token_file.exists()
    status = read_status(config)
    assert status["state"] == "enrolled" and status["agent_id"] == str(agent.identity.agent_id)
    agent_token = state.tokens[str(agent.identity.agent_id)]
    identity_text = (config.state_dir / "identity.json").read_text("utf-8")
    for secret in (TOKEN, agent_token):
        assert secret not in json.dumps(status)
    assert TOKEN not in identity_text
    register = state.requests[0][1]
    assert register["installation_method"] == "windows_service"


def test_rejected_token_is_deleted_and_reported(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, _ = fake_api  # el servidor no conoce el token: caducado o ya usado
    config = service_config(make_config, url, tmp_path)
    token_file = drop_token(config)
    agent = build_agent(config)

    outcome = bootstrap_service_enrollment(agent, threading.Event())

    assert outcome is not None and outcome.state == "rejected" and outcome.exit_code == 4
    assert not token_file.exists()  # no volverá a servir
    assert agent.identity.token is None
    assert TOKEN not in (config.state_dir / STATUS_FILE).read_text("utf-8")


def test_token_is_kept_while_the_server_is_unreachable(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    state.unavailable = True
    config = service_config(make_config, url, tmp_path)
    token_file = drop_token(config)
    agent = build_agent(config)
    stop = threading.Event()
    stop.set()  # la parada llega durante la espera del primer reintento

    outcome = bootstrap_service_enrollment(agent, stop)

    assert outcome is not None and outcome.state == "unreachable"
    assert token_file.exists()  # el siguiente arranque lo reintentará
    assert read_status(config)["state"] == "unreachable"

    state.unavailable = False
    again = bootstrap_service_enrollment(build_agent(config), threading.Event())
    assert again is not None and again.state == "enrolled" and not token_file.exists()


def test_service_retries_until_the_server_answers(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    state.unavailable = True
    config = service_config(make_config, url, tmp_path, interval_seconds=5)
    drop_token(config)
    agent = build_agent(config)
    waits: list[float] = []

    class FakeStop(threading.Event):
        def wait(self, timeout: float | None = None) -> bool:
            waits.append(timeout or 0)
            state.unavailable = False  # el servidor vuelve tras el primer fallo
            return False

    outcome = bootstrap_service_enrollment(agent, FakeStop())

    assert outcome is not None and outcome.state == "enrolled"
    assert len(waits) == 1 and 4 <= waits[0] <= 6  # backoff con jitter desde interval_seconds


def test_reinstall_with_a_valid_identity_does_not_spend_the_new_token(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path)
    drop_token(config)
    first = build_agent(config)
    bootstrap_service_enrollment(first, threading.Event())
    own_token = first.identity.token
    second_token = "sentra_et_" + "Z" * 43
    state.enrollment_tokens.add(second_token)
    token_file = drop_token(config, second_token)

    outcome = bootstrap_service_enrollment(build_agent(config), threading.Event())

    assert outcome is not None and outcome.state == "already_enrolled"
    assert not token_file.exists()  # no usado, pero tampoco se deja en disco
    assert second_token in state.enrollment_tokens  # sigue sin consumir en el servidor
    reloaded = IdentityStore(config.state_dir).load_or_create()
    assert reloaded.token == own_token


def test_upgrade_preserves_identity_token_and_does_not_reenroll(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path)
    drop_token(config)
    before = build_agent(config)
    bootstrap_service_enrollment(before, threading.Event())

    # Upgrade: binarios nuevos, mismo state\, sin token de instalación.
    after = build_agent(config)
    assert bootstrap_service_enrollment(after, threading.Event()) is None
    after.cycle()

    assert after.identity.agent_id == before.identity.agent_id
    assert after.identity.asset_id == before.identity.asset_id
    assert after.identity.token == before.identity.token
    assert state.paths().count("/agents/register") == 1


def test_revoked_then_reinstated_agent_reenrolls_as_the_same_asset(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path)
    drop_token(config)
    agent = build_agent(config)
    bootstrap_service_enrollment(agent, threading.Event())
    agent_id = str(agent.identity.agent_id)
    asset_id = state.agents[agent_id]
    # Revocado en el dashboard (su token deja de valer) y reactivado después.
    del state.tokens[agent_id]
    new_token = "sentra_et_" + "R" * 43
    state.enrollment_tokens.add(new_token)
    drop_token(config, new_token)  # instalador con -Reenroll

    outcome = bootstrap_service_enrollment(build_agent(config), threading.Event())

    assert outcome is not None and outcome.state == "enrolled"
    assert outcome.agent_id == agent_id and outcome.asset_id == asset_id
    assert len(state.agents) == 1  # sin activo duplicado


def test_still_revoked_agent_is_rejected_and_the_token_dropped(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path)
    drop_token(config)
    agent = build_agent(config)
    bootstrap_service_enrollment(agent, threading.Event())
    agent_id = str(agent.identity.agent_id)
    del state.tokens[agent_id]
    state.revoked.add(agent_id)  # revocado y sin reactivar
    new_token = "sentra_et_" + "S" * 43
    state.enrollment_tokens.add(new_token)
    token_file = drop_token(config, new_token)

    outcome = bootstrap_service_enrollment(build_agent(config), threading.Event())

    assert outcome is not None and outcome.state == "rejected"
    assert "revoked" in outcome.message
    assert not token_file.exists()


def test_no_secrets_in_service_logs(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    state.enrollment_tokens.add(TOKEN)
    config = service_config(make_config, url, tmp_path, log_dir=tmp_path / "logs")
    drop_token(config)
    log_file = configure_logging(config.state_dir, "DEBUG", config.log_dir, console=False)
    try:
        agent = build_agent(config)
        bootstrap_service_enrollment(agent, threading.Event())
        agent.cycle()
        logging.getLogger("sentra_agent").info("Authorization: Bearer %s", agent.identity.token)
    finally:
        for handler in logging.getLogger().handlers:
            handler.flush()
    text = log_file.read_text("utf-8")
    assert "agent enrolled" in text
    assert TOKEN not in text
    assert agent.identity.token is not None and agent.identity.token not in text
    # Sin consola: el servicio no tiene una; solo el archivo rotado.
    handlers = logging.getLogger().handlers
    assert [type(h).__name__ for h in handlers] == ["RotatingFileHandler"]
    for handler in handlers:
        handler.close()
    logging.getLogger().handlers = []


# --- installation_method ---------------------------------------------------------------------


def test_installation_method_travels_with_register_and_heartbeat(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    agent = build_agent(make_config(url, installation_method="windows_service"))

    agent.cycle()

    register = dict(state.requests)["/agents/register"]
    heartbeat = dict(state.requests)["/agents/heartbeat"]
    assert register["installation_method"] == "windows_service"
    assert heartbeat["host"]["installation_method"] == "windows_service"


def test_manual_runs_do_not_send_installation_method(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    build_agent(make_config(url)).cycle()
    assert "installation_method" not in dict(state.requests)["/agents/register"]
    assert "installation_method" not in dict(state.requests)["/agents/heartbeat"]["host"]


def test_older_server_without_installation_method_still_accepts_the_agent(
    fake_api: tuple[str, FakeApiState], make_config: Any
) -> None:
    url, state = fake_api
    state.unknown_host_fields = {"installation_method"}
    agent = build_agent(make_config(url, installation_method="windows_service"))

    agent.cycle()
    agent.cycle()

    assert agent.identity.token is not None
    assert len(state.telemetry) == 2
    # Una vez rechazado se deja de enviar en esta ejecución (sin un 422 por ciclo).
    rejected = [p for p, b in state.requests if "installation_method" in b.get("host", b)]
    assert rejected == ["/agents/register", "/agents/heartbeat"]


@pytest.mark.parametrize("value", ["Windows Service", "x" * 33, "1abc", "win-service"])
def test_installation_method_is_validated_like_the_server(value: str) -> None:
    with pytest.raises(ValueError, match="installation_method"):
        AgentConfig(installation_method=value).validate()


# --- SCM: estados del servicio ----------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.statuses: list[ServiceStatus] = []
        self.lock = threading.Lock()

    def __call__(self, status: ServiceStatus) -> None:
        with self.lock:
            self.statuses.append(status)

    def states(self) -> list[int]:
        return [status.state for status in self.statuses]


def test_service_lifecycle_start_run_stop() -> None:
    recorder = Recorder()
    reporter = StatusReporter(recorder, threading.Event())
    seen_running: list[ServiceStatus] = []

    def body(stop: threading.Event) -> None:
        seen_running.append(recorder.statuses[-1])
        # El SCM pide parar: debe responder enseguida y el bucle termina entre ciclos.
        assert reporter.handle_control(SERVICE_CONTROL_STOP) == NO_ERROR
        assert stop.wait(1)

    assert run_service_body(reporter, body) == 0

    assert recorder.states()[:2] == [SERVICE_START_PENDING, SERVICE_RUNNING]
    assert recorder.statuses[0].checkpoint == 1 and recorder.statuses[0].wait_hint_ms > 0
    running = seen_running[0]
    assert running.controls_accepted == SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
    assert running.checkpoint == 0
    assert SERVICE_STOP_PENDING in recorder.states()
    final = recorder.statuses[-1]
    assert final.state == SERVICE_STOPPED and final.win32_exit_code == NO_ERROR
    assert final.controls_accepted == 0


def test_shutdown_is_a_clean_stop_and_other_controls_are_refused() -> None:
    stop = threading.Event()
    reporter = StatusReporter(Recorder(), stop)
    reporter.report(SERVICE_RUNNING)
    assert reporter.handle_control(SERVICE_CONTROL_INTERROGATE) == NO_ERROR
    assert reporter.handle_control(0x0B) == ERROR_CALL_NOT_IMPLEMENTED  # p. ej. PRESHUTDOWN
    assert not stop.is_set()
    assert reporter.handle_control(SERVICE_CONTROL_SHUTDOWN) == NO_ERROR
    assert stop.is_set()


def test_unexpected_error_is_reported_as_a_service_failure_for_recovery() -> None:
    recorder = Recorder()
    reporter = StatusReporter(recorder, threading.Event())

    def body(_stop: threading.Event) -> None:
        raise PermissionError("state directory not writable")

    assert run_service_body(reporter, body) == 1
    final = recorder.statuses[-1]
    assert final.state == SERVICE_STOPPED
    assert final.win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR and final.service_exit_code == 1


def test_long_stop_keeps_the_scm_informed_and_never_reports_after_stopped() -> None:
    recorder = Recorder()
    reporter = StatusReporter(recorder, threading.Event(), ping_seconds=0.02, ping_limit_seconds=5)

    def body(stop: threading.Event) -> None:
        reporter.handle_control(SERVICE_CONTROL_STOP)
        time.sleep(0.15)  # un ciclo largo que termina después de pedir la parada

    run_service_body(reporter, body)
    time.sleep(0.1)  # el hilo de avisos ya no debe enviar nada

    states = recorder.states()
    pending = [s for s in recorder.statuses if s.state == SERVICE_STOP_PENDING]
    assert len(pending) >= 3
    assert [s.checkpoint for s in pending] == sorted({s.checkpoint for s in pending})
    assert states[-1] == SERVICE_STOPPED
    assert SERVICE_STOP_PENDING not in states[states.index(SERVICE_STOPPED) :]


@pytest.mark.skipif(sys.platform == "win32", reason="needs a non-Windows host")
def test_service_mode_outside_windows_fails_clearly(tmp_path: Path) -> None:
    code = main(["--service", "--state-dir", str(tmp_path / "state"), "--api-url", "http://x:1"])
    logging.getLogger().handlers = []
    assert code == 2


# --- DPAPI: comportamiento del almacenamiento protegido ---------------------------------------


def fake_dpapi(owner: str) -> Any:
    """DPAPI falso: "cifra" para una cuenta; otra cuenta no puede descifrar."""

    def call(data: bytes, protect: bool) -> bytes:
        tag = owner.encode() + b":"
        if protect:
            return tag + bytes(b ^ 0x5A for b in data)
        if not data.startswith(tag):
            raise credentials.CredentialError("DPAPI failed (Windows error 13)")
        return bytes(b ^ 0x5A for b in data[len(tag) :])

    return call


def test_token_is_dpapi_protected_and_unreadable_by_another_account(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(credentials, "_dpapi", fake_dpapi("NT SERVICE\\SentraAgent"), raising=False)
    store = IdentityStore(tmp_path)
    identity = store.load_or_create()
    identity.token = "agent-token-abcdefghijklmnopqrstuvwxyz"
    store.save(identity)

    stored = json.loads(store.path.read_text("utf-8"))
    assert stored["token"]["scheme"] == credentials.SCHEME_DPAPI
    assert identity.token not in store.path.read_text("utf-8")
    assert IdentityStore(tmp_path).load_or_create().token == identity.token

    # Cambiar la cuenta del servicio (p. ej. a LocalSystem): mismo agent_id, sin token,
    # el agente necesitará enrolarse de nuevo (el instalador pide un token nuevo).
    monkeypatch.setattr(credentials, "_dpapi", fake_dpapi("LocalSystem"), raising=False)
    other = IdentityStore(tmp_path).load_or_create()
    assert other.agent_id == identity.agent_id and other.token is None
