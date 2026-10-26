"""Fase 6E: configuración nueva, empaquetado del helper y versión 0.5.0 del agente."""

import re
import tomllib
from pathlib import Path
from typing import Any

import pytest

from sentra_agent import __version__
from sentra_agent.config import load_config
from sentra_agent.isolation.policy import parse_policy
from sentra_agent.winsetup import isolation_plan

AGENT = Path(__file__).resolve().parents[1]


def write(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "agent.toml"
    path.write_text('api_url = "http://127.0.0.1:8000"\n' + text)
    return path


def test_version_is_current() -> None:
    # Fase 7A.8: 0.6.0 (contexto del 4104). La configuración de 0.5.0 sigue siendo válida.
    assert __version__ == "0.6.0"
    project = tomllib.loads((AGENT / "pyproject.toml").read_text())
    assert project["project"]["version"] == "0.6.0"


def test_new_sections_have_safe_defaults(tmp_path: Path) -> None:
    config = load_config(write(tmp_path, ""))
    assert config.telemetry.enabled is True
    assert config.telemetry.cmdline == "redacted"  # nunca la línea completa por defecto
    assert config.telemetry.hash_executables is False
    assert config.forensics.allowed_roots is None and config.forensics.max_artifact_kb == 2048


def test_sections_are_read_from_toml(tmp_path: Path) -> None:
    config = load_config(
        write(
            tmp_path,
            '[telemetry]\nprocess_poll_seconds = 10\ncmdline = "off"\nnetwork_enabled = false\n'
            '[forensics]\nallowed_roots = ["/opt/app"]\nmax_artifact_kb = 512\n'
            "[isolation]\nwait_seconds = 30\n",
        )
    )
    assert config.telemetry.process_poll_seconds == 10 and config.telemetry.cmdline == "off"
    assert config.telemetry.network_enabled is False
    assert config.forensics.allowed_roots == ("/opt/app",)
    assert config.forensics.max_artifact_kb == 512
    assert config.isolation.wait_seconds == 30


@pytest.mark.parametrize(
    "text",
    [
        "[telemetry]\nunknown = 1\n",
        "[telemetry]\nprocess_poll_seconds = 1\n",  # por debajo del mínimo
        '[telemetry]\ncmdline = "everything"\n',
        '[telemetry]\nenabled = "maybe"\n',
        "[forensics]\nmax_artifact_kb = 999999\n",
        '[isolation]\naddresses = ["0.0.0.0/0"]\n',
        "telemetry = 3\n",
    ],
)
def test_invalid_sections_are_refused(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError):
        load_config(write(tmp_path, text))


def test_section_env_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENTRA_AGENT_TELEMETRY_ENABLED", "false")
    monkeypatch.setenv("SENTRA_AGENT_TELEMETRY_PROCESS_POLL_SECONDS", "30")
    monkeypatch.setenv("SENTRA_AGENT_FORENSICS_ALLOWED_ROOTS", "/opt/a" + ":" + "/srv/b")
    config = load_config(write(tmp_path, "[telemetry]\nprocess_poll_seconds = 10\n"))
    assert config.telemetry.enabled is False
    assert config.telemetry.process_poll_seconds == 30  # el entorno gana al fichero
    assert config.forensics.allowed_roots is not None and len(config.forensics.allowed_roots) >= 1


def test_example_config_documents_the_new_sections_commented() -> None:
    text = (AGENT / "agent.example.toml").read_text(encoding="utf-8")
    for section in ("telemetry", "forensics", "isolation"):
        assert f"# [{section}]" in text
        assert f"\n[{section}]" not in text  # comentadas: el ejemplo no cambia nada solo
    parsed = tomllib.loads(text)
    assert not {"telemetry", "forensics", "isolation"} & set(parsed)
    # Descomentada, la sección de telemetría es TOML válido con claves conocidas.
    block = re.search(r"# \[telemetry\]\n((?:#.*\n)+)", text)
    assert block is not None
    lines = [line[2:] for line in block.group(1).splitlines() if re.match(r"# [a-z_]+ = ", line)]
    tomllib.loads("\n".join(lines))


# --- Helper de aislamiento: empaquetado -----------------------------------------------------


def test_isolation_plan_for_windows() -> None:
    plan: dict[str, Any] = isolation_plan(r"C:\Program Files", r"C:\ProgramData")
    assert plan["service_name"] == "SentraIsolation"
    assert plan["policy_file"] == r"C:\ProgramData\Sentra\Isolation\isolation.toml"
    assert plan["exchange_dir"] == r"C:\ProgramData\Sentra\Agent\isolation"
    assert "-m sentra_agent.isolation_helper --service" in plan["binary_path"]
    policy = parse_policy(plan["policy_text"])
    assert policy.enabled is False  # desactivado hasta que un administrador lo active
    assert str(policy.agent_config).endswith("agent.toml")


def test_windows_installer_helper_is_opt_in_and_never_touches_the_firewall() -> None:
    text = (AGENT / "packaging" / "windows" / "install-sentra-agent.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "[switch]$InstallIsolationHelper" in text
    assert "if ($InstallIsolationHelper)" in text
    lowered = text.lower()
    for forbidden in ("new-netfirewallrule", "advfirewall", "set-netfirewallprofile"):
        assert forbidden not in lowered
    uninstall = (AGENT / "packaging" / "windows" / "uninstall-sentra-agent.ps1").read_text(
        encoding="utf-8-sig"
    )
    assert "isolation_helper" in uninstall and "revert" in uninstall


def test_linux_isolation_unit_is_hardened_and_not_enabled_by_default() -> None:
    linux = AGENT / "packaging" / "linux"
    unit = (linux / "sentra-isolation.service").read_text()
    keys = dict(
        line.split("=", 1) for line in unit.splitlines() if "=" in line and not line.startswith("#")
    )
    assert keys["User"] == "root"
    assert keys["ExecStart"].startswith("/opt/sentra-agent/bin/sentra-agent isolation-helper")
    assert keys["CapabilityBoundingSet"] == "CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN"
    assert keys["NoNewPrivileges"] == "true" and keys["ProtectSystem"] == "strict"
    for script in ("install-sentra-agent.sh", "debian/postinst"):
        text = (linux / script).read_text()
        assert "enable sentra-isolation" not in text and "start sentra-isolation" not in text
    assert "sentra-isolation" in (linux / "debian" / "prerm").read_text()
    example = parse_policy((linux / "isolation.toml.example").read_text())
    assert example.enabled is False


def test_main_delegates_isolation_helper(monkeypatch: pytest.MonkeyPatch) -> None:
    import sentra_agent.isolation_helper as helper
    from sentra_agent.__main__ import main

    seen: list[list[str] | None] = []

    def fake(argv: list[str] | None = None) -> int:
        seen.append(argv)
        return 7

    monkeypatch.setattr(helper, "main", fake)
    assert main(["isolation-helper", "status", "--policy", "/x.toml"]) == 7
    assert seen == [["status", "--policy", "/x.toml"]]
