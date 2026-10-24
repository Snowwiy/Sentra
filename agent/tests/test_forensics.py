"""Fase 6E.6: acciones forenses de solo lectura (parámetros, rutas, artefactos y runner)."""

import hashlib
import json
import os
import sys
import uuid
from pathlib import Path
from typing import Any

import pytest

from sentra_agent.commands import (
    CommandRejectedError,
    capabilities,
    parse_command_full,
)
from sentra_agent.config import ForensicsSettings
from sentra_agent.endpoint import CollectorUnavailableError
from sentra_agent.forensics import (
    FORENSIC_FILE_METADATA,
    FORENSIC_PROCESSES,
    FORENSIC_SCHEDULED_TASKS,
    FORENSIC_SERVICES,
    FORENSIC_TYPES,
    SCHEMA,
    ForensicCollector,
    PathRejectedError,
    build_artifact,
    canonical,
    forensic_capabilities,
    validate_path,
)
from sentra_agent.runner import Agent
from sentra_agent.syscmd import CommandOutput
from tests.conftest import FakeApiState, make_client, make_store
from tests.test_runner import HOST, FakeEvents, processes, sample, snapshot

posix_only = pytest.mark.skipif(
    sys.platform == "win32", reason="rutas POSIX reales y enlaces simbólicos"
)


def command(kind: str, params: Any = None) -> dict[str, Any]:
    raw: dict[str, Any] = {"request_id": str(uuid.uuid4()), "type": kind}
    if params is not None:
        raw["params"] = params
    return raw


# --- Parámetros estrictos ------------------------------------------------------------------


def test_file_metadata_params_are_exact() -> None:
    roots = ("/opt",)
    parsed = parse_command_full(
        command(FORENSIC_FILE_METADATA, {"path": "/opt/app/bin", "hash": True}), roots, "linux"
    )
    assert parsed.params == {"path": "/opt/app/bin", "hash": True}

    bad: tuple[Any, ...] = (
        {"path": "/opt/app/bin"},  # falta hash
        {"path": "/opt/app/bin", "hash": True, "follow": True},  # clave de más
        {"path": "/opt/app/bin", "hash": "yes"},  # hash no booleano
        {"path": 42, "hash": False},
        None,
        [],
    )
    for params in bad:
        with pytest.raises(CommandRejectedError) as info:
            parse_command_full(command(FORENSIC_FILE_METADATA, params), roots, "linux")
        assert info.value.code == "invalid_params"


def test_parameterless_actions_reject_any_params() -> None:
    assert parse_command_full(command(FORENSIC_PROCESSES)).params == {}
    assert parse_command_full(command(FORENSIC_PROCESSES, {})).kind == FORENSIC_PROCESSES
    with pytest.raises(CommandRejectedError) as info:
        parse_command_full(command(FORENSIC_PROCESSES, {"pid": 4}))
    assert info.value.code == "invalid_params"


def test_isolation_params_validate_uuid_and_zone() -> None:
    session = str(uuid.uuid4())
    parsed = parse_command_full(
        command("isolate_host", {"session_id": session, "expires_at": "2026-10-22T11:00:00Z"})
    )
    assert str(parsed.params["session_id"]) == session
    assert parsed.params["expires_at"].utcoffset() is not None

    bad = (
        {"session_id": "not-a-uuid", "expires_at": "2026-10-22T11:00:00Z"},
        {"session_id": session, "expires_at": "2026-10-22T11:00:00"},  # sin zona
        {"session_id": session},
        {"session_id": session, "expires_at": "2026-10-22T11:00:00Z", "allow": ["0.0.0.0/0"]},
    )
    for params in bad:
        with pytest.raises(CommandRejectedError) as info:
            parse_command_full(command("isolate_host", params))
        assert info.value.code == "invalid_params"
    with pytest.raises(CommandRejectedError):
        parse_command_full(command("release_isolation", {"session_id": 7}))


# --- Validación de rutas -------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        ("relative/path", "invalid_params"),
        ("/opt/../etc/shadow", "invalid_params"),
        ("/opt/a\x00b", "invalid_params"),
        ("/opt/" + "a" * 1100, "invalid_params"),
        ("/home/ana/.bashrc", "path_not_allowed"),
        ("/etc/shadow", "path_not_allowed"),
        ("/etc/ssh/ssh_host_ed25519_key", "path_not_allowed"),
        ("/var/lib/sentra-agent/identity.json", "path_not_allowed"),
    ],
)
def test_posix_paths_rejected(raw: str, code: str) -> None:
    with pytest.raises(PathRejectedError) as info:
        validate_path(raw, ("/opt", "/etc", "/var/lib"), "linux")
    assert info.value.code == code


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (r"\\server\share\x.exe", "invalid_params"),
        (r"\\?\C:\Windows\x.exe", "invalid_params"),
        (r"C:relative.exe", "invalid_params"),
        (r"C:\Program Files\app.exe:hidden", "invalid_params"),
        (r"C:\Program Files\..\Users\ana\x", "invalid_params"),
        (r"C:\Users\ana\Desktop\x.exe", "path_not_allowed"),
        (r"C:\Windows\System32\config\SAM", "path_not_allowed"),
    ],
)
def test_windows_paths_rejected(raw: str, code: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SYSTEMROOT", r"C:\Windows")
    with pytest.raises(PathRejectedError) as info:
        validate_path(raw, (r"C:\Program Files", r"C:\Windows"), "win32")
    assert info.value.code == code


def test_valid_paths_and_case_on_windows() -> None:
    assert validate_path("/opt/app/bin", ("/opt",), "linux") == "/opt/app/bin"
    # NTFS no distingue mayúsculas: una raíz escrita distinto sigue cubriendo la ruta.
    assert (
        validate_path(r"c:\program files\App\app.exe", (r"C:\Program Files",), "win32")
        == r"c:\program files\App\app.exe"
    )
    # /opt no cubre /optional: se comparan componentes, no prefijos de texto.
    with pytest.raises(PathRejectedError):
        validate_path("/optional/x", ("/opt",), "linux")


def test_extra_denied_protects_the_agent_state() -> None:
    with pytest.raises(PathRejectedError) as info:
        validate_path("/opt/sentra/state/identity.json", ("/opt",), "linux", ("/opt/sentra",))
    assert info.value.code == "path_not_allowed"


def test_path_rejection_maps_to_command_rejection() -> None:
    with pytest.raises(CommandRejectedError) as info:
        parse_command_full(
            command(FORENSIC_FILE_METADATA, {"path": "/root/.ssh/id_rsa", "hash": True}),
            ("/opt",),
            "linux",
        )
    assert info.value.code == "path_not_allowed"


# --- Artefactos ----------------------------------------------------------------------------


def test_artifact_hash_is_over_canonical_content() -> None:
    content = {"total": 1, "items": [{"b": 2, "a": "ñ"}]}
    artifact = build_artifact(FORENSIC_SERVICES, content, 64, "linux")
    assert artifact["schema"] == SCHEMA and artifact["platform"] == "linux"
    assert artifact["truncated"] is False
    expected = hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    assert artifact["sha256"] == expected
    assert canonical({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_artifact_is_truncated_to_the_size_cap() -> None:
    items = [{"name": f"svc{i}", "pad": "x" * 100} for i in range(2000)]
    artifact = build_artifact(FORENSIC_SERVICES, {"items": items, "total": 2000}, 64, "win32")
    kept = artifact["content"]["items"]
    assert artifact["truncated"] is True and artifact["platform"] == "windows"
    assert 0 < len(kept) < 2000
    assert len(canonical(artifact["content"])) <= 64 * 1024
    # Cabe exactamente el máximo: uno más ya no cabría.
    one_more = {"items": items[: len(kept) + 1], "total": 2000}
    assert len(canonical(one_more)) > 64 * 1024
    assert artifact["content"]["total"] == 2000  # el total real se conserva
    assert artifact["sha256"] == hashlib.sha256(canonical(artifact["content"])).hexdigest()


def test_reader_failures_become_limitations() -> None:
    def denied() -> dict[str, dict[str, Any]]:
        raise PermissionError("Access is denied")

    def missing() -> dict[str, dict[str, Any]]:
        raise CollectorUnavailableError("schtasks not found")

    collector = ForensicCollector(
        "boot",
        platform="linux",
        readers={FORENSIC_SERVICES: denied, FORENSIC_SCHEDULED_TASKS: missing},
    )
    summary, data = collector.collect(FORENSIC_SERVICES)
    assert summary == "0 items"
    assert data["limitations"][0]["code"] == "permission_denied"
    _, data = collector.collect(FORENSIC_SCHEDULED_TASKS)
    assert data["limitations"][0]["code"] == "not_supported"


def test_process_snapshot_is_real_and_redacted() -> None:
    collector = ForensicCollector("boot", platform=sys.platform)
    summary, data = collector.collect(FORENSIC_PROCESSES)
    artifact = data["artifact"]
    items = artifact["content"]["items"]
    assert any(item["pid"] == os.getpid() for item in items)
    assert summary.endswith("items") or "truncated" in summary
    assert artifact["sha256"] == hashlib.sha256(canonical(artifact["content"])).hexdigest()


# --- Metadatos de fichero ------------------------------------------------------------------


@posix_only
def test_file_metadata_with_hash(tmp_path: Path) -> None:
    target = tmp_path / "tool"
    target.write_bytes(b"binary")
    collector = ForensicCollector("boot", allowed_roots=(str(tmp_path),), platform="linux")
    summary, data = collector.collect(FORENSIC_FILE_METADATA, {"path": str(target), "hash": True})
    content = data["artifact"]["content"]
    assert summary == "file metadata"
    assert content["exists"] is True and content["type"] == "file" and content["size"] == 6
    assert content["sha256"] == hashlib.sha256(b"binary").hexdigest()
    assert content["signature"] is None
    assert [lim["code"] for lim in data["limitations"]] == ["not_supported"]

    content, _ = collector.file_metadata(str(target), want_hash=False)
    assert content["sha256"] is None


@posix_only
def test_file_metadata_missing_and_too_large(tmp_path: Path) -> None:
    collector = ForensicCollector(
        "boot", allowed_roots=(str(tmp_path),), hash_max_mb=1, platform="linux"
    )
    summary, data = collector.collect(
        FORENSIC_FILE_METADATA, {"path": str(tmp_path / "nope"), "hash": True}
    )
    assert summary == "file not found" and data["artifact"]["content"]["exists"] is False

    big = tmp_path / "big"
    with big.open("wb") as handle:
        handle.truncate(2 * 1024 * 1024)
    content, limits = collector.file_metadata(str(big), want_hash=True)
    assert content["sha256"] is None
    assert "hash_skipped_too_large" in [lim["code"] for lim in limits]


@posix_only
def test_symlink_is_reported_not_followed(tmp_path: Path) -> None:
    secret = tmp_path / "secret"
    secret.write_text("x")
    link = tmp_path / "link"
    os.symlink(secret, link)
    collector = ForensicCollector("boot", allowed_roots=(str(tmp_path),), platform="linux")
    content, limits = collector.file_metadata(str(link), want_hash=True)
    assert content["type"] == "symlink" and content["link_target"] == str(secret)
    assert content["sha256"] is None
    assert "symlink_not_followed" in [lim["code"] for lim in limits]


@posix_only
def test_parent_symlink_cannot_escape_roots(tmp_path: Path) -> None:
    allowed = tmp_path / "allowed"
    outside = tmp_path / "outside"
    allowed.mkdir()
    outside.mkdir()
    (outside / "private").write_text("x")
    os.symlink(outside, allowed / "door")
    collector = ForensicCollector("boot", allowed_roots=(str(allowed),), platform="linux")
    with pytest.raises(PathRejectedError) as info:
        collector.file_metadata(str(allowed / "door" / "private"), want_hash=True)
    assert info.value.code == "path_not_allowed"


def test_windows_signature_path_travels_in_env_not_argv() -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []
    path = r"C:\Program Files\App\-Command evil.exe"

    def fake_run(argv: list[str], **kwargs: Any) -> CommandOutput:
        calls.append((argv, kwargs))
        out = {"status": "Valid", "signer": "CN=Vendor", "issuer": "CN=CA",
               "thumbprint": "AB" * 20, "not_after": "2030-01-01T00:00:00Z"}  # fmt: skip
        return CommandOutput(json.dumps(out).encode(), "", 0)

    collector = ForensicCollector("boot", platform="win32", run=fake_run)
    limits: list[dict[str, str]] = []
    signature = collector._signature(path, limits)
    assert signature is not None and signature["status"] == "Valid" and limits == []
    [(argv, kwargs)] = calls
    assert all(path not in arg for arg in argv)  # nunca interpolada en el script
    assert kwargs["env"]["SENTRA_FORENSIC_PATH"] == path


def test_windows_signature_failure_is_a_limitation() -> None:
    def denied(argv: list[str], **_: Any) -> CommandOutput:
        return CommandOutput(b"", "Access is denied", 1)

    limits: list[dict[str, str]] = []
    collector = ForensicCollector("boot", platform="win32", run=denied)
    assert collector._signature(r"C:\Windows\x.exe", limits) is None
    assert limits[0]["code"] == "permission_denied"


# --- Capacidades ---------------------------------------------------------------------------


def test_forensic_capabilities_per_platform() -> None:
    assert forensic_capabilities("win32") == set(FORENSIC_TYPES)
    assert forensic_capabilities("linux") == set(FORENSIC_TYPES)
    assert forensic_capabilities("darwin") == set(FORENSIC_TYPES) - {FORENSIC_SCHEDULED_TASKS}
    assert forensic_capabilities("freebsd14") == set()
    assert set(FORENSIC_TYPES) <= set(capabilities("linux"))
    assert FORENSIC_SCHEDULED_TASKS not in capabilities("darwin")


# --- De punta a punta con el servidor falso ------------------------------------------------


def _agent(config: Any, roots: tuple[str, ...]) -> Agent:
    forensics = ForensicCollector(
        "boot",
        allowed_roots=roots,
        platform="linux",
        readers={FORENSIC_SERVICES: lambda: {"ssh": {"name": "ssh", "status": "running"}}},
    )
    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=sample,
        inventory=snapshot,
        events=FakeEvents(),
        processes=processes,
        forensics=forensics,
    )


@posix_only
def test_runner_reports_forensic_artifacts_and_rejections(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    # La raíz permitida contiene el estado del agente: aun así queda fuera de alcance.
    roots = (str(tmp_path),)
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "f").write_text("hola")
    config = make_config(url, forensics=ForensicsSettings(allowed_roots=roots))
    agent = _agent(config, roots)
    agent.cycle()
    agent_id = str(agent.identity.agent_id)
    services = command(FORENSIC_SERVICES, {})
    meta = command(FORENSIC_FILE_METADATA, {"path": str(tmp_path / "data" / "f"), "hash": True})
    outside = command(FORENSIC_FILE_METADATA, {"path": "/etc/hostname", "hash": False})
    state_file = command(
        FORENSIC_FILE_METADATA, {"path": str(config.state_dir / "x"), "hash": False}
    )
    state.commands[agent_id] = [services, meta, outside, state_file]

    agent.cycle()

    results = dict(state.command_results)
    ok = results[services["request_id"]]
    assert ok["status"] == "succeeded" and ok["summary"] == "1 items"
    assert ok["data"]["artifact"]["content"]["items"] == [{"name": "ssh", "status": "running"}]
    file_result = results[meta["request_id"]]
    assert (
        file_result["data"]["artifact"]["content"]["sha256"] == hashlib.sha256(b"hola").hexdigest()
    )
    for rejected in (outside, state_file):
        body = results[rejected["request_id"]]
        assert body["status"] == "rejected" and body["error_code"] == "path_not_allowed"
