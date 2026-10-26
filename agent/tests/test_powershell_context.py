"""Fase 7A.8 (agente 0.6.0): contexto del evento 4104 sin su contenido."""

import hashlib
from pathlib import Path

import pytest

from sentra_agent import events as events_module
from sentra_agent.events import (
    POWERSHELL_CHANNEL,
    parse_events,
    script_sha256,
    suspicious_keywords,
)

SCRIPT = (
    "$secure = Read-Host -AsSecureString; "
    "$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure); "
    "$token = 'hunter2'"
)


def _block(path: str = "", text: str = SCRIPT, pid: str = "4242") -> str:
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-PowerShell'/><EventID>4104</EventID>"
        "<Level>3</Level><TimeCreated SystemTime='2026-10-24T08:00:00.1234567Z'/>"
        "<EventRecordID>77</EventRecordID>"
        f"<Execution ProcessID='{pid}' ThreadID='9'/><Computer>PC-01</Computer>"
        "<Security UserID='S-1-5-21-1-2-3-1001'/></System><EventData>"
        "<Data Name='MessageNumber'>1</Data><Data Name='MessageTotal'>1</Data>"
        f"<Data Name='ScriptBlockText'>{text}</Data>"
        "<Data Name='ScriptBlockId'>0d6c3f4e-1b2a-4c5d-8e9f-a0b1c2d3e4f5</Data>"
        f"<Data Name='Path'>{path}</Data></EventData></Event>"
    )


def test_context_is_sent_without_the_script_text() -> None:
    (event,) = parse_events(_block(r"C:\Sentra\scripts\init_database.ps1"), POWERSHELL_CHANNEL)

    assert event["data"] == {
        "ScriptBlockId": "0d6c3f4e-1b2a-4c5d-8e9f-a0b1c2d3e4f5",
        "Path": r"C:\Sentra\scripts\init_database.ps1",
        "MessageNumber": "1",
        "MessageTotal": "1",
        "ProcessID": "4242",
        "UserID": "S-1-5-21-1-2-3-1001",
        # La causa probable del aviso, no el código.
        "SuspiciousKeywords": "InteropServices,Marshal",
    }
    assert "hunter2" not in str(event) and "SecureString" not in str(event)
    assert event["message"].endswith("event 4104 (content not collected)")


def test_inline_blocks_have_no_path_and_bad_pids_are_dropped() -> None:
    (event,) = parse_events(_block(text="Get-Date", pid="abc"), POWERSHELL_CHANNEL)

    assert "Path" not in event["data"] and "ProcessID" not in event["data"]
    assert "SuspiciousKeywords" not in event["data"]


def test_keywords_are_matched_case_insensitively_and_bounded() -> None:
    assert suspicious_keywords("add-type -TypeDefinition $x; [convert]::frombase64string($y)") == [
        "Add-Type",
        "FromBase64String",
    ]
    everything = " ".join(events_module.SUSPICIOUS_KEYWORDS)
    assert len(suspicious_keywords(everything)) == events_module.MAX_KEYWORDS


@pytest.mark.parametrize(
    "path",
    [
        r"\\attacker\share\x.ps1",  # UNC: el equipo se autenticaría contra ese servidor
        r"\\?\C:\x.ps1",
        r"\\.\pipe\x",
        r"C:\x.ps1:hidden",  # flujo alternativo
        "relative.ps1",
        "",
    ],
)
def test_only_local_drive_paths_are_hashed(path: str) -> None:
    assert script_sha256(path) is None


def test_script_file_is_hashed_and_cached(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # La ruta de prueba es de Linux: se acepta el formato para ejercitar la lectura real.
    monkeypatch.setattr(events_module, "_hashable", lambda path: True)
    events_module._hash_cache.clear()
    script = tmp_path / "install.ps1"
    script.write_bytes(b"Write-Output 'ok'\r\n")
    expected = hashlib.sha256(script.read_bytes()).hexdigest()

    assert script_sha256(str(script)) == expected
    assert len(events_module._hash_cache) == 1
    assert script_sha256(str(script)) == expected

    script.write_bytes(b"Write-Output 'changed'\r\n")
    # Otro contenido, otra huella: una excepción ligada al hash anterior ya no aplica.
    assert script_sha256(str(script)) == hashlib.sha256(script.read_bytes()).hexdigest()


def test_directories_links_and_large_files_are_not_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(events_module, "_hashable", lambda path: True)
    monkeypatch.setattr(events_module, "SCRIPT_HASH_MAX", 4)
    big = tmp_path / "big.ps1"
    big.write_bytes(b"12345")
    small = tmp_path / "small.ps1"
    small.write_bytes(b"1")
    link = tmp_path / "link.ps1"
    try:
        link.symlink_to(small)
    except OSError:
        link = small  # Windows sin privilegio de symlink (WinError 1314)
    assert script_sha256(str(tmp_path)) is None
    assert script_sha256(str(big)) is None
    if link != small:
        assert script_sha256(str(link)) is None
    assert script_sha256(str(tmp_path / "missing.ps1")) is None


def test_hash_is_attached_when_the_script_exists(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(events_module, "_hashable", lambda path: True)
    script = tmp_path / "start.ps1"
    script.write_bytes(b"param()")

    (event,) = parse_events(_block(str(script)), POWERSHELL_CHANNEL)

    assert event["data"]["ScriptSha256"] == hashlib.sha256(b"param()").hexdigest()
