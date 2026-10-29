"""Fase 7B-Fix1 (agente 0.6.2): identidad de los servicios de Windows en el inventario."""

import json
from pathlib import Path
from typing import Any

from sentra_agent import service_identity as si
from sentra_agent.syscmd import CommandOutput

ENV = {"SystemRoot": r"C:\Windows", "ProgramFiles": r"C:\Program Files"}


def test_image_from_binpath_handles_the_usual_forms() -> None:
    assert si.image_from_binpath(r"C:\Windows\system32\svchost.exe -k UnistackSvcGroup", ENV) == (
        r"C:\Windows\system32\svchost.exe"
    )
    assert si.image_from_binpath(r'"C:\Program Files\Sentra Agent\sentra.exe" --service', ENV) == (
        r"C:\Program Files\Sentra Agent\sentra.exe"
    )
    assert si.image_from_binpath(r"%SystemRoot%\System32\svchost.exe -k netsvcs -p", ENV) == (
        r"C:\Windows\System32\svchost.exe"
    )
    assert si.image_from_binpath(r"\SystemRoot\System32\drivers\x.sys", ENV) == (
        r"C:\Windows\System32\drivers\x.sys"
    )
    assert (
        si.image_from_binpath(r"system32\DRIVERS\y.sys", ENV)
        == r"C:\Windows\system32\DRIVERS\y.sys"
    )
    assert si.image_from_binpath(None, ENV) is None
    assert si.image_from_binpath("", ENV) is None


def test_parse_signatures_accepts_a_single_object_and_lowercases_paths() -> None:
    one = json.dumps(
        {
            "path": r"C:\Windows\System32\svchost.exe",
            "status": "Valid",
            "signer": "CN=Microsoft Windows",
        }
    )
    assert si.parse_signatures(one) == {
        r"c:\windows\system32\svchost.exe": {"status": "Valid", "signer": "CN=Microsoft Windows"}
    }
    assert si.parse_signatures("") == {}


def _fake_run(calls: list[dict[str, Any]], status: str = "Valid") -> Any:
    def run(argv: list[str], **kwargs: Any) -> CommandOutput:
        paths = json.loads(kwargs["env"]["SENTRA_SIGNATURE_PATHS"])
        calls.append({"argv": argv, "paths": paths})
        # El script es fijo: las rutas nunca van en la línea de comandos.
        assert not any(p in " ".join(argv) for p in paths)
        out = [
            {"path": p, "status": status, "signer": "CN=Microsoft Windows, O=Microsoft Corporation"}
            for p in paths
        ]
        return CommandOutput(json.dumps(out).encode(), "", 0)

    return run


def test_signature_cache_checks_each_file_once_until_it_changes(tmp_path: Path) -> None:
    exe = tmp_path / "svchost.exe"
    exe.write_bytes(b"MZ" + b"\0" * 64)
    calls: list[dict[str, Any]] = []
    cache = si.SignatureCache(run=_fake_run(calls))
    first = cache.lookup([str(exe)])
    assert first[str(exe).lower()]["status"] == "Valid"
    cache.lookup([str(exe)])
    assert len(calls) == 1
    exe.write_bytes(b"MZ" + b"\1" * 128)  # otro tamaño: se vuelve a comprobar
    cache.lookup([str(exe)])
    assert len(calls) == 2


def test_signature_cache_respects_the_per_cycle_limit(tmp_path: Path) -> None:
    files = []
    for i in range(5):
        f = tmp_path / f"s{i}.exe"
        f.write_bytes(b"MZ")
        files.append(str(f))
    calls: list[dict[str, Any]] = []
    cache = si.SignatureCache(run=_fake_run(calls), per_cycle=2)
    assert len(cache.lookup(files)) == 2
    assert len(cache.lookup(files)) == 4
    assert len(cache.lookup(files)) == 5


def test_signature_failure_keeps_the_rest_of_the_inventory(tmp_path: Path) -> None:
    exe = tmp_path / "a.exe"
    exe.write_bytes(b"MZ")

    def failing(argv: list[str], **kwargs: Any) -> CommandOutput:
        return CommandOutput(b"", "Get-AuthenticodeSignature not found", 1)

    services: list[dict[str, Any]] = [{"name": "Svc", "status": "running"}]
    si.enrich_windows_services(
        services,
        {"Svc": {"binpath": f'"{exe}" -x', "username": "LocalSystem"}},
        type_reader=lambda _name: 0x10,
        signatures=si.SignatureCache(run=failing),
    )
    assert services[0]["binpath"] == f'"{exe}" -x'
    assert services[0]["username"] == "LocalSystem"
    assert services[0]["service_type"] == 0x10
    assert "image_signature" not in services[0]


def test_enrich_reports_a_user_service_instance(tmp_path: Path) -> None:
    host = tmp_path / "svchost.exe"
    host.write_bytes(b"MZ")
    calls: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = [
        {"name": "WpnUserService_6df11", "status": "running"},
        {"name": "NoData", "status": "stopped"},
    ]
    si.enrich_windows_services(
        services,
        {"WpnUserService_6df11": {"binpath": f"{host} -k UnistackSvcGroup", "username": None}},
        type_reader=lambda name: 0xE0 if name.endswith("_6df11") else None,
        signatures=si.SignatureCache(run=_fake_run(calls)),
    )
    instance, missing = services
    assert instance["service_type"] & si.SERVICE_USERSERVICE_INSTANCE
    assert instance["image"] == str(host)
    assert instance["image_signature"]["status"] == "Valid"
    # Lo que no se pudo leer no se inventa.
    assert set(missing) == {"name", "status"}
