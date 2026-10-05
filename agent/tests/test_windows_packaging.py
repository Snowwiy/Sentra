"""Paquete Windows (Fase 4F): build.py y scripts PowerShell de instalación/desinstalación.

El build se ejecuta de verdad con un Python embebido y una rueda de psutil FALSOS
(--insecure-skip-verify, solo para tests). Los scripts PowerShell se analizan con el parser de
PowerShell y sus funciones puras se ejecutan con `pwsh`/`powershell` si está disponible, con
los cmdlets que tocan el sistema sustituidos por funciones falsas. Nada se instala ni se borra
fuera del directorio temporal; la instalación real se valida con el checklist de
docs/agent-windows-installation.md.
"""

import base64
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

AGENT_DIR = Path(__file__).resolve().parents[1]
WINDOWS = AGENT_DIR / "packaging" / "windows"
INSTALLER = WINDOWS / "install-sentra-agent.ps1"
UNINSTALLER = WINDOWS / "uninstall-sentra-agent.ps1"
POWERSHELL = shutil.which("pwsh") or shutil.which("powershell")
needs_powershell = pytest.mark.skipif(POWERSHELL is None, reason="PowerShell not installed")


# Fecha fija de las entradas de los zips falsos. writestr() con un nombre usa la hora actual:
# dos llamadas en segundos distintos (habitual en Windows, donde cada build tarda más) darían
# entradas distintas para el build, y VERSION registra el SHA-256 de esas entradas.
FIXTURE_DATE_TIME = (2026, 1, 1, 0, 0, 0)


def _fixed(name: str) -> zipfile.ZipInfo:
    return zipfile.ZipInfo(name, FIXTURE_DATE_TIME)


def fake_embed_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(_fixed("python.exe"), b"MZ fake python")
        archive.writestr(_fixed("python312.dll"), b"MZ fake dll")
        archive.writestr(_fixed("python312.zip"), b"PK fake stdlib")
        archive.writestr(_fixed("_ctypes.pyd"), b"MZ fake ctypes")
        archive.writestr(
            _fixed("python312._pth"), "python312.zip\n.\n\n# Uncomment\n#import site\n"
        )
    return path


def fake_wheel(path: Path) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(_fixed("psutil/__init__.py"), "# fake psutil\n")
        archive.writestr(_fixed("psutil/_psutil_windows.pyd"), b"MZ fake")
        archive.writestr(_fixed("psutil-7.2.2.dist-info/RECORD"), "")
    return path


def run_build(
    tmp_path: Path, *extra: str, epoch: str = "1790000000"
) -> subprocess.CompletedProcess[str]:
    out = tmp_path / "dist"
    command = [
        sys.executable,
        str(WINDOWS / "build.py"),
        "--out",
        str(out),
        "--python-embed-zip",
        str(fake_embed_zip(tmp_path / "embed.zip")),
        "--psutil-wheel",
        str(fake_wheel(tmp_path / "psutil-7.2.2-cp37-abi3-win_amd64.whl")),
        *extra,
    ]
    env = {**os.environ, "SOURCE_DATE_EPOCH": epoch}
    return subprocess.run(command, capture_output=True, text=True, env=env, check=False)  # noqa: S603


def built_zip(tmp_path: Path) -> Path:
    found = sorted((tmp_path / "dist").glob("sentra-agent-*-windows-x86_64.zip"))
    assert len(found) == 1
    return found[0]


# --- build.py ---------------------------------------------------------------------------------


def test_build_produces_an_agent_only_package(tmp_path: Path) -> None:
    result = run_build(tmp_path, "--insecure-skip-verify")
    assert result.returncode == 0, result.stderr
    archive = built_zip(tmp_path)
    version = re.search(r'(?m)^version = "([^"]+)"', (AGENT_DIR / "pyproject.toml").read_text())
    assert version is not None
    name = f"sentra-agent-{version.group(1)}-windows-x86_64"
    assert archive.name == f"{name}.zip"

    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        files = {n.removeprefix(name + "/"): package.read(n) for n in names}

    assert all(n.startswith(name + "/") for n in names)
    for required in (
        "install-sentra-agent.ps1",
        "uninstall-sentra-agent.ps1",
        "README.md",
        "VERSION",
        "MANIFEST.sha256",
        "payload/runtime/python.exe",
        "payload/lib/sentra_agent/__main__.py",
        "payload/lib/sentra_agent/winservice.py",
        "payload/lib/psutil/__init__.py",
    ):
        assert required in files, required
    # Solo el agente: ni servidor, ni frontend, ni tests, ni cachés, ni configuración local.
    for path in files:
        assert not re.search(r"(^|/)(backend|frontend|tests|__pycache__|node_modules)/", path), path
        assert not path.endswith((".pyc", ".env", ".toml")), path
    blob = b"\n".join(files.values())
    for secret_marker in (
        b"ADMIN_API_KEY=",
        b"AGENT_ENROLLMENT_KEY=",
        b"DATABASE_URL=",
        b"postgresql+psycopg://",
    ):
        assert secret_marker not in blob, secret_marker

    # sys.path fijado: stdlib, runtime y ..\lib; sin site-packages.
    pth = files["payload/runtime/python312._pth"].decode()
    assert pth.split("\r\n")[:3] == ["python312.zip", ".", "..\\lib"]
    assert "import site" not in pth

    # Scripts con BOM UTF-8 y CRLF (Windows PowerShell 5.1 lee sin BOM como ANSI).
    for script in ("install-sentra-agent.ps1", "uninstall-sentra-agent.ps1"):
        data = files[script]
        assert data.startswith(b"\xef\xbb\xbf")
        assert b"\r\n" in data and b"\n" not in data.replace(b"\r\n", b"")

    # El manifiesto cubre cada archivo (menos él mismo) con su hash real.
    manifest = files["MANIFEST.sha256"].decode().splitlines()
    listed = {}
    for line in manifest:
        digest, relative = line.split("  ", 1)
        listed[relative] = digest
    assert set(listed) == set(files) - {"MANIFEST.sha256"}
    for relative, digest in listed.items():
        assert hashlib.sha256(files[relative]).hexdigest() == digest, relative

    version_info = files["VERSION"].decode()
    assert "python=python312" in version_info and "psutil_sha256=" in version_info
    assert (
        (archive.parent / f"{archive.name}.sha256")
        .read_text()
        .startswith(hashlib.sha256(archive.read_bytes()).hexdigest())
    )


def test_build_is_reproducible(tmp_path: Path) -> None:
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    assert run_build(first, "--insecure-skip-verify").returncode == 0
    assert run_build(second, "--insecure-skip-verify").returncode == 0
    assert built_zip(first).read_bytes() == built_zip(second).read_bytes()


def test_fake_inputs_are_byte_identical_whenever_they_are_created(tmp_path: Path) -> None:
    # "Mismas entradas" de verdad: el test de reproducibilidad crea los zips falsos dos veces.
    first = fake_embed_zip(tmp_path / "a.zip").read_bytes()
    second = fake_embed_zip(tmp_path / "b.zip").read_bytes()
    assert first == second
    wheels = [fake_wheel(tmp_path / f"{n}.whl").read_bytes() for n in ("a", "b")]
    assert wheels[0] == wheels[1]


def test_zip_ignores_file_times_creation_order_and_permissions(tmp_path: Path) -> None:
    # Fuentes de no determinismo del sistema de archivos (más visibles en Windows: la copia
    # conserva fechas, el antivirus o la indexación las tocan, el orden de os.scandir depende
    # del volumen): nada de eso debe llegar al zip.
    build = load_build_module()
    files = {
        "b.txt": b"b",
        "A.txt": b"A",
        "payload/lib/x.py": b"x",
        "payload/lib/Y.py": b"Y",
        "payload/runtime/python.exe": b"MZ",
    }
    archives = []
    for index, order in enumerate((sorted(files), sorted(files, reverse=True))):
        stage = tmp_path / f"stage{index}" / "pkg"
        for number, relative in enumerate(order):
            path = stage / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(files[relative])
            stamp = 1_600_000_000 + 1_000 * index + number
            os.utime(path, (stamp, stamp))
            path.chmod(0o600 if index else 0o755)
        out = tmp_path / f"out{index}"
        out.mkdir()
        archives.append(build.write_zip(stage, "pkg", out, 1_790_000_000).read_bytes())
    assert archives[0] == archives[1]
    with zipfile.ZipFile(tmp_path / "out0" / "pkg.zip") as package:
        names = package.namelist()
        # Orden explícito por ruta POSIX (ordinal, sensible a mayúsculas), igual en Windows y
        # Linux; y la fecha de SOURCE_DATE_EPOCH en todas las entradas.
        assert names == sorted(names)
        assert {info.date_time for info in package.infolist()} == {(2026, 9, 21, 14, 13, 20)}


def load_build_module() -> Any:
    spec = importlib.util.spec_from_file_location("sentra_windows_build", WINDOWS / "build.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_build_refuses_a_psutil_wheel_with_another_hash(tmp_path: Path) -> None:
    result = run_build(tmp_path)
    assert result.returncode == 1 and "psutil wheel SHA-256 mismatch" in result.stderr
    assert not list((tmp_path / "dist").glob("*.zip"))


@pytest.mark.skipif(sys.platform == "win32", reason="on Windows Authenticode is checked instead")
def test_build_refuses_an_unverified_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = load_build_module()
    wheel = fake_wheel(tmp_path / "psutil-7.2.2-cp37-abi3-win_amd64.whl")
    monkeypatch.setattr(build, "PSUTIL_SHA256", build.sha256_file(wheel))  # psutil "correcto"
    args = build.argparse.Namespace(
        out=str(tmp_path / "dist"),
        python_version="3.12.10",
        python_embed_zip=str(fake_embed_zip(tmp_path / "embed.zip")),
        python_embed_sha256=None,
        psutil_wheel=str(wheel),
        insecure_skip_verify=False,
    )
    with pytest.raises(build.BuildError, match="cannot verify the embedded Python"):
        build.build(args)
    assert not list((tmp_path / "dist").glob("*.zip"))


PSF_SUBJECT = (
    "CN=Python Software Foundation, O=Python Software Foundation, L=Beaverton, S=Oregon, C=US"
)
VALID = json.dumps(
    {"status": "Valid", "status_message": "Firma verificada.", "subject": PSF_SUBJECT}
)
PWSH7 = Path("C:/Program Files/PowerShell/7/pwsh.exe")
WINPS = Path("C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe")
# Error real de Windows PowerShell 5.1 al importar dos veces Microsoft.PowerShell.Security.
TYPEDATA_ERROR = (
    'Error en TypeData "System.Security.AccessControl.ObjectSecurity": Ya existe el miembro'
    ' "AuditToString". FormatXmlUpdateException,Microsoft.PowerShell.Commands.ImportModuleCommand'
)

Outcome = tuple[int, str, str]


def fake_powershell(
    monkeypatch: pytest.MonkeyPatch, build: Any, outcomes: dict[str, Outcome | OSError]
) -> list[dict[str, Any]]:
    """Sustituye subprocess.run: cada PowerShell (por nombre de archivo) da su resultado."""
    calls: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        calls.append({"command": command, **kwargs})
        outcome = outcomes[Path(command[0].replace("\\", "/")).name]
        if isinstance(outcome, OSError):
            raise outcome
        returncode, stdout, stderr = outcome
        return subprocess.CompletedProcess(command, returncode, stdout, stderr)

    monkeypatch.setattr(build.subprocess, "run", run)
    return calls


def test_authenticode_accepts_a_valid_psf_signature(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = load_build_module()
    monkeypatch.setenv("PSModulePath", r"C:\Program Files\PowerShell\7\Modules")
    # Un aviso previo en stdout no debe impedir leer el JSON de la última línea.
    calls = fake_powershell(
        monkeypatch, build, {"powershell.exe": (0, f"AVISO\r\n{VALID}\r\n", "")}
    )
    signed = tmp_path / "Program Files" / "py $x 'q'" / "python.exe"
    build.verify_authenticode([signed], [WINPS])

    assert "signature ok: python.exe" in capsys.readouterr().out
    (call,) = calls
    command = call["command"]
    assert command[0] == str(WINPS) and command[-2] == "-EncodedCommand"
    script = base64.b64decode(command[-1]).decode("utf-16-le")
    assert script == build.AUTHENTICODE_SCRIPT
    assert "ConvertTo-Json -Compress" in script and "$ErrorActionPreference = 'Stop'" in script
    # La ruta (con espacios, comillas y $) viaja por el entorno, nunca dentro del script.
    assert str(signed) not in " ".join(command)
    assert call["env"]["SENTRA_SIGNED_FILE"] == str(signed)
    # Sin el PSModulePath de PowerShell 7: 5.1 cargaría módulos incompatibles.
    assert "PSModulePath" not in call["env"]
    assert call["check"] is False


def test_pwsh_7_is_preferred_and_windows_powershell_is_the_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = load_build_module()
    program_files = tmp_path / "Program Files"
    system_root = tmp_path / "Windows"
    monkeypatch.delenv("PROGRAMW6432", raising=False)
    monkeypatch.setenv("PROGRAMFILES", str(program_files))
    monkeypatch.setenv("SYSTEMROOT", str(system_root))
    pwsh = program_files / "PowerShell" / "7" / "pwsh.exe"
    winps = system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"

    # Solo Windows PowerShell 5.1 (lo normal en un Windows recién instalado).
    winps.parent.mkdir(parents=True)
    winps.write_bytes(b"MZ")
    assert build.powershell_candidates() == [winps]
    # Con PowerShell 7 instalado en su ruta estándar, va primero.
    pwsh.parent.mkdir(parents=True)
    pwsh.write_bytes(b"MZ")
    assert build.powershell_candidates() == [pwsh, winps]
    # Nunca se busca en el PATH.
    monkeypatch.setenv("PATH", str(tmp_path / "evil"))
    assert build.powershell_candidates() == [pwsh, winps]


def test_falls_back_to_windows_powershell_when_pwsh_cannot_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    build = load_build_module()
    calls = fake_powershell(
        monkeypatch,
        build,
        {"pwsh.exe": OSError("pwsh roto"), "powershell.exe": (0, VALID, "")},
    )
    build.verify_authenticode([tmp_path / "python.exe"], [PWSH7, WINPS])
    assert [Path(c["command"][0]).name for c in calls] == ["pwsh.exe", "powershell.exe"]
    assert "[powershell.exe]" in capsys.readouterr().out


def test_pwsh_verdict_is_used_without_starting_windows_powershell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = load_build_module()
    calls = fake_powershell(monkeypatch, build, {"pwsh.exe": (0, VALID, "")})
    build.verify_authenticode([tmp_path / "python.exe", tmp_path / "python312.dll"], [PWSH7, WINPS])
    assert [Path(c["command"][0]).name for c in calls] == ["pwsh.exe", "pwsh.exe"]


def test_a_negative_verdict_is_never_retried_with_another_powershell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    build = load_build_module()
    invalid = json.dumps({"status": "HashMismatch", "subject": PSF_SUBJECT})
    calls = fake_powershell(
        monkeypatch, build, {"pwsh.exe": (0, invalid, ""), "powershell.exe": (0, VALID, "")}
    )
    with pytest.raises(build.BuildError, match="not valid"):
        build.verify_authenticode([tmp_path / "python.exe"], [PWSH7, WINPS])
    assert len(calls) == 1


def test_all_powershells_failing_fails_closed_with_every_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Regresión del fallo en Windows real: 5.1 con el error de TypeData duplicado.
    build = load_build_module()
    fake_powershell(
        monkeypatch,
        build,
        {"pwsh.exe": (0, "", ""), "powershell.exe": (1, "", TYPEDATA_ERROR)},
    )
    with pytest.raises(build.BuildError) as error:
        build.verify_authenticode([tmp_path / "python.exe"], [PWSH7, WINPS])
    assert "pwsh.exe: no JSON" in str(error.value)
    assert "powershell.exe exit 1" in str(error.value) and "AuditToString" in str(error.value)


def test_no_powershell_at_all_fails_closed(tmp_path: Path) -> None:
    build = load_build_module()
    with pytest.raises(build.BuildError, match="no PowerShell found"):
        build.verify_authenticode([tmp_path / "python.exe"], [])


@pytest.mark.parametrize(
    ("outcome", "message"),
    [
        ((1, "", "Get-AuthenticodeSignature : module could not be loaded"), "exit 1"),
        ((0, "", ""), "no JSON"),
        ((0, "Status : Valid", ""), "no JSON"),
        ((0, "null", ""), "no JSON"),
        ((0, json.dumps({"status": "", "subject": ""}), ""), "not valid"),
        ((0, json.dumps({"status": "NotSigned", "subject": ""}), ""), "not valid"),
        ((0, json.dumps({"status": "HashMismatch", "subject": PSF_SUBJECT}), ""), "not valid"),
        ((0, json.dumps({"status": "Valid", "subject": "CN=Someone Else, O=Evil"}), ""), "not by"),
        (
            (
                0,
                json.dumps({"status": "Valid", "subject": "CN=Python Software Foundation X, O=X"}),
                "",
            ),
            "not by",
        ),
        (
            (
                0,
                json.dumps({"status": "Valid", "subject": "CN=Evil, O=Python Software Foundation"}),
                "",
            ),
            "not by",
        ),
        ((0, json.dumps(["Valid"]), ""), "unexpected"),
    ],
)
def test_authenticode_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: Outcome, message: str
) -> None:
    build = load_build_module()
    fake_powershell(monkeypatch, build, {"powershell.exe": outcome})
    with pytest.raises(build.BuildError, match=message):
        build.verify_authenticode([tmp_path / "python.exe"], [WINPS])


# --- El script PowerShell real, con cmdlets falsos ------------------------------------------
# Las funciones tienen prioridad sobre los cmdlets en PowerShell, así que se puede simular
# Get-AuthenticodeSignature e Import-Module (incluido el fallo de TypeData de 5.1) en pwsh.

FAKE_SIGNATURE = """
function Get-AuthenticodeSignature([string]$LiteralPath) {
    if ($LiteralPath -ne $env:SENTRA_SIGNED_FILE) { throw "ruta alterada: $LiteralPath" }
    [pscustomobject]@{
        Status = 'Valid'; StatusMessage = 'Firma verificada.'
        SignerCertificate = [pscustomobject]@{ Subject = $env:FAKE_SUBJECT }
    }
}
"""
IMPORT_FAILS_WITH_TYPEDATA = (
    f"function Import-Module {{ Write-Output 'IMPORT_CALLED'; throw '{TYPEDATA_ERROR}' }}\n"
)


def run_signature_script(tmp_path: Path, prelude: str) -> subprocess.CompletedProcess[str]:
    build = load_build_module()
    signed = tmp_path / "carpeta con espacios" / "py $x 'q'.exe"
    signed.parent.mkdir(exist_ok=True)
    signed.write_bytes(b"MZ")
    _, env = build.authenticode_command(signed)
    env["FAKE_SUBJECT"] = PSF_SUBJECT
    assert POWERSHELL is not None
    return subprocess.run(  # noqa: S603
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            prelude + build.AUTHENTICODE_SCRIPT,
        ],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


@needs_powershell
def test_script_uses_an_available_cmdlet_without_import_module(tmp_path: Path) -> None:
    # Caso Windows PowerShell 5.1: el cmdlet ya existe e Import-Module rompería con TypeData.
    result = run_signature_script(tmp_path, FAKE_SIGNATURE + IMPORT_FAILS_WITH_TYPEDATA)
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CALLED" not in result.stdout
    info = json.loads(result.stdout.strip().splitlines()[-1])
    load_build_module().check_signature("python.exe", info)


@needs_powershell
def test_script_imports_the_module_only_when_the_cmdlet_is_missing(tmp_path: Path) -> None:
    # Sin el cmdlet, Import-Module se llama y es él quien lo aporta.
    prelude = (
        "Remove-Item Function:Get-AuthenticodeSignature -ErrorAction SilentlyContinue\n"
        "function Get-Command { $null }\n"
        "function Import-Module([string]$Name) {\n"
        "  if ($Name -ne 'Microsoft.PowerShell.Security') { throw \"módulo $Name\" }\n"
        "  [Console]::Error.WriteLine('IMPORT_CALLED')\n"
        + FAKE_SIGNATURE.replace("function Get-", "function global:Get-")
        + "}\n"
    )
    result = run_signature_script(tmp_path, prelude)
    assert result.returncode == 0, result.stderr
    assert "IMPORT_CALLED" in result.stderr
    assert json.loads(result.stdout.strip().splitlines()[-1])["status"] == "Valid"


@needs_powershell
def test_script_fails_closed_when_import_module_fails(tmp_path: Path) -> None:
    result = run_signature_script(
        tmp_path, "function Get-Command { $null }\n" + IMPORT_FAILS_WITH_TYPEDATA
    )
    assert result.returncode != 0
    assert '"status"' not in result.stdout


@needs_powershell
def test_authenticode_script_fails_closed_in_real_powershell(tmp_path: Path) -> None:
    # El script real, sin dobles: con un archivo sin firma (o, fuera de Windows, sin el
    # cmdlet) nunca devuelve "Valid".
    build = load_build_module()
    unsigned = tmp_path / "carpeta con espacios" / "python.exe"
    unsigned.parent.mkdir()
    unsigned.write_bytes(b"MZ not signed")
    _, env = build.authenticode_command(unsigned)
    assert POWERSHELL is not None
    result = subprocess.run(  # noqa: S603
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-Command", build.AUTHENTICODE_SCRIPT],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.returncode == 0:
        info = json.loads(result.stdout.strip().splitlines()[-1])
        assert info["status"] != "Valid"
        with pytest.raises(build.BuildError):
            build.check_signature("python.exe", info)
    else:
        assert '"Valid"' not in result.stdout


def test_build_checks_the_python_embed_hash(tmp_path: Path) -> None:
    result = run_build(tmp_path, "--insecure-skip-verify", "--python-embed-sha256", "0" * 64)
    assert result.returncode == 1
    assert "embedded Python SHA-256 mismatch" in result.stderr


def test_build_module_pins_psutil_and_requires_verification() -> None:
    source = (WINDOWS / "build.py").read_text(encoding="utf-8")
    assert re.search(r'PSUTIL_SHA256 = "[0-9a-f]{64}"', source)
    assert "Get-AuthenticodeSignature" in source and "Python Software Foundation" in source
    assert "cannot verify the embedded Python here" in source


# --- Scripts PowerShell: análisis estático ----------------------------------------------------


def script(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def test_installer_never_takes_the_token_as_an_argument() -> None:
    text = script(INSTALLER)
    params = re.search(r"param\((.*?)\n\)", text, re.S)
    assert params is not None
    assert "[string]$TokenFile" in params.group(1)
    assert not re.search(r"\$Token\b", params.group(1))  # ningún -Token en claro
    assert "Read-Host -AsSecureString" in text
    assert "ZeroFreeBSTR" in text
    # El token nunca se imprime ni se pasa a python como argumento (solo rutas de archivo).
    assert not re.search(r"Write-(Host|Step|Warn|Output)[^\n]*\$(token|secureToken)\b", text, re.I)
    for call in re.findall(r"Invoke-Winsetup[^\n]*", text):
        assert not re.search(r"\$(secureToken|token)\b", call, re.I), call


def test_scripts_have_a_utf8_bom_for_windows_powershell() -> None:
    # Sin BOM, Windows PowerShell 5.1 lee el script como ANSI y estropea los acentos.
    for path in (INSTALLER, UNINSTALLER):
        assert path.read_bytes().startswith(b"\xef\xbb\xbf"), path.name


def test_scripts_do_not_weaken_the_system() -> None:
    for path in (INSTALLER, UNINSTALLER):
        text = script(path).lower()
        for forbidden in (
            "new-netfirewallrule",
            "advfirewall",
            "set-mppreference",
            "add-mppreference",
            "enablelua",
            "set-executionpolicy",
            "consentpromptbehavior",
            "hidden",
            "attrib +h",
        ):
            assert forbidden not in text, (path.name, forbidden)


def test_installer_configures_a_standard_recoverable_service() -> None:
    text = script(INSTALLER)
    assert "New-Service -Name $name -BinaryPathName $Plan.binary_path" in text
    assert "'start=', 'delayed-auto'" in text
    assert "'failure', $name, 'reset='" in text and "'failureflag', $name, '1'" in text
    assert "'sidtype', $name, 'unrestricted'" in text
    assert "Add-LocalGroupMember -SID $Plan.event_log_readers_sid" in text
    assert "/inheritance:r" in text
    # Verifica el paquete antes de copiarlo y quita la marca MOTW solo a la copia instalada.
    assert text.index("Test-PackageIntegrity $packageDir") < text.index("Install-Runtime -Plan")
    assert "Unblock-File" in text


def test_uninstaller_keeps_state_unless_purge() -> None:
    text = script(UNINSTALLER)
    purge_block = text[text.index("if ($Purge) {") :]
    before_purge = text[: text.index("if ($Purge) {")]
    assert "$paths.DataDir" not in before_purge.split("function Invoke-Uninstall")[1]
    assert "Remove-Item -LiteralPath $paths.DataDir -Recurse -Force" in purge_block
    assert "sc.exe" in text and "'delete', $ServiceName" in text
    assert "/delete" in text  # sale del grupo Event Log Readers


@needs_powershell
@pytest.mark.parametrize("path", [INSTALLER, UNINSTALLER], ids=lambda p: p.name)
def test_scripts_parse_without_errors(path: Path) -> None:
    command = (
        "$errors = $null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$null, [ref]$errors); "
        "if ($errors) { $errors | ForEach-Object { $_.ToString() }; exit 1 }"
    )
    result = pwsh(command)
    assert result.returncode == 0, result.stdout + result.stderr


# --- Scripts PowerShell: funciones con pwsh ---------------------------------------------------


def pwsh(command: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    assert POWERSHELL is not None
    return subprocess.run(  # noqa: S603  (PowerShell local, script del test)
        # Bypass solo para este proceso de prueba (en Windows la directiva por defecto impide
        # cargar el script con "."); no cambia la directiva del equipo.
        [
            POWERSHELL,
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
        cwd=cwd,
        check=False,
        timeout=120,
    )


def call_installer(body: str, cwd: Path) -> Any:
    # Cargar el script con "." define sus funciones sin ejecutar la instalación.
    command = f". '{INSTALLER}'\n{body}"
    result = pwsh(command, cwd)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads(result.stdout.strip().splitlines()[-1])


def make_package(tmp_path: Path) -> Path:
    package = tmp_path / "pkg"
    (package / "payload" / "lib").mkdir(parents=True)
    (package / "payload" / "lib" / "a.py").write_text("print('a')\n")
    (package / "VERSION").write_text("version=0.2.0\n")
    lines = [
        f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(package).as_posix()}"
        for p in sorted(package.rglob("*"))
        if p.is_file()
    ]
    (package / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    return package


@needs_powershell
def test_package_integrity_detects_tampering_and_path_tricks(tmp_path: Path) -> None:
    package = make_package(tmp_path)
    check = (
        "try {{ $n = Test-PackageIntegrity '{0}'; ConvertTo-Json -Compress @{{ok=$true; n=$n}} }}"
        " catch {{ ConvertTo-Json -Compress @{{ok=$false; error=$_.Exception.Message}} }}"
    )
    assert call_installer(check.format(package), tmp_path) == {"ok": True, "n": 2}

    (package / "payload" / "lib" / "a.py").write_text("print('evil')\n")
    tampered = call_installer(check.format(package), tmp_path)
    assert tampered["ok"] is False and "no coincide" in tampered["error"]

    manifest = package / "MANIFEST.sha256"
    manifest.write_text(f"{'0' * 64}  ../outside.txt\n")
    escaped = call_installer(check.format(package), tmp_path)
    assert escaped["ok"] is False and "../outside.txt" in escaped["error"]


@needs_powershell
@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"state": "enrolled", "message": "enrolled: agent_id=x"}, "enrolled"),
        ({"state": "rejected", "message": "enrollment refused"}, "rejected"),
        ({"state": "unreachable", "message": "server unreachable"}, "unreachable"),
        (None, "timeout"),
    ],
)
def test_wait_enrollment_reads_the_status_written_by_the_service(
    tmp_path: Path, status: dict[str, str] | None, expected: str
) -> None:
    status_file = tmp_path / "enrollment-status.json"
    if status is not None:
        status_file.write_text(json.dumps(status), encoding="utf-8")
    body = f"""
function Get-Service {{ [pscustomobject]@{{ Status = 'Running' }} }}
function Start-Sleep {{ }}
$plan = [pscustomobject]@{{ status_file = '{status_file}'; service_name = 'SentraAgent' }}
$result = Wait-Enrollment -Plan $plan -TimeoutSeconds 1
ConvertTo-Json -Compress @{{ state = $result.state }}
"""
    assert call_installer(body, tmp_path)["state"] == expected


@needs_powershell
def test_wait_enrollment_notices_a_stopped_service(tmp_path: Path) -> None:
    body = f"""
function Get-Service {{ [pscustomobject]@{{ Status = 'Stopped' }} }}
function Start-Sleep {{ }}
$plan = [pscustomobject]@{{
  status_file = '{tmp_path / "none.json"}'; service_name = 'SentraAgent'
}}
ConvertTo-Json -Compress @{{ state = (Wait-Enrollment -Plan $plan -TimeoutSeconds 5).state }}
"""
    assert call_installer(body, tmp_path)["state"] == "service_stopped"


@needs_powershell
def test_identity_token_detection(tmp_path: Path) -> None:
    with_token = tmp_path / "with.json"
    with_token.write_text(json.dumps({"agent_id": "x", "token": {"scheme": "dpapi-user"}}))
    without = tmp_path / "without.json"
    without.write_text(json.dumps({"agent_id": "x", "token": None}))
    body = f"""
ConvertTo-Json -Compress @(
  (Test-IdentityHasToken '{with_token}'),
  (Test-IdentityHasToken '{without}'),
  (Test-IdentityHasToken '{tmp_path / "missing.json"}')
)
"""
    assert call_installer(body, tmp_path) == [True, False, False]


@needs_powershell
@pytest.mark.parametrize(
    ("given", "existing", "expected"),
    [
        (None, None, "Virtual"),  # instalación nueva: mínimo privilegio
        (None, "LocalSystem", "LocalSystem"),  # upgrade conserva la cuenta
        (None, "NT SERVICE\\SentraAgent", "Virtual"),
        ("LocalSystem", "NT SERVICE\\SentraAgent", "LocalSystem"),  # cambio explícito
    ],
)
def test_service_account_is_kept_on_upgrade(
    tmp_path: Path, given: str | None, existing: str | None, expected: str
) -> None:
    existing_obj = f"([pscustomobject]@{{ StartName = '{existing}' }})" if existing else "$null"
    given_line = (
        f"$ServiceAccount = '{given}'; $script:ServiceAccountGiven = $true" if given else ""
    )
    body = f"""
{given_line}
$plan = [pscustomobject]@{{ virtual_account = 'NT SERVICE\\SentraAgent' }}
$account = Resolve-ServiceAccount -Plan $plan -Existing {existing_obj}
ConvertTo-Json -Compress @{{ account = $account }}
"""
    assert call_installer(body, tmp_path)["account"] == expected


@needs_powershell
def test_native_errors_are_returned_not_thrown(tmp_path: Path) -> None:
    body = f"""
$code = 'import sys; print("out"); sys.stderr.write("err\\n"); sys.exit(3)'
$r = Invoke-Native -FilePath '{sys.executable}' -Arguments @('-c', $code)
ConvertTo-Json -Compress @{{ code = $r.ExitCode; out = $r.StdOut; err = $r.StdErr }}
"""
    result = call_installer(body, tmp_path)
    assert result["code"] == 3 and result["out"] == "out" and "err" in result["err"]
