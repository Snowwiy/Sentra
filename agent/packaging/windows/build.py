"""Construye el paquete Windows de Sentra Agent (solo el agente: sin servidor ni secretos).

    python agent/packaging/windows/build.py
    python agent/packaging/windows/build.py --python-embed-zip python-3.12.10-embed-amd64.zip
    python agent/packaging/windows/build.py --psutil-wheel psutil-7.2.2-cp37-abi3-win_amd64.whl

Salida en <repo>/dist (fuera de git):
    sentra-agent-<versión>-windows-x86_64.zip      instalador + runtime
    sentra-agent-<versión>-windows-x86_64.zip.sha256

Contenido del zip (carpeta sentra-agent-<versión>-windows-x86_64\\):
    install-sentra-agent.ps1, uninstall-sentra-agent.ps1, README.md, VERSION, MANIFEST.sha256
    payload\\runtime\\   Python embebido oficial (python.org, firmado por la PSF)
    payload\\lib\\       sentra_agent + psutil (rueda binaria fijada por hash)

Por qué Python embebido y no PyInstaller/MSI: es el runtime oficial, sin compilar nada ni
añadir herramientas de build; el instalador PowerShell no necesita Python en el equipo, git,
pip ni venv. La estructura (binarios en Program Files, datos en ProgramData, servicio) es la
misma que tendría un MSI futuro (ver docs/agent-windows-installation.md).

Verificación de lo que se descarga:
- psutil: SHA-256 fijado abajo (el publicado en PyPI).
- Python embebido: en Windows se exige firma Authenticode válida de la Python Software
  Foundation en python.exe y pythonXY.dll; fuera de Windows (o además) --python-embed-sha256.
  Sin ninguna de las dos verificaciones el build se niega a continuar.

Reproducible: mismas fuentes + mismos binarios + mismo SOURCE_DATE_EPOCH = mismos bytes.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
AGENT_DIR = HERE.parents[1]
REPO_DIR = AGENT_DIR.parent

DEFAULT_PYTHON_VERSION = "3.12.10"
PSUTIL_VERSION = "7.2.2"
PSUTIL_WHEEL = f"psutil-{PSUTIL_VERSION}-cp37-abi3-win_amd64.whl"
# SHA-256 publicado en PyPI para esa rueda (https://pypi.org/project/psutil/7.2.2/#files).
PSUTIL_SHA256 = "eb7e81434c8d223ec4a219b5fc1c47d0417b12be7ea866e24fb5ad6e84b3d988"
PSF_SIGNER = "Python Software Foundation"
# Fecha mínima admitida por el formato zip.
ZIP_EPOCH_MIN = 315532800  # 1980-01-01


class BuildError(Exception):
    pass


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def agent_version() -> str:
    text = (AGENT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^version = "([^"]+)"', text)
    if not match:
        raise BuildError("version not found in agent/pyproject.toml")
    return match.group(1)


def download(url: str, dest: Path) -> Path:
    print(f"downloading {url}")
    with urllib.request.urlopen(url, timeout=120) as response, dest.open("wb") as out:  # noqa: S310  (URL https fija)
        shutil.copyfileobj(response, out)
    return dest


def fetch_psutil(work: Path) -> Path:
    """Descarga la rueda de psutil con pip (índice configurado) y verifica su hash."""
    target = work / "wheels"
    subprocess.run(  # noqa: S603  (argumentos fijos, sin shell)
        [
            sys.executable,
            "-m",
            "pip",
            "download",
            f"psutil=={PSUTIL_VERSION}",
            "--no-deps",
            "--only-binary=:all:",
            "--platform",
            "win_amd64",
            "--implementation",
            "cp",
            "--python-version",
            "3.12",
            "-d",
            str(target),
            "-q",
        ],
        check=True,
    )
    return target / PSUTIL_WHEEL


# Expresión PowerShell que construye un objeto explícito y lo emite como JSON: nunca se
# interpreta Format-List ni texto localizado. Vale para Windows PowerShell 5.1 y PowerShell 7.
# Cualquier error (cmdlet ausente, archivo ilegible) termina con código distinto de cero.
# Microsoft.PowerShell.Security solo se importa si el cmdlet no está disponible: en Windows
# PowerShell 5.1 ese módulo ya está cargado (o se autocarga) y un Import-Module explícito
# vuelve a registrar su TypeData y falla con "Ya existe el miembro AuditToString/Sddl/...".
AUTHENTICODE_SCRIPT = """
$ErrorActionPreference = 'Stop'
if ($null -eq (Get-Command -Name Get-AuthenticodeSignature -ErrorAction SilentlyContinue)) {
    Import-Module -Name Microsoft.PowerShell.Security
}
$sig = Get-AuthenticodeSignature -LiteralPath $env:SENTRA_SIGNED_FILE
if ($null -eq $sig) { throw 'Get-AuthenticodeSignature no devolvió nada' }
$subject = ''
if ($null -ne $sig.SignerCertificate) { $subject = [string]$sig.SignerCertificate.Subject }
[pscustomobject]@{
    status = $sig.Status.ToString()
    status_message = [string]$sig.StatusMessage
    subject = $subject
} | ConvertTo-Json -Compress
"""


def windows_powershell() -> Path:
    # Ruta absoluta: nunca un powershell.exe que aparezca antes en el PATH.
    root = Path(os.environ.get("SYSTEMROOT", r"C:\Windows"))
    return root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"


def powershell_7() -> Path:
    # Ruta de instalación estándar de PowerShell 7 (MSI/winget), tampoco por PATH.
    root = Path(
        os.environ.get("PROGRAMW6432") or os.environ.get("PROGRAMFILES", r"C:\Program Files")
    )
    return root / "PowerShell" / "7" / "pwsh.exe"


def powershell_candidates() -> list[Path]:
    """PowerShell a usar para la firma, por orden de preferencia (solo los que existen).

    Primero pwsh 7 si está instalado: carga sus módulos de forma predecible y es donde la
    comprobación manual funciona. Después Windows PowerShell 5.1, que viene con todo Windows
    soportado: PowerShell 7 nunca es un requisito.
    """
    return [shell for shell in (powershell_7(), windows_powershell()) if shell.is_file()]


def authenticode_command(path: Path, shell: Path | None = None) -> tuple[list[str], dict[str, str]]:
    """Línea de comandos y entorno para comprobar la firma de `path` con `shell`."""
    # -EncodedCommand (UTF-16LE en base64): el script no pasa por el troceado de argumentos
    # de Windows, así que ni comillas ni espacios pueden alterarlo. La ruta va en una
    # variable de entorno, no en el script: rutas con espacios, comillas o "$" llegan intactas.
    encoded = base64.b64encode(AUTHENTICODE_SCRIPT.encode("utf-16-le")).decode("ascii")
    env = {**os.environ, "SENTRA_SIGNED_FILE": str(path)}
    # Si build.py se lanza desde PowerShell 7, PSModulePath apunta a sus módulos y Windows
    # PowerShell 5.1 intentaría cargar módulos incompatibles. Sin la variable, cada
    # PowerShell calcula sus rutas por defecto.
    env.pop("PSModulePath", None)
    command = [
        str(shell or windows_powershell()),
        "-NoProfile",
        "-NonInteractive",
        # Errores en texto plano (con -EncodedCommand PowerShell los emite como CLIXML).
        "-OutputFormat",
        "Text",
        "-EncodedCommand",
        encoded,
    ]
    return command, env


def _subject_fields(subject: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for part in subject.split(","):
        key, sep, value = part.strip().partition("=")
        if sep:
            fields.setdefault(key.strip().upper(), value.strip())
    return fields


def check_signature(name: str, info: object) -> str:
    """Exige firma válida y certificado de la PSF (CN y O exactos). Devuelve el subject."""
    if not isinstance(info, dict):
        raise BuildError(f"{name}: unexpected signature check output: {info!r}")
    status = info.get("status")
    subject = info.get("subject") or ""
    if status != "Valid":
        raise BuildError(
            f"{name}: Authenticode signature not valid: status={status!r}"
            f" ({info.get('status_message')!r})"
        )
    fields = _subject_fields(str(subject))
    # Igualdad exacta de CN y O: un "contiene" aceptaría p. ej. "CN=Python Software
    # Foundation Fake" o un nombre de la PSF dentro de otro campo.
    if fields.get("CN") != PSF_SIGNER or fields.get("O") != PSF_SIGNER:
        raise BuildError(f"{name}: signed by {subject!r}, not by {PSF_SIGNER}")
    return str(subject)


def _signature_info(path: Path, shell: Path) -> tuple[object | None, str]:
    """Ejecuta la comprobación con `shell`. Devuelve (JSON, "") o (None, motivo del fallo)."""
    command, env = authenticode_command(path, shell)
    try:
        result = subprocess.run(  # noqa: S603  (PowerShell por ruta absoluta, script fijo)
            command, capture_output=True, text=True, check=False, env=env
        )
    except OSError as exc:
        return None, f"{shell.name}: {exc}"
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        return None, f"{shell.name} exit {result.returncode}: {detail}"
    # La última línea no vacía es el JSON (avisos previos no deben romper el análisis).
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    try:
        return (json.loads(lines[-1]) if lines else None), f"{shell.name}: no JSON output"
    except json.JSONDecodeError:
        return None, f"{shell.name}: no JSON output: {result.stdout.strip()!r}"


def verify_authenticode(paths: list[Path], shells: list[Path] | None = None) -> None:
    """Exige firma Authenticode válida de la PSF (solo posible en Windows). Fail closed.

    Se prueba el siguiente PowerShell solo si el anterior no pudo dar un veredicto (no
    arranca, falla el cmdlet o no hay JSON). Un veredicto negativo (firma no válida u otro
    firmante) detiene el build: nunca se "busca" un PowerShell que diga otra cosa.
    """
    candidates = powershell_candidates() if shells is None else shells
    if not candidates:
        raise BuildError("no PowerShell found to verify Authenticode signatures")
    for path in paths:
        failures = []
        for shell in candidates:
            info, failure = _signature_info(path, shell)
            if info is not None:
                subject = check_signature(path.name, info)
                print(f"signature ok: {path.name} ({subject}) [{shell.name}]")
                break
            failures.append(failure)
        else:
            raise BuildError(f"{path.name}: signature check failed: " + " | ".join(failures))


def stage_runtime(embed_zip: Path, runtime: Path) -> str:
    """Extrae el Python embebido y fija su sys.path. Devuelve la etiqueta pythonXY."""
    with zipfile.ZipFile(embed_zip) as archive:
        archive.extractall(runtime)
    pth_files = sorted(runtime.glob("python3*._pth"))
    if len(pth_files) != 1:
        raise BuildError("embedded Python ._pth file not found (is it an embed zip?)")
    tag = pth_files[0].name.removesuffix("._pth")
    # El archivo ._pth fija sys.path y desactiva PYTHONPATH y el registro. Solo el stdlib
    # comprimido, el propio runtime y ..\lib (sentra_agent + psutil). Sin "import site": nada
    # de site-packages ni de .pth de terceros.
    pth_files[0].write_text(f"{tag}.zip\n.\n..\\lib\n", encoding="ascii", newline="\r\n")
    return tag


def staged_files(stage: Path) -> list[tuple[str, Path]]:
    """Archivos del paquete con su ruta POSIX relativa, en orden explícito y estable.

    Se ordena por la cadena POSIX (ordinal, sensible a mayúsculas) y no por Path: en Windows
    Path compara sin distinguir mayúsculas y con separadores "\\", así que el orden del zip y
    de MANIFEST.sha256 dependería del sistema que construye. Tampoco se usa el orden de
    rglob/os.scandir, que depende del sistema de archivos.
    """
    found = [(p.relative_to(stage).as_posix(), p) for p in stage.rglob("*") if p.is_file()]
    return sorted(found, key=lambda item: item[0])


def write_manifest(stage: Path) -> None:
    lines = []
    for relative, path in staged_files(stage):
        lines.append(f"{sha256_file(path)}  {relative}")
    (stage / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_zip(stage: Path, name: str, out: Path, epoch: int) -> Path:
    stamp = time.gmtime(max(epoch, ZIP_EPOCH_MIN))[:6]
    archive_path = out / f"{name}.zip"
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, path in staged_files(stage):
            # Solo nombre, contenido y metadatos fijos: la fecha de SOURCE_DATE_EPOCH (nunca
            # la del archivo ni la actual), permisos fijos y sistema de origen fijo. Así ni las
            # fechas que conserva una copia en Windows ni los permisos del checkout llegan al
            # zip. Sin entradas de directorio (su presencia variaría entre extractores).
            info = zipfile.ZipInfo(f"{name}/{relative}", stamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.create_system = 0
            archive.writestr(info, path.read_bytes(), compresslevel=9)
    archive_path.write_bytes(buffer.getvalue())
    sha = sha256_file(archive_path)
    (out / f"{name}.zip.sha256").write_text(f"{sha}  {archive_path.name}\n", encoding="utf-8")
    return archive_path


def build(args: argparse.Namespace) -> Path:
    version = agent_version()
    name = f"sentra-agent-{version}-windows-x86_64"
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    epoch = int(os.environ.get("SOURCE_DATE_EPOCH") or _git_epoch())

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        embed = Path(args.python_embed_zip) if args.python_embed_zip else None
        if embed is None:
            url = (
                f"https://www.python.org/ftp/python/{args.python_version}/"
                f"python-{args.python_version}-embed-amd64.zip"
            )
            embed = download(url, work / f"python-{args.python_version}-embed-amd64.zip")
        embed_sha = sha256_file(embed)
        if args.python_embed_sha256 and embed_sha != args.python_embed_sha256.lower():
            raise BuildError(f"embedded Python SHA-256 mismatch: got {embed_sha}")

        wheel = Path(args.psutil_wheel) if args.psutil_wheel else fetch_psutil(work)
        wheel_sha = sha256_file(wheel)
        if wheel_sha != PSUTIL_SHA256 and not args.insecure_skip_verify:
            raise BuildError(f"psutil wheel SHA-256 mismatch: got {wheel_sha}")

        stage = work / name
        runtime = stage / "payload" / "runtime"
        lib = stage / "payload" / "lib"
        runtime.mkdir(parents=True)
        lib.mkdir(parents=True)
        tag = stage_runtime(embed, runtime)

        signed = [runtime / "python.exe", runtime / f"{tag}.dll"]
        if sys.platform == "win32" and not args.insecure_skip_verify:
            verify_authenticode(signed)
        elif not args.python_embed_sha256 and not args.insecure_skip_verify:
            raise BuildError(
                "cannot verify the embedded Python here: build on Windows (Authenticode) or"
                " pass --python-embed-sha256 with the value published on python.org"
            )

        with zipfile.ZipFile(wheel) as wheel_zip:
            wheel_zip.extractall(lib)
        shutil.copytree(
            AGENT_DIR / "sentra_agent",
            lib / "sentra_agent",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

        for script in ("install-sentra-agent.ps1", "uninstall-sentra-agent.ps1"):
            # CRLF y BOM UTF-8: Windows PowerShell 5.1 lee un .ps1 sin BOM como ANSI y
            # estropearía los acentos de los mensajes.
            text = (HERE / script).read_text(encoding="utf-8-sig")
            data = "﻿" + text.replace("\r\n", "\n").replace("\n", "\r\n")
            (stage / script).write_bytes(data.encode("utf-8"))
        shutil.copyfile(REPO_DIR / "docs" / "agent-windows-installation.md", stage / "README.md")
        (stage / "VERSION").write_text(
            f"version={version}\narch=x86_64\npython={tag}\n"
            f"python_embed_sha256={embed_sha}\npsutil={wheel.name}\n"
            f"psutil_sha256={wheel_sha}\n",
            encoding="utf-8",
        )
        write_manifest(stage)
        package = write_zip(stage, name, out, epoch)
    print(f"built {package}")
    return package


def _git_epoch() -> int:
    try:
        result = subprocess.run(  # noqa: S603  (argumentos fijos)
            ["git", "-C", str(REPO_DIR), "log", "-1", "--format=%ct"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        )
        return int(result.stdout.strip())
    except (OSError, subprocess.CalledProcessError, ValueError):
        return 1_790_000_000


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the Sentra Agent Windows package")
    parser.add_argument("--out", default=str(REPO_DIR / "dist"))
    parser.add_argument("--python-version", default=DEFAULT_PYTHON_VERSION)
    parser.add_argument("--python-embed-zip", help="local python-X.Y.Z-embed-amd64.zip")
    parser.add_argument("--python-embed-sha256", help="expected SHA-256 of the embed zip")
    parser.add_argument("--psutil-wheel", help=f"local {PSUTIL_WHEEL}")
    # Solo para los tests (binarios falsos). Nunca para un paquete que se vaya a instalar.
    parser.add_argument("--insecure-skip-verify", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        build(args)
    except (BuildError, OSError, subprocess.CalledProcessError) as exc:
        print(f"build failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
