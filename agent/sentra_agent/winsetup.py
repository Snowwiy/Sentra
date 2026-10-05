"""Plan de instalación del servicio Windows: rutas, configuración y línea de comandos.

El instalador PowerShell (packaging/windows/install-sentra-agent.ps1) hace el trabajo con
privilegios (servicio, ACL, grupos), pero todo lo que se puede calcular sin tocar el sistema
se calcula aquí, con el Python embebido del propio paquete:

    python.exe -I -m sentra_agent.winsetup plan --program-files ... --program-data ... --server URL

Así la generación de agent.toml, el entrecomillado de la ruta del servicio, la validación de
la URL y del token y el SID del servicio tienen una única implementación, probada con pytest en
cualquier plataforma (se usa PureWindowsPath, nunca el sistema de archivos real salvo en los
comandos que leen o escriben un archivo concreto que se les pasa).
"""

import argparse
import hashlib
import json
import re
import struct
import sys
import tomllib
import uuid
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Any
from urllib.parse import urlsplit

from sentra_agent.enrollment import STATUS_FILE
from sentra_agent.identity import FORMAT_VERSION, IDENTITY_FILE, write_atomic
from sentra_agent.winservice import DISPLAY_NAME, SERVICE_NAME

INSTALLATION_METHOD = "windows_service"
DESCRIPTION = (
    "Sentra Agent: monitorización del equipo (heartbeat, telemetría, inventario y eventos)."
    " Solo conexiones salientes al servidor Sentra."
)
# Grupo integrado "Event Log Readers" ("Lectores del registro de eventos" en Windows en
# español). Se usa el SID porque el nombre cambia con el idioma del sistema.
EVENT_LOG_READERS_SID = "S-1-5-32-573"
# Recuperación del SCM: reiniciar a los 10 s, 30 s y 60 s; el contador de fallos vuelve a cero
# tras un día sin fallos. Mismo espíritu que Restart=on-failure del servicio systemd.
FAILURE_RESET_SECONDS = 86_400
FAILURE_ACTIONS = "restart/10000/restart/30000/restart/60000"

# Misma regla que install-sentra-agent.sh y el wizard (frontend/src/lib/install.ts): sin
# espacios, comillas ni caracteres que puedan romper agent.toml o una línea de comandos.
SERVER_URL = re.compile(r"https?://[][A-Za-z0-9.:_-]+(/[A-Za-z0-9._~/-]*)?")
# Lo que genera el servidor: prefijo + base64 URL-safe.
ENROLLMENT_TOKEN = re.compile(r"sentra_et_[A-Za-z0-9_-]{20,200}")
# Caracteres que no pueden aparecer en una ruta que va a una cadena literal TOML ('...') o
# entre comillas dobles en la línea de comandos del servicio.
_UNSAFE_PATH = re.compile(r"['\"\x00-\x1f]")


class SetupError(ValueError):
    """Entrada inválida para el plan (el instalador la muestra y se detiene)."""


@dataclass(frozen=True)
class ServerUrl:
    url: str
    insecure: bool
    loopback: bool


def normalize_server_url(raw: str) -> ServerUrl:
    url = raw.strip().rstrip("/")
    if not SERVER_URL.fullmatch(url):
        raise SetupError(f"server URL is not valid: {raw!r} (expected http(s)://host[:port])")
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError as exc:  # p. ej. "[::1" sin cerrar
        raise SetupError(f"server URL is not valid: {raw!r}") from exc
    loopback = host in ("localhost", "::1") or host.startswith("127.")
    return ServerUrl(url=url, insecure=url.startswith("http://"), loopback=loopback)


def read_enrollment_token(path: Path) -> str:
    """Lee y valida el archivo de token de un solo uso (sin devolverlo a ningún log)."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SetupError(f"cannot read token file: {exc.strerror or exc}") from exc
    # Bloc de notas y Out-File de Windows PowerShell 5.1 escriben BOM (UTF-8 o UTF-16).
    for bom, encoding in ((b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le")):
        if raw.startswith(bom):
            text = raw[len(bom) :].decode(encoding, "replace")
            break
    else:
        text = raw.decode("utf-8", "replace")
    token = "".join(text.split())
    if not token:
        raise SetupError("token file is empty")
    if not ENROLLMENT_TOKEN.fullmatch(token):
        # Nunca se muestra el contenido: podría ser otro secreto pegado por error.
        raise SetupError("that is not a Sentra enrollment token (expected sentra_et_...)")
    return token


def stage_token(source: Path, dest: Path) -> None:
    """Deja el token validado y normalizado (sin BOM ni espacios) donde lo lee el servicio.

    `dest` está en state\\, cuya ACL solo da acceso a SYSTEM, Administradores y la cuenta del
    servicio; el archivo hereda esa ACL. El servicio lo borra al resolver el enrolamiento.
    """
    token = read_enrollment_token(source)
    write_atomic(dest, token, private=False)


def service_sid(name: str) -> str:
    """SID del servicio (`NT SERVICE\\<name>`), el mismo que calcula `sc.exe showsid`.

    Es S-1-5-80 seguido del SHA-1 del nombre en mayúsculas (UTF-16LE) como cinco DWORD little
    endian. Calcularlo permite dar permisos (icacls *SID) antes de que el servicio exista y sin
    depender de la resolución de nombres.
    """
    digest = hashlib.sha1(name.upper().encode("utf-16-le")).digest()  # noqa: S324  (algoritmo fijado por Windows)
    parts = struct.unpack("<5I", digest)
    return "S-1-5-80-" + "-".join(str(part) for part in parts)


@dataclass(frozen=True)
class WindowsLayout:
    """Rutas del agente instalado. Binarios, configuración, estado y logs separados."""

    program_files: PureWindowsPath
    program_data: PureWindowsPath

    @property
    def install_dir(self) -> PureWindowsPath:
        # Program Files: solo administradores pueden escribir, así que nadie sin privilegios
        # puede sustituir el python.exe que el servicio ejecuta.
        return self.program_files / "Sentra Agent"

    @property
    def runtime_python(self) -> PureWindowsPath:
        return self.install_dir / "runtime" / "python.exe"

    @property
    def lib_dir(self) -> PureWindowsPath:
        return self.install_dir / "lib"

    @property
    def data_dir(self) -> PureWindowsPath:
        return self.program_data / "Sentra" / "Agent"

    @property
    def config_dir(self) -> PureWindowsPath:
        return self.data_dir / "config"

    @property
    def config_file(self) -> PureWindowsPath:
        return self.config_dir / "agent.toml"

    @property
    def state_dir(self) -> PureWindowsPath:
        return self.data_dir / "state"

    @property
    def log_dir(self) -> PureWindowsPath:
        return self.data_dir / "logs"

    @property
    def token_file(self) -> PureWindowsPath:
        return self.state_dir / "enrollment.token"

    @property
    def status_file(self) -> PureWindowsPath:
        return self.state_dir / STATUS_FILE

    @property
    def identity_file(self) -> PureWindowsPath:
        return self.state_dir / IDENTITY_FILE


def make_layout(program_files: str, program_data: str) -> WindowsLayout:
    for label, value in (("program files", program_files), ("program data", program_data)):
        path = PureWindowsPath(value)
        if not path.is_absolute() or _UNSAFE_PATH.search(value):
            raise SetupError(f"{label} directory must be an absolute path without quotes")
    return WindowsLayout(PureWindowsPath(program_files), PureWindowsPath(program_data))


def service_binary_path(layout: WindowsLayout) -> str:
    """Línea de comandos del servicio (ImagePath), siempre con las rutas entre comillas.

    Sin comillas, una ruta con espacios ("C:\\Program Files\\...") permitiría al SCM ejecutar
    C:\\Program.exe (vulnerabilidad clásica de "unquoted service path").
    -I aísla el intérprete: ignora variables PYTHON*, el directorio actual y site-packages del
    usuario; sys.path sale solo del archivo ._pth del runtime embebido.
    """
    return f'"{layout.runtime_python}" -I -m sentra_agent --service --config "{layout.config_file}"'


def render_config(layout: WindowsLayout, server: ServerUrl) -> str:
    # Cadenas literales TOML ('...') para las rutas: las barras invertidas no se interpretan.
    # make_layout ya rechazó comillas simples y caracteres de control en las rutas.
    return (
        "# Sentra Agent: configuración del servicio Windows (generada por"
        " install-sentra-agent.ps1).\n"
        "# No contiene secretos: el token individual del agente está cifrado con DPAPI en\n"
        "# state\\identity.json y el token de instalación se borra al enrolar.\n"
        "# Tras cambiar api_url: Restart-Service SentraAgent\n"
        f'api_url = "{server.url}"\n'
        f"state_dir = '{layout.state_dir}'\n"
        f"log_dir = '{layout.log_dir}'\n"
        f"enrollment_token_file = '{layout.token_file}'\n"
        f'installation_method = "{INSTALLATION_METHOD}"\n'
    )


_API_URL_LINE = re.compile(r"(?m)^api_url\s*=.*$")


def update_config(existing: str, server: ServerUrl | None) -> str:
    """Upgrade: conserva la configuración del administrador; solo cambia api_url si se pide.

    También añade installation_method si falta, para que una configuración anterior empiece
    a informarlo sin perder el resto de claves.
    """
    try:
        data = tomllib.loads(existing)
    except tomllib.TOMLDecodeError as exc:
        raise SetupError(f"existing agent.toml is not valid TOML: {exc}") from exc
    text = existing if existing.endswith("\n") else existing + "\n"
    if server is not None:
        line = f'api_url = "{server.url}"'
        text = _API_URL_LINE.sub(line, text, count=1) if "api_url" in data else text + line + "\n"
    if "installation_method" not in data:
        text += f'installation_method = "{INSTALLATION_METHOD}"\n'
    return text


def existing_api_url(config_text: str) -> str | None:
    try:
        value = tomllib.loads(config_text).get("api_url")
    except tomllib.TOMLDecodeError:
        return None
    return value if isinstance(value, str) else None


def import_identity(source: Path, dest: Path) -> dict[str, str | None]:
    """Copia agent_id y asset_id de una instalación manual (sin el token).

    Un agente ejecutado antes a mano (start_agent.ps1) tiene su identidad en
    %LOCALAPPDATA%\\Sentra\\Agent. Reutilizar su agent_id hace que el servicio siga siendo el
    mismo activo en el servidor (mismo historial, sin duplicado) al enrolarse con el token de
    un solo uso. El token antiguo no se copia: está cifrado con DPAPI para el usuario que lo
    ejecutaba y la cuenta del servicio no podría descifrarlo.
    """
    if dest.exists():
        raise SetupError("the service already has an identity; nothing imported")
    try:
        data = json.loads(source.read_text(encoding="utf-8"))
        agent_id = str(uuid.UUID(str(data["agent_id"])))
        asset_raw = data.get("asset_id")
        asset_id = str(uuid.UUID(str(asset_raw))) if asset_raw else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        raise SetupError(f"manual identity not usable: {exc}") from exc
    payload = {
        "version": FORMAT_VERSION,
        "agent_id": agent_id,
        "asset_id": asset_id,
        "token": None,
        "token_issued_at": None,
    }
    write_atomic(dest, json.dumps(payload, indent=2), private=False)
    return {"agent_id": agent_id, "asset_id": asset_id}


def plan(
    program_files: str,
    program_data: str,
    server: str | None,
    existing_config: Path | None = None,
) -> dict[str, Any]:
    layout = make_layout(program_files, program_data)
    parsed = normalize_server_url(server) if server else None
    existing = (
        existing_config.read_text(encoding="utf-8")
        if existing_config is not None and existing_config.is_file()
        else None
    )
    if existing is not None:
        config_text: str | None = update_config(existing, parsed)
        if config_text == existing:
            config_text = None  # nada que reescribir
    elif parsed is not None:
        config_text = render_config(layout, parsed)
    else:
        raise SetupError("-Server is required for a first installation")
    api_url = parsed.url if parsed else existing_api_url(existing or "")
    return {
        "service_name": SERVICE_NAME,
        "display_name": DISPLAY_NAME,
        "description": DESCRIPTION,
        "service_sid": service_sid(SERVICE_NAME),
        "virtual_account": f"NT SERVICE\\{SERVICE_NAME}",
        "event_log_readers_sid": EVENT_LOG_READERS_SID,
        "failure_reset_seconds": FAILURE_RESET_SECONDS,
        "failure_actions": FAILURE_ACTIONS,
        "binary_path": service_binary_path(layout),
        "install_dir": str(layout.install_dir),
        "runtime_python": str(layout.runtime_python),
        "lib_dir": str(layout.lib_dir),
        "data_dir": str(layout.data_dir),
        "config_dir": str(layout.config_dir),
        "config_file": str(layout.config_file),
        "state_dir": str(layout.state_dir),
        "log_dir": str(layout.log_dir),
        "token_file": str(layout.token_file),
        "status_file": str(layout.status_file),
        "identity_file": str(layout.identity_file),
        "config_text": config_text,
        "api_url": api_url,
        "insecure": parsed.insecure if parsed else False,
        "loopback": parsed.loopback if parsed else False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="sentra_agent.winsetup")
    commands = parser.add_subparsers(dest="command", required=True)
    plan_cmd = commands.add_parser("plan", help="print the installation plan as JSON")
    plan_cmd.add_argument("--program-files", required=True)
    plan_cmd.add_argument("--program-data", required=True)
    plan_cmd.add_argument("--server")
    plan_cmd.add_argument("--existing-config", type=Path)
    token_cmd = commands.add_parser("check-token", help="validate a one-time token file")
    token_cmd.add_argument("--file", type=Path, required=True)
    stage_cmd = commands.add_parser("stage-token", help="validate and place a token file")
    stage_cmd.add_argument("--source", type=Path, required=True)
    stage_cmd.add_argument("--dest", type=Path, required=True)
    import_cmd = commands.add_parser("import-identity", help="reuse a manual agent_id")
    import_cmd.add_argument("--source", type=Path, required=True)
    import_cmd.add_argument("--dest", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        if args.command == "plan":
            result: Any = plan(
                args.program_files, args.program_data, args.server, args.existing_config
            )
        elif args.command == "check-token":
            read_enrollment_token(args.file)
            result = {"valid": True}
        elif args.command == "stage-token":
            stage_token(args.source, args.dest)
            result = {"staged": True}
        else:
            result = import_identity(args.source, args.dest)
    except SetupError as exc:
        # Una línea en stderr y código 2: el instalador la muestra tal cual.
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
