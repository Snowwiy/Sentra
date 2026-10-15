"""Configuración local: URL del servidor, rutas dentro del directorio de datos, tipos."""

import json
import sys
from pathlib import Path

import pytest

from sentra_sensor.config import ConfigError, LocalConfig, load_config, validate_server_url
from tests.privacy import assert_private, loosen

EXAMPLE = Path(__file__).resolve().parents[1] / "sensor.example.toml"
# Windows devuelve WinError 1314 (ERROR_PRIVILEGE_NOT_HELD) al crear un symlink sin Developer
# Mode ni privilegios de administrador. Es una limitación del entorno de test: solo en ese
# caso exacto se hace skip; el escape por junction (sin privilegios) se prueba aparte.
WINDOWS_PRIVILEGE_NOT_HELD = 1314


def toml_string(value: object) -> str:
    """String TOML básico: un string JSON es TOML válido (escapa las barras de Windows)."""
    return json.dumps(str(value))


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except OSError as exc:
        if sys.platform == "win32" and getattr(exc, "winerror", None) == WINDOWS_PRIVILEGE_NOT_HELD:
            pytest.skip(
                "Windows no permite crear symlinks en este entorno (WinError 1314: requiere "
                "Developer Mode o administrador); el escape por junction se prueba aparte"
            )
        raise


@pytest.mark.parametrize(
    "url",
    [
        "https://sentra.example.com",
        "https://10.1.2.3:8443/",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://[::1]:8000",
    ],
)
def test_server_url_accepted(url: str) -> None:
    assert validate_server_url(url) == url.rstrip("/")


@pytest.mark.parametrize(
    "url",
    [
        "http://10.0.0.5:8000",
        "http://sentra.example.com",
        "ftp://x",
        "https://u:p@host",
        "https://host/?q=1",
        "",
        "sentra.example.com",
    ],
)
def test_server_url_rejected(url: str) -> None:
    with pytest.raises(ConfigError):
        validate_server_url(url)


@pytest.mark.parametrize("value", ["../escape.sqlite3", "a/../../b", "/etc/passwd", "."])
def test_spool_path_traversal_rejected(tmp_path: Path, value: str) -> None:
    with pytest.raises(ConfigError):
        LocalConfig(data_dir=tmp_path, spool_path=value).validate()


def test_spool_path_inside_data_dir(tmp_path: Path) -> None:
    config = LocalConfig(data_dir=tmp_path, spool_path="queue/spool.db").validate()
    assert config.spool_file() == (tmp_path / "queue" / "spool.db").resolve()
    absolute = LocalConfig(data_dir=tmp_path, spool_path=str(tmp_path / "s.db")).validate()
    assert absolute.spool_file() == (tmp_path / "s.db").resolve()


def test_symlink_escape_rejected(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    _symlink_or_skip(data / "link", outside)
    with pytest.raises(ConfigError):
        LocalConfig(data_dir=data, spool_path="link/spool.db").validate()


def test_windows_junction_escape_rejected(tmp_path: Path) -> None:
    # Una junction no necesita privilegios: en Windows el escape del directorio de datos se
    # prueba siempre. El skip va dentro para que mypy solo analice _winapi en win32.
    if sys.platform != "win32":
        pytest.skip("las junctions solo existen en Windows; POSIX lo cubre con el symlink")
    import _winapi

    outside = tmp_path / "outside"
    outside.mkdir()
    data = tmp_path / "data"
    data.mkdir()
    _winapi.CreateJunction(str(outside), str(data / "escape"))
    escapes = (
        LocalConfig(data_dir=data, spool_path="escape/spool.db"),
        LocalConfig(data_dir=data, credential_path="escape/credential.json"),
        LocalConfig(data_dir=data, state_path="escape/state.json"),
    )
    for config in escapes:
        with pytest.raises(ConfigError, match="inside the data directory"):
            config.validate()


def test_credential_path_traversal_rejected(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        LocalConfig(data_dir=tmp_path, credential_path="../../root/cred.json").validate()


def test_load_toml_and_unknown_keys(tmp_path: Path) -> None:
    path = tmp_path / "sensor.toml"
    path.write_text(
        f'[sensor]\nserver_url = "https://s.example"\ndata_dir = {toml_string(tmp_path)}\n'
        "poll_interval_seconds = 45\nspool_max_mb = 8\n"
    )
    config = load_config(path)
    assert config.poll_interval_seconds == 45 and config.spool_max_mb == 8
    assert config.data_dir == tmp_path  # la ruta (con barras invertidas en Windows) llega intacta
    path.write_text('[sensor]\nallowed_networks = ["0.0.0.0/0"]\n')
    with pytest.raises(ConfigError, match="unknown"):
        load_config(path)


def test_invalid_types_and_ranges(tmp_path: Path) -> None:
    path = tmp_path / "sensor.toml"
    data_dir = toml_string(tmp_path)
    path.write_text(f'data_dir = {data_dir}\npoll_interval_seconds = "fast"\n')
    with pytest.raises(ConfigError, match="type"):
        load_config(path)
    path.write_text(f"data_dir = {data_dir}\nheartbeat_interval_seconds = 0\n")
    with pytest.raises(ConfigError, match="between"):
        load_config(path)
    path.write_text(f"data_dir = {data_dir}\nallow_system_ping = 1\n")
    with pytest.raises(ConfigError, match="type"):
        load_config(path)


def test_raw_windows_path_in_toml_is_a_clear_error(tmp_path: Path) -> None:
    # Una ruta Windows sin escapar es TOML inválido: el sensor no debe arrancar con ella.
    path = tmp_path / "sensor.toml"
    path.write_text('data_dir = "C:\\Users\\sentra\\sensor"\n')  # barra invertida sin escapar
    with pytest.raises(ConfigError, match="TOML"):
        load_config(path)


def test_no_option_disables_tls() -> None:
    names = {f for f in LocalConfig.__dataclass_fields__}
    assert not {n for n in names if "verify" in n or "insecure" in n}


def test_example_config_loads(tmp_path: Path) -> None:
    lines = [line.strip() for line in EXAMPLE.read_text().splitlines()]
    assert not any(line.startswith("allowed_networks") for line in lines)
    config = load_config(EXAMPLE, {"data_dir": tmp_path})
    assert config.server_url is not None and config.server_url.startswith("https://")


def test_ensure_data_dir_is_private(tmp_path: Path) -> None:
    data = tmp_path / "a" / "b"
    LocalConfig(data_dir=data).ensure_data_dir()
    assert_private(data, directory=True)  # 0700 en POSIX; DACL privada en Windows
    loosen(data, directory=True)
    LocalConfig(data_dir=data).ensure_data_dir()
    assert_private(data, directory=True)
