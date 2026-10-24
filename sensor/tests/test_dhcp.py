"""Fase 6E (sensor 0.6.0): fuentes DHCP locales, parsers de leases y job `dhcp_leases`."""

import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from sentra_sensor import CAPABILITIES, __version__
from sentra_sensor.config import ConfigError, LocalConfig, load_config
from sentra_sensor.dhcp import (
    MAX_LEASES_PER_BATCH,
    DhcpCollector,
    DhcpFormatError,
    DhcpReadError,
    ParseResult,
    client_id_value,
    decode_text,
    describe_sources,
    normalize_mac,
    parse_dnsmasq,
    parse_generic_csv,
    parse_isc_dhcpd,
    parse_kea_csv,
    parse_leases,
    parse_windows_dhcp_csv,
    read_lease_file,
    sanitize_hostname,
)
from sentra_sensor.diagnostics import local_status, run_diagnostics
from sentra_sensor.jobs import DhcpParameters, JobRejectedError, validate_job
from sentra_sensor.protocol import ServerConfig
from tests.conftest import (
    SENSOR_ID,
    SITE_ID,
    FakeServer,
    make_job,
    make_runner,
    server_config,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "dhcp"
# Hora de referencia de los ficheros de ejemplo: jueves 22/10/2026 12:00 UTC.
NOW = datetime(2026, 10, 22, 12, 0, tzinfo=UTC)
NOW_EPOCH = NOW.timestamp()


def fixture_text(name: str) -> str:
    return decode_text((FIXTURES / name).read_bytes())


def by_ip(result: ParseResult) -> dict[str, dict[str, Any]]:
    return {lease.ip: lease.to_json() for lease in result.leases}


def short_hash(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()[:16]


def toml_string(value: object) -> str:
    # Un string JSON es TOML válido (escapa las barras invertidas de las rutas de Windows).
    return json.dumps(str(value))


# --- normalización ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        (" 02:11:22:33:44:55 ", "02:11:22:33:44:55"),  # MAC aleatoria: válida aquí
        ("aa:bb-cc:dd:ee:ff", None),  # separadores mezclados
        ("aa:bb:cc:dd:ee", None),
        ("00:00:00:00:00:00", None),
        ("ff:ff:ff:ff:ff:ff", None),
        ("01:00:5e:00:00:01", None),  # multicast
        ("zz:bb:cc:dd:ee:ff", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_mac(raw: str | None, expected: str | None) -> None:
    assert normalize_mac(raw) == expected


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("pixel-7", "pixel-7"),
        ("  laptop  ", "laptop"),
        ("*", None),
        ("", None),
        (None, None),
        ("evil\x1b[31mname\x07", "evil[31mname"),
        ("zero​width", "zerowidth"),
        ("a" * 300, "a" * 255),
        ("café-pc", "café-pc"),
    ],
)
def test_sanitize_hostname(raw: str | None, expected: str | None) -> None:
    assert sanitize_hostname(raw) == expected


def test_client_id_mac_with_type_01_is_null_and_opaque_is_hashed() -> None:
    mac = "aa:bb:cc:dd:ee:ff"
    assert client_id_value(bytes.fromhex("01aabbccddeeff"), mac) is None
    assert client_id_value(None, mac) is None
    assert client_id_value(b"", mac) is None
    opaque = bytes.fromhex("ff00000001000100")
    value = client_id_value(opaque, mac)
    assert value == short_hash(opaque)
    assert value is not None and len(value) == len("sha256:") + 16
    # Tipo 01 con OTRA MAC: es un identificador distinto, se resume.
    assert client_id_value(bytes.fromhex("01aabbccddee00"), mac) is not None


def test_decode_text_handles_bom_and_utf16() -> None:
    assert decode_text("﻿ip,mac".encode()) == "ip,mac"
    assert decode_text("ip,mac".encode("utf-16")) == "ip,mac"
    assert decode_text(b"caf\xe9") == "caf�"  # nunca lanza por bytes inválidos


# --- parsers ------------------------------------------------------------------------------


def test_dnsmasq_fixture() -> None:
    result = parse_dnsmasq(fixture_text("dnsmasq.leases"), NOW)
    leases = by_ip(result)
    assert set(leases) == {"192.168.50.23", "192.168.50.10", "192.168.50.31"}
    assert leases["192.168.50.23"] == {
        "ip": "192.168.50.23",
        "mac": "aa:bb:cc:dd:ee:01",
        "hostname": "pixel-7",
        "client_id": None,  # 01 + su propia MAC
        "starts_at": None,
        "ends_at": "2026-10-22T20:00:00+00:00",
        "state": "active",
    }
    # expiry 0 = lease infinito.
    assert leases["192.168.50.10"]["ends_at"] is None
    assert leases["192.168.50.10"]["state"] == "active"
    assert leases["192.168.50.10"]["client_id"] is None
    expired = leases["192.168.50.31"]
    assert expired["state"] == "expired" and expired["hostname"] is None
    assert expired["client_id"] == short_hash(
        bytes.fromhex("ff56504d98000200 00ab119f362bc7aa130cd2".replace(" ", ""))
    )
    # La línea duid no cuenta; basura, MAC/IP inválidas y el lease IPv6 (IAID) sí.
    assert (result.lines, result.parsed, result.skipped, result.truncated) == (7, 3, 4, False)


def test_isc_fixture_last_occurrence_wins() -> None:
    result = parse_isc_dhcpd(fixture_text("dhcpd.leases"), NOW)
    leases = by_ip(result)
    assert set(leases) == {"192.168.50.100", "192.168.50.101", "192.168.50.102", "192.168.50.103"}
    assert leases["192.168.50.100"] == {
        "ip": "192.168.50.100",
        "mac": "00:1a:2b:3c:4d:5e",
        "hostname": "DESKTOP-7Q2K1",  # el bloque posterior gana
        "client_id": None,  # uid "\001" + MAC
        "starts_at": "2026-10-22T08:00:00+00:00",
        "ends_at": "2026-10-22T20:00:00+00:00",
        "state": "active",
    }
    assert leases["192.168.50.101"]["state"] == "expired"  # binding state free
    assert leases["192.168.50.101"]["client_id"] == short_hash(
        bytes([0o377, 3, 4, 5, 6, 0, 1, 0, 1])
    )
    assert leases["192.168.50.102"]["state"] == "released"
    assert leases["192.168.50.102"]["hostname"] == 'printer "lab"'
    infinite = leases["192.168.50.103"]
    assert infinite["ends_at"] is None and infinite["state"] == "active"
    assert infinite["starts_at"] == "2026-10-22T08:00:00+00:00"  # starts epoch N
    assert infinite["client_id"] is None  # uid sin comillas 1:<mac>
    # 8 bloques lease; sin MAC, fecha imposible y bloque sin cerrar = skipped. Las cabeceras,
    # failover y host son sentencias conocidas de dhcpd y no cuentan.
    assert (result.lines, result.parsed, result.skipped) == (8, 4, 3)


def test_isc_expired_active_binding_uses_end_time() -> None:
    text = (
        "lease 10.0.0.9 {\n  starts 4 2026/10/22 08:00:00;\n  ends 4 2026/10/22 09:00:00;\n"
        "  binding state active;\n  hardware ethernet 3c:22:fb:00:00:09;\n}\n"
    )
    (lease,) = parse_isc_dhcpd(text, NOW).leases
    assert lease.state == "expired"


def test_isc_rejects_other_formats() -> None:
    with pytest.raises(DhcpFormatError):
        parse_leases("isc_dhcpd", fixture_text("dnsmasq.leases"), NOW)
    with pytest.raises(DhcpFormatError):
        parse_leases("isc_dhcpd", fixture_text("generic.csv"), NOW)
    # Un dhcpd.leases recién creado (solo cabeceras) es válido y está vacío.
    empty = "# comment\nauthoring-byte-order little-endian;\n"
    assert parse_leases("isc_dhcpd", empty, NOW).parsed == 0


def test_kea_fixture() -> None:
    result = parse_kea_csv(fixture_text("kea-leases4.csv"), NOW)
    leases = by_ip(result)
    assert set(leases) == {"192.168.50.20", "192.168.50.21", "192.168.50.23", "192.168.50.24"}
    tablet = leases["192.168.50.20"]  # memfile de solo-añadir: la última fila gana
    assert tablet == {
        "ip": "192.168.50.20",
        "mac": "aa:bb:cc:00:00:01",
        "hostname": "tablet-01",
        "client_id": None,
        "starts_at": datetime.fromtimestamp(1792673200 - 3600, UTC).isoformat(),
        "ends_at": datetime.fromtimestamp(1792673200, UTC).isoformat(),
        "state": "active",
    }
    tv = leases["192.168.50.21"]
    assert tv["hostname"] == "tv, living"  # &#x2c desescapado
    assert tv["state"] == "expired"  # state 0 pero ya caducado
    assert tv["client_id"] == short_hash(bytes.fromhex("ff000000010001 2b4c".replace(" ", "")))
    assert leases["192.168.50.23"]["state"] == "expired"  # state 2
    printer = leases["192.168.50.24"]
    assert printer["ends_at"] is None and printer["starts_at"] is None
    assert printer["state"] == "active"
    assert (result.lines, result.parsed, result.skipped) == (7, 4, 2)


def test_kea_declined_state_is_unknown() -> None:
    text = (
        "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,"
        "hostname,state\n192.168.50.30,aa:bb:cc:00:00:30,,3600,1792672000,1,0,0,,1\n"
    )
    (lease,) = parse_kea_csv(text, NOW).leases
    assert lease.state == "unknown"


def test_kea_requires_its_header() -> None:
    with pytest.raises(DhcpFormatError):
        parse_kea_csv("ip,mac,hostname\n10.0.0.1,aa:bb:cc:dd:ee:ff,x\n", NOW)
    with pytest.raises(DhcpFormatError):
        parse_kea_csv("", NOW)


def test_windows_fixture() -> None:
    # Antes del vencimiento local de la fila en-US en cualquier zona horaria (-12..+14).
    now = datetime(2026, 10, 21, 0, 0, tzinfo=UTC)
    result = parse_windows_dhcp_csv(fixture_text("windows-dhcp.csv"), now)
    leases = by_ip(result)
    assert set(leases) == {"10.0.0.50", "10.0.0.51", "10.0.0.52", "10.0.0.53", "10.0.0.54"}
    ws = leases["10.0.0.50"]
    assert ws["mac"] == "00:15:5d:01:02:03" and ws["client_id"] is None
    assert ws["hostname"] == "ws01.corp.example" and ws["state"] == "active"
    # Formato en-US por defecto de PowerShell: hora local del host.
    local_end = datetime(2026, 10, 22, 18, 0).astimezone().astimezone(UTC)
    assert ws["ends_at"] == local_end.isoformat()
    assert leases["10.0.0.51"]["state"] == "active"  # ActiveReservation
    assert leases["10.0.0.51"]["hostname"] == "prn-2f.corp.example"
    assert leases["10.0.0.52"]["state"] == "expired"
    assert leases["10.0.0.52"]["ends_at"] == "2026-10-20T10:00:00+00:00"
    assert leases["10.0.0.53"]["state"] == "unknown" and leases["10.0.0.53"]["hostname"] is None
    # Fecha regional ambigua: no se adivina.
    assert leases["10.0.0.54"]["ends_at"] is None and leases["10.0.0.54"]["state"] == "released"
    assert (result.lines, result.parsed, result.skipped) == (6, 5, 1)


def test_windows_recommended_export_with_iso_utc() -> None:
    # La exportación de docs/sensor-upgrade-0.6.md: columnas mínimas, sin #TYPE y la hora
    # con ToUniversalTime().ToString('o') (7 decimales y 'Z').
    text = (
        '"IPAddress","ClientId","HostName","AddressState","LeaseExpiryTime"\n'
        '"10.0.0.60","00-15-5d-0a-0b-0c","lab-pc.corp.example","Active",'
        '"2026-10-22T18:00:00.0000000Z"\n'
    )
    (lease,) = parse_windows_dhcp_csv(text, NOW).leases
    assert lease.ends_at == datetime(2026, 10, 22, 18, 0, tzinfo=UTC)
    assert lease.state == "active" and lease.mac == "00:15:5d:0a:0b:0c"


def test_windows_inactive_states_never_name_an_asset() -> None:
    # Mismo criterio que el parser del servidor: reserva sin cliente = released.
    text = (
        '"IPAddress","ClientId","HostName","AddressState","LeaseExpiryTime"\n'
        '"10.0.0.61","00-15-5d-0a-0b-0d","old-pc.corp.example","InactiveReservation",""\n'
        '"10.0.0.62","00-15-5d-0a-0b-0e","gone.corp.example","Inactive",""\n'
    )
    states = {lease.ip: lease.state for lease in parse_windows_dhcp_csv(text, NOW).leases}
    assert states == {"10.0.0.61": "released", "10.0.0.62": "released"}


def test_windows_utf16_export_is_read() -> None:
    raw = (FIXTURES / "windows-dhcp.csv").read_text(encoding="utf-8").encode("utf-16")
    result = parse_leases("windows_dhcp_csv", decode_text(raw), NOW)
    assert result.parsed == 5


def test_generic_fixture() -> None:
    result = parse_generic_csv(fixture_text("generic.csv"), NOW)
    leases = by_ip(result)
    assert set(leases) == {"192.168.1.10", "192.168.1.11", "192.168.1.12"}
    assert leases["192.168.1.10"]["mac"] == "aa:bb:cc:dd:ee:10"
    assert leases["192.168.1.10"]["ends_at"] is None
    assert leases["192.168.1.10"]["state"] == "active"
    assert leases["192.168.1.11"]["ends_at"] == "2026-10-23T00:00:00+00:00"
    assert leases["192.168.1.12"]["state"] == "expired"
    assert leases["192.168.1.12"]["hostname"] is None
    assert (result.lines, result.parsed, result.skipped) == (5, 3, 2)


def test_generic_csv_sanitizes_hostnames_and_survives_bad_quotes() -> None:
    text = (
        "IP, MAC ,Hostname\n"
        '10.0.0.1,aa:bb:cc:dd:ee:01,"cam\x1b[2Jera"\n'
        '10.0.0.2,aa:bb:cc:dd:ee:02,"unterminated\n'
        "10.0.0.3,aa:bb:cc:dd:ee:03\n"
    )
    result = parse_generic_csv(text, NOW)
    assert [lease.hostname for lease in result.leases] == ["cam[2Jera"]
    assert result.skipped == 2


@pytest.mark.parametrize(
    ("fmt", "fixture"),
    [
        ("dnsmasq", "generic.csv"),
        ("kea_csv", "windows-dhcp.csv"),
        ("windows_dhcp_csv", "kea-leases4.csv"),
        ("generic_csv", "dnsmasq.leases"),
    ],
)
def test_wrong_format_is_reported_invalid(fmt: str, fixture: str) -> None:
    with pytest.raises(DhcpFormatError):
        parse_leases(fmt, fixture_text(fixture), NOW)


@pytest.mark.parametrize("fmt", ["dnsmasq", "isc_dhcpd"])
def test_empty_lease_file_is_valid(fmt: str) -> None:
    assert parse_leases(fmt, "", NOW).parsed == 0


def test_line_and_lease_caps_truncate(monkeypatch: pytest.MonkeyPatch) -> None:
    from sentra_sensor import dhcp

    monkeypatch.setattr(dhcp, "MAX_LINES", 5)
    lines = [f"0 aa:bb:cc:dd:ee:{i:02x} 10.0.0.{i + 1} host{i} *" for i in range(8)]
    result = parse_dnsmasq("\n".join(lines), NOW)
    assert result.truncated and result.parsed == 5
    monkeypatch.setattr(dhcp, "MAX_LINES", 100)
    monkeypatch.setattr(dhcp, "MAX_LEASES", 3)
    result = parse_dnsmasq("\n".join(lines), NOW)
    assert result.truncated and result.parsed == 3


def test_very_long_line_is_skipped() -> None:
    text = f"0 aa:bb:cc:dd:ee:01 10.0.0.1 {'x' * 9000} *\n0 aa:bb:cc:dd:ee:02 10.0.0.2 ok *\n"
    result = parse_dnsmasq(text, NOW)
    assert result.parsed == 1 and result.skipped == 1


# --- lectura del fichero ------------------------------------------------------------------


def test_read_lease_file_errors(tmp_path: Path) -> None:
    with pytest.raises(DhcpReadError) as info:
        read_lease_file(tmp_path / "missing.leases", 1024)
    assert info.value.code == "dhcp_file_missing"
    with pytest.raises(DhcpReadError) as info:
        read_lease_file(tmp_path, 1024)  # un directorio
    assert info.value.code == "dhcp_file_unreadable"
    big = tmp_path / "big.leases"
    big.write_bytes(b"x" * 2048)
    with pytest.raises(DhcpReadError) as info:
        read_lease_file(big, 1024)
    assert info.value.code == "dhcp_file_too_large"
    ok = tmp_path / "ok.leases"
    ok.write_bytes(b"0 aa:bb:cc:dd:ee:01 10.0.0.1 a *\n")
    data, mtime = read_lease_file(ok, 1024)
    assert data.startswith(b"0 aa") and mtime is not None and mtime.tzinfo is not None


def test_read_lease_file_refuses_fifo_and_unreadable(tmp_path: Path) -> None:
    # skip dentro del test (no con skipif) para que mypy --platform win32 estreche el tipo.
    if sys.platform == "win32":
        pytest.skip("FIFO y modos POSIX: solo fuera de Windows")
    fifo = tmp_path / "leases.fifo"
    os.mkfifo(fifo)
    # Sin O_NONBLOCK este open se quedaría esperando a un escritor.
    with pytest.raises(DhcpReadError) as info:
        read_lease_file(fifo, 1024)
    assert info.value.code == "dhcp_file_unreadable"
    if os.geteuid() == 0:
        return  # root lee aunque el modo sea 000
    locked = tmp_path / "locked.leases"
    locked.write_text("x")
    locked.chmod(0)
    with pytest.raises(DhcpReadError) as info:
        read_lease_file(locked, 1024)
    assert info.value.code == "dhcp_file_unreadable"


# --- configuración ------------------------------------------------------------------------


def write_config(tmp_path: Path, body: str) -> Path:
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    path = tmp_path / "sensor.toml"
    path.write_text(
        f'[sensor]\nserver_url = "https://sentra.example.com"\ndata_dir = {toml_string(data_dir)}\n'
        + body,
        encoding="utf-8",
    )
    return path


def test_config_loads_dhcp_sources(tmp_path: Path) -> None:
    leases = tmp_path / "dnsmasq.leases"
    path = write_config(
        tmp_path,
        "dhcp_max_file_kb = 512\n\n"
        f'[[dhcp_lease_files]]\nname = "lan-dnsmasq"\npath = {toml_string(leases)}\n'
        'format = "dnsmasq"\n\n'
        f'[[dhcp_lease_files]]\nname = "kea_main"\npath = {toml_string(leases)}\n'
        'format = "kea_csv"\n',
    )
    config = load_config(path)
    assert config.dhcp_max_file_kb == 512
    assert [s.name for s in config.dhcp_lease_files] == ["lan-dnsmasq", "kea_main"]
    source = config.dhcp_source("kea_main")
    assert source is not None and source.path == leases and source.format == "kea_csv"
    assert config.dhcp_source("other") is None


def test_config_defaults_and_nested_table(tmp_path: Path) -> None:
    assert LocalConfig().dhcp_max_file_kb == 4096
    assert LocalConfig().dhcp_lease_files == ()
    leases = tmp_path / "x.csv"
    path = write_config(
        tmp_path,
        f'[[sensor.dhcp_lease_files]]\nname = "x"\npath = {toml_string(leases)}\n'
        'format = "generic_csv"\n',
    )
    assert load_config(path).dhcp_lease_files[0].name == "x"


@pytest.mark.parametrize(
    ("entry", "message"),
    [
        ('name = "Bad Name"\npath = {path}\nformat = "dnsmasq"', "name must match"),
        ('name = "{long}"\npath = {path}\nformat = "dnsmasq"', "name must match"),
        ('name = "a"\npath = "leases/dnsmasq.leases"\nformat = "dnsmasq"', "absolute"),
        ('name = "a"\npath = ""\nformat = "dnsmasq"', "non-empty"),
        ('name = "a"\npath = {path}\nformat = "openwrt"', "format must be one of"),
        ('name = "a"\npath = {path}', "missing keys"),
        ('name = "a"\npath = {path}\nformat = "dnsmasq"\nurl = "x"', "unknown keys"),
        ('name = 1\npath = {path}\nformat = "dnsmasq"', "name must match"),
    ],
)
def test_config_rejects_invalid_dhcp_entries(tmp_path: Path, entry: str, message: str) -> None:
    body = entry.replace("{path}", toml_string(tmp_path / "f")).replace("{long}", "a" * 65)
    path = write_config(tmp_path, f"[[dhcp_lease_files]]\n{body}\n")
    with pytest.raises(ConfigError, match=message):
        load_config(path)


def test_config_rejects_duplicates_and_bad_limits(tmp_path: Path) -> None:
    entry = f'[[dhcp_lease_files]]\nname = "a"\npath = {toml_string(tmp_path / "f")}\n'
    path = write_config(tmp_path, f'{entry}format = "dnsmasq"\n{entry}format = "kea_csv"\n')
    with pytest.raises(ConfigError, match="duplicated"):
        load_config(path)
    for value in ("0", "65537", '"4096"', "true"):
        path = write_config(tmp_path, f"dhcp_max_file_kb = {value}\n")
        with pytest.raises(ConfigError):
            load_config(path)
    path = write_config(tmp_path, 'dhcp_lease_files = "nope"\n')
    with pytest.raises(ConfigError, match="array of tables"):
        load_config(path)
    both = (
        f'[[sensor.dhcp_lease_files]]\nname = "a"\npath = {toml_string(tmp_path / "f")}\n'
        'format = "dnsmasq"\n'
        f'[[dhcp_lease_files]]\nname = "b"\npath = {toml_string(tmp_path / "f")}\n'
        'format = "dnsmasq"\n'
    )
    with pytest.raises(ConfigError, match="both"):
        load_config(write_config(tmp_path, both))


def test_example_config_documents_dhcp_sources() -> None:
    example = (Path(__file__).resolve().parents[1] / "sensor.example.toml").read_text("utf-8")
    assert "[[dhcp_lease_files]]" in example and "dhcp_max_file_kb" in example


# --- validación del job -------------------------------------------------------------------


def dhcp_job(**parameters: Any) -> dict[str, Any]:
    params: dict[str, Any] = {"source_name": "lan"}
    params.update(parameters)
    job = make_job(job_type="dhcp_leases")
    job["parameters"] = params
    return job


def validate(job: dict[str, Any]) -> Any:
    return validate_job(
        job,
        sensor_id=SENSOR_ID,
        site_id=SITE_ID,
        config=ServerConfig.parse(server_config()),
        now=datetime.now(UTC),
    )


def test_capability_and_version() -> None:
    assert __version__ == "0.6.0"
    assert "dhcp.leases.file" in CAPABILITIES


def test_valid_dhcp_job() -> None:
    job = validate(dhcp_job())
    assert job.job_type == "dhcp_leases"
    assert job.parameters == DhcpParameters(source_name="lan")


@pytest.mark.parametrize(
    "parameters",
    [
        {"source_name": "lan", "path": "/etc/shadow"},
        {"source_name": "lan", "format": "dnsmasq"},
        {"source_name": ""},
        {"source_name": "a" * 65},
        {"source_name": 5},
        {"source_name": None},
    ],
)
def test_invalid_dhcp_job_parameters(parameters: dict[str, Any]) -> None:
    job = dhcp_job()
    job["parameters"] = parameters
    with pytest.raises(JobRejectedError) as info:
        validate(job)
    assert info.value.code == "invalid_schema"


def test_dhcp_job_without_parameters_is_rejected() -> None:
    job = dhcp_job()
    job["parameters"] = {}
    with pytest.raises(JobRejectedError):
        validate(job)


# --- collector ----------------------------------------------------------------------------


def config_with(tmp_path: Path, path: Path, fmt: str, max_kb: int = 4096) -> LocalConfig:
    data_dir = tmp_path / "data"
    data_dir.mkdir(exist_ok=True)
    toml = write_config(
        tmp_path,
        f"dhcp_max_file_kb = {max_kb}\n"
        f'[[dhcp_lease_files]]\nname = "lan"\npath = {toml_string(path)}\nformat = "{fmt}"\n',
    )
    return load_config(toml)


def run_collector(
    config: LocalConfig,
    name: str = "lan",
    on_emit: Callable[[DhcpCollector], None] | None = None,
) -> tuple[Any, list[list[dict[str, Any]]]]:
    batches: list[list[dict[str, Any]]] = []
    holder: list[DhcpCollector] = []

    def emit(items: list[dict[str, Any]]) -> None:
        batches.append(items)
        if on_emit is not None:
            on_emit(holder[0])

    collector = DhcpCollector(name, config, emit, clock=lambda: NOW_EPOCH)
    holder.append(collector)
    return collector.run(), batches


def test_collector_completes_with_contract_summary(tmp_path: Path) -> None:
    config = config_with(tmp_path, FIXTURES / "dnsmasq.leases", "dnsmasq")
    report, batches = run_collector(config)
    assert report.outcome == "completed" and report.errors == [] and report.leases == 3
    assert set(report.summary) == {
        "format",
        "lines",
        "parsed",
        "skipped",
        "truncated",
        "file_mtime",
        "error_code",
    }
    assert report.summary["format"] == "dnsmasq"
    assert (report.summary["lines"], report.summary["parsed"], report.summary["skipped"]) == (
        7,
        3,
        4,
    )
    assert report.summary["error_code"] is None and report.summary["file_mtime"] is not None
    assert [len(b) for b in batches] == [3]
    assert set(batches[0][0]) == {
        "ip",
        "mac",
        "hostname",
        "client_id",
        "starts_at",
        "ends_at",
        "state",
    }


@pytest.mark.parametrize(
    ("setup", "code"),
    [
        ("unknown", "dhcp_source_unknown"),
        ("missing", "dhcp_file_missing"),
        ("directory", "dhcp_file_unreadable"),
        ("large", "dhcp_file_too_large"),
        ("invalid", "dhcp_format_invalid"),
    ],
)
def test_collector_error_codes(tmp_path: Path, setup: str, code: str) -> None:
    target = tmp_path / "leases.txt"
    if setup == "directory":
        target.mkdir()
    elif setup == "large":
        target.write_bytes(b"0 aa:bb:cc:dd:ee:01 10.0.0.1 a *\n" * 64)  # > 1 KiB
    elif setup == "invalid":
        target.write_text("this is not\na dnsmasq file\n")
    config = config_with(tmp_path, target, "dnsmasq", max_kb=1)
    report, batches = run_collector(config, "nope" if setup == "unknown" else "lan")
    assert report.outcome == "failed"
    assert report.errors == [code] and report.summary["error_code"] == code
    assert report.summary["format"] == (None if setup == "unknown" else "dnsmasq")
    assert batches == []


def test_collector_splits_batches_of_5000(tmp_path: Path) -> None:
    leases = tmp_path / "big.csv"
    rows = ["ip,mac,hostname"] + [
        f"10.{i >> 16}.{(i >> 8) & 0xFF}.{i & 0xFF},02:00:00:{i >> 16:02x}:"
        f"{(i >> 8) & 0xFF:02x}:{i & 0xFF:02x},h{i}"
        for i in range(1, 12_001)
    ]
    leases.write_text("\n".join(rows) + "\n")
    config = config_with(tmp_path, leases, "generic_csv")
    report, batches = run_collector(config)
    assert report.outcome == "completed"
    assert all(len(b) <= MAX_LEASES_PER_BATCH for b in batches)
    assert sum(len(b) for b in batches) == report.leases == report.summary["parsed"] == 12_000
    assert [len(b) for b in batches] == [5000, 5000, 2000]


def test_collector_cancel_between_batches(tmp_path: Path) -> None:
    leases = tmp_path / "big.csv"
    rows = ["ip,mac,hostname"] + [
        f"10.1.{i // 256}.{i % 256},02:00:00:00:{i >> 8:02x}:{i & 0xFF:02x},h{i}"
        for i in range(1, 6000)
    ]
    leases.write_text("\n".join(rows) + "\n")
    config = config_with(tmp_path, leases, "generic_csv")
    report, batches = run_collector(config, on_emit=lambda c: c.request_cancel())
    assert report.outcome == "cancelled"
    assert len(batches) == 1 and report.leases == MAX_LEASES_PER_BATCH


def test_collector_cancelled_before_reading(tmp_path: Path) -> None:
    config = config_with(tmp_path, FIXTURES / "dnsmasq.leases", "dnsmasq")
    collector = DhcpCollector("lan", config, lambda _items: None)
    collector.request_cancel()
    assert collector.run().outcome == "cancelled"


# --- runner extremo a extremo --------------------------------------------------------------


def runner_config(tmp_path: Path, config: LocalConfig, leases: Path, fmt: str) -> LocalConfig:
    return load_config(
        write_config(
            tmp_path,
            f'[[dhcp_lease_files]]\nname = "lan"\npath = {toml_string(leases)}\nformat = "{fmt}"\n',
        ),
        {"data_dir": config.data_dir, "server_url": config.server_url},
    )


def test_runner_executes_dhcp_job(
    tmp_path: Path, config: LocalConfig, server: FakeServer, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("DEBUG")
    leases = FIXTURES / "kea-leases4.csv"
    local = runner_config(tmp_path, config, leases, "kea_csv")
    job = dhcp_job()
    server.jobs.append(job)
    runner = make_runner(local, server)
    runner.tick()
    job_id = job["job_id"]
    assert server.started == [job_id]
    sent = server.leases_for(job_id)
    assert {lease["ip"] for lease in sent} == {
        "192.168.50.20",
        "192.168.50.21",
        "192.168.50.23",
        "192.168.50.24",
    }
    complete = server.completes[job_id]
    assert complete["outcome"] == "completed" and complete["batches_sent"] == 1
    assert complete["dhcp"]["format"] == "kea_csv"
    assert complete["dhcp"]["parsed"] == 4 and complete["dhcp"]["error_code"] is None
    assert "observations" not in complete and "snmp" not in complete
    # El contenido ni la ruta del fichero llegan a los logs.
    assert str(leases) not in caplog.text and "tablet-01" not in caplog.text
    assert runner.state.last_successful_job_at is not None


def test_runner_respects_server_batch_limit(
    tmp_path: Path, config: LocalConfig, server: FakeServer
) -> None:
    server.config = server_config(max_observations_per_batch=2)
    local = runner_config(tmp_path, config, FIXTURES / "kea-leases4.csv", "kea_csv")
    job = dhcp_job()
    server.jobs.append(job)
    runner = make_runner(local, server)
    runner.tick()
    assert len(server.leases_for(job["job_id"])) == 4
    assert server.completes[job["job_id"]]["batches_sent"] == 2


def test_runner_reports_unknown_source(
    tmp_path: Path, config: LocalConfig, server: FakeServer
) -> None:
    job = dhcp_job(source_name="router-lan")
    server.jobs.append(job)
    runner = make_runner(config, server)
    runner.tick()
    complete = server.completes[job["job_id"]]
    assert server.started == [job["job_id"]]
    assert complete["outcome"] == "failed" and complete["errors"] == ["dhcp_source_unknown"]
    assert complete["dhcp"]["error_code"] == "dhcp_source_unknown"
    assert server.leases_for(job["job_id"]) == []


def test_runner_rejects_dhcp_job_with_path_before_start(
    config: LocalConfig, server: FakeServer
) -> None:
    job = dhcp_job(path="/etc/shadow")
    server.jobs.append(job)
    runner = make_runner(config, server)
    runner.tick()
    assert server.started == []
    assert server.completes[job["job_id"]]["errors"] == ["job_rejected:invalid_schema"]


def test_runner_threaded_dhcp_job_finishes(
    tmp_path: Path, config: LocalConfig, server: FakeServer
) -> None:
    local = runner_config(tmp_path, config, FIXTURES / "dnsmasq.leases", "dnsmasq")
    job = dhcp_job()
    server.jobs.append(job)
    runner = make_runner(local, server, threaded=True)
    runner.tick()
    active = runner.active
    if active is not None:
        # Espera determinista al hilo del job (sin sleeps), y luego se recoge.
        assert active.done.wait(timeout=30)
    runner.tick()
    assert server.completes[job["job_id"]]["outcome"] == "completed"


# --- status y diagnostics ------------------------------------------------------------------


def test_status_and_diagnostics_show_sources_without_content(
    tmp_path: Path, config: LocalConfig, server: FakeServer
) -> None:
    present = tmp_path / "dnsmasq.leases"
    present.write_text("0 aa:bb:cc:dd:ee:01 10.0.0.1 secret-host *\n")
    missing = tmp_path / "gone.csv"
    local = load_config(
        write_config(
            tmp_path,
            f'[[dhcp_lease_files]]\nname = "lan"\npath = {toml_string(present)}\n'
            'format = "dnsmasq"\n'
            f'[[dhcp_lease_files]]\nname = "old"\npath = {toml_string(missing)}\n'
            'format = "generic_csv"\n',
        ),
        {"data_dir": config.data_dir, "server_url": config.server_url},
    )
    described = describe_sources(local)
    assert described[0]["exists"] and described[0]["readable"]
    assert described[0]["size_bytes"] == present.stat().st_size
    assert not described[1]["exists"] and described[1]["size_bytes"] is None
    status = local_status(local)
    assert [s["name"] for s in status["dhcp_sources"]] == ["lan", "old"]
    checks = {c.name: c for c in run_diagnostics(local, server)}
    assert checks["dhcp_source:lan"].ok
    assert not checks["dhcp_source:old"].ok and "missing" in checks["dhcp_source:old"].detail
    dumped = json.dumps(status) + json.dumps([c.__dict__ for c in checks.values()])
    assert "secret-host" not in dumped


def test_diagnostics_flags_too_large_source(tmp_path: Path, config: LocalConfig) -> None:
    big = tmp_path / "big.leases"
    big.write_bytes(b"x" * 4096)
    local = load_config(
        write_config(
            tmp_path,
            "dhcp_max_file_kb = 1\n"
            f'[[dhcp_lease_files]]\nname = "lan"\npath = {toml_string(big)}\n'
            'format = "dnsmasq"\n',
        ),
        {"data_dir": config.data_dir},
    )
    (entry,) = describe_sources(local)
    assert entry["too_large"] and entry["readable"]
