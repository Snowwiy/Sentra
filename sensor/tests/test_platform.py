"""Abstracciones Linux/Windows: rutas por defecto, argv de ping, tablas ARP, servicio."""

import threading
from pathlib import Path

import pytest

from sentra_sensor.config import default_config_path, default_data_dir
from sentra_sensor.scanner import parse_arp_a, parse_proc_net_arp, ping_argv
from sentra_sensor.state import platform_name
from sentra_sensor.winservice import (
    SERVICE_RUNNING,
    SERVICE_STOPPED,
    NotRunningAsServiceError,
    ServiceStatus,
    StatusReporter,
    dispatch,
    run_service_body,
)


def test_default_paths_windows() -> None:
    env = {"PROGRAMDATA": "C:\\ProgramData"}
    assert default_data_dir("win32", env) == Path("C:\\ProgramData") / "Sentra" / "Sensor"
    assert default_config_path("win32", env).name == "sensor.toml"


def test_default_paths_linux_service_and_user() -> None:
    assert default_data_dir("linux", {"SENTRA_SENSOR_SERVICE": "1"}) == Path(
        "/var/lib/sentra-sensor"
    )
    assert default_config_path("linux", {}) == Path("/etc/sentra-sensor/sensor.toml")
    user = default_data_dir("linux", {"XDG_STATE_HOME": "/home/u/.state"})
    assert user in (Path("/home/u/.state/sentra-sensor"), Path("/var/lib/sentra-sensor"))


def test_platform_names() -> None:
    assert platform_name("win32") == "windows"
    assert platform_name("linux") == "linux"


def test_ping_argv_is_fixed_and_validated() -> None:
    assert ping_argv("/usr/bin/ping", "10.0.0.1", 1.0, "linux") == [
        "/usr/bin/ping",
        "-n",
        "-q",
        "-c",
        "1",
        "-W",
        "1",
        "10.0.0.1",
    ]
    assert ping_argv("C:\\ping.exe", "10.0.0.1", 0.5, "win32") == [
        "C:\\ping.exe",
        "-n",
        "1",
        "-w",
        "500",
        "10.0.0.1",
    ]
    assert ping_argv("/usr/bin/ping", "fe80::1", 1.0, "linux")[-2:] == ["-6", "fe80::1"]
    for hostile in ["-f", "10.0.0.1; rm -rf /", "$(id)", "10.0.0.1 -c 100000"]:
        with pytest.raises(ValueError):
            ping_argv("/usr/bin/ping", hostile, 1.0, "linux")


def test_parse_proc_net_arp() -> None:
    lines = [
        "IP address       HW type     Flags       HW address            Mask     Device",
        "10.0.0.1         0x1         0x2         AA:BB:CC:DD:EE:01     *        eth0",
        "10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        eth0",
        "garbage",
    ]
    assert parse_proc_net_arp(lines) == {"10.0.0.1": "aa:bb:cc:dd:ee:01"}


def test_parse_windows_arp_a() -> None:
    lines = [
        "Interface: 10.0.0.5 --- 0x4",
        "  Internet Address      Physical Address      Type",
        "  10.0.0.1              aa-bb-cc-dd-ee-02     dynamic",
        "  10.0.0.255            ff-ff-ff-ff-ff-ff     static",
    ]
    assert parse_arp_a(lines) == {"10.0.0.1": "aa:bb:cc:dd:ee:02"}


def test_service_status_flow_without_windows() -> None:
    statuses: list[ServiceStatus] = []
    reporter = StatusReporter(statuses.append, threading.Event())
    seen: list[int] = []

    def body(stop: threading.Event) -> None:
        seen.append(reporter.state)

    assert run_service_body(reporter, body) == 0
    assert seen == [SERVICE_RUNNING]
    assert statuses[-1].state == SERVICE_STOPPED


@pytest.mark.skipif(__import__("sys").platform == "win32", reason="non-Windows")
def test_dispatch_outside_windows_raises() -> None:
    with pytest.raises(NotRunningAsServiceError):
        dispatch(lambda _e: None)
