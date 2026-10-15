"""Validación estricta de jobs y de CIDR antes de ejecutar nada."""

import ipaddress
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from sentra_sensor.jobs import (
    JobRejectedError,
    host_count,
    parse_target,
    target_allowed,
    validate_job,
)
from sentra_sensor.protocol import ProtocolError, ServerConfig
from tests.conftest import OTHER_ID, SENSOR_ID, SITE_ID, make_job, server_config

NOW = datetime.now(UTC)
CONFIG = ServerConfig.parse(server_config())


def validate(job: dict[str, Any], config: ServerConfig = CONFIG) -> Any:
    return validate_job(job, sensor_id=SENSOR_ID, site_id=SITE_ID, config=config, now=NOW)


def rejected(job: dict[str, Any], config: ServerConfig = CONFIG) -> JobRejectedError:
    with pytest.raises(JobRejectedError) as info:
        validate(job, config)
    return info.value


def test_valid_job() -> None:
    job = validate(make_job(NOW))
    assert str(job.parameters.target) == "10.0.0.0/29"
    assert job.parameters.ports == (22, 80, 443)


def test_unknown_type() -> None:
    error = rejected(make_job(NOW, job_type="shell_command"))
    assert error.code == "unknown_job_type"
    assert error.job_id is not None and error.attempt == 1  # se puede informar el rechazo


@pytest.mark.parametrize(
    "mutation",
    [
        {"command": "id"},  # clave extra en el job
        {"parameters": {"script": "x"}},  # clave extra en parameters
        {"attempt": "1"},
        {"parameters": {"ports": "22"}},
        {"parameters": {"icmp": "yes"}},
        {"parameters": {"timeout_ms": 999_999}},
        {"parameters": {"concurrency": 0}},
        {"parameters": {"max_probes_per_second": 1_000_000}},
        {"parameters": {"deadline_seconds": 0}},
        {"expires_at": "tomorrow"},
        {"expires_at": "2030-01-01T00:00:00"},  # sin zona horaria
        {"idempotency_key": ""},
    ],
)
def test_invalid_schema(mutation: dict[str, Any]) -> None:
    error = rejected(make_job(NOW, **mutation))
    assert error.code == "invalid_schema"


def test_missing_key() -> None:
    job = make_job(NOW)
    del job["idempotency_key"]
    assert rejected(job).code == "invalid_schema"


def test_other_sensor_and_other_site() -> None:
    assert rejected(make_job(NOW, sensor_id=OTHER_ID)).code == "wrong_sensor"
    assert rejected(make_job(NOW, site_id=OTHER_ID)).code == "wrong_site"


def test_expired() -> None:
    job = make_job(NOW, expires_at=(NOW - timedelta(seconds=1)).isoformat())
    assert rejected(job).code == "expired"


@pytest.mark.parametrize("target", ["8.8.8.0/24", "10.0.1.0/24", "10.0.0.0/23", "fd00::/64"])
def test_target_outside_allowed_networks(target: str) -> None:
    error = rejected(make_job(NOW, parameters={"target": target}))
    assert error.code == "target_out_of_scope"


@pytest.mark.parametrize("target", ["0.0.0.0/0", "::/0", "10.0.0.1/24", "nonsense", "224.0.0.0/24"])
def test_invalid_targets(target: str) -> None:
    assert rejected(make_job(NOW, parameters={"target": target})).code == "target_invalid"


def test_slash_zero_even_if_server_allowed_it() -> None:
    with pytest.raises(ProtocolError):
        ServerConfig.parse(server_config(allowed_networks=["0.0.0.0/0"]))


def test_target_too_large() -> None:
    config = ServerConfig.parse(server_config(max_hosts_per_job=100))
    error = rejected(make_job(NOW, parameters={"target": "10.0.0.0/24"}), config)
    assert error.code == "target_too_large"


@pytest.mark.parametrize("ports", [[0], [65536], [22, 22], [-1], [True]])
def test_bad_ports(ports: list[Any]) -> None:
    assert rejected(make_job(NOW, parameters={"ports": ports})).code in (
        "ports_invalid",
        "invalid_schema",
    )


def test_too_many_ports() -> None:
    error = rejected(make_job(NOW, parameters={"ports": list(range(1, 40))}))
    assert error.code == "ports_invalid"


def test_no_probe_method() -> None:
    job = make_job(NOW, parameters={"ports": [], "icmp": False, "arp": False})
    assert rejected(job).code == "invalid_schema"


def test_cidr_helpers() -> None:
    assert host_count(ipaddress.ip_network("10.0.0.0/24")) == 254
    assert host_count(ipaddress.ip_network("10.0.0.0/31")) == 2
    assert host_count(ipaddress.ip_network("10.0.0.5/32")) == 1
    assert host_count(ipaddress.ip_network("fd00::/120")) == 255
    for cidr in ["10.0.0.0/24", "10.0.0.0/31", "10.0.0.5/32", "fd00::/124"]:
        net = ipaddress.ip_network(cidr)
        assert host_count(net) == len(list(net.hosts()))
    assert str(parse_target("10.0.0.7")) == "10.0.0.7/32"
    allowed = (ipaddress.ip_network("10.0.0.0/24"),)
    assert target_allowed(ipaddress.ip_network("10.0.0.128/25"), allowed)
    assert not target_allowed(ipaddress.ip_network("10.0.0.0/16"), allowed)
    assert not target_allowed(ipaddress.ip_network("fd00::/64"), allowed)


def test_server_config_values_are_clamped() -> None:
    config = ServerConfig.parse(server_config(heartbeat_interval_seconds=0, max_concurrency=10**9))
    assert config.heartbeat_interval_seconds == 5
    assert config.max_concurrency == 4096
