"""Agentless adapters are contracts only: unavailable, read-only, secret-safe."""

import pytest

from app.agentless.adapters import ADAPTERS
from app.agentless.base import (
    AdapterUnavailableError,
    Capability,
    CredentialKind,
    CredentialRef,
    NoSecretProvider,
    RemoteTarget,
    Secret,
)


def test_no_adapter_collects_yet() -> None:
    target = RemoteTarget("192.168.1.20", CredentialRef("cred-1", CredentialKind.WINDOWS_ACCOUNT))
    for adapter in ADAPTERS:
        usable, reason = adapter.available()
        assert not usable and reason
        for capability in adapter.capabilities:
            with pytest.raises(AdapterUnavailableError):
                adapter.collect(target, capability, NoSecretProvider())


def test_contracts_are_read_only() -> None:
    names = {a.name for a in ADAPTERS}
    assert names == {"winrm", "wmi", "remote_eventlog", "ssh", "snmp"}
    assert {c.value for c in Capability} == {
        "inventory",
        "services",
        "events",
        "metrics",
        "interfaces",
        "device_info",
    }  # no write/execute capability exists
    for adapter in ADAPTERS:
        assert adapter.planned_operations, adapter.name
        text = " ".join(adapter.planned_operations).lower()
        for forbidden in ("set-", "enable-", "start-service", "stop-service", "netsh", "sudo "):
            assert forbidden not in text, (adapter.name, forbidden)


def test_secrets_never_leak_through_repr() -> None:
    secret = Secret("hunter2")
    ref = CredentialRef("cred-1", CredentialKind.SSH_KEY, {"user": "monitor"})

    assert "hunter2" not in repr(secret) and "hunter2" not in str(secret)
    assert "hunter2" not in f"{secret}" and secret.reveal() == "hunter2"
    assert "monitor" not in repr(ref)
    with pytest.raises(AdapterUnavailableError):
        NoSecretProvider().resolve(ref)
