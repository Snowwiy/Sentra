"""Interfaces shared by every agentless adapter (none is implemented yet)."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol


class Capability(StrEnum):
    """What a collector can read. Read-only by definition: there is no write capability."""

    INVENTORY = "inventory"  # OS, interfaces, software, accounts (agent inventory format)
    SERVICES = "services"
    EVENTS = "events"  # remote event log / journald
    METRICS = "metrics"  # CPU/RAM/disk counters
    INTERFACES = "interfaces"  # SNMP IF-MIB
    DEVICE_INFO = "device_info"  # SNMP sysDescr/sysName/sysObjectID


class CredentialKind(StrEnum):
    WINDOWS_ACCOUNT = "windows_account"  # WinRM / WMI / remote Event Log
    SSH_KEY = "ssh_key"
    SSH_PASSWORD = "ssh_password"  # noqa: S105  (a kind name, not a password; discouraged)
    SNMP_V2C = "snmp_v2c"
    SNMP_V3 = "snmp_v3"


@dataclass(frozen=True)
class CredentialRef:
    """An opaque reference to a secret held elsewhere. Never contains the secret."""

    ref_id: str
    kind: CredentialKind
    # Non-secret parameters (user name, SNMPv3 auth protocol...).
    params: Mapping[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"CredentialRef({self.ref_id!r}, {self.kind.value})"


class Secret:
    """A secret value that does not leak through repr/str/logging."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "Secret('***')"

    __str__ = __repr__


class SecretProvider(Protocol):
    """Resolves a CredentialRef at the moment of use (e.g. Windows Credential Manager/DPAPI,
    an OS keyring, HashiCorp Vault). Implementations must not cache secrets on disk."""

    def resolve(self, ref: CredentialRef) -> Secret: ...


class NoSecretProvider:
    """The only provider shipped: agentless collection stays disabled."""

    def resolve(self, ref: CredentialRef) -> Secret:
        raise AdapterUnavailableError("no secret provider configured")


@dataclass(frozen=True)
class RemoteTarget:
    address: str
    credential: CredentialRef | None = None
    port: int | None = None


class AdapterUnavailableError(RuntimeError):
    pass


class RemoteCollector(Protocol):
    """A read-only remote collector for one protocol."""

    name: str
    capabilities: frozenset[Capability]
    credential_kinds: frozenset[CredentialKind]

    def available(self) -> tuple[bool, str]:
        """(usable here?, reason), e.g. a missing library or "not implemented"."""
        ...

    def collect(
        self, target: RemoteTarget, capability: Capability, secrets: SecretProvider
    ) -> dict[str, Any]:
        """Read one capability from the target, in the agent's data format."""
        ...
