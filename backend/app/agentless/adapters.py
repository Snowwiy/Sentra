"""Planned adapters. Each declares what it will read and how, and reports itself unavailable.

Implementing one means: add its (optional) dependency, implement `collect` with read-only
operations only, and keep `available()` honest. The planned operations are listed so a
reviewer can check they are all reads.
"""

from typing import Any

from app.agentless.base import (
    AdapterUnavailableError,
    Capability,
    CredentialKind,
    RemoteTarget,
    SecretProvider,
)


class _Planned:
    name = "planned"
    capabilities: frozenset[Capability] = frozenset()
    credential_kinds: frozenset[CredentialKind] = frozenset()
    # Human-readable list of the read-only operations the adapter will perform.
    planned_operations: tuple[str, ...] = ()

    def available(self) -> tuple[bool, str]:
        return False, "not implemented yet (contract only)"

    def collect(
        self, target: RemoteTarget, capability: Capability, secrets: SecretProvider
    ) -> dict[str, Any]:
        raise AdapterUnavailableError(f"{self.name}: {self.available()[1]}")


class WinRMAdapter(_Planned):
    """Windows Remote Management (WS-Man, 5985/5986). Uses WinRM where an administrator
    already enabled it; Sentra never enables it, nor changes TrustedHosts or the firewall."""

    name = "winrm"
    capabilities = frozenset({Capability.INVENTORY, Capability.SERVICES, Capability.METRICS})
    credential_kinds = frozenset({CredentialKind.WINDOWS_ACCOUNT})
    planned_operations = (
        "Get-CimInstance Win32_OperatingSystem / Win32_ComputerSystem (read)",
        "Get-Service (read)",
        "Get-LocalUser, Get-LocalGroupMember -SID S-1-5-32-544 (read)",
        "HKLM Uninstall registry keys (read)",
        "HTTPS (5986) preferred; HTTP 5985 only with message encryption (Kerberos/NTLM)",
    )


class WMIAdapter(_Planned):
    """WMI/CIM over DCOM (135 + dynamic RPC ports) for hosts without WinRM."""

    name = "wmi"
    capabilities = frozenset({Capability.INVENTORY, Capability.SERVICES, Capability.METRICS})
    credential_kinds = frozenset({CredentialKind.WINDOWS_ACCOUNT})
    planned_operations = (
        "SELECT * FROM Win32_OperatingSystem, Win32_Service, Win32_Product-free software list",
        "Win32_PerfFormattedData_PerfOS_Processor / Memory (read)",
    )


class RemoteEventLogAdapter(_Planned):
    """Remote Windows Event Log (EventLog-Remoting / wevtutil /r:). Needs 'Event Log
    Readers' membership for Security; never grants it."""

    name = "remote_eventlog"
    capabilities = frozenset({Capability.EVENTS})
    credential_kinds = frozenset({CredentialKind.WINDOWS_ACCOUNT})
    planned_operations = ("wevtutil qe <channel> /r:<host> with the agent's XPath filters (read)",)


class SSHAdapter(_Planned):
    """SSH for Linux/Unix hosts: fixed read-only commands, no sudo, no file writes."""

    name = "ssh"
    capabilities = frozenset(
        {Capability.INVENTORY, Capability.SERVICES, Capability.EVENTS, Capability.METRICS}
    )
    credential_kinds = frozenset({CredentialKind.SSH_KEY, CredentialKind.SSH_PASSWORD})
    planned_operations = (
        "cat /etc/os-release; uname -a; ip -j addr (read)",
        "systemctl list-units --type=service --all --no-pager --plain (read)",
        "journalctl -p warning -o json --since <cursor> (read)",
        "dpkg-query -W / rpm -qa (read)",
        "host key pinned on first use and verified afterwards (no blind accept)",
    )


class SNMPAdapter(_Planned):
    """SNMP for network devices (switches, routers, printers, APs, UPS, NAS). Discovery
    does not depend on it; it only enriches devices an operator opted in."""

    name = "snmp"
    capabilities = frozenset({Capability.DEVICE_INFO, Capability.INTERFACES})
    credential_kinds = frozenset({CredentialKind.SNMP_V3, CredentialKind.SNMP_V2C})
    planned_operations = (
        "GET sysDescr, sysName, sysObjectID, sysUpTime (SNMPv2-MIB)",
        "WALK ifTable/ifXTable (IF-MIB); Printer-MIB and UPS-MIB where present",
        "SNMPv3 authPriv preferred; never SET",
    )


ADAPTERS = (WinRMAdapter(), WMIAdapter(), RemoteEventLogAdapter(), SSHAdapter(), SNMPAdapter())
