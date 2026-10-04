"""Conservative device-type inference.

Only from evidence Sentra actually has, and always with the reason, so the operator can
judge it. When nothing is conclusive the type stays unknown (None): an SSH port alone says
nothing (Linux server, NAS, switch, firewall…), so it is not guessed.
"""

from collections.abc import Iterable

WINDOWS = "windows"
LINUX = "linux"
PRINTER = "printer"
NETWORK_DEVICE = "network_device"
DEVICE_TYPES = (WINDOWS, LINUX, PRINTER, NETWORK_DEVICE)

_PRINTER_PORTS = {9100: "jetdirect 9100", 515: "lpd 515"}
_WINDOWS_PORTS = {135: "msrpc 135", 3389: "rdp 3389", 5985: "winrm 5985", 5986: "winrm 5986"}


def classify(
    open_ports: Iterable[int], *, is_gateway: bool = False, agent_os: str | None = None
) -> tuple[str | None, str | None]:
    """(device_type, reason), or (None, None) when it cannot be told reasonably."""
    if agent_os:
        os_lower = agent_os.lower()
        if "windows" in os_lower:
            return WINDOWS, f"reported by the Sentra agent ({agent_os})"
        if "linux" in os_lower:
            return LINUX, f"reported by the Sentra agent ({agent_os})"
    if is_gateway:
        return NETWORK_DEVICE, "default gateway of the Sentra server"
    ports = set(open_ports)
    printer = [label for port, label in _PRINTER_PORTS.items() if port in ports]
    if printer:
        return PRINTER, "printing port open: " + ", ".join(printer)
    windows = [label for port, label in _WINDOWS_PORTS.items() if port in ports]
    if windows:
        return WINDOWS, "Windows service ports open: " + ", ".join(windows)
    return None, None
