"""Individual, non-invasive observations of one address.

- TCP: a plain connect() that is closed as soon as it completes; no data is sent or read.
  An accepted connection means "open"; a refusal (RST) proves the host is up with the port
  closed; a timeout means filtered or no host.
- ICMP: the operating system's own `ping` (one echo request), run by absolute path without
  a shell. No raw sockets, so the server needs no elevated rights. If `ping` is missing the
  probe reports "unavailable" and discovery relies on TCP and the neighbour table.
- Neighbour (ARP) table: read from the OS, never written. MAC addresses are only known for
  hosts on the server's own L2 segment; behind a router they stay unknown (null).
- Reverse DNS: the system resolver, bounded by a timeout.

🪟 VALIDACIÓN LOCAL EN WINDOWS: `PING.EXE`/`ARP.EXE`/`ROUTE.EXE` parsing and the Windows
error codes below are tested with captured output only.
"""

import asyncio
import contextlib
import errno
import ipaddress
import os
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from enum import StrEnum
from pathlib import Path

from app.discovery.targets import IPAddress


class PortState(StrEnum):
    OPEN = "open"
    # Refused (RST): host up, nothing listening.
    CLOSED = "closed"
    # No answer within the timeout: firewall drop or no host.
    FILTERED = "filtered"
    # The network stack says the host/network is unreachable (no ARP reply, no route).
    UNREACHABLE = "unreachable"
    ERROR = "error"


_UNREACHABLE_ERRNOS = {errno.EHOSTUNREACH, errno.ENETUNREACH, getattr(errno, "EHOSTDOWN", -1)}
# WSAENETUNREACH, WSAEHOSTUNREACH, WSAEHOSTDOWN
_UNREACHABLE_WINERRORS = {10051, 10065, 10064}
_REFUSED_WINERRORS = {10061}


async def tcp_probe(address: IPAddress, port: int, timeout: float) -> PortState:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(str(address), port), timeout)
    except ConnectionRefusedError:
        return PortState.CLOSED
    except TimeoutError:
        return PortState.FILTERED
    except OSError as exc:
        winerror = getattr(exc, "winerror", None)
        if winerror in _REFUSED_WINERRORS:
            return PortState.CLOSED
        if exc.errno in _UNREACHABLE_ERRNOS or winerror in _UNREACHABLE_WINERRORS:
            return PortState.UNREACHABLE
        return PortState.ERROR
    writer.close()
    with contextlib.suppress(OSError, TimeoutError):
        await asyncio.wait_for(writer.wait_closed(), timeout)
    return PortState.OPEN


# --- ICMP ------------------------------------------------------------------------------------


def _system32(name: str) -> str:
    return str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / name)


def ping_executable() -> str | None:
    if sys.platform == "win32":
        path = _system32("PING.EXE")
        return path if Path(path).exists() else None
    for candidate in ("/usr/bin/ping", "/bin/ping", "/usr/sbin/ping", "/sbin/ping"):
        if Path(candidate).exists():
            return candidate
    return None


def ping_command(executable: str, address: IPAddress, timeout_ms: int) -> list[str]:
    if sys.platform == "win32":
        return [executable, "-n", "1", "-w", str(timeout_ms), str(address)]
    # iputils: -W is in whole seconds; -n: no reverse lookup by ping itself.
    seconds = max(1, -(-timeout_ms // 1000))
    return [executable, "-n", "-c", "1", "-W", str(seconds), str(address)]


def ping_succeeded(returncode: int, output: bytes) -> bool:
    if sys.platform == "win32":
        # PING.EXE exits 0 even for "Destination host unreachable" sent by a router. A real
        # echo reply always prints "TTL=" whatever the display language.
        return returncode == 0 and b"TTL=" in output.upper()
    return returncode == 0


async def ping(executable: str | None, address: IPAddress, timeout_ms: int) -> bool | None:
    """True/False for reply/no reply; None when ping cannot be used here."""
    if executable is None:
        return None
    try:
        process = await asyncio.create_subprocess_exec(
            *ping_command(executable, address, timeout_ms),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
            stdin=asyncio.subprocess.DEVNULL,
        )
    except OSError:
        return None
    try:
        output, _ = await asyncio.wait_for(process.communicate(), timeout_ms / 1000 + 2)
    except TimeoutError:
        process.kill()
        await process.wait()
        return False
    return ping_succeeded(process.returncode or 0, output)


# --- Neighbour table -------------------------------------------------------------------------

_MAC = re.compile(r"^[0-9a-f]{2}([:-])[0-9a-f]{2}(\1[0-9a-f]{2}){4}$")


def normalize_mac(value: str | None) -> str | None:
    """aa:bb:cc:dd:ee:ff, or None for anything that is not a usable unicast MAC."""
    if not value:
        return None
    text = value.strip().lower()
    if not _MAC.match(text):
        return None
    mac = text.replace("-", ":")
    first = int(mac[:2], 16)
    if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") or first & 1:  # multicast bit
        return None
    return mac


def parse_proc_arp(text: str) -> dict[str, str]:
    """Linux /proc/net/arp → {ip: mac}, complete entries only (flags 0x2)."""
    table: dict[str, str] = {}
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 4:
            continue
        ip, flags, mac = fields[0], fields[2], normalize_mac(fields[3])
        try:
            complete = int(flags, 16) & 0x2
        except ValueError:
            continue
        if complete and mac:
            table[ip] = mac
    return table


_ARP_LINE = re.compile(r"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\b")


def parse_windows_arp(text: str) -> dict[str, str]:
    """`arp -a` output (any display language: only IP and MAC columns are used)."""
    table: dict[str, str] = {}
    for line in text.splitlines():
        match = _ARP_LINE.match(line)
        if match:
            mac = normalize_mac(match.group(2))
            if mac:
                table[match.group(1)] = mac
    return table


def neighbour_table() -> dict[str, str]:
    """Current IPv4 neighbour table of this server; empty when it cannot be read."""
    try:
        if sys.platform == "win32":
            result = subprocess.run(  # noqa: S603  (fixed executable and arguments, no shell)
                [_system32("ARP.EXE"), "-a"], capture_output=True, timeout=15, check=False
            )
            return parse_windows_arp(result.stdout.decode("utf-8", "replace"))
        return parse_proc_arp(Path("/proc/net/arp").read_text(encoding="utf-8"))
    except (OSError, subprocess.SubprocessError):
        return {}


# --- Default gateways ------------------------------------------------------------------------


def parse_proc_route(text: str) -> set[str]:
    gateways = set()
    for line in text.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 3 and fields[1] == "00000000" and fields[2] != "00000000":
            try:
                raw = bytes.fromhex(fields[2])[::-1]  # little-endian
                gateways.add(str(ipaddress.IPv4Address(raw)))
            except ValueError:
                continue
    return gateways


_ROUTE_LINE = re.compile(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+(\d{1,3}(?:\.\d{1,3}){3})\s")


def parse_windows_route(text: str) -> set[str]:
    """`route print -4` default routes (on-link routes have no gateway address)."""
    return {m.group(1) for line in text.splitlines() if (m := _ROUTE_LINE.match(line))}


def default_gateways() -> set[str]:
    try:
        if sys.platform == "win32":
            result = subprocess.run(  # noqa: S603  (fixed executable and arguments, no shell)
                [_system32("ROUTE.EXE"), "print", "-4"],
                capture_output=True,
                timeout=15,
                check=False,
            )
            return parse_windows_route(result.stdout.decode("utf-8", "replace"))
        return parse_proc_route(Path("/proc/net/route").read_text(encoding="utf-8"))
    except (OSError, subprocess.SubprocessError):
        return set()


# --- Reverse DNS -----------------------------------------------------------------------------

_HOSTNAME = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,252})$")


def clean_hostname(name: str | None, address: str) -> str | None:
    if not name:
        return None
    name = name.strip().rstrip(".")
    if not _HOSTNAME.match(name) or name == address:
        return None
    # Sin pasar a minúsculas (Fase 4E): el nombre se muestra tal como lo registró el equipo
    # ("MNA-LX9"); las búsquedas y comparaciones ya ignoran mayúsculas.
    return name


def _lookup(address: str) -> str | None:
    try:
        return socket.gethostbyaddr(address)[0]
    except (OSError, UnicodeError):
        return None


async def reverse_dns(
    executor: ThreadPoolExecutor, address: IPAddress, timeout: float
) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        name = await asyncio.wait_for(
            loop.run_in_executor(executor, _lookup, str(address)), timeout
        )
    except TimeoutError:
        return None
    return clean_hostname(name, str(address))
