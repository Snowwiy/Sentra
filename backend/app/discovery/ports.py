"""TCP port lists for exposure monitoring and the hints shown next to each port."""

PROFILES: dict[str, tuple[int, ...]] = {
    # Smallest useful set: remote administration and file sharing.
    "minimal": (22, 80, 443, 445, 3389),
    # Default: what is usually worth knowing is reachable on an internal network.
    "common": (
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        389,
        443,
        445,
        515,
        631,
        993,
        995,
        1433,
        3306,
        3389,
        5432,
        5900,
        5985,
        5986,
        8080,
        8443,
        9100,
    ),
    "windows": (135, 139, 445, 3389, 5985, 5986),
    "printers": (80, 443, 515, 631, 9100),
    "web": (80, 443, 8000, 8080, 8443),
}

MAX_PORTS = 1024

# IANA-registered service for the port number. A hint, not a fingerprint: Sentra does not
# talk to the service, so "8080 → http-alt" only says what usually listens there.
SERVICE_HINTS: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    515: "lpd",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    5985: "winrm-http",
    5986: "winrm-https",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9100: "jetdirect",
    9200: "elasticsearch",
    27017: "mongodb",
}

# Remote administration, file sharing and databases: a new exposure of one of these is
# raised as critical; any other new port as a warning. Still a signal, not an attack.
SENSITIVE_PORTS = frozenset(
    {22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 9200, 27017}
)

# Probed first to decide whether a host is up (when ping is unavailable or filtered).
LIVENESS_PORTS = (445, 80, 443, 22, 3389, 135, 139, 9100, 8080)


def parse_ports(spec: str) -> tuple[int, ...]:
    """'common,8081,9000-9005' → sorted unique ports. Raises ValueError."""
    ports: set[int] = set()
    for raw in spec.replace(";", ",").split(","):
        token = raw.strip().lower()
        if not token:
            continue
        if token in PROFILES:
            ports.update(PROFILES[token])
            continue
        start_text, dash, end_text = token.partition("-")
        try:
            start = int(start_text)
            end = int(end_text) if dash else start
        except ValueError:
            raise ValueError(
                f"unknown port or profile {token!r} (profiles: {', '.join(PROFILES)})"
            ) from None
        if not 1 <= start <= end <= 65535:
            raise ValueError(f"invalid port range {token!r}")
        if end - start + 1 > MAX_PORTS:
            raise ValueError(f"port range {token!r} is larger than {MAX_PORTS} ports")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("no ports configured")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"{len(ports)} ports configured, more than the limit of {MAX_PORTS}")
    return tuple(sorted(ports))


def liveness_ports(ports: tuple[int, ...], limit: int = 6) -> tuple[int, ...]:
    """A few configured ports likely to answer, used to tell whether a host is up."""
    preferred = [p for p in LIVENESS_PORTS if p in ports]
    rest = [p for p in ports if p not in preferred]
    return tuple((preferred + rest)[:limit])
