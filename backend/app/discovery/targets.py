"""Which addresses Sentra may probe: the discovery allowlist.

Safety rules, enforced when the configuration is parsed (the API refuses to start with an
invalid allowlist rather than scanning something unintended) and again for every target:

- only networks listed in DISCOVERY_ALLOWED_NETWORKS are ever probed; an explicit target
  must be inside one of them;
- no default route (0.0.0.0/0, ::/0), no multicast, unspecified, reserved or broadcast space;
- at most DISCOVERY_MAX_HOSTS_PER_NETWORK addresses per network (hard cap 65536), so a typo
  such as /8 instead of /24 is refused instead of scanning 16 million addresses;
- Internet (globally routable) space is refused unless DISCOVERY_ALLOW_PUBLIC_NETWORKS is
  set, for organisations that really own public ranges;
- host bits must be clear ("192.168.1.10/24" is refused: was 192.168.1.0/24 meant, or the
  single host?);
- DISCOVERY_EXCLUDED addresses/networks are never probed, even inside an allowed network.
"""

import ipaddress
from collections.abc import Iterator
from dataclasses import dataclass

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

HARD_MAX_HOSTS = 65_536


class TargetError(ValueError):
    """A network or target that discovery must not touch."""


def _split(value: str) -> list[str]:
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def parse_network(text: str) -> IPNetwork:
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise TargetError(f"{text!r} is not a valid network or address ({exc})") from exc


def validate_network(network: IPNetwork, max_hosts: int, allow_public: bool) -> IPNetwork:
    """Raise TargetError unless `network` is a reasonable, local, bounded scan scope."""
    if network.prefixlen == 0:
        raise TargetError(f"{network} would cover every address: refused")
    if network.num_addresses > min(max_hosts, HARD_MAX_HOSTS):
        raise TargetError(
            f"{network} has {network.num_addresses} addresses, more than the limit of"
            f" {min(max_hosts, HARD_MAX_HOSTS)} (DISCOVERY_MAX_HOSTS_PER_NETWORK)"
        )
    first, last = network.network_address, network.broadcast_address
    for flag in ("is_multicast", "is_unspecified", "is_reserved"):
        if getattr(first, flag) or getattr(last, flag):
            raise TargetError(f"{network} is {flag.removeprefix('is_')} address space: refused")
    if isinstance(network, ipaddress.IPv4Network) and last == ipaddress.IPv4Address(
        "255.255.255.255"
    ):
        raise TargetError(f"{network} includes the limited broadcast address: refused")
    if not allow_public and (first.is_global or last.is_global):
        raise TargetError(
            f"{network} is public Internet address space; only private/local networks are"
            " allowed unless DISCOVERY_ALLOW_PUBLIC_NETWORKS=true"
        )
    return network


@dataclass(frozen=True)
class DiscoveryScope:
    allowed: tuple[IPNetwork, ...]
    excluded: tuple[IPNetwork, ...]
    max_hosts: int
    allow_public: bool = False

    @classmethod
    def parse(
        cls, allowed: str, excluded: str = "", max_hosts: int = 1024, allow_public: bool = False
    ) -> "DiscoveryScope":
        networks = [
            validate_network(parse_network(item), max_hosts, allow_public)
            for item in _split(allowed)
        ]
        # Overlapping entries (10.0.0.0/24 and 10.0.0.0/25) collapse into one scope, so a
        # host is never probed twice in the same run.
        collapsed: list[IPNetwork] = []
        v4 = [n for n in networks if isinstance(n, ipaddress.IPv4Network)]
        v6 = [n for n in networks if isinstance(n, ipaddress.IPv6Network)]
        collapsed.extend(ipaddress.collapse_addresses(v4))
        collapsed.extend(ipaddress.collapse_addresses(v6))
        for network in collapsed:
            # Two adjacent /24 collapse into a /23: still bounded by the limit.
            validate_network(network, max_hosts, allow_public)
        return cls(
            allowed=tuple(collapsed),
            excluded=tuple(parse_network(item) for item in _split(excluded)),
            max_hosts=max_hosts,
            allow_public=allow_public,
        )

    @property
    def enabled(self) -> bool:
        return bool(self.allowed)

    def resolve(self, target: str | None = None) -> list[IPNetwork]:
        """Networks to scan for a run: all allowed ones, or one explicit target inside them."""
        if not self.allowed:
            raise TargetError("discovery is disabled: DISCOVERY_ALLOWED_NETWORKS is empty")
        if target is None:
            return list(self.allowed)
        network = validate_network(parse_network(target), self.max_hosts, self.allow_public)
        if not any(
            network.version == allowed.version and network.subnet_of(allowed)  # type: ignore[arg-type]
            for allowed in self.allowed
        ):
            raise TargetError(f"{network} is outside DISCOVERY_ALLOWED_NETWORKS: refused")
        return [network]

    def is_excluded(self, address: IPAddress) -> bool:
        return any(address.version == ex.version and address in ex for ex in self.excluded)

    def is_allowed(self, address: IPAddress) -> bool:
        return not self.is_excluded(address) and any(
            address.version == net.version and address in net for net in self.allowed
        )

    def hosts(self, network: IPNetwork) -> Iterator[IPAddress]:
        """Probe-able addresses of `network` (no network/broadcast address, no exclusions)."""
        for address in network.hosts():
            if not self.is_excluded(address):
                yield address
