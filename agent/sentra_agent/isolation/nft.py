"""Aislamiento con nftables en Linux (solo lo ejecuta el helper privilegiado).

Tabla PROPIA `inet sentra_isolation` con dos cadenas base (`input` y `output`, prioridad
`filter - 5`, política `drop`) que aceptan lo permitido y descartan el resto. No toca tablas
de firewalld, ufw ni de nadie: en nftables un paquete debe aceptarse en TODAS las cadenas base
del gancho, así que nuestra cadena basta para aislar sin modificar las demás. Revertir es
borrar la tabla; no se guarda en /etc/nftables.conf, así que un reinicio también la elimina.

Si el equipo no tiene el binario `nft` (solo iptables-legacy), el aislamiento no se ofrece.

Además de las direcciones permitidas se aceptan: loopback por interfaz, descubrimiento de
vecinos IPv6 (sin él no hay ruta IPv6 al servidor) y DHCP por puertos (68<->67), para que
una renovación del lease no deje al equipo sin dirección durante el aislamiento.
"""

import json
import os
import tempfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sentra_agent.isolation import METHOD_NFTABLES, NFT_TABLE, IsolationError
from sentra_agent.isolation.addresses import Network, normalize_tokens, to_ranges
from sentra_agent.syscmd import CommandOutput, first_existing, run_bounded

NFT_CANDIDATES = ("/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft")
_ND_TYPES = "nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert"


def _elements(allowed: list[Network], version: int) -> list[str]:
    return [str(net) for net in allowed if net.version == version]


def build_ruleset(allowed: list[Network]) -> str:
    """Script para `nft -f`: crea (o sustituye) la tabla propia en una sola transacción."""
    sets = []
    for name, kind, version in (("allow4", "ipv4_addr", 4), ("allow6", "ipv6_addr", 6)):
        elements = _elements(allowed, version)
        body = f"type {kind}; flags interval;"
        if elements:
            body += " elements = { " + ", ".join(elements) + " }"
        sets.append(f"  set {name} {{ {body} }}")
    chains = []
    for chain, hook, iface, addr, sport, dport in (
        ("input", "input", "iifname", "saddr", 67, 68),
        ("output", "output", "oifname", "daddr", 68, 67),
    ):
        chains.append(
            "\n".join(
                [
                    f"  chain {chain} {{",
                    f"    type filter hook {hook} priority filter - 5; policy drop;",
                    f'    {iface} "lo" accept',
                    f"    ip {addr} @allow4 accept",
                    f"    ip6 {addr} @allow6 accept",
                    f"    icmpv6 type {{ {_ND_TYPES} }} accept",
                    f"    udp sport {sport} udp dport {dport} accept",
                    "  }",
                ]
            )
        )
    return "\n".join(
        [
            # Crear-y-borrar primero hace idempotente la aplicación dentro de la transacción.
            f"table inet {NFT_TABLE} {{}}",
            f"delete table inet {NFT_TABLE}",
            f"table inet {NFT_TABLE} {{",
            *sets,
            *chains,
            "}",
            "",
        ]
    )


def _element_tokens(elem: Any) -> list[str]:
    if isinstance(elem, str):
        return [elem]
    if isinstance(elem, dict):
        if "prefix" in elem:
            prefix = elem["prefix"]
            return [f"{prefix['addr']}/{prefix['len']}"]
        if "range" in elem:
            first, last = elem["range"]
            return [f"{first}-{last}"]
        if "elem" in elem:
            return _element_tokens(elem["elem"].get("val"))
    return []


def parse_table(text: str) -> dict[str, Any]:
    """Cadenas y conjuntos de `nft -j list table inet sentra_isolation`."""
    data = json.loads(text)
    chains: dict[str, dict[str, Any]] = {}
    sets: dict[str, list[str]] = {}
    for item in data.get("nftables", []):
        if not isinstance(item, dict):
            continue
        if "chain" in item and item["chain"].get("table") == NFT_TABLE:
            chain = item["chain"]
            chains[str(chain.get("name"))] = chain
        elif "set" in item and item["set"].get("table") == NFT_TABLE:
            entry = item["set"]
            tokens = []
            for elem in entry.get("elem", []) or []:
                tokens.extend(_element_tokens(elem))
            sets[str(entry.get("name"))] = tokens
    return {"chains": chains, "sets": sets}


def table_matches(parsed: dict[str, Any], allowed: list[Network]) -> bool:
    chains = parsed["chains"]
    for name in ("input", "output"):
        chain = chains.get(name)
        if chain is None or chain.get("hook") != name or chain.get("policy") != "drop":
            return False
        if chain.get("type") != "filter" or chain.get("prio") != -5:
            return False
    try:
        for set_name, version in (("allow4", 4), ("allow6", 6)):
            found = normalize_tokens(parsed["sets"].get(set_name, [])).get(version, [])
            if found != to_ranges(allowed, version):
                return False
    except (ValueError, KeyError, TypeError):
        return False
    return True


class NftablesBackend:
    method = METHOD_NFTABLES

    def __init__(
        self,
        work_dir: Path,
        run: Callable[..., CommandOutput] = run_bounded,
        nft: str | None = None,
    ) -> None:
        self._work_dir = work_dir
        self._run = run
        self._nft = nft

    def _binary(self) -> str:
        nft = self._nft or first_existing(NFT_CANDIDATES)
        if nft is None:
            # Sin nftables (solo iptables-legacy): no soportado, nunca se improvisa con iptables.
            raise IsolationError("nftables_unavailable", "nft binary not found")
        return nft

    def _call(self, *args: str) -> CommandOutput:
        try:
            return self._run([self._binary(), *args], timeout=30, max_bytes=4 * 1024 * 1024)
        except OSError as exc:
            raise IsolationError("firewall_command_failed", str(exc)) from exc

    def precheck(self) -> None:
        result = self._call("list", "tables")
        if result.returncode != 0:
            raise IsolationError("firewall_command_failed", result.stderr.strip()[:200])

    def apply(
        self, allowed: list[Network], session_id: UUID, expires_at: datetime
    ) -> list[dict[str, Any]]:
        self._work_dir.mkdir(parents=True, exist_ok=True)
        fd, path = tempfile.mkstemp(dir=self._work_dir, prefix="nft-", suffix=".rules")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(build_ruleset(allowed))
            result = self._call("-f", path)
        finally:
            Path(path).unlink(missing_ok=True)
        if result.returncode != 0:
            raise IsolationError("firewall_command_failed", result.stderr.strip()[:200])
        remote_v4 = ",".join(_elements(allowed, 4))
        remote_v6 = ",".join(_elements(allowed, 6))
        return [
            {"name": f"{NFT_TABLE} input", "direction": "inbound", "action": "block",
             "remote": f"all except {remote_v4};{remote_v6}"},
            {"name": f"{NFT_TABLE} output", "direction": "outbound", "action": "block",
             "remote": f"all except {remote_v4};{remote_v6}"},
        ]  # fmt: skip

    def _listing(self) -> dict[str, Any] | None:
        result = self._call("-j", "list", "table", "inet", NFT_TABLE)
        if result.returncode != 0:
            return None
        try:
            return parse_table(result.text())
        except (ValueError, AttributeError, KeyError, TypeError):
            return None

    def verify(self, allowed: list[Network]) -> bool:
        parsed = self._listing()
        return parsed is not None and table_matches(parsed, allowed)

    def present(self) -> bool:
        result = self._call("list", "tables")
        return result.returncode == 0 and f"inet {NFT_TABLE}" in result.text()

    def revert(self) -> None:
        if not self.present():
            return
        result = self._call("delete", "table", "inet", NFT_TABLE)
        if result.returncode != 0:
            raise IsolationError("firewall_command_failed", result.stderr.strip()[:200])
