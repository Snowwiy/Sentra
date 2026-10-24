"""Fase 6E.7: aislamiento seguro (cálculo de direcciones, reglas, helper y lado del agente).

Ningún test ejecuta nft, netsh ni PowerShell: los backends de firewall se sustituyen por
dobles y los generadores de reglas se comprueban como texto o con salidas de ejemplo.
"""

import ipaddress
import itertools
import json
import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID

import pytest

from sentra_agent.config import IsolationSettings
from sentra_agent.isolation import GROUP, NFT_TABLE, IsolationError
from sentra_agent.isolation.addresses import (
    allowed_networks,
    complement_ranges,
    format_range,
    normalize_tokens,
    parse_extra,
    to_ranges,
)
from sentra_agent.isolation.client import IsolationClient
from sentra_agent.isolation.exchange import (
    REQUEST_FILE,
    STATE_FILE,
    STATUS_FILE,
    ExchangeDir,
    create_request,
    parse_request,
    read_json,
    request_payload,
)
from sentra_agent.isolation.nft import NftablesBackend, build_ruleset, parse_table, table_matches
from sentra_agent.isolation.policy import (
    PolicyError,
    load_policy,
    parse_policy,
    render_default_policy,
)
from sentra_agent.isolation.windows import (
    REVERT_SCRIPT,
    Rule,
    WindowsFirewallBackend,
    active_profiles_enabled,
    apply_script,
    backup_task_script,
    build_rules,
    parse_profiles,
    rules_match,
)
from sentra_agent.isolation_helper import PRIVATE_STATE, IsolationHelper
from sentra_agent.runner import Agent
from sentra_agent.syscmd import CommandOutput
from tests.conftest import FakeApiState, make_client, make_store
from tests.test_runner import HOST, FakeEvents, processes, sample, snapshot

BASE = datetime(2026, 10, 22, 10, 0, tzinfo=UTC).timestamp()
SERVER = "203.0.113.10"
DNS = "192.0.2.53"


def ip(text: str) -> int:
    return int(ipaddress.ip_address(text))


# --- Direcciones ---------------------------------------------------------------------------


def test_allowed_networks_are_local_and_minimal() -> None:
    allowed = allowed_networks([SERVER], dns_servers=[DNS, "0.0.0.0", "224.0.0.1"])  # noqa: S104
    texts = {str(n) for n in allowed}
    assert {"127.0.0.0/8", "::1/128", "255.255.255.255/32", f"{SERVER}/32", f"{DNS}/32"} <= texts
    assert "0.0.0.0/32" not in texts and "224.0.0.1/32" not in texts
    # Sin IPv6 en el servidor no se abre el descubrimiento de vecinos.
    assert "fe80::/10" not in texts

    v6 = {str(n) for n in allowed_networks(["2001:db8::10"], allow_dns=False, dns_servers=[DNS])}
    assert {"fe80::/10", "ff02::/16", "2001:db8::10/128"} <= v6
    assert f"{DNS}/32" not in v6


def test_extra_allow_cannot_be_too_broad() -> None:
    assert [str(n) for n in parse_extra(["10.20.0.0/16", "198.51.100.7"])] == [
        "10.20.0.0/16",
        "198.51.100.7/32",
    ]
    for entry in ("10.0.0.0/7", "0.0.0.0/0", "2000::/3", "no-ip"):
        with pytest.raises(ValueError):
            parse_extra([entry])


def test_complement_covers_everything_except_allowed() -> None:
    allowed = allowed_networks([SERVER], dns_servers=[DNS])
    gaps = complement_ranges(allowed, 4)
    permitted = to_ranges(allowed, 4)
    # Rango completo partido sin solapes ni huecos entre permitidos y bloqueados.
    pieces = sorted(gaps + permitted)
    assert pieces[0][0] == 0 and pieces[-1][1] == 2**32 - 1
    assert all(a[1] + 1 == b[0] for a, b in itertools.pairwise(pieces))
    expectations = [(SERVER, False), (DNS, False), ("127.0.0.1", False), ("8.8.8.8", True),
                    ("203.0.113.11", True), ("10.0.0.1", True)]  # fmt: skip
    for address, blocked in expectations:
        inside = any(start <= ip(address) <= end for start, end in gaps)
        assert inside is blocked, address
    assert format_range(ip("10.0.0.1"), ip("10.0.0.1"), 4) == "10.0.0.1"
    assert format_range(ip("10.0.0.0"), ip("10.0.0.255"), 4) == "10.0.0.0-10.0.0.255"


def test_normalize_tokens_reads_windows_formats() -> None:
    merged = normalize_tokens(["10.0.0.0/255.255.255.0", "10.0.1.0-10.0.1.255", "10.0.2.0/24"])
    assert merged[4] == [(ip("10.0.0.0"), ip("10.0.2.255"))]
    with pytest.raises(ValueError):
        normalize_tokens(["10.0.0.9-10.0.0.1"])


# --- Firewall de Windows -------------------------------------------------------------------


def test_windows_rules_block_the_complement_in_both_directions() -> None:
    allowed = allowed_networks([SERVER])
    rules = build_rules(allowed)
    assert sorted((r.direction, r.name.split()[-1]) for r in rules) == [
        ("inbound", "IPv4"), ("inbound", "IPv6"), ("outbound", "IPv4"), ("outbound", "IPv6"),
    ]  # fmt: skip
    assert all(r.name.startswith(GROUP) and r.action == "block" for r in rules)
    v4 = next(r for r in rules if r.name.endswith("outbound IPv4"))
    assert normalize_tokens(v4.remote)[4] == complement_ranges(allowed, 4)


def test_apply_script_only_carries_validated_values() -> None:
    session = uuid.uuid4()
    rules = build_rules(allowed_networks([SERVER]))
    script = apply_script(rules, session)
    assert f"Remove-NetFirewallRule -Group '{GROUP}'" in script
    assert script.count("New-NetFirewallRule") == 4
    assert str(session) in script
    assert "Set-NetFirewallProfile" not in script  # nunca se cambian perfiles
    bad = [Rule("x", "outbound", "block", ("1.2.3.4'; Remove-Item C:\\ -Recurse; '",))]
    with pytest.raises(IsolationError) as info:
        apply_script(bad, session)
    assert info.value.code == "invalid_rule"
    with pytest.raises(ValueError):
        apply_script(rules, "1'; whoami; '")  # type: ignore[arg-type]


def readback(rules: list[Rule]) -> list[dict[str, Any]]:
    return [
        {"name": r.name, "direction": r.direction.capitalize(), "action": "Block",
         "enabled": "True", "remote": list(r.remote)}
        for r in rules
    ]  # fmt: skip


def test_rules_match_requires_exact_readback() -> None:
    rules = build_rules(allowed_networks([SERVER]))
    found = readback(rules)
    assert rules_match(found, rules)
    assert not rules_match(found[:-1], rules)
    disabled = [dict(found[0], enabled="False"), *found[1:]]
    assert not rules_match(disabled, rules)
    narrowed = [dict(found[0], remote=["8.8.8.8"]), *found[1:]]
    assert not rules_match(narrowed, rules)
    allowing = [dict(found[0], action="Allow"), *found[1:]]
    assert not rules_match(allowing, rules)


def test_profiles_and_backup_task() -> None:
    active, profiles = parse_profiles(
        '{"active":["DomainAuthenticated"],"profiles":[{"name":"Domain","enabled":"True"},'
        '{"name":"Public","enabled":"False"}]}'
    )
    assert active_profiles_enabled(active, profiles) is True
    assert active_profiles_enabled(["Public"], profiles) is False
    script = backup_task_script(datetime(2026, 10, 22, 12, 0, tzinfo=UTC))
    assert "'2026-10-22T12:00:00Z'" in script and "S-1-5-18" in script
    assert f"Remove-NetFirewallRule -Group '{GROUP}'" in script
    assert "Unregister-ScheduledTask" in REVERT_SCRIPT


class FakePowerShell:
    def __init__(self) -> None:
        self.scripts: list[str] = []
        self.fail_on: str | None = None
        self.outputs: dict[str, str] = {}

    def __call__(self, argv: list[str], **_: Any) -> CommandOutput:
        script = argv[-1]
        self.scripts.append(script)
        if self.fail_on and self.fail_on in script:
            return CommandOutput(b"", "Register-ScheduledTask failed", 1)
        for marker, out in self.outputs.items():
            if marker in script:
                return CommandOutput(out.encode(), "", 0)
        return CommandOutput(b"", "", 0)


def test_windows_backend_refuses_when_profile_disabled() -> None:
    ps = FakePowerShell()
    ps.outputs["Get-NetConnectionProfile"] = (
        '{"active":"Public","profiles":[{"name":"Public","enabled":"False"}]}'
    )
    with pytest.raises(IsolationError) as info:
        WindowsFirewallBackend(ps).precheck()
    assert info.value.code == "firewall_disabled"


def test_windows_backend_reverts_if_backup_task_fails() -> None:
    ps = FakePowerShell()
    ps.fail_on = "Register-ScheduledTask"
    backend = WindowsFirewallBackend(ps)
    with pytest.raises(IsolationError) as info:
        backend.apply(allowed_networks([SERVER]), uuid.uuid4(), datetime.now(UTC))
    assert info.value.code == "backup_task_failed"
    assert ps.scripts[-1] == REVERT_SCRIPT  # sin respaldo no queda nada aplicado


def test_windows_backend_verifies_readback() -> None:
    allowed = allowed_networks([SERVER])
    ps = FakePowerShell()
    ps.outputs["Get-NetFirewallAddressFilter"] = json.dumps(readback(build_rules(allowed)))
    backend = WindowsFirewallBackend(ps)
    assert backend.verify(allowed) is True and backend.present() is True
    assert backend.verify(allowed_networks(["198.51.100.1"])) is False


# --- nftables ------------------------------------------------------------------------------


def test_nft_ruleset_is_an_own_table_with_drop_policy() -> None:
    allowed = allowed_networks([SERVER], dns_servers=[DNS])
    text = build_ruleset(allowed)
    assert f"table inet {NFT_TABLE} {{" in text and f"delete table inet {NFT_TABLE}" in text
    assert text.count("policy drop;") == 2 and "priority filter - 5" in text
    assert f"{SERVER}/32" in text and f"{DNS}/32" in text
    assert "udp sport 68 udp dport 67 accept" in text
    for foreign in ("flush ruleset", "table ip filter", "firewalld", "iptables"):
        assert foreign not in text


def nft_listing(allowed: list[Any], prio: int = -5, extra: str | None = None) -> str:
    def elems(version: int) -> list[Any]:
        out: list[Any] = []
        for net in allowed:
            if net.version != version:
                continue
            if net.num_addresses == 1:
                out.append(str(net.network_address))
            else:
                out.append({"prefix": {"addr": str(net.network_address), "len": net.prefixlen}})
        return out

    allow4 = elems(4) + ([extra] if extra else [])
    items: list[dict[str, Any]] = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": NFT_TABLE}},
        {"set": {"family": "inet", "name": "allow4", "table": NFT_TABLE, "elem": allow4}},
        {"set": {"family": "inet", "name": "allow6", "table": NFT_TABLE, "elem": elems(6)}},
    ]
    for name in ("input", "output"):
        items.append({"chain": {"family": "inet", "table": NFT_TABLE, "name": name,
                                "type": "filter", "hook": name, "prio": prio,
                                "policy": "drop"}})  # fmt: skip
    return json.dumps({"nftables": items})


def test_nft_table_readback() -> None:
    allowed = allowed_networks([SERVER], dns_servers=[DNS])
    assert table_matches(parse_table(nft_listing(allowed)), allowed)
    assert not table_matches(parse_table(nft_listing(allowed, prio=0)), allowed)
    widened = nft_listing(allowed, extra={"range": ["8.8.8.0", "8.8.8.255"]})  # type: ignore[arg-type]
    assert not table_matches(parse_table(widened), allowed)
    assert not table_matches(parse_table('{"nftables": []}'), allowed)


class FakeNft:
    def __init__(self, listing: str = "") -> None:
        self.calls: list[list[str]] = []
        self.files: list[str] = []
        self.listing = listing
        self.tables = ""

    def __call__(self, argv: list[str], **_: Any) -> CommandOutput:
        self.calls.append(argv)
        args = argv[1:]
        if args[:1] == ["-f"]:
            self.files.append(Path(args[1]).read_text())
            self.tables = f"table inet {NFT_TABLE}\n"
        elif args == ["list", "tables"]:
            return CommandOutput(self.tables.encode(), "", 0)
        elif args[:2] == ["-j", "list"]:
            return CommandOutput(self.listing.encode(), "", 0)
        elif args[:2] == ["delete", "table"]:
            self.tables = ""
        return CommandOutput(b"", "", 0)


def test_nft_backend_applies_via_file_and_reverts(tmp_path: Path) -> None:
    allowed = allowed_networks([SERVER])
    nft = FakeNft(nft_listing(allowed))
    backend = NftablesBackend(tmp_path, nft, nft="/usr/sbin/nft")
    backend.precheck()
    rules = backend.apply(allowed, uuid.uuid4(), datetime.now(UTC))
    assert nft.files and "policy drop;" in nft.files[0]
    assert list(tmp_path.iterdir()) == []  # el fichero temporal no se queda
    assert {r["direction"] for r in rules} == {"inbound", "outbound"}
    assert backend.verify(allowed) and backend.present()
    backend.revert()
    assert nft.calls[-1] == ["/usr/sbin/nft", "delete", "table", "inet", NFT_TABLE]
    assert backend.present() is False


def test_nft_missing_is_not_supported(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import sentra_agent.isolation.nft as nft_module

    monkeypatch.setattr(nft_module, "first_existing", lambda _: None)
    with pytest.raises(IsolationError) as info:
        NftablesBackend(tmp_path, FakeNft()).precheck()
    assert info.value.code == "nftables_unavailable"


# --- Política local ------------------------------------------------------------------------


def test_policy_is_strict_and_disabled_by_default(tmp_path: Path) -> None:
    assert load_policy(tmp_path / "missing.toml").enabled is False
    policy = parse_policy(
        "enabled = true\nmax_minutes = 60\nallow_dns = false\n"
        "extra_allow = ['10.1.0.0/16']\nagent_config = '/etc/sentra-agent/agent.toml'\n"
    )
    assert policy.enabled and policy.max_minutes == 60 and not policy.allow_dns
    assert [str(n) for n in policy.extra_allow] == ["10.1.0.0/16"]
    for text in (
        "enabled = 'yes'",
        "max_minutes = 0",
        "max_minutes = 1441",
        "extra_allow = ['0.0.0.0/0']",
        "allow_addresses = ['1.2.3.4']",
        "enabled = true\nenabled = false",
    ):
        with pytest.raises(PolicyError):
            parse_policy(text)
    rendered = parse_policy(render_default_policy("/etc/sentra-agent/agent.toml"))
    assert rendered.enabled is False and rendered.agent_config == Path(
        "/etc/sentra-agent/agent.toml"
    )
    with pytest.raises(PolicyError):
        render_default_policy("/srv/x'\nenabled = true")


# --- Intercambio ---------------------------------------------------------------------------


def payload(session: UUID, action: str = "isolate", minutes: int | None = 30) -> dict[str, Any]:
    now = datetime.fromtimestamp(BASE, UTC)
    expires = now + timedelta(minutes=minutes) if minutes is not None else None
    return request_payload(session, action, expires, now)


def test_parse_request_accepts_only_contract_keys() -> None:
    session = uuid.uuid4()
    request = parse_request(json.dumps(payload(session)).encode())
    assert request.session_id == session and request.action == "isolate"
    bad = [
        {**payload(session), "allowed": ["0.0.0.0/0"]},  # nunca direcciones desde fuera
        {**payload(session), "action": "shell"},
        payload(session, minutes=None),  # isolate sin expiración
        {**payload(session), "expires_at": "2026-10-22T11:00:00"},  # sin zona
        {k: v for k, v in payload(session).items() if k != "requested_at"},
    ]
    for data in bad:
        with pytest.raises(IsolationError) as info:
            parse_request(json.dumps(data).encode())
        assert info.value.code == "invalid_request"
    with pytest.raises(IsolationError):
        parse_request(b"x" * 5000)
    assert parse_request(json.dumps(payload(session, "release", None)).encode()).expires_at is None


def test_take_request_waits_for_partial_writes(tmp_path: Path) -> None:
    exchange = ExchangeDir(tmp_path, secure=False)
    assert exchange.take_request(BASE) is None
    (tmp_path / REQUEST_FILE).write_text('{"session_id": "abc')
    mtime = (tmp_path / REQUEST_FILE).stat().st_mtime
    assert exchange.take_request(mtime + 1) is None  # quizá a medio escribir
    assert (tmp_path / REQUEST_FILE).exists()
    assert exchange.take_request(mtime + 10) == b'{"session_id": "abc'
    assert not (tmp_path / REQUEST_FILE).exists()


def test_create_request_never_replaces_a_pending_one(tmp_path: Path) -> None:
    create_request(tmp_path, payload(uuid.uuid4()))
    with pytest.raises(IsolationError) as info:
        create_request(tmp_path, payload(uuid.uuid4()))
    assert info.value.code == "helper_busy"
    with pytest.raises(IsolationError) as info:
        create_request(tmp_path / "missing", payload(uuid.uuid4()))
    assert info.value.code == "helper_absent"


root_posix = pytest.mark.skipif(
    sys.platform == "win32" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="permisos POSIX reales: solo como root",
)


@root_posix
def test_secure_exchange_dir_rejects_symlinks_and_foreign_owner(tmp_path: Path) -> None:
    directory = tmp_path / "exchange"
    exchange = ExchangeDir(directory, secure=True, group="sentra-agent-test-missing")
    exchange.prepare()
    assert directory.stat().st_mode & 0o7777 == 0o700  # sin el grupo: solo root
    exchange.write(STATUS_FILE, {"helper": "ready"})
    assert read_json(directory / STATUS_FILE) == {"helper": "ready"}

    victim = tmp_path / "victim"
    victim.write_text("keep")
    os.symlink(victim, directory / REQUEST_FILE)
    with pytest.raises(IsolationError) as info:
        exchange.take_request(BASE)
    assert info.value.code == "invalid_request"
    assert victim.read_text() == "keep" and not (directory / REQUEST_FILE).is_symlink()

    os.chown(directory, 1000, 1000)  # type: ignore[attr-defined,unused-ignore]
    with pytest.raises(IsolationError) as info:
        exchange.prepare()
    assert info.value.code == "exchange_dir_insecure"


# --- Helper --------------------------------------------------------------------------------


class FakeBackend:
    method = "nftables"

    def __init__(self) -> None:
        self.allowed: list[Any] | None = None
        self.active = False
        self.verify_ok = True
        self.revert_fails = False
        self.calls: list[str] = []

    def precheck(self) -> None:
        self.calls.append("precheck")

    def apply(
        self, allowed: list[Any], session_id: UUID, expires_at: datetime
    ) -> list[dict[str, Any]]:
        self.calls.append("apply")
        self.allowed = allowed
        self.active = True
        return [{"name": "fake", "direction": "outbound", "action": "block", "remote": "x"}]

    def verify(self, allowed: list[Any]) -> bool:
        return self.verify_ok

    def present(self) -> bool:
        return self.active

    def revert(self) -> None:
        self.calls.append("revert")
        if self.revert_fails:
            raise IsolationError("firewall_command_failed", "boom")
        self.active = False


class Rig:
    """Helper con política, agent.toml, reloj y backend falsos sobre tmp_path."""

    def __init__(self, tmp_path: Path, policy: str = "enabled = true\nmax_minutes = 60\n") -> None:
        self.tmp = tmp_path
        self.clock = [BASE]
        self.backend = FakeBackend()
        (tmp_path / "agent.toml").write_text('api_url = "https://sentra.example:8443"\n')
        self.set_policy(policy)
        self.resolved: list[tuple[str, int]] = []
        self.helper = self.new_helper()

    def set_policy(self, text: str) -> None:
        agent_config = (self.tmp / "agent.toml").as_posix()
        (self.tmp / "isolation.toml").write_text(text + f"agent_config = '{agent_config}'\n")

    def new_helper(self) -> IsolationHelper:
        def resolve(host: str, port: int) -> list[str]:
            self.resolved.append((host, port))
            return [SERVER]

        return IsolationHelper(
            self.tmp / "isolation.toml",
            ExchangeDir(self.tmp / "isolation", secure=False),
            self.tmp / "helper-state",
            self.backend,
            resolve=resolve,
            dns_servers=lambda: [DNS],
            dhcp_server=lambda: None,
            wall=lambda: self.clock[0],
        )

    def send(self, session: UUID, action: str = "isolate", minutes: int | None = 30) -> None:
        now = datetime.fromtimestamp(self.clock[0], UTC)
        expires = now + timedelta(minutes=minutes) if minutes is not None else None
        create_request(self.tmp / "isolation", request_payload(session, action, expires, now))
        self.helper.step()

    def status(self) -> dict[str, Any]:
        data = read_json(self.tmp / "isolation" / STATUS_FILE)
        assert data is not None
        return data


def test_disabled_policy_never_touches_the_firewall(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy="enabled = false\n")
    rig.helper.startup()
    assert rig.status()["helper"] == "disabled"
    rig.send(uuid.uuid4())
    last = rig.status()["last_action"]
    assert last["outcome"] == "failed" and last["error_code"] == "helper_disabled"
    assert rig.backend.calls == []


def test_isolate_uses_only_locally_computed_addresses(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    session = uuid.uuid4()
    rig.send(session)

    status = rig.status()
    assert status["helper"] == "ready" and status["state"] == "isolated"
    assert status["verified"] is True and status["session_id"] == str(session)
    assert status["last_action"]["outcome"] == "succeeded"
    assert rig.resolved == [("sentra.example", 8443)]  # de agent.toml, no de la petición
    allowed = {str(n) for n in rig.backend.allowed or []}
    assert {f"{SERVER}/32", f"{DNS}/32", "127.0.0.0/8"} <= allowed
    assert {SERVER, DNS, "127.0.0.0/8"} <= set(status["allowed"])  # formato del contrato
    assert not (tmp_path / "isolation" / REQUEST_FILE).exists()
    # El estado del que depende la reversión está en el directorio privado.
    private = read_json(tmp_path / "helper-state" / PRIVATE_STATE)
    assert private is not None and private["state"] == "isolated"
    assert read_json(tmp_path / "isolation" / STATE_FILE) is not None  # copia informativa


def test_request_with_addresses_is_ignored(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    data = {**payload(uuid.uuid4()), "allowed": ["0.0.0.0/0"]}
    (tmp_path / "isolation" / REQUEST_FILE).write_text(json.dumps(data))
    rig.helper.step()
    assert rig.backend.calls == [] and rig.status()["state"] == "none"


def test_helper_enforces_duration_and_single_session(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy="enabled = true\nmax_minutes = 20\n")
    rig.helper.startup()
    rig.send(uuid.uuid4(), minutes=30)
    assert rig.status()["last_action"]["error_code"] == "duration_exceeds_policy"

    first = uuid.uuid4()
    rig.send(first, minutes=10)
    rig.send(first, minutes=10)  # reentrega del mismo comando: no se aplica dos veces
    assert rig.backend.calls.count("apply") == 1
    assert rig.status()["last_action"]["outcome"] == "succeeded"
    rig.send(uuid.uuid4(), minutes=10)
    assert rig.status()["last_action"]["error_code"] == "already_isolated"


def test_release_checks_the_session(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    session = uuid.uuid4()
    rig.send(session)
    rig.send(uuid.uuid4(), action="release", minutes=None)
    assert rig.status()["last_action"]["error_code"] == "session_mismatch"
    assert rig.status()["state"] == "isolated"
    rig.send(session, action="release", minutes=None)
    status = rig.status()
    assert status["state"] == "none" and status["last_action"]["outcome"] == "succeeded"
    assert rig.backend.active is False


def test_expiry_reverts_without_the_agent(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.send(uuid.uuid4(), minutes=15)
    rig.clock[0] += 15 * 60
    rig.helper.step()
    status = rig.status()
    assert status["state"] == "none" and status["last_action"]["action"] == "expire"
    assert rig.backend.active is False


def test_failed_verification_reverts(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.backend.verify_ok = False
    rig.helper.startup()
    rig.send(uuid.uuid4())
    status = rig.status()
    assert status["state"] == "failed" and status["error_code"] == "verification_failed"
    assert rig.backend.active is False


def test_unresolvable_server_or_missing_agent_config(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.helper._resolve = lambda host, port: []
    rig.send(uuid.uuid4())
    assert rig.status()["last_action"]["error_code"] == "server_unresolvable"
    (tmp_path / "isolation.toml").write_text("enabled = true\n")
    rig.send(uuid.uuid4())
    assert rig.status()["last_action"]["error_code"] == "agent_config_missing"
    assert rig.backend.calls == []


def test_invalid_policy_reports_error(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy="enabled = true\nwhatever = 1\n")
    rig.helper.startup()
    status = rig.status()
    assert status["helper"] == "error" and status["error_code"] == "policy_invalid"


@pytest.mark.parametrize("situation", ["applying", "expired", "policy_disabled"])
def test_startup_reverts_unsafe_states(tmp_path: Path, situation: str) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.send(uuid.uuid4(), minutes=30)
    private = tmp_path / "helper-state" / PRIVATE_STATE
    if situation == "applying":
        data = json.loads(private.read_text())
        data["state"] = "applying"
        private.write_text(json.dumps(data))
    elif situation == "expired":
        rig.clock[0] += 31 * 60
    else:
        rig.set_policy("enabled = false\n")

    restarted = rig.new_helper()  # el helper murió y vuelve a arrancar
    restarted.startup()
    assert rig.backend.calls[-1] == "revert" and rig.backend.active is False
    assert rig.status()["state"] == "none"


def test_startup_notices_rules_lost_after_reboot(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.send(uuid.uuid4())
    rig.backend.active = False  # nft no persiste tras reiniciar el equipo
    restarted = rig.new_helper()
    restarted.startup()
    status = rig.status()
    assert status["state"] == "none" and status["error_code"] == "rules_lost"
    assert rig.backend.calls.count("apply") == 1  # no se vuelve a aplicar solo


def test_presence_check_detects_external_removal(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.send(uuid.uuid4())
    rig.backend.active = False
    rig.clock[0] += 61
    rig.helper.step()
    assert rig.status()["error_code"] == "rules_lost"


def test_revert_now_and_failed_revert(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    rig.send(uuid.uuid4())
    rig.backend.revert_fails = True
    assert rig.helper.revert_now() is False
    assert rig.status()["state"] == "failed" and rig.status()["error_code"] == "revert_failed"
    rig.backend.revert_fails = False
    assert rig.new_helper().revert_now() is True
    assert rig.status()["state"] == "none"


# --- Lado del agente -----------------------------------------------------------------------


def client(rig: Rig, wait: int = 10, step: bool = True) -> IsolationClient:
    settings = IsolationSettings(
        exchange_dir=rig.tmp / "isolation",
        policy_file=rig.tmp / "isolation.toml",
        wait_seconds=wait,
        status_max_age_seconds=180,
    )

    def sleep(seconds: float) -> None:
        rig.clock[0] += seconds
        if step:
            rig.helper.step()

    return IsolationClient(settings, wall=lambda: rig.clock[0], sleep=sleep)


def test_client_status_absent_ready_and_stale(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    agent_side = client(rig)
    assert agent_side.status()["helper"] == "absent" and not agent_side.ready()
    rig.helper.startup()
    status = agent_side.status()
    assert status["helper"] == "ready" and agent_side.ready()
    assert set(status) == {"helper", "state", "session_id", "applied_at", "expires_at",
                           "method", "verified", "error_code"}  # fmt: skip
    rig.clock[0] += 600  # helper parado: status.json viejo
    stale = agent_side.status()
    assert stale["helper"] == "error" and stale["error_code"] == "helper_stale"


def test_client_round_trip_with_the_helper(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    agent_side = client(rig)
    session = uuid.uuid4()
    expires = datetime.fromtimestamp(rig.clock[0], UTC) + timedelta(minutes=30)

    status, summary, data, code = agent_side.request("isolate", session, expires)
    assert (status, summary, code) == ("succeeded", "Host isolated", None)
    assert data["isolation"]["state"] == "isolated" and data["isolation"]["verified"] is True
    assert SERVER in data["isolation"]["allowed"]

    status, summary, data, code = agent_side.request("release", session, None)
    assert status == "succeeded" and data["isolation"]["state"] == "restored"


def test_client_checks_before_handing_over(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy="enabled = true\nmax_minutes = 20\n")
    agent_side = client(rig)
    now = datetime.fromtimestamp(rig.clock[0], UTC)
    assert agent_side.request("isolate", uuid.uuid4(), now + timedelta(minutes=5))[3] == (
        "helper_absent"
    )
    rig.helper.startup()
    assert agent_side.request("isolate", uuid.uuid4(), now + timedelta(minutes=30))[3] == (
        "duration_exceeds_policy"
    )
    assert agent_side.request("isolate", uuid.uuid4(), now - timedelta(minutes=1))[3] == (
        "invalid_params"
    )
    assert not (tmp_path / "isolation" / REQUEST_FILE).exists()


def test_client_times_out_if_the_helper_does_not_answer(tmp_path: Path) -> None:
    rig = Rig(tmp_path)
    rig.helper.startup()
    agent_side = client(rig, wait=5, step=False)
    expires = datetime.fromtimestamp(rig.clock[0], UTC) + timedelta(minutes=5)
    assert agent_side.request("isolate", uuid.uuid4(), expires)[3] == "helper_timeout"
    # La petición sigue pendiente: otra no la sustituye.
    assert agent_side.request("isolate", uuid.uuid4(), expires)[3] == "helper_busy"


def test_disabled_helper_maps_to_helper_disabled(tmp_path: Path) -> None:
    rig = Rig(tmp_path, policy="enabled = false\n")
    rig.helper.startup()
    expires = datetime.fromtimestamp(rig.clock[0], UTC) + timedelta(minutes=5)
    assert client(rig).request("isolate", uuid.uuid4(), expires)[3] == "helper_disabled"


# --- Runner de punta a punta ---------------------------------------------------------------

isolation_platform = pytest.mark.skipif(
    sys.platform == "darwin", reason="macOS nunca anuncia aislamiento"
)


def agent_with(config: Any, isolation: IsolationClient) -> Agent:
    return Agent(
        config,
        make_client(config),
        make_store(config),
        host_info=lambda: HOST,
        metrics=sample,
        inventory=snapshot,
        events=FakeEvents(),
        processes=processes,
        isolation=isolation,
    )


@isolation_platform
def test_runner_announces_and_runs_isolation_only_with_a_ready_helper(
    fake_api: tuple[str, FakeApiState], make_config: Any, tmp_path: Path
) -> None:
    url, state = fake_api
    config = make_config(url)  # exchange_dir y policy_file dentro de tmp_path
    rig = Rig(tmp_path, policy="enabled = false\n")
    rig.helper.startup()
    agent = agent_with(config, client(rig))
    agent.cycle()
    heartbeat = dict(state.requests)["/agents/heartbeat"]
    assert heartbeat["isolation"]["helper"] == "disabled"
    assert "isolate_host" not in heartbeat["host"]["capabilities"]

    rig.set_policy("enabled = true\nmax_minutes = 60\n")
    rig.helper.step()
    assert "isolate_host" in agent._capabilities()
    assert "release_isolation" in agent._capabilities()

    agent_id = str(agent.identity.agent_id)
    session = str(uuid.uuid4())
    expires = (datetime.fromtimestamp(rig.clock[0], UTC) + timedelta(minutes=30)).isoformat()
    isolate: dict[str, Any] = {"request_id": str(uuid.uuid4()), "type": "isolate_host",
               "params": {"session_id": session, "expires_at": expires}}  # fmt: skip
    forged: dict[str, Any] = {"request_id": str(uuid.uuid4()), "type": "isolate_host",
              "params": {"session_id": session, "expires_at": expires,
                         "allowed": ["0.0.0.0/0"]}}  # fmt: skip
    state.commands[agent_id] = [forged, isolate]

    agent.cycle()

    results = dict(state.command_results)
    assert results[forged["request_id"]]["status"] == "rejected"
    assert results[forged["request_id"]]["error_code"] == "invalid_params"
    done = results[isolate["request_id"]]
    assert done["status"] == "succeeded"
    assert done["data"]["isolation"]["session_id"] == session
    assert rig.backend.calls.count("apply") == 1
    heartbeats = [body for path, body in state.requests if path == "/agents/heartbeat"]
    assert heartbeats[-1]["isolation"]["helper"] == "ready"
