"""Parsers of OS output for the inventory, tested with captured fixtures on every platform.

The Windows ones (PowerShell JSON, registry values) cannot run for real outside Windows:
🪟 VALIDACIÓN LOCAL EN WINDOWS covers the collectors that call them.
"""

import json

import pytest

from sentra_agent.inventory import (
    ip_list,
    parse_linux_accounts,
    parse_package_list,
    parse_proc_route,
    parse_resolv_conf,
    parse_windows_accounts,
    registry_date,
    windows_architecture,
)

ADMIN_SID = "S-1-5-21-1-2-3-500"


def _windows(users: object, admins: object) -> str:
    return json.dumps({"users": users, "admins": admins})


def test_windows_accounts_with_admin_membership_by_sid() -> None:
    output = "﻿" + _windows(  # PowerShell may prefix a UTF-8 BOM
        [
            {"name": "Administrador", "sid": ADMIN_SID, "enabled": False, "last_logon": None},
            {
                "name": "José",
                "sid": "S-1-5-21-1-2-3-1001",
                "enabled": True,
                "last_logon": "2026-10-03T21:15:02.0000000Z",
            },
        ],
        [ADMIN_SID],
    )

    accounts = parse_windows_accounts(output)

    assert accounts == [
        {"name": "Administrador", "enabled": False, "is_admin": True, "last_logon": None},
        {
            "name": "José",
            "enabled": True,
            "is_admin": False,
            "last_logon": "2026-10-03T21:15:02+00:00",
        },
    ]


def test_windows_accounts_tolerate_powershell_json_quirks() -> None:
    # A single user and a single admin come as an object and a string, not arrays.
    single = parse_windows_accounts(
        _windows({"name": "ana", "sid": ADMIN_SID, "enabled": True}, ADMIN_SID)
    )
    assert single[0]["is_admin"] is True
    # Get-LocalGroupMember failed (orphaned SID): membership unknown, never guessed.
    unknown = parse_windows_accounts(_windows([{"name": "ana", "sid": ADMIN_SID}], None))
    assert unknown[0]["is_admin"] is None and unknown[0]["enabled"] is None
    # Unparseable or naive timestamps are dropped, not sent.
    odd = parse_windows_accounts(
        _windows([{"name": "x", "sid": "s", "last_logon": "03/10/2026"}], [])
    )
    assert odd[0]["last_logon"] is None


def test_linux_accounts() -> None:
    passwd = "\n".join(
        [
            "root:x:0:0:root:/root:/bin/bash",
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
            "ana:x:1000:1000:Ana:/home/ana:/bin/bash",
            "bob:x:1001:1001::/home/bob:/bin/zsh",
            "svc:x:1002:1002::/srv:/usr/sbin/nologin",
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
            "broken line",
        ]
    )
    group = "sudo:x:27:ana\nbob:x:1001:\nwheel:x:10:"

    accounts = {a["name"]: a for a in parse_linux_accounts(passwd, group)}

    assert set(accounts) == {"root", "ana", "bob", "svc"}  # no daemons, no nobody
    assert accounts["root"]["is_admin"] is True
    assert accounts["ana"]["is_admin"] is True and accounts["bob"]["is_admin"] is False
    assert accounts["svc"]["enabled"] is False  # cannot log in
    assert accounts["ana"]["enabled"] is None  # shadow unreadable: lock state unknown


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("20240115", "2024-01-15"), ("2024-01-15", None), ("20241399", None), (None, None)],
)
def test_registry_install_date(raw: object, expected: str | None) -> None:
    assert registry_date(raw) == expected


def test_windows_architecture_names() -> None:
    assert windows_architecture("AMD64") == "x64"
    assert windows_architecture("ARM64") == "arm64"
    assert windows_architecture("weird") is None


def test_ip_lists_from_registry_values() -> None:
    # REG_MULTI_SZ list, space/comma separated REG_SZ, zone indexes, junk and duplicates.
    values = [["192.168.1.1", ""], "8.8.8.8 1.1.1.1,8.8.8.8", "fe80::1%12", "0.0.0.0", "x"]  # noqa: S104

    assert ip_list(values) == ["192.168.1.1", "8.8.8.8", "1.1.1.1", "fe80::1"]


def test_linux_gateway_and_dns() -> None:
    route = (
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\n"
        "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\n"
    )
    resolv = "# comment\nnameserver 127.0.0.53\nnameserver   1.1.1.1\nsearch lan\n"

    assert parse_proc_route(route) == ["192.168.1.1"]
    assert parse_resolv_conf(resolv) == ["127.0.0.53", "1.1.1.1"]


def test_package_lines_with_architecture_and_rpm_install_time() -> None:
    packages = parse_package_list(
        "bash\t5.2-1.el9\tRed Hat\tx86_64\t1727049600\n"
        "tzdata\t2024a\tRed Hat\tnoarch\t(none)\n"
        "curl\t8.5\tUbuntu Developers <x@y>\tamd64\n"
    )

    by_name = {p["name"]: p for p in packages}
    assert by_name["bash"]["install_date"] == "2024-09-23"
    assert by_name["bash"]["architecture"] == "x86_64"
    assert by_name["tzdata"]["install_date"] is None
    assert by_name["curl"]["architecture"] == "amd64"
