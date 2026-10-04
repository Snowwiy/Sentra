"""Linux inventory collectors: systemd services and dpkg/rpm packages.

The parsers run on every platform against captured command output; the `real_*` tests read
the host itself when it is Linux (CI runners have systemd and dpkg).
"""

import os
import sys

import pytest

from sentra_agent.inventory import (
    _installed_dpkg_lines,
    collect_services,
    collect_software,
    parse_package_list,
    parse_systemd_services,
)

linux_only = pytest.mark.skipif(sys.platform != "linux", reason="reads this Linux host")

UNITS = """\
cron.service                 loaded    active   running Regular background program processing daemon
getty@tty1.service           loaded    active   running Getty on tty1
apt-daily.service            loaded    inactive dead    Daily apt download activities
nginx.service                loaded    failed   failed  A high performance web server
ghost.service                not-found inactive dead    ghost.service
no-description.service       loaded    active   exited
dbus.socket                  loaded    active   running D-Bus System Message Bus Socket
"""

UNIT_FILES = """\
apt-daily.service                      static          -
cron.service                           enabled         enabled
getty@.service                         enabled         enabled
nginx.service                          disabled        enabled
"""


def test_systemd_units_become_api_services() -> None:
    services = {s["name"]: s for s in parse_systemd_services(UNITS, UNIT_FILES)}

    assert set(services) == {"cron", "getty@tty1", "apt-daily", "nginx", "no-description"}
    assert services["cron"] == {
        "name": "cron",
        "display_name": "Regular background program processing daemon",
        "status": "running",
        "start_type": "enabled",
    }
    assert services["apt-daily"]["status"] == "dead"
    assert services["apt-daily"]["start_type"] == "static"
    assert services["nginx"]["status"] == "failed"
    # Template instances have no unit file of their own: start type unknown, not wrong.
    assert services["getty@tty1"]["start_type"] is None
    assert services["no-description"]["display_name"] is None


def test_dpkg_status_keeps_installed_packages_only() -> None:
    output = (
        "ii \tcurl\t8.5.0-2ubuntu10\tUbuntu Developers <ubuntu-devel@lists.ubuntu.com>\n"
        "hi \tlinux-image\t6.8.0-45\tUbuntu Kernel Team <kernel-team@lists.ubuntu.com>\n"
        "rc \told-tool\t1.0\tSomeone <someone@example.com>\n"
        "un \tnever-installed\t\t\n"
    )

    packages = parse_package_list(_installed_dpkg_lines(output))

    assert [p["name"] for p in packages] == ["curl", "linux-image"]  # held is still installed
    assert packages[0]["publisher"] == "Ubuntu Developers"  # e-mail dropped


def test_package_list_is_deduplicated_sorted_and_tolerant() -> None:
    output = (
        "zlib1g\t1:1.3\tUbuntu Developers <x@y>\n"
        "libc6\t2.39\tGNU <a@b>\n"
        "libc6\t2.39\tGNU <a@b>\n"  # multi-arch: same name and version twice
        "bash\t5.2.21-1.el9\t(none)\n"  # rpm without vendor
        "malformed line without tabs\n"
        "\t1.0\tnobody\n"  # no name
    )

    packages = parse_package_list(output)

    assert [p["name"] for p in packages] == ["bash", "libc6", "zlib1g"]
    assert packages[0]["publisher"] is None


@linux_only
def test_real_packages_are_valid_for_the_api() -> None:
    if not any(os.path.isfile(p) for p in ("/usr/bin/dpkg-query", "/usr/bin/rpm")):
        pytest.skip("no dpkg or rpm on this host")

    software = collect_software()

    assert software, "a Linux host with a package manager has packages"
    assert len(software) <= 5000
    for package in software:
        assert 1 <= len(package["name"]) <= 512
        assert package["version"] is None or len(package["version"]) <= 128


@linux_only
def test_real_services_are_valid_or_empty_without_systemd() -> None:
    services = collect_services()

    if not os.path.isdir("/run/systemd/system"):
        assert services == []  # containers and other init systems: nothing to report
        return
    assert services, "a systemd host always has services"
    for service in services:
        assert service["name"] and service["status"]
        assert len(service["status"]) <= 32
