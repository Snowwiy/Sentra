"""Extracción de señales (funciones puras): de eventos, cambios y puertos a SignalKind."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from app.detection import text
from app.detection.signals import (
    SignalKind,
    privileged_group,
    signal_from_discovery_change,
    signals_from_events,
    signals_from_inventory_changes,
    signals_from_listeners,
    unusual_location,
)
from app.models.change import ChangeCategory, ChangeKind
from app.models.event import EventLevel, SystemEvent
from app.services.change_detection import Change

NOW = datetime.now(UTC)
OLD = NOW - timedelta(days=1)


def _event(
    code: int,
    channel: str = "Security",
    provider: str = "Microsoft-Windows-Security-Auditing",
    level: EventLevel = EventLevel.WARNING,
    at: datetime = NOW,
    fields: dict[str, str] | None = None,
    **data: str,
) -> SystemEvent:
    return SystemEvent(
        public_id=uuid.uuid4(),
        asset_id=1,
        source="windows_eventlog",
        channel=channel,
        record_id=1,
        event_code=code,
        provider=provider,
        level=level,
        message="m",
        data={**(fields or {}), **data} or None,
        occurred_at=at,
    )


def _kinds(events: list[SystemEvent]) -> list[tuple[str, str | None]]:
    return [(s.kind.value, s.subject) for s in signals_from_events(events, OLD)]


def test_logon_events_map_to_auth_signals_with_normalized_account() -> None:
    failed = _event(4625, TargetUserName="PC-01\\Admin", IpAddress="10.0.0.9", LogonType="3")
    ok = _event(4624, level=EventLevel.INFO, TargetUserName="admin", TargetUserSid="S-1-5-21-9-500")

    signals = signals_from_events([failed, ok], OLD)

    assert [(s.kind, s.subject) for s in signals] == [
        (SignalKind.AUTH_FAILURE, "admin"),
        (SignalKind.AUTH_SUCCESS, "admin"),
    ]
    assert signals[0].data["source_ip"] == "10.0.0.9"
    assert signals[1].data["sid"] == "S-1-5-21-9-500"
    assert signals[0].source_id is not None  # public_id del evento: enlaza con /events


def test_window_manager_and_system_logons_are_not_people() -> None:
    dwm = _event(4624, TargetUserName="DWM-1", TargetDomainName="Window Manager")
    system = _event(4624, TargetUserName="SYSTEM", TargetUserSid="S-1-5-18")
    umfd = _event(4624, TargetUserName="UMFD-0", TargetUserSid="S-1-5-96-0-0")

    assert signals_from_events([dwm, system, umfd], OLD) == []


def test_events_without_structured_data_still_produce_signals_without_subject() -> None:
    # Agente anterior a la Fase 4H: sin `data`. Se cuenta, pero sin cuenta asociada.
    assert _kinds([_event(4625), _event(1102)]) == [
        ("auth_failure", None),
        ("log_cleared", "security"),
    ]


def test_group_membership_only_for_privileged_groups_by_sid() -> None:
    admins = _event(4732, MemberSid="S-1-5-21-1-1001", TargetSid="S-1-5-32-544")
    users = _event(4732, MemberSid="S-1-5-21-1-1001", TargetSid="S-1-5-32-545")  # Users
    domain_admins = _event(4728, MemberName="CN=Eve,OU=x", TargetSid="S-1-5-21-7-8-9-512")
    no_sid = _event(4732, MemberName="bob")  # sin SID del grupo: no se sabe si es privilegiado

    signals = signals_from_events([admins, users, domain_admins, no_sid], OLD)

    assert [(s.kind, s.subject, s.data["group"]) for s in signals] == [
        (SignalKind.ADMIN_GROUP_ADDED, "s-1-5-21-1-1001", "Administrators"),
        (SignalKind.ADMIN_GROUP_ADDED, "eve", "Domain Admins"),
    ]
    assert privileged_group("S-1-5-32-555") == "Remote Desktop Users"
    assert privileged_group("S-1-5-21-1-2-3-513") is None  # Domain Users


def test_system_defender_and_powershell_mapping() -> None:
    events = [
        _event(7045, "System", "Service Control Manager", ServiceName="EvilSvc",
               ImagePath='"C:\\Users\\Public\\x.exe" -k'),
        _event(7034, "System", "Service Control Manager", EventLevel.ERROR, param1="Spooler"),
        _event(41, "System", "Microsoft-Windows-Kernel-Power", EventLevel.CRITICAL),
        _event(6008, "System", "EventLog", EventLevel.ERROR),
        _event(104, "System", "Microsoft-Windows-Eventlog", Channel="Application"),
        _event(1116, "Microsoft-Windows-Windows Defender/Operational", "Defender",
               fields={"Threat Name": "Trojan:Win32/X"}),
        _event(5001, "Microsoft-Windows-Windows Defender/Operational", "Defender"),
        _event(4104, "Microsoft-Windows-PowerShell/Operational", "PowerShell"),
        # PowerShell con error (no 4104 Warning): no es señal de seguridad.
        _event(4100, "Microsoft-Windows-PowerShell/Operational", "PowerShell", EventLevel.ERROR),
        # Un 7045 de otro proveedor no se interpreta como instalación de servicio.
        _event(7045, "System", "Fake-Provider", ServiceName="x"),
    ]  # fmt: skip

    signals = signals_from_events(events, OLD)

    assert [(s.kind.value, s.subject) for s in signals] == [
        ("service_installed", "evilsvc"),
        ("service_crashed", "spooler"),
        ("unexpected_shutdown", None),
        ("unexpected_shutdown", None),
        ("log_cleared", "application"),
        ("malware_detected", "trojan:win32/x"),
        ("antimalware_disabled", "real-time protection"),
        ("powershell_suspicious", None),
    ]
    assert signals[0].data["unusual_location"] == "public user folder"


def test_old_events_produce_no_signals() -> None:
    # El primer envío de un agente trae eventos antiguos: no se convierten en detecciones.
    assert signals_from_events([_event(1102, at=NOW - timedelta(days=3))], OLD) == []


def test_audit_policy_removed_vs_added() -> None:
    removed = _event(4719, AuditPolicyChanges="%%8448, %%8450")
    added = _event(4719, AuditPolicyChanges="%%8449")
    unknown = _event(4719)

    flags = [s.data.get("removed") for s in signals_from_events([removed, added, unknown], OLD)]

    assert flags == [True, False, None]


@pytest.mark.parametrize(
    ("path", "reason"),
    [
        ("C:\\Users\\ana\\AppData\\Local\\Temp\\a.exe", "user temp folder"),
        ("c:\\windows\\temp\\b.exe", "Windows temp folder"),
        ("C:\\Users\\Public\\c.exe", "public user folder"),
        ("C:\\ProgramData\\d.exe", "ProgramData root"),
        ("C:\\Users\\ana\\AppData\\Roaming\\e.exe", "AppData\\Roaming root"),
        ("/tmp/.x/miner", "/tmp"),  # noqa: S108
        ("/dev/shm/x", "/dev/shm"),  # noqa: S108
        ("/usr/bin/python3 (deleted)", "binary deleted from disk while running"),
        ("C:\\Program Files\\App\\app.exe", None),
        ("C:\\ProgramData\\Vendor\\svc.exe", None),
        ("C:\\Users\\ana\\AppData\\Roaming\\Vendor\\app.exe", None),
        ("/usr/sbin/sshd", None),
        (None, None),
    ],
)
def test_unusual_locations(path: str | None, reason: str | None) -> None:
    assert unusual_location(path) == reason


def test_inventory_changes_reuse_the_existing_diff() -> None:
    changes = [
        Change(ChangeCategory.SERVICE, ChangeKind.ADDED, "NewSvc", {"status": "running"}),
        Change(ChangeCategory.SERVICE, ChangeKind.STOPPED, "WinDefend", {"after": "stopped"}),
        Change(ChangeCategory.SERVICE, ChangeKind.STOPPED, "Spooler", {"after": "stopped"}),
        Change(
            ChangeCategory.SERVICE, ChangeKind.START_TYPE_CHANGED, "mpssvc", {"after": "disabled"}
        ),
        Change(ChangeCategory.ACCOUNT, ChangeKind.ADDED, "eve", {"is_admin": True}),
        Change(ChangeCategory.ACCOUNT, ChangeKind.ADMIN_REVOKED, "bob"),
        Change(ChangeCategory.SOFTWARE, ChangeKind.ADDED, "7-Zip"),
    ]  # fmt: skip

    signals = signals_from_inventory_changes(changes, NOW, frozenset({"windefend", "mpssvc"}))

    assert [(s.kind.value, s.subject) for s in signals] == [
        ("service_added", "newsvc"),
        ("security_service_down", "windefend"),
        ("security_service_down", "mpssvc"),
        ("account_created", "eve"),
        ("admin_group_added", "eve"),
        ("admin_group_removed", "bob"),
    ]


def _listen(port: int, address: str = "0.0.0.0", **extra: Any) -> dict[str, Any]:  # noqa: S104
    return {"protocol": "tcp", "status": "listen", "local_address": address, "local_port": port,
            **extra}  # fmt: skip


def test_new_listeners_ignore_loopback_ephemeral_and_failed_collections() -> None:
    before = {"connections": [_listen(80)]}
    after = {
        "connections": [
            _listen(80),
            _listen(3389, process_name="svchost.exe", pid=10),
            _listen(5432, "127.0.0.1"),
            _listen(50123),
            {"protocol": "tcp", "status": "established", "local_port": 22},
        ]
    }

    (signal,) = signals_from_listeners(before, after, NOW)

    assert signal.kind is SignalKind.LISTEN_PORT_NEW and signal.subject == "3389"
    assert signal.data["sensitive"] is True and signal.data["process"] == "svchost.exe"
    # Lista anterior vacía o ausente = fallo de recogida o primer snapshot: nada.
    assert signals_from_listeners({"connections": []}, after, NOW) == []
    assert signals_from_listeners({}, after, NOW) == []


def test_discovery_changes() -> None:
    exposed = signal_from_discovery_change(ChangeKind.PORT_OPENED, "3389/tcp (rdp)", NOW, {})
    gone = signal_from_discovery_change(ChangeKind.DISAPPEARED, "192.168.1.9", NOW, {})

    assert exposed is not None and exposed.subject == "3389" and exposed.data["sensitive"]
    assert gone is not None and gone.kind is SignalKind.ASSET_DISAPPEARED
    assert signal_from_discovery_change(ChangeKind.PORT_CLOSED, "22/tcp", NOW, {}) is None


def test_untrusted_text_is_cleaned_and_bounded() -> None:
    assert text.clean("a\x1b[31mb\nc\td") == "a [31mb c d"
    assert len(text.clean("x" * 5000)) == text.MAX_VALUE
    assert text.principal("  DOMAIN\\Ádmin ") == "ádmin"
    assert text.principal("-") is None and text.sid("S-1-0-0") is None
    data = text.bounded_data(
        {"k": "<script>alert(1)</script>\r\n", "n": None, "l": list(range(50))}
    )
    assert data == {"k": "<script>alert(1)</script>", "l": [str(i) for i in range(20)]}
