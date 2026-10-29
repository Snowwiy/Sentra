"""Differences between two inventory snapshots of one asset (services, software, accounts).

Pure functions over the stored JSON documents, so the rules are easy to test and work for
every agent version. Noise control is deliberate:
- a section missing or empty on either side is skipped: an empty list means the collection
  failed or the agent is older, not that everything was removed (or added);
- service start/stop is recorded only for automatic services (a manual service starting on
  demand is normal) and not while the host is booting, when services come up one by one;
- at most MAX_CHANGES per snapshot, so a reimaged host does not write thousands of rows.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.detection.service_identity import classify_inventory_service, classify_modified
from app.models.change import ChangeCategory, ChangeKind

MAX_CHANGES = 500
# Start types that mean "should be running": Windows (psutil) and systemd unit file states.
_AUTOMATIC = {"automatic", "auto", "enabled"}


@dataclass(frozen=True)
class Change:
    category: ChangeCategory
    kind: ChangeKind
    item: str
    details: dict[str, Any] | None = None


def diff_inventory(
    previous: dict[str, Any], current: dict[str, Any], *, booting: bool = False
) -> list[Change]:
    changes = [
        *_services(previous.get("services"), current.get("services"), booting=booting),
        *_software(previous.get("software"), current.get("software")),
        *_accounts(previous.get("accounts"), current.get("accounts")),
    ]
    return changes[:MAX_CHANGES]


def admin_changes(changes: Iterable[Change]) -> list[dict[str, str]]:
    """The account changes that deserve an alert (administrator rights)."""
    return [
        {"account": change.item, "change": change.kind.value}
        for change in changes
        if change.kind in (ChangeKind.ADMIN_GRANTED, ChangeKind.ADMIN_REVOKED)
        or (
            change.category is ChangeCategory.ACCOUNT
            and change.kind is ChangeKind.ADDED
            and (change.details or {}).get("is_admin") is True
        )
    ]


def _by_key(items: Any) -> dict[str, dict[str, Any]] | None:
    if not isinstance(items, list) or not items:
        return None
    # Windows service and account names are case-insensitive.
    return {str(item["name"]).lower(): item for item in items if isinstance(item, dict)}


def _services(previous: Any, current: Any, *, booting: bool) -> list[Change]:
    before, after = _by_key(previous), _by_key(current)
    if before is None or after is None:
        return []
    changes = [
        Change(
            ChangeCategory.SERVICE,
            ChangeKind.ADDED,
            after[key]["name"],
            # Fase 7B-Fix1: la clasificación (instancia por usuario, servicio descubierto...)
            # se decide aquí, con el inventario completo a mano (plantilla e instancias de la
            # misma sesión), y viaja en el cambio hasta la señal de detección.
            {
                **_service(after[key]),
                "classification": classify_inventory_service(
                    str(after[key]["name"]), after[key], after
                ).to_json(),
            },
        )
        for key in sorted(after.keys() - before.keys())
    ]
    changes += [
        Change(
            ChangeCategory.SERVICE, ChangeKind.REMOVED, before[key]["name"], _service(before[key])
        )
        for key in sorted(before.keys() - after.keys())
    ]
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        if old.get("binpath") and new.get("binpath") and old["binpath"] != new["binpath"]:
            # Fase 7B-Fix1: mismo servicio con otro ejecutable (solo con agentes 0.6.2 en los
            # dos inventarios; uno antiguo no informa de binpath y nunca cuenta como cambio).
            changes.append(
                Change(
                    ChangeCategory.SERVICE,
                    ChangeKind.IMAGE_CHANGED,
                    new["name"],
                    {
                        **_service(new),
                        "before": old.get("binpath"),
                        "after": new.get("binpath"),
                        "classification": classify_modified(old, new).to_json(),
                    },
                )
            )
        if old.get("start_type") != new.get("start_type"):
            changes.append(
                Change(
                    ChangeCategory.SERVICE,
                    ChangeKind.START_TYPE_CHANGED,
                    new["name"],
                    {"before": old.get("start_type"), "after": new.get("start_type")},
                )
            )
        was_running = str(old.get("status")).lower() == "running"
        is_running = str(new.get("status")).lower() == "running"
        automatic = str(new.get("start_type") or "").lower() in _AUTOMATIC
        if was_running != is_running and automatic and not booting:
            changes.append(
                Change(
                    ChangeCategory.SERVICE,
                    ChangeKind.STARTED if is_running else ChangeKind.STOPPED,
                    new["name"],
                    {"before": old.get("status"), "after": new.get("status")},
                )
            )
    return changes


def _service(item: dict[str, Any]) -> dict[str, Any]:
    details = {"status": item.get("status"), "start_type": item.get("start_type")}
    # Fase 7B.1: el 7045 del SCM puede nombrar el servicio por su nombre visible ("Sentra
    # Agent") y el inventario por su clave ("SentraAgent"). Guardar el nombre visible permite
    # reconocer que las dos señales son la MISMA instalación y no contarla dos veces.
    if item.get("display_name"):
        details["display_name"] = item.get("display_name")
    # Fase 7B-Fix1 (agente 0.6.2): identidad verificable del servicio.
    for key in ("binpath", "image", "username", "service_type", "image_signature"):
        if item.get(key) is not None:
            details[key] = item.get(key)
    return details


def _versions(items: Any) -> dict[str, tuple[str, list[str]]] | None:
    """Lowercased name -> (display name, sorted versions). Several versions can coexist."""
    if not isinstance(items, list) or not items:
        return None
    found: dict[str, tuple[str, list[str]]] = {}
    for item in items:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        name = str(item["name"])
        _, versions = found.setdefault(name.lower(), (name, []))
        versions.append(str(item.get("version") or ""))
    return {key: (name, sorted(set(versions))) for key, (name, versions) in found.items()}


def _software(previous: Any, current: Any) -> list[Change]:
    before, after = _versions(previous), _versions(current)
    if before is None or after is None:
        return []
    changes = [
        Change(
            ChangeCategory.SOFTWARE, ChangeKind.ADDED, after[key][0], {"versions": after[key][1]}
        )
        for key in sorted(after.keys() - before.keys())
    ]
    changes += [
        Change(
            ChangeCategory.SOFTWARE,
            ChangeKind.REMOVED,
            before[key][0],
            {"versions": before[key][1]},
        )
        for key in sorted(before.keys() - after.keys())
    ]
    changes += [
        Change(
            ChangeCategory.SOFTWARE,
            ChangeKind.VERSION_CHANGED,
            after[key][0],
            {"before": before[key][1], "after": after[key][1]},
        )
        for key in sorted(before.keys() & after.keys())
        if before[key][1] != after[key][1]
    ]
    return changes


def _accounts(previous: Any, current: Any) -> list[Change]:
    before, after = _by_key(previous), _by_key(current)
    if before is None or after is None:
        return []
    changes = [
        Change(
            ChangeCategory.ACCOUNT,
            ChangeKind.ADDED,
            after[key]["name"],
            {"enabled": after[key].get("enabled"), "is_admin": after[key].get("is_admin")},
        )
        for key in sorted(after.keys() - before.keys())
    ]
    changes += [
        Change(ChangeCategory.ACCOUNT, ChangeKind.REMOVED, before[key]["name"])
        for key in sorted(before.keys() - after.keys())
    ]
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        if old.get("binpath") and new.get("binpath") and old["binpath"] != new["binpath"]:
            # Fase 7B-Fix1: mismo servicio con otro ejecutable (solo con agentes 0.6.2 en los
            # dos inventarios; uno antiguo no informa de binpath y nunca cuenta como cambio).
            changes.append(
                Change(
                    ChangeCategory.SERVICE,
                    ChangeKind.IMAGE_CHANGED,
                    new["name"],
                    {
                        **_service(new),
                        "before": old.get("binpath"),
                        "after": new.get("binpath"),
                        "classification": classify_modified(old, new).to_json(),
                    },
                )
            )
        # Null means "unknown" (not collected): only a change between two known values counts.
        enabled = _known_change(old, new, "enabled")
        if enabled is not None:
            kind = ChangeKind.ENABLED if enabled else ChangeKind.DISABLED
            changes.append(Change(ChangeCategory.ACCOUNT, kind, new["name"]))
        admin = _known_change(old, new, "is_admin")
        if admin is not None:
            kind = ChangeKind.ADMIN_GRANTED if admin else ChangeKind.ADMIN_REVOKED
            changes.append(Change(ChangeCategory.ACCOUNT, kind, new["name"]))
    return changes


def _known_change(old: dict[str, Any], new: dict[str, Any], key: str) -> bool | None:
    """The new boolean value when it changed between two known values, else None."""
    before, after = old.get(key), new.get(key)
    if before is None or after is None or before == after:
        return None
    return bool(after)
