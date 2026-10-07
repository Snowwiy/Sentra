"""Fase 5C.1: ciclo de vida de activos y eventos Linux contra una API Sentra EN MARCHA.

Mismo entorno que qa/e2e_api.py (instancia QA, nunca producción):

    set SENTRA_QA_API_URL=http://127.0.0.1:8100
    set SENTRA_QA_ENROLLMENT_KEY=<AGENT_ENROLLMENT_KEY de esa API>
    set SENTRA_QA_ADMIN_USER=<admin>
    set SENTRA_QA_ADMIN_PASSWORD=<contraseña>
    python qa/e2e_lifecycle.py

Escenarios (hostnames e IPs con un sufijo aleatorio para poder repetirlo):

A. reinstalación: agente antiguo revocado y agente nuevo del mismo equipo -> posible duplicado
   de confianza media -> reconciliar -> el agente nuevo informa en el activo histórico;
B. archivar: exige revocar antes, oculta el activo (lista y resumen), restaurar no reactiva la
   credencial, versión obsoleta = 409, un agente de un activo archivado no se enrola;
C. borrar: un activo gestionado nunca se borra (409 con motivos) y queda auditado;
D. permisos: viewer solo lee, analyst lee duplicados pero no archiva ni borra;
E. Linux: identidad de máquina (alta confianza, nunca expuesta), cobertura sin permiso,
   eventos del journal sin Event ID, filtros y reglas LIN-AUTH-001 / LIN-AUTH-002 (necesita el
   job del motor activo; conviene DETECTION_EVAL_INTERVAL_SECONDS=2).

El borrado de un activo descubierto sin historial lo cubre backend/tests (aquí haría falta
un discovery real).
"""

import random
import sys
import uuid
from typing import Any

import e2e_api as qa
from e2e_api import bearer, call, check, login, now_iso, wait_for

TAG = uuid.uuid4().hex[:6]
NET = f"10.{random.randint(100, 250)}.{random.randint(0, 250)}"  # noqa: S311  (datos de QA)
MACHINE = uuid.uuid4().hex + uuid.uuid4().hex  # 64 hex: hash sintético de identidad


def register(hostname: str, ip: str, **extra: Any) -> tuple[str, str, str]:
    agent_id = str(uuid.uuid4())
    body = {
        "agent_id": agent_id,
        "hostname": hostname,
        "os_name": extra.pop("os_name", "Windows"),
        "os_version": "QA",
        "architecture": "x86_64",
        "primary_ip": ip,
        "agent_version": extra.pop("agent_version", "0.2.1"),
        **extra,
    }
    r = call("POST", "/agents/register", body, {"X-Enrollment-Key": qa.KEY})
    if r.status != 201:
        raise RuntimeError(f"enrollment failed: {r.status} {r.body}")
    return agent_id, r.body["agent_token"], r.body["asset_id"]


def asset(asset_id: str, session: dict[str, str] | None = None) -> dict[str, Any]:
    r = call("GET", f"/assets/{asset_id}", session=session)
    return r.body if r.status == 200 else {}


def listed(asset_id: str, archived: str = "exclude") -> bool:
    r = call("GET", f"/assets?limit=500&archived={archived}")
    return (
        any(a["asset_id"] == asset_id for a in r.body.get("items", []))
        if r.status == 200
        else False
    )


def revoke(asset_id: str) -> None:
    r = call("POST", f"/console/agents/{asset_id}/revoke")
    check("admin revokes the agent", r.status == 200, (r.status, r.body))


def audited(response: Any, target_id: str) -> bool:
    items = response.body.get("items", []) if response.status == 200 else []
    return any(item.get("target_id") == target_id for item in items)


def users() -> dict[str, dict[str, str]]:
    sessions: dict[str, dict[str, str]] = {}
    for role in ("analyst", "viewer"):
        name = f"qa-life-{role}-" + uuid.uuid4().hex[:6]
        password = f"qa {role} password " + uuid.uuid4().hex[:8]
        r = call("POST", "/users", {"username": name, "password": password, "role": role})
        check(f"admin creates a {role}", r.status == 201, (r.status, r.body))
        sessions[role] = login(name, password)[1]
    return sessions


def scenario_reinstall() -> None:
    host, ip = f"QA-RAV-{TAG}", f"{NET}.66"
    old_agent, old_token, old_id = register(host, ip, agent_version="0.1.0")
    r = call("POST", "/agents/heartbeat", {"agent_id": old_agent}, bearer(old_token))
    check("old agent reports", r.status == 200, (r.status, r.body))
    revoke(old_id)
    new_agent, new_token, new_id = register(host, ip, agent_version="0.2.0")
    check("reinstalled agent gets a new asset", new_id != old_id)

    r = call("GET", f"/assets/{new_id}/duplicate-candidates")
    items = r.body.get("items", []) if r.status == 200 else []
    match = next((c for c in items if c["asset"]["asset_id"] == old_id), None)
    check("revoked asset suggested as duplicate", match is not None, (r.status, r.body))
    if match is None:
        return
    check(
        "medium confidence by hostname + IP, reconcilable",
        match["confidence"] == "medium"
        and set(match["reasons"]) == {"same_hostname", "same_ip"}
        and match["reconcilable"],
        match,
    )
    pairs = call("GET", "/assets/duplicates").body.get("items", [])
    check(
        "fleet duplicate list includes the pair",
        any(
            p["asset"]["asset_id"] == new_id and p["candidate"]["asset_id"] == old_id for p in pairs
        ),
        pairs[:3],
    )
    stale = call(
        "POST",
        f"/assets/{new_id}/reconcile",
        {"target_asset_id": old_id, "version": 99, "target_version": 0},
    )
    check("reconcile with a stale version -> 409", stale.status == 409, (stale.status, stale.body))
    r = call(
        "POST",
        f"/assets/{new_id}/reconcile",
        {
            "target_asset_id": old_id,
            "version": asset(new_id)["lifecycle_version"],
            "target_version": asset(old_id)["lifecycle_version"],
        },
    )
    check("admin reconciles new agent into historical asset", r.status == 200, (r.status, r.body))
    beat = call("POST", "/agents/heartbeat", {"agent_id": new_agent}, bearer(new_token))
    check(
        "new agent now reports into the historical asset",
        beat.status == 200 and beat.body.get("asset_id") == old_id,
        (beat.status, beat.body),
    )
    duplicate = asset(new_id)
    check(
        "duplicate asset archived by the system, history kept",
        duplicate.get("archived_at") is not None and duplicate.get("archived_by") == "system",
        duplicate,
    )
    # /audit solo filtra por acción: el activo se busca en los elementos devueltos.
    audit = call("GET", "/audit?action=agent_asset_reconciled&limit=200")
    check("reconciliation audited", audited(audit, old_id), audit.body)


def scenario_archive() -> None:
    agent_id, token, asset_id = register(f"QA-ARCH-{TAG}", f"{NET}.70")
    version = asset(asset_id)["lifecycle_version"]
    r = call("POST", f"/assets/{asset_id}/archive", {"reason": "QA retirado", "version": version})
    check(
        "archive with active agent credential -> 409",
        r.status == 409 and r.body["error"]["code"] == "asset_state_conflict",
        (r.status, r.body),
    )
    revoke(asset_id)
    check("revoking does not archive", asset(asset_id).get("archived_at") is None)
    before = call("GET", "/dashboard/summary").body["assets"]["total"]
    r = call("POST", f"/assets/{asset_id}/archive", {"reason": "QA retirado", "version": version})
    check("admin archives with a reason", r.status == 200, (r.status, r.body))
    check("archived asset hidden by default", not listed(asset_id))
    check("archived asset visible with archived=include", listed(asset_id, "include"))
    after = call("GET", "/dashboard/summary").body["assets"]["total"]
    check("dashboard summary excludes archived", after == before - 1, (before, after))
    stale = call("POST", f"/assets/{asset_id}/restore", {"version": version})
    check("restore with stale version -> 409", stale.status == 409, (stale.status, stale.body))
    again = call("POST", "/agents/register", {
        "agent_id": agent_id, "hostname": f"QA-ARCH-{TAG}", "os_name": "Windows",
        "os_version": "QA", "architecture": "x86_64", "primary_ip": f"{NET}.70",
        "agent_version": "0.2.1"}, {"X-Enrollment-Key": qa.KEY})  # fmt: skip
    check(
        "agent of an archived asset cannot enroll (403)",
        again.status == 403,
        (again.status, again.body),
    )
    r = call(
        "POST", f"/assets/{asset_id}/restore", {"version": asset(asset_id)["lifecycle_version"]}
    )
    check("admin restores", r.status == 200 and r.body["archived_at"] is None, (r.status, r.body))
    agents = call("GET", "/agents").body.get("items", [])
    row = next((a for a in agents if a["asset_id"] == asset_id), {})
    check("restore keeps the credential revoked", row.get("credential_status") == "revoked", row)
    del token


def scenario_delete() -> None:
    _, _, asset_id = register(f"QA-DEL-{TAG}", f"{NET}.80")
    revoke(asset_id)
    r = call("GET", f"/assets/{asset_id}/delete-check")
    check(
        "managed asset not deletable (managed_history)",
        r.status == 200
        and not r.body["deletable"]
        and "managed_history" in r.body["blocking_reasons"],
        (r.status, r.body),
    )
    d = call("DELETE", f"/assets/{asset_id}?version={r.body.get('version', 0)}")
    check(
        "DELETE managed asset -> 409 asset_not_deletable",
        d.status == 409 and d.body["error"]["code"] == "asset_not_deletable",
        (d.status, d.body),
    )
    check("asset still there", asset(asset_id).get("asset_id") == asset_id)
    audit = call("GET", "/audit?action=asset_delete_rejected&limit=200")
    check("rejected delete audited", audited(audit, asset_id), audit.body)
    missing = call("GET", f"/assets/{uuid.uuid4()}/delete-check")
    check("delete-check of unknown asset -> 404", missing.status == 404, missing.status)


def scenario_rbac(roles: dict[str, dict[str, str]]) -> None:
    _, _, asset_id = register(f"QA-RBAC-{TAG}", f"{NET}.90")
    for role, session in roles.items():
        for method, path, body in (
            ("GET", f"/assets/{asset_id}/delete-check", None),
            ("POST", f"/assets/{asset_id}/archive", {"reason": "nope", "version": 0}),
            ("POST", f"/assets/{asset_id}/restore", {"version": 0}),
            ("DELETE", f"/assets/{asset_id}?version=0", None),
        ):
            r = call(method, path, body, session=session)
            check(f"{role} cannot {method} {path.split('/')[-1]} -> 403", r.status == 403, r.status)
        r = call("GET", f"/assets/{asset_id}/duplicate-candidates", session=session)
        expected = 200 if role == "analyst" else 403
        check(f"{role} duplicate suggestions -> {expected}", r.status == expected, r.status)
        r = call("GET", "/assets?archived=include", session=session)
        check(f"{role} reads archived filter", r.status == 200, r.status)


def scenario_linux() -> None:
    old_agent, _, old_id = register(f"qa-mint-{TAG}", f"{NET}.100", os_name="Linux",
                                    machine_id_hash=MACHINE)  # fmt: skip
    revoke(old_id)
    agent_id, token, asset_id = register(f"qa-mint-renamed-{TAG}", f"{NET}.101", os_name="Linux",
                                         machine_id_hash=MACHINE)  # fmt: skip
    items = call("GET", f"/assets/{asset_id}/duplicate-candidates").body.get("items", [])
    top = next((c for c in items if c["asset"]["asset_id"] == old_id), {})
    check("same machine id -> high confidence", top.get("confidence") == "high", items[:2])
    raw = call("GET", f"/assets/{asset_id}")
    check("machine id hash never exposed", MACHINE not in str(raw.body), "exposed")
    h = bearer(token)

    r = call("POST", "/events", {"agent_id": agent_id, "events": [],
             "coverage": {"journal": "no_permission", "sshd": "no_permission"}}, h)  # fmt: skip
    check("coverage-only batch accepted", r.status == 201, (r.status, r.body))
    check(
        "coverage stored on the asset",
        asset(asset_id).get("event_coverage", {}).get("journal") == "no_permission",
    )

    def ev(
        i: int, event_type: str, provider: str = "sshd", level: str = "warning", **data: str
    ) -> dict[str, Any]:
        return {"source": "linux_journal", "channel": "journal", "record_id": 7_000_000 + i,
                "event_type": event_type, "provider": provider, "level": level,
                "message": f"QA {event_type}", "occurred_at": now_iso(), "data": data}  # fmt: skip

    events = [ev(i, "auth_failure", user="qa-root", source_ip="203.0.113.77") for i in range(6)]
    events.append(ev(10, "auth_success", level="info", user="qa-root", source_ip="203.0.113.77"))
    events.append(ev(11, "sudo_command", provider="sudo", level="info", user="qa-root",
                     target_user="root", command="/usr/bin/id"))  # fmt: skip
    coverage = {"journal": "active", "sshd": "active", "sudo": "active", "auditd": "unavailable"}
    r = call("POST", "/events", {"agent_id": agent_id, "events": events, "coverage": coverage}, h)
    check(
        "Linux journal events accepted",
        r.status == 201 and r.body["stored"] == 8,
        (r.status, r.body),
    )
    again = call("POST", "/events", {"agent_id": agent_id, "events": events}, h)
    check(
        "resent Linux events deduplicated",
        again.status == 201 and again.body["stored"] == 0,
        again.body,
    )
    listed_events = call("GET", f"/events?asset_id={asset_id}&provider=sudo").body.get("items", [])
    check(
        "events filtered by provider, no Windows Event ID",
        len(listed_events) == 1
        and listed_events[0]["event_code"] is None
        and listed_events[0]["event_type"] == "sudo_command",
        listed_events,
    )
    by_type = call("GET", f"/events?asset_id={asset_id}&event_type=auth_failure").body.get(
        "items", []
    )
    check("events filtered by event_type", len(by_type) == 6, len(by_type))

    def rules() -> dict[str, dict[str, Any]]:
        r = call("GET", f"/detections?asset_id={asset_id}&active=true")
        return {d["rule_id"]: d for d in r.body.get("items", [])} if r.status == 200 else {}

    found = wait_for(rules, lambda d: "LIN-AUTH-001" in d and "LIN-AUTH-002" in d, timeout=60)
    check("SSH brute force -> LIN-AUTH-001", "LIN-AUTH-001" in found, list(found))
    check("not the Windows AUTH-001", "AUTH-001" not in found, list(found))
    check(
        "failures + success + sudo -> LIN-AUTH-002 critical",
        found.get("LIN-AUTH-002", {}).get("severity") == "critical",
        found.get("LIN-AUTH-002"),
    )
    del old_agent


def main() -> int:
    if not qa.KEY or not qa.ADMIN_USER or not qa.ADMIN_PASSWORD:
        print(
            "SENTRA_QA_ENROLLMENT_KEY, SENTRA_QA_ADMIN_USER and SENTRA_QA_ADMIN_PASSWORD"
            " are required",
            file=sys.stderr,
        )
        return 2
    r, admin = login(qa.ADMIN_USER, qa.ADMIN_PASSWORD)
    if not admin:
        print(f"admin login failed: {r.status} {r.body}", file=sys.stderr)
        return 2
    qa.SESSION.update(admin)
    try:
        roles = users()
        print("--- A. reinstalación y reconciliación")
        scenario_reinstall()
        print("--- B. archivar y restaurar")
        scenario_archive()
        print("--- C. borrado")
        scenario_delete()
        print("--- D. permisos")
        scenario_rbac(roles)
        print("--- E. Linux")
        scenario_linux()
    except Exception as exc:  # un fallo inesperado es un FAIL, no un traceback
        check("scenario crashed", False, repr(exc))
    failed = [r for r in qa.RESULTS if not r[1]]
    print(f"\n{len(qa.RESULTS) - len(failed)}/{len(qa.RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
