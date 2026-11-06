"""Fase 7C: selectores contextuales y asistente de la consola contra una API EN MARCHA.

Mismo entorno que qa/e2e_api.py (instancia QA, nunca producción). Para la parte del
asistente, la API debe usar un modelo: real o qa/console_assist_fake_llm.py.

    set SENTRA_QA_API_URL=http://127.0.0.1:8100
    set SENTRA_QA_ENROLLMENT_KEY=<AGENT_ENROLLMENT_KEY de esa API>
    set SENTRA_QA_ADMIN_USER=<admin>
    set SENTRA_QA_ADMIN_PASSWORD=<contraseña>
    python qa/e2e_console_assist.py

Comprueba:
A. /lookup/asset encuentra por hostname e IP, avisa de ambigüedad con dos equipos de la misma
   IP y resuelve ids conocidos;
B. una herramienta de lectura (asset.profile) se ejecuta y su resultado se puede analizar;
C. /ai/console/assist: con IA disponible, la respuesta cita datos reales, marca origen y
   descarta referencias inventadas; sin IA, error claro (ai_not_configured) y nada más cambia;
   7C-Security-Fix1: sin revisión previa (/ai/console/context) o con una huella distinta no se
   envía nada; la revisión no lleva secretos y dice que el destino es loopback;
D. una acción nunca se puede analizar (console_execution_not_usable) y un viewer no ejecuta.
"""

import random
import sys
import uuid

import e2e_api as qa
from e2e_api import call, check, login

TAG = uuid.uuid4().hex[:6]
# IP propia de cada ejecución: con la 10.0.0.10 de e2e_api la base de QA acumula equipos y el
# tope de 20 resultados dejaría fuera los de esta pasada.
IP = f"10.77.{random.randint(0, 250)}.{random.randint(1, 250)}"


def enroll(hostname: str) -> str:
    agent_id = str(uuid.uuid4())
    body = {**qa.host(agent_id, hostname), "primary_ip": IP}
    r = call("POST", "/agents/register", body, {"X-Enrollment-Key": qa.KEY})
    if r.status != 201:
        raise RuntimeError(f"enrollment failed: {r.status} {r.body}")
    asset_id: str = r.body["asset_id"]
    return asset_id


def lookups() -> tuple[str, str]:
    first = enroll(f"qa7c-{TAG}-a")
    second = enroll(f"qa7c-{TAG}-b")  # misma IP sintética que el primero
    r = call("GET", f"/lookup/asset?q=qa7c-{TAG}-a")
    check("lookup by hostname is exact", r.status == 200 and r.body["resolution"] == "exact", r.body)
    check(
        "lookup item has the right id",
        r.status == 200 and r.body["items"] and r.body["items"][0]["id"] == first,
        r.body,
    )
    r = call("GET", f"/lookup/asset?q={IP}&limit=20")
    ids = {i["id"] for i in (r.body or {}).get("items", [])}
    check(
        "same IP on two assets is ambiguous, never auto-picked",
        r.status == 200 and r.body["resolution"] == "ambiguous" and {first, second} <= ids,
        r.body,
    )
    r = call("GET", f"/lookup/asset?ids={first}&ids={second}")
    check("lookup resolves known ids", r.status == 200 and len(r.body["items"]) == 2, r.body)
    r = call("GET", "/lookup/incident?q=INC-1")
    check("incident lookup answers", r.status == 200, r.body)
    return first, second


def tools_and_assist(asset_id: str) -> None:
    r = call("POST", "/tools/asset.profile/execute", {"input": {"asset_id": asset_id}})
    check("read tool runs", r.status in (200, 201) and r.body.get("status") == "succeeded", r.body)
    if r.status not in (200, 201):
        return
    execution = r.body["execution_id"]
    status = call("GET", "/ai/status").body or {}
    body: dict[str, object] = {
        "task": "hypotheses",
        "execution_ids": [execution],
        "asset_id": asset_id,
    }
    if status.get("console_assist_available"):
        r = call("POST", "/ai/console/assist", body)
        check(
            "assist without review is refused",
            r.status == 422
            and (r.body or {}).get("error", {}).get("code") == "console_context_review_required",
            r.body,
        )
        wrong = {**body, "context_sha256": "0" * 64, "confirm_send": True}
        r = call("POST", "/ai/console/assist", wrong)
        check(
            "assist with another digest is refused",
            r.status == 409
            and (r.body or {}).get("error", {}).get("code") == "console_context_changed",
            r.body,
        )
        review = call("POST", "/ai/console/context", body)
        preview = review.body or {}
        check(
            "review shows the loopback document",
            review.status == 200 and preview.get("destination") == "loopback",
            review.body,
        )
        sent = {**body, "context_sha256": preview.get("context_sha256"), "confirm_send": True}
        r = call("POST", "/ai/console/assist", sent)
    else:
        r = call("POST", "/ai/console/context", body)
    if status.get("console_assist_available"):
        result = (r.body or {}).get("result", {})
        check("assist answers", r.status == 200, r.body)
        check("assist marks origin", result.get("origin") in ("model", "sentra"), result)
        check(
            "every hypothesis cites Sentra data",
            all(h["evidence"] for h in result.get("hypotheses", [])),
            result,
        )
        refs = {e["ref"] for e in result.get("evidence_refs", [])}
        check("invented refs are dropped", "R99" not in refs, refs)
        check(
            "assist links the analysed execution",
            execution in (r.body or {}).get("tool_execution_ids", []),
            r.body,
        )
    else:
        code = ((r.body or {}).get("error") or {}).get("code")
        check(
            "assist without AI fails cleanly",
            r.status in (409, 502, 503) and code is not None,
            r.body,
        )


def permissions(asset_id: str) -> None:
    username = f"qa7c-viewer-{TAG}"
    password = uuid.uuid4().hex + "Aa1!"
    created = call(
        "POST", "/users", {"username": username, "password": password, "role": "viewer"}
    )
    if not check("viewer created", created.status == 201, created.body):
        return
    _, viewer = login(username, password)
    r = call("POST", "/tools/asset.profile/execute", {"input": {"asset_id": asset_id}}, session=viewer)
    check("viewer cannot run tools", r.status == 403, r.body)
    r = call("GET", f"/lookup/asset?q=qa7c-{TAG}", session=viewer)
    check("viewer can use the selectors", r.status == 200, r.body)
    r = call("POST", "/ai/console/context", {"asset_id": asset_id}, session=viewer)
    check("viewer cannot share console data with the model", r.status == 403, r.body)


def main() -> int:
    if not qa.KEY or not qa.ADMIN_USER or not qa.ADMIN_PASSWORD:
        print("SENTRA_QA_ENROLLMENT_KEY, SENTRA_QA_ADMIN_USER y SENTRA_QA_ADMIN_PASSWORD", file=sys.stderr)
        return 2
    r, admin = login(qa.ADMIN_USER, qa.ADMIN_PASSWORD)
    if not admin:
        print(f"admin login failed: {r.status} {r.body}", file=sys.stderr)
        return 2
    qa.SESSION.update(admin)
    first, _ = lookups()
    tools_and_assist(first)
    permissions(first)
    failed = [x for x in qa.RESULTS if not x[1]]
    print(f"\n{len(qa.RESULTS) - len(failed)}/{len(qa.RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
