"""7C-Fix2: AI Security Insights contra una API EN MARCHA y su modelo (real o simulado).

Pide un análisis de un equipo de QA y dice qué pasó. Con ai_invalid_response enseña el motivo
que ahora devuelve el servidor (sin contenido del modelo), para saber si hay que desactivar el
razonamiento (AI_REASONING_EFFORT=none) o ampliar AI_MAX_OUTPUT_TOKENS.

Mismo entorno que qa/e2e_console_assist.py (instancia QA, nunca producción):

    set SENTRA_QA_API_URL=http://127.0.0.1:8000
    set SENTRA_QA_ENROLLMENT_KEY=<AGENT_ENROLLMENT_KEY de esa API>
    set SENTRA_QA_ADMIN_USER=<admin>
    set SENTRA_QA_ADMIN_PASSWORD=<contraseña>
    python qa/e2e_ai_insights_reasoning.py                      # espera un análisis válido
    python qa/e2e_ai_insights_reasoning.py --expect truncated_reasoning

Con qa/console_assist_fake_llm.py --mode llamacpp: sin AI_REASONING_EFFORT el motivo es
truncated_reasoning; con AI_REASONING_EFFORT=none, análisis válido.
"""

import argparse
import sys
import uuid

import e2e_api as qa
from e2e_api import call, check, login

REASONS = {
    "truncated_reasoning": "el modelo agotó AI_MAX_OUTPUT_TOKENS razonando: pruebe AI_REASONING_EFFORT=none",
    "truncated": "respuesta cortada por AI_MAX_OUTPUT_TOKENS: amplíe el límite",
    "reasoning_only": "solo razonamiento, sin respuesta: pruebe AI_REASONING_EFFORT=none",
    "empty_answer": "respuesta vacía del servidor",
    "invalid_json": "el modelo no devolvió JSON (¿AI_JSON_MODE desactivado o plantilla de chat?)",
    "schema_mismatch": "JSON sin la estructura RawInsight (modelo demasiado pequeño o mal prompt)",
    "unexpected_body": "el servidor no responde como la API de chat de OpenAI",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", default="ok", choices=["ok", *REASONS])
    args = parser.parse_args()
    if not qa.KEY or not qa.ADMIN_USER or not qa.ADMIN_PASSWORD:
        print("SENTRA_QA_ENROLLMENT_KEY, SENTRA_QA_ADMIN_USER y SENTRA_QA_ADMIN_PASSWORD", file=sys.stderr)
        return 2
    r, admin = login(qa.ADMIN_USER, qa.ADMIN_PASSWORD)
    if not admin:
        print(f"admin login failed: {r.status} {r.body}", file=sys.stderr)
        return 2
    qa.SESSION.update(admin)
    status = call("GET", "/ai/status")
    check("AI available", status.status == 200 and status.body.get("available") is True, status.body)
    agent_id = str(uuid.uuid4())
    r = call("POST", "/agents/register", qa.host(agent_id, f"qa7cfix2-{agent_id[:6]}"), {"X-Enrollment-Key": qa.KEY})
    if not check("QA asset enrolled", r.status == 201, r.body):
        return 1
    r = call("POST", f"/ai/assets/{r.body['asset_id']}/analyze", {"refresh": True})
    error = (r.body or {}).get("error", {}) if r.status != 200 else {}
    details = error.get("details") or [{}]
    reason = details[0].get("reason") if isinstance(details[0], dict) else None
    print(f"HTTP {r.status} {error.get('code', 'ok')} reason={reason}")
    if reason in REASONS:
        print(f"  -> {REASONS[reason]}")
    if args.expect == "ok":
        result = (r.body or {}).get("result", {}) if r.status == 200 else {}
        check("insight is a valid RawInsight from the model", r.status == 200 and bool(result.get("summary")), error)
        check("insight cites Sentra evidence or says data is insufficient", bool(result.get("evidence_refs")) or result.get("insufficient_data") is True, result)
    else:
        check(f"failure reason is {args.expect}", r.status == 502 and reason == args.expect, r.body)
    failed = [x for x in qa.RESULTS if not x[1]]
    print(f"\n{len(qa.RESULTS) - len(failed)}/{len(qa.RESULTS)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
