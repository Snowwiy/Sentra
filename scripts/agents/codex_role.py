"""Ejecuta un rol Codex (backend u operaciones) con el modelo y esfuerzo fijados.

El modelo y el esfuerzo salen de .claude/orchestration/routing.json, nunca de
argumentos, para que ningún hilo los cambie sin autorización.

Cada rol mantiene su propio hilo de Codex: el id de sesión se guarda en
.claude/orchestration/state/<rol>.session y la siguiente llamada lo reanuda.
Así backend y operaciones conservan su continuidad sin mezclar historiales.

Uso:
    python3 scripts/agents/codex_role.py <backend|operaciones> [--fresh] "tarea"
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
ROUTING = REPO / ".claude" / "orchestration" / "routing.json"
STATE_DIR = REPO / ".claude" / "orchestration" / "state"

# Se antepone a cada tarea: Codex trabaja en el árbol local, pero las
# escrituras Git son exclusivas de Jesus (regla permanente del proyecto).
GUARD = (
    "Reglas fijas: no ejecutes git commit, git push, tags ni cambios de ramas o "
    "remotes. Trabaja solo en los archivos de tu responsabilidad: {owns}. "
    "Comentarios nuevos en español. Al terminar resume archivos tocados y pruebas.\n\n"
)


def git_head() -> str:
    # HEAD y refs locales: si cambian durante la ejecución, Codex hizo un commit.
    out = subprocess.run(
        ["git", "for-each-ref", "--format=%(objectname) %(refname)"],
        cwd=REPO, capture_output=True, text=True, check=False,
    )
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, capture_output=True, text=True, check=False
    )
    return head.stdout + out.stdout


def main(argv: list[str]) -> int:
    args = [a for a in argv if a != "--fresh"]
    fresh = len(args) != len(argv)
    if len(args) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    role_name, task = args
    roles = json.loads(ROUTING.read_text(encoding="utf-8"))["roles"]
    role = roles.get(role_name)
    if not role or role.get("provider") != "openai-codex":
        print(f"rol no Codex o desconocido: {role_name}", file=sys.stderr)
        return 2

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    session_file = STATE_DIR / f"{role_name}.session"
    session = None if fresh or not session_file.exists() else session_file.read_text().strip()

    config = [
        "-c", f'model_reasoning_effort="{role["effort"]}"',
        "-c", f'sandbox_mode="{role["sandbox"]}"',
    ]
    prompt = GUARD.format(owns=", ".join(role["owns"])) + task
    if session:
        cmd = ["codex", "exec", "resume", "--json", "-m", role["model"], *config, session, prompt]
    else:
        cmd = ["codex", "exec", "--json", "-m", role["model"], *config, "-C", str(REPO), prompt]

    before = git_head()
    proc = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, stdin=subprocess.DEVNULL, check=False)

    last_message, thread_id, usage = "", None, None
    for line in proc.stdout.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "thread.started":
            thread_id = event.get("thread_id")
        elif event.get("type") == "item.completed" and event["item"].get("type") == "agent_message":
            last_message = event["item"].get("text", "")
        elif event.get("type") == "turn.completed":
            usage = event.get("usage")

    if thread_id:
        session_file.write_text(thread_id)
    if git_head() != before:
        # No se revierte nada automáticamente: se avisa para que Jesus decida.
        print("ALERTA: las refs de Git cambiaron durante la ejecución de Codex.", file=sys.stderr)

    print(json.dumps({
        "role": role_name,
        "model": role["model"],
        "effort": role["effort"],
        "thread_id": thread_id or session,
        "resumed": bool(session),
        "exit_code": proc.returncode,
        "usage": usage,
        "result": last_message,
        "stderr_tail": proc.stderr[-1500:] if proc.returncode else "",
    }, ensure_ascii=False, indent=2))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
