# Sentra: coordinación multiagente

La política completa está en `.claude/orchestration/routing.json`. No cambies modelos ni esfuerzos sin autorización de Jesus.

## Roles
- **Coordinador**: Claude Code (esta sesión). Analiza, fija contratos, delega e integra. Las tareas triviales las resuelve directamente.
- **Frontend**: subagente `sentra-frontend` (Claude Opus 5.5, esfuerzo medium). Dueño de `frontend/**`.
- **Backend**: subagente `sentra-backend` → Codex `gpt-5.6-terra`, esfuerzo xhigh. Dueño de `backend/**`, `agent/**`, `integrations/**`.
- **Operaciones**: subagente `sentra-ops` → Codex `gpt-6-luna`, esfuerzo xhigh. Dueño de `scripts/**`, `deploy/**`, `qa/**`. Primera opción para diagnóstico.
- **Jev** (MCP de TypeSafe): juicios rápidos, no ejecuta agentes. `jev_classify` cuando la ruta de una tarea no sea obvia; `jev_gate` para verificar afirmaciones de cierre ("tests pasan") contra la evidencia antes de entregar.

## Flujo
1. Solo frontend → `sentra-frontend`. Solo backend → `sentra-backend`. Diagnóstico u operaciones → `sentra-ops`.
2. Fullstack: el coordinador escribe el contrato (endpoints, JSON, tipos, códigos de error) y lo pasa a backend y frontend; pueden ir en paralelo porque no comparten archivos. Después `sentra-ops` ejecuta pruebas y el coordinador integra.
3. Pasa a cada hilo solo el contrato, los archivos relevantes y los criterios de aceptación, nunca conversaciones completas.
4. Los hilos Codex reanudan su propia sesión (`.claude/orchestration/state/`). Para empezar uno limpio, `--fresh`.
5. No invoques los tres roles para tareas triviales ni hagas revisiones cruzadas innecesarias.

## Reglas fijas
- Nadie hace git commit, push, tags ni toca ramas remotas: solo Jesus.
- Comentarios y documentación nuevos en español; identificadores en inglés.
- Cada tarea termina con un bloque REVIEW BEFORE PUSH.
