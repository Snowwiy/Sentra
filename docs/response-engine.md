# Response Engine (Fase 5D)

Capa única de respuesta de Sentra: acciones estructuradas sobre activos e incidentes, con
preview, ejecución manual, seguimiento de estado, resultados acotados y auditoría completa.
Todo lo que lanza una acción (API, UI, playbooks y el barrido periódico) pasa por
`backend/app/services/response_service.py`. No hay otra ruta de ejecución.

Principios:

- **Sin shell ni comandos arbitrarios.** Una acción se pide por `action_id` de un catálogo
  cerrado y sus parámetros los valida el modelo pydantic de esa acción (`extra=forbid`). No
  existe ningún campo de comando, script, ruta, URL o plantilla, ni en la API ni en la
  cola del agente.
- **Solo manual.** Ninguna regla, detección, alerta ni IA lanza acciones. No existe modo de
  automatización (por eso no hay `RESPONSE_AUTOMATION_ENABLED`).
- **Una sola política.** `app/response/policy.py:evaluate` decide los bloqueos y avisos; la
  usan el preview, la ejecución y cada paso de playbook, siempre en el momento (nunca se
  confía en un preview anterior).
- **Nunca un éxito falso.** Una acción de agente solo termina `succeeded` cuando el agente
  devuelve un resultado de un comando que se le entregó.

## Arquitectura

```
UI / API / tools.py ──► ResponseService ──► policy.evaluate (bloqueos, avisos)
                              │
                ┌─────────────┴───────────────┐
        acción de servidor              acción de agente
   handler (handlers.py) en la      AgentCommand en cola (TTL)
   misma petición, con plazo          │  heartbeat: pending_commands
                                       ▼
                       POST /agents/commands/poll  (token del agente)
                       POST /agents/commands/{request_id}/result
                              │
             barrido "response-engine" (cada 15 s, advisory lock):
             TTL, leases, reentrega única, plazos, agente reasignado,
             activo archivado, avance de playbooks
```

Ficheros:

| Fichero | Qué contiene |
|---------|--------------|
| `app/response/catalog.py` | `ActionDefinition` y el catálogo `ACTIONS`; modelos de parámetros |
| `app/response/policy.py` | `evaluate`: bloqueos/avisos/precondiciones |
| `app/response/handlers.py` | handlers de servidor (reutilizan los motores existentes) |
| `app/response/results.py` | saneado y límite de tamaño de resultados |
| `app/response/playbooks.py` | validación de pasos y playbooks built-in |
| `app/response/tools.py` | registro cerrado de herramientas para la futura Analyst Console |
| `app/services/response_service.py` | motor: ejecución, cola, barrido, playbooks |
| `app/api/v1/routes/response.py` | API `/api/v1/response/*` |
| `app/models/response.py` | tablas (migración 0030) |

## Modelo de acción

Cada `ActionDefinition` define: `id`, `name`, `description`, `category`, `scope`
(`server`/`agent`), `target_type` (`asset`/`incident`), `risk_level`, permisos de dominio,
`required_role` (derivado del rol mínimo que tiene todos los permisos), `destructive`,
`requires_confirmation`, `requires_agent`, `supported_platforms`, `timeout_seconds`,
`retry_policy` (derivada de `max_deliveries`), `parameters_schema` (JSON Schema del modelo),
`expected_effect` (texto del preview), `precheck` opcional y `handler`.

Permisos efectivos de una acción = `response:execute` + permisos de dominio + (si es MEDIUM o
superior) `response:manage`. Así una acción nunca da más poder que la API del dominio.

### Catálogo inicial

| Acción | Ámbito | Riesgo | Rol | Notas |
|--------|--------|--------|-----|-------|
| `collect_inventory` | agente | LOW | analyst | Inventario completo (incluye interfaces y conexiones: cubre el "network snapshot") |
| `collect_processes` | agente | LOW | analyst | Instantánea de procesos |
| `collect_events` | agente | LOW | analyst | Envío inmediato de eventos pendientes (Windows/Linux) |
| `collect_telemetry` | agente | LOW | analyst | Muestra de telemetría inmediata |
| `collect_diagnostics` | agente | LOW | analyst | Estado del agente, sin secretos |
| `recalculate_risk` | servidor | LOW | analyst | Motor 4I |
| `reevaluate_detections` | servidor | LOW | analyst | Motor 4H sobre las señales recientes del activo (`hours`) |
| `refresh_threat_context` | servidor | LOW | analyst | Marca el activo para el motor 5B/5C |
| `reevaluate_vulnerabilities` | servidor | LOW | admin | Requiere `vulnerabilities:admin` (política 5B) |
| `start_discovery` | servidor | LOW | analyst | Scan de la IP del activo dentro de las redes permitidas |
| `collect_timeline` | servidor | LOW | analyst | Detecciones, alertas, cambios y eventos (acotado); admite archivados |
| `collect_response_bundle` | servidor | LOW | analyst | Resumen de evidencia del activo; admite archivados |
| `open_incident` | servidor | MEDIUM | admin | Desde una detección reutiliza el caso existente |
| `add_incident_note` | servidor | MEDIUM | admin | Objetivo: incidente abierto |
| `archive_asset` | servidor | MEDIUM | admin | Misma puerta 5C.1 (exige credencial revocada) |
| `isolate_host` | — | CRITICAL | — | `not_implemented`, sin handler |
| `kill_process` | — | HIGH | — | `not_implemented`, sin handler |
| `block_network_address` | — | HIGH | — | `not_implemented`, sin handler |

`refresh_asset_context` no se implementa: el contexto 4L es dato manual de un admin; no hay
nada que "refrescar" sin inventarlo.

Las acciones `not_implemented` aparecen en el catálogo (para que el diseño sea visible) pero
no tienen handler ni tipo de comando: la política las bloquea siempre y un playbook no puede
incluirlas.

## Estados

`pending` → (`queued` → `running`) → `succeeded` | `failed` | `cancelled` | `timed_out`.
`blocked` cuando la política lo impide (se guarda como evidencia y la API responde 409
`response_blocked` con el `execution_id` y los bloqueos). `approval_required` existe en el
modelo para una futura aprobación de dos personas; en 5D ninguna acción lo usa.

## Preview

`POST /response/preview` devuelve `action`, `target_label`, `parameters` normalizados,
`risk_level`, `required_role`, `requires_confirmation`, `requires_agent`, `expected_effect`,
`preconditions` (comprobaciones superadas), `blockers`, `warnings` y `allowed`. No tiene
efectos salvo la auditoría `response_preview_generated` de acciones mutativas.

Bloqueos posibles: `response_disabled`, `action_not_implemented`, `target_missing`,
`asset_archived`, `detection_mismatch`, `no_agent`, `agent_credential_inactive`,
`unsupported_platform`, `agent_capabilities_unknown`, `unsupported_capability`,
`agent_offline`, `incident_closed`, `too_many_active`, más los `precheck` de cada acción
(`discovery_disabled` en `start_discovery`, `agent_active` en `archive_asset`,
`incident_closed` en `add_incident_note`).

Un 403 de permisos no es un bloqueo: se comprueba antes de mirar el objetivo, para no revelar
nada de él a quien no puede actuar.

## Idempotencia y deduplicación

- `idempotency_key` opcional (una por diálogo en la UI): repetir la petición devuelve la misma
  ejecución (`deduplicated: true`); reutilizarla para otra petición es 409. Índice único
  parcial `(actor_user_id, idempotency_key)`.
- `dedupe_key` = acción + objetivo: mientras haya una ejecución viva igual, se devuelve esa
  (índice único parcial sobre las vivas). Dos peticiones simultáneas crean una sola fila.
- `open_incident` desde una detección ya ligada devuelve el incidente existente.
- Un resultado repetido del agente responde `duplicate: true` y no cambia nada.

## Cola de comandos del agente

Ver [agent-response.md](agent-response.md). Resumen: tipos cerrados, sin parámetros, TTL
(`RESPONSE_COMMAND_TTL_MINUTES`), lease por entrega, como mucho una reentrega para acciones
idempotentes, autenticación por agente, ningún acceso entre activos.

## Linaje 5C.2

El comando guarda `asset_id` y `agent_id` del agente actual del activo. El poll solo entrega
comandos cuyo `agent_id` coincide con el agente actual del activo autenticado. Tras una
reconciliación, el activo canónico pasa a tener el agente actual (y sus capacidades); el
barrido cancela (`agent_reassigned` o `asset_archived`) lo que quedara pendiente para el
activo origen. Un agente histórico o revocado no autentica y la política lo bloquea
(`agent_credential_inactive`).

## Resultados

`results.bounded_result` reduce el resultado a JSON simple: tipos básicos, profundidad 6,
claves de 64, cadenas de 2000, listas de 500, 200 claves, sin caracteres de control, enteros
fuera de ±2^53 como texto. Si supera `RESPONSE_RESULT_MAX_KB` se sustituye por
`{"truncated": true, ...}` en lugar de guardarlo cortado. La UI lo muestra siempre como texto.

## Auditoría

Acciones: `response_preview_generated`, `response_execution_created` (incluye bloqueadas con
`denied`), `response_started`, `response_completed`, `response_failed`, `response_cancelled`,
`playbook_created`, `playbook_updated`, `playbook_enabled`, `playbook_disabled`,
`playbook_executed`, `playbook_run_finished`, y `permission_denied`. Los detalles llevan ids
(ejecución, correlación, objetivo, run), acción, estado, error y SOLO los nombres de los
parámetros (una nota puede contener texto sensible). Nunca tokens ni identidades de máquina.

Las ejecuciones lanzadas con contexto de incidente escriben también en su timeline
(`response_requested`, `response_blocked`, `response_completed`, `response_failed`,
`response_cancelled`, `playbook_*`).

## Configuración

| Variable | Defecto | Uso |
|----------|---------|-----|
| `RESPONSE_ENABLED` | `true` | Apaga todo el motor (409 `response_disabled`, heartbeat sin comandos) |
| `PLAYBOOKS_ENABLED` | `true` | Apaga solo los playbooks |
| `RESPONSE_COMMAND_TTL_MINUTES` | `15` | Vida de un comando en cola (1-1440) |
| `RESPONSE_COMMAND_LEASE_SECONDS` | `300` | Tope del lease de cada entrega (30-3600) |
| `RESPONSE_RESULT_MAX_KB` | `64` | Tamaño máximo del resultado guardado (1-512) |
| `RESPONSE_OFFLINE_AGENT_POLICY` | `block` | `block` o `queue` (encolar con TTL y aviso) |
| `RESPONSE_MAX_ACTIVE_PER_ASSET` | `10` | Ejecuciones vivas por activo (1-100) |
| `RESPONSE_SWEEP_INTERVAL_SECONDS` | `15` | Intervalo del barrido (5-3600) |

Retención: indefinida (sin `RESPONSE_RETENTION_DAYS`): el historial de respuesta es
evidencia. Los tests fijan estos valores en `tests/conftest.py`.

## API

| Método | Ruta | Permiso |
|--------|------|---------|
| GET | `/response/actions?asset_id=` | `response:read` |
| POST | `/response/preview` | `response:execute` (+ permisos de la acción) |
| POST | `/response/executions` | `response:execute` (+ permisos de la acción) |
| GET | `/response/executions` (`status`, `action_id`, `asset_id`, `incident_id`, `run_id`, `limit`, `offset`) | `response:read` |
| GET | `/response/executions/{execution_id}` | `response:read` |
| POST | `/response/executions/{execution_id}/cancel` | `response:manage` |
| GET/POST | `/response/playbooks` | `response:read` / `response:manage` |
| GET/PATCH | `/response/playbooks/{playbook_id}` | `response:read` / `response:manage` |
| POST | `/response/playbooks/{playbook_id}/enable` y `/disable` | `response:manage` |
| POST | `/response/playbooks/{playbook_id}/preview` y `/execute` | `response:execute` (+ permisos de los pasos) |
| GET | `/response/runs`, `/response/runs/{run_id}` | `response:read` |
| POST | `/response/runs/{run_id}/cancel` | `response:manage` |
| POST | `/agents/commands/poll` | token del agente |
| POST | `/agents/commands/{request_id}/result` | token del agente |

## Analyst Console (preparación)

`app/response/tools.py` expone un registro cerrado: `response.list_actions`,
`response.preview`, `response.execute`, `response.status`, `playbooks.list`,
`playbooks.preview`, `playbooks.execute`. Cada herramienta valida sus argumentos con los
modelos de la API y llama al mismo `ResponseService` con un operador humano (su rol, su
auditoría). No hay chat, NLP ni LLM, ni herramientas genéricas.

## Modos de fallo

| Situación | Resultado |
|-----------|-----------|
| Agente offline | `blocked` (`agent_offline`) o, con política `queue`, `queued` con TTL |
| Agente no recoge el comando | `timed_out` (`command_expired`) |
| Agente no responde tras la entrega | una reentrega si la acción lo permite; después `timed_out` (`agent_timeout`) |
| Proceso del servidor cae a mitad de un handler | `timed_out` (`deadline_exceeded`) por el barrido |
| Activo archivado con comandos pendientes | `cancelled` (`asset_archived`) |
| Agente reasignado por reconciliación | `cancelled` (`agent_reassigned`) |
| Resultado tardío / cancelado | `accepted: false`, no reabre nada |
| Resultado duplicado | `duplicate: true` |
| Resultado de otro agente | 404 `command_not_found` |
| Resultado de un comando no entregado | 409 |
| Excepción inesperada en un handler | `failed` (`internal_error`), sin texto interno |

## QA manual

1. Como analyst, en un activo con agente 0.3.0 en línea: Response → `collect_inventory` →
   preview sin bloqueos → ejecutar → `queued` → `running` → `succeeded` en menos de un ciclo.
2. Parar el servicio del agente y repetir: `blocked (agent_offline)`.
3. Como admin, `open_incident` desde una detección: pide confirmación; repetir no crea otro.
4. Como viewer: el catálogo se ve, los botones de ejecutar no aparecen y la API da 403.
5. Reconciliar un activo con un comando pendiente (5C.2): el comando se cancela; uno nuevo va
   al agente actual.
