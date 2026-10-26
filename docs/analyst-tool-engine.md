# Analyst Tool Engine (Fase 7A)

El Analyst Tool Engine es la capa de herramientas deterministas que usa el analista (y, más
adelante, la Analyst Console de 7B y el modelo local de 7C) para investigar y actuar. Cada
herramienta hace una sola cosa sobre datos que Sentra ya tiene, o delega una sola acción en
el Response Engine o en el servicio de casos.

No es un intérprete: no existe ninguna herramienta que acepte comandos, scripts, SQL, URLs,
plantillas ni nombres de función arbitrarios, y no se pueden registrar herramientas desde la
API. El registro es código revisado (`backend/app/tools/catalog.py`).

## Garantías

| Garantía | Cómo se cumple |
| --- | --- |
| Registro cerrado | `TOOLS` en `app/tools/catalog.py`; `validate_registry` se ejecuta al importar y en los tests. |
| Sin código en la entrada | Modelos de entrada `extra=forbid`; `validate_registry` rechaza campos llamados `command`, `cmd`, `script`, `shell`, `exec`, `code`, `sql`, `url`, `template`, `args` y similares, también anidados. |
| RBAC en el backend | `tools:execute` más los permisos de dominio de cada herramienta, comprobados en cada petición. Un rechazo deja una fila `rejected` (sin la entrada) y un evento `permission_denied` en la auditoría. |
| Alcance | El activo o el caso de la entrada debe existir y, si se pide `site_id`, pertenecer a ese site (404 en otro caso, sin revelar que existe). |
| Lecturas sin efectos | Cada lectura corre en una conexión propia con `SET TRANSACTION READ ONLY` y `statement_timeout`; un intento de escritura falla con `tool_database_error`. |
| Plazo y cancelación | `statement_timeout` por herramienta; el PID de PostgreSQL se guarda en la fila y `cancel` llama a `pg_cancel_backend` solo para ese PID. |
| Causa de una cancelación | PostgreSQL usa el mismo SQLSTATE (57014) para el plazo y para `pg_cancel_backend`, y su mensaje depende del idioma del servidor, así que nunca se lee. `cancel` confirma `cancelled` antes de cancelar la consulta: si la fila dice `cancelled`, fue una persona (`tool_cancelled`); si no y pasó el plazo, `timed_out` (`tool_timeout`); cualquier otra cancelación (un DBA, un reinicio) queda `failed` con `tool_query_cancelled`. |
| Concurrencia | Límite por usuario y global, contado bajo un advisory lock (`TOOL_CONCURRENCY_LOCK_KEY`), y rate limit por usuario. 429 con `Retry-After`. |
| Duplicados | Clave de idempotencia del cliente y un índice único parcial que impide dos ejecuciones idénticas en curso del mismo usuario. |
| Recuperación | Una fila `running` cuyo plazo venció hace más de 2 minutos (proceso caído) se cierra como `failed`/`interrupted`; una vista previa caducada pasa a `expired`. Lo hace el job `response-engine` y cada nueva ejecución. |
| Acciones con aprobación | Toda herramienta de categoría `action` es `preview_confirm`: primero una vista previa sin efectos, después `confirm` con `confirm: true`, la versión y la MISMA entrada guardada. Queda quién aprobó, cuándo y la nota. |
| Evidencia verificable | Salida validada contra el modelo de salida, SHA-256 del JSON canónico, referencias a los registros originales y procedencia (fuentes, ventana, versión). Por encima de `ANALYST_TOOLS_RESULT_MAX_KB` se guarda un marcador con el tamaño y el hash, nunca un JSON cortado. |
| Auditoría | `tool_executed`, `tool_preview_generated`, `tool_action_approved`, `tool_execution_cancelled` y `permission_denied`. |

La contención (aislar y liberar un equipo) no se puede delegar desde las herramientas: tiene
su propio flujo con doble confirmación (docs/safe-isolation.md).

## Herramientas

| Id | Categoría | Riesgo | Política | Permisos | Plazo | Qué hace |
| --- | --- | --- | --- | --- | --- | --- |
| `asset.lookup` | read | none | direct | monitoring:read, tools:execute | 15 s | Busca activos por IP, MAC, nombre o etiqueta dentro del site pedido. |
| `asset.profile` | read | none | direct | monitoring:read, tools:execute | 15 s | Identidad, estado, agente, riesgo y contadores de trabajo abierto. |
| `asset.history` | read | none | direct | monitoring:read, tools:execute | 15 s | Cambios de inventario, red y estado, más el historial de identidad. |
| `telemetry.recent` | read | none | direct | monitoring:read, tools:execute | 15 s | Últimas muestras de CPU, RAM, disco y red del agente. |
| `process.tree` | read | none | direct | monitoring:read, telemetry:read, tools:execute | 15 s | Un nivel del árbol de procesos, en un instante o reciente; búsqueda por nombre, ruta o PID. |
| `process.instance` | read | none | direct | monitoring:read, telemetry:read, tools:execute | 15 s | Una instancia de proceso con su cadena de antecesores, usuario, firma, hash y conexiones. |
| `events.search` | read | none | direct | monitoring:read, tools:execute | 15 s | Eventos del activo en una ventana acotada (máximo 7 días), por nivel, canal o código. |
| `detections.search` | read | none | direct | monitoring:read, tools:execute | 15 s | Detecciones y correlaciones por activo, estado, severidad, regla o ventana. |
| `detections.get` | read | none | direct | monitoring:read, tools:execute | 15 s | Una detección con su explicación, evidencias, timeline y contexto. |
| `vulnerabilities.assess` | read | none | direct | monitoring:read, vulnerabilities:read, tools:execute | 15 s | Findings del activo por prioridad, con estado técnico, KEV y EPSS. |
| `exposure.ports` | read | none | direct | monitoring:read, tools:execute | 15 s | Puertos con su servicio y el proceso propietario si hay agente. |
| `risk.explain` | read | none | direct | monitoring:read, tools:execute | 15 s | Score, nivel, confianza y ledger de contribuciones. |
| `timeline.build` | read | none | direct | monitoring:read, tools:execute | 15 s | Detecciones, alertas, cambios y eventos en orden cronológico (máximo 200). |
| `topology.changes` | read | none | direct | monitoring:read, tools:execute | 15 s | Cambios de red de un site o de un activo. |
| `identity.evidence` | read | none | direct | monitoring:read, tools:execute | 15 s | Por qué Sentra cree que el dispositivo es lo que dice: nombres, fabricante, DHCP, huellas y conflictos. |
| `operations.history` | read | none | direct | monitoring:read, tools:execute | 15 s | Ejecuciones anteriores de herramientas y de Response del activo o del caso. |
| `discovery.scan_host` | investigation | low | direct | monitoring:read, discovery:run, response:execute, tools:execute | 30 s | Discovery de un host dentro de las redes autorizadas (acción `start_discovery`). |
| `forensics.collect` | investigation | low | direct | monitoring:read, forensics:acquire, response:execute, tools:execute | 30 s | Recogida forense de solo lectura dentro de una investigación abierta. |
| `response.prepare` | investigation | none | direct | monitoring:read, response:execute, tools:execute | 15 s | Vista previa de una acción de Response (efecto, bloqueos, rol). No ejecuta nada. |
| `response.execute` | action | medium | preview_confirm | monitoring:read, response:execute, tools:execute | 60 s | Ejecuta una acción de Response tras vista previa y confirmación (nunca contención). |
| `case.open` | action | low | preview_confirm | incidents:read, incidents:manage, tools:execute | 15 s | Abre un caso desde una detección, alerta, vulnerabilidad o activo, o reutiliza el activo; lo asigna. |
| `case.link_evidence` | action | low | preview_confirm | incidents:read, incidents:manage, tools:execute | 15 s | Añade una detección, alerta, activo o ejecución de herramienta a un caso abierto. |

Las herramientas que delegan en Response heredan su política completa: rol según el riesgo de
la acción (una acción MEDIUM exige `response:manage`), agente en línea, capacidades,
idempotencia y auditoría propias. Si Response deniega algo, la herramienta responde con el
mismo código HTTP y la fila queda `failed` con ese código.

## API

Todas las rutas usan la sesión del dashboard con CSRF.

| Método y ruta | Permiso | Descripción |
| --- | --- | --- |
| `GET /api/v1/tools` | tools:read | Catálogo con esquemas de entrada y salida, permisos, rol mínimo, riesgo, política, plazo, disponibilidad y `permitted` para el usuario. |
| `GET /api/v1/tools/{tool_id}` | tools:read | Una herramienta. |
| `POST /api/v1/tools/{tool_id}/execute` | tools:execute | Lecturas e investigaciones. Una acción responde 422 `tool_preview_required`. |
| `POST /api/v1/tools/{tool_id}/preview` | tools:execute | Vista previa de una acción (estado `previewed`). |
| `POST /api/v1/tools/executions/{id}/confirm` | tools:execute | `{version, confirm: true, note?}`. Ejecuta la vista previa vigente. |
| `POST /api/v1/tools/executions/{id}/cancel` | tools:execute | Cancela una vista previa o una ejecución en curso; en una acción delegada, cancela la ejecución de Response (con `response:manage`). |
| `GET /api/v1/tools/executions` | tools:read | Historial (propio; todos con tools:manage y `mine=false`). |
| `GET /api/v1/tools/executions/{id}` | tools:read | Detalle con entrada, salida, hashes, evidencia, procedencia y aprobación. |

Cuerpo de `execute` y `preview`:

```json
{
  "input": {"asset_id": "8f0c..."},
  "site_id": null,
  "incident_id": null,
  "idempotency_key": "consola-0001"
}
```

Errores propios: `tools_disabled` (409), `tool_unavailable` (409), `tool_invalid_input` (422,
con `loc` y `type` de cada error, nunca el valor), `tool_preview_required` (422),
`tool_preview_not_applicable` (422), `confirmation_required` (422), `tool_invalid_state`
(409), `tool_concurrency_limit` (429) y `rate_limited` (429).

Estados de una ejecución: `previewed`, `running`, `succeeded`, `failed`, `cancelled`,
`timed_out`, `rejected` y `expired`.

## Contrato para 7B y 7C

- El catálogo publica JSON Schema de entrada y salida: una consola o un modelo puede
  construir la petición sin conocer el código.
- `invoker` es siempre `user` en 7A. Una consola o un modelo futuros ejecutarán en nombre de
  un usuario concreto y con sus permisos: no hay permisos implícitos ni cuenta de servicio.
- Un modelo nunca puede saltarse la vista previa: `execute` rechaza las acciones, y `confirm`
  exige `confirm: true` explícito de un usuario con los permisos de la herramienta.
- La salida es estructurada, acotada y con hash: un modelo puede citar la evidencia por su id
  y cualquiera puede comprobar después que la salida no cambió.

## Configuración

| Variable | Defecto | Uso |
| --- | --- | --- |
| `ANALYST_TOOLS_ENABLED` | true | Apaga el motor entero (409 `tools_disabled`). |
| `ANALYST_TOOLS_MAX_CONCURRENT_PER_USER` | 3 | Ejecuciones simultáneas por usuario. |
| `ANALYST_TOOLS_MAX_CONCURRENT` | 12 | Ejecuciones simultáneas en todo el servidor. |
| `ANALYST_TOOLS_PER_USER_PER_MINUTE` | 60 | Peticiones por usuario y minuto. |
| `ANALYST_TOOLS_RESULT_MAX_KB` | 256 | Tamaño máximo de la salida guardada. |
| `ANALYST_TOOLS_PREVIEW_TTL_MINUTES` | 15 | Caducidad de una vista previa. |
| `ANALYST_TOOLS_RETENTION_DAYS` | vacío | Días de historial; vacío = sin purga. Nunca se purga lo vinculado a un caso. |

## Datos

Tabla `tool_executions` (migración 0044). Es evidencia SOC: no se borra salvo con la
retención opt-in. El downgrade elimina la tabla; la auditoría `tool_*` se conserva.

## Limitaciones conocidas

- Las investigaciones y acciones corren en la sesión de la petición: su `statement_timeout`
  acota cada transacción, pero la cancelación con `pg_cancel_backend` solo se aplica a las
  lecturas (las delegaciones se cancelan en el Response Engine).
- No hay doble aprobación (cuatro ojos): se registra quién aprobó. Si se necesita, es una
  decisión de producto para una fase posterior.
