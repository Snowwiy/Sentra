# Playbooks (Fase 5D)

Un playbook es una lista ordenada y declarativa de acciones del catálogo del
[Response Engine](response-engine.md). No es un script: no hay variables, plantillas,
expresiones, bucles, condiciones, `eval` ni Jinja. Cada paso es un `action_id` con
parámetros validados por el modelo de la acción y dos decisiones de un conjunto cerrado.

## Formato de un paso

```json
{
  "action_id": "reevaluate_detections",
  "parameters": {"hours": 24},
  "on_success": "continue",
  "on_failure": "stop",
  "timeout_seconds": 120
}
```

- `on_success`: `continue` (defecto) o `stop`.
- `on_failure`: `stop` (defecto, **fail-stop**) o `continue`. `continue` solo se admite en
  pasos LOW (lecturas y reevaluaciones): seguir tras el fallo de una mutación podría dejar el
  caso a medias. El servidor lo rechaza con 422 `playbook_unsafe_continue`.
- `timeout_seconds`: 10-3600; por defecto el de la acción (para acciones de agente manda la
  cola: TTL + lease).
- Máximo 10 pasos y 10 parámetros por paso. Solo acciones disponibles con objetivo activo.

El riesgo del playbook es el máximo de sus pasos, el rol necesario el que tenga todos los
permisos de todos los pasos, y pide confirmación si algún paso la pide.

## Versionado

Crear un playbook (admin) genera la versión 1 con clave `custom_<hex>`. Cada edición
(`PATCH` con `revision` para la concurrencia optimista; 409 si otro admin editó antes) crea
una versión nueva en `playbook_versions`; nunca se modifica una versión existente.

Cada ejecución (`playbook_runs`) guarda una copia inmutable de clave, nombre, versión y pasos
usados: el historial muestra exactamente lo que se ejecutó aunque el playbook cambie o se
desactive después.

Los built-in viven en código (`app/response/playbooks.py`) y se sincronizan con la base al
leer el catálogo; no se pueden editar desde la API (sí activar/desactivar). Cambiar sus pasos
en una versión nueva de Sentra exige subir su `version`.

## Built-in

| Clave | Pasos | Riesgo / rol |
|-------|-------|--------------|
| `investigate_endpoint` | inventario, procesos, eventos (agente), reevaluar detecciones, recalcular riesgo, timeline | LOW / analyst |
| `refresh_asset_analysis` | refrescar contexto de amenaza, reevaluar detecciones, recalcular riesgo, resumen de evidencia (sin agente) | LOW / analyst |
| `investigate_detection` | timeline, reevaluar detecciones, recalcular riesgo, resumen de evidencia (sin agente) | LOW / analyst |

## Ejecución

1. `POST /response/playbooks/{id}/preview`: evalúa cada paso con la misma política que la
   ejecución y devuelve los bloqueos por paso. Sin efectos.
2. `POST /response/playbooks/{id}/execute`: comprueba permisos de todos los pasos, el
   preflight y la confirmación; crea el run (`running`) o lo guarda como `blocked` (409).
   Un run vivo igual (playbook + activo) se devuelve en lugar de crear otro; admite
   `idempotency_key`.
3. El motor avanza paso a paso: los pasos de servidor se ejecutan en la misma petición; uno de
   agente deja el run esperando y lo continúa el resultado del agente o el barrido.
4. Antes de cada paso se vuelve a comprobar que el usuario sigue activo y con los permisos
   (`actor_inactive`, `permission_revoked`) y se evalúa la política en ese momento.

Cada paso tiene como mucho una ejecución (índice único `(playbook_run_id, step_index)`) y el
avance usa `version` optimista: dos procesos que avanzan el mismo run no duplican pasos.

Estados del run: `running`, `succeeded`, `failed` (`step_failed`, `step_timed_out`,
`step_blocked`...), `cancelled`, `blocked`. Cancelar un run (`response:manage`) cancela el
paso vivo y sus comandos.

## Integración con incidentes y detecciones

Con `incident_id` el run y sus ejecuciones quedan en el timeline del incidente
(`playbook_started`, `playbook_succeeded`/`failed`/`cancelled`, `response_*`). Con
`detection_id` se comprueba que la detección es del activo objetivo.

## RBAC

| Operación | Permiso |
|-----------|---------|
| Ver playbooks y runs | `response:read` (todos los roles) |
| Preview y ejecutar | `response:execute` + permisos de todos los pasos |
| Crear, editar, activar, desactivar, cancelar runs | `response:manage` (admin) |
