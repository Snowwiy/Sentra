# Responsables, tareas y controles de red en los casos (Fase 7A.6)

Esta fase amplía la gestión de incidentes de la 4K ([incident-management.md](incident-management.md)).
No hay un motor de casos paralelo: las tareas y las solicitudes de control de red pertenecen a
un incidente, aparecen en su timeline y quedan en la auditoría.

## Responsable al crear el caso

Todas las formas de abrir un caso aceptan `owner_user_id` (id público del usuario):

| Origen | Ruta |
| --- | --- |
| Manual | `POST /api/v1/incidents` |
| Detección | `POST /api/v1/detections/{id}/incident` |
| Alerta | `POST /api/v1/alerts/{id}/incident` |
| Vulnerabilidad | `POST /api/v1/vulnerabilities/findings/{id}/incident` |
| Match de inteligencia | `POST /api/v1/threat-intel/matches/{id}/incident` |
| Riesgo de un activo (nuevo) | `POST /api/v1/assets/{asset_id}/risk/incident` |

Las reglas son las mismas que en `assign`: un analyst solo puede elegirse a sí mismo; un admin
puede elegir a cualquier analyst o admin activo; un viewer nunca es responsable. Si el
responsable no es válido, el caso no se crea (422 `incident_invalid_reference`).

### Caso desde el riesgo

Lo abre un analista mirando el riesgo de un activo, nunca el motor de riesgo. Exige un riesgo ya
calculado (409 `incident_invalid_state` si no) y que el activo no esté ya en un caso activo
abierto por riesgo (409 `incident_already_linked`). La gravedad sale del nivel (informational
cuenta como low), la confianza es la del cálculo y la descripción cita el score y los factores
principales del ledger.

## Tareas

Una tarea es trabajo humano dentro del caso: investigar un puerto expuesto, verificar un
servicio, revisar una vulnerabilidad, analizar evidencia, investigar un script, revisar
actividad de red, solicitar una política, verificar una corrección, preparar una regla de
bloqueo o documentar una excepción (`kind`).

**Asignar una tarea no ejecuta nada.** Una tarea cambia de estado, acumula evidencia y termina
con un resultado. Las acciones técnicas (herramientas, Response, aislamiento) tienen su propio
flujo con su vista previa y sus permisos; una tarea solo puede citar su ejecución como
evidencia.

| Estado | Puede pasar a |
| --- | --- |
| `open` | `in_progress`, `blocked`, `done`, `cancelled` |
| `in_progress` | `open`, `blocked`, `done`, `cancelled` |
| `blocked` | `open`, `in_progress`, `cancelled` |
| `done`, `cancelled` | `open` (reabrir) |

- `done` exige `result` (también lo comprueba la base de datos).
- Una tarea terminada o cancelada no se edita ni se reasigna sin reabrirla.
- Evidencia: referencias validadas en el servidor a detecciones, alertas, activos, findings,
  ejecuciones de herramientas (propias, del mismo caso o por un admin) y ejecuciones de
  Response. La etiqueta la pone el servidor. Como mucho 50 por tarea.
- `due_at` es opcional; `overdue` se calcula al leer.

### Quién puede qué

| Acción | Quién |
| --- | --- |
| Ver tareas | `incidents:read` |
| Crear | `incidents:manage` |
| Asignar a otra persona, reasignar | owner del caso o admin |
| Tomar una tarea sin responsable | cualquiera con `incidents:manage` (no viewer) |
| Trabajarla (estado, resultado, evidencia) | responsable, quien la creó, owner del caso o admin; si no tiene responsable, cualquiera con `incidents:manage` |
| Quitar responsable | el propio responsable, el owner del caso o un admin |

Los rechazos de política responden 403 `permission_denied` y quedan auditados como fallo.

## Solicitudes de control de red

Proponen una restricción y piden la decisión de un admin:

| Tipo | Objetivo | Sentido |
| --- | --- | --- |
| `block_port` | `{"port", "protocol": "tcp"\|"udp"}` | obligatorio |
| `block_service` | `{"service", "port"?}` | obligatorio |
| `block_address` | `{"cidr"}` (como mucho /16 en IPv4 y /48 en IPv6) | obligatorio |
| `block_domain` | `{"domain"}` (admite `*.` al principio) | saliente |
| `restrict_site_access` | `{"domain"}` | saliente |
| `prevent_upload` | `{"destination"}` | saliente |

El objetivo se valida y normaliza en el servidor: nada de claves extra, ni bloqueos demasiado
amplios (0.0.0.0/0, un /8, un TLD), ni loopback, multicast o comodines en mitad del dominio.
El alcance es un activo del caso, un site o, sin ninguno, toda la instalación. `expires_at` es
opcional (futuro, como mucho 365 días).

Estados: `pending_approval` → `approved` | `rejected` | `cancelled` | `expired`.

### Qué hace Sentra al aprobar

**Nada en la red.** Al aprobar se evalúan los puntos de control instalados capaces de aplicar
ese tipo. En 7A no hay ninguno: Sentra no integra firewalls, proxies, resolvedores DNS ni
gateways, y el agente no toca el firewall del host (el aislamiento es otro flujo, con helper
privilegiado y doble confirmación: [safe-isolation.md](safe-isolation.md)). La solicitud queda
`approved` con `enforcement_status = no_enforcement_point` y una explicación de lo que haría
falta:

| Tipo | Haría falta |
| --- | --- |
| Puerto, dirección | Firewall gestionable del host o perimetral integrado con Sentra |
| Servicio | Firewall o gestión de servicios del host integrada |
| Dominio | Resolvedor DNS o proxy integrado (un bloqueo solo DNS se salta con DoH/DoT o por IP) |
| Acceso a sitio | Proxy web o gateway con filtrado por dominio |
| Subidas | Proxy con inspección, gateway/DLP o agente con control de subidas; DNS solo no distingue una subida de una descarga |

`GET /api/v1/network-controls/capabilities` lo publica por tipo (`any_available: false`).

Si alguien aplica el control fuera de Sentra, un admin lo registra con `mark-applied`
(`applied_manually`, con quién, cuándo y dónde). Cancelar una solicitud aplicada manualmente
no la retira: el timeline avisa de que hay que retirarla en el punto de control.

Una instalación con un solo admin puede aprobar sus propias solicitudes; la respuesta lo marca
con `self_approved: true` y la auditoría lo registra.

**Nada se crea ni se aprueba solo.** Ni el motor de riesgo, ni las detecciones, ni la
clasificación de un dispositivo crean casos, tareas ni solicitudes (lo comprueba un test).

### API

| Método y ruta | Permiso |
| --- | --- |
| `GET /api/v1/network-controls` (`incident_id`, `status`, `control_type`) | incidents:read |
| `GET /api/v1/network-controls/capabilities` | incidents:read |
| `GET /api/v1/network-controls/{id}` | incidents:read |
| `POST /api/v1/incidents/{id}/network-controls` | incidents:manage |
| `POST /api/v1/network-controls/{id}/approve` `{version, note?}` | network_controls:approve |
| `POST /api/v1/network-controls/{id}/reject` `{version, note}` | network_controls:approve |
| `POST /api/v1/network-controls/{id}/cancel` `{version}` | quien la pidió o un aprobador |
| `POST /api/v1/network-controls/{id}/mark-applied` `{version, note}` | network_controls:approve |

Tareas:

| Método y ruta | Permiso |
| --- | --- |
| `GET /api/v1/incidents/{id}/tasks` | incidents:read |
| `POST /api/v1/incidents/{id}/tasks` | incidents:manage |
| `GET /api/v1/tasks` (`mine`, `status`) | incidents:read |
| `GET /api/v1/tasks/{id}` | incidents:read |
| `PATCH /api/v1/tasks/{id}` | incidents:manage + reglas de arriba |
| `POST /api/v1/tasks/{id}/assign` `{version, user_id?}` (sin `user_id` = uno mismo) | incidents:manage + reglas |
| `POST /api/v1/tasks/{id}/unassign` `{version}` | incidents:manage + reglas |
| `POST /api/v1/tasks/{id}/evidence` `{version, type, id}` | incidents:manage + reglas |

Errores propios: `task_conflict` y `network_control_conflict` (409, versión vieja),
`task_invalid_state` y `network_control_invalid_state` (409).

## Fusión de casos

Al fusionar un caso en otro, las tareas pendientes (`open`, `in_progress`, `blocked`) y las
solicitudes vivas (`pending_approval`, `approved`) se MUEVEN al destino, porque el origen queda
congelado. Lo terminado se queda en el origen como historial.

## Datos

Migración 0046: `incident_tasks` y `network_control_requests`. La caducidad de las solicitudes
la aplica el job `response-engine`. El downgrade elimina las dos tablas; la actividad del caso
y la auditoría se conservan.
