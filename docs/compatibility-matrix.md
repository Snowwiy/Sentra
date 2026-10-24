# Matriz de compatibilidad (Fase 6E, Sentra 0.3.0)

`0.3.0` es la versión del servidor y del frontend. La API sigue siendo `/api/v1` y todos los
cambios de 6E son aditivos: endpoints nuevos, campos opcionales nuevos en el heartbeat y en los
resultados de jobs de sensor, valores nuevos en enumeraciones de respuesta.

## Componentes

| Componente | Versión 6E | ¿Cambia? | Notas |
| --- | --- | --- | --- |
| Servidor (backend) | 0.3.0 | Sí | Migraciones 0039-0043 |
| Frontend | 0.3.0 | Sí | Requiere servidor 0.3.0 para las vistas nuevas |
| Agente | 0.5.0 | Sí | Actividad, árbol de procesos, forense, cliente del helper de aislamiento |
| Helper de aislamiento | 0.5.0 (mismo paquete del agente) | Nuevo, opcional | Desactivado por defecto; Windows y Linux |
| Sensor | 0.6.0 | Sí | Job `dhcp_leases` (capacidad `dhcp.leases.file`) |

## Cruces

| Cliente | Servidor 0.2.0 | Servidor 0.3.0 |
| --- | --- | --- |
| Agentes 0.1.x-0.4.0 | Compatibles | Compatibles sin cambios: sin actividad, sin forense, sin aislamiento (la UI lo explica) |
| Agente 0.5.0 | Compatible: `/agents/activity` da 404 y el agente deja de enviar actividad; los campos nuevos del heartbeat se descartan solos | Completo |
| Sensores 0.1.x-0.5.x | Compatibles | Compatibles; sin lecturas DHCP (`dhcp_sensor_unavailable`) |
| Sensor 0.6.0 | Compatible (el servidor ignora `dhcp.leases.file`) | Completo |

## Clientes de la API

- Endpoints nuevos: `/topology/snapshots`, `/topology/diff`, `/topology/changes`,
  `/topology/history/*`, `/dhcp/*`, `/assets/{id}/identity*`, `/assets/{id}/process-tree`,
  `/assets/{id}/process-instances/{instance_id}`, `/assets/{id}/activity`,
  `/assets/{id}/telemetry-status`, `/endpoint/metrics`, `/detection-exclusions`,
  `/investigations/*`, `/assets/{id}/isolation*`, `/isolation/sessions`,
  `POST /agents/activity`.
- `ExecutionRequest` admite `investigation_id` (opcional).
- Catálogo de Response: acciones `forensic_*`; `isolate_host` y `release_isolation` pasan de
  `not_implemented` a disponibles, pero solo desde el flujo de aislamiento.
- Enumeraciones ampliadas: fuente de nombre `dhcp_lease`; regla de alerta `isolation_state`;
  reglas de detección `BEH-001`..`BEH-006`.
- Permisos nuevos: `dhcp:manage`, `telemetry:read`, `forensics:read|acquire|download|manage`,
  `containment:preview|isolate|release`.

---

## Histórico: Fase 6D (Sentra 0.2.0)

`0.2.0` es la versión del software del servidor (backend). La API sigue siendo `/api/v1`: no hay
`/api/v2` ni migración automática de contratos. Los cambios de 0.2.0 son aditivos (endpoints de
topología, campos nuevos en respuestas, valores nuevos en enumeraciones de respuesta) y los
contratos de agentes y sensores no cambian.

## Componentes

| Componente | Versión 6D | ¿Cambia en 6D? | Notas |
| --- | --- | --- | --- |
| Servidor (backend) | 0.2.0 | Sí | Migración 0038; `server_version` en `/auth/me` y OpenAPI |
| Frontend | 0.2.0 | Sí | Requiere servidor 0.2.0 para topología y diagnóstico SNMP |
| Sensor | 0.5.1 | Sí (corrección) | Solo el colector SNMP (KeyError); sin cambios de protocolo |
| Agente | 0.4.0 | No | Sin cambios |

## Agentes y sensores enrolados

| Cliente | Contra servidor 0.2.0 |
| --- | --- |
| Agentes 0.1.x-0.4.0 | Compatibles sin cambios (mismo protocolo; credenciales e identidades conservadas) |
| Sensores 0.1.x-0.2.x | Compatibles: discovery básico/avanzado v1 como antes |
| Sensores 0.3.x-0.4.x | Compatibles: SNMP y WLAN como antes |
| Sensor 0.5.0 | Compatible; un fallo interno de su colector SNMP llega como `internal` con el mensaje «snmp error: KeyError», que el servidor muestra como error interno del colector. Se recomienda 0.5.1 |
| Sensor 0.5.1 | Compatible (recomendado) |

Un servidor 0.1.x con un sensor 0.5.1: compatible (el sensor no envía nada nuevo).

## Clientes de la API

- Respuestas con campos nuevos: `NetworkDeviceRead.snmp_status`, `monitoring_paused_at`,
  `monitoring_pause_reason`; `AssetRead.name_status`; `breakdown.trace` y
  `details.nominal_breakdown` en el riesgo. Un cliente que ignore campos desconocidos no se ve
  afectado.
- Enumeraciones de respuesta ampliadas: `monitoring_status` admite `paused`; el `trigger` de una
  consulta SNMP admite `check`.
- Endpoints nuevos: `/topology/*`, `POST /network/devices/{id}/compatibility-check`,
  `POST /network/devices/{id}/monitoring/resume`.
- Permiso nuevo: `topology:manage` (solo admin). La lectura de topología usa `monitoring:read`.
- Informes: las plantillas nuevas son v2; los informes v1 ya generados no cambian y siguen
  verificándose con su SHA-256.
- Detecciones: las correlaciones pasan a versión 2 (cooldown = ventana de la correlación).
  `occurrence_count` de detecciones nuevas crece más despacio; las ya abiertas conservan su
  contador.
