# Ciclo de vida de agentes y activos (Fase 5C.1)

Separa lo que antes se confundía: la **credencial del agente**, el **activo** y su
**historial**. Revocar un agente nunca borra ni archiva nada; archivar un activo nunca revoca
su agente; borrar solo existe para activos descubiertos sin historial.

## Conceptos

| Concepto | Qué es | Dónde se ve |
|---|---|---|
| Credencial del agente | El token por agente (hash en `assets.agent_token_hash`) y su estado: `active`, `revoked`, `re_enrollment_required` | Agentes → columna **Credencial** |
| Activo | La fila de `assets`: el equipo tal y como Sentra lo conoce | Activos, detalle del activo |
| Managed | Activo que tuvo agente alguna vez (`assets.ever_managed`, `managed_history` en la API) | Detalle: «Activo gestionado» |
| Discovered | Activo visto solo por la red (discovery), nunca con agente | Método «discovered» |
| Archived | Activo oculto por defecto, con todo su historial (`archived_at`, `archived_by`, `archive_reason`) | Badge **Archivado**, filtro **Mostrar archivados** |

## Archivar

- Solo admin (`assets:manage`), con motivo obligatorio (3–500 caracteres).
- Un activo cuyo agente tiene la credencial **activa** no se archiva (409
  `asset_state_conflict`, `agent_active`): primero se revoca en Agentes. Así nunca queda un
  agente enviando datos a un activo que nadie ve.
- Revocar **no** archiva (son dos decisiones) y un agente revocado conserva su activo visible.
- Archivado = oculto en Activos y en Agentes salvo con **Mostrar archivados**
  (`GET /assets?archived=include|only`), fuera del resumen del dashboard (activos, riesgo,
  detecciones, vulnerabilidades, alertas activas), fuera del riesgo actual (lista y resumen de
  4I) y fuera de las alertas «sin datos». Los **incidentes** siguen contando: son casos de
  trabajo, no estado del activo.
- Se conserva todo: telemetría, eventos, inventario, detecciones, riesgo histórico,
  vulnerabilidades, coincidencias de TI, incidentes, contexto y auditoría.
- Un agente cuyo activo está archivado no puede volver a enrolarse (403 `asset_archived`); el
  agente 0.2.1 lo registra como «asset archived by an operator; restore it on the server».
- Discovery no reactiva un activo archivado: lo ignora al reconciliar por MAC/IP y no lo marca
  como desaparecido.

## Restaurar

Solo admin. Vuelve a mostrarse y a contar. **No** reactiva la credencial: un agente revocado
sigue revocado (reactivarlo es «Reinstate» en Agentes, una decisión aparte). Pide un
recálculo de riesgo del activo.

## Borrar (solo descubiertos sin historial)

`GET /assets/{id}/delete-check` devuelve `deletable`, `blocking_reasons`, recuentos por
dependencia, lo que se borraría con él (`removes`) y si puede archivarse en su lugar.

| Motivo | Qué lo provoca |
|---|---|
| `managed_history` | Tuvo agente (o `monitoring_method = agent`) |
| `agent_history` | Telemetría, eventos, inventario, snapshots de procesos o un token de enrolamiento que apunta a él |
| `detections` | Detecciones de severidad media o superior |
| `incidents` | Vinculado a incidentes (directo, por detección o por alerta) |
| `vulnerabilities` | Findings de vulnerabilidad |
| `threat_intel` | Coincidencias de inteligencia de amenazas |
| `audit_dependency` | Contexto editado por un admin (4L) o análisis de IA (4J) |
| `other` | Alertas sin resolver |

Lo que sí desaparece con un descubierto borrable (ON DELETE CASCADE, mostrado antes de
confirmar): puertos, cambios, detecciones de bajo impacto (NET-003 «dispositivo nuevo»,
NET-004 «desaparecido»), alertas resueltas e instantáneas de riesgo.

`DELETE /assets/{id}?version=N` (solo admin, 204). **Sin TOCTOU**: el servidor bloquea la
fila del activo (`FOR UPDATE`) y recalcula todas las dependencias dentro de la misma
transacción; cualquier inserción concurrente que referencie el activo toma `FOR KEY SHARE`
sobre esa fila, así que o ya está y se ve, o espera y falla por la clave foránea. Si hay
dependencias: 409 `asset_not_deletable` con los motivos y auditoría `asset_delete_rejected`.

La UI muestra hostname, IP, MAC y última vez visto, y los textos exactos:
«Este activo descubierto no tiene historial gestionado y será eliminado permanentemente.» o
«No se puede eliminar porque contiene historial.» con el botón **Archivar**. Un activo
gestionado nunca muestra **Eliminar**.

## Duplicados

Sugerencias, nunca fusiones automáticas. `GET /assets/{id}/duplicate-candidates` (analyst y
admin) y `GET /assets/duplicates` (pares de la flota, al menos uno con agente, confianza
media o alta, máximo 200).

| Confianza | Evidencia |
|---|---|
| high | Misma identidad de máquina (`machine_id_hash`) |
| medium | Mismo hostname y además misma MAC o misma IP; o misma MAC |
| low | Solo hostname o solo IP (DHCP reasigna direcciones: nunca basta para reconciliar) |

Identidades de máquina distintas descartan la coincidencia aunque nombre e IP coincidan
(equipos con el mismo nombre, VM clonada con id regenerado). Al enrolarse un agente nuevo se
audita `asset_duplicate_detected` (solo IDs, razones y confianza) si hay candidatos medios o
altos. La UI muestra «Posible duplicado» con razones y confianza, y en el activo de un agente
nuevo: «Este agente parece corresponder a un activo existente.»

## Reconciliar (reasignar, no fusionar)

`POST /assets/{id}/reconcile` con `{target_asset_id, version, target_version}`. `{id}` es
el activo **nuevo** (el del agente reinstalado) y `target` el **histórico**. Solo admin con
`agents:manage` y `assets:manage`. El servidor bloquea ambas filas en orden de id, comprueba
versiones y vuelve a evaluar la evidencia; rechaza (409 `asset_reconcile_refused`) si:
mismo activo, el nuevo no tiene agente o está archivado, el histórico nunca tuvo agente, el
agente del histórico tiene credencial activa **y** está en línea, plataformas distintas,
identidades de máquina distintas o evidencia insuficiente (baja).

Qué hace: mueve el `agent_id` y su credencial (hash, emisión, revocación) al activo
histórico, que pasa a `agent`, recibe los datos de host del agente nuevo y se desarchiva si
estaba archivado; el activo nuevo queda sin agente y archivado por `system` («Reconciliado con
el activo …») conservando lo poco que llegó a enviar (es Managed: no se borra). El agente no
necesita re-enrolarse: su siguiente heartbeat ya informa en el activo histórico. Recalcula el
riesgo de ambos y reevalúa vulnerabilidades del histórico. Auditoría `agent_asset_reconciled`
con `agent_id`, activo de origen, confianza y razones.

No hay «merge universal»: la telemetría y eventos del activo nuevo no se copian (se quedan
en él, archivado). Es deliberado: copiar historial entre activos rompe la trazabilidad.

### Caso real: Ravenslg

`Ravenslg` (192.168.50.66) con Agent v0.1.0 revocado y offline, y un agente v0.2.0 nuevo en
línea con el mismo hostname e IP: aparece como posible duplicado de confianza media
(«mismo hostname, misma IP»), reconciliable. Un admin pulsa **Reconciliar con activo
existente** en el activo nuevo; el histórico conserva detecciones, riesgo y vulnerabilidades y
pasa a recibir los datos del agente v0.2.0. Con el agente 0.2.1 (identidad de máquina) la
confianza sería alta.

## Identidad de máquina

El agente 0.2.1 lee el identificador que el sistema ya genera (Linux `/etc/machine-id` o
`/var/lib/dbus/machine-id`, Windows `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` en la
vista de 64 bits), sin privilegios ni lecturas de hardware, y envía
`HMAC-SHA256(clave=id, mensaje="sentra-agent/machine-identity/v1")` (el esquema que systemd
recomienda para ids derivados por aplicación). El id en claro nunca sale del equipo; el
servidor guarda el hash (índice `ix_assets_machine_id_hash`) y **no lo expone** en ninguna
respuesta (solo la razón `same_machine_id`). No es una credencial: no autentica ni fusiona
nada por sí solo. Ids no válidos o todo ceros (imágenes sin inicializar) se descartan. Un
servidor anterior rechaza el campo y el agente lo deja de enviar en esa ejecución.

## Concurrencia

Cada escritura del ciclo de vida lleva la `lifecycle_version` que la UI mostró (no
`updated_at`, que cambia con cada heartbeat); si cambió: 409 `asset_lifecycle_conflict`.

## API y permisos

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/assets?archived=exclude\|include\|only` | lectura (todos) |
| GET | `/assets/duplicates`, `/assets/{id}/duplicate-candidates` | `assets:duplicates_read` (analyst, admin) |
| GET | `/assets/{id}/delete-check` | `assets:manage` (admin) |
| POST | `/assets/{id}/archive` `{reason, version}`, `/assets/{id}/restore` `{version}` | `assets:manage` |
| DELETE | `/assets/{id}?version=` | `assets:manage` |
| POST | `/assets/{id}/reconcile` | `agents:manage` + `assets:manage` |

Viewer solo lee activos (incluidos archivados con el filtro). Analyst no archiva ni borra.

## Auditoría

`asset_archived` (motivo, managed), `asset_restored`, `asset_deleted` (nombre, IP, MAC y
recuentos borrados), `asset_delete_rejected` (motivos), `asset_duplicate_detected`
(candidato, confianza, razones), `agent_asset_reconciled`. Nunca telemetría ni la identidad de
máquina. Los rechazos (409) también se auditan como `failure`.

## Migración 0028

Añade a `assets` `archived_at`, `archived_by`, `archive_reason`, `lifecycle_version`,
`ever_managed` (rellenado con `agent_id IS NOT NULL`), `machine_id_hash`, `event_coverage`,
`event_coverage_at` y los índices `ix_assets_machine_id_hash` e `ix_assets_hostname_lower`;
en `system_events`, `event_code` pasa a admitir NULL y se añade `event_type` (eventos Linux).

**Bajar a 0027** pierde: el estado archivado (los activos vuelven a verse), motivos, versión,
`ever_managed`, la identidad de máquina, la cobertura de eventos y el tipo de los eventos
Linux; esos eventos se conservan con `event_code = 0` porque el esquema anterior lo exigía.
Probado 0027 → 0028 → 0027 → 0028 con datos (`tests/test_asset_lifecycle.py`).
