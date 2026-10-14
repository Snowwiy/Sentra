# Ciclo de vida de agentes y activos (Fases 5C.1 y 5C.2)

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

## Stale y limpieza (Fase 5C.2)

Offline no es eliminado. El estado de ciclo de vida se **deriva** al leer (no se guarda) en
`app/services/asset_lifecycle_policy.py` y depende del origen del activo:

| Origen (`lifecycle_source`) | Qué es | Stale cuando | Candidato a limpieza |
|---|---|---|---|
| `discovered` | Solo visto por la red, nunca con agente | `network_misses >= DISCOVERED_STALE_MISSED_SCANS` **y** sin verse `DISCOVERED_STALE_AFTER_HOURS` | Stale **y** sin verse `DISCOVERED_PURGE_AFTER_DAYS` |
| `monitored` | Agentless (reservado) | Sin actividad `MANAGED_STALE_AFTER_DAYS` | Nunca (como mucho archivar) |
| `managed` | Tuvo agente alguna vez | Sin contacto `MANAGED_STALE_AFTER_DAYS` | Nunca (como mucho archivar) |

`lifecycle_state` (en `GET /assets` y el detalle): `active` → `offline` → `stale` →
`cleanup_candidate`; `archived` gana a todo. También `missed_discovery_scans` y
`last_activity_at` (máximo de contacto del agente y última vez visto en la red).
`GET /assets?lifecycle=stale|cleanup_candidate` filtra en SQL con la misma regla
(`stale_condition`, comprobada contra la versión Python en los tests).

Los scans perdidos solo cuentan si el scan fue completo, exitoso y cubría la dirección (ver
[discovery.md](discovery.md#scans-perdidos-como-prueba-de-ausencia-fase-5c2)). Hacen falta
las dos condiciones (scans **y** tiempo): con el discovery parado no hay pruebas de ausencia, y
tres scans en una hora no prueban que un equipo apagado por la noche haya desaparecido.

### Gate único de borrado físico

`AssetLifecycleService.hard_delete_decision` es la **única** fuente de
`CAN_HARD_DELETE / CANNOT_HARD_DELETE + reasons[]`. La usan el delete-check, `DELETE`, el
preview, el ejecutor por lotes, la limpieza automática y la disposición del origen de una
reconciliación. Combina:

- motivos de política: `not_stale`, `purge_window_not_reached`, `managed_history`,
  `monitored_source`;
- motivos por historial (tabla de abajo), contados con subselects acotados
  (`LIMIT 10000`) en **una** consulta por lote (sin N+1 ni recorridos de telemetría).

**Cambio respecto a 5C.1:** un descubierto sin historial ya no se puede borrar en cualquier
momento; tiene que ser candidato a limpieza. Archivarlo sigue siendo posible siempre.
Un descubierto **archivado** (discovery deja de seguirlo) es borrable cuando lleva
`DISCOVERED_PURGE_AFTER_DAYS` sin verse y no tiene historial.

### Acciones del preview

| Acción | Cuándo |
|---|---|
| `keep` | Activo al día (no aparece en el preview) |
| `mark_stale` | Descubierto stale sin historial, dentro de la ventana de purga |
| `archive_candidate` | Stale con algún bloqueo de borrado (gestionado, monitorizado o historial); archivable |
| `hard_delete_eligible` | Descubierto candidato a limpieza sin ningún bloqueo |
| `blocked` | Stale pero su agente tiene la credencial activa: revocar antes de archivar |

`GET /assets/lifecycle/cleanup-preview?action=&source=&limit=&offset=` (admin) devuelve la
política, el reparto por acción y una página de candidatos con IP, plataforma, estado, última
actividad, scans perdidos, horas stale, motivos y dependencias. No escribe nada. Evalúa como
mucho 10 000 candidatos (los más antiguos primero).

`POST /assets/lifecycle/cleanup` `{action: "hard_delete"|"archive", items: [{asset_id,
version}], reason}` (admin; como mucho `ASSET_CLEANUP_BATCH_SIZE`, `reason` obligatorio para
archivar). Cada activo va en su SAVEPOINT con la fila bloqueada y se **revalida con el mismo
motor**: si un heartbeat o un discovery lo vio, apareció una detección, cambió su versión u
otro admin actuó, se omite con el motivo (`not_stale`, `detections`, `version_conflict`,
`already_archived`, `agent_active`...). Un omitido no deshace los demás.

### Limpieza automática (opt-in)

`ASSET_AUTO_CLEANUP=false` por defecto. Con `true`, el job `asset-cleanup` (advisory lock
propio) borra cada `ASSET_CLEANUP_INTERVAL_MINUTES` como mucho `ASSET_CLEANUP_BATCH_SIZE`
descubiertos `hard_delete_eligible`, revalidando cada uno y auditando como `system`. Nunca
toca gestionados ni monitorizados y nunca archiva.

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
| `other` | Alertas sin resolver (salvo `asset_disappeared`, que habla de la propia desaparición del descubierto y se borra con él) |
| `agent_history` (5C.2) | También filas de linaje de agentes (`asset_agent_lineage`) |

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
admin) y `GET /assets/duplicates?min_confidence=low|medium|high` (pares de la flota, al menos
uno con agente, por defecto media o alta, máximo 200; sin comparación O(n²): igualdades sobre
columnas indexadas y linaje).

Cada candidato trae `evidence` (señal y fuerza), `confidence`, `conflicts`,
`reconcile_blockers` (duros), `reconcile_warnings` (aceptables) y `requires_acknowledgement`.

| Señal | Fuerza |
|---|---|
| `same_machine_id` (identidad de máquina) | fuerte |
| `same_agent_lineage` (el agente estuvo en el otro activo, ver Linaje) | fuerte |
| `same_mac` (MAC universal, no aleatoria) | media |
| `same_hostname`, `same_ip`, `same_random_mac` (MAC administrada localmente), `same_os` | débil |

| Confianza (5C.2) | Cuándo |
|---|---|
| high | Alguna señal fuerte y ningún conflicto |
| medium | MAC universal igual, sin conflicto |
| low | Solo señales débiles (**IP + hostname = low**), o identidades de máquina distintas (`conflicts: ["machine_id_mismatch"]`) |

`same_os` solo acompaña: nunca hace candidato a nadie. Un conflicto de identidad ya no oculta
el candidato (5C.1 lo ocultaba): se muestra con confianza baja para revisión manual, porque una
reinstalación de Windows genera un MachineGuid nuevo. Al enrolarse un agente nuevo se audita
`asset_duplicate_detected` solo con candidatos medios o altos.

## Reconciliar (reasignar, no fusionar)

`GET /assets/{id}/reconcile-preview?target_asset_id=` muestra evidencia, bloqueos, avisos,
historial que conserva cada parte (recuentos acotados), si el destino tenía agente y la
disposición prevista del origen. `POST /assets/{id}/reconcile` con `{target_asset_id, version,
target_version, acknowledge_weak_evidence}`. `{id}` es el activo **nuevo** (SOURCE, el agente
reinstalado) y `target` el **histórico**. Solo admin con `agents:manage` y `assets:manage`. La
UI nunca toca IDs: el servidor bloquea ambas filas en orden de id, comprueba versiones y vuelve
a evaluar la evidencia.

- **Bloqueos duros** (409 `asset_reconcile_refused`, siempre): mismo activo, el nuevo no tiene
  agente o está archivado, el histórico nunca tuvo agente, el agente del histórico tiene
  credencial activa **y** está en línea, plataformas distintas.
- **Avisos** (`machine_id_mismatch`, `insufficient_evidence`): 409 con
  `requires_acknowledgement: true` salvo que el admin envíe `acknowledge_weak_evidence: true`.
  Es el caso de una reinstalación (identidad nueva, misma IP, otro hostname).

Qué hace, en una sola transacción (cualquier error la deshace entera):

1. Linaje: fila `reassigned` para el agente que deja el origen y, si el histórico tenía
   agente, fila `replaced` para ese agente antiguo (ver Linaje).
2. Mueve `agent_id` y la credencial **del agente actual** (hash, emisión; nunca el token, que
   el servidor no tiene) al histórico. El hash del agente antiguo del histórico se descarta:
   ese agente deja de autenticar y su credencial nunca se reutiliza.
3. El histórico pasa a `agent`, recibe los datos de host del agente actual (hostname, SO, IP,
   versión, identidad de máquina) y se desarchiva si estaba archivado.
4. Disposición del origen con el **mismo gate de borrado**: `source_deleted` solo si pasara
   todos los gates; como tuvo agente es Managed y queda `source_archived` (por `system`,
   «Reconciliado con el activo …»), con los motivos en `source_disposition_reasons`. Nada se
   borra en silencio.
5. Recalcula riesgo y reevalúa vulnerabilidades del histórico.

El agente actual no necesita re-enrolarse: su siguiente heartbeat ya informa en el histórico.

### Historial: qué se mueve y qué no

Nada se copia ni se re-parenta. Es deliberado, tabla a tabla:

| Datos | Decisión | Por qué |
|---|---|---|
| Telemetría, procesos | Se quedan en el origen archivado | Describen otra instalación; el histórico recibe las nuevas desde el siguiente envío |
| Eventos del sistema | Se quedan | `record_id` reinicia tras reinstalar Windows: chocarían con los del histórico (`uq_system_events_record`) |
| Inventario | Se queda | Uno por activo; el agente envía el actual al histórico en su siguiente ciclo |
| Detecciones, alertas, riesgo, vulnerabilidades, TI, incidentes, contexto, IA | Se quedan donde ocurrieron | Son evidencia de ese activo en ese momento; moverlas rompe deduplicación y trazabilidad |
| Auditoría | No cambia | Referencia ids públicos |

El origen archivado sigue consultable con **Mostrar archivados** y no se puede borrar.

### Linaje de agentes (migración 0029)

`asset_agent_lineage` guarda cada asociación activo↔agente que termina por reconciliación:
`asset_id`, `agent_id`, `ended_at`, `end_reason` (`reassigned` | `replaced`),
`related_asset_id`, `reconciliation_id`, `agent_version`, `actor`. Sin tokens ni identidad de
máquina. Antes (5C.1) el agent_id antiguo del histórico se sobrescribía. Sirve de evidencia
fuerte: si un agente antiguo vuelve a enrolarse (crea un activo nuevo, porque su credencial
se descartó), aparece como duplicado `same_agent_lineage` de confianza alta.

### Caso real: DESKTOP-03IJGBE ← ravenslg (QA manual)

Histórico `DESKTOP-03IJGBE` (192.168.50.201, offline, con historial) y nuevo `ravenslg` (misma
IP, agent ID `64cf210d-…`, Windows reinstalado). Esperado: candidato de confianza **baja** con
`same_ip` (+ `same_os`) y, si el histórico tenía identidad de máquina, conflicto
`machine_id_mismatch`. Pasos (solo tras revisar 5C.2, con copia de seguridad hecha):

1. Activo `ravenslg` → Ciclo de vida → Reconciliar → destino `DESKTOP-03IJGBE` (de la lista o
   pegando su Asset ID).
2. Revisar evidencia e impacto: historial del destino que se conserva, agente anterior que
   queda histórico, `source_disposition: source_archived`.
3. Marcar la confirmación de evidencia débil y confirmar.
4. Comprobar: el agente actual sigue en línea en `DESKTOP-03IJGBE` (hostname pasa a
   `ravenslg`), detecciones/riesgo/telemetría previos siguen ahí, `ravenslg` queda archivado,
   auditoría `agent_asset_reconciled`, `agent_reassigned` y `asset_archived`.

### Caso histórico de 5C.1: Ravenslg

Mismo hostname e IP con un agente 0.1.0 revocado: en 5C.2 es confianza **baja** (antes
media) y requiere la confirmación explícita.

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

Carreras cubiertas (5C.2, con tests):

- dos reconciliaciones a la vez: el segundo admin espera el `FOR UPDATE` y recibe 409;
- preview viejo + heartbeat/discovery/detección/acción de otro admin antes de ejecutar: el
  ejecutor revalida con la fila bloqueada y lo omite;
- heartbeat (o telemetría, eventos, inventario) en curso mientras se reconcilia: el `UPDATE`
  de contacto se hace también por `agent_id`; si el agente se movió entre medias, la petición
  se deshace entera con 409 (reintentable por el agente) y el reintento llega al histórico,
  nunca al duplicado archivado;
- discovery o una inserción concurrente durante un borrado: `FOR UPDATE` frente a
  `FOR KEY SHARE` de las claves foráneas (ver Borrar).

## API y permisos

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/assets?archived=exclude\|include\|only` | lectura (todos) |
| GET | `/assets/duplicates`, `/assets/{id}/duplicate-candidates` | `assets:duplicates_read` (analyst, admin) |
| GET | `/assets/{id}/delete-check` | `assets:manage` (admin) |
| POST | `/assets/{id}/archive` `{reason, version}`, `/assets/{id}/restore` `{version}` | `assets:manage` |
| DELETE | `/assets/{id}?version=` | `assets:manage` |
| GET | `/assets?lifecycle=stale\|cleanup_candidate` | lectura (todos) |
| GET | `/assets/lifecycle/cleanup-preview` | `assets:manage` |
| POST | `/assets/lifecycle/cleanup` | `assets:manage` |
| GET | `/assets/{id}/reconcile-preview?target_asset_id=` | `agents:manage` + `assets:manage` |
| POST | `/assets/{id}/reconcile` | `agents:manage` + `assets:manage` |

Viewer solo lee activos (incluidos archivados con el filtro). Analyst no archiva ni borra.

## Auditoría

`asset_archived` (motivo, managed), `asset_restored`, `asset_deleted` (nombre, IP, MAC y
recuentos borrados), `asset_delete_rejected` (motivos), `asset_duplicate_detected`
(candidato, confianza, razones), `agent_asset_reconciled`. Nunca telemetría ni la identidad de
máquina. Los rechazos (409) también se auditan como `failure`.

5C.2 añade: `asset_cleanup_executed` (acción, automática o no, recuentos e ids), y en cada
borrado/archivado de un lote `cleanup: true`; en una reconciliación, además de
`agent_asset_reconciled` (ahora con `reconciliation_id`, `previous_target_agent_id`,
`acknowledged_warnings`, `source_disposition` y motivos), `agent_reassigned` (agente, de/a) y
`asset_archived` del origen. No se audita el preview (solo lee) ni un "reconciliation started"
separado: la reconciliación es atómica y un fallo queda como `agent_asset_reconciled` con
`failure`. Nunca tokens, hashes ni identidad de máquina.

## Configuración (Fase 5C.2)

| Variable | Defecto | Rango | Uso |
|---|---|---|---|
| `DISCOVERED_STALE_AFTER_HOURS` | 72 | 1–8760 | Tiempo mínimo sin verse para stale |
| `DISCOVERED_STALE_MISSED_SCANS` | 3 | 1–100 | Scans completos perdidos para stale |
| `DISCOVERED_PURGE_AFTER_DAYS` | 14 | 1–3650, ≥ stale | Ventana de purga (candidato a limpieza) |
| `MANAGED_STALE_AFTER_DAYS` | 30 | 1–3650 | Stale de gestionados y monitorizados |
| `ASSET_AUTO_CLEANUP` | false | — | Limpieza automática de descubiertos elegibles |
| `ASSET_CLEANUP_BATCH_SIZE` | 50 | 1–500 | Máximo por lote (manual o automático) |
| `ASSET_CLEANUP_INTERVAL_MINUTES` | 360 | 5–10080 | Cada cuánto corre la limpieza automática |

Una ventana de purga más corta que el stale detiene la API al arrancar. Los tests fijan
todas en `tests/conftest.py` (no dependen del `.env`).

## Recuperación

- Un archivado (también el origen de una reconciliación) se restaura con **Restaurar**; la
  credencial no se reactiva.
- Una reconciliación no tiene "deshacer" automático: el linaje y la auditoría dicen qué
  agente estaba en cada activo. Para revertirla a mano, restaurar el origen, revocar/reinstalar
  el agente según convenga y, si hiciera falta, re-enrolar el equipo. Por eso exige preview y
  confirmación, y conviene una copia de seguridad antes del caso real.
- Un borrado físico es irreversible (solo restaurando una copia): solo ocurre con descubiertos
  sin historial que llevan la ventana de purga sin verse.

## Migración 0028

Añade a `assets` `archived_at`, `archived_by`, `archive_reason`, `lifecycle_version`,
`ever_managed` (rellenado con `agent_id IS NOT NULL`), `machine_id_hash`, `event_coverage`,
`event_coverage_at` y los índices `ix_assets_machine_id_hash` e `ix_assets_hostname_lower`;
en `system_events`, `event_code` pasa a admitir NULL y se añade `event_type` (eventos Linux).

**Bajar a 0027** pierde: el estado archivado (los activos vuelven a verse), motivos, versión,
`ever_managed`, la identidad de máquina, la cobertura de eventos y el tipo de los eventos
Linux; esos eventos se conservan con `event_code = 0` porque el esquema anterior lo exigía.
Probado 0027 → 0028 → 0027 → 0028 con datos (`tests/test_asset_lifecycle.py`).

## Migración 0029

Solo crea `asset_agent_lineage` con índices en `asset_id`, `agent_id` y `related_asset_id`
(claves foráneas e índice de búsqueda de linaje). No toca tablas ni filas existentes; stale y
scans perdidos se derivan de columnas existentes. **Bajar a 0028** borra el linaje registrado
(la auditoría conserva los mismos ids). Probado con datos (`tests/test_asset_lifecycle_5c2.py`).
