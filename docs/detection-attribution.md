# Atribución verificable de detecciones (Fase 7B.1)

Responde a una pregunta: ¿esta detección la produjo una operación de mantenimiento que un
administrador autorizó, o no? La respuesta sale de comparar la evidencia guardada con una
operación aprobada, nunca de un nombre. Código: `backend/app/detection/attribution.py`
(cálculo puro), `backend/app/services/attribution_service.py` (datos y efectos),
migración `0048`.

## Principios

- **Nada se verifica por el nombre.** `SentraAgent`, `sentra.exe`, `install-sentra-agent.ps1`
  o `powershell.exe` se falsifican con facilidad.
- **Hashes de referencia de confianza.** Los escribe un admin o salen del propio servidor
  (catálogo de referencia). El servidor nunca aprende un hash de lo que observó en el equipo.
- **Toda la evidencia con una sola operación.** Si un único elemento no casa (otro script en
  la ventana, un hash distinto), la detección queda sospechosa. Una operación legítima no
  tapa actividad que no describe, y nunca se mezclan artefactos de dos operaciones.
- **Si falta un dato, se dice.** El veredicto es `insufficient_evidence`, con lo que falta y
  cómo obtenerlo sin desactivar controles (`HOW_TO_OBTAIN`).
- **`confirmed_malicious` lo decide una persona.** El cálculo nunca lo devuelve, y la base lo
  impide con una restricción CHECK (`source = 'analyst'`).
- **Excepciones estrechas y temporales.** Cada operación es de UN activo, con una ventana
  cerrada (72 h como máximo) y una caducidad (90 días como máximo), y nace pendiente de
  aprobación. No hay excepciones amplias por defecto.

## Reglas afectadas

| Regla | Qué se comprueba | Efecto de `verified_benign` |
|---|---|---|
| SCR-001 (PowerShell sospechoso) | Script: SHA-256, ruta canónica, cuenta (SID o nombre), ventana; intérprete, proceso padre y firma si la operación los exige | Se cierra como mantenimiento verificado y no suma riesgo activo |
| PER-001 (servicio nuevo) | Servicio: nombre, ImagePath exacto, cuenta y ventana (7045). El inventario solo corrobora un 7045 verificado del mismo servicio | Igual que SCR-001 |
| CORR-002 (PowerShell seguido de persistencia) | Lo de SCR-001 y PER-001, todo con la MISMA operación | Igual que SCR-001 |
| NET-001 (puerto expuesto) | Quién escucha (binario, ruta, hash) | **Nunca se cierra**: el puerto sigue expuesto y sigue contando |

El resto de reglas no cambian.

Fase 7B-Fix1: antes de la atribución, PER-001 v3 clasifica el servicio (instalado, instancia
por usuario, modificado, descubierto) y CORR-002 v5 exige una relación causal demostrable. Una
instancia por usuario verificada no abre detección y nunca se reconoce por nombre. La
atribución a una operación de mantenimiento no cambia. Ver `docs/fase-7b-fix1.md`.

Cada elemento de evidencia produce comprobaciones con un resultado: `pass`, `fail`,
`missing` o `not_required`. Las comprobaciones son `operation`, `artifact`, `origin`, `path`,
`sha256`, `account`, `interpreter`, `parent`, `signer`, `service`, `image_path`,
`service_account` y `binary`.

El veredicto se decide así:

- Un `fail` en una comprobación decisiva da `suspicious_unverified`. Si no hay operación y
  además faltan datos, da `insufficient_evidence`.
- Un `missing` da `insufficient_evidence`.
- Si todo es `pass` y hay operación, el veredicto es `verified_benign`.

Hay dos señales de manipulación (`tampered`):

- **Script cambiado:** el script tiene la misma ruta que el autorizado y otro hash.
- **Servicio redirigido:** el servicio tiene el mismo nombre que el autorizado y otro
  ImagePath.

Un bloque tecleado o pasado con `-Command` no tiene fichero ni hash, así que no se puede
atribuir.

## Operaciones de mantenimiento

Ciclo de vida: `pending_review` → `approved`. Una operación aprobada puede pasar a `revoked`,
y una nueva versión deja la anterior en `superseded`. No se borran desde la API.

Cada operación tiene:

- El activo, el tipo (`agent_install`, `agent_upgrade`, `sensor_install`, `database_init`,
  `server_setup`, `software_install`, `other`), un título y un motivo (al menos 10
  caracteres).
- La ventana de ejecución y la caducidad.
- Las cuentas ejecutoras. Son obligatorias si hay scripts.
- Opcionalmente, los intérpretes y procesos padre esperados y el firmante.
- Los artefactos, de 1 a 20:
  - `script` y `binary`: ruta completa y SHA-256 obligatorios.
  - `service`: nombre, ImagePath completo y cuenta.
- `reference_source` en cada artefacto: `manual` (lo tecleó el admin) o
  `server_distribution` (hash calculado por el servidor de sus propios ficheros).

Para evitar que una operación sea una excepción encubierta, el servidor rechaza:

- Un intérprete del sistema (`powershell.exe`, `pwsh.exe`, `cmd.exe`...) como artefacto
  autorizado.
- Rutas con `..`.
- Una ventana que acaba antes de empezar.
- Una caducidad anterior al final de la ventana.

### Catálogo de referencia

`GET /maintenance-operations/reference-artifacts` calcula el SHA-256 de los `.ps1` que
distribuye Sentra (`scripts/`, `agent/packaging/windows/`, `sensor/packaging/windows/`) a
partir de los ficheros del servidor. Ignora los enlaces simbólicos.

Es la referencia de confianza más cercana que existe sin firma de código. Tiene dos límites:

- No protege si un atacante controla el propio servidor.
- El hash es de los bytes: una copia con otros finales de línea (LF frente a CRLF) tiene otro
  hash y no se verifica.

### Política de autorización: aprobación inicial, después reconocimiento automático

Es la configuración por defecto (`MAINTENANCE_AUTO_RECOGNITION=true`).

1. **Aprobación humana inicial.** Una operación nace `pending_review` y no reconoce nada hasta
   que un admin la aprueba. Mientras está pendiente, las detecciones siguen activas.
2. **Reconocimiento automático, solo de lo nuevo.** Con la operación aprobada, el motor
   reconoce sola una detección cuando se cumple todo lo siguiente:
   - es de SCR-001, PER-001 o CORR-002;
   - se creó después de la aprobación;
   - toda su evidencia ocurrió después de la aprobación, dentro de la ventana y antes de la
     caducidad;
   - cada elemento casa exactamente con la operación: SHA-256 y ruta canónica del script o
     binario, cuenta, intérprete y proceso padre si la operación los exige, y servicio con
     nombre, ImagePath exacto y cuenta.

   La detección queda resuelta como mantenimiento verificado (`resolved_by = attribution`),
   sigue visible y conserva su evidencia, su correlación, su veredicto y el historial
   (`detection_attribution_events`). No se oculta ni se borra ningún evento.
3. **Nada amplio.** No hay excepciones globales. Un nombre (`SentraAgent`, `sentra.exe`,
   `powershell.exe`) o una ruta sin su hash no bastan. Un script nuevo (otro hash u otra ruta)
   o modificado (misma ruta, otro hash) no se reconoce nunca, y el modificado marca posible
   manipulación.
4. **Si algo no casa, sigue activa.** Cualquier elemento que no casa deja la detección activa
   con su severidad, y la explicación pide investigación. Si llega evidencia nueva de la misma
   oleada a una detección ya reconocida y no casa, la detección **se reabre**: el historial
   guarda los dos veredictos.
5. **Las históricas solo con revisión explícita.** Una detección anterior a la aprobación, o
   con evidencia anterior a ella, no se reclasifica sola, ni con el motor ni con «Reevaluar».
   Su atribución lleva `review_required` (operación y motivo `approved_after_activity`) y el
   panel lo explica. Solo cambia con `POST /maintenance-operations/{id}/preview`, que muestra
   qué pasaría con cada detección, seguido de `apply` con `{"confirm": true}`. Las dos llamadas
   son de un admin y quedan auditadas (`maintenance_operation_applied`). Después se recalcula
   el riesgo del activo.
6. **Caducidad y revocación.** Al caducar o revocarse, la operación deja de reconocer
   detecciones nuevas. Lo ya reconocido se queda como está, con su historial.
7. **La exposición no se oculta.** NET-001 (por ejemplo, PostgreSQL en 5432) nunca se cierra
   por atribución y sigue sumando riesgo aunque el proceso que escucha esté autorizado.

Con `MAINTENANCE_AUTO_RECOGNITION=false` no se reconoce nada solo: toda reclasificación pasa
por la vista previa y aplicar, y las detecciones muestran `review_required` con el motivo
`auto_recognition_disabled`.

Hay un límite que conviene conocer: «posterior a la aprobación» compara la hora del evento,
que viene del reloj del equipo, con la hora del servidor. Con el reloj del equipo atrasado,
una instalación hecha justo después de aprobar puede quedar como histórica y pedir revisión.
Es el lado seguro: nunca se reconoce de más.

Regresiones: `backend/tests/test_attribution.py::test_policy_*` y
`test_dev_install_is_verified_after_review_and_risk_drops`.

## Veredicto del analista

Con `detections:manage` se puede declarar `confirmed_malicious`, `suspicious_unverified` o
`insufficient_evidence`, con un motivo de al menos 10 caracteres. Un analista no puede
declarar `verified_benign`, porque verificar exige una operación cuya evidencia case.

El veredicto del analista manda sobre el del sistema: una reevaluación posterior queda en el
historial (`detection_attribution_events`, solo inserción) pero no lo sustituye.

## API

| Método y ruta | Permiso |
|---|---|
| `GET /maintenance-operations` (filtros `asset_id`, `status`) | `monitoring:read` |
| `GET /maintenance-operations/reference-artifacts` | `maintenance:manage` |
| `GET /maintenance-operations/{id}` | `monitoring:read` |
| `POST /maintenance-operations` | `maintenance:manage` |
| `POST /maintenance-operations/{id}/approve` `{note}` | `maintenance:manage` |
| `POST /maintenance-operations/{id}/revoke` `{reason}` | `maintenance:manage` |
| `POST /maintenance-operations/{id}/preview` | `maintenance:manage` |
| `POST /maintenance-operations/{id}/apply` `{confirm: true}` | `maintenance:manage` |
| `GET /detections/{id}/attribution` | `monitoring:read` |
| `POST /detections/{id}/attribution/evaluate` | `detections:manage` |
| `POST /detections/{id}/attribution/verdict` `{verdict, reason}` | `detections:manage` |

`maintenance:manage` solo lo tiene el rol admin. Cada creación, aprobación, revocación,
aplicación y veredicto queda en la auditoría (`maintenance_operation_*`,
`detection_attribution_*`). Códigos de error: `maintenance_operation_invalid` (422),
`maintenance_operation_state` (409).

## UI

- **Administración → Mantenimiento:** registrar, aprobar, revocar, vista previa y aplicar.
  El hash puede tomarse del catálogo de referencia del servidor.
- **Detalle de detección → Atribución:** veredicto, efecto en el riesgo, aviso de posible
  manipulación, comprobaciones por elemento, evidencia que falta y cómo obtenerla, historial,
  «Reevaluar» y «Veredicto del analista».
- **Listado de detecciones:** insignia con el veredicto.

## Limitaciones

- La cuenta, el proceso padre y la firma dependen de lo que envíe el agente. Los agentes
  anteriores a 0.6.0 no envían contexto del 4104 (`insufficient_evidence`).
- No hay telemetría 4688 real (fase-7b-auditoria.md, H3). El proceso padre sale de la
  telemetría de actividad.
- La firma Authenticode solo se compara si la telemetría la trae. Que falte no bloquea la
  verificación; una firma distinta sí la bloquea.
