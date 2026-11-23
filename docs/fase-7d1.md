# Fase 7D.1: identidad, acceso y transporte

Corrige los hallazgos H01-H05 del informe de seguridad del 2026-11-05, revalidados sobre el
código posterior a 7C (main `265f63f` = Dev `5ad952c`). Servidor, frontend y agente 0.7.0;
sensor 0.7.0 sin cambios. Migración 0051 (reversible). Sin dependencias nuevas.

Documentos relacionados:

- docs/agent-https-migration.md: migración de agentes por HTTP a HTTPS (H04).
- docs/fase-7d1-recovery.md: recuperación de identidad de agentes (H01, procedimiento).
- docs/fase-7d1-auditoria.md: matriz de cobertura H01-H05 y auditoría.
- docs/fase-7d2-plan.md: lo que queda para 7D.2.

## H01: suplantación de agentes

### Problema revalidado

`POST /agents/register` con un token de instalación válido (o la clave legacy) y el
`agent_id` de un agente existente sustituía su credencial. Quien tuviera cualquier token de
alta podía quedarse con la identidad, el histórico y el site de otro equipo.

### Diseño: tres operaciones separadas

| Operación | Credencial que la autoriza | Qué hace | Transporte |
|-----------|----------------------------|----------|------------|
| Registro | Token de instalación ordinario o clave legacy | Da de alta un `agent_id` NUEVO | Cualquiera (se registra el transporte) |
| Rotación | Credencial vigente del agente (Bearer) | Emite una credencial nueva para la MISMA identidad | Solo HTTPS o loopback |
| Recuperación | Autorización de recuperación emitida por un admin para ese activo | Sustituye la credencial de una identidad existente (equipo reinstalado, credencial perdida) | Solo HTTPS o loopback |

Registro:

- Un `agent_id` que ya existe con un token ordinario o la clave legacy devuelve
  **403 `agent_recovery_required`**. La transacción se revierte, así que el token no se
  consume. Se audita como `agent_enrollment_refused`.
- Se mantienen la caducidad, el uso único, la plataforma, el hostname esperado y el site
  del token.
- Dos registros concurrentes del mismo `agent_id` nuevo: uno gana y el otro recibe
  `agent_recovery_required`. Lo resuelve la restricción única, no una comprobación previa.
- Clave legacy: `AGENT_ENROLLMENT_KEY_EXPIRES_AT` (ISO 8601 con zona) la retira
  progresivamente. Pasada la fecha ya no sirve ni para altas nuevas. Vacío significa sin
  fecha. Desde 7D.1 nunca sirve para una identidad existente.

Rotación (`POST /agents/credentials/rotate`, cuerpo `{"agent_id"}`, cabecera
`Authorization: Bearer <credencial vigente>`):

- La credencial nueva queda **pendiente**. La anterior sigue valiendo hasta el primer uso
  de la nueva, que la promueve. Si el agente pierde la respuesta, no se queda sin
  credencial: sigue con la anterior y puede volver a rotar.
- Las rotaciones concurrentes se serializan con bloqueo de fila. Al terminar solo hay una
  credencial pendiente válida.
- El operador la pide desde el dashboard (`POST /console/agents/{asset_id}/rotate-credential`,
  admin) o el servidor la pide sola si el agente habló por HTTP en claro (motivo
  `insecure_transport`). El heartbeat devuelve `rotate_credential: true` **solo** cuando el
  heartbeat llegó por HTTPS o loopback, para que la credencial nueva nunca viaje en claro.
- Por HTTP fuera de loopback devuelve 403 `https_required`.
- Agente: `sentra-agent --rotate-credential` la fuerza a mano. Guarda la credencial nueva
  antes de usarla y vuelve a la anterior si no puede guardarla.

Recuperación:

- `POST /console/agents/{asset_id}/recovery-tokens` (admin, `agents:manage`), con cuerpo
  `{reason (10-500), confirm: true, ttl_minutes?, expected_hostname?}`. Devuelve 201 con el
  token, que se muestra una sola vez (prefijo `sentra_et_rec_`). En la base solo se guarda
  su SHA-256.
- La autorización queda ligada al agente, al activo y al site, y opcionalmente al hostname.
  Es de un solo uso y vida corta (`AGENT_RECOVERY_TOKEN_TTL_MINUTES`, 15 por defecto, máximo
  60). Emitir una nueva revoca las anteriores del mismo activo.
- `GET /console/agents/{asset_id}/recovery-tokens` lista el historial sin tokens.
  `POST /console/agents/recovery-tokens/{recovery_id}/revoke` revoca una autorización.
- El agente la presenta en `X-Enrollment-Token` como un token de instalación (los
  instaladores 0.6.x ya la aceptan: `-Reenroll` en Windows, `--token-file` en Linux y
  macOS). El agente conserva su `agent_id`, su histórico y su site.
- Un agente revocado necesita primero «Reactivar» y después la autorización. El dashboard
  encadena los dos pasos.
- CLI del servidor: `python -m app.cli authorize-agent-recovery <asset_id> --reason "…" --confirm
  [--ttl-minutes N] [--hostname H]`. El token sale solo en la última línea de stdout.
- Auditoría: `agent_enrollment_refused`, `agent_recovery_authorized`,
  `agent_recovery_revoked`, `agent_recovery_rejected`, `agent_recovered`,
  `agent_rotation_requested`, `agent_credential_rotated` y
  `agent_credential_rotation_completed`. Ninguna guarda el token ni su hash.

### Modelo (migración 0051)

- `assets`: credencial pendiente (hash, fecha de emisión), `credential_source`
  (`enrollment_token`, `legacy_key`, `recovery`, `rotation`), petición de rotación
  (fecha y motivo), transporte del último heartbeat y fecha del último HTTP en claro.
- `agent_recovery_tokens`: hash único, activo, agent_id, site, hostname esperado, motivo,
  autor, caducidad, consumo y revocación. Cada FK tiene su índice.

## H02: el rol viewer veía evidencias de endpoint

### Problema revalidado

La telemetría 6E (procesos con su línea de comando, usuario, rutas, hashes y conexiones)
exige `telemetry:read`, que el rol viewer no tiene. Pero el motor de detecciones copia esos
datos a la detección y a su evidencia, y de ahí pasaban a vistas que solo piden
`monitoring:read`: detecciones, incidentes, alertas, informes, herramientas de la consola,
contexto de IA y su caché, y la búsqueda (incluida la de SHA-256, que funcionaba como
oráculo).

### Política central (`backend/app/core/evidence_policy.py`)

- Una evidencia es de endpoint si su `source_type` es `endpoint_activity`. Una detección es
  de endpoint si su regla es de la categoría `behavior` o si tiene alguna evidencia de
  endpoint.
- Sin `telemetry:read`, de lo que es de endpoint solo se entrega una **allowlist** de campos
  operativos (`SAFE_ENDPOINT_EVIDENCE_FIELDS` y `SAFE_ENDPOINT_DETAIL_KEYS`): mecanismo,
  producto, hallazgos ya clasificados, estados. Nunca rutas, usuarios, líneas de comando,
  hashes ni direcciones. Lo demás se omite y se nombra en `withheld_fields` y
  `withheld_details`, solo por nombre y nunca con su valor. El resumen se sustituye por el
  título de la regla más una nota fija.
- La decisión usa los permisos **actuales** de quien lee en cada petición. Degradar un rol
  afecta también a lo ya generado.
- La evidencia original no se modifica nunca. Solo cambia lo que se serializa.

Puntos de aplicación:

- Detecciones: lista y detalle (`restricted`, `withheld_details`, y en cada evidencia
  `restricted` y `withheld_fields`).
- Búsqueda de la consola (texto y SHA-256), que excluye detecciones de endpoint.
- Incidentes: detecciones adjuntas, timeline y descripción copiada.
- Alertas: el resumen guardado en `details` ya se escribe seguro y la migración sanea las
  existentes.
- Herramientas `detections.*`, `attribution.explain` y `detections.related`, más las notas
  que `case_link` copia a un incidente.
- Contexto de IA (`ContextBuilder`) y caché de insights: cada insight guarda
  `content_permissions`.
- Informes: cada informe guarda `content_permissions`, y descargarlo exige tenerlos.

## H03: historial de herramientas con permisos antiguos

Cada ejecución guarda `read_permissions`: los permisos de dominio de la herramienta, más
`telemetry:read` si su salida incluyó detalle de endpoint. En la lista y el detalle se
comparan con los permisos actuales del lector: si le falta alguno, recibe solo metadatos
inocuos (herramienta, estado, fechas, objetivo) con `content_withheld: true` y
`withheld_permissions`, sin entrada, salida, resumen, evidencia ni procedencia.

Las copias también se comprueban: `case_link` deniega enlazar a un incidente una ejecución
que el usuario ya no puede leer, y la nota que copia al caso solo incluye el resumen si la
ejecución no exigía más que `monitoring:read`. Los informes comprueban su propio
`content_permissions` al listarlos y descargarlos. Se mantiene la política
`tools:execute` de 7C-Security-Fix1. La migración rellena `read_permissions` de las
ejecuciones antiguas con una tabla fija y protege por defecto las herramientas
desconocidas.

## H04: transporte del agente

- Agente 0.7.0: `api_url` debe ser `https://`. Se admite `http://` solo a 127.0.0.0/8,
  `::1` o `localhost`. Se rechazan las URL con credenciales, query o fragmento. La
  validación TLS es la normal del sistema (TLS 1.2 como mínimo); `ca_bundle` añade una CA
  interna y no hay forma de desactivar la verificación.
- Una configuración antigua con http remoto da un error claro que apunta a
  docs/agent-https-migration.md. Los instaladores (Windows PS1, Linux `.sh`, `.deb` preinst
  y macOS preinstall) la rechazan **antes de parar el servicio**, así que una actualización
  mal preparada no deja el equipo sin monitorizar.
- Servidor: clasifica cada petición de agente como `https`, `http_loopback` o
  `http_remote`, respetando `TRUSTED_PROXIES` y `X-Forwarded-Proto`. Un agente `http_remote`
  (0.6.x) **sigue funcionando**: se marca en el dashboard (insignia, aviso y contador en el
  resumen) y se le pide rotación, que solo se le entrega cuando hable por HTTPS. No hay
  corte silencioso ni excepción insegura permanente.
- `suggested_server_urls` y el asistente «Añadir agente» solo proponen y aceptan HTTPS (o
  http a loopback).

## H05: redirecciones

El cliente del agente no sigue ninguna redirección: 301, 302, 303, 307 y 308 terminan en
`RedirectError`, con el estado y el destino en el log y sin reintento inmediato. Así no
reenvía la credencial a otro origen ni baja de HTTPS a HTTP. Los errores transitorios (red,
5xx, 429 con `Retry-After`) mantienen su reintento con backoff y el buffer local.

## Endurecimiento del transporte del agente

| Clave (`agent.toml`) | Por defecto | Límites | Efecto |
|----------------------|-------------|---------|--------|
| `max_response_bytes` | 4 MiB | 64 KiB a 64 MiB | Lectura incremental; si se supera, `ResponseTooLargeError` |
| `request_deadline_seconds` | 60 | Al menos `timeout`, como mucho 600 | Plazo total de la petición, incluida la lectura lenta |
| `ca_bundle` | (sistema) | Fichero PEM | CA adicional de confianza |

La respuesta debe ser un objeto JSON. El cuerpo de error también se lee acotado.

## Compatibilidad

| Caso | Resultado |
|------|-----------|
| Agente 0.6.x por HTTPS | Sigue igual. No rota solo (no entiende `rotate_credential`) |
| Agente 0.6.x por HTTP remoto | Sigue enviando datos. Marcado como inseguro y pendiente de migrar |
| Agente 0.6.x que se reinstala con un token ordinario | 403 `agent_recovery_required`: hace falta una autorización de recuperación |
| Instalador 0.7.0 sobre una configuración http remota | Se niega antes de parar el servicio anterior |
| Sensor 0.7.0 | Sin cambios (ya rechazaba redirecciones y exigía HTTPS) |
| Frontend 0.6.x contra servidor 0.7.0 | Los campos nuevos son aditivos |

## Ajustes nuevos (opcionales, fijados en `tests/conftest.py`)

- `AGENT_ENROLLMENT_KEY_EXPIRES_AT`: vacío por defecto.
- `AGENT_RECOVERY_TOKEN_TTL_MINUTES`: 15 por defecto.
- `AGENT_SERVER_URL`, si está fijado, debe pasar a `https://…`. El servidor no lo impone
  para no impedir el arranque con el `.env` actual, pero el asistente no generará comandos
  con una URL http remota.
