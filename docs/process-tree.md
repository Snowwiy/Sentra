# Telemetría de endpoint y árbol de procesos: servidor (Fases 6E.3 y 6E.4)

> Estado: implementado en el backend (`app/endpoint/`, `app/api/v1/routes/endpoint.py`,
> migración 0041). Probado con lotes sintéticos (`tests/test_endpoint_telemetry.py`);
> pendiente de verificar en equipos reales con el agente 0.5.0 (Windows, Linux y macOS).

Este documento cubre el lado servidor: ingesta de actividad, validación, privacidad de la línea
de comandos, árbol de procesos y su API. El lado agente (colectores, cola offline, latencias de
sondeo) está en [endpoint-telemetry-agent.md](endpoint-telemetry-agent.md), y el contrato
completo de `data` por categoría en [fase-6e-contracts.md](fase-6e-contracts.md). Las reglas
de comportamiento que consumen esta actividad están en
[behavioral-detection.md](behavioral-detection.md).

## Modelo (migración 0041)

| Tabla / columna | Contenido |
|---|---|
| `endpoint_activity` | Un evento: `asset_id`, `event_uid` (único por activo), `boot_id`, `seq`, `category`, `action`, `source`, `instance_key`, `data` (JSONB acotado), `occurred_at` (en el host), `received_at` (en el servidor) |
| `process_instances` | Índice derivado del árbol: `instance_key` (único por activo), `boot_id`, `pid`, `ppid`, `parent_instance_key`, `parent_relation`, `name`, `exe`, `cmdline` (ya redactada), `username`, `sha256`, `signer`, `integrity`, `source`, `started_at`, `ended_at`, `first_seen_at`, `last_seen_at` |
| `assets.telemetry_status`, `assets.telemetry_status_at` | Último `stats` del agente (más `boot_id`) y cuándo llegó |
| `detection_exclusions` | Excepciones de reglas (6E.5, ver [behavioral-detection.md](behavioral-detection.md)) |

## `POST /api/v1/agents/activity`

Lo llama el agente 0.5.0 con su token (`Authorization: Bearer <token>`). Resumen del contrato:

```json
{
  "agent_id": "uuid",
  "batch_id": "uuid",
  "boot_id": "1-64 caracteres",
  "events": [{"event_uid": "uuid", "seq": 0, "category": "process", "action": "start",
              "occurred_at": "2026-10-22T10:00:00.123+00:00", "source": "psutil_poll",
              "instance_key": "32 hex o null", "data": {}}],
  "stats": {"queued": 0, "dropped_total": 0, "dropped_since_last": 0,
            "oldest_queued_at": null, "process_poll_seconds": 5, "collectors": {}}
}
```

Respuesta 200:

```json
{"asset_id": "uuid", "accepted": 1, "duplicates": 0, "rejected": [{"index": 3, "code": "unknown_action"}]}
```

### Orden de proceso y errores del lote

1. Cuerpo: limitado por `MAX_REQUEST_BYTES` (4 MiB por defecto) en el middleware.
2. Con `Content-Encoding: gzip`, se descomprime con el mismo tope sobre el tamaño
   **descomprimido**: si lo supera, 413 `payload_too_large` (una bomba de compresión no agota
   la memoria); gzip corrupto, 422.
3. Validación del sobre (`ActivityBatchIn`, claves desconocidas prohibidas): `events` de 1 a
   1000, `boot_id` de 1 a 64. Si falla, 422 y no se guarda nada.
4. Autenticación del agente: agente desconocido, token ausente, incorrecto o revocado dan el
   mismo 401.
5. Límite de ritmo: `TELEMETRY_ACTIVITY_MAX_PER_MINUTE` lotes (120 por defecto) por
   `agent_id` en una ventana de 60 s, con el backend de `RATE_LIMIT_BACKEND` (memoria o
   PostgreSQL). Por encima: 429 `rate_limited` con `Retry-After`. Se cuenta después de
   autenticar: quien no tiene el token no puede gastar el cupo de un agente real.
6. Validación evento a evento (ver abajo), inserción y efectos.

`stats` ignora claves que no conoce (un agente más nuevo puede añadir contadores).

### Validación por evento

Cada evento se valida por separado: uno inválido se rechaza solo, con su índice en el lote, y
el resto sigue.

| Código | Motivo |
|---|---|
| `invalid_event` | No cumple `ActivityEventIn`: falta un campo, `event_uid` no es UUID, `seq` fuera de 0..2^62, `category` fuera del catálogo, `occurred_at` sin zona horaria, `instance_key` que no son 32 hexadecimales, una clave desconocida en el evento... |
| `unknown_action` | La acción no está en el catálogo de su categoría |
| `unknown_source` | `source` fuera del catálogo (`psutil_poll`, `sysmon`, `security_4688`, `journald`, `proc`, `unified_log`, `service_poll`, `task_poll`, `persistence_poll`, `firewall_poll`, `protection_poll`, `agent`) |
| `occurred_in_future` | `occurred_at` más de 10 minutos por delante del reloj del servidor |
| `invalid_data` | Un campo conocido de `data` tiene un tipo o rango inválido |

En `data`, las claves desconocidas se descartan sin error (compatibilidad hacia delante) y los
textos se acotan por campo (por ejemplo, `name` 255, `exe` 1024, `cmdline` 8192) y se limpian
de caracteres no imprimibles. Las IP se normalizan.

### Deduplicación

- Inserción con `ON CONFLICT DO NOTHING` sobre `(asset_id, event_uid)`: reenviar un lote ya
  guardado (respuesta perdida, cola offline del agente) cuenta los eventos como
  `duplicates` y no cambia nada.
- Un `event_uid` repetido dentro del mismo lote se ignora sin contarse.
- Solo los eventos realmente nuevos actualizan `process_instances` y pasan al motor de
  detección.

### Efectos de un lote aceptado

- `process/start` crea o actualiza la instancia (`pid`, padre, nombre, ruta, línea de
  comandos ya redactada, usuario, hash, firmante, integridad, `started_at`); `process/stop`
  fija `ended_at`. La instancia guarda el `boot_id` del lote.
- `stats` sustituye `assets.telemetry_status` (con el `boot_id`) y `telemetry_status_at`.
- Cuenta como contacto del agente (`record_contact`): actualiza `last_seen_at` y cierra la
  alerta de agente sin contacto, como cualquier otra llamada autenticada.
- Los eventos que encajan en un patrón de comportamiento generan señales
  ([behavioral-detection.md](behavioral-detection.md)).

## Línea de comandos: `TELEMETRY_CMDLINE_POLICY`

El servidor vuelve a aplicar su política a `data.cmdline` de cada `process` antes de guardar
nada, en la actividad y en la instancia. El agente aplica antes la suya (`[telemetry] cmdline`):
el servidor no puede recuperar lo que el agente ya quitó, así que se guarda lo más restrictivo
de las dos.

| Valor | Efecto |
|---|---|
| `off` | La línea de comandos no se guarda |
| `redacted` (por defecto) | Se enmascara y se corta a 2048 caracteres |
| `full` | Se guarda tal cual, cortada a 8192 caracteres |

Con `redacted` se sustituye por `[REDACTED]`:

- credenciales en una URL (`https://usuario:clave@host` → `https://[REDACTED]@host`);
- la clave de `-u`, `--user`, `--proxy-user`, `--http-user` con forma `usuario:clave`;
- el valor tras `Bearer` o `Basic` (8 o más caracteres);
- el valor de los modificadores `-`, `--` o `/` llamados `p`, `pw`, `pwd`, `pass`, `passwd`,
  `password`, `secret`, `token`, `apikey`, `api-key`, `api_key`, `key`, `auth`,
  `credential` o `credentials`, seguidos de `:`, `=` o espacio;
- el valor de asignaciones cuyo nombre contiene `password`, `passwd`, `secret`, `token`,
  `apikey`, `api_key`, `access_key` o `client_secret` (`DB_PASSWORD=...`).

Además, un bloque base64 de 120 o más caracteres (por ejemplo, el de `-EncodedCommand`) se
sustituye por `[BASE64:<longitud>]`: la regla de comportamiento solo necesita saber que hay
una orden codificada.

Es una redacción por patrones, no una garantía: un secreto pasado de otra forma (posicional,
en un nombre de opción no listado) se guarda. Y tiene falsos positivos conocidos: `-p 22` de
`ssh` también se enmascara. `GET /assets/{id}/telemetry-status` informa la política vigente
(`cmdline_policy`).

## Identidad de proceso: `instance_key` y PID reutilizado

`instance_key` lo calcula el agente: los 32 primeros hexadecimales de
`sha256("{boot_id}|{pid}|{create_time_ms}")`. El servidor solo exige el formato (32
hexadecimales) y lo usa como clave única por activo. Como incluye el arranque y la hora de
inicio, un PID reutilizado da otra clave y nunca se confunde con el proceso anterior
(`test_pid_reuse_keeps_distinct_instances`).

`parent_relation` (lo decide el agente):

- `observed`: el padre existía y arrancó antes que el hijo;
- `inferred`: padre conocido sin hora de inicio (Sysmon);
- `missing`: el padre ya no existía;
- `pid_reused`: el PID del padre pertenece a un proceso más nuevo que el hijo.

El árbol solo cuelga un hijo de su padre con `observed` o `inferred`. Con `missing`,
`pid_reused` o sin relación, el proceso aparece como raíz.

## Vida de un proceso y `boot_id`

Si el equipo se apaga, el agente no envía el fin de sus procesos. Por eso, sin `at`, un proceso
cuenta como vivo solo si no tiene `ended_at` **y** su `boot_id` es el del último `stats` del
agente (`assets.telemetry_status.boot_id`). Los de un arranque anterior sin fin no aparecen como
vivos (`test_processes_from_a_previous_boot_are_not_alive`).

Con `at`, se muestran los procesos con `started_at <= at` (o desconocido) y
`ended_at >= at` (o sin fin), sin comprobar el arranque.

## Permisos

`telemetry:read` (analyst y admin) para todas las rutas de lectura de este documento,
incluido `/endpoint/metrics`. El viewer no ve actividad, árbol ni líneas de comandos. No existe
un permiso `process_tree:read` separado. Las lecturas de líneas de comandos no generan
auditoría propia en el código actual.

## API de lectura (`/api/v1`)

Activo o instancia inexistentes: 404 `not_found`.

### `GET /assets/{asset_id}/process-tree`

Un nivel del árbol, nunca el árbol entero (carga diferida).

| Parámetro | Efecto |
|---|---|
| sin `parent` ni `search` | Raíces: sin padre, con relación que no es `observed`/`inferred`, o cuyo padre no está registrado |
| `parent` (32 hex) | Hijos de esa instancia con relación `observed` o `inferred` |
| `search` (1-128) | Coincidencias planas por nombre o ruta (contiene, sin distinguir mayúsculas) o PID exacto; la UI abre el detalle para ver los antecesores |
| `at` | Procesos vivos en ese instante (regla de la sección anterior) |
| `limit` | 1-200, 100 por defecto |

Sin `at`, cada nivel incluye los procesos vivos y los terminados en la última hora. Orden:
`started_at` ascendente (desconocidos primero). Respuesta: `{"asset_id", "parent", "at",
"nodes": [...], "truncated"}`; cada nodo lleva sus datos, `running` (`ended_at` nulo) y
`children_count` (solo hijos `observed`/`inferred`).

### `GET /assets/{asset_id}/process-instances/{instance_key}`

La instancia, sus antecesores (del padre hacia la raíz, como mucho 32, siguiendo solo
relaciones `observed`/`inferred` y sin ciclos) y sus últimas 50 conexiones (eventos `network`
con ese `instance_key`). No incluye detecciones relacionadas.

### `GET /assets/{asset_id}/activity`

Eventos de actividad, del más reciente al más antiguo. Filtros: `category`, `action` (≤ 24),
`instance_key`, `start`, `end` (sobre `occurred_at`). Paginación por cursor: `before_id` =
`next_before_id` de la página anterior. `limit` 1-500 (100).

### `GET /assets/{asset_id}/telemetry-status`

```json
{
  "asset_id": "uuid",
  "enabled": true,
  "reported_at": "...",
  "stats": {"queued": 0, "dropped_total": 0, "collectors": {"process": "active"}, "boot_id": "..."},
  "last_event_at": "...",
  "events_last_hour": 42,
  "ingest_lag_p50_seconds": 3.2,
  "ingest_lag_p95_seconds": 6.8,
  "cmdline_policy": "redacted"
}
```

- `enabled`: el agente ha enviado `stats` alguna vez.
- `events_last_hour` y el retraso de ingesta se calculan sobre los eventos **recibidos** en la
  última hora; el retraso es `received_at - occurred_at` (incluye el intervalo de sondeo del
  agente y el tiempo en su cola offline, y depende de que los relojes estén sincronizados).
- `stats.dropped_total` y `dropped_since_last` cuentan los eventos que el agente descartó al
  llenarse su cola; `collectors` dice qué colector está `active`, `unavailable`,
  `permission_denied`, `disabled` o en `error`.

### `GET /endpoint/metrics`

Métricas globales medidas a partir de marcas guardadas (no estimaciones):

| Campo | Cálculo |
|---|---|
| `window_hours` | 1 |
| `events_last_hour`, `assets_reporting_last_hour` | Eventos recibidos y activos distintos en la última hora |
| `ingest_lag_p50_seconds`, `ingest_lag_p95_seconds`, `ingest_lag_max_seconds` | `received_at - occurred_at` de esos eventos |
| `behavior_detections_24h` | Detecciones `BEH-*` creadas en 24 horas |
| `detection_latency_p50_seconds`, `detection_latency_p95_seconds` | `created_at` de la detección - `first_seen_at` (primera evidencia) de esas detecciones |

## Retención

En el job `retention` de 6E (`purge_endpoint`), cada `RETENTION_SWEEP_INTERVAL_SECONDS`:

| Variable | Defecto | Qué se borra |
|---|---|---|
| `TELEMETRY_ACTIVITY_RETENTION_DAYS` | 14 | Eventos con `received_at` anterior al plazo |
| `PROCESS_INSTANCE_RETENTION_DAYS` | 30 | Instancias con `last_seen_at` anterior al plazo **y** (terminadas antes del plazo **o** de un arranque distinto del actual del activo) |

Un proceso sin fin del arranque actual (un servicio que lleva meses vivo) se conserva aunque
sea antiguo (`test_retention_keeps_long_running_processes`). Vacío = sin purga.

## Configuración

| Variable | Defecto | Rango |
|---|---|---|
| `TELEMETRY_CMDLINE_POLICY` | `redacted` | `off`, `redacted`, `full` |
| `TELEMETRY_ACTIVITY_MAX_PER_MINUTE` | 120 | 1-10000 |
| `TELEMETRY_ACTIVITY_RETENTION_DAYS` | 14 | 1-3650 o vacío |
| `PROCESS_INSTANCE_RETENTION_DAYS` | 30 | 1-3650 o vacío |
| `MAX_REQUEST_BYTES` | 4194304 | Tope del cuerpo y del cuerpo descomprimido |

## Rendimiento medido

`qa/perf_endpoint.py` en el contenedor de desarrollo de la fase (PostgreSQL 16 local, base de
pruebas, un solo proceso), 20 lotes de 1000 eventos de proceso con línea de comandos
redactada (19 380 instancias, raíces con 50 hijos cada una):

| Medida | Resultado |
|---|---|
| Ingesta, lote de 1000 eventos | mediana 601 ms, p95 1349 ms (unos 1200 eventos/s) |
| Árbol: 100 raíces | 13.8 ms |
| Árbol: hijos de una raíz | 3.1 ms |
| Árbol: búsqueda por nombre | 17.5 ms |
| Actividad: página de 100 | 2.9 ms |

Un agente con el sondeo por defecto (5 s) envía lotes mucho más pequeños; el tope de 1000
eventos es el peor caso. Las cifras del PC de Jesus y de un servidor real pueden variar.

## Límites conocidos

- La actividad depende de lo que recoge el agente: por sondeo (5 s por defecto) no se ven los
  procesos que viven menos que el intervalo, salvo con Sysmon en Windows. Ver
  [endpoint-telemetry-agent.md](endpoint-telemetry-agent.md).
- El retraso de ingesta usa el reloj del host: un reloj desfasado lo falsea (los eventos más
  de 10 minutos en el futuro se rechazan).
- Sin colector DNS en el agente 0.5.0: la categoría `dns` se acepta pero hoy no llega.

## Pruebas

`tests/test_endpoint_telemetry.py`: rechazo individual de eventos con su código, claves
desconocidas descartadas y reenvío como duplicado, gzip y bomba de compresión, token
obligatorio, redacción en el servidor y políticas, 429, árbol perezoso con recuento de hijos,
PID reutilizado, procesos de un arranque anterior, actividad, estado y métricas, 404,
permisos, retención de procesos de larga duración y contacto del agente.

## Validación pendiente en equipos reales

1. Aplicar la migración 0041 en `sentra_test` y, tras revisar, en producción.
2. Actualizar un agente a 0.5.0 en Windows y en Linux y comprobar `telemetry-status`
   (colectores, cola, retraso de ingesta).
3. Abrir el árbol de procesos, expandir varios niveles y comprobar que un proceso de antes de
   un reinicio no aparece como vivo.
4. Lanzar un comando con `--password x` y comprobar que se guarda `[REDACTED]`.
5. Medir `/endpoint/metrics` con varios agentes reales durante un día.
