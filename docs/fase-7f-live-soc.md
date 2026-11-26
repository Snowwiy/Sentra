# Fase 7F.7: Live SOC (stream SSE)

La página **Live SOC** (`/live`) muestra en directo lo que entra en la base de Sentra:
detecciones, alertas, actividad de casos y alertas SIEM. No hay datos simulados ni de relleno:
si no llega nada, la página lo dice.

## Endpoint: `GET /api/v1/live/stream`

- Requiere sesión de consola (cookie) y `monitoring:read`. Anónimo: 401.
- `site_id` opcional (UUID público). Un site inexistente responde 404 antes de abrir el stream.
- Respuesta `text/event-stream` con `Cache-Control: no-store` y `X-Accel-Buffering: no` (para que
  Caddy o nginx no acumulen los mensajes).

### Canales y permisos

Cada canal se decide en el servidor con los permisos actuales del usuario; el cliente no
elige canales.

| Canal | Permiso | Origen | Campos |
| --- | --- | --- | --- |
| `detection` | `monitoring:read` | `detections` | id, regla, título, severidad, activo, hora |
| `alert` | `monitoring:read` | `alerts` | id, mensaje, severidad, activo, hora |
| `incident` | `incidents:read` | `incident_activities` | id del caso, número, título, resumen de la actividad |
| `siem` | `siem:evidence` | `siem_events` (solo categoría `detection`) | id, fuente, tipo, severidad, mensaje |

Solo viajan campos de catálogo: los `details` de una detección, el registro original de un
evento SIEM o las notas de un caso no salen por el stream. Todo el texto es de fuentes no
confiables: el servidor lo serializa como JSON en una sola línea `data:` (un salto de línea en
un mensaje no puede inyectar campos SSE) y el navegador lo pinta como texto.

### Mensajes

| Evento | Cuándo |
| --- | --- |
| `status` | Al empezar (`live`, `catching_up` o `degraded` con `reason`) y al terminar de recuperar el atraso |
| `detection`, `alert`, `incident`, `siem` | Una fila nueva; `id:` lleva el cursor |
| `: ping` | Latido cada `LIVE_HEARTBEAT_SECONDS` |
| `reconnect` | Se cumplió `LIVE_MAX_STREAM_SECONDS` o el servidor se apaga; el navegador reconecta solo |
| `session_ended` | La sesión se revocó, caducó o perdió `monitoring:read`; el cliente no reintenta |

### Cursores y reconexión

El cursor es `d{n}-a{n}-i{n}-s{n}`: el último id visto en cada tabla. EventSource lo reenvía
como `Last-Event-ID` al reconectar; si la conexión se cerró del todo, el cliente abre una nueva
con `?resume=` y espera creciente (2, 4, 8... hasta 60 s). Un cursor malformado se ignora y el
stream empieza en el presente.

Si el atraso es mayor que `LIVE_BACKLOG_LIMIT`, el servidor no lo reenvía: salta al presente y
manda `degraded` con `backlog_skipped`. La UI avisa de consultar las listas para el resto.

### Varios workers sin Redis

Cada stream lee la base con su propio cursor y una sesión corta por consulta
(`LIVE_POLL_INTERVAL_MS`); no hay memoria compartida entre procesos. Los límites de streams
por usuario y totales (`LIVE_MAX_STREAMS_PER_USER`, `LIVE_MAX_STREAMS`) son **por worker**:
con N workers el máximo real es N veces el configurado. Por encima: 429 `live_stream_limit`.

### Sesión

La sesión se revalida cada `LIVE_REVALIDATE_SECONDS` (revocación, caducidad, permisos). El
stream **no** alarga la sesión inactiva: `last_seen_at` no se actualiza mientras solo está
abierta esta página.

## Frontend

- `src/lib/liveStream.ts`: reducer puro (`liveReducer`), buffer circular de 200 mensajes
  (`BUFFER_SIZE`) y hook `useLiveStream`.
- Estados visibles: Conectando, En directo, Reconectando, Desconectado, Degradado y
  Recuperando eventos pendientes.
- Los contadores cuentan lo recibido desde que se abrió la página. El panel "Fuentes SIEM"
  (con `siem:read`) usa `GET /siem/overview` cada 30 s.

## Ajustes

| Variable | Defecto | Uso |
| --- | --- | --- |
| `LIVE_POLL_INTERVAL_MS` | 2000 | Intervalo de consulta |
| `LIVE_HEARTBEAT_SECONDS` | 15 | Latido |
| `LIVE_MAX_STREAM_SECONDS` | 900 | Duración máxima de un stream |
| `LIVE_REVALIDATE_SECONDS` | 30 | Revalidación de sesión y permisos |
| `LIVE_MAX_STREAMS_PER_USER` | 3 | Por worker |
| `LIVE_MAX_STREAMS` | 50 | Por worker |
| `LIVE_BACKLOG_LIMIT` | 500 | Atraso máximo reenviado |

## Pruebas

`tests/test_live_7f7.py` (12), `src/lib/liveStream.test.ts` y `src/pages/LiveSocPage.test.tsx`.

## Limitaciones

- Una fila confirmada con un id menor que otra ya enviada (transacciones largas concurrentes)
  puede no aparecer en el stream. Sigue en las listas.
- Cada stream abierto ocupa un hilo del pool durante cada consulta; con muchos analistas,
  ajustar `LIVE_POLL_INTERVAL_MS`.
- El canal `siem` solo emite alertas (categoría `detection`), no todo el tráfico normalizado.
