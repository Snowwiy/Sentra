# Sensores distribuidos (Fase 5F)

Un **sensor** es un proceso desplegado dentro de un site remoto (posiblemente detrás de
NAT) que observa la red de ese site y ejecuta tareas de descubrimiento **autorizadas** por
el servidor. No es el agente de endpoint: el agente monitoriza su propio equipo; el sensor
descubre otros equipos de su red. Código del sensor: `sensor/` (paquete `sentra_sensor`,
solo biblioteca estándar). Seguridad: [sensor-security.md](sensor-security.md). Despliegue:
[sensor-deployment.md](sensor-deployment.md).

Fase 6A: los sensores 0.2.0 aceptan además `discovery_advanced` (capability
`network.discovery.advanced`, límites revalidados en el sensor); ver
[advanced-network-discovery.md](advanced-network-discovery.md).

## Arquitectura

```
Sentra Server  <──HTTPS saliente──  Sensor (site B)  ──TCP/ICMP/ARP──>  red del site B
     │
     └─ discovery local (solo site por defecto)
```

- Solo conexiones **salientes** del sensor (HTTPS con TLS verificado). El servidor nunca
  conecta con el sensor: funciona tras NAT sin abrir puertos.
- Protocolo pull con polling (sin WebSocket, MQTT, Kafka ni Redis).
- El servidor es la autoridad: decide el alcance (redes del site), crea los jobs y convierte
  las observaciones en activos con la misma lógica que el discovery local (`ResultApplier`),
  restringida al site del job. El sensor nunca decide "este es el activo X".

## Ciclo de un job

1. Un operador (`discovery:run`) pide un discovery con `execution_target: "sensor"`,
   `site_id` y `sensor_id`. El servidor comprueba: site activo; sensor del mismo site, activo,
   con versión soportada y la capability `network.discovery.basic`; target dentro de una red
   habilitada del site y dentro del límite de hosts. Crea un `discovery_job` (QUEUED,
   `execution_target=sensor`) y un `sensor_job` dirigido a ese sensor.
2. El sensor ve `pending_jobs` en su heartbeat y hace `POST /sensor/jobs/poll`. Recibe solo
   jobs **suyos**: nunca de otro sensor ni de otro site. El job queda `leased` (intento +1,
   lease `SENSOR_JOB_LEASE_SECONDS`). Dos polls concurrentes nunca reciben el mismo job
   (`FOR UPDATE SKIP LOCKED`).
3. `POST /sensor/jobs/{id}/start`: el job pasa a `running`; el discovery a RUNNING.
4. `POST /sensor/jobs/{id}/results` en lotes, cada uno con un `batch_id` (UUID). Un lote
   repetido con el mismo contenido devuelve `duplicate=true`; con contenido distinto, 409
   `sensor_batch_conflict`. Las observaciones de la misma dirección se fusionan.
5. `POST /sensor/jobs/{id}/complete` con el resultado (`completed`, `cancelled`,
   `timed_out`, `failed`) y `batches_sent`. El servidor aplica lo recibido:
   - Completo: igual que un scan local (activos nuevos, cambios, ausencias si el scan fue
     completo).
   - Si faltan lotes (`batches_sent` > recibidos), se aplica como **parcial**
     (`stop_reason=incomplete`): se crean y actualizan activos, pero no se sacan
     conclusiones negativas (nada se marca como desaparecido).
   - `failed`: el discovery termina FAILED, sin aplicar nada.

Estados del `sensor_job`: `pending → leased → running → succeeded | failed | cancelled`,
y `expired` si nadie lo recoge antes de `SENSOR_JOB_TTL_MINUTES`.

## Recuperación y mantenimiento

El trabajo periódico `sensor-maintenance` (lock consultivo propio, cada
`SENSOR_SWEEP_INTERVAL_SECONDS`) y cada heartbeat del sensor ejecutan el barrido:

- `pending` caducado → `expired` (discovery FAILED, `stop_reason=expired`).
- `leased` con lease vencido → vuelve a `pending` si quedan intentos
  (`SENSOR_JOB_MAX_ATTEMPTS`), si no `failed` (`lease_expired`).
- `running` con plazo vencido (plazo del scan + `SENSOR_RESULT_GRACE_SECONDS`) → `failed`
  (`sensor_lost`, discovery `interrupted`). Lo recibido no se aplica.

Revocar o deshabilitar un sensor cancela sus jobs abiertos. Cancelar un discovery cancela
su job: si está `pending`/`leased` al momento; si está `running` se marca y el sensor lo
recibe en `cancel_job_ids` (heartbeat) o `cancel_requested` (resultados).

## Estado del sensor

Guardado: `active`, `disabled`, `revoked`. Mostrado (derivado de `last_seen_at`, nunca
desfasado): `pending` (sin heartbeat aún), `online` (≤ `SENSOR_OFFLINE_AFTER_SECONDS`),
`offline`, `stale` (> `SENSOR_STALE_AFTER_SECONDS`), `disabled`, `revoked`. Versión:
`supported`, `outdated` (< recomendada) o `unsupported` (< `SENSOR_MIN_VERSION`, sin jobs).

## Offline y spool

El sensor guarda lo observado en un spool SQLite local acotado (por elementos, tamaño y
edad) y lo entrega cuando vuelve la conexión, con los mismos `batch_id`: el servidor
deduplica, así que una reconexión no crea duplicados (entrega at-least-once, efecto
exactly-once). Si el servidor da el job por perdido mientras el sensor estaba aislado, sus
envíos posteriores reciben 409 y el sensor los descarta (registrado en su log).

## Protocolo (`/api/v1/sensor`, credencial Bearer del sensor)

| Endpoint | Uso |
|----------|-----|
| `POST /sensor/enroll` | Cabecera `X-Sensor-Enrollment-Token` (un solo uso). Devuelve `sensor_id`, `site_id`, credencial (una vez) y configuración. |
| `POST /sensor/heartbeat` | Salud (claves conocidas), configuración efectiva, `pending_jobs`, `cancel_job_ids`, `rotate_credential`. |
| `POST /sensor/jobs/poll` | Hasta `max_jobs` jobs propios. Sensor deshabilitado: 403. |
| `POST /sensor/jobs/{id}/start` · `/results` · `/complete` | Ciclo del job. |
| `POST /sensor/credential/rotate` | Rotación en dos fases. |

Errores: 401 `sensor_unauthorized` / `sensor_enrollment_invalid` (mismo error para token
inexistente, caducado, usado o revocado), 403 `sensor_revoked` / `sensor_disabled`, 404
`sensor_job_not_found` (también para jobs de otro sensor), 409 `sensor_job_finished` /
`sensor_job_not_leased` / `sensor_job_expired` / `sensor_batch_conflict` /
`sensor_batch_limit`, 413 cuerpo demasiado grande, 422 `sensor_batch_too_large` /
`sensor_observation_out_of_scope` / `sensor_timestamp_invalid`, 429 límite de peticiones.

## Administración (`/api/v1`)

- Lectura (`monitoring:read`): `GET /sensors?site_id=`, `GET /sensors/{id}`,
  `GET /sensors/{id}/jobs`.
- `sensors:manage` (solo admin): `GET|POST /sensors/enrollment-tokens`,
  `POST /sensors/enrollment-tokens/{id}/revoke`, `POST /sensors/{id}/revoke|disable|enable|rotate-credential`.
- UI: Sites (sites y redes) y Sensores (lista con estado, alta con token de un solo uso,
  acciones, últimos jobs). El modal de discovery de la página Red permite elegir el site y
  el sensor.

## Configuración (servidor)

Todas opcionales; valores por defecto en `app/core/config.py`:

| Variable | Defecto | Uso |
|----------|---------|-----|
| `SENSOR_ENROLLMENT_TOKEN_TTL_MINUTES` | 60 | Vida del token de enrolamiento. |
| `SENSOR_ENROLL_MAX_PER_MINUTE` | 10 | Enrolamientos por IP. |
| `SENSOR_HEARTBEAT_MAX_PER_MINUTE`, `SENSOR_POLL_MAX_PER_MINUTE` | 30 | Por sensor. |
| `SENSOR_HEARTBEAT_INTERVAL_SECONDS`, `SENSOR_POLL_INTERVAL_SECONDS` | 30 | Enviados al sensor. |
| `SENSOR_OFFLINE_AFTER_SECONDS` / `SENSOR_STALE_AFTER_SECONDS` | 180 / 86400 | Estado mostrado. |
| `SENSOR_JOB_TTL_MINUTES` | 60 | Caducidad de un job no recogido. |
| `SENSOR_JOB_LEASE_SECONDS` | 120 | Lease entre poll y start. |
| `SENSOR_RESULT_GRACE_SECONDS` | 14400 | Margen tras el plazo del scan (cortes del enlace). |
| `SENSOR_JOB_MAX_ATTEMPTS` | 2 | Reintentos de un lease vencido. |
| `SENSOR_MAX_REQUEST_KB` | 1024 | Tamaño máximo de petición en `/api/v1/sensor/*`. |
| `SENSOR_MAX_OBSERVATIONS_PER_BATCH` / `SENSOR_MAX_PORTS_PER_OBSERVATION` / `SENSOR_MAX_BATCHES_PER_JOB` | 500 / 256 / 1000 | Límites de resultados. |
| `SENSOR_MAX_CLOCK_SKEW_SECONDS` | 300 | Tolerancia de `observed_at`. |
| `SENSOR_MIN_VERSION` / `SENSOR_RECOMMENDED_VERSION` | 0.1.0 | Política de versión. |
| `SENSOR_SWEEP_INTERVAL_SECONDS` | 30 | Barrido de mantenimiento. |

## Limitaciones

- Un único tipo de job: `discovery_basic` (TCP connect, ICMP y ARP opcionales, DNS inverso).
  Sin SNMP, LLDP/CDP, topología ni Wi-Fi (fases 6A-6E).
- Discovery programado (schedule) solo para el discovery local.
- Sin mTLS: credencial Bearer por sensor (mismo modelo que los agentes).
