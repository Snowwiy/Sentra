# Observabilidad: salud, logs, métricas y errores (Fase 4M)

## Salud

| Ruta | Para qué | Respuesta |
| --- | --- | --- |
| `GET /api/v1/health` | *liveness*: el proceso responde | `200 {"status":"ok"}`. No toca la base. |
| `GET /api/v1/health/ready` | *readiness*: puede atender tráfico | `200` o `503` con `{"status":"ready"\|"not_ready","checks":{...}}` |

`checks` solo contiene `ok`/`error` por dependencia:

- `api`: `error` mientras el proceso se está apagando (el proxy deja de enviarle tráfico);
- `database`: PostgreSQL responde a `SELECT 1`;
- `migrations`: la base está en la revisión del código.

Las rutas de salud son públicas y no muestran versiones, hosts, puertos, nombres de base ni
errores internos (la versión se ve en el dashboard, con sesión). Los fallos se registran en el
log del servidor, sin traza.

La **IA no forma parte de readiness**: es opcional. Con el runtime local caído Sentra sigue
`ready`; el estado de la IA está en `GET /api/v1/ai/status` (con sesión).

Los jobs de fondo (detección, riesgo, offline, retención, discovery) tampoco tumban la
readiness: un fallo en una vuelta se registra y se reintenta en la siguiente. Se vigilan con
las métricas `sentra_job_*` (abajo).

## Logs

- JSON de una línea por evento (`LOG_FORMAT=json`, por defecto); `text` para consola.
- Campos: `timestamp` (UTC ISO 8601), `level`, `logger`, `event` (= `message`),
  `request_id` cuando el evento ocurre dentro de una petición, y campos propios del evento.
- Cada petición registra `sentra.request` con método, ruta, estado, duración y `client` (la IP
  real resuelta desde `TRUSTED_PROXIES`).
- `X-Request-ID`: si el cliente (o el proxy) envía uno válido se reutiliza; si no, se genera.
  Se devuelve en la respuesta y aparece en todos los logs de esa petición y en el cuerpo de
  los errores 500/503: un usuario puede dar ese identificador y se encuentra en el log.
- Redacción central: contraseñas, tokens, cookies, CSRF, credenciales de agentes, claves de
  IA y contraseñas en URLs de base se sustituyen por `[REDACTED]`, también dentro de trazas.
- **Auditoría separada**: `sentra.audit` (quién hizo qué, en la tabla `audit_events`, sin
  purga) frente a los logs técnicos. Filtrar con `jq 'select(.logger=="sentra.audit")'`.

Rotación:

- **Linux/systemd**: stdout → journald, que rota según `/etc/systemd/journald.conf`
  (`SystemMaxUse=2G`, por ejemplo). `journalctl -u sentra -o cat | jq .`
- **Windows**: `LOG_FILE=C:\ProgramData\Sentra\logs\sentra.log` con rotación por tamaño
  (`LOG_FILE_MAX_MB=50`, `LOG_FILE_BACKUPS=10`): nunca logs infinitos.

## Errores

Toda respuesta de error tiene la misma forma:

```json
{"error": {"code": "rate_limited", "message": "...", "request_id": "…"}}
```

- `code` es estable (los clientes deciden con él); `message` es seguro para mostrar.
- `request_id` va en los 500 y 503 (y siempre en la cabecera `X-Request-ID`).
- Nunca trazas, SQL, rutas del servidor ni versiones de librerías en la respuesta.
- 503 = transitorio (base caída, pool agotado): reintentable. 429 lleva `Retry-After`.

## Métricas (Prometheus)

`GET /api/v1/metrics`, formato de texto de Prometheus. **Apagado por defecto**.

```
METRICS_ENABLED=true
METRICS_ALLOWED_NETWORKS=127.0.0.1,::1      # o la IP del servidor Prometheus
METRICS_TOKEN=<python -m app.cli generate-secret>
```

Capas: desactivado → 404; IP del cliente fuera de `METRICS_ALLOWED_NETWORKS` → 404; sin el
`Authorization: Bearer <METRICS_TOKEN>` correcto → 401. El Caddyfile de referencia devuelve
404 en `/api/v1/metrics`: se consulta en `http://127.0.0.1:8000` desde el propio servidor o
desde un Prometheus en la red autorizada que llegue directo (abrir el 8000 solo para él).

```yaml
# prometheus.yml
scrape_configs:
  - job_name: sentra
    metrics_path: /api/v1/metrics
    authorization: {credentials_file: /etc/prometheus/sentra_token}
    static_configs: [{targets: ["127.0.0.1:8000"]}]
```

| Métrica | Tipo | Etiquetas |
| --- | --- | --- |
| `sentra_http_requests_total` | counter | `method`, `route` (plantilla, p. ej. `/api/v1/assets/{asset_id}`), `status` (2xx, 4xx, 5xx) |
| `sentra_http_request_duration_seconds` | histogram | `route` |
| `sentra_rate_limited_total` | counter | `scope` (login, agent_register, ai, api_mutations, api_searches) |
| `sentra_job_runs_total` | counter | `job`, `result` (success, failure, skipped) |
| `sentra_job_last_success_timestamp_seconds` | gauge | `job` |
| `sentra_job_last_duration_seconds` | gauge | `job` |
| `sentra_db_pool_connections` | gauge | `state` (checked_out, idle, overflow) |
| `sentra_assets` / `sentra_assets_by_method` | gauge | `status` / `method` |
| `sentra_detections_active` | gauge | `severity` |
| `sentra_incidents_active` | gauge | `kind` (active, critical) |
| `sentra_alerts_active` | gauge | — |
| `sentra_queue_pending` | gauge | `queue` (risk, detection) |
| `sentra_process_start_time_seconds`, `sentra_metrics_generated_timestamp_seconds` | gauge | — |

Sin etiquetas sensibles: nunca IPs, hostnames, usuarios, ids de activos ni rutas con ids
(se usa la plantilla de la ruta). Contadores HTTP, jobs y pool son **por proceso** (con
varios workers, sumar por instancia); los de activos, detecciones, incidentes y colas salen
de la base y son globales.

Alertas útiles:

- `time() - sentra_job_last_success_timestamp_seconds{job="detection-engine"} > 300`
- `sentra_queue_pending{queue="risk"} > 1000` durante 15 min
- `rate(sentra_http_requests_total{status="5xx"}[5m]) > 0`
- `increase(sentra_rate_limited_total{scope="login"}[10m]) > 20` (fuerza bruta)
- el servicio `sentra-backup` en estado `failed`
