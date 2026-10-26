# Variables de entorno del servidor

Referencia que antes estaba en el README (movida en la Fase 7A sin cambios de contenido). El
`.env` de la raíz se crea con `scripts/setup_windows.ps1` a partir de `.env.example`, que es la
referencia completa y comentada; nunca se versiona. Los ajustes de cada módulo están en su
documento de `docs/`.

Root `.env` (template: `.env.example`, never committed):

| Variable | Purpose |
|----------|---------|
| `ENVIRONMENT` | `development`, `test` or `production` (production hides `/docs`, exige HTTPS y se niega a arrancar con una configuración insegura: `python -m app.cli production-check`) |
| `LOG_LEVEL` | Log level for JSON logs |
| `DATABASE_URL` | Main database, `postgresql+psycopg://user:pass@host:port/db` |
| `TEST_DATABASE_URL` | Separate database used by the test suite |
| `CORS_ORIGINS` | Comma separated browser origins allowed to call the API |
| `MAX_REQUEST_BYTES` | Largest accepted request body, default 4 MiB (413 above it) |
| `AGENT_ENROLLMENT_KEY` | Legacy shared secret agents can enroll with (min 24 chars; unset disables key-based enrollment). New agents should use one-time enrollment tokens |
| `ENROLLMENT_TOKEN_TTL_MINUTES` | Default lifetime of one-time enrollment tokens (default 15, max 1440) |
| `ADMIN_API_KEY` | Legacy: operator key (`X-Admin-Key`) for the administration API (enrollment tokens), only for scripts on the server; unset = those endpoints disabled (403). The dashboard and the CLI do not use it |
| `SESSION_TTL_HOURS`, `SESSION_IDLE_MINUTES` | Duración absoluta (12 h) e inactividad (60 min) de las sesiones del dashboard |
| `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_SAMESITE` | Cookie `Secure` (por defecto solo con `ENVIRONMENT=production`, que debe ir por HTTPS) y `strict`/`lax` |
| `LOGIN_RATE_WINDOW_MINUTES`, `LOGIN_MAX_FAILURES_PER_USER_IP`, `LOGIN_MAX_ATTEMPTS_PER_IP`, `LOGIN_MAX_FAILURES_PER_USER` | Límites de intentos de login (15 min; 5, 30, 50) |
| `AGENT_REGISTER_MAX_PER_MINUTE` | `POST /agents/register` por IP y minuto (30) |
| `ALLOWED_HOSTS` | Nombres de `Host` aceptados (vacío = cualquiera; recomendado en producción) |
| `AGENT_SERVER_URL` | URL agents use to reach this server, shown in the dashboard's install command (unset = suggested from local addresses) |
| `HEARTBEAT_TIMEOUT_SECONDS` | Seconds without contact before an asset is `offline` (default 90) |
| `ALERT_CPU_PERCENT`, `ALERT_RAM_PERCENT`, `ALERT_DISK_PERCENT` | Alert thresholds (default 90) |
| `ALERT_SUSTAINED_SAMPLES` | Consecutive samples over threshold before CPU/RAM alert (default 3) |
| `ALERT_WATCHED_SERVICES` | Services whose stop raises an alert (default `EventLog,WinDefend,mpssvc`; empty disables; services set to disabled are skipped) |
| `ALERT_CRITICAL_EVENTS` | `Provider:EventID` list that raises an alert on its own (default: unexpected shutdown 41/6008, log cleared 1102/104) |
| `ALERT_EVENT_BURST_COUNT`, `ALERT_EVENT_BURST_MINUTES` | Error/critical events from one asset within the window that raise a burst alert (default 10 in 10 min) |
| `ALERT_EVENT_QUIET_MINUTES` | Event-based alerts resolve after this long without firing again (default 60) |
| `BACKGROUND_JOBS_ENABLED`, `OFFLINE_SWEEP_INTERVAL_SECONDS` | Offline alert sweeper (default on, 30 s) |
| `TELEMETRY_RETENTION_DAYS`, `EVENT_RETENTION_DAYS` | Delete telemetry samples / host events older than N days (unset = keep forever, the default) |
| `CHANGE_RETENTION_DAYS`, `ALERT_RETENTION_DAYS` | Delete inventory changes / **resolved** alerts older than N days (unset = keep forever; active alerts are never deleted) |
| `RETENTION_SWEEP_INTERVAL_SECONDS` | How often the retention job runs when a retention is set (default 3600) |
| `DETECTION_*` | Motor de detección y correlación (Fase 4H): activado por defecto; ventanas, umbrales, alerta mínima (`DETECTION_ALERT_MIN_SEVERITY=high`), reglas desactivadas y retención de detecciones resueltas. Todas en [docs/detection-engine.md](detection-engine.md) |
| `SIGMA_DEFAULT_CONFIDENCE`, `RULE_TEST_MAX_HOURS`, `RULE_TEST_MAX_ROWS`, `RULE_TEST_TIMEOUT_SECONDS`, `RULE_TEST_PER_MINUTE` | Reglas personalizadas y Sigma (Fase 5A): confianza inicial de las reglas Sigma importadas (`low`) y límites de la prueba histórica (72 h, 20 000 filas, 10 s, 6 por usuario y minuto). [docs/custom-detection-rules.md](custom-detection-rules.md) |
| `RISK_*` | Risk Engine (Fase 4I): activado por defecto; umbrales de nivel (`RISK_LEVEL_THRESHOLDS=20,40,60,80`), decay, historial, alerta `risk_critical` y retención. Todas en [docs/risk-engine.md](risk-engine.md) |
| `VULN_*` | Vulnerabilidades (Fase 5B): evaluación por cola (`VULN_EVAL_INTERVAL_SECONDS=30`, reevaluación completa cada 24 h), evidencia antigua (72 h), capturas sin el componente antes de resolver (2), límites del catálogo (64 MiB, 200 000 registros), lotes de importación y alertas `vulnerability` con cooldown. Todas en [docs/vulnerability-management.md](vulnerability-management.md) |
| `THREAT_INTEL_*` | Threat Intelligence (Fase 5C): módulo activo (`THREAT_INTEL_ENABLED=true`), descargas por red **apagadas** (`THREAT_INTEL_SYNC_ENABLED=false`), espejos internos solo por `THREAT_INTEL_SOURCE_URLS` y `THREAT_INTEL_ALLOWED_NETWORKS`, límites de descarga (128 MiB, 1 000 000 registros), política de la detección TI-001 (`high_confidence_malicious`) e intervalo del job (60 s). Todas en [docs/threat-intelligence.md](threat-intelligence.md) |
| `AI_*` | AI Security Insights (Fase 4J): **desactivado por defecto** (`AI_ENABLED=false`); local-first (Fase 4J.1): modelo local OpenAI-compatible como Ollama, llama.cpp o vLLM (`AI_BASE_URL`, `AI_MODEL`, `AI_API_KEY` opcional), LAN solo con `AI_LOCAL_NETWORKS`, externos bloqueados salvo `AI_ALLOW_EXTERNAL=true` y sin fallback cloud, redacción, límites y timeouts. Todas en [docs/ai-security-insights.md](ai-security-insights.md) Gestor de modelos locales (Fase 4J.2): `AI_RUNTIME`, `AI_MODEL_DIRECTORIES`, contexto, margen de memoria y benchmark en [docs/local-model-manager.md](local-model-manager.md) |
| `TRUSTED_PROXIES` | Proxies (IPs/redes) cuyos `X-Forwarded-For/Proto` se aceptan (Fase 4M; por defecto `127.0.0.1,::1`) |
| `RATE_LIMIT_BACKEND`, `API_MUTATIONS_PER_USER_PER_MINUTE`, `API_SEARCHES_PER_USER_PER_MINUTE` | Rate limiting compartido en PostgreSQL en producción (`auto`) y límites por usuario del dashboard (120/min) |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT_SECONDS`, `DB_POOL_RECYCLE_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS`, `DB_STATEMENT_TIMEOUT_SECONDS` | Pool y tiempos máximos de PostgreSQL de la API |
| `LOG_FORMAT`, `LOG_FILE`, `LOG_FILE_MAX_MB`, `LOG_FILE_BACKUPS` | Logs JSON/texto y rotación propia a archivo (Windows) |
| `METRICS_ENABLED`, `METRICS_ALLOWED_NETWORKS`, `METRICS_TOKEN` | `/api/v1/metrics` Prometheus, apagado por defecto ([docs/observability.md](observability.md)) |
| `BACKUP_DIR`, `BACKUP_RETENTION_DAYS`, `PG_BIN_DIR`, `FRONTEND_DIST_DIR` | Copias de seguridad ([docs/backup-restore.md](backup-restore.md)) y build publicado |
| `DISCOVERY_ALLOWED_NETWORKS` | Networks agentless discovery may probe (empty = discovery off, the default). Internet space and huge ranges are refused. All `DISCOVERY_*` settings: [docs/discovery.md](discovery.md) |

Frontend variables are documented in `frontend/.env.example`.
