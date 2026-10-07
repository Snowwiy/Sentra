# Sentra

Real-time asset and security event monitoring platform. Sentra has its own architecture,
API and domain model; third-party tools (Wazuh, Suricata, Syslog, SNMP…) will plug in later
as optional integrations, never as the core.

## Current goal (phase 1: MVP foundation)

Register assets/agents, receive heartbeat and telemetry, store it with history, query assets
and see their state in a web dashboard. No advanced SOC features yet.

## Architecture

```
Agent ──HTTP/JSON──► Sentra API (FastAPI) ──SQLAlchemy──► PostgreSQL
                          ▲
Browser (React) ──────────┘   /api/v1
```

Backend layers (`backend/app/`):

| Layer | Responsibility |
|-------|----------------|
| `api/` | Thin routers and dependency wiring, versioned under `/api/v1` |
| `schemas/` | Pydantic request/response contracts |
| `services/` | Business logic (registration, liveness, status, ingestion) |
| `repositories/` | Database access through the ORM |
| `models/` | SQLAlchemy 2 models |
| `db/` | Engine, sessions, declarative base |
| `core/` | Settings, JSON logging, error handling, middleware |

Status rules: an asset is `unknown` until its first heartbeat/telemetry, `online` while it
reports, and `offline` once `HEARTBEAT_TIMEOUT_SECONDS` pass without contact (resolved at
read time). Every telemetry sample is stored in `telemetry_samples` for history.

## Stack

Backend: Python 3.12+, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL (native), Pydantic, Pytest,
Ruff, mypy. Frontend: React, TypeScript, Vite. Runs natively on Windows, no containers.

## Project structure

```
backend/        API (app/), migrations (alembic/), tests (tests/)
frontend/       React + Vite dashboard
agent/          Python agent (Windows first, Linux compatible)
docs/           Agent protocol and DEVELOPMENT_STATUS.md (handoff)
deploy/         Plantillas de producción: Caddy, nginx, systemd, PostgreSQL, Windows
integrations/   Future optional integrations (empty)
scripts/        PowerShell setup and start scripts for Windows
.github/        CI (backend lint, types, tests)
```

## Getting started (Windows)

Requirements: Python 3.12+, Node.js 20+, PostgreSQL 15+ running as a Windows service.

```powershell
.\scripts\setup_windows.ps1     # venv, dependencies, .env with a random DB password
.\scripts\init_database.ps1     # asks for the postgres superuser password; creates role, DBs, runs migrations
.\scripts\start_backend.ps1     # API on http://127.0.0.1:8000 (docs at /docs)
.\scripts\start_frontend.ps1    # dashboard on http://localhost:5173
```

Linux endpoints get a standalone package (tarball or `.deb`, systemd service, one command
with a one-time enrollment token): [docs/agent-linux-installation.md](docs/agent-linux-installation.md).
The **Agentes** page creates that token and the install command, and revokes agents (admin
role): [docs/agent-management.md](docs/agent-management.md).

El dashboard exige iniciar sesión (usuarios locales con roles admin, analyst y viewer). El
primer administrador se crea en el servidor con `python -m app.cli create-admin` desde
`backend/`; no hay credenciales por defecto: [docs/authentication.md](docs/authentication.md).

Windows endpoints get a zip with an embedded Python runtime and a PowerShell installer that
enrolls the host and installs the standard Windows service "Sentra Agent" (no Git, Python or
open console needed): [docs/agent-windows-installation.md](docs/agent-windows-installation.md).

To report this machine with the real agent:

```powershell
.\scripts\start_agent.ps1
```

## Environment variables

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
| `DETECTION_*` | Motor de detección y correlación (Fase 4H): activado por defecto; ventanas, umbrales, alerta mínima (`DETECTION_ALERT_MIN_SEVERITY=high`), reglas desactivadas y retención de detecciones resueltas. Todas en [docs/detection-engine.md](docs/detection-engine.md) |
| `SIGMA_DEFAULT_CONFIDENCE`, `RULE_TEST_MAX_HOURS`, `RULE_TEST_MAX_ROWS`, `RULE_TEST_TIMEOUT_SECONDS`, `RULE_TEST_PER_MINUTE` | Reglas personalizadas y Sigma (Fase 5A): confianza inicial de las reglas Sigma importadas (`low`) y límites de la prueba histórica (72 h, 20 000 filas, 10 s, 6 por usuario y minuto). [docs/custom-detection-rules.md](docs/custom-detection-rules.md) |
| `RISK_*` | Risk Engine (Fase 4I): activado por defecto; umbrales de nivel (`RISK_LEVEL_THRESHOLDS=20,40,60,80`), decay, historial, alerta `risk_critical` y retención. Todas en [docs/risk-engine.md](docs/risk-engine.md) |
| `VULN_*` | Vulnerabilidades (Fase 5B): evaluación por cola (`VULN_EVAL_INTERVAL_SECONDS=30`, reevaluación completa cada 24 h), evidencia antigua (72 h), capturas sin el componente antes de resolver (2), límites del catálogo (64 MiB, 200 000 registros), lotes de importación y alertas `vulnerability` con cooldown. Todas en [docs/vulnerability-management.md](docs/vulnerability-management.md) |
| `THREAT_INTEL_*` | Threat Intelligence (Fase 5C): módulo activo (`THREAT_INTEL_ENABLED=true`), descargas por red **apagadas** (`THREAT_INTEL_SYNC_ENABLED=false`), espejos internos solo por `THREAT_INTEL_SOURCE_URLS` y `THREAT_INTEL_ALLOWED_NETWORKS`, límites de descarga (128 MiB, 1 000 000 registros), política de la detección TI-001 (`high_confidence_malicious`) e intervalo del job (60 s). Todas en [docs/threat-intelligence.md](docs/threat-intelligence.md) |
| `AI_*` | AI Security Insights (Fase 4J): **desactivado por defecto** (`AI_ENABLED=false`); local-first (Fase 4J.1): modelo local OpenAI-compatible como Ollama, llama.cpp o vLLM (`AI_BASE_URL`, `AI_MODEL`, `AI_API_KEY` opcional), LAN solo con `AI_LOCAL_NETWORKS`, externos bloqueados salvo `AI_ALLOW_EXTERNAL=true` y sin fallback cloud, redacción, límites y timeouts. Todas en [docs/ai-security-insights.md](docs/ai-security-insights.md) Gestor de modelos locales (Fase 4J.2): `AI_RUNTIME`, `AI_MODEL_DIRECTORIES`, contexto, margen de memoria y benchmark en [docs/local-model-manager.md](docs/local-model-manager.md) |
| `TRUSTED_PROXIES` | Proxies (IPs/redes) cuyos `X-Forwarded-For/Proto` se aceptan (Fase 4M; por defecto `127.0.0.1,::1`) |
| `RATE_LIMIT_BACKEND`, `API_MUTATIONS_PER_USER_PER_MINUTE`, `API_SEARCHES_PER_USER_PER_MINUTE` | Rate limiting compartido en PostgreSQL en producción (`auto`) y límites por usuario del dashboard (120/min) |
| `DB_POOL_SIZE`, `DB_MAX_OVERFLOW`, `DB_POOL_TIMEOUT_SECONDS`, `DB_POOL_RECYCLE_SECONDS`, `DB_CONNECT_TIMEOUT_SECONDS`, `DB_STATEMENT_TIMEOUT_SECONDS` | Pool y tiempos máximos de PostgreSQL de la API |
| `LOG_FORMAT`, `LOG_FILE`, `LOG_FILE_MAX_MB`, `LOG_FILE_BACKUPS` | Logs JSON/texto y rotación propia a archivo (Windows) |
| `METRICS_ENABLED`, `METRICS_ALLOWED_NETWORKS`, `METRICS_TOKEN` | `/api/v1/metrics` Prometheus, apagado por defecto ([docs/observability.md](docs/observability.md)) |
| `BACKUP_DIR`, `BACKUP_RETENTION_DAYS`, `PG_BIN_DIR`, `FRONTEND_DIST_DIR` | Copias de seguridad ([docs/backup-restore.md](docs/backup-restore.md)) y build publicado |
| `DISCOVERY_ALLOWED_NETWORKS` | Networks agentless discovery may probe (empty = discovery off, the default). Internet space and huge ranges are refused. All `DISCOVERY_*` settings: [docs/discovery.md](docs/discovery.md) |

Frontend variables are documented in `frontend/.env.example`.

## Migrations

```powershell
cd backend
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m alembic revision --autogenerate -m "describe change"
```

## API (v1)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Liveness: `{"status":"ok"}` sin tocar la base (Fase 4M) |
| GET | `/api/v1/health/ready` | Readiness: base, migraciones y apagado; 503 si no está lista. Sin versiones ni hosts |
| GET | `/api/v1/dashboard/summary` | Agregados del dashboard en SQL (activos por estado/método/tipo, riesgo, incidentes, detecciones, alertas) |
| GET | `/api/v1/metrics` | Prometheus; 404 salvo `METRICS_ENABLED` y red autorizada, token opcional ([docs/observability.md](docs/observability.md)) |
| POST | `/api/v1/agents/register` | Enroll an agent (`X-Enrollment-Token` one-time token, or legacy `X-Enrollment-Key`); returns its token once |
| POST | `/api/v1/agent-enrollment-tokens` | **Admin** (`X-Admin-Key`): create a one-time enrollment token (shown once) |
| GET | `/api/v1/agent-enrollment-tokens` | **Admin**: list tokens and their state (never the token) |
| POST | `/api/v1/agent-enrollment-tokens/{id}/revoke` | **Admin**: revoke an unused token |
| POST | `/api/v1/agents/heartbeat` | Mark an agent alive (Bearer token) |
| GET | `/api/v1/agents` | Enrolled agents with state, credential status and summary (no secrets) |
| GET | `/api/v1/assets/{asset_id}/agent` | The asset's agent and credential status |
| GET/POST | `/api/v1/console/...` | **Dashboard console** (sesión, solo rol admin): enrollment tokens, revoke/reinstate agents ([docs/agent-management.md](docs/agent-management.md)) |
| GET | `/api/v1/assets` | List assets with status and latest telemetry; paginado en el servidor (Fase 4M: `limit` 100 por defecto, máx. 500; `offset`; `sort`, `order`; `status_counts`) |
| GET | `/api/v1/assets/{asset_id}` | Asset detail |
| GET | `/api/v1/assets/{asset_id}/telemetry?limit=120` | Telemetry history, oldest first |
| GET | `/api/v1/alerts?status=&active=&severity=&rule=&asset_id=&q=&limit=&offset=` | Alerts, newest first; `total` is the number matching the filters |
| GET | `/api/v1/alerts/{alert_id}` | Alert detail (details, occurrences, source event) |
| POST | `/api/v1/inventory` | Ingest inventory snapshot (Bearer token) |
| GET | `/api/v1/assets/{asset_id}/inventory` | Latest inventory snapshot |
| GET | `/api/v1/assets/{asset_id}/changes?category=&limit=&offset=` | Changes detected between inventories (services, software, accounts) |
| POST | `/api/v1/processes` | Ingest a process snapshot (Bearer token; only the latest is kept) |
| GET | `/api/v1/assets/{asset_id}/processes` | Latest process snapshot |
| POST | `/api/v1/telemetry` | Ingest CPU, RAM, disk and uptime (Bearer token) |
| POST | `/api/v1/events` | Ingest host log events (Bearer token, idempotent) |
| GET | `/api/v1/events?asset_id=&min_level=&channel=&event_code=&provider=&event_type=&q=&limit=&offset=` | Events, newest first (`has_more` instead of a total); Linux events have `event_code: null` and an `event_type` (Fase 5C.1, [docs/linux-events.md](docs/linux-events.md)) |
| GET | `/api/v1/assets/duplicates`, `/api/v1/assets/{asset_id}/duplicate-candidates` | Posibles duplicados con razones y confianza (Fase 5C.1, `assets:duplicates_read`: analyst y admin) |
| GET | `/api/v1/assets/{asset_id}/delete-check` | ¿Se puede borrar? Motivos y dependencias (admin) |
| POST | `/api/v1/assets/{asset_id}/archive` `{reason, version}`, `/restore` `{version}` | Archivar / restaurar un activo (admin; archivar exige revocar antes su agente; restaurar no reactiva la credencial) |
| DELETE | `/api/v1/assets/{asset_id}?version=` | Borrar un activo descubierto sin historial (admin; 409 `asset_not_deletable` si tiene historial) |
| POST | `/api/v1/assets/{asset_id}/reconcile` `{target_asset_id, version, target_version}` | Reasignar el agente nuevo a un activo histórico de la misma máquina (admin, validado por el servidor) ([docs/agent-asset-lifecycle.md](docs/agent-asset-lifecycle.md)) |
| GET | `/api/v1/assets?method=&status=&device_type=&subnet=&q=&criticality=&role=&environment=&network_zone=&data_sensitivity=&internet_exposed=&department=&tag=&sort=&limit=&offset=` | (filters, all optional) agent and discovered assets; filtros de contexto, orden por criticidad y paginación opcional (Fase 4L) |
| GET/PATCH | `/api/v1/assets/{asset_id}/context`, GET `/{asset_id}/context/history`, `/assets/context/options` | Asset Context (Fase 4L): rol, entorno, owner, equipo, sensibilidad, zona, exposición a Internet y tags con procedencia; PATCH solo admin (`assets:manage`), `version` obligatoria y 409 `asset_context_conflict`: [docs/asset-context.md](docs/asset-context.md) |
| GET | `/api/v1/assets/{asset_id}/threat-summary` | Contexto de amenaza interno del activo (detecciones, incidentes, riesgo, cambios recientes; sin feeds externos) |
| GET | `/api/v1/assets/{asset_id}/exposure` | Ports reachable from the Sentra server, correlated with the agent's listeners |
| GET | `/api/v1/discovery/scope` | Networks and ports discovery may probe (configuration) |
| GET | `/api/v1/discovery/jobs?limit=` | Recent discovery runs |
| GET | `/api/v1/detections?status=&active=&severity=&min_severity=&confidence=&rule_id=&asset_id=&since=&until=&q=&limit=&offset=` | Detecciones del motor (Fase 4H), la actividad más reciente primero |
| GET | `/api/v1/detections/{detection_id}` | Detalle: qué pasó, por qué importa, evidencias (timeline), MITRE, recomendaciones |
| POST | `/api/v1/detections/{detection_id}/acknowledge`, `/resolve` | Reconocer / resolver (roles admin y analyst; auditado). `resolve` acepta `{"note": "…"}` |
| GET | `/api/v1/detection-rules?source=&status=&compile_status=&severity=&logsource=&mitre=&q=&sort=&order=&limit=&offset=` | Catálogo unificado de reglas (built-in, personalizadas y Sigma; `rules:read`) |
| GET | `/api/v1/detection-rules/catalog`, `/{rule_id}`, `/{rule_id}/versions[/{v}]`, `/diff?from=&to=`, `/export`, `/sigma-source`, `/audit` | Logsources y campos, detalle, versiones inmutables, diff semántico, exportación, YAML Sigma original y auditoría (Fase 5A) |
| POST/PATCH | `/api/v1/detection-rules`, `PATCH /{rule_id}`, `/{rule_id}/enable\|disable\|retire\|unretire`, `/{rule_id}/versions/{v}/restore` | Crear, versionar y gestionar reglas personalizadas (`rules:manage`, admin; `revision` obligatoria, 409 si otro admin la cambió) |
| POST | `/api/v1/detection-rules/validate`, `/test`, `/test/historical` | Validar y probar sin efectos: sintética (`rules:test`) e histórica de solo lectura (`rules:manage`) |
| POST | `/api/v1/sigma/preview`, `/sigma/import` | Vista previa (`rules:test`) e importación Sigma (`rules:manage`; siempre desactivada) ([docs/sigma-support.md](docs/sigma-support.md)) |
| GET | `/api/v1/vulnerabilities/overview`, `/vulnerabilities/findings?status=&active=&severity=&match_state=&confidence=&exposure=&asset_id=&vulnerability_id=&source=&stale=&q=&sort=&order=&limit=&offset=`, `/findings/{id}` (`/history`, `/audit`), `/vulnerabilities/exposure`, `/vulnerabilities/catalog`, `/assets/{id}/vulnerabilities` | Vulnerabilidades y exposición (Fase 5B, `vulnerabilities:read`): [docs/vulnerability-management.md](docs/vulnerability-management.md) |
| POST | `/api/v1/vulnerabilities/findings/{id}/acknowledge\|mitigating\|resolve\|incident` (`vulnerabilities:manage`), `/accept-risk\|false-positive\|reopen`, `/vulnerabilities/catalog/preview\|import`, `/vulnerabilities/evaluate` (`vulnerabilities:admin`) | Flujo de trabajo (`version` obligatoria, 409 `vulnerability_conflict`), catálogo local con previsualización y reevaluación |
| GET | `/api/v1/threat-intel/overview`, `/threat-intel/sources` (`/{id}/syncs`), `/threat-intel/indicators?type=&classification=&confidence=&source_id=&state=&matched=&tag=&q=`, `/indicators/{id}`, `/threat-intel/matches?status=&active=&classification=&observation_type=&asset_id=&source_id=`, `/matches/{id}`, `/vulnerabilities/findings/{id}/threat-intel` | Threat Intelligence (Fase 5C, `threat_intel:read`): KEV/EPSS con procedencia, indicadores y coincidencias con datos locales ([docs/threat-intelligence.md](docs/threat-intelligence.md)) |
| POST | `/api/v1/threat-intel/matches/{id}/acknowledge\|dismiss\|reopen\|incident` (`threat_intel:triage`), `/threat-intel/sources` (`/{id}/enable\|disable\|archive\|sync`), `/threat-intel/import/preview\|import`, `/threat-intel/reevaluate` (`threat_intel:manage`) | Triage con `version` (409 `threat_intel_conflict`, motivo obligatorio al descartar), fuentes sin URLs desde el navegador, importación con previsualización y sha256 |
| GET | `/api/v1/risk/overview` | Riesgo (Fase 4I): activos por nivel y confianza, factores principales, transiciones recientes |
| GET | `/api/v1/risk/assets?level=&confidence=&device_type=&status=&criticality=&min_score=&q=&sort=&order=&limit=&offset=` | Activos por riesgo, el más alto primero |
| GET | `/api/v1/risk/assets/{asset_id}`, `/history?range=24h\|7d\|30d`, `/contributions?snapshot_id=` | Detalle explicable, tendencia y contribuciones |
| GET | `/api/v1/ai/status` | AI Security Insights (Fase 4J): si la IA está disponible y con qué modelo (sin URL ni clave) |
| GET/POST/PATCH | `/api/v1/ai/local/hardware`, `/runtime`, `/models`, `/recommendations`, `/settings`, `/models/{id}/select\|benchmark\|unregister`… | Gestor de modelos locales (Fase 4J.2): hardware, runtime, modelos GGUF, recomendaciones y benchmark (lectura `ai:use`, cambios solo admin `ai:manage`): [docs/local-model-manager.md](docs/local-model-manager.md) |
| POST | `/api/v1/ai/assets/{asset_id}/analyze`, `/ai/detections/{detection_id}/analyze`, `/ai/risk/assets/{asset_id}/analyze`, `/ai/soc/analyze`, `/ai/ask` | Análisis de IA bajo demanda, grounded en datos de Sentra (`ai:use` + `monitoring:read`; rate limited) |
| GET | `/api/v1/ai/insights?kind=&asset_id=&detection_id=`, `/ai/insights/{insight_id}` | Historial de análisis con estado actual/desactualizado |
| GET | `/api/v1/incidents?status=&active=&severity=&priority=&owner=&asset_id=&since=&until=&q=&sort=&order=&limit=&offset=`, `/incidents/overview`, `/incidents/{id}`, `/{id}/timeline?cursor=`, `/{id}/evidence`, `/{id}/notes`, `/{id}/audit` | Gestión de incidentes (Fase 4K, `incidents:read`): listado, vista SOC, detalle, timeline unificado por cursor, evidencia agrupada y auditoría del caso: [docs/incident-management.md](docs/incident-management.md) |
| POST/PATCH | `/api/v1/incidents`, `/detections/{id}/incident`, `/alerts/{id}/incident`, `PATCH /incidents/{id}`, `/{id}/assign\|unassign\|notes\|resolve`, `/{id}/detections/{did}`, `/{id}/alerts/{aid}`, `/{id}/assets/{asset_id}` | Crear, promover, trabajar y resolver incidentes (`incidents:manage`, analyst y admin; `version` obligatoria, 409 `incident_conflict` si otro operador lo cambió) |
| POST | `/api/v1/incidents/{id}/close`, `/reopen`, `/merge` | Cerrar, reabrir y fusionar (solo admin, `incidents:admin`) |
| POST | `/api/v1/ai/incidents/{incident_id}/analyze` | IA de solo lectura sobre un incidente (`summary`, `timeline`, `evidence`, `next_steps`); nunca cambia el caso |
| PATCH | `/api/v1/assets/{asset_id}/criticality` | Criticidad del activo (solo admin, `assets:manage`; auditado) |
| POST | `/api/v1/auth/login`, `/auth/logout`; GET `/auth/me` | Sesión del dashboard (cookie HttpOnly + `X-CSRF-Token` en mutaciones). Todos los GET del dashboard requieren sesión; usuarios, auditoría y acciones por rol: [docs/authentication.md](docs/authentication.md) |

Las alertas se reconocen o resuelven desde el dashboard (roles admin y analyst) o con
`python -m app.cli ack-alert <id>` / `resolve-alert <id>`.
Network discovery se lanza desde la página **Red → Iniciar descubrimiento** (roles admin y
analyst, desde cualquier equipo de la LAN con sesión), de forma periódica
con `DISCOVERY_INTERVAL_MINUTES`, o con `python -m app.cli discover` como herramienta
administrativa: [docs/discovery.md](docs/discovery.md).

Payloads and error format: [docs/agent-protocol.md](docs/agent-protocol.md). Interactive docs at
`/docs` in development.

## Tests and checks

Tests run against the real PostgreSQL database in `TEST_DATABASE_URL` (migrations are applied
down and up on every run; never point it at real data).

```powershell
cd backend
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m ruff format --check .
.venv\Scripts\python.exe -m mypy app tests
```

The backend suite also fails when the ORM models and the migrations drift apart (the
equivalent of `alembic check`), so a model change always needs its migration.

Frontend (Vitest unit tests for the API client and formatting helpers, then lint and build):

```powershell
cd frontend
npm test
npm run lint
npm run build
```

## Project status

MVP working end to end with real data (PC → agent → API → PostgreSQL → web). Agents
enroll with one-time tokens (created and revoked from the Agentes page) and then use
per-agent tokens. Per asset the dashboard shows
overview, processes, services, software, network, users, events and alerts, plus the changes
detected between inventories. **Hybrid monitoring**: hosts without agent are found by
agentless network discovery on explicitly authorized networks (DISCOVERED), with their
reachable ports and changes; installing the agent (MANAGED) merges both views into one
asset ([docs/discovery.md](docs/discovery.md)). Monitoring only: no remote actions on hosts. See
[docs/DEVELOPMENT_STATUS.md](docs/DEVELOPMENT_STATUS.md) for details and known issues.
El dashboard exige login con roles y sesiones de servidor ([docs/authentication.md](docs/authentication.md)).
**Detecciones** (Fase 4H): un motor determinista de reglas y correlaciones temporales convierte
eventos, inventario, procesos y descubrimiento en detecciones con severidad y confianza
separadas, evidencias y recomendaciones; las graves abren una alerta
([docs/detection-engine.md](docs/detection-engine.md)).
**Reglas personalizadas y Sigma** (Fase 5A): Detecciones → Reglas lista las built-in, las
personalizadas y las importadas de Sigma. Las reglas son JSON declarativo (nunca código),
validado con allowlist, con regex seguras, versiones inmutables, estados (borrador, activa,
desactivada, retirada) separados del estado de compilación, pruebas sintéticas e históricas
sin efectos y auditoría completa. Se ejecutan en el mismo motor de 4H, con recarga en caliente
entre workers. La importación Sigma admite un subconjunto honesto y marca como no soportado
lo que Sentra no recoge ([docs/custom-detection-rules.md](docs/custom-detection-rules.md),
[docs/sigma-support.md](docs/sigma-support.md)).
**Vulnerabilidades y exposición** (Fase 5B): un administrador importa un catálogo local
(sin descargas externas) y Sentra lo cruza con el software inventariado por los agentes y con
la exposición observada. Cada finding indica si es confirmado, probable o potencial (las
potenciales siempre aparte), con su porqué, evidencia, exposición y prioridad; flujo de
trabajo con concurrencia optimista, riesgo aceptado con caducidad (admin), integración en el
riesgo sin doble conteo, alertas solo en cambios relevantes, incidentes manuales e IA de solo
lectura. Un puerto abierto nunca es una vulnerabilidad
([docs/vulnerability-management.md](docs/vulnerability-management.md),
[docs/vulnerability-catalog.md](docs/vulnerability-catalog.md)).
**Ciclo de vida de activos y eventos Linux** (Fase 5C.1): revocar un agente, archivar un
activo y borrarlo son tres cosas distintas. Un activo gestionado nunca se borra: se archiva
con todo su historial (oculto por defecto, fuera del resumen, restaurable); solo un activo
descubierto sin historial puede borrarse, y el servidor lo recomprueba con la fila bloqueada.
Los duplicados (reinstalación del agente) se sugieren con razones y confianza y un admin
reconcilia el agente nuevo con el activo histórico. El agente Linux 0.2.1 envía un subconjunto
del journal (SSH, sudo saneado, cuentas y grupos, systemd, kernel, auditd opcional) como
usuario sin privilegios del grupo `systemd-journal`, con reglas LIN-AUTH-001/002 y
LIN-SYS-001 ([docs/agent-asset-lifecycle.md](docs/agent-asset-lifecycle.md),
[docs/linux-events.md](docs/linux-events.md)).
**Threat Intelligence** (Fase 5C, offline-first): CISA KEV y FIRST EPSS enriquecen los
findings como contexto de explotabilidad ("explotación conocida reportada", "probabilidad de
explotación EPSS"), con la procedencia de cada dato y las discrepancias entre fuentes lado a
lado; un admin importa IOCs (`sentra-ioc/1` o un subset seguro de STIX 2.x) con
previsualización y sha256, y Sentra los busca por coincidencia exacta en inicios de sesión,
conexiones y activos. Un match es contexto, nunca "equipo comprometido": triage con motivo,
detección TI-001 solo por política, contribución al riesgo explicada e incidentes manuales.
Sin fuentes Sentra funciona igual; descargas por red apagadas por defecto y protegidas frente
a SSRF ([docs/threat-intelligence.md](docs/threat-intelligence.md),
[docs/threat-intel-sources.md](docs/threat-intel-sources.md),
[docs/stix-support.md](docs/stix-support.md)).
**Riesgo** (Fase 4I): cada activo tiene un score 0-100 determinista con nivel y confianza
separados, calculado a partir de sus detecciones, su exposición, su criticidad y su tipo, con
contribuciones explicables, historial de cambios y tendencia; página Riesgo y sección Riesgo
del activo ([docs/risk-engine.md](docs/risk-engine.md)).
**AI Security Insights** (Fase 4J, opcional y desactivado por defecto): un modelo local o
externo compatible con OpenAI interpreta los resultados de detección y riesgo bajo demanda
(resumen de activo, explicación de detección y de riesgo, resumen SOC y Ask Sentra AI), con
cada hallazgo vinculado a evidencia real de Sentra, defensas frente a prompt injection, sin
SQL ni herramientas y sin acciones automáticas ([docs/ai-security-insights.md](docs/ai-security-insights.md)).
**Gestor de modelos locales** (Fase 4J.2): Configuración → IA local → Modelos detecta el
hardware, habla con el runtime local (llama.cpp, Ollama, vLLM), registra modelos GGUF,
estima su memoria, recomienda de forma determinista el más adecuado para Sentra, los activa
con health check y mide su rendimiento con un benchmark local; sin descargas ni fallback
cloud ([docs/local-model-manager.md](docs/local-model-manager.md)).
**Incidentes** (Fase 4K): página Incidentes y vista SOC del dashboard. Un incidente
(INC-000001) agrupa por referencia detecciones, correlaciones, alertas y activos, con
state machine explícita (open → triage → investigating → contained → resolved → closed),
severidad y prioridad separadas, responsable, notas append-only, timeline unificado,
resolución con categoría obligatoria, duplicados y fusión (admin), sugerencia de incidentes
relacionados sin deduplicación automática, snapshot de riesgo de 4I y concurrencia optimista
(409). La IA solo lee ([docs/incident-management.md](docs/incident-management.md)).
**Asset Context** (Fase 4L): pestaña Contexto del activo con rol, entorno, owner,
equipo/departamento, sensibilidad, zona de red, exposición a Internet (sí/no/desconocida),
estado de gestión y tags, cada dato con su procedencia; lo confirmado por un admin nunca lo
sobrescribe una heurística. El contexto amplifica de forma acotada la evidencia existente en
el riesgo (nunca crea riesgo; lo desconocido no suma), aparece en incidentes (actual y
snapshot), detecciones e IA (sin inventar datos), y cada activo tiene un resumen de amenaza
interno ([docs/asset-context.md](docs/asset-context.md)).
**Producción** (Fase 4M): servidor central con Caddy (HTTPS, frontend estático) delante de
la API en 127.0.0.1, PostgreSQL con rol dedicado, validación de producción que impide
arrancar inseguro, proxy de confianza, rate limiting compartido, readiness, logs JSON
redactados, métricas protegidas, copias verificadas y restauración segura, y dashboard
paginado en el servidor ([docs/production-deployment.md](docs/production-deployment.md),
[docs/network-security.md](docs/network-security.md),
[docs/backup-restore.md](docs/backup-restore.md), [docs/observability.md](docs/observability.md),
plantillas en `deploy/`).

## Roadmap

1. Signed MSI for the Windows agent.
2. Telemetry downsampling (opt-in retention exists); journald events on Linux.
3. Live updates (WebSockets/SSE).
4. Agentless collectors (WinRM/WMI, SSH, SNMP; contracts in `backend/app/agentless/`) once
   a credential store is decided; OUI vendor database.
5. Optional integrations (Wazuh, Suricata, Syslog).
