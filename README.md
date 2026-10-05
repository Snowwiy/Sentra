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
| `ENVIRONMENT` | `development`, `test` or `production` (production hides `/docs`) |
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
| `RISK_*` | Risk Engine (Fase 4I): activado por defecto; umbrales de nivel (`RISK_LEVEL_THRESHOLDS=20,40,60,80`), decay, historial, alerta `risk_critical` y retención. Todas en [docs/risk-engine.md](docs/risk-engine.md) |
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
| GET | `/api/v1/health` | API, database and migration state (503 when degraded) |
| POST | `/api/v1/agents/register` | Enroll an agent (`X-Enrollment-Token` one-time token, or legacy `X-Enrollment-Key`); returns its token once |
| POST | `/api/v1/agent-enrollment-tokens` | **Admin** (`X-Admin-Key`): create a one-time enrollment token (shown once) |
| GET | `/api/v1/agent-enrollment-tokens` | **Admin**: list tokens and their state (never the token) |
| POST | `/api/v1/agent-enrollment-tokens/{id}/revoke` | **Admin**: revoke an unused token |
| POST | `/api/v1/agents/heartbeat` | Mark an agent alive (Bearer token) |
| GET | `/api/v1/agents` | Enrolled agents with state, credential status and summary (no secrets) |
| GET | `/api/v1/assets/{asset_id}/agent` | The asset's agent and credential status |
| GET/POST | `/api/v1/console/...` | **Dashboard console** (sesión, solo rol admin): enrollment tokens, revoke/reinstate agents ([docs/agent-management.md](docs/agent-management.md)) |
| GET | `/api/v1/assets` | List assets with status and latest telemetry |
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
| GET | `/api/v1/events?asset_id=&min_level=&channel=&event_code=&q=&limit=&offset=` | Events, newest first (`has_more` instead of a total) |
| GET | `/api/v1/assets?method=&status=&device_type=&subnet=&q=` | (filters, all optional) agent and discovered assets |
| GET | `/api/v1/assets/{asset_id}/exposure` | Ports reachable from the Sentra server, correlated with the agent's listeners |
| GET | `/api/v1/discovery/scope` | Networks and ports discovery may probe (configuration) |
| GET | `/api/v1/discovery/jobs?limit=` | Recent discovery runs |
| GET | `/api/v1/detections?status=&active=&severity=&min_severity=&confidence=&rule_id=&asset_id=&since=&until=&q=&limit=&offset=` | Detecciones del motor (Fase 4H), la actividad más reciente primero |
| GET | `/api/v1/detections/{detection_id}` | Detalle: qué pasó, por qué importa, evidencias (timeline), MITRE, recomendaciones |
| POST | `/api/v1/detections/{detection_id}/acknowledge`, `/resolve` | Reconocer / resolver (roles admin y analyst; auditado). `resolve` acepta `{"note": "…"}` |
| GET | `/api/v1/detection-rules` | Catálogo de reglas, ventanas y umbral de alerta |
| GET | `/api/v1/risk/overview` | Riesgo (Fase 4I): activos por nivel y confianza, factores principales, transiciones recientes |
| GET | `/api/v1/risk/assets?level=&confidence=&device_type=&status=&criticality=&min_score=&q=&sort=&order=&limit=&offset=` | Activos por riesgo, el más alto primero |
| GET | `/api/v1/risk/assets/{asset_id}`, `/history?range=24h\|7d\|30d`, `/contributions?snapshot_id=` | Detalle explicable, tendencia y contribuciones |
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
**Riesgo** (Fase 4I): cada activo tiene un score 0-100 determinista con nivel y confianza
separados, calculado a partir de sus detecciones, su exposición, su criticidad y su tipo, con
contribuciones explicables, historial de cambios y tendencia; página Riesgo y sección Riesgo
del activo ([docs/risk-engine.md](docs/risk-engine.md)).
Sin HTTPS la contraseña y la cookie viajan en claro: en producción, detrás de un proxy HTTPS.

## Roadmap

1. HTTPS de serie (proxy inverso documentado) y endurecimiento de producción.
2. Signed MSI for the Windows agent.
3. Telemetry downsampling (opt-in retention exists); journald events on Linux.
4. Live updates (WebSockets/SSE).
5. Agentless collectors (WinRM/WMI, SSH, SNMP; contracts in `backend/app/agentless/`) once
   a credential store is decided; OUI vendor database.
6. Optional integrations (Wazuh, Suricata, Syslog).
