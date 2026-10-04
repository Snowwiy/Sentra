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
| `AGENT_ENROLLMENT_KEY` | Secret agents need to enroll (min 24 chars; unset disables enrollment) |
| `HEARTBEAT_TIMEOUT_SECONDS` | Seconds without contact before an asset is `offline` (default 90) |
| `ALERT_CPU_PERCENT`, `ALERT_RAM_PERCENT`, `ALERT_DISK_PERCENT` | Alert thresholds (default 90) |
| `ALERT_SUSTAINED_SAMPLES` | Consecutive samples over threshold before CPU/RAM alert (default 3) |
| `BACKGROUND_JOBS_ENABLED`, `OFFLINE_SWEEP_INTERVAL_SECONDS` | Offline alert sweeper (default on, 30 s) |

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
| POST | `/api/v1/agents/register` | Enroll an agent (`X-Enrollment-Key`); returns its token once |
| POST | `/api/v1/agents/heartbeat` | Mark an agent alive (Bearer token) |
| GET | `/api/v1/assets` | List assets with status and latest telemetry |
| GET | `/api/v1/assets/{asset_id}` | Asset detail |
| GET | `/api/v1/assets/{asset_id}/telemetry?limit=120` | Telemetry history, oldest first |
| GET | `/api/v1/alerts?status=open&asset_id=&limit=` | Alerts (open/resolved) |
| POST | `/api/v1/inventory` | Ingest inventory snapshot (Bearer token) |
| GET | `/api/v1/assets/{asset_id}/inventory` | Latest inventory snapshot |
| POST | `/api/v1/telemetry` | Ingest CPU, RAM, disk and uptime (Bearer token) |
| POST | `/api/v1/events` | Ingest host log events (Bearer token, idempotent) |
| GET | `/api/v1/events?asset_id=&min_level=&limit=` | Events, newest first |

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

## Project status

MVP working end to end with real data (PC → agent → API → PostgreSQL → web). Agents
authenticate with an enrollment key and per-agent tokens. See
[docs/DEVELOPMENT_STATUS.md](docs/DEVELOPMENT_STATUS.md) for details and known issues.
Known limitation: the dashboard has **no login yet**; keep the API on a trusted network
(it binds to 127.0.0.1 by default).

## Roadmap

1. Dashboard users and authentication.
2. Agent as a Windows service; event-based alerts.
3. Telemetry/event retention; Linux collectors.
4. Live updates (WebSockets/SSE).
5. Optional integrations (Wazuh, Suricata, Syslog, SNMP).
