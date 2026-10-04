# Sentra development status

Handoff document: enough to continue the project without prior conversation context.
Last updated: 2026-10-04.

## Current state

MVP working end to end on the developer's Windows PC with real data:
PC → Sentra Agent → API → PostgreSQL → Web (verified in the browser, including an API
outage during which the agent buffered samples and delivered them on reconnection).

| Component | State |
|-----------|-------|
| Backend API (FastAPI) | Done: agents (enrollment + tokens), assets, telemetry + history, inventory, events, alerts, health |
| Database (PostgreSQL 18 native, Alembic) | Done: migrations 0001–0007 |
| Agent (Python, Windows-first) | Done: identity + token (DPAPI-encrypted at rest), heartbeat (+ host refresh), telemetry, inventory incl. disks and network connections (15 min), Windows Event Log (60 s), buffering persisted across restarts, backoff + jitter + Retry-After, re-enrollment, revocation handling (403), rotating logs with secret redaction |
| Frontend (React, Vite) | Done: dashboard (counts, assets, open alerts, recent activity), asset detail (metrics, trends, alerts, events, inventory tabs), alerts page |
| Alerts | Done: offline, sustained high CPU/RAM, critical disk; dedup + auto-resolve |
| Tests | Backend 103 (real PostgreSQL), agent 61; frontend tsc + ESLint + build |

## Architecture

```
Agent (per host) ──JSON + Bearer token──► API (FastAPI) ──SQLAlchemy──► PostgreSQL
                                                       ▲  └─ offline sweeper thread (alerts)
Web (React, polling 15 s, Vite proxy in dev) ──────────┘  /api/v1
```

- Backend layers in `backend/app/`: `api` (thin routers) → `services` (business logic) →
  `repositories` (ORM queries) → `models`; `schemas` are the Pydantic API contracts.
- Native Windows, no Docker, no Redis (explicit decision for this phase).
- Public identifiers are UUIDs; internal integer PKs never leave the API.
- All timestamps are UTC (`timestamptz`, connections forced to `timezone=utc`).
- Domains kept separate: telemetry (measurements), events (facts from host logs), alerts
  (Sentra rule findings).

## Data model

- `assets`: one per agent. `public_id`, `agent_id`, `agent_token_hash` (SHA-256), host info,
  `status` (last reported), `first_seen_at`, `last_seen_at`.
- `telemetry_samples`: append-only history. Index `(asset_id, recorded_at)`.
- `alerts`: rule, severity, open/resolved. Partial unique index = one open alert per asset+rule.
- `asset_inventories`: one JSONB snapshot per asset (interfaces, disks, listening/established
  connections, users, processes, services, software); newer snapshots replace older only.
- `system_events`: host log events; unique `(asset_id, channel, record_id)` makes resends idempotent.

## Key rules

- Agent auth: enrollment requires `AGENT_ENROLLMENT_KEY` (`X-Enrollment-Key`); returns a token
  once; all other agent calls need `Authorization: Bearer`. Re-enrollment rotates the token.
- Status: `unknown` until first contact; `online` while reporting; `offline` when
  `last_seen_at` is older than `HEARTBEAT_TIMEOUT_SECONDS` (computed at read time; server clock).
- Alerts: CPU/RAM need `ALERT_SUSTAINED_SAMPLES` consecutive samples over threshold; disk alerts
  on one sample; offline opened by a 30 s sweeper, resolved on the next heartbeat.

## Endpoints (`/api/v1`)

Agent (token): `POST /agents/register` (enrollment key) · `POST /agents/heartbeat` ·
`POST /telemetry` · `POST /inventory` · `POST /events`.
Read (dashboard): `GET /health` · `GET /assets` · `GET /assets/{id}` ·
`GET /assets/{id}/telemetry` · `GET /assets/{id}/inventory` · `GET /alerts` · `GET /events`.
Details: `docs/agent-protocol.md`.

## Run

```powershell
.\scripts\setup_windows.ps1      # venvs, deps, .env (random DB password + enrollment key, PG port)
.\scripts\init_database.ps1      # once: role + DBs + migrations (asks postgres password)
.\scripts\start_backend.ps1      # http://127.0.0.1:8000
.\scripts\start_frontend.ps1     # http://localhost:5173
.\scripts\start_agent.ps1        # reports this PC (reads the enrollment key from .env)
```

After pulling new migrations: `cd backend; .venv\Scripts\python.exe -m alembic upgrade head`.

## Tests

```powershell
cd backend; .venv\Scripts\python.exe -m pytest      # uses TEST_DATABASE_URL (sentra_test)
cd agent;   .venv\Scripts\python.exe -m pytest      # includes a real Event Log read on Windows
cd frontend; npm run typecheck; npm run lint; npm run build
```

## Known issues and limitations

- **Dashboard read endpoints are unauthenticated** (no users/login yet). The API binds to
  127.0.0.1 by default; do not expose it on a network until dashboard auth exists.
- Agent runs in the foreground as the current user; no Windows service/installer. The Security
  event channel needs admin rights, so it is skipped.
- Agent token in `%LOCALAPPDATA%\Sentra\Agent\identity.json`, DPAPI-encrypted (current user).
  No mTLS yet; API URLs other than loopback should be https (the agent warns).
- No retention policy for telemetry/events.
- Alert thresholds are global environment variables, not per asset.
- Local PostgreSQL listens on 5433 on the dev PC (setup detects it).

## Decisions

- Offline computed on read (+ sweeper for alerts) instead of a status-writing scheduler.
- Token hashes with SHA-256 (tokens are 256-bit random; slow hashes add no security here).
- Agent buffers up to 120 samples (memory + `telemetry_buffer.json`); backoff interval → 300 s with jitter.
- Agent token at rest: DPAPI current-user scope via ctypes (no pywin32). Revocation via operator CLI (`python -m app.cli`), not HTTP, until dashboard auth exists.
- Agent uses stdlib + psutil + built-in `wevtutil.exe` (no pywin32).
- Inventory as JSONB snapshot; normalize a section when SQL queries over it are needed.

## Recommended next phase

1. Dashboard authentication (users, login, sessions) — needs a product decision on the scheme.
2. Agent as a Windows service (would allow the Security event log) — needs a decision on
   running with elevated privileges.
3. Event-based alerts (e.g. service crashed 7034, unexpected shutdown 6008) and a watch list of
   important services.
4. Retention/downsampling for telemetry and events; Linux collectors (systemd, journald, dpkg).
