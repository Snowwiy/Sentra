# QA and integration checks

`backend/tests` and `agent/tests` are unit/integration suites that run in-process. This folder
holds checks that run against **real, separately started processes** (uvicorn + PostgreSQL +
agent + Vite), so they also cover startup, middleware, CORS, the wire format of errors, the
offline sweeper and recovery after outages.

Run them against a dedicated QA instance, never against the `sentra` database or the API other
people are using: the suite creates throwaway assets and opens alerts.

## 1. Throwaway PostgreSQL cluster (no Docker, no admin rights)

```powershell
$pg = "C:\Program Files\PostgreSQL\18\bin"
$qa = "$env:TEMP\sentra-qa"; New-Item -ItemType Directory -Force $qa | Out-Null
Set-Content "$qa\pw.txt" "qapass"
& "$pg\initdb.exe" -D "$qa\pgdata" -U postgres --pwfile="$qa\pw.txt" -A scram-sha-256 -E UTF8 --locale=C
& "$pg\pg_ctl.exe" -D "$qa\pgdata" -o "-p 55432 -c listen_addresses=127.0.0.1" -l "$qa\pg.log" start
$env:PGPASSWORD = "qapass"
& "$pg\psql.exe" -h 127.0.0.1 -p 55432 -U postgres -c "create role sentra_qa login password 'qapass'"
& "$pg\psql.exe" -h 127.0.0.1 -p 55432 -U postgres -c "create database sentra_qa owner sentra_qa"
& "$pg\psql.exe" -h 127.0.0.1 -p 55432 -U postgres -c "create database sentra_qa_test owner sentra_qa"
```

Stop it with `pg_ctl -D "$qa\pgdata" stop`; delete `$qa` to throw everything away.

## 2. QA API on port 8100

Environment variables override the root `.env`, so the real configuration is left untouched.
A short heartbeat timeout makes the offline checks finish in under a minute.

```powershell
$env:DATABASE_URL = "postgresql+psycopg://sentra_qa:qapass@127.0.0.1:55432/sentra_qa"
$env:TEST_DATABASE_URL = "postgresql+psycopg://sentra_qa:qapass@127.0.0.1:55432/sentra_qa_test"
$env:AGENT_ENROLLMENT_KEY = "qa-enrollment-key-0123456789abcdef"
$env:HEARTBEAT_TIMEOUT_SECONDS = "20"
$env:OFFLINE_SWEEP_INTERVAL_SECONDS = "5"
cd backend
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8100
```

With the same variables, `python -m pytest` uses `sentra_qa_test` instead of the shared
`sentra_test`, so it can run while other people run theirs.

## 3. Contract and failure-case suite

```powershell
$env:SENTRA_QA_API_URL = "http://127.0.0.1:8100"
$env:SENTRA_QA_ENROLLMENT_KEY = "qa-enrollment-key-0123456789abcdef"
backend\.venv\Scripts\python.exe qa\e2e_api.py --offline
```

Covers: health and error envelope, request id and security headers, the error envelope in the
published OpenAPI (hidden in production), CORS, enrollment (missing/wrong key, duplicate agent,
token rotation), agent authentication on every agent endpoint, telemetry validation (negative,
>100, NaN/Infinity, naive/future/late timestamps, BIGINT overflow), events (idempotent resend,
limits), inventory (stale snapshot, invalid items), NUL characters (422, never 500), body size
limit, telemetry idempotency, read endpoints (404/422, limits), alert lifecycle and offline
detection, and the operational features: process snapshots (stale/out of range), inventory
change detection, service-stopped and critical-event alerts (resend not counted, linked
event, auto-resolution), alert and event filters, NUL in search parameters and accounts that
carry a `password` field (422), and the hybrid read API (asset method/subnet filters,
exposure, discovery scope and jobs, and that no HTTP endpoint starts a scan). Discovery
runs themselves are covered by `backend/tests/test_discovery_*.py`, including real TCP
probes against listeners on 127.0.0.0/8.

## 4. Real agent and dashboard against the QA API

```powershell
$env:SENTRA_AGENT_ENROLLMENT_KEY = "qa-enrollment-key-0123456789abcdef"
cd agent
.venv\Scripts\python.exe -m sentra_agent --api-url http://127.0.0.1:8100 --interval 5 --state-dir "$env:TEMP\sentra-qa\agent"

cd frontend
$env:SENTRA_API_PROXY_TARGET = "http://127.0.0.1:8100"; $env:SENTRA_FRONTEND_PORT = "5180"
npx vite --host 127.0.0.1
```

The separate `--state-dir` keeps this agent's identity apart from the real agent's.

## Linux (CI runner or a cloud session)

The same checks run on Linux with the distribution's native PostgreSQL (still no Docker). As
root, replace `sudo -u postgres` with `su postgres -c "..."`.

```bash
sudo service postgresql start
sudo -u postgres psql -c "create role sentra_qa login password 'qapass'"
sudo -u postgres createdb -O sentra_qa sentra_qa
sudo -u postgres createdb -O sentra_qa sentra_qa_test

export DATABASE_URL=postgresql+psycopg://sentra_qa:qapass@127.0.0.1:5432/sentra_qa
export TEST_DATABASE_URL=postgresql+psycopg://sentra_qa:qapass@127.0.0.1:5432/sentra_qa_test
export AGENT_ENROLLMENT_KEY=qa-enrollment-key-0123456789abcdef

cd backend
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
.venv/bin/python -m alembic upgrade head
HEARTBEAT_TIMEOUT_SECONDS=20 OFFLINE_SWEEP_INTERVAL_SECONDS=5 \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 &
cd ..

SENTRA_QA_API_URL=http://127.0.0.1:8100 SENTRA_QA_ENROLLMENT_KEY=$AGENT_ENROLLMENT_KEY \
  backend/.venv/bin/python qa/e2e_api.py --offline
```

The agent runs on Linux too (`pip install -e ".[dev]"` in `agent/`, then
`SENTRA_AGENT_ENROLLMENT_KEY=$AGENT_ENROLLMENT_KEY .venv/bin/python -m sentra_agent --api-url
http://127.0.0.1:8100 --interval 5 --state-dir /tmp/sentra-qa-agent`). It reports metrics,
interfaces, disks, processes, connections, installed packages (dpkg/rpm) and systemd services
(empty in containers without systemd). Host log events are Windows-only for now (journald is
not collected yet).

## Manual recovery scenarios

| Scenario | How | Expected |
|----------|-----|----------|
| API down | stop the 8100 uvicorn, wait, start it again | agent logs `API unreachable` with backoff, buffers samples, then `connection to API restored`; buffered samples keep their original `recorded_at` |
| PostgreSQL down | `pg_ctl stop` on the QA cluster | `/health` 503 `degraded`; other endpoints 503 `database_unavailable`; agent buffers; after `pg_ctl start` everything recovers without restarting the API |
| Agent restart | kill the agent, start it with the same `--state-dir` | same `agent_id`/asset, no new enrollment, no duplicated events |
| Token revoked | `python -m app.cli revoke-agent <asset_id>` then `reinstate-agent` | agent gets 401, then 403 `agent_revoked` and backs off; after reinstating it re-enrolls into the same asset |
| Dashboard without API | stop the API with the dashboard open | "No se pudo conectar con la API de Sentra (HTTP 502)" and the header shows the API as unavailable |
