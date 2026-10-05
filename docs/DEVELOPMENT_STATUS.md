# Sentra development status

Handoff document: enough to continue the project without prior conversation context.
Last updated: 2026-10-05 (Fase 4G).

## Current state

MVP working end to end on the developer's Windows PC with real data:
PC → Sentra Agent → API → PostgreSQL → Web (verified in the browser, including an API
outage during which the agent buffered samples and delivered them on reconnection).

| Component | State |
|-----------|-------|
| Backend API (FastAPI) | Done: agents (enrollment with one-time tokens or legacy shared key + per-agent tokens; admin API for enrollment tokens behind ADMIN_API_KEY), assets, telemetry + history, inventory + change detection, process snapshots, events (filters), alerts (lifecycle, filters, detail), retention, health; hybrid monitoring: agentless network discovery (allowlisted networks only), exposed ports with baseline, agent/discovery reconciliation, exposure correlation |
| Database (PostgreSQL 18 native, Alembic) | Done: migrations 0001–0017 |
| Agent (Python, Windows-first) | Done: identity + token (DPAPI-encrypted at rest), heartbeat (+ host refresh), telemetry, inventory incl. disks, network connections, gateways/DNS, local accounts, service pid, software install date/architecture (15 min; on Linux also systemd services and dpkg/rpm packages), process snapshots (60 s), Windows Event Log System/Application/Security/PowerShell (60 s), compatibility with older servers (drops unknown fields), buffering persisted across restarts, backoff + jitter + Retry-After, re-enrollment, revocation handling (403), rotating logs with secret redaction |
| Agent management (dashboard) | Done: Agentes page (summary, agents with credential status, installation tokens), Add agent wizard (Linux one-time token, install command, live registration), revoke / reinstate with confirmation, Agent section in asset detail. Admin operations through `/api/v1/console` (sesión + rol admin desde cualquier equipo, Fase 4G) |
| Autenticación del dashboard | Fase 4G: usuarios locales (Argon2id), roles admin/analyst/viewer con permisos centralizados, sesiones de servidor en cookie HttpOnly (caducidad, inactividad, rotación, revocación), CSRF (Origin + token), límites de intentos en login y registro de agentes, página Usuarios, auditoría (`audit_events`), bootstrap y recuperación por CLI (`create-admin`, `reset-password`). Migración 0017. [authentication.md](authentication.md) |
| Agent distribution (Linux) | Done: reproducible tarball + `.deb` (`agent/packaging/linux/build.sh`), one-command installer with one-time token, systemd service as unprivileged `sentra-agent` with hardening, upgrade keeping identity, uninstall / purge. Pending: validation under a real systemd at boot |
| Agent distribution (Windows) | Fase 4F: zip reproducible con Python embebido oficial (`agent/packaging/windows/build.py`, firma PSF verificada), instalador PowerShell con token de un solo uso (aviso oculto o `-TokenFile`), servicio Windows estándar `SentraAgent` (inicio automático retrasado, recuperación ante fallos) con cuenta virtual `NT SERVICE\SentraAgent` + Event Log Readers (Security sin administrador), enrolamiento hecho por el propio servicio (DPAPI de su cuenta), upgrade sin re-enrolar, `-Reenroll`, desinstalación / `-Purge`; `installation_method` en el dashboard (migración 0016, tras la 0015 de la Fase 4E). Pendiente: validación en Windows físico (checklist en docs/agent-windows-installation.md) |
| Frontend (React, Vite) | Done: dashboard (counts, assets, active alerts, recent activity), asset detail with tabs Overview / Processes / Services / Software / Network / Users / Events / Alerts (search, filters, sort, pagination, change history), alerts page with filters and detail; Network page (discovered/monitored/managed, filters, discovery runs) and Exposure tab. Fase 4D: descubrimiento desde la página Red (iniciar, progreso real, cancelar, resultado, historial, estado del scheduler) sin terminal |
| Alerts | Done: offline, sustained high CPU/RAM, critical disk, watched service stopped, critical events, error bursts, administrator changes; new asset / unknown device / disappeared / port exposed / port closed / monitoring lost (discovery; first run is a quiet baseline); states open/acknowledged/resolved (ack/resolve desde el dashboard o la CLI), dedup, occurrences, auto-resolve |
| Tests | Backend 481 (real PostgreSQL, incl. model/migration drift, indexed foreign keys, frontend type contract checks, autenticación/RBAC/CSRF/auditoría and real TCP discovery on loopback), agent 136 (3 Windows-only; Linux packaging tests run the real installer under a fake root); frontend 137 tests (Vitest, incl. DOM tests of the Agentes and Red pages with Testing Library + jsdom) + tsc + ESLint + build; `qa/e2e_api.py` 170 contract checks |

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
- `alerts`: rule, severity, open/acknowledged/resolved, details (JSONB), occurrences, source event
  (FK, SET NULL on event deletion). Partial unique index = one active (not resolved) alert per
  asset+rule.
- `asset_changes`: differences between consecutive inventories (service/software/account).
- `asset_process_snapshots`: latest process list per asset (one row, replaced; no history).
- `assets` also holds hosts without agent (`monitoring_method` discovered/agentless/agent;
  agent fields null for them) and the network view (MAC, reverse DNS, device type, network
  status, discovery times).
- `asset_ports`: TCP exposure per asset and port (open/closed, first/last seen), updated in
  place; history in `asset_changes` (category exposure/network).
- `discovery_jobs`: one row per discovery run and network; one queued or running job per network (0014: estado `queued`, progreso, latido, cancelación, origen y resultados del job).
- `asset_inventories`: one JSONB snapshot per asset (interfaces, disks, listening/established
  connections, users, processes, services, software, accounts, network); newer snapshots
  replace older only.
- `system_events`: host log events; unique `(asset_id, channel, record_id)` makes resends idempotent.

## Key rules

- Agent auth: enrollment with a one-time token (`X-Enrollment-Token`, recommended: hash-only,
  15 min, single use, revocable, consumed atomically) or the legacy `AGENT_ENROLLMENT_KEY`
  (`X-Enrollment-Key`); returns a per-agent token once; all other agent calls need
  `Authorization: Bearer` with that token. Re-enrollment rotates the token.
- Enrollment tokens are managed from the dashboard (Agentes page, through `/console`), with
  `python -m app.cli create-enrollment-token` / `list-enrollment-tokens` /
  `revoke-enrollment-token`, or the admin API (`/agent-enrollment-tokens`, header
  `X-Admin-Key` = `ADMIN_API_KEY`; disabled if unset). The browser never gets the admin key.
- Dashboard: todo endpoint del dashboard exige sesión y un permiso (`require_permission`);
  las mutaciones además Origin + `X-CSRF-Token`. `DASHBOARD_ADMIN_ENABLED` y la consola
  local se eliminaron en la Fase 4G; `ADMIN_API_KEY` queda como legacy para scripts.
  Revoking keeps all history; reinstating requires a new one-time
  token (re-enrollment keeps the same asset).
- Status: `unknown` until first contact; `online` while reporting; `offline` when
  `last_seen_at` is older than `HEARTBEAT_TIMEOUT_SECONDS` (computed at read time; server clock).
- Alerts: CPU/RAM need `ALERT_SUSTAINED_SAMPLES` consecutive samples over threshold; disk alerts
  on one sample; offline opened by a 30 s sweeper, resolved on the next contact of any kind.
  Service alerts come from inventory (`ALERT_WATCHED_SERVICES`, disabled services skipped);
  event alerts from newly stored events (`ALERT_CRITICAL_EVENTS`, bursts) and resolve after
  `ALERT_EVENT_QUIET_MINUTES` without firing. No alert on a single CPU/RAM spike.
- `last_seen_at` only moves forward (`GREATEST`), so delayed requests cannot age an asset.

## Endpoints (`/api/v1`)

Agent (token): `POST /agents/register` (one-time token or enrollment key) · `POST /agents/heartbeat` ·
`POST /telemetry` · `POST /inventory` · `POST /events` · `POST /processes`.
Read (dashboard): `GET /health` · `GET /assets` · `GET /assets/{id}` ·
`GET /assets/{id}/telemetry` · `GET /assets/{id}/inventory` · `GET /assets/{id}/changes` ·
`GET /assets/{id}/processes` · `GET /alerts` · `GET /alerts/{id}` · `GET /events` ·
`GET /agents` · `GET /assets/{id}/agent`.
Console (local dashboard): `GET /console` · `GET|POST /console/enrollment-tokens` ·
`POST /console/enrollment-tokens/{id}/revoke` · `POST /console/agents/{id}/revoke|reinstate` ·
`POST /console/discovery/jobs` · `POST /console/discovery/jobs/{id}/cancel` (Fase 4D).
Operator CLI (`python -m app.cli`): `list-agents`, `revoke-agent`, `reinstate-agent`,
`ack-alert`, `resolve-alert`, `purge-old-data`, `discovery-scope`, `discover`.
Read (discovery): `GET /assets/{id}/exposure` · `GET /discovery/scope` · `GET /discovery/schedule` ·
`GET /discovery/jobs` · `GET /discovery/jobs/{id}`. `discover` en la CLI queda como herramienta
administrativa/debug: el uso normal es la página Red (docs/discovery.md).
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
cd frontend; npm test; npm run typecheck; npm run lint; npm run build
```

## Known issues and limitations

- Sin HTTPS integrado: en la LAN por HTTP la contraseña y la cookie viajan en claro; en
  producción servir detrás de un proxy HTTPS (docs/authentication.md). Los límites de login
  son en memoria de un solo proceso. `GET /health` sigue público (sin datos).
- Agent runs in the foreground as the current user; no Windows service/installer. The Security
  event channel needs admin rights: as a standard user it is logged once as unreadable and
  skipped (privileges are never changed).
- Agent token in `%LOCALAPPDATA%\Sentra\Agent\identity.json`, DPAPI-encrypted (current user).
  No mTLS yet; API URLs other than loopback should be https (the agent warns).
- Retention is opt-in (`TELEMETRY_RETENTION_DAYS`, `EVENT_RETENTION_DAYS`,
  `CHANGE_RETENTION_DAYS`, `ALERT_RETENTION_DAYS` for resolved alerts; unset keeps everything)
  and deletes rows; there is no downsampling (aggregating old samples) yet.
- Free-text search over all events (no asset filter) scans the table: 0.8 s at 1M events.
  Per-asset search is 40 ms. A trigram index (pg_trgm) would fix it if it becomes a need.
- Alert thresholds are global environment variables, not per asset.
- Discovery: la cola del dashboard es en memoria por proceso (un job a la vez por worker);
  la configuración sigue en variables de entorno. No OUI vendor database; `GET /assets` is not paginated (about 850 KB and 120 ms
  with 1000 assets); agentless collectors are contracts only (no credential store yet).
- Local PostgreSQL listens on 5433 on the dev PC (setup detects it).

## Decisions

- Offline computed on read (+ sweeper for alerts) instead of a status-writing scheduler.
- Token hashes with SHA-256 (tokens are 256-bit random; slow hashes add no security here).
- Agent buffers up to 120 samples (memory + `telemetry_buffer.json`); backoff interval → 300 s with jitter.
- Agent token at rest: DPAPI current-user scope via ctypes (no pywin32). Revocation via operator CLI (`python -m app.cli`) or the dashboard (rol admin).
- Descubrimiento desde la web (Fase 4D): jobs en cola ejecutados por un runner en segundo
  plano en el proceso de la API (uno a la vez), progreso y cancelación a través de la base
  de datos (funciona con varios workers), latido para detectar jobs huérfanos. Iniciar y
  cancelar requieren `discovery:run` (Fase 4G); sin worker ni cola externa (Redis).
- Identificación de dispositivos (Fase 4E, docs/discovery.md): motor puro con evidencias y
  confianza low/medium/high, recalculado con cada dato nuevo; el agente es autoritativo; el
  OUI es un fichero local del IEEE (sin API externa) y la NIC no se confunde con el
  fabricante del dispositivo. Migración 0015.
- Autenticación (Fase 4G): sesiones de servidor (token aleatorio, solo el hash en la base de
  datos) en vez de JWT, para poder revocarlas; Argon2id para contraseñas; política por
  longitud sin reglas de composición; permisos en una tabla central, no comprobaciones de
  rol; los usuarios se desactivan, no se borran; siempre queda al menos un admin activo.
- Agent uses stdlib + psutil + built-in `wevtutil.exe` (no pywin32).
- Inventory as JSONB snapshot; normalize a section when SQL queries over it are needed.
- Retention opt-in and per data type (`services/retention_service.py`): batches of 5000 rows,
  each committed on its own, found through existing indexes. Only resolved alerts are
  purged. Every foreign key has an index (enforced by a test): without
  `ix_alerts_source_event` a 5000-event batch took 51 s with 100k alerts, 0.3 s with it. An asset silent for longer than the telemetry retention loses its last sample, so
  the dashboard shows its metrics as "—". On-demand: `python -m app.cli purge-old-data`.

## Recommended next phase

1. HTTPS de producción documentado y probado (proxy inverso) y validación física de la
   Fase 4F (servicio Windows).
2. Per-asset alert thresholds.
4. Downsampling for old telemetry (retention exists, opt-in); journald events on Linux
   (systemd services and dpkg/rpm packages are collected already).
