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
.venv\Scripts\python.exe -m app.cli create-admin --username qaadmin   # Fase 4G, una vez
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8100
```

With the same variables, `python -m pytest` uses `sentra_qa_test` instead of the shared
`sentra_test`, so it can run while other people run theirs.

## 3. Contract and failure-case suite

```powershell
$env:SENTRA_QA_API_URL = "http://127.0.0.1:8100"
$env:SENTRA_QA_ENROLLMENT_KEY = "qa-enrollment-key-0123456789abcdef"
$env:SENTRA_QA_ADMIN_USER = "qaadmin"
$env:SENTRA_QA_ADMIN_PASSWORD = "<la contraseña elegida en create-admin>"
backend\.venv\Scripts\python.exe qa\e2e_api.py --offline
```

Covers: login, sesión, CSRF y roles (Fase 4G), health and error envelope, request id and security headers, the error envelope in the
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

Fase 4H (`test_detections`): una detección simple (registro borrado), una correlación
(fallos de inicio de sesión seguidos de un acceso correcto, CORR-001), la deduplicación (un
segundo borrado añade evidencia a la misma detección) y la resolución con nota, el 409 al
reconocer una resuelta y su registro en `audit_events`. Usa el job real del motor: arranca la
API QA con `$env:DETECTION_EVAL_INTERVAL_SECONDS = "2"` para que tarde poco.

Fase 4I (`test_risk`): el escenario completo del riesgo sobre un activo nuevo. Limpio
(informativo, sin contribuciones), detección alta (sube y la contribución enlaza a la
detección), correlación (sube más y la ráfaga queda absorbida, sin doble conteo; las
contribuciones suman el score), criticidad (viewer 403, valor inválido 422, activo
inexistente 404, admin recalcula al momento y queda auditado; cruzar a crítico abre una sola
alerta `risk_critical`) y resolver (baja, las resueltas conservan memoria y la alerta se
resuelve al salir de crítico), además del historial con subida y bajada. Arranca la API QA
también con `$env:RISK_EVAL_INTERVAL_SECONDS = "2"`. El decay por horas no se espera aquí: lo
cubren los tests de backend con reloj simulado.

Fase 4K (`test_incidents`): crea un analyst y un viewer temporales y cubre tres escenarios:
(1) detección → incidente (y 409 al promoverla dos veces) → triage → asignación → nota →
investigación → contención → resolución (422 sin categoría) → cierre por admin (403 para el
analyst), caso cerrado congelado, auditoría `incident_*` completa y timeline con caso, nota y
detección (la nota como texto plano); (2) una segunda detección del mismo activo sugiere el
incidente abierto, se adjunta y no se crea otro; (3) dos sesiones escriben sobre la misma
`version`: la primera gana y la segunda recibe 409 `incident_conflict` con la versión actual,
sin sobrescritura silenciosa. Necesita `DETECTION_EVAL_INTERVAL_SECONDS=2`.

Fase 4L (`test_asset_context`): crea un viewer y un segundo admin temporales. Contexto por
defecto en `unknown`; el viewer lee pero no edita (403); HTML en el owner → 422; el admin fija
rol `server`, criticidad `high`, entorno `production`, owner `IT` y zona `server` con
procedencia `manual`; un único evento de auditoría con los campos cambiados; la explicación
del riesgo muestra la influencia del contexto; el incidente creado desde la detección muestra
el contexto actual y guarda el snapshot; el resumen de amenaza cuenta detecciones e
incidentes; dos admins con la misma `version`: el primero guarda y el segundo recibe 409
`asset_context_conflict` sin sobrescritura; y los filtros de contexto del listado.

Fase 5B (`qa/e2e_vulnerabilities.py`, mismo entorno que `e2e_api.py`): cinco escenarios con
un catálogo sintético propio por ejecución (fuente `qa-vuln-<aleatorio>`, `CVE-2099-*`).
(1) Catálogo: previsualizar no escribe, importar con otra huella da 409, una referencia
`javascript:` es un registro inválido, JSON muy anidado 422, analyst y viewer 403 al importar.
(2) Windows: inventario → finding confirmado con su porqué; una coincidencia solo por nombre
no se confirma; un activo con un puerto abierto y sin inventario no tiene findings.
(3) Flujo: viewer 403, analyst reconoce, versión obsoleta 409 `vulnerability_conflict`,
analyst no acepta riesgo (403), admin acepta con caducidad y reabre. (4) Ciclo de vida:
actualizar a la versión corregida resuelve (`resolved_by_inventory_change`), volver a la
vulnerable reabre, con historial. (5) Integraciones: incidente manual (viewer 403), vínculo
en ambos sentidos, IA de solo lectura (409 si está desactivada), contribución en el riesgo
y auditoría. Fuerza la evaluación con `POST /vulnerabilities/evaluate`; el riesgo espera al
job (`RISK_EVAL_INTERVAL_SECONDS=2` lo acelera).

```powershell
backend\.venv\Scripts\python.exe qa\e2e_vulnerabilities.py
```

Fase 5C (`qa/e2e_threat_intel.py`, mismo entorno): cinco escenarios con IPs aleatorias de
198.18.0.0/15 (RFC 2544) por ejecución. (1) Fuentes: las tres sembradas, solo el host de
descarga, una URL desde el navegador 422, sincronizar sin `THREAT_INTEL_SYNC_ENABLED` 422
`threat_intel_sync_disabled`, readiness independiente. (2) Importación de IOCs: previsualizar
no escribe, otra huella 409 `threat_intel_changed`, inválidos sin `skip_invalid` 422, STIX
muy anidado 422, patrón STIX complejo como "unsupported", analyst y viewer 403. (3) Matching:
un 4625 y una conexión establecida contra IOCs maliciosos → coincidencias con evidencia y
TI-001 enlazada (según `THREAT_INTEL_DETECTION_POLICY`). (4) Triage: viewer 403, versión
vieja 409, descartar sin motivo 422, incidente manual nunca con confianza alta, contribución
en el riesgo. (5) KEV/EPSS offline: con `SENTRA_QA_BACKEND_DIR` crea fuentes propias
`qa-kev-…`/`qa-epss-…`, las importa con la CLI (no toca `cisa-kev` ni `first-epss`) y
comprueba la procedencia en el finding; sin la variable, SKIP. Arranca la API QA con
`THREAT_INTEL_EVAL_INTERVAL_SECONDS=10` (el matching es un job; el script espera hasta
`SENTRA_QA_TI_TIMEOUT`, 180 s). No descarga nada de Internet.

```powershell
$env:SENTRA_QA_BACKEND_DIR = "$PWD\backend"   # opcional: escenario 5
backend\.venv\Scripts\python.exe qa\e2e_threat_intel.py
```

## 4. Rendimiento del motor de detección

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_detections.py --explain
```

Con datos sintéticos (por defecto 200 activos, 50 eventos por activo y 50 000 detecciones de
histórico) mide la extracción de señales por lote, las señales/s del job, los listados y el
detalle (con el número de sentencias SQL) y muestra los planes de PostgreSQL. Borra lo que
crea. Ejecútalo contra la base QA con la API QA parada, para que su job no evalúe las señales
antes. Resultados de referencia en [docs/detection-engine.md](../docs/detection-engine.md).

### Rendimiento del Risk Engine

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_risk.py   # --assets 1000 --detections 20000 --history-per-asset 200
```

Con datos sintéticos mide la primera evaluación, un recálculo completo sin cambios y una
pasada de decay (activos/s y sentencias SQL por activo), y después el resumen, el listado,
el detalle, la tendencia y las contribuciones con un historial grande. Borra lo que crea.
Ejecútalo con la API QA parada. Resultados de referencia en
[docs/risk-engine.md](../docs/risk-engine.md).

### Rendimiento de incidentes

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_incidents.py   # --incidents 10000 --activity-per-incident 10
```

Con datos sintéticos (10 000 incidentes, 50 000 relaciones, 100 000 elementos de actividad y
10 000 notas) mide overview, listados con filtros y orden, búsqueda (INC, hostname, IP,
título de detección), detalle, timeline por cursor, evidencia, notas y sugerencias de
relacionados, con sentencias SQL por petición. Borra lo que crea. Resultados de referencia en
[docs/incident-management.md](../docs/incident-management.md).

### Rendimiento de Asset Context

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_asset_context.py   # --assets 10000
```

Con 10 000 activos sintéticos (contexto, etiquetas, historial y detecciones) mide la lista
paginada, el orden por criticidad, cada filtro de contexto, el detalle, el contexto, el
historial, las opciones y el resumen de amenaza, con sentencias SQL por petición. Borra lo que
crea (por prefijo, también restos de una ejecución interrumpida). Ejecútalo con la API QA
parada: sus jobs de riesgo compiten por las mismas filas al borrar. Resultados de referencia en
[docs/asset-context.md](../docs/asset-context.md).

### Rendimiento de vulnerabilidades

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_vulnerabilities.py   # --assets 10000 --records 100000
```

Con 10 000 activos sintéticos (100 000 programas), un catálogo de 100 000 registros y ~50 000
findings mide la importación por la ruta de la CLI, la evaluación completa y una reevaluación
sin cambios (activos/s) y las lecturas de la UI (resumen, listado con filtros, orden y
búsqueda, findings de un activo y exposición) con sentencias SQL por petición. Borra lo que
crea. Ejecútalo con la API QA parada. Resultados de referencia en
[docs/vulnerability-management.md](../docs/vulnerability-management.md).

### Rendimiento de Threat Intelligence

```powershell
cd backend
$env:PYTHONPATH = "."
.venv\Scripts\python.exe ..\qa\perf_threat_intel.py   # --indicators 100000 --epss 300000
```

Con datos sintéticos (KEV de 2 000 entradas, EPSS de 300 000 filas en gzip, 100 000 IOCs,
2 000 activos con conexiones y 50 000 eventos 4625) mide la importación de feeds por la ruta
de la CLI (también la reimportación idéntica y la del "día siguiente"), la previsualización y
la importación de IOCs, el matching retroactivo e incremental y las lecturas de la UI con
sentencias SQL por petición. Borra lo que crea (prefijo `perf-ti-`). Ejecútalo con la API QA
parada. Resultados de referencia en
[docs/threat-intelligence.md](../docs/threat-intelligence.md).

### Fase 4M: producción y dashboard paginado

`qa/e2e_production.py` (solo stdlib) prueba la API en modo producción detrás de un Caddy real
(`deploy/caddy/Caddyfile.example` con `tls internal` y el upstream en el 8100):

```bash
SENTRA_QA_PUBLIC_URL=https://sentra.qa.lan SENTRA_QA_HTTP_URL=http://sentra.qa.lan \
SENTRA_QA_CA_FILE=<raíz de Caddy> SENTRA_QA_DIRECT_URL=http://127.0.0.1:8100 \
SENTRA_QA_ADMIN_USER=... SENTRA_QA_ADMIN_PASSWORD=... \
python qa/e2e_production.py --scenario proxy   # también: ai-down, db-down, db-up, workers
```

`proxy`: HTTPS, redirección, cabeceras y CSP, cookie `__Host-`, CSRF/Origin, IP real tras el
proxy, sourcemaps y métricas ocultos, agente con TLS verificado. `ai-down`: readiness sigue
`ready`. `db-down`/`db-up`: 503 sin trazas y recuperación sin reiniciar. `workers`: dos
workers comparten rate limiting y los jobs singleton.

`qa/perf_dashboard.py` siembra 10 000 activos y 10 000 incidentes y mide el dashboard
(`seed`, `measure`, `cleanup`; uso en el docstring). Resultados en `docs/DEVELOPMENT_STATUS.md`.

## 5. Real agent and dashboard against the QA API

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
.venv/bin/python -m app.cli create-admin --username qaadmin   # pide la contraseña
HEARTBEAT_TIMEOUT_SECONDS=20 OFFLINE_SWEEP_INTERVAL_SECONDS=5 \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8100 &
cd ..

read -rs -p "QA admin password: " SENTRA_QA_ADMIN_PASSWORD; export SENTRA_QA_ADMIN_PASSWORD
SENTRA_QA_API_URL=http://127.0.0.1:8100 SENTRA_QA_ENROLLMENT_KEY=$AGENT_ENROLLMENT_KEY \
  SENTRA_QA_ADMIN_USER=qaadmin backend/.venv/bin/python qa/e2e_api.py --offline
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
| PostgreSQL down | `pg_ctl stop` on the QA cluster | `/health` 200 (liveness), `/health/ready` 503 `not_ready`; other endpoints 503 `database_unavailable`; agent buffers; after `pg_ctl start` everything recovers without restarting the API |
| Agent restart | kill the agent, start it with the same `--state-dir` | same `agent_id`/asset, no new enrollment, no duplicated events |
| Token revoked | `python -m app.cli revoke-agent <asset_id>` then `reinstate-agent` | agent gets 401, then 403 `agent_revoked` and backs off; after reinstating it re-enrolls into the same asset |
| Dashboard without API | stop the API with the dashboard open | "No se pudo conectar con la API de Sentra (HTTP 502)" and the header shows the API as unavailable |
