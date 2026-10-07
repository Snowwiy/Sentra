# Sentra development status

Handoff document: enough to continue the project without prior conversation context.
Last updated: 2026-10-06 (Fase 5C).

## Current state

MVP working end to end on the developer's Windows PC with real data:
PC → Sentra Agent → API → PostgreSQL → Web (verified in the browser, including an API
outage during which the agent buffered samples and delivered them on reconnection).

| Component | State |
|-----------|-------|
| Backend API (FastAPI) | Done: agents (enrollment with one-time tokens or legacy shared key + per-agent tokens; admin API for enrollment tokens behind ADMIN_API_KEY), assets, telemetry + history, inventory + change detection, process snapshots, events (filters), alerts (lifecycle, filters, detail), retention, health; hybrid monitoring: agentless network discovery (allowlisted networks only), exposed ports with baseline, agent/discovery reconciliation, exposure correlation |
| Database (PostgreSQL 18 native, Alembic) | Done: migrations 0001–0026 |
| Agent (Python, Windows-first) | Done: identity + token (DPAPI-encrypted at rest), heartbeat (+ host refresh), telemetry, inventory incl. disks, network connections, gateways/DNS, local accounts, service pid, software install date/architecture (15 min; on Linux also systemd services and dpkg/rpm packages), process snapshots (60 s), Windows Event Log System/Application/Security/PowerShell (60 s), compatibility with older servers (drops unknown fields), buffering persisted across restarts, backoff + jitter + Retry-After, re-enrollment, revocation handling (403), rotating logs with secret redaction |
| Agent management (dashboard) | Done: Agentes page (summary, agents with credential status, installation tokens), Add agent wizard (Linux one-time token, install command, live registration), revoke / reinstate with confirmation, Agent section in asset detail. Admin operations through `/api/v1/console` (sesión + rol admin desde cualquier equipo, Fase 4G) |
| Autenticación del dashboard | Fase 4G: usuarios locales (Argon2id), roles admin/analyst/viewer con permisos centralizados, sesiones de servidor en cookie HttpOnly (caducidad, inactividad, rotación, revocación), CSRF (Origin + token), límites de intentos en login y registro de agentes, página Usuarios, auditoría (`audit_events`), bootstrap y recuperación por CLI (`create-admin`, `reset-password`). Migración 0017. [authentication.md](authentication.md) |
| Motor de detección | Fase 4H: señales normalizadas en la ingesta (sin bloquearla), job `detection-engine` con 19 reglas simples y 4 correlaciones (CORR-001..004), detecciones persistentes con severidad y confianza separadas, evidencias, explicación y recomendaciones por plantilla, deduplicación, cooldown y línea base; alerta `security_detection` solo desde `DETECTION_ALERT_MIN_SEVERITY`; páginas Detecciones y detalle con timeline; reconocer/resolver con `detections:manage` y auditoría. Agente: campos estructurados por lista permitida, 4624 interactivo/RDP y canal de Defender. Migración 0018. [detection-engine.md](detection-engine.md) |
| Risk Engine | Fase 4I: score 0-100 por activo con nivel (umbrales `RISK_LEVEL_THRESHOLDS`) y confianza separados; fórmula determinista (severidad × confianza × ocurrencias × correlación × estado × antigüedad, sin doble conteo, rendimientos decrecientes, criticidad y tipo acotados, saturación) con ledger de contribuciones que suma el score; cola `dirty_at` alimentada por detecciones, ack/resolve, puertos y criticidad (nunca por heartbeat) y job `risk-engine` con decay; historial solo en cambios materiales; alerta `risk_critical` al cruzar hacia crítico con cooldown; criticidad de activo solo admin (`assets:manage`, auditada). Página Riesgo, sección Riesgo del activo con tendencia 24h/7d/30d y columna Riesgo en Activos. Migración 0019. [risk-engine.md](risk-engine.md) |
| AI Security Insights | Fase 4J: capa de interpretación opcional (`AI_ENABLED=false` por defecto) sobre 4H/4I. Proveedor desacoplado (`AIProvider`) con implementación OpenAI-compatible por stdlib (local o externo; externos bloqueados salvo `AI_ALLOW_EXTERNAL`), context builder con lecturas cerradas y acotadas, plantillas versionadas, salida JSON validada, grounding con referencias cortas traducidas a ids reales (IDs inventados descartados; respuesta sin evidencia válida rechazada), redacción opcional reversible, caché con huella de datos y estado stale, rate limit por usuario/global y tope de concurrencia, auditoría `ai_analysis_*`. Permiso `ai:use` (todos los roles, junto a `monitoring:read`). UI: página AI Insights con Ask Sentra AI y resumen SOC, "Analizar con IA" en el activo, "Explicar con IA" en la detección, "Analizar riesgo" en Riesgo. Migración 0020. Fase 4J.1 (local-first): modo recomendado Local AI (Ollama, llama.cpp, vLLM...), LAN solo con `AI_LOCAL_NETWORKS`, verificación de la IP real antes de enviar, externos solo con `AI_ALLOW_EXTERNAL` y https, sin fallback cloud, estado del proveedor con health check (`state`, `mode_label`) en `/ai/status` y en la UI. [ai-security-insights.md](ai-security-insights.md) |
| Gestor de modelos locales | Fase 4J.2: Configuración → IA local → Modelos. Perfil de hardware (CPU, RAM, GPU NVIDIA/AMD/Intel, VRAM, disco) bajo demanda; abstracción `LocalAIRuntime` (llama.cpp, Ollama, vLLM, genérico) que solo habla con `AI_BASE_URL` local; registro de GGUF dentro de `AI_MODEL_DIRECTORIES` con cabecera validada y SHA-256; estimación de memoria (pesos + KV cache + overhead, offload, margen); motor de recomendación determinista con perfiles y "Recommended for Sentra"; selección con health check sin fallback cloud; benchmark local acotado y cancelable. Permiso `ai:manage` (solo admin). Migración 0021. [local-model-manager.md](local-model-manager.md) |
| Gestión de incidentes | Fase 4K: incidentes `INC-000001` (secuencia, no PK) que agrupan por referencia detecciones, correlaciones, alertas y activos; state machine centralizada (open → triage → investigating ⇄ contained → resolved → closed, reopen explícito, merged terminal); severidad, prioridad (sugerida, no 1:1) y confianza (de la evidencia) separadas; creación manual o desde detección/alerta; incidentes relacionados sugeridos con motivos (sin deduplicación automática); asignación (analyst a sí mismo, admin a otros; nunca viewer ni inactivos); notas append-only; timeline unificado con cursor; evidencia agrupada; resolución con categoría obligatoria, feedback de falsos positivos, duplicado (referencia) vs fusión (admin); snapshot de riesgo 4I; concurrencia optimista (`version`, 409 `incident_conflict`); IA de solo lectura (`summary`, `timeline`, `evidence`, `next_steps`). Permisos `incidents:read` / `incidents:manage` / `incidents:admin`, auditoría `incident_*`. UI: Incidentes, detalle con 8 pestañas, panel en detección/alerta y vista SOC en el dashboard. Migración 0022. [incident-management.md](incident-management.md) |
| Asset Context | Fase 4L: contexto de negocio por activo sin duplicar Asset (`asset_context`, `asset_tags`, `asset_context_changes`): criticidad 4I con justificación y autor, rol (sugerencia 4E aparte, nunca sobrescribe), entorno, owner, equipo, sensibilidad, zona lógica, exposición a Internet tri-estado, estado de gestión reutilizado y tags normalizadas con límites; procedencia por campo (manual/agent/discovery/inferred, listo para snmp/lldp/manufacturer/threat_intel); un evento de auditoría con diff por operación; concurrencia optimista (409 `asset_context_conflict`); riesgo con factores de contexto acotados (×1,25, solo con evidencia, `FORMULA_VERSION` 2) y visibles en la explicación; contexto y snapshots en incidentes; impacto separado de la severidad en detecciones; contexto grounded y seudonimizado en la IA; resumen de amenaza interno. Edición solo admin. UI: pestaña Contexto, filtros compactos en Activos. Migración 0023. [asset-context.md](asset-context.md) |
| Reglas personalizadas y Sigma | Fase 5A: Detecciones → Reglas. Reglas `builtin` (las 23 de 4H, solo lectura), `custom` y `sigma` con UID estable (`SENTRA-CUSTOM-nnnnnn`, `SENTRA-SIGMA-nnnnnn`), versiones inmutables (restaurar crea versión nueva), estado admin (draft/active/disabled/retired) separado del de compilación (valid/partial/invalid/unsupported). Formato declarativo `sentra-rule/1` (operadores acotados, regex segura, umbral con agrupación, campos `asset.*` del contexto 4L) compilado y ejecutado por el mismo motor 4H (sin motor paralelo): índice por tipo/canal/id de evento, evaluación en memoria, savepoint solo al coincidir, recarga en caliente por huella sin Redis. Importador Sigma de subconjunto (YAML seguro, siempre en borrador, `unsupported` con motivo). Validar, prueba sintética e histórica (solo lectura, `statement_timeout`, advisory lock, límite por usuario) sin efectos. `rules:read` (todos), `rules:test` (analyst), `rules:manage` (admin), auditoría de cada cambio y prueba. [custom-detection-rules.md](custom-detection-rules.md), [sigma-support.md](sigma-support.md) |
| Vulnerabilidades y exposición | Fase 5B: catálogo local offline-first `sentra-vuln-catalog/1` (importación por UI con previsualización y huella SHA-256, o CLI por lotes con lock; revisiones por fuente; sin feeds externos) y `VulnerabilityEngine` por activo con cola `dirty_at` (inventario, SO, puertos, contexto, catálogo; nunca por heartbeat). Matcher determinista y explicable: claves exactas de nombre/paquete/SO, editor, esquemas de versión `generic`/`semver`/`windows_build`/`dpkg`/`rpm`; estados técnicos confirmed/probable/potential/unknown/not_affected con confianza y `rationale`; las potenciales siempre aparte. Ciclo de vida automático (resuelto por inventario, por desinstalación tras N capturas completas, por catálogo; reapertura; evidencia antigua). Flujo humano con concurrencia optimista (409 `vulnerability_conflict`), resolver con `override_evidence`, riesgo aceptado admin-only con caducidad, falso positivo reevaluado ante cambio material. Exposición honesta (sensor LAN, escucha del agente, Internet solo si el contexto 4L lo confirma). Prioridad Sentra 0-100 con factores. Riesgo 4I fórmula v3 (vulnerabilidad agrupada con la exposición de su puerto, sin doble conteo). Alerta `vulnerability` solo en cambios relevantes; incidentes solo manuales; IA `vulnerability_analysis` de solo lectura; métricas sin CVE. Agente: `software_source` e `incomplete_sections`. `vulnerabilities:read` (todos), `:manage` (analyst), `:admin` (admin). UI: Vulnerabilidades, detalle con pestañas, Exposición, Catálogo (admin), pestaña del activo y columna en Software. Migración 0026. [vulnerability-management.md](vulnerability-management.md), [vulnerability-catalog.md](vulnerability-catalog.md) |
| Threat Intelligence | Fase 5C, offline-first: fuentes con adapter (`cisa_kev`, `first_epss`, `local_import`; TAXII solo documentado), sembradas desactivadas salvo `local-iocs`; descargas por red apagadas (`THREAT_INTEL_SYNC_ENABLED=false`), solo desde la URL del adapter o `THREAT_INTEL_SOURCE_URLS` (la API nunca acepta URLs) con defensas SSRF (IPs públicas o redes autorizadas, anti DNS rebinding, redirecciones revalidadas, tamaño y tiempos). Sincronización/importación con advisory lock por fuente, ETag/If-Modified-Since, staging con COPY y aplicación atómica por conjuntos, guardia de feed encogido y caché conservada ante fallos (`stale` sin borrar nada). KEV y EPSS (streaming, historial solo de cambios materiales) por CVE con procedencia y discrepancias lado a lado; `vulnerability_findings.intel_cve`; prioridad 5B fórmula v2 (KEV +10, EPSS alta +6/elevada +3, tope 14, mitad si stale). IOCs `sentra-ioc/1` y subset seguro de STIX 2.x con previsualización y sha256; matching exacto (IP, CIDR, dominio/hostname) con inicios de sesión 4624/4625, conexiones establecidas y activos, incremental por cursores y retroactivo por indicador; hashes/URLs/emails "unsupported". Triage con `version` y motivo, TI-001 solo por política (`high_confidence_malicious`), riesgo 4I fórmula v4 (multiplicador de explotabilidad de findings confirmados/probables y contribución de matches enlazada), incidentes manuales, IA con KEV/EPSS y matches como datos, auditoría y métricas sin IOCs. `threat_intel:read` (todos), `:triage` (analyst), `:manage` (admin). UI: Inteligencia (resumen, fuentes, indicadores, coincidencias, importar), detalle de indicador y de coincidencia, pestaña Inteligencia del finding, filtros KEV/EPSS, pestaña del activo y sección del incidente. CLI `threat-intel-import|sync|status`. Migración 0027. [threat-intelligence.md](threat-intelligence.md), [threat-intel-sources.md](threat-intel-sources.md), [stix-support.md](stix-support.md) |
| Producción y servidor central | Fase 4M: despliegue nativo (Linux/systemd de referencia, Windows Server con WinSW) detrás de Caddy (TLS, frontend estático, CSP, HSTS solo con certificado válido); `ENVIRONMENT=production` valida y se niega a arrancar inseguro (`core/production.py`, sin secretos en los mensajes) y exige HTTPS; `TRUSTED_PROXIES` con X-Forwarded-For/Proto solo desde proxies de confianza (`core/proxy.py`); redacción central de logs (`core/redaction.py`), logs JSON con `request_id` y rotación propia en Windows; `/health` (liveness) y `/health/ready` (base, migraciones, apagado; la IA no cuenta); `/metrics` Prometheus protegido; rate limiting compartido en PostgreSQL (`rate_limit_hits`, migración 0024) para login, registro, IA, mutaciones y búsquedas por usuario; jobs singleton con advisory locks y benchmark único entre workers; pool y `statement_timeout` configurables; `GET /dashboard/summary` y `/assets` paginado en SQL (estado efectivo, subred, orden por IP/puertos...); CLI `production-check`, `migration-status`, `generate-secret`, `backup`, `verify-backup`, `restore`, `integrity-check`. Plantillas en `deploy/`. [production-deployment.md](production-deployment.md), [network-security.md](network-security.md), [backup-restore.md](backup-restore.md), [observability.md](observability.md) |
| Agent distribution (Linux) | Done: reproducible tarball + `.deb` (`agent/packaging/linux/build.sh`), one-command installer with one-time token, systemd service as unprivileged `sentra-agent` with hardening, upgrade keeping identity, uninstall / purge. Pending: validation under a real systemd at boot |
| Agent distribution (Windows) | Fase 4F: zip reproducible con Python embebido oficial (`agent/packaging/windows/build.py`, firma PSF verificada), instalador PowerShell con token de un solo uso (aviso oculto o `-TokenFile`), servicio Windows estándar `SentraAgent` (inicio automático retrasado, recuperación ante fallos) con cuenta virtual `NT SERVICE\SentraAgent` + Event Log Readers (Security sin administrador), enrolamiento hecho por el propio servicio (DPAPI de su cuenta), upgrade sin re-enrolar, `-Reenroll`, desinstalación / `-Purge`; `installation_method` en el dashboard (migración 0016, tras la 0015 de la Fase 4E). Pendiente: validación en Windows físico (checklist en docs/agent-windows-installation.md) |
| Frontend (React, Vite) | Done: dashboard (counts, assets, active alerts, recent activity), asset detail with tabs Overview / Processes / Services / Software / Network / Users / Events / Alerts (search, filters, sort, pagination, change history), alerts page with filters and detail; Network page (discovered/monitored/managed, filters, discovery runs) and Exposure tab. Fase 4D: descubrimiento desde la página Red (iniciar, progreso real, cancelar, resultado, historial, estado del scheduler) sin terminal |
| Alerts | Done: offline, sustained high CPU/RAM, critical disk, watched service stopped, critical events, error bursts, administrator changes; new asset / unknown device / disappeared / port exposed / port closed / monitoring lost (discovery; first run is a quiet baseline); states open/acknowledged/resolved (ack/resolve desde el dashboard o la CLI), dedup, occurrences, auto-resolve |
| Tests | Backend 1221 (real PostgreSQL, incl. model/migration drift, indexed foreign keys, frontend type contract checks, autenticación/RBAC/CSRF/auditoría and real TCP discovery on loopback), agent 229 (+21 skipped on Linux) (3 Windows-only; Linux packaging tests run the real installer under a fake root); frontend 259 tests (Vitest, incl. DOM tests of the Agentes, Red e Incidentes pages with Testing Library + jsdom) + tsc + ESLint + build; `qa/e2e_api.py` 313 contract checks (incl. detección simple, correlación, deduplicación y resolución; riesgo: activo limpio → detección alta → correlación → criticidad → resolver; IA: estado, 409 sin configurar, alcance y permisos; incidentes: detección → caso → cerrado con auditoría, detección relacionada adjuntada sin duplicar y dos sesiones con 409; contexto de activo: admin fija el contexto, auditoría, riesgo e incidente con contexto, viewer sin edición y dos admins con 409); `qa/perf_detections.py`, `qa/perf_risk.py`, `qa/perf_ai.py`, `qa/perf_incidents.py` y `qa/perf_asset_context.py` miden los motores con datos sintéticos; `qa/e2e_production.py` (Fase 4M: Caddy real con TLS, IA caída, PostgreSQL caído y recuperado, dos workers) y `qa/perf_dashboard.py` (dashboard con 10 000 activos); `qa/perf_custom_rules.py` (Fase 5A: 1000 reglas activas y 100 000 señales en 66 s, ~1500 señales/s, índice en 288 ms); `qa/e2e_vulnerabilities.py` (Fase 5B: 37 comprobaciones en 5 escenarios) y `qa/perf_vulnerabilities.py` (10 000 activos, catálogo de 100 000 registros importado en 88 s, 50 000 findings evaluados a 46 activos/s, lecturas de 130-250 ms) |

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
- `system_events`: host log events; unique `(asset_id, channel, record_id)` makes resends idempotent. `data` (0018): campos estructurados de la lista permitida del agente.
- `ai_local_models`, `ai_model_benchmarks`, `ai_local_settings` (Fase 4J.2): modelos locales registrados (metadata GGUF, ruta, checksum), resultados de benchmark y fila única con runtime elegido y modelo activo.
- `ai_insights` (Fase 4J): análisis de IA validados con referencias de evidencia resueltas, huella de datos (`data_version`) para caché y stale, versión de prompt, modelo y métricas técnicas; sin prompts, contexto ni claves.
- `incidents` (número por `incident_number_seq`, estado, severidad/prioridad/confianza, responsable, resolución, duplicado/fusión, snapshot de riesgo, `version`), `incident_detections` / `incident_alerts` / `incident_assets` (FK SET NULL + referencia mínima, sin copiar evidencias), `incident_notes` (append-only), `incident_activity` (historial del caso), `incident_feedback` (falsos positivos); `ai_insights.incident_id`. Fase 4K.
- `asset_context` (rol, entorno, owner, departamento, sensibilidad, zona, exposición, justificación de la criticidad, procedencia JSONB, `version`), `asset_tags`, `asset_context_changes` (historial por campo); `incident_assets.context_snapshot` / `resolved_context_snapshot`. Fase 4L.
- `asset_risk` (riesgo actual por activo, contribuciones JSONB y cola `dirty_at`), `risk_snapshots` (historial en cambios materiales), `risk_contributions` (contribuciones por snapshot); `assets.criticality` (low/medium/high/critical, por defecto medium). Fase 4I.
- `detection_rules` (UID, origen, estado admin y de compilación, versión actual, `revision` para concurrencia optimista), `detection_rule_versions` (contenido inmutable por versión, YAML Sigma original), `detection_rule_stats` (contadores por regla), `detection_rule_matches` (coincidencias de reglas con umbral, purgadas con las señales); `detections.rule_source` y `rule_category` (Fase 5A, migración 0025).
- `vulnerability_sources` (procedencia y revisión de cada catálogo importado), `vulnerabilities` (registros; único source + id), `vulnerability_affected` (productos/paquetes/SO con claves normalizadas, índice GIN), `vulnerability_findings` (uno por activo + vulnerabilidad + componente; estado técnico, estado de trabajo, `version`, exposición, prioridad, evidencia), `vulnerability_finding_history`, `asset_vulnerability_state` (cola `dirty_at` y huella por activo), `incident_vulnerabilities`; `ai_insights.vulnerability_finding_id`. Fase 5B, migración 0026.
- `threat_intel_sources` (adapter, confianza, estado, ETag, revisión), `threat_intel_syncs` (historial de sincronizaciones e importaciones), `vulnerability_intel` (KEV/EPSS por fuente y CVE, activo/inactivo, valor EPSS anterior al último cambio material), `threat_indicators` (único fuente + tipo + valor normalizado, red CIDR con índice GiST, `pending_match`), `threat_intel_matches` (uno por indicador + activo + observación + valor; triage con `version`), `threat_intel_changes` (historial de cambios materiales), `threat_intel_cursors` (cursores del matching incremental), `incident_threat_matches`; `vulnerability_findings.intel_cve`, `incident_vulnerabilities.intel_snapshot`/`resolved_intel_snapshot`. Fase 5C, migración 0027.
- `detection_signals` (estado de correlación, se purga tras `DETECTION_SIGNAL_RETENTION_HOURS`), `detections` (índice único parcial = una activa por activo+regla+clave), `detection_evidence` (máx. 100 por detección), `detection_baselines` (línea base de ejecutables por activo). Fase 4H.

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
Health: `GET /health` (liveness) · `GET /health/ready` (readiness) · `GET /metrics` (Prometheus,
apagado por defecto). Read (dashboard): `GET /dashboard/summary` · `GET /assets` (paginado) · `GET /assets/{id}` ·
`GET /assets/{id}/telemetry` · `GET /assets/{id}/inventory` · `GET /assets/{id}/changes` ·
`GET /assets/{id}/processes` · `GET /alerts` · `GET /alerts/{id}` · `GET /events` ·
`GET /agents` · `GET /assets/{id}/agent` · `GET /detections` · `GET /detections/{id}` ·
`POST /detections/{id}/acknowledge|resolve` (detections:manage) ·
`/detection-rules` (Fase 5A: lista con filtros, `/catalog`, `/{id}`, versiones, diff, export,
`/sigma-source`, `/audit`; `POST /validate`, `/test`, `/sigma/preview` con rules:test;
crear, `PATCH`, enable/disable/retire/unretire, restore, `/test/historical`, `/sigma/import`
con rules:manage) ·
`/vulnerabilities` (Fase 5B: `/overview`, `/findings` con filtros y orden, `/findings/{id}` con
`/history` y `/audit`, `/exposure`, `/catalog`; acciones `acknowledge|mitigating|resolve|incident`
con vulnerabilities:manage y `accept-risk|false-positive|reopen`, `/catalog/preview|import`,
`/evaluate` con vulnerabilities:admin; `GET /assets/{id}/vulnerabilities`) ·
`/threat-intel` (Fase 5C: `/overview`, `/sources` con `/syncs`, `/indicators`, `/matches`, `GET /vulnerabilities/findings/{id}/threat-intel` con threat_intel:read; `acknowledge|dismiss|reopen|incident` de un match con threat_intel:triage; fuentes, `enable|disable|archive|sync`, `/import/preview|import`, `/reevaluate` con threat_intel:manage) ·
`GET /risk/overview` · `GET /risk/assets` · `GET /risk/assets/{id}` (`/history`, `/contributions`);
`PATCH /assets/{id}/criticality` (assets:manage, solo admin) ·
`GET /ai/status` · `GET /ai/insights` · `GET /ai/insights/{id}`; `POST /ai/ask`,
`/ai/assets/{id}/analyze`, `/ai/detections/{id}/analyze`, `/ai/risk/assets/{id}/analyze`,
`/ai/soc/analyze` (ai:use, Fase 4J) · `/ai/local/*` (gestor de modelos locales, Fase 4J.2: lectura con ai:use, cambios con ai:manage; docs/local-model-manager.md).
Console (local dashboard): `GET /console` · `GET|POST /console/enrollment-tokens` ·
`POST /console/enrollment-tokens/{id}/revoke` · `POST /console/agents/{id}/revoke|reinstate` ·
`POST /console/discovery/jobs` · `POST /console/discovery/jobs/{id}/cancel` (Fase 4D).
Operator CLI (`python -m app.cli`): `list-agents`, `revoke-agent`, `reinstate-agent`,
`ack-alert`, `resolve-alert`, `purge-old-data`, `discovery-scope`, `discover`, `run-detections`,
`run-risk [--all]`; Fase 4M: `production-check`, `migration-status`, `generate-secret`, `backup`,
`verify-backup`, `restore --target-db --confirm`, `integrity-check`.
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

- Fase 4M: HTTPS mediante Caddy (no integrado en la API). En desarrollo por HTTP en la LAN
  la contraseña y la cookie viajan en claro. Probado en Linux con Caddy real y `tls internal`;
  pendiente en Windows Server real y con un certificado de la CA interna de la empresa.
- Fase 4M: `AI_MAX_CONCURRENT` y los contadores de `/metrics` (HTTP, jobs, pool) son por
  proceso; con N workers el runtime de IA puede recibir N x AI_MAX_CONCURRENT peticiones.
- Fase 4M: la restauración necesita que un administrador de PostgreSQL cree antes la base
  vacía (el rol `sentra` no tiene CREATEDB). `pg_dump`/`pg_restore` deben ser de la versión
  del servidor o más nuevos.
- Reglas personalizadas (Fase 5A): solo los campos que Sentra recoge (sin línea de comandos,
  proceso padre, hashes ni texto de scripts); `process` solo ve ejecutables nuevos por
  snapshot; Linux no envía eventos. Sigma es un subconjunto (sin `base64*`, `cidr`, `near`,
  correlaciones ni agregaciones distintas de `count()`). Las estadísticas por regla se
  vuelcan al final de cada lote del motor. Una regla poco selectiva
  baja mucho el rendimiento del motor (cada coincidencia escribe). No probado aún con eventos
  reales del PC de desarrollo.
- Vulnerabilidades (Fase 5B): solo lo que inventarían los agentes (matriz en
  docs/vulnerability-catalog.md). En Linux los paquetes no pasan de `probable` porque el agente
  no informa la versión de la distribución (backports); en Windows el SO solo se confirma si
  el agente informa la revisión UBR. Sin catálogo de ejemplo real (KEV/EPSS de 5C solo enriquecen):
  hay que importar uno. No probado aún con inventario real del PC ni con un catálogo grande
  real.
- Threat Intelligence (Fase 5C): no validado aún contra los feeds reales de CISA y FIRST
  (formato vigente, ETag, proxy); solo con ficheros sintéticos y un espejo HTTP local. El
  matching de dominios solo compara con nombres de activos (Sentra no recoge DNS); hashes,
  URLs y emails no se casan. El cursor de eventos avanza por id: un evento confirmado fuera
  de orden puede saltarse en la vuelta incremental. `intel_cve` se rellena al migrar solo
  cuando el id del finding es un CVE (los alias, en la siguiente evaluación).
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
- Motor de detección (Fase 4H): Linux no envía eventos (solo detecciones de inventario,
  procesos y exposición); sin líneas de comando no hay detección de PowerShell codificado;
  no se recogen tareas programadas (4698) ni el canal del firewall. El job evalúa unas 140
  señales/s en el peor caso medido; la búsqueda de texto en detecciones recorre la tabla
  (380 ms con 52 000). Pendiente validar en Windows real la consulta de 4624, los campos de
  Defender y los `EventData`. Desplegar el servidor antes que los agentes 4H.
- Risk Engine (Fase 4I): la exposición solo cuenta puertos sensibles vistos por discovery (sin
  datos de vulnerabilidades); Linux tiene como mucho confianza parcial (no envía eventos); la
  criticidad es manual (todo `medium` hasta que un admin la cambie); la primera evaluación
  tras desplegar no alerta. Pesos calibrados con escenarios sintéticos: revisar con datos
  reales. Primera evaluación de 1000 activos en ~9 s (docs/risk-engine.md).
- AI Security Insights (Fase 4J): rate limit y concurrencia en memoria por proceso; la
  redacción del texto libre es por valores conocidos y patrones (IPv4, rutas); Ask reconoce
  activos por nombre exacto; los insights no tienen retención automática; la calidad del texto
  depende del modelo (la validación garantiza formato y referencias, no el acierto). No
  probado todavía con un modelo real en el PC de desarrollo (solo FakeAIProvider y servidor
  HTTP local de pruebas).
- Gestor de modelos locales (Fase 4J.2): las cifras de memoria son estimaciones (el overhead
  real depende del runtime y del backend de GPU); VRAM de AMD/Intel en Windows sale del
  registro y puede faltar; el pico de memoria del benchmark es del sistema, no del proceso;
  Sentra no arranca llama-server ni vLLM (cambiar de modelo ahí exige reiniciarlos con `-m`);
  hardware, snapshot del runtime y cola de benchmark son en memoria por proceso. No probado
  aún con runtimes reales en el PC de desarrollo (solo servidores falsos en loopback).
- Incidentes (Fase 4K): sin SLA/MTTR, playbooks ni respuesta automática (decisión); el
  feedback de falsos positivos solo se guarda; la búsqueda de texto usa `ILIKE` sobre el
  título (67-86 ms con 10 000 casos; pg_trgm si crece); una detección puede adjuntarse a mano
  a dos casos activos (la promoción lo impide); sondeo cada 15 s, sin tiempo real.
- Asset Context (Fase 4L): sin edición masiva; owner y departamento son texto libre (sin
  directorio); el dashboard aún pide la lista completa de activos (~1,5 s con 10 000; la API
  ya pagina con `limit`/`offset` en 20-30 ms); los pesos de contexto son iniciales.
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
- Detección (Fase 4H): reglas en código y textos por plantilla (sin IA ni APIs externas);
  la petición del agente solo escribe señales en un SAVEPOINT y un job evalúa las reglas,
  cada una aislada en su SAVEPOINT; Detección = conclusión, Alerta = notificación (solo
  severidad ≥ umbral); `GET /detection-rules` legible por cualquier rol (lo usa el filtro de
  la UI); el agente envía solo campos de una lista permitida y nunca el texto de scripts.
- Riesgo (Fase 4I): cálculo puro y determinista (`app/risk/calculator.py`) separado de la
  persistencia (`engine.py`), de la explicación (`explain.py`) y de la API; pesos en
  `app/risk/config.py` con `FORMULA_VERSION` en cada cálculo; cola en `asset_risk.dirty_at`
  con `FOR UPDATE SKIP LOCKED` y un savepoint por activo, sin Redis ni Celery; reconocida no
  es mitigada; criticidad como modificador multiplicativo acotado que nunca crea riesgo.
- IA (Fase 4J): interpretación, nunca decisión; el modelo no define severidad ni riesgo, no
  consulta la base de datos, no tiene herramientas ni ejecuta acciones. Un único protocolo
  (chat OpenAI-compatible) por stdlib en vez de SDKs por proveedor; local/externo por URL sin
  resolver DNS; insights persistidos (auditables, caché tras reinicios, stale por huella) en
  vez de caché en memoria; `ai:use` separado de `monitoring:read` para poder retirarlo por rol.
- Gestor de modelos locales (Fase 4J.2): runtime (`LocalAIRuntime`) separado del proveedor
  de análisis (`AIProvider`), reutilizando su cliente y su política de destinos; Sentra nunca
  lanza procesos del runtime; recomendación determinista sin LLM, la medición del benchmark
  pesa más que la estimación; sin descargas (solo diseño documentado); quitar registro nunca
  borra el fichero; el modelo activo sustituye a `AI_MODEL` solo con destino local.
- Incidentes (Fase 4K): relaciones por referencia (FK SET NULL + mínimo copiado) en vez de
  copiar evidencias; numeración por secuencia de PostgreSQL; concurrencia optimista con
  `version` y `SELECT … FOR UPDATE` (notas y adjuntos no cambian la versión); la fusión copia
  relaciones y el caso principal ve notas/actividad/insights de los absorbidos por CTE
  recursiva; duplicado es solo una referencia; la IA nunca cambia el caso.
- Asset Context (Fase 4L): tablas asociadas a `assets` en vez de columnas o una tabla de
  dispositivos; el rol inferido se calcula al leer y nunca se guarda (no puede pisar al
  admin); edición solo admin porque varios campos alimentan el riesgo; el contexto multiplica
  la evidencia con tope y nunca suma puntos fijos; owner/departamento siempre seudonimizados
  hacia proveedores de IA no locales.
- Reglas personalizadas (Fase 5A): formato declarativo propio (nunca código, SQL ni
  plantillas) y Sigma traducido a ese formato en vez de ejecutarlo; las reglas son objetos
  del mismo motor 4H; la base de datos es la fuente de verdad (huella por lote, sin Redis);
  una regla que falla no se desactiva sola; métricas por origen, nunca por regla; las
  importaciones Sigma entran en borrador y las no soportadas no se pueden activar.
- Vulnerabilidades (Fase 5B): catálogo local importado por un admin (offline-first, sin
  descargas); solo coincidencias exactas declaradas en el catálogo (sin fuzzy matching); un
  puerto abierto nunca es evidencia; el estado técnico y el de trabajo van separados; las
  potenciales nunca cuentan como confirmadas ni alertan; los incidentes se crean a mano; la
  vulnerabilidad entra en el riesgo 4I como señal agrupada con la exposición de su puerto.
- Threat Intelligence (Fase 5C): la inteligencia es contexto externo, nunca prueba de
  compromiso (vocabulario fijado y vigilado por un test); offline-first con red apagada por
  defecto y URLs solo en la configuración del servidor; procedencia por dato y conflictos
  visibles en vez de elegir una fuente; solo coincidencia exacta; una importación local no
  desactiva lo ausente; TI-001 solo por política; incidentes siempre manuales; EPSS sin
  historial diario (solo cambios materiales).
- Agent uses stdlib + psutil + built-in `wevtutil.exe` (no pywin32).
- Inventory as JSONB snapshot; normalize a section when SQL queries over it are needed.
- Retention opt-in and per data type (`services/retention_service.py`): batches of 5000 rows,
  each committed on its own, found through existing indexes. Only resolved alerts are
  purged. Every foreign key has an index (enforced by a test): without
  `ix_alerts_source_event` a 5000-event batch took 51 s with 100k alerts, 0.3 s with it. An asset silent for longer than the telemetry retention loses its last sample, so
  the dashboard shows its metrics as "—". On-demand: `python -m app.cli purge-old-data`.

## Recommended next phase

Fase 5C (Threat Intelligence) entregada: importar los ficheros reales de KEV y EPSS por la
CLI (o activar la sincronización con Internet o un espejo), revisar los findings con KEV/EPSS
y la prioridad, importar unos IOCs de prueba y comprobar los matches con inicios de sesión y
conexiones reales del PC, y medir con `qa/perf_threat_intel.py` en el hardware del servidor.

Fase 5B (vulnerabilidades y exposición) entregada: importar un catálogo pequeño con
productos reales del PC (ver docs/vulnerability-catalog.md), revisar los findings, sus
estados técnicos y la prioridad con inventario real Windows y Linux, y medir con
`qa/perf_vulnerabilities.py` en el hardware del servidor.

Fase 5A (reglas personalizadas y Sigma) entregada: escribir y probar reglas con eventos
reales del PC (prueba histórica antes de activar), importar unas pocas reglas Sigma de
`windows/builtin/security` y revisar cuáles quedan soportadas.

Fase 4M (producción y servidor central) entregada: desplegar en un servidor de prueba con
Caddy y la CA interna, ejecutar `production-check`, programar copias y hacer una restauración
de prueba; validar la CSP con el dashboard real y los agentes Windows/Linux por HTTPS.

Fase 4L (Asset Context) entregada. Antes de la siguiente fase, probar 4K/4L con datos
reales en el PC (contexto de servidores reales, flujo detección → incidente → cierre con
varios operadores) y la 4J/4J.2 con un runtime y modelo local reales; revisar los pesos del
riesgo y del contexto con datos reales.

1. Validación física de la Fase 4F (servicio Windows) y de la 4M en Windows Server.
2. Per-asset alert thresholds.
4. Downsampling for old telemetry (retention exists, opt-in); journald events on Linux
   (systemd services and dpkg/rpm packages are collected already).
