# Referencia de la API v1

Tabla que antes estaba en el README (movida en la Fase 7A sin cambios de contenido). La
referencia completa y actualizada es el OpenAPI que publica el servidor en `/docs` (solo fuera
de producción) y los documentos de cada módulo en `docs/`. Endpoints añadidos en 7A:
[compatibility-matrix.md](compatibility-matrix.md). Endpoints añadidos en 7B: tabla al final.

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Liveness: `{"status":"ok"}` sin tocar la base (Fase 4M) |
| GET | `/api/v1/health/ready` | Readiness: base, migraciones y apagado; 503 si no está lista. Sin versiones ni hosts |
| GET | `/api/v1/dashboard/summary` | Agregados del dashboard en SQL (activos por estado/método/tipo, riesgo, incidentes, detecciones, alertas) |
| GET | `/api/v1/metrics` | Prometheus; 404 salvo `METRICS_ENABLED` y red autorizada, token opcional ([docs/observability.md](observability.md)) |
| POST | `/api/v1/agents/register` | Enroll an agent (`X-Enrollment-Token` one-time token, or legacy `X-Enrollment-Key`); returns its token once |
| POST | `/api/v1/agent-enrollment-tokens` | **Admin** (`X-Admin-Key`): create a one-time enrollment token (shown once) |
| GET | `/api/v1/agent-enrollment-tokens` | **Admin**: list tokens and their state (never the token) |
| POST | `/api/v1/agent-enrollment-tokens/{id}/revoke` | **Admin**: revoke an unused token |
| POST | `/api/v1/agents/heartbeat` | Mark an agent alive (Bearer token) |
| GET | `/api/v1/agents` | Enrolled agents with state, credential status and summary (no secrets) |
| GET | `/api/v1/assets/{asset_id}/agent` | The asset's agent and credential status |
| GET/POST | `/api/v1/console/...` | **Dashboard console** (sesión, solo rol admin): enrollment tokens, revoke/reinstate agents ([docs/agent-management.md](agent-management.md)) |
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
| GET | `/api/v1/events?asset_id=&min_level=&channel=&event_code=&provider=&event_type=&q=&limit=&offset=` | Events, newest first (`has_more` instead of a total); Linux events have `event_code: null` and an `event_type` (Fase 5C.1, [docs/linux-events.md](linux-events.md)) |
| GET | `/api/v1/assets/duplicates`, `/api/v1/assets/{asset_id}/duplicate-candidates` | Posibles duplicados con razones y confianza (Fase 5C.1, `assets:duplicates_read`: analyst y admin) |
| GET | `/api/v1/assets/{asset_id}/delete-check` | ¿Se puede borrar? Motivos y dependencias (admin) |
| POST | `/api/v1/assets/{asset_id}/archive` `{reason, version}`, `/restore` `{version}` | Archivar / restaurar un activo (admin; archivar exige revocar antes su agente; restaurar no reactiva la credencial) |
| DELETE | `/api/v1/assets/{asset_id}?version=` | Borrar un activo descubierto sin historial (admin; 409 `asset_not_deletable` si tiene historial) |
| POST | `/api/v1/assets/{asset_id}/reconcile` `{target_asset_id, version, target_version}` | Reasignar el agente nuevo a un activo histórico de la misma máquina (admin, validado por el servidor) ([docs/agent-asset-lifecycle.md](agent-asset-lifecycle.md)) |
| GET | `/api/v1/assets?method=&status=&device_type=&subnet=&q=&criticality=&role=&environment=&network_zone=&data_sensitivity=&internet_exposed=&department=&tag=&sort=&limit=&offset=` | (filters, all optional) agent and discovered assets; filtros de contexto, orden por criticidad y paginación opcional (Fase 4L) |
| GET/PATCH | `/api/v1/assets/{asset_id}/context`, GET `/{asset_id}/context/history`, `/assets/context/options` | Asset Context (Fase 4L): rol, entorno, owner, equipo, sensibilidad, zona, exposición a Internet y tags con procedencia; PATCH solo admin (`assets:manage`), `version` obligatoria y 409 `asset_context_conflict`: [docs/asset-context.md](asset-context.md) |
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
| POST | `/api/v1/sigma/preview`, `/sigma/import` | Vista previa (`rules:test`) e importación Sigma (`rules:manage`; siempre desactivada) ([docs/sigma-support.md](sigma-support.md)) |
| GET | `/api/v1/vulnerabilities/overview`, `/vulnerabilities/findings?status=&active=&severity=&match_state=&confidence=&exposure=&asset_id=&vulnerability_id=&source=&stale=&q=&sort=&order=&limit=&offset=`, `/findings/{id}` (`/history`, `/audit`), `/vulnerabilities/exposure`, `/vulnerabilities/catalog`, `/assets/{id}/vulnerabilities` | Vulnerabilidades y exposición (Fase 5B, `vulnerabilities:read`): [docs/vulnerability-management.md](vulnerability-management.md) |
| POST | `/api/v1/vulnerabilities/findings/{id}/acknowledge\|mitigating\|resolve\|incident` (`vulnerabilities:manage`), `/accept-risk\|false-positive\|reopen`, `/vulnerabilities/catalog/preview\|import`, `/vulnerabilities/evaluate` (`vulnerabilities:admin`) | Flujo de trabajo (`version` obligatoria, 409 `vulnerability_conflict`), catálogo local con previsualización y reevaluación |
| GET | `/api/v1/threat-intel/overview`, `/threat-intel/sources` (`/{id}/syncs`), `/threat-intel/indicators?type=&classification=&confidence=&source_id=&state=&matched=&tag=&q=`, `/indicators/{id}`, `/threat-intel/matches?status=&active=&classification=&observation_type=&asset_id=&source_id=`, `/matches/{id}`, `/vulnerabilities/findings/{id}/threat-intel` | Threat Intelligence (Fase 5C, `threat_intel:read`): KEV/EPSS con procedencia, indicadores y coincidencias con datos locales ([docs/threat-intelligence.md](threat-intelligence.md)) |
| POST | `/api/v1/threat-intel/matches/{id}/acknowledge\|dismiss\|reopen\|incident` (`threat_intel:triage`), `/threat-intel/sources` (`/{id}/enable\|disable\|archive\|sync`), `/threat-intel/import/preview\|import`, `/threat-intel/reevaluate` (`threat_intel:manage`) | Triage con `version` (409 `threat_intel_conflict`, motivo obligatorio al descartar), fuentes sin URLs desde el navegador, importación con previsualización y sha256 |
| GET | `/api/v1/risk/overview` | Riesgo (Fase 4I): activos por nivel y confianza, factores principales, transiciones recientes |
| GET | `/api/v1/risk/assets?level=&confidence=&device_type=&status=&criticality=&min_score=&q=&sort=&order=&limit=&offset=` | Activos por riesgo, el más alto primero |
| GET | `/api/v1/risk/assets/{asset_id}`, `/history?range=24h\|7d\|30d`, `/contributions?snapshot_id=` | Detalle explicable, tendencia y contribuciones |
| GET | `/api/v1/ai/status` | AI Security Insights (Fase 4J): si la IA está disponible y con qué modelo (sin URL ni clave) |
| GET/POST/PATCH | `/api/v1/ai/local/hardware`, `/runtime`, `/models`, `/recommendations`, `/settings`, `/models/{id}/select\|benchmark\|unregister`… | Gestor de modelos locales (Fase 4J.2): hardware, runtime, modelos GGUF, recomendaciones y benchmark (lectura `ai:use`, cambios solo admin `ai:manage`): [docs/local-model-manager.md](local-model-manager.md) |
| POST | `/api/v1/ai/assets/{asset_id}/analyze`, `/ai/detections/{detection_id}/analyze`, `/ai/risk/assets/{asset_id}/analyze`, `/ai/soc/analyze`, `/ai/ask` | Análisis de IA bajo demanda, grounded en datos de Sentra (`ai:use` + `monitoring:read`; rate limited) |
| GET | `/api/v1/ai/insights?kind=&asset_id=&detection_id=`, `/ai/insights/{insight_id}` | Historial de análisis con estado actual/desactualizado |
| GET | `/api/v1/incidents?status=&active=&severity=&priority=&owner=&asset_id=&since=&until=&q=&sort=&order=&limit=&offset=`, `/incidents/overview`, `/incidents/{id}`, `/{id}/timeline?cursor=`, `/{id}/evidence`, `/{id}/notes`, `/{id}/audit` | Gestión de incidentes (Fase 4K, `incidents:read`): listado, vista SOC, detalle, timeline unificado por cursor, evidencia agrupada y auditoría del caso: [docs/incident-management.md](incident-management.md) |
| POST/PATCH | `/api/v1/incidents`, `/detections/{id}/incident`, `/alerts/{id}/incident`, `PATCH /incidents/{id}`, `/{id}/assign\|unassign\|notes\|resolve`, `/{id}/detections/{did}`, `/{id}/alerts/{aid}`, `/{id}/assets/{asset_id}` | Crear, promover, trabajar y resolver incidentes (`incidents:manage`, analyst y admin; `version` obligatoria, 409 `incident_conflict` si otro operador lo cambió) |
| POST | `/api/v1/incidents/{id}/close`, `/reopen`, `/merge` | Cerrar, reabrir y fusionar (solo admin, `incidents:admin`) |
| POST | `/api/v1/ai/incidents/{incident_id}/analyze` | IA de solo lectura sobre un incidente (`summary`, `timeline`, `evidence`, `next_steps`); nunca cambia el caso |
| PATCH | `/api/v1/assets/{asset_id}/criticality` | Criticidad del activo (solo admin, `assets:manage`; auditado) |
| POST | `/api/v1/auth/login`, `/auth/logout`; GET `/auth/me` | Sesión del dashboard (cookie HttpOnly + `X-CSRF-Token` en mutaciones). Todos los GET del dashboard requieren sesión; usuarios, auditoría y acciones por rol: [docs/authentication.md](authentication.md) |

Las alertas se reconocen o resuelven desde el dashboard (roles admin y analyst) o con
`python -m app.cli ack-alert <id>` / `resolve-alert <id>`.
Network discovery se lanza desde la página **Red → Iniciar descubrimiento** (roles admin y
analyst, desde cualquier equipo de la LAN con sesión), de forma periódica
con `DISCOVERY_INTERVAL_MINUTES`, o con `python -m app.cli discover` como herramienta
administrativa: [docs/discovery.md](discovery.md).

Payloads and error format: [docs/agent-protocol.md](agent-protocol.md). Interactive docs at
`/docs` in development.

## Fase 7B (server 0.5.0)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/maintenance-operations?asset_id=&status=&limit=&offset=` | Operaciones de mantenimiento autorizadas (`monitoring:read`) ([detection-attribution.md](detection-attribution.md)) |
| GET | `/api/v1/maintenance-operations/reference-artifacts` | SHA-256 de los scripts que distribuye este servidor (`maintenance:manage`) |
| GET | `/api/v1/maintenance-operations/{id}` | Detalle de una operación |
| POST | `/api/v1/maintenance-operations` | Registrar una operación (nace `pending_review`; `maintenance:manage`, solo admin) |
| POST | `/api/v1/maintenance-operations/{id}/approve` `{note}`, `/revoke` `{reason}` | Aprobar o revocar (admin) |
| POST | `/api/v1/maintenance-operations/{id}/preview`, `/apply` `{confirm: true}` | Recálculo controlado de las detecciones existentes de su ventana (admin) |
| GET | `/api/v1/detections/{id}/attribution` | Veredicto de atribución, comprobaciones e historial |
| POST | `/api/v1/detections/{id}/attribution/evaluate` | Reevaluar (`detections:manage`) |
| POST | `/api/v1/detections/{id}/attribution/verdict` `{verdict, reason}` | Veredicto del analista; nunca `verified_benign` (`detections:manage`) |
| GET | `/api/v1/assets/{id}/identity/profile` | Identidad por niveles con procedencia ([device-identity-wifi.md](device-identity-wifi.md)) |
| GET | `/api/v1/assets/{id}/identity/candidates` | Posibles coincidencias con evidencia (sin fusión automática) |
| GET | `/api/v1/identity/compare?left=&right=` | Clasifica dos registros (reinstalación, histórico, reutilización de IP...) |
| GET | `/api/v1/identity/links?asset_id=&wlan_client_id=&active=` | Asociaciones manuales |
| POST | `/api/v1/identity/links/preview`, `/api/v1/identity/links` `{..., reason, confirm: true}` | Vista previa y asociación manual (`identity:manage`, solo admin) |
| POST | `/api/v1/identity/links/{id}/revoke` `{reason}` | Deshacer una asociación (admin) |
| GET | `/api/v1/network/wlan/clients/{id}`, `/observations` | Ficha e historial de un cliente Wi-Fi |
| GET | `/api/v1/search?q=&site_id=` | Búsqueda de la Analyst Console ([analyst-console.md](analyst-console.md)) |

Cambios aditivos: `GET /assets` acepta `sort=risk` y devuelve `identity_state` y
`mac_randomized`; las detecciones devuelven `attribution_verdict`; el riesgo devuelve
`breakdown.components` y `breakdown.reductions` (fórmula v6, [risk-attribution.md](risk-attribution.md)).

### Fase 7B-Fix1

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/detections/correlation-review/preview` `{asset_id?}` | Reevalúa las CORR-002 abiertas anteriores a la v5 con la evidencia guardada: `causal`, `temporal_only` o `insufficient_evidence` (`detections:manage`) ([fase-7b-fix1.md](fase-7b-fix1.md)) |
| POST | `/api/v1/detections/correlation-review/apply` `{detection_ids, note?, confirm: true}` | Anota la revisión y resuelve solo las `temporal_only` sin actuación del analista; pide el recálculo del riesgo y audita `correlation_review_applied` (`detections:manage`) |

Cambios aditivos: el perfil de identidad devuelve `model`, `assigned_name` y `missing`
(`[{field, code, detail}]`); `GET /topology/graph` devuelve `coverage` (nodos sin enlace,
enlaces por tipo, limitaciones); los candidatos y pares de duplicados devuelven `hypothesis`;
el riesgo devuelve `breakdown.by_class` y, por aportación, `risk_class`, `absorbed_reason` y,
en exposición, `reachability`, `listen_scope` y `missing` (fórmula v7); los cambios de
servicio pueden ser `image_changed`; las detecciones PER-001 y CORR-002 incluyen
`classification` y `causal_links`.
