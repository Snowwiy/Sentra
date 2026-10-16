# Sentra development status

Handoff document: enough to continue the project without prior conversation context.
Last updated: 2026-10-16 (Fase 6B fix 3).

## Current state

MVP working end to end on the developer's Windows PC with real data:
PC → Sentra Agent → API → PostgreSQL → Web (verified in the browser, including an API
outage during which the agent buffered samples and delivered them on reconnection).

| Component | State |
|-----------|-------|
| Backend API (FastAPI) | Done: agents (enrollment with one-time tokens or legacy shared key + per-agent tokens; admin API for enrollment tokens behind ADMIN_API_KEY), assets, telemetry + history, inventory + change detection, process snapshots, events (filters), alerts (lifecycle, filters, detail), retention, health; hybrid monitoring: agentless network discovery (allowlisted networks only), exposed ports with baseline, agent/discovery reconciliation, exposure correlation |
| Database (PostgreSQL 18 native, Alembic) | Done: migrations 0001–0034 |
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
| Ciclo de vida de activos y eventos Linux | Fase 5C.1: credencial del agente, activo y historial separados. Archivar (admin, motivo, oculto por defecto, fuera del resumen y del riesgo actual, restaurable sin reactivar la credencial; exige revocar antes), borrar solo descubiertos sin historial (delete-check con motivos, recomprobado con la fila bloqueada), duplicados con confianza alta/media/baja (identidad de máquina con hash por aplicación, hostname+MAC/IP; nunca solo hostname o solo IP), reconciliar = reasignar el agente nuevo al activo histórico (admin, validado por el servidor). Concurrencia con `lifecycle_version`. Agente Linux 0.2.1: journald acotado (sshd, sudo con saneado de secretos, cuentas/grupos, systemd, kernel, auditd opcional) por `journalctl` sin shell, cursor por fuente, cobertura informada (`no_permission` ≠ 0 eventos), grupo `systemd-journal`; reglas LIN-AUTH-001/002 y LIN-SYS-001, ACCT y SYS-002 con Linux; riesgo con cobertura Linux. Empaquetado sin CRLF (`.gitattributes` y build). Migración 0028. [agent-asset-lifecycle.md](agent-asset-lifecycle.md), [linux-events.md](linux-events.md) |
| Limpieza y reconciliación segura (Fase 5C.2) | Stale según el origen: un descubierto solo es stale con N scans completos y exitosos que cubrían su red sin verlo (fallidos, cancelados, parciales, direcciones con error de sondeo o discovery parado no cuentan) y un tiempo mínimo; gestionados (alguna vez con agente) y monitorizados nunca se borran automáticamente. Estados derivados (active/offline/stale/cleanup_candidate/archived), sin columnas nuevas en `assets`. Una única puerta de borrado físico (`hard_delete_decision`) que usan el preview, el ejecutor manual, la limpieza automática y DELETE, recomprobada con la fila bloqueada. Preview y ejecución de limpieza por lotes (KEEP/MARK_STALE/ARCHIVE_CANDIDATE/HARD_DELETE_ELIGIBLE/BLOCKED), con savepoint por activo. Limpieza automática opt-in (`ASSET_AUTO_CLEANUP=false`), solo descubiertos elegibles. Duplicados con evidencia, fuerza y confianza (IP, hostname o IP+hostname solos = baja y nunca automático); reconciliar con evidencia débil exige `acknowledge_weak_evidence`. Reconciliación transaccional con preview, linaje de agentes (`asset_agent_lineage`), disposición explícita del origen (archivado/borrado) y auditoría `agent_reassigned`. Heartbeat durante una reconciliación → 409 y reintento. UI: página Ciclo de vida (admin) y asistente de reconciliación en 6 pasos. Migración 0029. [agent-asset-lifecycle.md](agent-asset-lifecycle.md) |
| Response Engine y Playbooks (Fase 5D) | Motor único (`services/response_service.py`) para acciones estructuradas de un catálogo cerrado (`app/response/catalog.py`): 5 de agente (inventario, procesos, eventos, telemetría, diagnóstico) y 10 de servidor (riesgo, detecciones, contexto de amenaza, vulnerabilidades, discovery, timeline, bundle de evidencia, abrir incidente, nota, archivar); `isolate_host`, `kill_process` y `block_network_address` solo como `not_implemented` sin handler. Sin shell ni campos de comando. Política única (`policy.evaluate`) para preview, ejecución y cada paso de playbook; riesgo LOW/MEDIUM/HIGH/CRITICAL, MEDIUM+ exige `response:manage` y confirmación. Idempotencia por clave y dedupe de vivas por índice único. Cola de comandos tipados con TTL, lease, una reentrega para acciones idempotentes, aviso por heartbeat (`pending_commands`), poll y resultado con el token del agente, sin acceso entre activos, resultados duplicados/tardíos/falsificados rechazados; capacidades declaradas por el agente; agente offline → `blocked` (o `queued` con TTL); linaje 5C.2 respetado. Playbooks declarativos versionados (3 built-in), fail-stop, copia inmutable de los pasos por run. Solo manual. Resultados saneados y acotados (`RESPONSE_RESULT_MAX_KB`), auditoría `response_*`/`playbook_*` sin secretos ni texto de parámetros, timeline del incidente. `response:read` (todos), `:execute` (analyst), `:manage` (admin). Registro cerrado de herramientas para la futura Analyst Console. Agente 0.3.0. UI: Response, Playbooks, pestaña Response del activo, "Investigar" en incidente y detección. Migración 0030. [response-engine.md](response-engine.md), [playbooks.md](playbooks.md), [agent-response.md](agent-response.md) |
| Reporting y evidencias (Fase 5E) | Catálogo cerrado de 9 tipos (`app/reports/catalog.py`): resumen ejecutivo, técnico, incidente, activo, vulnerabilidades, riesgo, detecciones, actividad de Response y ciclo de vida/cambios. Formatos HTML autocontenido (CSP, sin scripts), PDF con escritor propio (sin dependencias ni Internet), CSV con fórmulas neutralizadas y paquete de evidencia ZIP con manifest y SHA-256. Snapshot en una transacción REPEATABLE READ de solo lectura (hora de corte común), guardado con su SHA-256 y renderizado solo desde el snapshot (determinista). Trabajos persistentes (`reports`, `report_artifacts`) con idempotencia, dedupe de vivas, colas acotadas, lease y recuperación de huérfanos, cancelación segura con lock de fila, plazo y límite de tamaño. Almacenamiento en `REPORT_OUTPUT_DIR` fuera del repo, escritura atómica, claves validadas, descarga solo por id con verificación de SHA-256. Retención opt-in (sin valor: se conserva todo). `reports:read` (todos), `:generate` (analyst), `:admin` (admin); permisos de dominio por tipo; 404 sin IDOR. Redacción de credenciales, auditoría `report_*` sin secretos, resumen determinista sin IA, herramientas cerradas para la Analyst Console. UI: Informes (catálogo, preview, generar, historial, detalle, descarga) y botones en Incidente, Activo, Detección y Response. Migración 0031. [reporting.md](reporting.md), [report-security.md](report-security.md), [report-storage.md](report-storage.md) |
| Multi-site y sensores distribuidos (Fase 5F) | Sites (ubicaciones, no tenants) con redes autorizadas; solapamiento de CIDR permitido entre sites y prohibido dentro de uno. Site por defecto `Local` con todos los datos anteriores (`sentra_default_site_id()` como valor por defecto de `assets.site_id` y `discovery_jobs.site_id`). Identidad de activo descubierto = site + IP; reconciliación y duplicados nunca cruzan sites; mover un activo es acción explícita de admin. Sensor distribuido (`sensor/`, stdlib, Linux systemd y servicio Windows) con conexiones solo salientes HTTPS, enrolamiento con token de un solo uso, credencial Bearer con hash en servidor, rotación en dos fases, revocar/deshabilitar. Jobs de catálogo cerrado (`discovery_basic`) dirigidos a un sensor, con lease, intentos, caducidad, recuperación y cancelación; resultados en lotes idempotentes por `batch_id`, validados (alcance, hora, tamaños) e ingeridos por el `ResultApplier` del servidor restringido al site; lotes perdidos = resultado parcial sin conclusiones negativas. Spool SQLite acotado en el sensor (offline, sin duplicados al reconectar). Filtro `site_id` en dashboard, activos, agentes, alertas, detecciones, incidentes, findings, riesgo, Response, discovery e informes. UI: Sites, Sensores, selector global de site y discovery remoto. `sites:manage` y `sensors:manage` solo admin. Migración 0032. [sites.md](sites.md), [distributed-sensors.md](distributed-sensors.md), [sensor-security.md](sensor-security.md), [sensor-deployment.md](sensor-deployment.md) |
| Advanced Network Discovery (Fase 6A) | Perfiles `quick`, `standard` (por defecto) y `deep` sobre el mismo motor: ICMP del sistema, TCP connect, tabla ARP, DNS inverso y confirmación directa (solo compara direcciones). Sin SYN, raw sockets, privilegios, banners ni fingerprinting. Límites en servidor (DISCOVERY_* + topes fijos) y en el sensor (revalida con los topes del heartbeat); reintentos solo de puertos sin respuesta en hosts vivos; presupuesto de consultas DNS; alcance y `max_hosts` por job. Ajustes de puertos y límites solo con `discovery:tune` (admin). Job de sensor `discovery_advanced` versionado con capability `network.discovery.advanced` (sensor 0.2.0); los sensores 0.1.x siguen con `discovery_basic`. Evidencia por job y dirección en `discovery_observations` (observed/inferred/unknown, confianza, RTT, cambios frente a la observación anterior); sin conclusiones negativas en scans parciales. `GET /discovery/profiles`, `GET /discovery/observations` (filtros y paginación en servidor). UI: perfil en el modal, observaciones en la vista del job y pestaña «Observaciones de red». Migración 0033. [advanced-network-discovery.md](advanced-network-discovery.md) |
| SNMP, LLDP, CDP y switches (Fase 6B) | Inventario SNMP de solo lectura de equipos de red registrados por un admin, ejecutado siempre por un sensor 0.3.0 del site del equipo (job `snmp_inventory` con nombres de módulo, nunca OIDs; catálogo cerrado en el sensor, sin SET). SNMPv3 authPriv (SHA-1/SHA-2 + AES) como opción principal; SNMPv2c solo con `SNMP_ALLOW_V2C=true`; sin SNMPv1. Perfiles de credenciales por site cifrados con AES-256-GCM (fichero de claves `SNMP_CREDENTIAL_KEY_FILE`, AAD perfil+site), secretos de solo escritura entregados solo en el start del job; rotación (cancela consultas abiertas), revocación, rotación de clave maestra (`snmp-keygen --add`, `snmp-rekey`). Módulos SNMPv2-MIB, ENTITY-MIB, IF-MIB (con ifStack para LAG), LLDP-MIB, CISCO-CDP-MIB, BRIDGE-MIB y Q-BRIDGE-MIB con límites de varbinds, filas, plazo y cancelación; registros en staging aplicados al cerrar. Clasificación switch/router/AP/cortafuegos con confianza y evidencias (nunca por puertos TCP ni sysDescr). Vecinos con procedencia y valoración `reported_by_device`, sin enlaces inferidos. MACs con VLAN y ubicación (`edge_candidate`, `uplink_or_shared`, `unknown`; nunca confirmada) y búsqueda por MAC sin fusionar sites. Estado y frescura derivados al leer (un equipo con evidencia antigua nunca se muestra online). Consulta manual o periódica opt-in (`SNMP_POLL_INTERVAL_MINUTES`); sin credencial = configuración pendiente. `network:poll` (analyst), `network:manage` y `snmp_credentials:manage` (admin). UI: Infraestructura (equipos, candidatos de 6A, perfiles, búsqueda de MAC) y detalle con interfaces, vecinos, VLANs, MACs e historial. Migración 0034. [snmp-network-intelligence.md](snmp-network-intelligence.md) |
| Producción y servidor central | Fase 4M: despliegue nativo (Linux/systemd de referencia, Windows Server con WinSW) detrás de Caddy (TLS, frontend estático, CSP, HSTS solo con certificado válido); `ENVIRONMENT=production` valida y se niega a arrancar inseguro (`core/production.py`, sin secretos en los mensajes) y exige HTTPS; `TRUSTED_PROXIES` con X-Forwarded-For/Proto solo desde proxies de confianza (`core/proxy.py`); redacción central de logs (`core/redaction.py`), logs JSON con `request_id` y rotación propia en Windows; `/health` (liveness) y `/health/ready` (base, migraciones, apagado; la IA no cuenta); `/metrics` Prometheus protegido; rate limiting compartido en PostgreSQL (`rate_limit_hits`, migración 0024) para login, registro, IA, mutaciones y búsquedas por usuario; jobs singleton con advisory locks y benchmark único entre workers; pool y `statement_timeout` configurables; `GET /dashboard/summary` y `/assets` paginado en SQL (estado efectivo, subred, orden por IP/puertos...); CLI `production-check`, `migration-status`, `generate-secret`, `backup`, `verify-backup`, `restore`, `integrity-check`. Plantillas en `deploy/`. [production-deployment.md](production-deployment.md), [network-security.md](network-security.md), [backup-restore.md](backup-restore.md), [observability.md](observability.md) |
| Agent distribution (Linux) | Done: reproducible tarball + `.deb` (`agent/packaging/linux/build.sh`), one-command installer with one-time token, systemd service as unprivileged `sentra-agent` with hardening, upgrade keeping identity, uninstall / purge. Pending: validation under a real systemd at boot |
| Agent distribution (Windows) | Fase 4F: zip reproducible con Python embebido oficial (`agent/packaging/windows/build.py`, firma PSF verificada), instalador PowerShell con token de un solo uso (aviso oculto o `-TokenFile`), servicio Windows estándar `SentraAgent` (inicio automático retrasado, recuperación ante fallos) con cuenta virtual `NT SERVICE\SentraAgent` + Event Log Readers (Security sin administrador), enrolamiento hecho por el propio servicio (DPAPI de su cuenta), upgrade sin re-enrolar, `-Reenroll`, desinstalación / `-Purge`; `installation_method` en el dashboard (migración 0016, tras la 0015 de la Fase 4E). Pendiente: validación en Windows físico (checklist en docs/agent-windows-installation.md) |
| Frontend (React, Vite) | Done: dashboard (counts, assets, active alerts, recent activity), asset detail with tabs Overview / Processes / Services / Software / Network / Users / Events / Alerts (search, filters, sort, pagination, change history), alerts page with filters and detail; Network page (discovered/monitored/managed, filters, discovery runs) and Exposure tab. Fase 4D: descubrimiento desde la página Red (iniciar, progreso real, cancelar, resultado, historial, estado del scheduler) sin terminal |
| Alerts | Done: offline, sustained high CPU/RAM, critical disk, watched service stopped, critical events, error bursts, administrator changes; new asset / unknown device / disappeared / port exposed / port closed / monitoring lost (discovery; first run is a quiet baseline); states open/acknowledged/resolved (ack/resolve desde el dashboard o la CLI), dedup, occurrences, auto-resolve |
| Tests | Backend 1672 (real PostgreSQL, incl. model/migration drift, indexed foreign keys, frontend type contract checks, autenticación/RBAC/CSRF/auditoría and real TCP discovery on loopback), agent 315 (+21 skipped on Linux) (3 Windows-only; Linux packaging tests run the real installer under a fake root); sensor 259 (+2 skipped on Linux; incl. a real pysnmp SNMPv3 agent on loopback); frontend 438 tests (Vitest, incl. DOM tests of the Agentes, Red e Incidentes pages with Testing Library + jsdom) + tsc + ESLint + build; `qa/e2e_api.py` 313 contract checks (incl. detección simple, correlación, deduplicación y resolución; riesgo: activo limpio → detección alta → correlación → criticidad → resolver; IA: estado, 409 sin configurar, alcance y permisos; incidentes: detección → caso → cerrado con auditoría, detección relacionada adjuntada sin duplicar y dos sesiones con 409; contexto de activo: admin fija el contexto, auditoría, riesgo e incidente con contexto, viewer sin edición y dos admins con 409); `qa/perf_detections.py`, `qa/perf_risk.py`, `qa/perf_ai.py`, `qa/perf_incidents.py` y `qa/perf_asset_context.py` miden los motores con datos sintéticos; `qa/e2e_production.py` (Fase 4M: Caddy real con TLS, IA caída, PostgreSQL caído y recuperado, dos workers) y `qa/perf_dashboard.py` (dashboard con 10 000 activos); `qa/perf_custom_rules.py` (Fase 5A: 1000 reglas activas y 100 000 señales en 66 s, ~1500 señales/s, índice en 288 ms); `qa/e2e_vulnerabilities.py` (Fase 5B: 37 comprobaciones en 5 escenarios) y `qa/perf_vulnerabilities.py` (10 000 activos, catálogo de 100 000 registros importado en 88 s, 50 000 findings evaluados a 46 activos/s, lecturas de 130-250 ms); `qa/e2e_lifecycle.py` (Fases 5C.1 y 5C.2: reinstalación y reconciliación con preview y confirmación de evidencia débil, dos reconciliaciones concurrentes, token antiguo rechazado, preview de limpieza, archivar/restaurar, borrado rechazado, permisos y eventos Linux; 74/74 contra una instancia QA en la nube) |

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
- `reports` (trabajo, filtros, alcance, resumen, snapshot JSONB con SHA-256, idempotencia, lease, estado) y `report_artifacts` (un fichero por informe: clave de almacenamiento validada, tamaño, SHA-256, `deleted_at`). Fase 5E, migración 0031.
- `sites` (estado, `is_default`, `version`), `site_networks` (CIDR autorizados por site, exclusión de solapamiento dentro del site), `sensors` (hash de credencial y de la pendiente de rotación, estado, versión, capabilities, salud acotada), `sensor_enrollment_tokens` (solo hash, un solo uso, caducidad), `sensor_jobs` (catálogo cerrado, lease, intentos, idempotencia, un job por discovery), `sensor_job_batches` (idempotencia por `batch_id` + SHA-256) y `sensor_observations` (evidencia con procedencia); `assets.site_id`, `discovery_jobs.site_id`/`execution_target`/`sensor_id`, `agent_enrollment_tokens.site_id`. Fase 5F, migración 0032.
- `discovery_observations` (una fila por job + dirección: site, ejecutor, sensor, activo, métodos, MAC, nombres, puertos, RTT, confianza, evidencia y cambios JSONB); `discovery_jobs.profile`; `sensor_observations.rtt_ms`/`forward_dns_match`. Fase 6A, migración 0033.
- `snmp_credential_profiles` (secreto cifrado, `secret_key_id`, `secret_revision`, estado), `network_devices` (equipo registrado: site, dirección de gestión, perfil, sensor, activo, identidad SNMP, clasificación con evidencias, último resultado), `network_device_polls` (historial de consultas, una abierta por equipo), `network_poll_records` (staging de registros SNMP), `network_entities`, `network_interfaces`, `network_neighbors`, `network_vlans`, `network_vlan_ports` y `network_mac_entries` (inventario con `present`, primera/última vez y procedencia). Fase 6B, migración 0034.
- `asset_agent_lineage` (Fase 5C.2, migración 0029): una fila por asociación activo↔agente terminada en una reconciliación (agente, motivo reasignado/reemplazado, activo relacionado, id de reconciliación, actor); sin credenciales. Stale y candidatos a limpieza se derivan de `network_misses` y las fechas existentes.
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
Sites y sensores (Fase 5F): `/sites` (lectura con monitoring:read, cambios con sites:manage),
`/sensors` (lectura; tokens y acciones con sensors:manage), `POST /assets/{id}/site`,
protocolo del sensor en `/sensor/*` (enroll, heartbeat, jobs/poll, start, results, complete,
credential/rotate); `site_id` opcional en las listas (docs/sites.md, docs/distributed-sensors.md).
Advanced discovery (Fase 6A): `GET /discovery/profiles`, `GET /discovery/observations`;
`POST /console/discovery/jobs` acepta `profile`, `ports` y `limits` (docs/advanced-network-discovery.md).
Infraestructura (Fase 6B): `/network/snmp-profiles` (CRUD, `rotate`, `revoke`), `/network/devices` (CRUD, `archive`, `interfaces`, `neighbors`, `vlans`, `mac-entries`, `polls`), `/network/candidates`, `/network/polls/{id}/cancel`, `/network/mac-locations?mac=` (docs/snmp-network-intelligence.md).
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

- SNMP (Fase 6B): sin topología ni enlaces inferidos (6D), sin traps ni syslog; CDP solo
  IPv4; sin LLDP-MED, LLDP-V2-MIB ni tablas propietarias; equipos con una FDB por contexto
  SNMPv3 solo informan del contexto por defecto; AES-192/256 «Reeder» no soportado; la VLAN
  de una MAC se asume igual al FDB si el equipo no publica el mapa. Validado con agentes
  simulados y un agente pysnmp real en loopback; pendiente con switches reales. La
  comprobación de la DACL del fichero de claves no resuelve pertenencia a grupos (ante la
  duda, rechaza).
- Fix 1 de 6B: el test del Event Log real exigía solo warning/error/critical, pero desde la 4H
  el agente envía Security 4624 interactivo/RDP/caché como `info` (contrato documentado); el
  test valida ahora ese contrato y hay pruebas deterministas de niveles y cursor. El cierre del
  transporte pysnmp (y del agente SNMP de los tests) drena con tope las tareas del dispatcher,
  los sockets y el ejecutor de getaddrinfo antes de cerrar el bucle.
- Fix 2 de 6B: en Windows el backend comprueba por SID la DACL real del fichero de claves SNMP
  (descriptor abierto), de su directorio y de sus antecesores, rechaza enlaces y junctions y
  falla cerrado (app/core/file_acl.py); `snmp-keygen` y `--add` crean los ficheros con DACL
  protegida desde el primer byte y verifican antes de sustituir; `snmp-rekey` verifica cada
  blob. Nuevo ajuste opcional `SNMP_CREDENTIAL_KEY_READERS`. Sensor: el spool cierra su
  conexión SQLite si el arranque falla y en el apagado aunque falle el último envío; los tests
  cierran runners y spools (la conexión sin cerrar llegaba al GC durante el test de pysnmp).
- Fix 3 de 6B: `UrllibTransport` cierra el `HTTPError` que captura en las respuestas 4xx/5xx
  (es también la respuesta abierta); sin el cierre, Python 3.14+ avisa "Implicitly cleaning
  up" y la suite estricta del sensor fallaba en el test de loopback HTTP.
- Reporting (Fase 5E): horas siempre en UTC; PDF con fuentes estándar WinAnsi (caracteres
  fuera de cp1252 salen como "?"); sin DOCX; los posibles duplicados del informe de ciclo de
  vida reflejan el estado actual (misma lógica de 5C.2), no el de la hora de corte; el
  worker genera de uno en uno por vuelta en un solo proceso; los ficheros de
  REPORT_OUTPUT_DIR no entran en el `backup` de la base de datos. No probado aún en Windows
  real (visor PDF, Excel, ACL de la carpeta).
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
  snapshot; los eventos Linux (5C.1) aún no llegan a las reglas personalizadas. Sigma es un subconjunto (sin `base64*`, `cidr`, `near`,
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
- Ciclo de vida y eventos Linux (Fase 5C.1): eventos Linux solo probados con un journalctl
  simulado (y uno real sin journal); pendiente journald real con sshd, sudo y auditd, la
  instalación real del .deb 0.2.1 (grupo systemd-journal) y la reconciliación del caso
  Ravenslg con los agentes reales. La identidad de máquina de Windows (MachineGuid) solo está
  probada por tipos (`mypy --platform win32`). Reglas personalizadas/Sigma y la inteligencia
  de amenazas no usan aún los eventos Linux. Reconciliar no copia el historial del activo
  nuevo (queda archivado con él).
- Limpieza y reconciliación (Fase 5C.2): probado solo con fixtures y una instancia QA en la
  nube; pendiente la reconciliación real DESKTOP-03IJGBE ← ravenslg (procedimiento en
  agent-asset-lifecycle.md) y revisar el preview de limpieza con el inventario real antes de
  activar `ASSET_AUTO_CLEANUP`. Reconciliar no re-asigna el historial del activo origen (queda
  archivado con él). El borrado manual de un descubierto exige ahora que sea candidato a
  limpieza (stale y fuera de la ventana de purga). Los activos monitorizados sin agente aún no
  existen (sin colectores agentless): su política es conservadora (solo archivar).
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
- Motor de detección (Fase 4H): Linux envía un subconjunto del journal desde la Fase 5C.1
  (ver docs/linux-events.md); sin líneas de comando no hay detección de PowerShell codificado;
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

- Fase 6B: el servidor nunca habla SNMP ni envía OIDs; el sensor tiene el único catálogo y
  no contiene operaciones de escritura. pysnmp 7 (BSD-2, Python puro) como extra opcional del
  sensor, en vez de net-snmp por subprocess (credenciales en argumentos del proceso) o
  easysnmp (sin wheels Windows). Secretos con AES-256-GCM y fichero de claves en vez de DPAPI
  para que una copia de la base se pueda restaurar en otra máquina y varios workers compartan
  la clave. La interpretación (tipo de puerto, VLAN de una MAC, clasificación) solo en el
  servidor, con la evidencia en bruto guardada aparte.
- Fase 6A: un perfil es un conjunto cerrado de valores sobre el mismo motor, no otro
  scanner. El sensor revalida los límites con topes propios (un servidor anterior sin topes
  = rechazo). La evidencia se guarda aparte (`discovery_observations`) para no cambiar la
  semántica de activos, puertos y alertas del discovery básico. Bloqueo fijo discovery →
  job de sensor en complete/results/cancel (antes, cancel y complete simultáneos podían
  bloquearse mutuamente y devolver 503).

- Fase 5F: un site es una ubicación, no un tenant (RBAC global). Sensor por polling HTTPS
  saliente (sin WebSocket, MQTT, Kafka ni Redis) para funcionar tras NAT. El servidor crea
  los jobs y aplica los resultados con la misma lógica del discovery local; el sensor solo
  aporta observaciones. Discovery local solo en el site por defecto. Lotes que faltan al
  cerrar un job: se aplica como parcial en lugar de rechazar el cierre (el spool del sensor
  descarta envíos rechazados y bloquear el cierre dejaría el job colgado).
- Fase 5E: PDF con un escritor propio (stdlib) en lugar de ReportLab o HTML→PDF con un
  navegador: sin dependencias nuevas, determinista y sin superficie de JavaScript/URLs.
  Informes generados por un job en segundo plano con trabajos persistentes, no en la
  petición HTTP. Snapshot en la base de datos y fichero en disco fuera del repo.
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

Fase 6B (SNMP, LLDP, CDP y switches) implementada: aplicar la migración 0034, crear el
fichero de claves (`snmp-keygen`), instalar un sensor 0.3.0 con el extra `snmp` en el site
del switch, crear un perfil SNMPv3 y registrar el switch; consultar y revisar identidad,
clasificación, interfaces, vecinos LLDP/CDP, VLANs y MACs; provocar un `auth_failed`, rotar
y revocar (QA manual completo en docs/snmp-network-intelligence.md). Siguiente: 6C Wi-Fi o
6D Topología.

Fase 6A (Advanced Network Discovery) implementada: aplicar la migración 0033, actualizar un
sensor a 0.2.0 y comprobar que declara `network.discovery.advanced`; lanzar `quick`,
`standard` y `deep` sobre una red de laboratorio autorizada desde el servidor y desde el
sensor, revisar la evidencia, cancelar uno a mitad y comprobar que no concluye nada
negativo; comprobar como analyst que no puede ajustar límites (pasos en el HANDOFF).
Siguiente: 6B SNMP/LLDP/CDP.

Fase 5F (multi-site y sensores distribuidos) implementada: aplicar la migración 0032 y
comprobar que todo queda en el site `Local`; crear Site A y Site B con la misma red, enrolar
un sensor en cada uno (Linux y Windows), lanzar un discovery en A y comprobar que el sensor
de B no lo recibe; cortar la red del sensor durante un scan y comprobar que entrega lo
pendiente al volver sin duplicados; revocar un sensor y ver el rechazo; filtrar Dashboard e
Informes por site (pasos completos en el HANDOFF de la fase).

Siguientes fases: 6A Advanced Network Discovery, 6B SNMP/LLDP/CDP, 6C Wi-Fi, 6D Topología,
6E detección de cambios e historial de topología. Después: 7A Analyst Tool Engine, 7B Analyst
Console, 7C capa de modelo open-weight autoalojado.

Fase 5E (Reporting y evidencias) completada. Comprobaciones en Windows si siguen pendientes: fijar
`REPORT_OUTPUT_DIR` fuera del repo (por ejemplo `D:\SentraData\reports`), generar cada tipo
en PDF y HTML con datos reales, abrir los PDF en el visor de Windows y en Edge, abrir un CSV
en Excel, verificar un paquete de evidencia (manifest y SHA-256) y revisar la auditoría.

Fase 5D (Response Engine y Playbooks) entregada: aplicar la migración 0030, actualizar un
agente Windows y uno Linux a 0.3.0 y comprobar en Response que declaran capacidades; lanzar
`collect_inventory` y el playbook "Investigar endpoint" sobre un activo real; parar el agente
y comprobar `blocked (agent_offline)`; como admin abrir un incidente desde una detección real
y repetir sin duplicarlo; revisar la auditoría.

Fase 5C.2 (limpieza de activos y reconciliación segura) entregada: aplicar la migración 0029,
abrir Administración → Ciclo de vida y revisar el preview con los activos reales (sin
ejecutar), hacer la reconciliación real DESKTOP-03IJGBE ← ravenslg siguiendo el
procedimiento de agent-asset-lifecycle.md (preview, confirmar evidencia, comprobar heartbeat
y auditoría) y dejar `ASSET_AUTO_CLEANUP=false` hasta validar varios ciclos de discovery.
Después: 5D (respuesta automatizada con humano en el bucle).

Fase 5C.1 (ciclo de vida de activos y eventos Linux) entregada: instalar el .deb 0.2.1 en
un Linux real (comprobar el grupo systemd-journal y la cobertura en Events), provocar fallos
SSH y un sudo para ver LIN-AUTH-001/002, reconciliar Ravenslg (agente 0.1.0 revocado con el
0.2.x nuevo) y archivar/borrar algún activo descubierto de prueba.

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
