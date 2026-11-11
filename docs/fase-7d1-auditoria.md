# Fase 7D.1: auditoría y matriz de cobertura H01-H05

Base: main `265f63f` = Dev `5ad952c` (después de 7C, 7C-Security-Fix1 y 7C-Fix2). Cada
hallazgo del informe del 2026-11-05 se revalidó leyendo el código actual, sin fiarse de los
números de línea del informe.

## Revalidación

| Hallazgo | ¿Seguía presente? | Dónde estaba (código anterior a 7D.1) | Vías adicionales encontradas |
|----------|-------------------|----------------------------------------|------------------------------|
| H01 suplantación de agente | Sí | `AgentService.register`: con un token de alta válido y un `agent_id` existente, sustituía `agent_token_hash` | La clave legacy permitía lo mismo; reactivar y volver a registrar con cualquier token valía para cualquier activo |
| H02 viewer ve evidencias de endpoint | Sí | Detecciones (lista, detalle y evidencias) solo con `monitoring:read` | Resumen copiado a alertas y a la descripción de incidentes, timeline de incidentes, herramientas `detections.*`, `attribution.explain` y `detections.related`, nota de `case_link`, contexto de IA y su caché, informes, y búsqueda por texto y SHA-256 (oráculo) |
| H03 historial de herramientas | Sí | `ToolService` devolvía salida y resumen con los permisos del momento de ejecutar | `case_link` copiaba el resumen al incidente |
| H04 transporte del agente | Sí | El agente avisaba de `http://` pero lo usaba; los instaladores lo aceptaban | `suggested_server_urls` y el asistente proponían `http://` |
| H05 redirecciones | Sí | `urllib` seguía 301, 302, 303, 307 y 308 (reenviando el cuerpo con la credencial en 307 y 308, y permitiendo bajar de HTTPS a HTTP) | El cuerpo de error y la respuesta se leían sin límite |

## Matriz de cobertura

«Test» indica el test automático que reproduce el ataque o el requisito y comprueba el
resultado esperado. Todos pasan en la nube (ver TEST-RESULTS en la entrega).

### H01

| Requisito | Implementación | Test |
|-----------|----------------|------|
| Token ordinario o clave legacy no toman un `agent_id` existente | `AgentService.register` → 403 `agent_recovery_required`, rollback, token sin consumir, auditoría | `test_h01_existing_agent_id_cannot_be_taken_over` |
| Altas nuevas siguen funcionando con ambos métodos | Igual que antes para identidades nuevas | `test_h01_new_identities_still_enroll_with_both_methods` |
| Registro concurrente sin carreras | Restricción única más rollback | `test_h01_concurrent_registration_of_a_new_agent_id_creates_one_identity` |
| Retirada progresiva de la clave legacy | `AGENT_ENROLLMENT_KEY_EXPIRES_AT` | `test_h01_legacy_key_can_be_retired_without_cutting_enrolled_agents`, `test_h01_expiry_setting_must_be_timezone_aware` |
| Recuperación solo para admin, con motivo y confirmación | `POST /console/agents/{id}/recovery-tokens`, CLI `authorize-agent-recovery` | `test_h01_recovery_is_admin_only_and_needs_reason_and_confirmation`, `test_agent_auth.py` (CLI) |
| Un solo uso, vida corta, ligada a agente, activo, site y hostname | `AgentService._recover` con filas bloqueadas | `test_h01_recovery_is_single_use_short_lived_and_bound_to_its_agent`, `test_h01_recovery_checks_site_hostname_and_replaces_previous_authorizations` |
| Revocado: primero reactivar | Comprobación en la recuperación | `test_h01_revoked_agent_needs_reinstate_before_recovery` |
| Rotación con la credencial vigente, nunca con la clave de instalación | `POST /agents/credentials/rotate` (Bearer) | `test_h01_rotation_requires_the_current_credential_and_https` |
| Rotación sin perder la identidad ni dejar al agente fuera | Credencial pendiente hasta su primer uso | `test_h01_rotation_keeps_identity_and_never_locks_the_agent_out`, `agent/tests/test_runner.py` (rotación) |
| Rotación concurrente | Bloqueo de fila | `test_h01_concurrent_rotations_leave_a_single_new_credential` |
| La petición de rotación solo viaja cifrada | `rotate_credential` solo en heartbeats HTTPS o loopback | `test_h01_rotation_requests_reach_the_agent_only_over_a_secure_transport` |
| Sin tokens en logs ni auditoría | Solo SHA-256 en la base; la auditoría lleva `recovery_id` | Revisión de código, más `test_h01_recovery_is_admin_only…` (la auditoría no contiene el token) |
| Interfaz | `RecoveryDialog`, `RotationDialog` | `AgentsPage.test.tsx`, `AgentPanel.test.tsx` |

### H02

| Requisito | Implementación | Test |
|-----------|----------------|------|
| Allowlist central aplicada en el backend | `app/core/evidence_policy.py` | `test_h02_viewer_gets_only_the_operational_allowlist` |
| El analista sigue viendo todo; la evidencia original queda intacta | Filtrado solo al serializar | El mismo test (comprueba la base) |
| La búsqueda no sirve de oráculo | `console_search` y `/detections?q=` excluyen el texto retenido | `test_h02_search_is_not_an_oracle_for_withheld_text` |
| Incidentes y copias | Timeline, detecciones adjuntas, descripción copiada | `test_h02_incident_copies_and_views_follow_the_reader` |
| Contexto y caché de IA | `ContextBuilder` y `ai_insights.content_permissions` | `test_h02_ai_context_only_contains_what_the_reader_may_read` |
| Informes y exportaciones | `reports.content_permissions` al listar y descargar | `test_h02_report_with_endpoint_content_requires_telemetry_read` |
| Datos históricos ya copiados | Migración 0051 (alertas, incidentes, permisos de copias) | `test_migration_0051_backfills_copies_and_downgrade_restores_them` |
| Interfaz | Aviso de contenido protegido y campos omitidos solo por nombre | `DetectionsPage.test.tsx` |

### H03

| Requisito | Implementación | Test |
|-----------|----------------|------|
| Revalidar los permisos actuales en la lista y el detalle | `tool_executions.read_permissions` | `test_h03_tool_history_revalidates_current_permissions` |
| Herramientas que exigen detalle de endpoint | `_endpoint_gate` | `test_h03_tools_needing_endpoint_detail_deny_restricted_callers` |
| Copia a un caso | `case_link` deniega o protege el resumen | Revisión de código, más el test de copias de incidente |
| Se mantiene `tools:execute` (7C-Security-Fix1) | Sin cambios | Suite de herramientas y consola existente |
| Interfaz | Aviso «Resultado protegido» | `ToolOutput.test.tsx` |

### H04

| Requisito | Implementación | Test |
|-----------|----------------|------|
| HTTPS obligatorio fuera de loopback | `config.insecure_url_reason` y `SentraClient` | `test_h04_only_https_or_loopback_http` |
| Validación TLS normal y CA interna | `tls_context_with(ca_bundle)` | `test_h04_https_with_a_trusted_private_ca_works`, `test_h04_untrusted_or_mismatched_certificates_are_rejected` |
| Diagnóstico claro para configuraciones antiguas | Mensaje que cita docs/agent-https-migration.md | `test_h04_legacy_http_config_gets_a_migration_diagnostic` |
| Instaladores Windows, Linux y macOS | Comprobación antes de parar el servicio; `.deb` preinst y macOS preinstall | `test_linux_packaging.py`, `test_windows_service.py` |
| Sin corte silencioso | El servidor marca `http_remote` y no corta | `test_h04_http_outside_loopback_is_flagged_but_not_cut_off` |
| Loopback | `http_loopback` cuenta como seguro | `test_h04_loopback_http_is_accepted_as_secure` |
| Asistente y sugerencias | Solo HTTPS | `install.test.ts`, `AgentsPage.test.tsx`, `test_agent_management.py` |

### H05 y endurecimiento del transporte

| Requisito | Implementación | Test |
|-----------|----------------|------|
| 301, 302, 303, 307 y 308 rechazadas sin reenviar la credencial (con origen cruzado) | `_NoRedirect` → `RedirectError` | `test_h05_redirects_are_refused_and_credentials_never_forwarded` (servidor atacante con datos sintéticos que no recibe nada) |
| Sin bajada de HTTPS a HTTP | Igual | `test_h05_redirect_from_https_to_http_is_refused` |
| Límite de bytes y lectura incremental | `_read_bounded` | `test_response_size_is_bounded_and_read_incrementally` |
| Respuesta tipo objeto JSON | Comprobación tras parsear | `test_response_must_be_a_json_object` |
| Plazo total | `request_deadline_seconds` | `test_total_deadline_stops_a_server_that_dribbles_the_response` |
| Reintento y backoff para errores transitorios | Sin cambios | `test_client_errors_and_retryable_errors_are_still_distinguished`, suite existente |

## Riesgos residuales (aceptados en 7D.1)

1. **Agentes 0.6.x por HTTP**: siguen enviando datos con una credencial que viaja en claro
   hasta que se migren. Es una decisión deliberada (no cortar la monitorización); el
   dashboard lo hace visible y la rotación se entrega en cuanto hablen por HTTPS.
2. **Altas nuevas por HTTP**: un instalador 0.6.x todavía puede registrar un equipo NUEVO por
   HTTP. El token es de un solo uso y vida corta, el alta queda marcada como `http_remote` y
   se le pide rotación. Los instaladores 0.7.0 ya no lo permiten.
3. **`AGENT_SERVER_URL`** no se rechaza en el arranque si es `http://`, para no impedir que
   arranque un servidor con el `.env` actual. El asistente no genera comandos con ella.
4. **Eventos del sistema operativo** (Windows Event Log, journald) siguen con
   `monitoring:read` como antes de 7D.1: no son telemetría 6E. Si deben protegerse, es una
   decisión de producto aparte.
5. **Sin mTLS ni cuotas por agente**: la autenticación sigue siendo token por agente. Las
   cuotas (H06) van en 7D.2.

## Validación: simulación frente a validación real

Hecho en la nube (simulación):

- Suites completas de backend con PostgreSQL de laboratorio, frontend (Node 22 y 24),
  agente y sensor.
- TLS real con una CA generada por openssl y un servidor HTTPS local.
- Redirecciones con un servidor «atacante» en otro puerto.
- Instaladores Linux ejecutados con systemctl simulado.
- Migración 0051 arriba, abajo y arriba en una base de laboratorio.

Pendiente en hardware real (no se ha ejecutado):

- Suites en Windows (incluidos los tests solo de Windows del instalador PowerShell).
- Caddy con certificado real y CA interna delante de agentes reales.
- Actualización de un agente 0.6.2 por HTTP a 0.7.0 en Windows, Linux (`.deb`) y macOS
  (`.pkg`).
- Recuperación de identidad en un equipo reinstalado y rotación automática tras migrar.
- Comprobación visual en el navegador de los diálogos nuevos.
