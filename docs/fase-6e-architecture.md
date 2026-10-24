# Fase 6E: arquitectura

Network Change Detection & Topology History, ampliada con identidad DHCP/Wi-Fi, telemetría
avanzada de endpoints, árboles de procesos, detección conductual, investigación forense remota y
aislamiento seguro. Este documento fija los contratos antes del código; cada módulo tiene además
su documento propio (ver «Documentos» al final).

## Punto de partida verificado

- Base: `origin/main` en `e7a3ee6` (merge del PR #8, 6C + 6D). `origin/Dev` (`c55a9d5`) tiene
  el mismo árbol. CI run 42 sobre `e7a3ee6`: success (backend, agente Linux, agente macOS arm64 e
  Intel, sensor, frontend).
- Versiones al empezar: backend 0.2.0, frontend 0.2.0, sensor 0.5.1, agente 0.4.0, API `/api/v1`,
  última migración `0038_topology_engine`.
- Lo que ya existe y se reutiliza (no se duplica):
  - Topología 6D: `topology_links` con `present`, `first_seen_at`, `last_seen_at` y revisión
    humana; `topology_builds` (sin retención).
  - Identidad 6C: PTR, mDNS, NetBIOS, SSDP/UPnP, OUI, `custom_label` con prioridad visual,
    `observed_names`, `name_source`, vigencia de nombres (`NAME_STALE_DAYS`).
  - Procesos: solo la última instantánea por activo (`asset_process_snapshots`), sin historia.
  - Detección 4H/5A: señales normalizadas (`SignalKind`), reglas con ventana, cooldown, versión,
    MITRE opcional; el motor corre como job periódico.
  - Response 5D: catálogo cerrado, política única (`policy.evaluate`), comandos de agente por
    heartbeat + poll + result, `isolate_host` listado como `not_implemented`.
  - Privilegios del agente: Windows con cuenta virtual (`NT SERVICE\SentraAgent`, sin admin),
    Linux con usuario `sentra-agent` sin capacidades y `NoNewPrivileges=true`, macOS daemon.

## Versiones objetivo

| Componente | Antes | 6E | Motivo |
|---|---|---|---|
| Backend | 0.2.0 | 0.3.0 | API ampliada de forma aditiva; `/api/v1` se mantiene |
| Frontend | 0.2.0 | 0.3.0 | Acompaña al backend |
| Agente | 0.4.0 | 0.5.0 | Telemetría avanzada, árbol de procesos, forense, aislamiento |
| Sensor | 0.5.1 | 0.6.0 | Fuentes DHCP locales y diagnósticos de identidad |
| Migraciones | 0038 | 0039–0043 | Una por módulo para revisar y revertir por separado |

## Mapa de dependencias

```
0039 topology history ──> 6E.1 snapshots + diff + cambios ──┐
0040 identity/DHCP ─────> 6E.2 leases + historial identidad ─┼─> 6E.1 (cambios de nombre/IP/MAC)
                           sensor 0.6.0 (job dhcp_leases) ───┘
0041 telemetry ─────────> 6E.3 ingesta actividad ──> 6E.4 árbol de procesos
                           agente 0.5.0 (tracker)        │
                                                         v
                                        6E.5 reglas conductuales (Detection Engine existente)
                                                         │
0042 forensics ─────────> 6E.6 investigaciones (Response Engine 5D: nuevas acciones de agente)
0043 isolation ─────────> 6E.7 aislamiento (Response Engine + helper privilegiado local)
                                                         │
                           6E.10 frontend (consume todo lo anterior)
```

Orden de implementación: contratos → 6E.1 → 6E.2 → 6E.3/6E.4 → 6E.5 → 6E.6 → 6E.7 →
agente/sensor → frontend → QA. El agente, el sensor y el frontend se desarrollan en paralelo en
cuanto el contrato de su módulo está fijado.

## 6E.1 Historial de topología y cambios de red

Tablas (0039):

- `topology_snapshots`: una fila por estado distinto del grafo de un site. `sequence` creciente
  por site, `content_hash` (SHA-256 del contenido canónico), `nodes` y `links` compactos en JSONB,
  `scan_quality` (`complete` | `partial` | `degraded`, con motivos), `build_id`, `taken_at`,
  `confirmed_at` (última reconstrucción que obtuvo el mismo hash), `preserved` (no se purga) y
  `preserve_reason`. Si el hash no cambia solo se actualiza `confirmed_at`: el historial crece con
  los cambios, no con las reconstrucciones.
- `network_changes`: cambio detectado entre dos snapshots consecutivos o por identidad.
  `change_type` en catálogo cerrado (`device_appeared`, `device_not_observed`,
  `device_disappeared`, `device_retired`, `ip_changed`, `mac_changed`, `name_changed`,
  `vendor_changed`, `gateway_changed`, `role_changed`, `classification_changed`,
  `connectivity_changed`, `link_added`, `link_not_observed`, `link_removed`, `link_port_changed`,
  `link_vlan_changed`, `link_kind_changed`, `link_confidence_changed`, `wifi_association_changed`,
  `wifi_ap_changed`), `subject_type` + `subject_key`, `before`/`after`, `evidence` acotada,
  `source`, `confidence`, `status` (`detected` | `confirmed` | `dismissed`), revisión humana,
  `from_snapshot_id`/`to_snapshot_id`, `detected_at`, `preserved`.

Reglas de no falsos cambios:

- Un nodo que falta en el snapshot nuevo es `device_not_observed`, nunca `device_disappeared`.
  Solo pasa a `device_disappeared` cuando el estado del activo ya lo dice con la lógica existente
  (scans completos consecutivos, `network_misses`) y a `device_retired` si se archiva.
- Un enlace que deja de derivarse es `link_not_observed`. Solo es `link_removed` tras
  `TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS` snapshots seguidos sin él **y** con su fuente de evidencia
  sana (la última consulta SNMP/WLAN del equipo que lo informaba terminó bien). Si la fuente
  falló, el snapshot es `degraded` y no se concluye nada sobre ese enlace.
- Compartir subred o gateway sigue sin crear enlace físico (regla de 6D).

API (lectura `monitoring:read`, revisión `topology:manage`):

- `GET /topology/snapshots?site_id&start&end&limit&before_sequence` (cursor por secuencia)
- `GET /topology/snapshots/{id}` (contenido completo, acotado por los topes de 6D)
- `GET /topology/diff?site_id&from_snapshot&to_snapshot` o `&from_time&to_time` (`&subnet`)
- `GET /topology/changes?site_id&change_type&status&subject&asset_id&start&end&subnet&limit&offset`
- `PATCH /topology/changes/{id}/review` (`confirmed` | `dismissed` | `detected`, `version`)
- `GET /topology/history/nodes/{node_id}` y `GET /topology/history/links/{link_id}`
- `GET /topology/diff/export?format=json|csv` (SHA-256 del cuerpo en `X-Sentra-SHA256`; es un
  hash de integridad, no una firma)

Retención y carga: `TOPOLOGY_BUILD_RETENTION_DAYS` (30), `TOPOLOGY_SNAPSHOT_RETENTION_DAYS` (180,
conservando siempre el último de cada site y los `preserved`), `NETWORK_CHANGE_RETENTION_DAYS`
(365, salvo `preserved`), `TOPOLOGY_ABSENT_LINK_RETENTION_DAYS` (90, enlaces `present=false` sin
revisión humana), `TOPOLOGY_MANUAL_REBUILD_COOLDOWN_SECONDS` (60, 429 `topology_rebuild_cooldown`).
La retención respeta `preserved`; el servicio tiene `preserve_for`, pero ningún flujo de
incidentes ni de investigaciones lo llama todavía (ver `topology-history.md`).

## 6E.2 Identidad avanzada y DHCP

Tablas (0040):

- `dhcp_sources`: fuente autorizada por site. `kind`: `lease_import` (fichero subido por un admin)
  o `sensor_file` (fichero local de un sensor, referenciado por un nombre que el propio sensor
  define en su configuración; el servidor nunca envía rutas). `format`: `dnsmasq`, `isc_dhcpd`,
  `kea_csv`, `windows_dhcp_csv`, `generic_csv`. Estado, última importación, último error.
- `dhcp_leases`: `site_id`, `source_id`, `ip`, `mac`, `hostname` (saneado), `client_id`
  (hash si es opaco), `starts_at`, `ends_at`, `state` (`active` | `expired` | `released`),
  `first_seen_at`, `last_seen_at`, `asset_id` asociado (o null) y `match` (motivo).
- `asset_identity_history`: cambio de identidad de un activo (`field`: `name`, `label`, `ip`,
  `mac`, `vendor`, `device_type`; los cambios Wi-Fi de AP y SSID viven en `network_changes` de
  6E.1), `old_value`, `new_value`, `source`, `confidence`,
  `observed_at`. Alimenta la vista de historial de identidad.

Asociación lease → activo (nunca fusiona activos):

1. Solo dentro del mismo site.
2. Lease activo cuya MAC **y** IP coinciden con el activo → `mac_ip`, `high`. Es la única
   asociación que da nombre.
3. MAC coincide con un único activo, IP distinta → `mac_moved`, `medium`: se enlaza como
   evidencia, sin dar nombre.
4. Solo IP (`ip_only`) o MAC aleatoria sin coincidencia exacta (`randomized_mac`) → no se
   asocia; queda como evidencia. Varios activos con la misma MAC → `ambiguous`, sin asociar.
5. Hostname genérico o dado a la vez a varias MACs (`localhost`, `android`, `iphone`,
   `unknown`, `*`, vacío) → no da nombre.

Prioridad del nombre visible: `custom_label` > nombre automático. Nombre automático: hostname
del agente; sin agente, entre los nombres no genéricos, primero los recientes, después los no
desmentidos (un PTR que no resuelve a la IP va al final) y, a igualdad, `dhcp_lease` > DNS
inverso > mDNS > NetBIOS > UPnP > fabricante + modelo. El fabricante OUI nunca es un nombre.
Todos los nombres observados se conservan con fuente y vigencia. `GET /assets/{id}/identity`
devuelve nombre elegido, fuentes, leases, Wi-Fi y, si sigue sin identificar,
`unidentified_reasons` (`no_name_sources`, `only_generic_names`, `names_stale`,
`randomized_mac`, `dhcp_source_missing`, `dhcp_no_lease`, `dhcp_lease_unusable_name`,
`only_vendor`).

API: `GET /dhcp/sources` (`monitoring:read`), `POST/PATCH/DELETE /dhcp/sources`
(`dhcp:manage`), `POST /dhcp/sources/{id}/import` (texto del fichero en JSON, acotado por
`DHCP_IMPORT_MAX_KB`, solo admin, auditado), `POST /dhcp/sources/{id}/read` (job del sensor),
`GET /dhcp/leases`, `GET /assets/{id}/identity`, `GET /assets/{id}/identity/history`.
Detalle en `dhcp-identity.md`.

Sensor 0.6.0: job `dhcp_leases` (capacidad `dhcp.leases.file`). El sensor lee solo los ficheros
declarados en su `sensor.toml` (`[[dhcp_lease_files]] name, path, format`), con tamaño máximo,
y devuelve leases normalizados. Sin APIs de routers: un router doméstico (Archer GX90) no publica
leases por una API oficial; si se quiere integrar uno concreto será una decisión aparte.

## 6E.3 Telemetría avanzada de endpoints

Tablas (0041):

- `endpoint_activity`: evento enriquecido. `asset_id`, `event_uid` (UUID del agente, único por
  activo: deduplicación de reintentos), `seq`, `category` (`process`, `network`, `service`,
  `persistence`, `scheduled_task`, `auth`, `dns`, `protection`, `firewall`, `agent_health`),
  `action` (`start`, `stop`, `connect`, `listen`, `created`, `modified`, `deleted`, `enabled`,
  `disabled`, `state`...), `instance_key` (proceso relacionado), `occurred_at`, `received_at`,
  `source` (`psutil_poll`, `sysmon`, `security_4688`, `journald`, `proc`, `unified_log`),
  `data` JSONB acotado.
- `process_instances`: índice derivado del árbol. `asset_id`, `instance_key` (único por activo),
  `pid`, `ppid`, `parent_instance_key`, `parent_relation` (`observed` | `inferred` | `missing`
  | `pid_reused`), `name`, `exe`, `cmdline` (según política), `username`, `sha256`, `signer`,
  `integrity`, `started_at`, `ended_at`, `first_seen_at`, `last_seen_at`, `source`.
- Columnas en `assets`: `telemetry_status` y `telemetry_status_at` (colectores activos, fuente
  real de cada categoría, eventos en cola, descartados, latencia del último lote).

`instance_key` = SHA-256 de `boot_id|pid|create_time_ms` (32 hex): un PID reutilizado nunca se
confunde con el proceso anterior.

Contrato agente → servidor: `POST /agents/activity` con `{agent_id, batch_id, boot_id, events[],
stats}`, máximo 1000 eventos (fijo en el esquema), `Content-Encoding: gzip` admitido
(descompresión acotada a `max_request_bytes`), deduplicación por `(asset_id, event_uid)`,
`TELEMETRY_ACTIVITY_MAX_PER_MINUTE` lotes por agente (429), respuesta con `accepted`,
`duplicates`, `rejected`. Un agente 0.4.0 no conoce el endpoint y sigue igual. Detalle del
servidor en `process-tree.md`.

Política de privacidad (`TELEMETRY_CMDLINE_POLICY` en el servidor y `cmdline` en el agente, gana
la más restrictiva): `off` | `redacted` (por defecto: se eliminan valores tras `-p`, `--password`,
`token=`, `key=`, cabeceras `Authorization`, URLs con credenciales; el agente corta a 1024 y el
servidor a 2048) | `full` (el servidor corta a 8192).
Nunca se lee el contenido de ficheros. Los hashes de ejecutables están desactivados por defecto en
el agente (`hash_executables = false`) y, si se activan, tienen tope de tamaño y caché.

Latencias honestas: en las tres plataformas el arranque y fin de procesos se observa por sondeo
(`process_poll_seconds`, 5 s por defecto), así que un proceso que vive menos que el intervalo
puede no verse. Con Sysmon (evento 1) o la auditoría 4688 ya activas en Windows, el inicio de
proceso llega orientado a eventos (latencia = intervalo del lector de eventos). El agente nunca
cambia la política de auditoría ni instala Sysmon.

## 6E.4 Árbol de procesos

API (`telemetry:read`, analista y admin; el permiso `process_tree:read` previsto se integró en
`telemetry:read`; el viewer no ve actividad ni líneas de comando):

- `GET /assets/{id}/process-tree?parent=&at=&search=&limit=` raíces, hijos de `parent` o
  búsqueda plana; carga diferida
- `GET /assets/{id}/process-instances/{key}` detalle, ancestros (hasta 32) y conexiones
- `GET /assets/{id}/activity?category=&action=&instance_key=&start=&end=&before_id=&limit=`
- `GET /assets/{id}/telemetry-status`
- `GET /endpoint/metrics` (retraso de ingesta y latencia de detección)

El listado `GET /assets/{id}/process-instances` previsto no se implementó: la búsqueda va por
`process-tree?search=`.

Nunca se envía el árbol completo: cada nivel es una página (`limit` máx. 200).

## 6E.5 Detección conductual

Se amplía el Detection Engine existente, sin motor paralelo:

- Nuevos `SignalKind`: `process_start`, `process_network`, `persistence_change`,
  `protection_change`, `firewall_change`. El recorder solo registra los eventos que encajan en
  un patrón (padre de documentos que lanza un intérprete, línea de comandos sospechosa, ruta
  inusual, conexión a Internet desde ruta inusual, persistencia, transición de protección o
  firewall), para acotar el volumen.
- Reglas implementadas (`BEH-*`, versión 1, tipo `single`, con cooldown y evidencia; detalle en
  `behavioral-detection.md`):
  - `BEH-001` aplicación de documentos que lanza un intérprete o LOLBin.
  - `BEH-002` línea de comandos sospechosa (lista cerrada de patrones).
  - `BEH-003` proceso en ubicación inusual con conexión a Internet (confianza baja).
  - `BEH-004` mecanismo de persistencia creado o modificado.
  - `BEH-005` protección del endpoint desactivada (transición respecto al último estado).
  - `BEH-006` firewall del host desactivado (transición respecto al último estado).
  Las secuencias previstas (servicio de red que lanza un shell; fallos, éxito y persistencia en
  orden) no se implementaron en 6E.5.
- Herramientas legítimas (PowerShell, Python, SSH, utilidades admin) nunca disparan por sí
  solas: cada regla exige contexto (padre, patrón de línea de comandos, ruta o transición).
- Exclusiones justificadas: tabla `detection_exclusions` (migración 0041: regla integrada,
  activo opcional, campo, valor exacto, justificación, autor, caducidad, revocación, `hits`),
  `rules:manage` para crear y revocar, auditadas.
- Latencia medible: `GET /endpoint/metrics` da el retraso de ingesta (`received_at -
  occurred_at`) y la latencia de las detecciones `BEH-*` (`created_at - first_seen_at`, p50 y
  p95 de 24 h). Clasificación: periódica (motor cada `DETECTION_EVAL_INTERVAL_SECONDS`), no
  «tiempo real».
- Riesgo e incidentes por las vías existentes (fórmula determinista, sin IA). Ninguna detección
  lanza aislamiento, terminación de procesos ni bloqueo.

## 6E.6 Investigación forense remota

Tablas (0042): `investigations` (activo, site, incidente opcional, título, estado, `legal_hold`),
`forensic_artifacts` (investigación, ejecución de Response, activo, agente, site, operador,
acción, alcance, `agent_sha256`, `sha256` calculado por el servidor sobre el JSON canónico,
tamaño, contenido, versión del agente, `collected_at`, `received_at`), `investigation_notes`
(interpretaciones, separadas de la evidencia), `evidence_packages` (cada paquete generado, con su
SHA-256 y quién lo descargó). Columna `investigation_id` en `response_executions`.

Acciones nuevas del catálogo 5D (agente, solo lectura, categoría `forensic`):
`forensic_processes`, `forensic_connections`, `forensic_services`, `forensic_scheduled_tasks`,
`forensic_persistence`, `forensic_sessions`, `forensic_network_config`,
`forensic_firewall_state`, `forensic_file_metadata` (parámetro `path` validado por el servidor y
de nuevo por el agente contra `forensics.allowed_roots` local; tamaño máximo para el hash; MEDIUM:
solo admin). El agente rechaza cualquier parámetro que no sea el previsto.

Integridad: el agente calcula SHA-256 del JSON canónico de la evidencia y el servidor lo
recalcula; si no coinciden, el artefacto queda `integrity_mismatch` y no se puede empaquetar sin
aviso. El paquete (`GET /investigations/{id}/package`) es un ZIP con `manifest.json` (artefactos,
hashes, cadena de custodia desde la auditoría), `evidence/` y `interpretations/` (notas y resúmenes
de IA etiquetados como interpretación). Su SHA-256 va en `X-Sentra-SHA256` y queda registrado.

Permisos: `forensics:read` y `forensics:acquire` (analista y admin), `forensics:download`
(analista y admin, auditado), `forensics:manage` (admin: cerrar, reabrir, legal hold).

## 6E.7 Aislamiento seguro

Principios: desactivado por defecto en **dos** sitios (servidor `ISOLATION_ENABLED=false` y
política local del equipo), iniciado solo por un admin con `containment:isolate`, con
confirmación escrita (nombre del equipo), duración máxima, previsualización de impacto y
reversión local que no depende del servidor.

Modelo de privilegios (decidido por Jesus el 2026-10-22): el agente sigue sin
privilegios. Un **helper de aislamiento** opcional y separado (`sentra-isolation`, servicio de
Windows como LocalSystem / unidad systemd como root) es el único que toca el firewall. Lee su
propia política local (`isolation.toml`, `enabled=false` por defecto, `max_minutes`,
`extra_allow`), recibe del agente solo `{session_id, action, expires_at}` por un fichero con ACL,
calcula él mismo qué se permite (IPs del servidor Sentra a partir de la URL configurada del
agente, loopback, DHCP, DNS configurados, `extra_allow` local) y aplica la expiración por su
cuenta. Un servidor o un agente comprometidos no pueden abrir agujeros ni aislar más allá de lo
que permite la política local.

- Windows: reglas de bloqueo de Windows Defender Firewall en el grupo `Sentra Isolation`
  (bloqueo de todo salvo el complemento de las direcciones permitidas; en Windows un bloqueo
  prevalece sobre un permiso). No se deshabilita el firewall ni se tocan reglas del usuario ni
  perfiles. Si un perfil activo está desactivado, la precomprobación falla (`firewall_disabled`).
  Reversión: borrar solo las reglas del grupo; tarea programada de respaldo como SYSTEM a la hora
  de expiración y comprobación al arrancar.
- Linux: tabla propia `inet sentra_isolation` de nftables (no toca tablas de firewalld/ufw).
  No se aplica si solo hay iptables-legacy. Reversión: borrar la tabla; la tabla no es
  persistente, así que un reinicio restaura la red.
- macOS: no se habilita en 6E (pf con reversión garantizada queda pendiente); el agente no
  anuncia la capacidad y la UI muestra «Aislamiento no disponible para este dispositivo».
- Dispositivos sin agente: siempre «Aislamiento no disponible para este dispositivo», con
  recomendaciones manuales.

Estados (`isolation_sessions`, 0043): `requested` → `approved` → `applying` → `isolated` →
`reverting` → `restored`, más `failed`, `expired` y `unknown`. `isolated` solo con confirmación
del helper (reglas verificadas leyéndolas de vuelta). El heartbeat del agente informa el estado
real del helper; si el servidor y el equipo discrepan, el estado pasa a `unknown` y se alerta.

Permisos: `containment:preview` (analista y admin), `containment:isolate` y
`containment:release` (admin).

## 6E.8 / 6E.9 Agente 0.5.0 y sensor 0.6.0

Capacidades declarativas nuevas del agente (solo si funcionan en ese equipo):
`telemetry.activity`, `telemetry.process_tree`, `telemetry.process_network`,
`telemetry.sysmon` (Windows con canal legible), `forensic_*` (una por acción),
`isolate_host` y `release_isolation` (solo si el helper está instalado, habilitado y sano).
El servidor nunca encola un comando cuya capacidad el agente no anunció (regla de 5D).

Cola offline de actividad: fichero persistente acotado (`activity_queue_max_events`, 20 000) con
descarte del más antiguo y contador de descartados que se informa en `stats` y en el diagnóstico.

## Seguridad transversal

- RBAC: permisos nuevos separados; ver/telemetría nunca implica responder.
- Todas las rutas nuevas pasan por CSRF, auditoría y filtro de site existentes.
- Acceso a datos sensibles auditado (`evidence_package_downloaded`). La lectura de líneas de
  comandos no tiene auditoría propia (`telemetry_cmdline_read` no se implementó); la protege
  `telemetry:read`.
- IA: sin cambios; solo bajo demanda, nunca decide severidad, riesgo ni acciones.

## Documentos

`topology-history.md`, `dhcp-identity.md`, `endpoint-telemetry-agent.md`, `process-tree.md`,
`behavioral-detection.md`, `forensic-investigation.md`, `safe-isolation.md`,
`agent-upgrade-0.5.md`, `sensor-upgrade-0.6.md`, `fase-6e-migrations.md`,
`fase-6e-recovery.md`, `fase-6e-known-issues.md`, `compatibility-matrix.md` (actualizado).
