# Threat Intelligence & Exploitability Context (Fase 5C)

Sentra añade **contexto externo** a lo que ya sabe de sus activos:

- **explotabilidad de vulnerabilidades**: CISA KEV (explotación conocida reportada) y FIRST
  EPSS (probabilidad de explotación) sobre los findings de 5B;
- **indicadores (IOCs)** importados por un administrador (formato `sentra-ioc/1` o STIX 2.x)
  que se buscan, solo por coincidencia exacta, en la telemetría que Sentra ya recoge.

Fuentes, formatos y su contrato: [threat-intel-sources.md](threat-intel-sources.md). Subset
STIX admitido: [stix-support.md](stix-support.md).

Principios:

- **La inteligencia es contexto, no un veredicto.** Que un CVE esté en KEV significa que
  CISA tiene evidencia de explotación *en algún sitio*; no que este activo haya sido
  explotado ni que sea vulnerable (eso lo decide el matcher 5B con el inventario). EPSS es
  un modelo estadístico, no un "% de vulnerabilidad". Un match de IOC dice "este dato local
  coincide con un indicador que la fuente X clasifica como Y", no "equipo comprometido".
  Vocabulario usado en toda la UI y la API: *Known exploited* / "Explotación conocida
  reportada", *High exploitation likelihood*, *EPSS exploitation probability*. Nunca
  "Exploitable", "Exploited on this server" ni "90 % vulnerable" (hay un test que lo vigila).
- **Offline-first.** Sin ninguna fuente configurada Sentra funciona igual y muestra *"No
  intelligence source configured"*. Las descargas por red están **apagadas**
  (`THREAT_INTEL_SYNC_ENABLED=false`); todo puede cargarse con ficheros por la CLI o la UI.
  La readiness (`/health/ready`) nunca depende de la inteligencia.
- **Procedencia de cada dato.** Cada registro guarda su fuente, nivel de confianza
  (`official`, `trusted`, `local`, `community`), fecha de obtención y versión del feed. Si
  dos fuentes discrepan, la UI las muestra **lado a lado** (`conflicting: true`); Sentra no
  elige una en silencio.
- **Coincidencia exacta.** IP, red CIDR, dominio y hostname contra datos locales; sin
  difusa, sin subcadenas. Hashes, URLs y emails se importan y se pueden consultar, pero se
  marcan como **"unsupported"** para el matching: el agente no recoge esos datos.
- **Reutiliza lo existente.** Prioridad 5B, motor de detección 4H, riesgo 4I, incidentes 4K,
  IA 4J, auditoría, RBAC y métricas: sin motores paralelos.

## Reutiliza lo existente

| Pieza | Uso en 5C |
|-------|-----------|
| Findings 5B | `intel_cve` por finding, KEV/EPSS en la lista, el detalle y la prioridad (fórmula v2) |
| Motor de detección 4H | Regla `TI-001 Threat Intel IOC Match` por la cola de señales de siempre, solo según política |
| Risk Engine 4I | Fórmula v4: multiplicador de explotabilidad de findings y contribución de matches de IOC |
| Incidentes 4K | "Crear incidente" desde un match (siempre manual) y snapshot de KEV/EPSS al vincular un finding |
| AI Insights 4J | KEV/EPSS y matches entran en el contexto como datos; sin acciones |
| Jobs de fondo, advisory locks, auditoría, métricas, backups 4M | Sin mecanismos nuevos |

## Fuentes y sincronización

La migración siembra tres fuentes:

| Clave | Proveedor | Estado inicial |
|-------|-----------|----------------|
| `cisa-kev` | `cisa_kev`, confianza `official` | **desactivada** |
| `first-epss` | `first_epss`, confianza `official` | **desactivada** |
| `local-iocs` | `local_import`, confianza `local` | activada, sin red (importaciones manuales) |

Activar una fuente es decisión del admin. Una fuente activada pero sin datos todavía no
cuenta como "configurada". El admin puede crear más fuentes (`POST /threat-intel/sources`):
otra fuente local de IOCs o un **espejo interno** de KEV/EPSS. La API **nunca acepta una
URL**: un campo `url` en el cuerpo es 422. La URL de cada fuente es la oficial del adapter o
la que fije el servidor en `THREAT_INTEL_SOURCE_URLS` (`clave=https://...`); la API solo
devuelve el host (`download_host`).

Sincronizar por red exige `THREAT_INTEL_SYNC_ENABLED=true`. Pedirlo desde la UI
(`POST /sources/{id}/sync`) solo **marca** la fuente; la descarga la hace el job
(`threat-intel`, cada `THREAT_INTEL_EVAL_INTERVAL_SECONDS`) o la CLI. Cada sincronización o
importación:

1. toma un **advisory lock** de PostgreSQL por fuente (nunca dos a la vez sobre la misma);
2. descarga **fuera** de la transacción, con peticiones condicionales (**ETag** /
   `If-Modified-Since`: un 304 no toca nada) y las defensas SSRF de abajo, a un fichero
   temporal con tope de tamaño;
3. valida y parsea en streaming, copia a **staging** (`COPY` a una tabla temporal) y aplica
   nuevos/cambiados/sin cambios/desaparecidos con pocas sentencias por conjuntos, en **una
   transacción**;
4. si algo falla antes del commit no queda nada a medias: la fuente conserva su última
   inteligencia válida (*"Using cached intelligence"*), apunta `status`/`last_error` y deja
   la sincronización en el historial;
5. un feed completo sospechosamente pequeño (menos de la mitad de los registros anteriores,
   cuando había al menos 1000) se rechaza (`intel_feed_shrunk`) en lugar de "retirar" medio
   catálogo;
6. encola solo los findings y activos afectados por cambios materiales.

Una fuente con más de `stale_after_hours` sin sincronizar queda **stale**: sigue sirviendo,
la UI lo dice con la fecha de la última sincronización correcta, la prioridad y el riesgo
reducen su aporte a la mitad. Nunca se borra nada por caducar. Desactivar una fuente quita
su influencia en prioridad, riesgo y matching **a la vez** (lo decide un solo módulo,
`app/threat_intel/lookup.py`) sin borrar su historial; archivarla es el "borrado": los
matches, el historial y los incidentes la siguen citando.

### Protección SSRF (`app/threat_intel/http.py`, solo stdlib)

- solo `https` (en desarrollo `http` únicamente hacia una red autorizada), sin credenciales
  en la URL ni esquemas `file`, `ftp`, `gopher`, `data`...;
- el host se resuelve una vez y **todas** sus IPs deben ser públicas o estar en
  `THREAT_INTEL_ALLOWED_NETWORKS`. Loopback, link-local (incluye `169.254.169.254`),
  multicast, reservadas, CGNAT, NAT64/6to4 y redes privadas no autorizadas se bloquean;
- **DNS rebinding**: se conecta a la IP ya validada y se comprueba la IP real del socket
  antes de enviar nada; TLS verifica el certificado contra el nombre original;
- como mucho 3 redirecciones, cada una revalidada, nunca de https a http;
- plazos de conexión, lectura y total; tope de bytes en streaming; sin proxy del entorno;
- los errores no incluyen la URL completa ni el cuerpo de la respuesta.

Un IOC **nunca** se visita, resuelve ni descarga.

## Importación manual de IOCs

`Inteligencia → Importar` (admin) o la CLI. En la UI es en dos pasos:

1. `POST /threat-intel/import/preview` valida el fichero y devuelve qué haría (nuevos,
   actualizados, sin cambios, inválidos con su motivo, objetos STIX fuera del subset, tipos
   no casables) y su **sha256**. No escribe nada;
2. `POST /threat-intel/import` con `expected_sha256`: si el contenido no es exactamente el
   previsualizado, 409 `threat_intel_changed`. Con registros inválidos es todo o nada salvo
   `skip_invalid: true`.

`classification` es obligatoria en `sentra-ioc/1`: aparecer en un fichero no hace malicioso a
un valor. Una importación nunca desactiva los indicadores que falten en el fichero (las
fuentes locales se mantienen indicador a indicador: revocación, `valid_until`). Ficheros
grandes: CLI (`threat-intel-import`).

## Matching con datos locales

El job compara los indicadores activos (no revocados, dentro de `valid_from`/`valid_until`)
con:

| Observación | Dato de Sentra |
|-------------|----------------|
| `auth_source_ip` | IP de origen de inicios de sesión Windows 4624/4625 (`system_events.data.IpAddress`) |
| `connection_remote_ip` | IP remota de conexiones **establecidas** del último inventario |
| `asset_address` | IP principal de un activo conocido |
| `asset_name` | hostname o DNS inverso de un activo (visibilidad parcial: Sentra no recoge consultas DNS) |

Escala sin bucles por IOC: incremental hacia delante con cursores (eventos por id,
inventarios por `received_at`) y un único JOIN por índice (igualdad y GiST para CIDR) contra
todos los indicadores; retroactivo solo para indicadores nuevos o cambiados (eventos de los
últimos 30 días, inventarios actuales y activos). Repetir no duplica (un match por
indicador + activo + observación + valor, con contador y primera/última vez).

Un indicador revocado, caducado o reclasificado actualiza sus matches (historial
`indicator_reclassified`); la memoria de un match pasado se conserva a la mitad en el riesgo.

### Triage

`open` → `acknowledged` → `dismissed` (falso positivo) y `reopen`. Descartar y reabrir exigen
**motivo escrito**; cada acción usa la `version` vista (409 `threat_intel_conflict` si cambió)
y queda auditada (`threat_intel_match_updated`). "Crear incidente" (requiere además
`incidents:manage`) abre un incidente 4K vinculado al match; **nunca con confianza alta** y
nunca automático.

## Detección (TI-001)

Un match nuevo genera una señal `threat_intel_match` y el motor 4H decide según
`THREAT_INTEL_DETECTION_POLICY`:

| Política | Crea TI-001 cuando |
|----------|--------------------|
| `off` | nunca (solo contexto) |
| `high_confidence_malicious` (por defecto) | `malicious` y confianza **alta** del indicador y del match |
| `malicious` | `malicious` con confianza alta o media |

Solo IPs y redes (auth y conexiones). Severidad alta solo para malicioso de confianza alta;
confianza alta solo si además la fuente es `official` o `trusted`. **Nunca crítica.** La
detección enlaza al match y viceversa.

## Prioridad de findings (5B, fórmula v2)

| Factor | Puntos |
|--------|--------|
| KEV (explotación conocida reportada) | +10 |
| EPSS alta (≥ 0,5) / elevada (≥ 0,1) | +6 / +3 |

Ponderados por la solidez del match (mínimo 0,45 para que una potencial no gane mucho), con
tope conjunto de 14 y a la mitad si la fuente está stale. Cada factor aparece con sus puntos
en el detalle ("Explotación conocida reportada (CISA KEV)", "Probabilidad de explotación
EPSS alta (91,2 %)").

## Riesgo (4I, fórmula v4)

- **Findings**: multiplicador de explotabilidad solo para `confirmed` y `probable` (cuenta el
  mayor, no se suman): KEV ×1,35, EPSS alta ×1,2, elevada ×1,1. Fuente stale: la mitad del
  incremento. Una potencial no gana nada: la duda es si el activo es vulnerable.
- **Matches de IOC**: `malicious` 30 / `suspicious` 12 puntos (`unknown` y `benign` nada) ×
  confianza del match (alta 1, media 0,7, baja 0,4) × confianza de la fuente (official 1,
  trusted 0,9, local 0,85, community 0,7) × estado (open 1, acknowledged 0,85, dismissed 0)
  × indicador inactivo 0,5, con vida media de 72 h y olvido a los 30 días. Un IOC malicioso
  de confianza alta aporta como mucho 30: medio, nunca "crítico" por sí solo. La
  contribución enlaza al match (`threat_match_id`); si el match tiene detección TI-001, se
  agrupan (sin doble conteo).

## IA

El contexto de análisis de activos, incidentes y findings incluye KEV/EPSS con su fuente y
los matches como **datos** (nunca en las instrucciones). Las descripciones de IOCs y STIX son
texto no confiable: acotadas y sin URLs. Solo lectura.

## RBAC

| Permiso | viewer | analyst | admin |
|---------|--------|---------|-------|
| `threat_intel:read` (resumen, fuentes, indicadores, matches, inteligencia de un finding) | ✓ | ✓ | ✓ |
| `threat_intel:triage` (reconocer, descartar, reabrir, crear incidente con `incidents:manage`) | | ✓ | ✓ |
| `threat_intel:manage` (fuentes, sincronizar, importar, reevaluar) | | | ✓ |

## API

| Método | Ruta | Permiso |
|--------|------|---------|
| GET | `/threat-intel/overview` | read |
| GET | `/threat-intel/sources`, `/sources/{id}/syncs` | read |
| POST | `/threat-intel/sources`, PATCH `/sources/{id}` | manage |
| POST | `/threat-intel/sources/{id}/enable`, `/disable`, `/archive`, `/sync` | manage |
| GET | `/threat-intel/indicators` (filtros `type`, `classification`, `confidence`, `source_id`, `state`, `matched`, `tag`, `q` prefijo), `/indicators/{id}` | read |
| GET | `/threat-intel/matches` (filtros `status`, `active`, `classification`, `observation_type`, `asset_id`, `source_id`), `/matches/{id}` | read |
| POST | `/threat-intel/matches/{id}/acknowledge`, `/dismiss`, `/reopen`, `/incident` | triage |
| POST | `/threat-intel/import/preview`, `/threat-intel/import`, `/threat-intel/reevaluate` | manage |
| GET | `/vulnerabilities/findings/{id}/threat-intel` | read + `vulnerabilities:read` |
| GET | `/vulnerabilities/findings?kev=true&epss_min=0.5&intel_stale=false` | `vulnerabilities:read` |

Errores propios: `threat_intel_sync_disabled`, `threat_source_manual`,
`threat_source_disabled`, `threat_intel_changed`, `threat_intel_conflict`,
`intel_invalid_format`, `intel_invalid_json`, `intel_too_large`, `intel_too_deep`,
`intel_too_many_records`, `intel_invalid_records`, `intel_feed_shrunk`.

## CLI

```powershell
python -m app.cli threat-intel-status
python -m app.cli threat-intel-import --source cisa-kev known_exploited_vulnerabilities.json
python -m app.cli threat-intel-import --source first-epss epss_scores-2026-10-06.csv.gz
python -m app.cli threat-intel-import --source local-iocs iocs.json [--format stix] [--skip-invalid]
python -m app.cli threat-intel-sync [--source cisa-kev]   # requiere THREAT_INTEL_SYNC_ENABLED
```

Importar a una fuente desactivada está permitido: los datos quedan inertes hasta activarla.

## Variables de entorno

| Variable | Por defecto | Uso |
|----------|-------------|-----|
| `THREAT_INTEL_ENABLED` | `true` | Job de matching y sincronización (sin fuentes no hace nada) |
| `THREAT_INTEL_SYNC_ENABLED` | `false` | Descargas por red de KEV/EPSS |
| `THREAT_INTEL_SOURCE_URLS` | vacío | URL de una fuente si no es la oficial: `cisa-kev=https://espejo/kev.json,...` |
| `THREAT_INTEL_ALLOWED_NETWORKS` | vacío | Redes privadas permitidas como destino (espejo interno) |
| `THREAT_INTEL_DEFAULT_INTERVAL_HOURS` | 24 | Intervalo de una fuente nueva |
| `THREAT_INTEL_HTTP_TIMEOUT_SECONDS` | 120 | Plazo total de una descarga |
| `THREAT_INTEL_MAX_DOWNLOAD_MB` | 128 | Tamaño máximo de descarga o fichero de CLI |
| `THREAT_INTEL_MAX_RECORDS` | 1 000 000 | Registros/objetos por importación |
| `THREAT_INTEL_BATCH_SIZE` | 5000 | Filas por lote (staging, matching retroactivo) |
| `THREAT_INTEL_DETECTION_POLICY` | `high_confidence_malicious` | Cuándo un match crea TI-001 |
| `THREAT_INTEL_EVAL_INTERVAL_SECONDS` | 60 | Cada cuánto corre el job |

## Auditoría y observabilidad

Auditoría: `threat_source_created`, `threat_source_updated`, `threat_source_enabled`,
`threat_source_disabled`, `threat_source_archived`, `threat_sync_requested`,
`threat_sync_started`, `threat_sync_completed`, `threat_sync_failed`,
`threat_import_previewed`, `threat_imported`, `threat_intel_reevaluation_requested`,
`threat_intel_match_created`, `threat_intel_match_updated`, `threat_intel_incident_created`.

`/api/v1/metrics` añade `sentra_threat_intel_syncs_total`,
`sentra_threat_intel_sync_records_total` y `sentra_threat_intel_sync_seconds_total` (por
`provider` y `result`) y `sentra_threat_intel_matches_total{outcome=created|updated}`. Ningún IOC, CVE ni
hostname va como etiqueta.

## Rendimiento

`qa/perf_threat_intel.py` con datos sintéticos, medido en un contenedor Linux con PostgreSQL
16 local (pendiente de medir en el hardware del servidor real):

| Operación | Resultado |
|-----------|-----------|
| KEV de 2 000 entradas (ruta de la CLI) | 0,3 s |
| EPSS de 300 000 filas (gzip): primera vez / idéntico / "día siguiente" con todo cambiado | 14 s / 13 s / 30 s |
| 100 000 IOCs: previsualizar / importar | 4,3 s / 6,3 s |
| Matching retroactivo (90 000 indicadores × 2 000 activos con 20 conexiones, 50 000 eventos 4625; 54 000 matches, caso extremo) | 155 s |
| Vuelta incremental sin datos nuevos | 16 ms |
| Resumen / indicadores (filtro o prefijo) / coincidencias | 154 ms / 37-66 ms / 14 ms, 2-7 sentencias SQL |
| KEV/EPSS de 50 000 CVE de una vez | 4,4 s, 10 sentencias |

Las sentencias SQL por petición son constantes (sin N+1). Dos problemas salieron en esta
medición y están corregidos: el plan genérico que PostgreSQL elegía tras 5 ejecuciones de la
misma consulta de candidatos (de 30 ms a ~1 s por lote; ahora `plan_cache_mode =
force_custom_plan` local a la transacción, matching ×2,2) y un anti-join que, con
estadísticas vacías tras borrados masivos, hacía un Seq Scan por fila al insertar (80 s para
100 000 IOCs; ahora `ON CONFLICT DO NOTHING`, 6 s).

## Migración 0027

Crea `threat_intel_sources` (con las tres fuentes sembradas), `threat_intel_syncs`,
`vulnerability_intel`, `threat_indicators`, `threat_intel_matches`, `threat_intel_changes`,
`threat_intel_cursors` e `incident_threat_matches`; añade `vulnerability_findings.intel_cve`
(rellenada al migrar para los findings cuyo identificador ya es un CVE; los que solo lo tienen
como alias se completan en su siguiente evaluación), `incident_vulnerabilities.intel_snapshot`
y `resolved_intel_snapshot`, y un índice parcial de `system_events` por `data->>'IpAddress'`.

**Downgrade**: borra esas tablas, columnas e índices. Se pierden las fuentes, toda la
inteligencia importada, los indicadores, los matches y su triage, el historial de cambios y
los vínculos incidente ↔ match (los incidentes se conservan). Las detecciones TI-001 ya
creadas se quedan como detecciones normales. Hacer backup antes (Fase 4M); KEV, EPSS e IOCs
se reimportan desde sus ficheros.

## Limitaciones

- Sin red por defecto: la primera validación con los feeds reales (formato vigente de KEV y
  EPSS, ETag de los servidores oficiales, proxy corporativo) queda pendiente con Internet.
- Matching de dominios solo contra nombres de activos; sin consultas DNS, URLs, hashes de
  ficheros ni emails (el agente no los recoge).
- El cursor de eventos avanza por id: un evento confirmado fuera de orden por una transacción
  más lenta puede saltarse en la vuelta incremental (lo recoge la siguiente reevaluación).
- TAXII 2.1, avisos de fabricante y proveedores comerciales: solo el contrato documentado.
- Sin bloqueo, aislamiento ni ninguna acción automática sobre los equipos.
