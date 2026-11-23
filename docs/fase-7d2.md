# Fase 7D.2: resiliencia de ingesta, cadena de suministro y CI

Segunda y última entrega de la Fase 7D. Cierra los hallazgos H06 a H08 del informe de seguridad
del 2026-11-05 sobre el código de 7D.1 (H01 a H05). Versiones: servidor y frontend **0.7.1**,
agente **0.7.1**, sensor sin cambios (0.7.0). Migración **0052**.

La matriz de cierre completa está en `AUDITORIA-7D.md` (paquete de entrega); el resumen, en la
sección "Estado de H01 a H08" al final de este documento.

## H06: cuotas de ingesta por identidad

### Problema revalidado sobre 7D.1

Solo `POST /agents/register` (por IP) y `POST /agents/activity` (lotes por agente) tenían
límite. `/events`, `/telemetry`, `/inventory`, `/processes`, `/agents/heartbeat`, la rotación y
los comandos de Response no tenían ninguno: un agente comprometido o defectuoso podía llenar la
base, el motor de detección y el pool de conexiones.

### Diseño

Código: `backend/app/core/ingest_quota.py` y `backend/app/api/ingest.py`.

- **Identidad**: la cuota es del `agent_id` **después** de validar su credencial. Una petición
  sin token válido recibe 401 y no gasta el cupo de nadie, así que conocer un `agent_id` no
  permite dejar sin cupo a ese agente. No se usa la IP (varios agentes tras un NAT no
  comparten cuota).
- **Cubos de tokens** (tasa sostenida + ráfaga acotada). Cada petición gasta, de forma atómica,
  de varios cubos a la vez y, si cualquiera no alcanza, no gasta de ninguno:

  | Cubo | Clave | Coste |
  |------|-------|-------|
  | Peticiones del agente por clase de ruta | `agent:<id>:<clase>` | 1 |
  | Eventos del agente | `agent:<id>:events` | eventos del lote (`/events` y `/agents/activity`) |
  | Bytes del agente | `agent:<id>:bytes` | bytes del cuerpo recibido |
  | Peticiones globales | `global:requests` | 1 |
  | Eventos globales | `global:events` | eventos del lote |
  | Bytes globales | `global:bytes` | bytes del cuerpo |

  Clases de ruta: `control` (heartbeat, rotación, comandos), `telemetry`, `events`,
  `inventory`, `processes`, `activity`. Cada clase tiene su propio cubo de peticiones: vaciar
  el buffer de telemetría tras una caída no deja sin cupo a los eventos ni al heartbeat.
- **Heartbeat protegido**: la clase `control` solo gasta de su cubo de peticiones y de la
  concurrencia; no gasta de eventos, bytes ni de los cubos globales. Un agente que agota su cupo
  de datos sigue latiendo y no aparece offline por estar limitado; una saturación global no
  marca como offline a toda la flota.
- **Bytes reales**: se cobra el cuerpo que llegó (ya acotado por `MAX_REQUEST_BYTES`), no
  `Content-Length`, que un cliente podría omitir. En `/agents/activity`, los bytes comprimidos
  tal como llegaron.
- **Concurrencia**: peticiones simultáneas por agente (`AGENT_QUOTA_MAX_CONCURRENT`) y totales
  (`INGEST_MAX_CONCURRENT`) **por worker**, en memoria. Su objetivo es proteger los hilos y el
  pool de conexiones de cada proceso, que son locales por naturaleza. No espera: rechaza al
  momento con `Retry-After: 3`.
- **Backpressure antes del trabajo**: orden de cada petición: hueco de concurrencia global →
  autenticación → hueco del agente → cubos → servicio. El 429 llega antes de cualquier escritura,
  alerta o evaluación de detecciones.
- **429 con `Retry-After`**: entero en segundos, redondeado hacia arriba y con 1 s de colchón,
  calculado como el tiempo que necesita el cubo que más tarda en tener margen. Cuerpo:
  `{"error": {"code": "rate_limited", "details": [{"reason": "<motivo>"}]}}` con motivo
  `agent_requests`, `agent_events`, `agent_bytes`, `agent_concurrency`, `global_requests`,
  `global_events`, `global_bytes` o `global_concurrency`. Sin secretos.
- **Idempotencia y deduplicación**: como el 429 no escribe nada, el reenvío posterior del agente
  se procesa con las reglas de siempre (`sample_id`, `record_id`, `batch_id`/`event_uid`): sin
  duplicados ni pérdidas. Un reenvío de datos ya guardados también gasta cupo (la deduplicación
  ocurre al escribir); por eso la ráfaga de eventos debe cubrir el mayor atraso de un ciclo del
  agente (validado al arrancar: al menos 2500 eventos).

### Varios procesos del backend

| Almacén | Cuándo | Garantía |
|---------|--------|----------|
| `DatabaseBucketStore` (tabla `ingest_quota_buckets`, migración 0052) | `RATE_LIMIT_BACKEND=database`, o `auto` con `ENVIRONMENT=production` | Global entre workers y procesos. Una transacción corta y propia por petición; filas bloqueadas con `FOR UPDATE` en orden de clave (sin sobregasto ni interbloqueos); hora de PostgreSQL. Si PostgreSQL no responde: 503 (falla cerrado). |
| `MemoryBucketStore` | `memory`, o `auto` fuera de producción | **Solo un worker.** Con N workers cada uno tendría su cupo y el límite efectivo se multiplicaría por N. No es una garantía global. |

La concurrencia es siempre por worker (ver arriba). Sin Redis ni Docker: PostgreSQL ya es
obligatorio y el volumen es pequeño (como mucho 8 filas por agente y 3 globales; los cubos sin
uso durante un día se purgan solos).

Coste medido en el contenedor de la nube (PostgreSQL 16 en la misma máquina, 2026-11-09): una
transacción de tres sentencias más la actualización de cada cubo; 1,8 ms por petición de datos
(7 cubos) y 1,7 ms por heartbeat (1 cubo) en un hilo, y unas 417 peticiones/s con 16 hilos
concurrentes (unas 25 000 por minuto, cuatro veces el límite global por defecto). Las filas
globales son el punto de contención (todas las peticiones de datos las actualizan); con la flota
de Jesus (decenas de agentes, una petición por agente y clase cada 30-60 s) no es significativo.
Por encima de miles de agentes convendría repartir el cubo global en varias filas (trabajo
posterior, no necesario hoy). Falta medirlo en Windows con PostgreSQL 18.

### Valores por defecto

Holgados a propósito: un agente sano (heartbeat y telemetría cada 30 s, eventos y procesos cada
60 s, inventario cada 15 min) usa menos del 5 % de cada cupo. Todos son configurables y `0`
desactiva una dimensión concreta.

| Variable | Defecto | Significado |
|----------|---------|-------------|
| `AGENT_QUOTA_ENABLED` | `true` | Interruptor general (false = sin cuotas ni límites de concurrencia) |
| `AGENT_QUOTA_REQUESTS_PER_MINUTE` | `120` | Peticiones por agente, minuto y clase de ruta |
| `AGENT_QUOTA_EVENTS_PER_MINUTE` | `6000` | Eventos por agente y minuto |
| `AGENT_QUOTA_BYTES_PER_MINUTE` | `16777216` (16 MiB) | Bytes de cuerpo por agente y minuto |
| `AGENT_QUOTA_BURST_MINUTES` | `3` | Minutos de cupo acumulables (ráfaga) |
| `AGENT_QUOTA_MAX_CONCURRENT` | `4` | Peticiones simultáneas por agente y worker |
| `INGEST_GLOBAL_REQUESTS_PER_MINUTE` | `6000` | Peticiones de datos de todos los agentes |
| `INGEST_GLOBAL_EVENTS_PER_MINUTE` | `200000` | Eventos de todos los agentes |
| `INGEST_GLOBAL_BYTES_PER_MINUTE` | `536870912` (512 MiB) | Bytes de todos los agentes |
| `INGEST_GLOBAL_BURST_MINUTES` | `1` | Ráfaga global |
| `INGEST_MAX_CONCURRENT` | `32` | Peticiones de ingesta simultáneas por worker |

Validaciones al arrancar: la ráfaga de eventos cubre al menos 2500 eventos, y los cubos de bytes
no pueden ser menores que `MAX_REQUEST_BYTES` (una petición legítima de tamaño máximo nunca
cabría).

Pendiente de decisión de Jesus con datos reales: ajustar los valores con el volumen medido de
sus equipos (`capacity-report` y la métrica de rechazos ayudan a hacerlo).

### Observabilidad

- `GET /agents` y `GET /assets/{id}/agent`: `ingest_throttled_at` (último 429 por cuota) y
  `ingest_rejections` (rechazos acumulados, como mucho el último día). Resumen:
  `summary.throttled` = agentes activos con un 429 en los últimos 15 minutos.
- Panel: aviso en Agentes cuando `summary.throttled > 0` y campo "Cuota de ingesta" en el panel
  del agente del activo.
- `/metrics` (si está activado): `sentra_ingest_quota_rejections_total{route,reason}` (por
  worker; nunca por agente, la cardinalidad crecería con la flota) y `sentra_ingest_in_flight`.
- Con el almacén en memoria, el estado de limitación del panel es el de ese proceso.

### Agente 0.7.1

El agente ya trataba el 429 como temporal (7D.1 y anteriores): conserva el buffer persistente de
telemetría, no confirma el cursor de eventos, conserva la cola de actividad, no se vuelve a
enrolar y no descarta su credencial. 0.7.1 añade:

- espera de al menos `Retry-After` con un jitter del 0 al 25 % (sin él, una flota limitada a la
  vez por la cuota global volvería en el mismo segundo), sin superar `max_backoff_seconds`;
- mensaje de log propio (`API throttled the agent`) para distinguir una cuota de una caída.

Pruebas: `agent/tests/test_quota_7d2.py`.

### Retención y capacidad

Estado revalidado (sin cambios de comportamiento en 7D.2):

| Dato | Ajuste | Defecto |
|------|--------|---------|
| Telemetría, eventos, cambios de inventario, alertas resueltas, detecciones resueltas, historial de riesgo, observaciones de discovery | `*_RETENTION_DAYS` | Sin purga (se conserva todo) |
| Actividad de endpoint / instancias de proceso terminadas | `TELEMETRY_ACTIVITY_RETENTION_DAYS` / `PROCESS_INSTANCE_RETENTION_DAYS` | 14 / 30 días (desde 6E) |
| Topología, DHCP, identidad | ajustes de 6D/6E | Ver `docs/configuration.md` |
| Auditoría | — | Sin retención automática |

Novedades:

- **Purgas auditadas**: cada purga que borra algo (job periódico o `purge-old-data`) escribe
  un evento de auditoría `retention_purge` con los recuentos por tabla y el origen
  (`scheduled`/`cli`). Nunca contenido. Una purga vacía no escribe nada.
- **Informe de capacidad de solo lectura**: `python -m app.cli capacity-report [--exact]
  [--output fichero.json]`. Tamaño en disco y filas estimadas por tabla (estadísticas del
  catálogo, sin recorrer tablas); con `--exact`, fila más antigua y cuántas filas superan la
  retención configurada (vista previa de lo que borraría la purga). Nunca borra.
- Ninguna retención nueva se activa. La instalación de 7D.2 no elimina ningún dato.

Política recomendada (decisión de Jesus): ejecutar `capacity-report --exact` en la base
productiva mensualmente fuera de horas, y fijar `TELEMETRY_RETENTION_DAYS` y
`EVENT_RETENTION_DAYS` solo cuando el crecimiento lo justifique, tras un backup.

## H07: dependencias y cadena de suministro

### Frontend

- `npm audit` (2026-11-09, antes): 10 avisos moderados, todos derivados de un único advisory,
  GHSA-g3hv-75wg-m249 (`minimatch` >=7.0.0 <11.0.1, CWE-405), que llega por `eslint` 10.12.0,
  `@eslint/config-array` 0.23.5 y `@typescript-eslint/typescript-estree` 8.71.0. Directos:
  `eslint`, `@eslint/js` y `typescript-eslint` (marcados solo porque contienen el transitivo).
  Producción (`--omit=dev`): 0.
- No existe un `minimatch` 10.x corregido y las últimas `eslint` (10.14.0) y `typescript-eslint`
  (8.72.1) siguen pidiendo `^10.2.x`. `npm audit fix --force` propone bajar a eslint 9 (cambio
  incompatible): descartado.
- Corrección: `overrides` en `frontend/package.json` fija `minimatch` a **11.0.5**. Verificado
  que las tres dependencias solo usan `Minimatch`, `minimatch()` y las opciones `dot`,
  `flipNegate` y `partial`, presentes en 11.x (lo eliminado en 11 es `makeRe` y `AST`, que no
  usan). Evidencia: ESLint analiza exactamente los mismos 351 ficheros con los mismos errores y
  avisos que con 10.2.6, y lint, typecheck, tests (Node 22 y 24) y build pasan.
- `npm audit` (después): **0** vulnerabilidades en total y 0 en producción.
- Dependencias nuevas transitivas por el override: `@isaacs/nonrecursive-glob-match` 1.1.0 y
  `brace-expansion` 5.0.12 (mismo autor que `minimatch`). Solo desarrollo.
- Cuando `eslint` y `typescript-eslint` publiquen versiones que acepten `minimatch` 11, se
  quitará el override (ver la guía de actualización).

### Python (backend, agente, sensor)

- `pip-audit` 2.10.1 sobre `backend/requirements-dev.txt` y sobre todas las dependencias (con
  extras) de `agent/pyproject.toml` y `sensor/pyproject.toml`: sin vulnerabilidades conocidas
  (2026-11-09).
- Reproducibilidad: los requisitos son rangos compatibles (`>=x,<y`), no versiones exactas. Se
  mantiene así en 7D.2 (cambiar a ficheros de bloqueo con hashes afecta al flujo de instalación
  en Windows de Jesus y es una decisión aparte). Como control verificable, cada ejecución de CI
  publica un SBOM CycloneDX con las versiones exactas resueltas de cada paquete (artefacto
  `sbom`), y pip-audit se ejecuta sobre esa misma resolución. Recomendación posterior:
  `uv pip compile --universal --generate-hashes` para backend, agente y sensor.

## H08: repositorio y CI

### CI (`.github/workflows/ci.yml`)

- Acciones fijadas por **SHA completo** (la versión en comentario): `actions/checkout` v4.4.0,
  `actions/setup-python` v5.6.0, `actions/setup-node` v4.4.0, `actions/upload-artifact` v4.6.2.
  Son exactamente los commits a los que apuntaban las etiquetas `v4`/`v5` que ya usaba CI: cero
  cambio de comportamiento.
- `permissions: contents: read` en todo el workflow y `persist-credentials: false` en cada
  checkout (el token no queda en `.git/config` para los pasos siguientes).
- `concurrency` cancela ejecuciones anteriores de la misma rama; `timeout-minutes` por job.
- Disparadores: push a `main` y `Dev`, pull requests y ejecución manual.
- Nuevos pasos: `mypy --platform win32` en backend, agente y sensor; `mypy --no-incremental`;
  migraciones (`alembic upgrade head` + `alembic check`) sobre la base de CI; `npm run typecheck`;
  tests del frontend también con Node 24; `npm ci --ignore-scripts`.
- Job nuevo `supply-chain`: pip-audit (backend, agente, sensor), `npm audit` completo
  (bloquea desde moderado) y de producción (bloquea desde bajo), SBOM CycloneDX de todo
  (artefacto `sbom`, 30 días).
- Job nuevo `repo-hygiene`: `scripts/ci/check_repo_hygiene.py` falla si un fichero versionado es
  sensible (`.env` real, claves, certificados con clave, volcados, venvs, `node_modules`,
  `dist`, cachés, `agent/agent.toml`) o contiene un secreto con formato reconocible (claves
  privadas, tokens `sentra_et_`/`sentra_et_rec_`, GitHub, Slack, AWS, OpenAI). Nunca imprime el
  valor. **No** detecta secretos sin formato (contraseñas, credenciales de agente) ni revisa el
  historial: para eso, el secret scanning de GitHub con push protection (guía).
  Uso local antes de un commit: `python scripts/ci/check_repo_hygiene.py --include-untracked`.

Nombres de los checks para el Ruleset: ver [`github-rulesets.md`](github-rulesets.md).

### Protección de `main`

No se ha cambiado nada en GitHub. La guía [`github-rulesets.md`](github-rulesets.md) describe
exactamente qué configurar, con una política de recuperación administrativa deliberada y
auditable. H08 solo estará cerrado cuando Jesus aplique el Ruleset y compruebe que un push
directo y un force-push a `main` son rechazados.

## Mejoras complementarias revisadas

| Recomendación | Estado | Acción en 7D.2 |
|---------------|--------|----------------|
| Límites de lectura de respuestas del agente | Hecho en 7D.1 (H05) | Ninguna |
| TLS de PostgreSQL remoto | `production-check` avisa (WARN) si la base está en otro host sin `sslmode=require/verify-full` | Sin cambio: la base de Jesus es local. Convertirlo en FAIL es decisión de Jesus |
| Integridad de artefactos | Paquetes con SHA-256 (build Windows, Linux y macOS) y verificación Authenticode opcional (4F) | SBOM en CI. Firma comercial: posterior |
| Seguridad de instaladores | 7D.1: HTTPS obligatorio y migración guiada | Ninguna |
| Auditoría de operaciones sensibles | Credenciales, recuperación, revocación, IA, herramientas auditadas | Purgas de retención auditadas |
| Retención y protección de evidencias | Paquetes de evidencia y detecciones abiertas nunca se purgan | Informe de capacidad de solo lectura |
| Clasificación de datos enviados a la IA | 7C-Security-Fix1 y 7D.1 (H02/H03) | Ninguna |
| `AGENT_SERVER_URL` http en producción | 7D.1: aviso en la consola; el asistente no genera comandos con http | Sin cambio: rechazarla en el arranque cortaría un servidor que aún no tenga HTTPS. Decisión de Jesus cuando el suyo esté publicado por HTTPS |

Trabajo posterior (requiere infraestructura, certificados o decisiones): MFA administrativo
(TOTP), firma de instaladores (Authenticode, `.deb`, `.pkg` notarizado), PKI interna y mTLS de
agentes, ficheros de bloqueo Python con hashes, auditoría externa y envío de auditoría a un
sistema externo (WORM/SIEM).

## QA en Windows

`qa/windows-7d/`: plan conjunto de 7D.1 y 7D.2 (`PLAN-QA-7D.md`), comprobaciones estáticas y
suites (`run-checks-7d.ps1`), camino de migraciones con rollback y restauración sobre una base
aislada (`test-migrations-7d.ps1`) y carga con varios agentes contra un servidor de
laboratorio (`qa_ingest_quota_load.py`).

## Migración 0052 y rollback

Ver `MIGRACION-Y-ROLLBACK.md` en el paquete. Resumen: solo crea la tabla
`ingest_quota_buckets` (vacía, sin claves foráneas, sin tocar datos). `downgrade` la elimina
y solo pierde estado efímero de cuotas.

## Estado de H01 a H08

| Hallazgo | Estado tras 7D.2 |
|----------|------------------|
| H01-H05 | Corregidos en 7D.1, sin cambios funcionales en 7D.2; su regresión está en las suites |
| H06 | Corregido y probado (cloud). Pendiente: carga real en Windows con varios agentes |
| H07 | Corregido (`npm audit` 0/0, `pip-audit` 0). Override documentado hasta que eslint acepte minimatch 11 |
| H08 | Implementado en el repositorio (CI). **Abierto** hasta que Jesus aplique el Ruleset y lo verifique |
