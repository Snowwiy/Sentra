# Detección de comportamiento en endpoints (Fase 6E.5)

> Estado: implementado en el backend (`app/detection/behavior.py`, reglas `BEH-*` en
> `app/detection/rules.py`, `SignalRecorder.record_activity` en `app/detection/recorder.py`,
> excepciones en `app/detection/exclusions.py`). Probado con actividad sintética
> (`tests/test_endpoint_telemetry.py`); pendiente de verificar en equipos reales con el agente
> 0.5.0 y con software legítimo de cada entorno (falsos positivos).

Amplía el motor de detección de la Fase 4H ([detection-engine.md](detection-engine.md)); no es
un motor paralelo. La actividad que envía el agente 0.5.0 (`POST /agents/activity`, ver
[process-tree.md](process-tree.md)) se guarda entera como contexto, pero solo los eventos que
encajan en un patrón cerrado se convierten en señales, y las reglas `BEH-*` deciden severidad,
confianza, deduplicación y cooldown con el mismo motor, evidencia y alertas que el resto.

## Principios

- **Señal solo con patrón.** Un proceso normal no produce señal ni detección
  (`test_benign_process_creates_no_signal_and_no_detection`).
- **Listas cerradas y explicables**, no puntuaciones opacas.
- **Sin respuesta automática.** Ninguna regla aísla, termina procesos ni bloquea nada: abren
  una detección (y una alerta según severidad) para que una persona decida. Ni
  `app/detection` ni `app/endpoint` importan el Response Engine ni el aislamiento.
- **Sin IA en la severidad.** La severidad y la confianza las fijan la regla y su evaluador;
  ningún modelo interviene.
- **Una señal débil se queda débil.** Una ubicación inusual sin más contexto nunca pasa de
  confianza baja.
- **Herramientas legítimas por sí solas no disparan.** PowerShell, Python o cmd solo cuentan con
  contexto: un padre de ofimática o una línea de comandos que encaje en un patrón de abuso.

## De la actividad a la señal

En la misma petición de ingesta, para los eventos **recién insertados** (los duplicados no
llegan aquí), `record_activity` construye señales con estas reglas:

| Evento | Señal (`SignalKind`) | Condición |
|---|---|---|
| `process` / `start` | `process_start` | Al menos una: la línea de comandos encaja en un patrón sospechoso; el padre es una aplicación de documentos y el hijo un intérprete; el ejecutable corre desde una ubicación inusual |
| `network` / `connect` | `process_network` | Dirección no `inbound`, `instance_key` de un proceso ya registrado, destino público y ejecutable del proceso en una ubicación inusual |
| `persistence` o `scheduled_task` / `created`, `modified` | `persistence_change` | Siempre (un `deleted` no genera señal) |
| `protection` / `state` | `protection_change` | `realtime_enabled`, `antivirus_enabled` o `tamper_protection` pasa de `true` a `false` respecto al estado anterior del mismo producto |
| `firewall` / `state` | `firewall_change` | `enabled` pasa de `true` a `false` respecto al estado anterior del mismo perfil |

`auth`, `dns`, `service`, `agent_health` y `network` / `listen` no generan señales en 6E.5.

Más reglas de la extracción:

- El padre solo se tiene en cuenta si `parent_relation` es `observed` o `inferred` y su
  instancia está registrada en `process_instances`. Si el inicio del padre nunca llegó (por
  ejemplo, arrancó antes que el agente y no se informó), no hay relación padre-hijo que
  evaluar.
- Un destino es privado (no cuenta) si es privado, loopback, link-local, multicast, reservado,
  sin especificar, ausente o no es una IP válida.
- Se ignoran los eventos más antiguos que `DETECTION_MAX_EVENT_AGE_HOURS` (24): se guardan,
  pero no generan señal.
- Como mucho 200 señales por lote. `subject` se limita a 255 caracteres y `data` se acota con
  las mismas utilidades que el resto de señales.
- Con `DETECTION_ENABLED=false` no se extrae nada. Si la extracción falla, se deshace solo su
  SAVEPOINT, se registra el error y la ingesta sigue.

### Línea base de protección y firewall

El estado anterior es el último evento guardado de la misma categoría y el mismo `product`
(protección) o `profile` (firewall) con `occurred_at` no posterior. **Sin estado anterior no se
concluye nada**: el primer informe es la línea base. Un equipo que ya llega con la protección
apagada no genera «desactivado»; solo una transición `true` → `false` posterior lo hace
(`test_protection_and_firewall_only_fire_on_transition`). Dentro de un mismo lote, los estados
se comparan en orden (`occurred_at`, `seq`).

### Patrones

Aplicaciones de documentos (`DOCUMENT_APPS`, por nombre del ejecutable): `winword.exe`,
`excel.exe`, `powerpnt.exe`, `outlook.exe`, `msaccess.exe`, `mspub.exe`, `onenote.exe`,
`acrord32.exe`, `acrobat.exe`, `foxitreader.exe`, `soffice.bin`.

Intérpretes y binarios del sistema abusables (`SHELLS`): `cmd.exe`, `powershell.exe`,
`pwsh.exe`, `wscript.exe`, `cscript.exe`, `mshta.exe`, `rundll32.exe`, `regsvr32.exe`,
`msbuild.exe`, `installutil.exe`, `bitsadmin.exe`, `certutil.exe`, `sh`, `bash`, `dash`, `zsh`,
`python`, `python3`, `perl`.

Líneas de comandos sospechosas (`SUSPICIOUS_CMDLINE`, lista cerrada):

| Identificador | Qué detecta |
|---|---|
| `powershell_encoded` | Modificador `-e`, `-ec`, `-enc`... `-encodedcommand` |
| `powershell_download` | Descarga (`DownloadString`, `DownloadFile`, `Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `Net.WebClient`, `Start-BitsTransfer`) y ejecución (`iex`, `Invoke-Expression`) en la misma línea |
| `certutil_download` | `certutil` con `-urlcache` o `-verifyctl` y una URL `http(s)` |
| `bitsadmin_transfer` | `bitsadmin /transfer` con una URL `http(s)` |
| `mshta_remote` | `mshta` con `http:`, `https:`, `javascript:` o `vbscript:` |
| `regsvr32_remote` | `regsvr32 /i:` con una URL `http(s)` |
| `pipe_to_shell` | `curl` o `wget` canalizado a `sh`, `bash`, `dash` o `zsh` (también con `sudo`) |
| `base64_to_shell` | `base64 -d` o `--decode` canalizado a un intérprete |

Los patrones se aplican a la línea de comandos **ya redactada** por el servidor. Con
`TELEMETRY_CMDLINE_POLICY=off` (o la misma política en el agente) no hay línea de comandos y
`BEH-002` no puede disparar. La redacción de `redacted` conserva los modificadores y sustituye
los bloques base64 largos por `[BASE64:n]`, así que `powershell_encoded` sigue funcionando.

Ubicaciones inusuales (`unusual_location`, solo texto de la ruta, no se abre nada):

- Windows: `\AppData\Local\Temp\`, `X:\Windows\Temp\`, `X:\Users\Public\`, `\$Recycle.Bin\`,
  `X:\PerfLogs\`, un ejecutable directamente en la raíz de `X:\ProgramData\` o de
  `\AppData\Roaming\`.
- Linux y macOS: `/tmp/`, `/var/tmp/`, `/dev/shm/`.
- Cualquier plataforma: ruta terminada en ` (deleted)` (binario borrado mientras corre).

## Reglas

Todas son versión 1, tipo `single` (una señal basta) y categoría `behavior`. La severidad y la
confianza base son las de la tabla; la columna «Ajuste» indica cuándo el evaluador las cambia.

| Regla | Título | Señal | Severidad | Confianza | Ajuste | MITRE | Cooldown |
|---|---|---|---|---|---|---|---|
| `BEH-001` | Aplicación de documentos inicia un intérprete | `process_start` con padre de documentos e hijo intérprete | medium | medium | Con algún patrón de línea de comandos: high / high | TA0002 / T1204 / T1204.002 | 1 h |
| `BEH-002` | Línea de comando sospechosa | `process_start` con al menos un patrón | high | medium | Dos o más patrones: confianza high | TA0002 / T1059 | 1 h |
| `BEH-003` | Proceso en ubicación inusual con conexión a Internet | `process_network` | medium | low | Ninguno | TA0011 / T1071 | 6 h |
| `BEH-004` | Mecanismo de persistencia creado o modificado | `persistence_change` | low | medium | Destino en ubicación inusual o con patrón sospechoso: high / medium | Según mecanismo (abajo) | 24 h |
| `BEH-005` | Protección del endpoint desactivada | `protection_change` | high | medium | Ninguno | TA0005 / T1562 / T1562.001 | 6 h |
| `BEH-006` | Firewall del host desactivado | `firewall_change` | medium | medium | Ninguno | TA0005 / T1562 / T1562.004 | 6 h |

MITRE de `BEH-004` por mecanismo:

| mechanism | MITRE |
|---|---|
| `run_key`, `startup_folder` | TA0003 / T1547 / T1547.001 |
| `systemd_unit` | TA0003 / T1543 / T1543.002 |
| `cron` | TA0003 / T1053 / T1053.003 |
| `scheduled_task` | TA0003 / T1053 / T1053.005 |
| `launch_agent` | TA0003 / T1543 / T1543.001 |
| `launch_daemon` | TA0003 / T1543 / T1543.004 |

Notas:

- Un `process_start` con un padre de documentos y una línea sospechosa abre `BEH-001` y
  `BEH-002` a la vez: cada regla responde a su propia pregunta.
- Un `process_start` que solo tiene ubicación inusual genera señal pero ninguna regla `BEH-*`
  la convierte en detección por sí sola; queda como contexto. `BEH-003` necesita además la
  conexión saliente (`process_network`).
- Clave de deduplicación: `BEH-001` padre + hijo + `instance_key`; `BEH-002` proceso +
  patrones + `instance_key`; `BEH-003` ruta + destino; `BEH-004` mecanismo + nombre;
  `BEH-005` producto; `BEH-006` perfil.
- Una regla se puede desactivar entera con `DETECTION_DISABLED_RULES` (como cualquier regla
  integrada).

### Flujo y latencia

Las señales las evalúa el job `detection-engine` cada `DETECTION_EVAL_INTERVAL_SECONDS` (5 por
defecto). La clasificación es periódica, no «tiempo real». Una detección `BEH-*` sigue el ciclo
normal del motor: alerta `security_detection` si su severidad alcanza
`DETECTION_ALERT_MIN_SEVERITY` (por defecto `high`), y el riesgo y los incidentes por las vías
ya existentes ([detection-engine.md](detection-engine.md)).

La latencia se mide, no se estima. `GET /api/v1/endpoint/metrics` (`telemetry:read`) devuelve:

- `ingest_lag_p50_seconds`, `ingest_lag_p95_seconds`, `ingest_lag_max_seconds`:
  `received_at - occurred_at` de los eventos recibidos en la última hora;
- `behavior_detections_24h`, `detection_latency_p50_seconds`,
  `detection_latency_p95_seconds`: `created_at` de cada detección `BEH-*` de las últimas 24
  horas menos `first_seen_at` (el `occurred_at` en el host de su primera evidencia).

La latencia de detección incluye el intervalo de sondeo del agente (5 s por defecto para
procesos; 120-300 s para servicios, tareas, persistencia, protección y firewall), su cola
offline, el retraso de ingesta y el ciclo del motor. Depende de que el reloj del host esté
sincronizado. Pendiente de medir con agentes reales.

## Excepciones de reglas (`detection_exclusions`)

Una excepción dice «esta regla integrada no abre detección cuando el campo X de la señal vale
Y», en un activo o en todos. Tabla `detection_exclusions` (migración 0041).

| Campo | Contenido |
|---|---|
| `rule_id` | Regla integrada (cualquier id de `RULE_IDS`, no solo `BEH-*`) |
| `asset_id` | Activo concreto o `null` (todos) |
| `field` | `exe`, `name`, `sha256`, `signer`, `parent_name` o `remote_address` |
| `value` | Valor exacto, guardado sin espacios alrededor y en minúsculas (≤ 1024) |
| `reason` | Justificación obligatoria (3-500) |
| `created_by`, `created_at` | Autor y fecha |
| `expires_at` | Caducidad opcional (fecha con zona horaria) |
| `revoked_at`, `revoked_by` | Revocación |
| `hits`, `last_hit_at` | Cuántas veces se aplicó y cuándo por última vez |

Comportamiento:

- **Coincidencia exacta**: el valor del campo en `data` de la señal, sin espacios alrededor y en
  minúsculas, debe ser igual a `value`. Sin comodines ni expresiones regulares.
- **Qué campos lleva cada señal** (una excepción sobre un campo que la señal no tiene nunca se
  aplica):
  - `process_start` (`BEH-001`, `BEH-002`): `name` (nombre del ejecutable en minúsculas), `exe`
    (ruta tal como la informa el agente), `sha256`, `signer`, `parent_name`;
  - `process_network` (`BEH-003`): `name`, `exe`, `remote_address`;
  - `persistence_change` (`BEH-004`): `name`;
  - `protection_change` y `firewall_change` (`BEH-005`, `BEH-006`): ninguno de los campos
    admitidos, así que hoy no se pueden excluir con este mecanismo (sí desactivar con
    `DETECTION_DISABLED_RULES`).
- **Vigencia**: activa si no está revocada y no ha caducado. El motor carga las vigentes una vez
  por lote de señales.
- **Efecto**: si una excepción vigente coincide, el motor no evalúa esa regla con esa señal y
  suma 1 a `hits` (con `last_hit_at`). Las demás reglas sí evalúan la señal. `hits` cuenta
  señales saltadas, no detecciones evitadas: por ejemplo, una excepción de `BEH-001` por
  `name=cmd.exe` también cuenta las señales de `cmd.exe` que no tenían padre de documentos.
- **Nunca se borra**: se revoca, para poder explicar después por qué no hubo detección.
- Solo reglas integradas: una regla personalizada se ajusta editando su condición.
- Como mucho 500 excepciones vigentes por regla.

### API (`/api/v1/detection-exclusions`)

| Método y ruta | Permiso | Notas |
|---|---|---|
| `GET /detection-exclusions?include_inactive=` | `rules:read` (todos los roles) | Sin `include_inactive`, oculta las revocadas (las caducadas se listan con `active=false`). Como mucho 500 filas, de la más reciente a la más antigua |
| `POST /detection-exclusions` | `rules:manage` (solo admin) | 201. Auditado (`detection_exclusion_created`) |
| `POST /detection-exclusions/{id}/revoke` | `rules:manage` (solo admin) | Idempotente; audita `detection_exclusion_revoked` solo la primera vez |

```json
{
  "rule_id": "BEH-003",
  "asset_id": "uuid o null",
  "field": "exe",
  "value": "C:\\Users\\bob\\AppData\\Local\\Temp\\updater.exe",
  "reason": "Actualizador interno revisado por soporte (ticket 1234)",
  "expires_at": "2026-12-31T23:59:59Z"
}
```

Errores: regla que no es integrada, 422 `exclusion_rule_unknown`; activo inexistente, 404
`not_found`; más de 500 vigentes para la regla, 409 `exclusion_limit`; excepción inexistente al
revocar, 404 `not_found`. `expires_at` no se valida contra el reloj: una fecha pasada crea una
excepción ya inactiva.

Fase 7A.8: campos `script_path` y `script_sha256`, condiciones `require_sha256` y `port`, y
políticas estrictas para `SCR-001`, `CORR-002` y `NET-001` (422 `exclusion_too_broad`). Ver
[powershell-detections.md](powershell-detections.md).

## Configuración

| Variable | Defecto | Efecto |
|---|---|---|
| `DETECTION_ENABLED` | `true` | Sin ella no se extraen señales ni se evalúan reglas |
| `DETECTION_EVAL_INTERVAL_SECONDS` | 5 | Ciclo del job del motor |
| `DETECTION_MAX_EVENT_AGE_HOURS` | 24 | Eventos más antiguos no generan señal |
| `DETECTION_DISABLED_RULES` | vacío | Lista de reglas desactivadas (por ejemplo `BEH-004`) |
| `DETECTION_ALERT_MIN_SEVERITY` | `high` | Severidad mínima para abrir alerta |
| `TELEMETRY_CMDLINE_POLICY` | `redacted` | `off` desactiva en la práctica `BEH-002` |

## Pruebas

`tests/test_endpoint_telemetry.py`: patrones de línea de comandos, aplicación de documentos
que lanza un intérprete, proceso benigno sin señal ni detección, ubicación inusual con conexión
a Internet con confianza baja, protección y firewall solo en transición, persistencia,
excepción que suprime y cuenta `hits`, excepción de regla desconocida, señales acotadas y
latencia de detección medida.

## Validación pendiente en equipos reales

1. Con un agente 0.5.0 en Windows, abrir un documento de prueba con una macro que lance
   `cmd.exe` y comprobar `BEH-001`.
2. Ejecutar `powershell -enc ...` inocuo y comprobar `BEH-002` y la línea redactada.
3. Desactivar y reactivar la protección en tiempo real de Defender en un equipo de laboratorio
   y comprobar `BEH-005` solo en la transición.
4. Instalar software legítimo habitual del entorno y revisar las detecciones `BEH-004` que
   abre; crear las excepciones justificadas que hagan falta.
5. Revisar `/endpoint/metrics` tras un día de actividad real.
