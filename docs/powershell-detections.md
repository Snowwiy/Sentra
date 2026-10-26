# PowerShell, puertos nuevos y excepciones exactas (Fase 7A.8)

En 6E aparecieron detecciones `CORR-002` (PowerShell sospechoso seguido de persistencia),
`SCR-001` (script marcado como sospechoso) y `NET-001` (puerto nuevo, incluida la API en
8000/TCP) en el equipo de desarrollo. Ninguna decía qué script, qué proceso ni por qué. Esta
fase añade ese contexto y una forma de exceptuar lo legítimo sin apagar nada.

**No se desactiva PowerShell, ni el registro de scripts, ni ninguna regla, y no se toca
Defender, la Execution Policy ni el firewall.** El contexto explica; solo una excepción
explícita, revisada, con alcance y caducidad evita una detección.

## Causa probable de los avisos en el equipo de desarrollo

PowerShell escribe el evento 4104 con nivel Warning cuando su motor encuentra en el bloque
palabras de una lista interna (reflexión, P/Invoke, `Marshal`, `FromBase64String`...). Dos
scripts de Sentra las usan para manejar contraseñas sin dejarlas en texto plano:

| Script | Palabras | Por qué |
| --- | --- | --- |
| `agent/packaging/windows/install-sentra-agent.ps1` | `InteropServices`, `Marshal`, `PtrToString`, `Bypass` | convierte el token de inscripción (SecureString) para escribirlo en un fichero protegido; `Bypass` aparece en la ayuda de cómo lanzarlo |
| `scripts/init_database.ps1` | `InteropServices`, `Marshal`, `PtrToString` | pasa la contraseña de PostgreSQL a `psql` sin mostrarla |
| `scripts/setup_windows.ps1` | `Cryptography`, `ToBase64String` | genera secretos aleatorios para el `.env` |

El instalador del agente además crea los servicios `SentraAgent` (y `SentraIsolation` si se
pide): un 4104 Warning seguido de un 7045 en la ventana de correlación es exactamente
`CORR-002`. Esto es una hipótesis comprobada leyendo los scripts; la confirmación es el campo
`trigger.keywords` de la detección con el agente 0.6.0 en el equipo real.

Los scripts que el agente ejecuta (inventario, endpoint, forense) usan `-Command` y no
contienen ninguna palabra del vocabulario, así que no deberían marcarse.

## Qué envía el agente 0.6.0 en un 4104

| Campo | Origen | Notas |
| --- | --- | --- |
| `Path` | EventData | ruta del script; vacía si se tecleó o vino por `-Command` |
| `ScriptBlockId`, `MessageNumber`, `MessageTotal` | EventData | une los trozos de un bloque largo |
| `ProcessID` | System/Execution | PID del proceso de PowerShell |
| `UserID` | System/Security | SID del usuario |
| `ScriptSha256` | calculado | SHA-256 del fichero de `Path` al leer el evento |
| `SuspiciousKeywords` | calculado | palabras de una lista cerrada presentes en el bloque |

`ScriptBlockText` **nunca** sale del equipo: el agente lo lee solo para buscar las palabras y lo
descarta. El hash solo se calcula para rutas locales con unidad (`C:\...`): nunca UNC
(`\\servidor\...`, que haría que el equipo se autenticara contra ese servidor), dispositivos
(`\\.\`, `\\?\`), flujos alternativos ni enlaces; como mucho 16 MiB y con caché por ruta,
tamaño y fecha de modificación. Un agente anterior sigue funcionando: sus 4104 producen la
detección agregada de siempre, con `missing_context = ["agent_without_script_context"]`.

## Qué añade el servidor

Al guardar la señal (no al leer la detección, para que las excepciones comparen lo mismo que
se ve):

- **Proceso:** la instancia de la telemetría 6E.4 con ese PID viva en ese momento (los PID se
  reutilizan; margen de 2 min si terminó justo antes), con ejecutable, línea de comandos (tal
  como la guarda el agente, redactada por defecto), usuario, hash, firma y padre.
- **Relación con Sentra:** el nombre del script frente a los scripts que distribuye Sentra y la
  línea de comandos del proceso o su padre frente a `-m sentra_agent`, `-m sentra_sensor` o
  `uvicorn app.main:app`. Es una pista y se dice así: un nombre se falsifica con facilidad, y
  nunca rebaja la severidad.
- **Puerto expuesto (NET-001):** el proceso que escucha en ese puerto según el último
  inventario de conexiones del agente y su instancia en la telemetría.

## Reglas

| Regla | Versión | Cambio |
| --- | --- | --- |
| `SCR-001` | 2 | una detección por script (hash, si no ruta; los bloques en línea se agrupan); detalles `script`, `process`, `user_sid`, `trigger.keywords`, `sentra`, `explanation`, `missing_context` |
| `CORR-002` | 3 | los scripts con excepción de `CORR-002` no cuentan; detalles `scripts[]` (mismo formato), `persistence` (servicio, ruta, cuenta, tipo de inicio, origen 7045 o inventario, ubicación inusual, nombre de servicio de Sentra), `sequence` y `explanation` |
| `NET-001` | 2 | `owner` (proceso, PID, ejecutable, hash, firma, dirección de escucha, componente de Sentra) y `explanation` |

`missing_context` dice qué faltó en vez de inventarlo:
`agent_without_script_context` (agente < 0.6.0), `process_not_in_telemetry` (sin telemetría de
actividad o el proceso no llegó a verse), `script_hash_unavailable` (fichero borrado, sin
permisos de lectura o fuera de los límites).

Severidad y confianza no cambian: `SCR-001` media, `CORR-002` alta, `NET-001` baja (alta en
puertos sensibles). Cómo pesan en el riesgo del activo se ve en su desglose del Risk Engine
(contribución de cada detección abierta según severidad, confianza y ocurrencias).

## Excepciones exactas

`POST /api/v1/detection-exclusions` (admin, `rules:manage`) admite dos campos nuevos y dos
condiciones (migración 0047):

| Campo o condición | Uso |
| --- | --- |
| `field = script_path` | ruta del script (en minúsculas) |
| `field = script_sha256` | hash del script |
| `require_sha256` | hash que además debe coincidir |
| `port` | puerto que además debe coincidir |

Políticas por regla (422 `exclusion_too_broad` si no se cumplen):

| Regla | Campos admitidos | Obligatorio |
| --- | --- | --- |
| `SCR-001`, `CORR-002` | `script_path` (con `require_sha256`) o `script_sha256` | caducidad futura, como mucho 90 días |
| `NET-001` | `exe` o `sha256` | `port`, `asset_id` y caducidad (90 días como mucho) |
| todas | nunca `name` de un intérprete ni el `exe` de un intérprete del sistema (`System32`, `SysWOW64`, `Program Files\PowerShell`, `/usr/bin`, `/bin`) | |

Con ruta + hash, si alguien modifica después el script, el hash cambia y la detección vuelve.
En `CORR-002`, una excepción saca solo ese script de la secuencia: cualquier otro bloque
sospechoso en la ventana sigue correlacionando con el servicio. Las excepciones se auditan al
crearse y revocarse, cuentan cuántas veces evitaron una detección y nunca se borran.

### Ejemplos para el equipo de desarrollo

Tras comprobar en el equipo que el hash es el del script del repositorio:

```json
{"rule_id": "CORR-002", "field": "script_path",
 "value": "C:\\Users\\<usuario>\\Documents\\Sentra\\agent\\packaging\\windows\\install-sentra-agent.ps1",
 "require_sha256": "<sha256 del fichero>", "asset_id": "<activo>",
 "reason": "Instalación del agente 0.6.0 revisada", "expires_at": "<fecha en menos de 90 días>"}
```

```json
{"rule_id": "NET-001", "field": "exe",
 "value": "C:\\Users\\<usuario>\\Documents\\Sentra\\backend\\.venv\\Scripts\\python.exe",
 "port": 8000, "asset_id": "<activo>",
 "reason": "API de Sentra en desarrollo expuesta a la LAN a propósito",
 "expires_at": "<fecha en menos de 90 días>"}
```

Para la API, la alternativa sin excepción es no exponerla: `scripts/start_backend.ps1` escucha
en `127.0.0.1` salvo que se pase `-BindHost`.

## Pendiente de validar en Windows real

- Que PowerShell 5.1 y 7 rellenan `Execution/@ProcessID`, `Security/@UserID` y `Path` como
  se espera en el 4104, y qué palabras marca de verdad en los dos scripts.
- Si la cuenta del servicio del agente puede leer el script para calcular el hash. El agente
  Windows corre por defecto como la cuenta virtual `NT SERVICE\SentraAgent`, que normalmente
  **no** puede leer el perfil de otro usuario (`C:\Users\<usuario>\Documents`): en ese caso
  la detección muestra `script_hash_unavailable` y no se puede crear una excepción por ruta +
  hash. Es el comportamiento seguro (sin hash no hay excepción). Opciones, por orden de
  preferencia: ejecutar el instalador desde la carpeta extraída del zip en una ruta que el
  servicio pueda leer (por ejemplo bajo `C:\ProgramData`), o revisar la detección y cerrarla a
  mano. No se recomienda ampliar los permisos de la cuenta del servicio.
- Que la telemetría de actividad ve el proceso de PowerShell del instalador (dura segundos).
