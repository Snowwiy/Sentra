# Motor de detección y correlación (Fase 4H)

Sentra convierte los datos que ya recoge (eventos de Windows, inventario, procesos y
descubrimiento de red) en **detecciones**: conclusiones deterministas con evidencia, una
explicación de por qué importan y recomendaciones defensivas. Sin IA y sin APIs externas: las
reglas son código y los textos salen de plantillas.

## Evento, señal, detección y alerta

| Concepto | Qué es | Dónde vive |
|----------|--------|------------|
| Evento | Un hecho del host tal cual (p. ej. Security 4625) | `system_events` |
| Señal | Hecho normalizado y saneado que el motor sabe interpretar (`auth_failure`, `service_installed`…) | `detection_signals` (estado de correlación de corta vida) |
| Detección | Conclusión del motor: regla, severidad, confianza, evidencia, explicación | `detections` + `detection_evidence` |
| Alerta | Notificación operativa para que alguien mire | `alerts` (regla `security_detection`) |

No toda detección es una alerta: solo las de severidad igual o superior a
`DETECTION_ALERT_MIN_SEVERITY` (por defecto `high`) abren o actualizan una alerta
`security_detection` del activo. Una detección informativa o baja se queda en la página
**Detecciones** sin notificar. Al resolver una detección se resuelve su alerta si ninguna otra
detección activa la usa; además, como el resto de alertas por eventos, se cierra sola tras
`ALERT_EVENT_QUIET_MINUTES` sin volver a dispararse.

## Flujo

```
POST /events | /inventory | /processes | discovery
        │  (en la misma petición, en un SAVEPOINT con try/except)
        ▼
  detection_signals  ──►  job "detection-engine" (cada DETECTION_EVAL_INTERVAL_SECONDS)
                              │  FOR UPDATE SKIP LOCKED, lotes de 500
                              │  cada regla en su propio SAVEPOINT
                              ▼
                   detections + detection_evidence ──► alerts (si severidad ≥ umbral)
```

- **La ingesta nunca se bloquea ni se rechaza por el motor.** En la petición del agente solo
  se extraen e insertan señales (medido: mediana 15 ms por lote de 50 eventos). Si la
  extracción falla, se deshace solo su SAVEPOINT, se registra el error y la petición sigue.
- **Una regla que falla no detiene a las demás**: su SAVEPOINT se deshace, se cuenta en
  `rule_errors` del log y la señal se marca evaluada igualmente (no se reintenta en bucle).
- Varios workers de uvicorn pueden ejecutar el job a la vez: `SKIP LOCKED` reparte las señales
  y un índice único parcial impide duplicar detecciones.

## Reglas

Severidad = impacto si la detección es cierta. Confianza = cuánto respalda la evidencia la
conclusión. Son campos separados: una detección crítica con confianza baja pide verificar antes
de actuar. La tabla muestra los valores base; algunas reglas los suben según la evidencia (p. ej.
AUTH-001 pasa a `high` con 4 veces el umbral y a confianza `low` si los eventos no traen la
cuenta; DEF-005 pasa a `critical` si el antimalware no pudo neutralizar la amenaza).

| Regla | Título | Severidad | Confianza | MITRE | Cooldown (min) | Datos que usa |
|-------|--------|-----------|-----------|-------|----------------|---------------|
| AUTH-001 | Múltiples inicios de sesión fallidos | medium | medium | TA0006 / T1110 | ventana auth (5) | Security 4625 |
| AUTH-002 | Cuenta bloqueada | low | high | TA0006 / T1110 | 0 | Security 4740 |
| ACCT-001 | Cuenta creada | medium | high | TA0003 / T1136 | 0 | Security 4720 o inventario |
| ACCT-002 | Cuenta añadida a un grupo privilegiado | high | high | TA0004 / T1098.007 | 0 | Security 4728/4732/4756 o inventario |
| ACCT-003 | Cambio de estado de una cuenta | low | high | — | 0 | Security 4722/4725/4726/4729/4733/4757 o inventario |
| SCR-001 | PowerShell marcó un script como sospechoso | medium | medium | TA0002 / T1059.001 | 15 | PowerShell/Operational 4104 (Warning) |
| PER-001 | Servicio nuevo | medium | high | TA0003 / T1543 | 0 | System 7045 o inventario |
| PROC-001 | Proceso desde una ubicación inusual | medium | low | — | 0 | Snapshots de procesos |
| NET-001 | Puerto expuesto en la red | low | high | — | 0 | Discovery (línea base de exposición) |
| NET-002 | Nuevo puerto sensible en escucha | medium | medium | — | 0 | Conexiones en escucha del inventario |
| NET-003 | Dispositivo nuevo en la red | low | medium | — | 0 | Discovery |
| NET-004 | Activo desaparecido de la red | informational | medium | — | 0 | Discovery |
| DEF-001 | Registro de eventos borrado | high | high | TA0005 / T1070.001 | 0 | Security 1102 o System 104 |
| DEF-002 | Política de auditoría modificada | medium | medium | — | 0 | Security 4719 |
| DEF-003 | Servicio de seguridad detenido o deshabilitado | high | medium | TA0005 / T1562.001 | 0 | Servicios del inventario |
| DEF-004 | Protección antimalware desactivada | high | high | TA0005 / T1562.001 | 0 | Defender/Operational 5001, 5010, 5012 |
| DEF-005 | Amenaza detectada por el antimalware | high | high | — | 0 | Defender/Operational 1116–1119 |
| SYS-001 | Apagado inesperado | low | high | — | 10 | System 41 / 6008 |
| SYS-002 | Servicio que falla repetidamente | medium | high | — | 60 | System 7031/7034 o journal Linux (unidad systemd con fallo) |
| LIN-AUTH-001 | Múltiples inicios de sesión SSH/PAM fallidos (Linux) | medium | medium | TA0006 / T1110 | ventana auth (5) | journal: sshd y PAM |
| LIN-SYS-001 | Evento crítico del kernel (Linux) | low/medium | high | — | 60 | journal: kernel (OOM, sistema de ficheros, hardware, BUG) |

Fase 5C.1: ACCT-001/002/003 también reciben cuentas y grupos del journal Linux (useradd,
usermod, gpasswd; grupos privilegiados `sudo`, `wheel`, `admin`, `root`). Las reglas de
autenticación son por plataforma: AUTH-001/CORR-001 solo ven señales Windows y
LIN-AUTH-001/LIN-AUTH-002 solo Linux. Detalle en [linux-events.md](linux-events.md).

Criterios de severidad: `critical` = compromiso muy probable con privilegios; `high` = acción
típica de un atacante o pérdida de una defensa; `medium` = cambio relevante que suele ser
legítimo pero merece revisión; `low` = contexto útil; `informational` = solo historial.

MITRE ATT&CK solo se asigna cuando la técnica es inequívoca. Exposición de red, procesos
nuevos o reinicios no llevan mapeo para no aparentar una certeza que no hay.

## Correlaciones

Todas por activo (nunca se mezclan activos) y dentro de ventanas configurables. El sujeto
(cuenta) se compara por SID cuando ambas señales lo traen y si no por nombre normalizado
(sin dominio, minúsculas).

| Regla | Qué une | Ventana | Severidad / confianza |
|-------|---------|---------|-----------------------|
| CORR-001 | ≥ umbral de fallos (4625) de una cuenta y después un inicio interactivo/RDP correcto (4624) de la misma cuenta; sube a `critical` si además la cuenta entra en un grupo privilegiado | correlación (15 min) | high / medium |
| CORR-002 | PowerShell sospechoso (4104 Warning) y servicio instalado o nuevo cerca en el tiempo; confianza `high` si además hay procesos nuevos | correlación (±15 min) | high / medium |
| CORR-003 | Puerto sensible nuevo en escucha con proceso asociado (inventario) y servicio instalado o nuevo; confianza `high` si discovery confirma que es accesible en la red | cambios (±60 min) | high / medium |
| CORR-004 | Cuenta creada, añadida a un grupo privilegiado y usada para iniciar sesión | correlación (15 min) | critical / high |
| LIN-AUTH-002 | ≥ umbral de fallos SSH/PAM de una cuenta y después un acceso SSH correcto de la misma cuenta; sube a `critical` si después usa sudo o entra en un grupo privilegiado (Fase 5C.1) | correlación (15 min) | high / medium |

## Línea base, deduplicación y cooldown

- **Primer snapshot = línea base, nunca avalancha.** Procesos: la primera vez que un activo
  envía procesos solo se rellena `detection_baselines` (tipo `process_exe`); después, solo
  las rutas nunca vistas generan señal (máximo 100 por snapshot). Inventario: se reutiliza el
  diff existente (`change_detection`), que no compara el primer inventario. Puertos en
  escucha: se comparan dos inventarios; una lista vacía (recogida fallida) no genera nada.
  Discovery: se reutiliza su propia línea base de exposición. Eventos: se ignoran los que
  tengan más de `DETECTION_MAX_EVENT_AGE_HOURS` (el primer envío de un agente trae histórico).
- **Deduplicación**: una sola detección activa (abierta o reconocida) por
  (activo, regla, clave). La clave depende de la regla (cuenta, servicio, puerto…). Un índice
  único parcial (`uq_detections_active_key`) lo garantiza también con varios workers.
- **Cooldown**: dentro del cooldown de la regla, una coincidencia nueva añade evidencia y
  actualiza `last_seen_at` sin sumar `occurrence_count` (es la misma oleada). Fuera del
  cooldown suma una ocurrencia. La severidad y la confianza solo suben.
- La evidencia es idempotente por señal y se limita a 100 filas por detección (se conservan
  las más recientes si no cabe todo).
- Resolver cierra la detección; una coincidencia posterior abre una detección nueva.

## Datos no confiables

Todo lo que viene del host (nombres de cuenta, rutas, nombres de servicio, campos de
eventos) se trata como dato no confiable: se eliminan caracteres de control, se acotan
longitudes y número de campos (`app/detection/text.py`) y el frontend lo muestra como texto
(React lo escapa; nunca HTML). Nada se ejecuta ni se interpola en una shell. El agente nunca
envía el contenido de scripts (4104 `ScriptBlockText`) ni líneas de comando.

### Campos estructurados de eventos (agente)

El agente envía en `events[].data` solo los campos de una lista permitida por canal y evento
(`DATA_FIELDS` en `agent/sentra_agent/events.py`), máximo 16 campos de 512 caracteres. Nuevo
en 4H: Security 4624 solo para logons interactivos, RDP y con credenciales en caché (tipos 2,
10 y 11, consulta y cursor propios `Security:4624`) y el canal
`Microsoft-Windows-Windows Defender/Operational` (1116–1119, 5001, 5010, 5012).

⚠️ **Despliegue: primero el servidor, después los agentes.** El esquema de eventos rechaza
campos desconocidos: un agente 4H contra un servidor anterior recibiría 422 en `/events`.
Un agente anterior contra un servidor 4H funciona; sus eventos sin `data` generan señales sin
cuenta asociada (menos confianza y sin correlación por cuenta).

## Flujo del analista y permisos

| Acción | Permiso | Roles |
|--------|---------|-------|
| `GET /detections`, `GET /detections/{id}`, `GET /detection-rules` | `monitoring:read` | admin, analyst, viewer |
| `POST /detections/{id}/acknowledge` | `detections:manage` | admin, analyst |
| `POST /detections/{id}/resolve` (cuerpo opcional `{"note": "…"}`, ≤ 500) | `detections:manage` | admin, analyst |

El backend comprueba el permiso en cada petición; ocultar botones en la UI es solo
comodidad. Reconocer y resolver se registran en `audit_events`
(`detection_acknowledged`, `detection_resolved`), también los intentos fallidos (404/409).
`GET /detection-rules` es legible por cualquier rol porque la UI lo usa para el filtro de
reglas y no contiene secretos.

Filtros de `GET /detections`: `status`, `active`, `severity`, `min_severity`, `confidence`,
`rule_id`, `asset_id`, `since`/`until` (sobre la última actividad), `q` (título, resumen,
regla, activo), `limit` (≤ 500), `offset`.

## Configuración

| Variable | Defecto | Uso |
|----------|---------|-----|
| `DETECTION_ENABLED` | `true` | Desactiva señales y job |
| `DETECTION_EVAL_INTERVAL_SECONDS` | 5 | Frecuencia del job |
| `DETECTION_AUTH_FAILURE_THRESHOLD`, `DETECTION_AUTH_FAILURE_WINDOW_MINUTES` | 5, 5 | AUTH-001 y CORR-001 |
| `DETECTION_CORRELATION_WINDOW_MINUTES` | 15 | CORR-001, CORR-002, CORR-004 |
| `DETECTION_CHANGE_WINDOW_MINUTES` | 60 | CORR-003 y cambio de privilegios tras CORR-001 |
| `DETECTION_REPEAT_THRESHOLD`, `DETECTION_REPEAT_WINDOW_MINUTES` | 3, 1440 | SYS-001, SYS-002 |
| `DETECTION_MAX_EVENT_AGE_HOURS` | 24 | Eventos más antiguos no generan señales |
| `DETECTION_SIGNAL_RETENTION_HOURS` | 48 | Purga de señales evaluadas (debe cubrir la ventana más larga; se valida al arrancar) |
| `DETECTION_SECURITY_SERVICES` | `WinDefend,mpssvc,EventLog,wscsvc,Sense,auditd,firewalld,ufw` | Servicios vigilados por DEF-003 |
| `DETECTION_ALERT_MIN_SEVERITY` | `high` | `medium`, `high`, `critical` u `off` |
| `DETECTION_DISABLED_RULES` | vacío | Lista de reglas desactivadas (se valida contra el catálogo) |
| `DETECTION_RETENTION_DAYS` | sin definir | Purga detecciones **resueltas** más antiguas; las abiertas o reconocidas y su evidencia nunca se borran |

CLI: `python -m app.cli run-detections` evalúa pendientes ahora;
`--reevaluate-hours N` vuelve a evaluar las señales de las últimas N horas (idempotente).

## Rendimiento medido

`qa/perf_detections.py` con datos sintéticos (PostgreSQL 16 local, 200 activos):

| Medida | Resultado |
|--------|-----------|
| Extracción de señales por lote de 50 eventos (dentro de `POST /events`) | mediana 14,9 ms, p95 28,6 ms |
| Job: 10 000 señales (90 % fallos de login en ráfagas, el peor caso) | 69,9 s → 143 señales/s, 0 errores de regla |
| Listado con 52 000 detecciones (activas, todas, por severidad, por regla+24 h) | 13–20 ms, 2 sentencias SQL |
| Listado de un activo | 14,5 ms, 3 sentencias |
| Detalle con evidencia | 7,2 ms, 3 sentencias |
| Búsqueda de texto libre | 380 ms (recorre la tabla; un índice pg_trgm lo resolvería si hace falta) |

Los planes (`--explain`) usan `ix_detections_last_seen` y `ix_detections_asset_last_seen`
con orden incremental; sin N+1 (activo y alerta en la misma consulta).

## Limitaciones y validación pendiente

- Linux (Fase 5C.1) envía un subconjunto del journal (sshd, sudo, cuentas, systemd, kernel,
  auditd opcional); pendiente de validar con journald real. Las reglas personalizadas y Sigma
  siguen siendo de canales Windows.
- Sin líneas de comando no es posible detectar PowerShell codificado (`-EncodedCommand`);
  SCR-001 depende del nivel Warning que Windows asigna a 4104.
- Tareas programadas (4698) y el canal de eventos del firewall no se recogen: la cobertura
  del firewall es DEF-003 por estado del servicio.
- Cuentas locales en 4732 solo traen SID: ACCT-002 desde evento y desde inventario puede
  quedar con claves distintas (dos detecciones de la misma cuenta).
- Pendiente de validar en Windows real: la consulta XPath de 4624 por tipo de logon, los
  nombres de campo del canal de Defender y los `EventData` de cada evento de la lista.
