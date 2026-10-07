# Eventos Linux (Fase 5C.1)

El agente Linux 0.2.1 envía un subconjunto acotado del **journal de systemd**, con el mismo
esquema de eventos que Windows (`system_events`, `POST /events`): `source =
"linux_journal"`, `channel = "journal"` (o `"audit"`), `event_code = null` (Linux no tiene
Event ID) y un tipo normalizado en `event_type`. No hay tabla paralela.

## Qué se recoge

`journalctl` con ruta absoluta (`/usr/bin/journalctl` o `/bin/journalctl`), argumentos fijos
y sin shell: `--output=json --no-pager --quiet --output-fields=…` y coincidencias por campo.
Cada mensaje es texto no confiable que solo se analiza con expresiones regulares fijas. De
cada fuente solo salen los mensajes reconocidos (y en el kernel, los errores sin clasificar).

| Fuente (cobertura) | Coincidencia del journal | Tipos (`event_type`) |
|---|---|---|
| `sshd` | `SYSLOG_IDENTIFIER=sshd`, `sshd-session` (OpenSSH ≥ 9.8) | `auth_failure` (contraseña/clave, usuario inválido), `auth_success` (password, publickey…), `ssh_invalid_user`, `ssh_max_auth_exceeded`, `pam_auth_failure`, `session_opened`, `session_closed` |
| `sudo` | `SYSLOG_IDENTIFIER=sudo` | `sudo_command`, `sudo_auth_failure`, `sudo_not_allowed`, `sudo_error`, `auth_failure` (PAM), sesiones |
| `accounts` | `su`, `login`, `useradd`, `userdel`, `usermod`, `groupadd`, `groupdel`, `groupmod`, `gpasswd`, `passwd`, `chpasswd` | `account_created`, `account_deleted`, `account_changed`, `account_locked/unlocked`, `password_changed`, `group_created/deleted`, `group_member_added/removed`, `login_failure`, `auth_failure` (PAM), sesiones |
| `systemd` | `_PID=1` + `_COMM=systemd` | `service_started`, `service_stopped`, `service_failed`, `service_start_failed`, `service_exited` (salida distinta de 0), `systemd_reload` |
| `kernel` | `_TRANSPORT=kernel`, prioridad warning o superior | `oom_kill`, `filesystem_error` (EXT4, XFS, BTRFS, I/O), `hardware_error` (MCE, EDAC), `kernel_bug` (BUG, Oops, panic, soft lockup), `kernel_error` (otros errores) |
| `auditd` (opcional) | `_TRANSPORT=audit` + `_AUDIT_TYPE_NAME` de una lista | `audit_add_user`, `audit_user_auth` (solo fallidos), `audit_config_change`, `audit_anom_*`… |

Datos estructurados (`data`) con nombres neutros: `user`, `source_ip`, `source_port`,
`auth_method`, `invalid_user`, `target_user`, `tty`, `command`, `group`, `uid`, `unit`,
`result`, `process`, `device`, `audit_type`. Un origen `UNKNOWN` o `?` no se inventa.

Ruido que no sale del equipo: conexiones cerradas, volcados de OOM línea a línea, avisos
de drivers sin clasificar, `exited status=0/SUCCESS`, la copia de gshadow de `usermod`.

## Saneado

El comando de sudo y todos los mensajes pasan por `redact()` antes de enviarse:
credenciales en URLs (`user:pass@`), `Bearer`/`Basic`, `mysql -pSECRETO`, `--password x`,
`clave=valor` con nombres de secreto (`password`, `token`, `secret`, `api_key`,
`access_key`…) y cadenas largas tipo token (≥ 40 caracteres) → `[REDACTED]`. Además se
quitan los caracteres de control y se acotan (mensaje 2000, valores 256). Puede ocultar algún
hash legítimo: se acepta, es preferible a enviar un secreto.

## Cursor, reinicios y deduplicación

- Un cursor del journal por fuente en `/var/lib/sentra-agent/linux_events_state.json`
  (`{version, boot_id, sources: {fuente: {cursor, realtime}}}`), escrito de forma atómica
  **solo después** de que el servidor aceptó el lote: un fallo de red relee lo mismo.
- Primer arranque de una fuente: solo la última hora y como mucho 50 entradas
  (`--since=-1h --lines=50`). La instalación no envía el histórico del equipo.
- Reinicio del equipo: se detecta por `boot_id`; los cursores siguen siendo válidos.
- Rotación o vaciado del journal: si `journalctl` no reconoce el cursor, la fuente vuelve a la
  ventana reciente en el ciclo siguiente (nunca relee todo). Entradas más de 5 min anteriores
  a lo último enviado se descartan (relectura).
- Fichero de estado corrupto: se empieza de nuevo por la ventana reciente.
- `record_id` = hash SHA-256 (63 bits) de `linux|canal|cursor`: la misma entrada siempre da
  el mismo id y el servidor la ignora al reenviarse; dos fallos SSH idénticos son dos eventos.
  Sin cursor (salida anómala): hora + arranque + identificador + hash del mensaje.
- Kernel: como mucho 5 copias del mismo mensaje por lote.
- Límites: 200 entradas por fuente y ciclo (el resto, en el siguiente), 30 s por lectura; el
  runner envía en lotes de 500 (máximo del servidor) con la cobertura en el primero.

## Permisos (mínimo privilegio)

El servicio sigue siendo `sentra-agent` sin capacidades. El instalador lo añade al grupo
**`systemd-journal`** (solo lectura del journal) o, si no existe, a `adm`. Nunca root,
`CAP_SYS_ADMIN`, cambios de permisos del journal ni journal legible por todos. El grupo se
aplica al (re)iniciar el servicio, que el instalador hace. `ProtectKernelLogs=true` no
afecta: el agente lee los ficheros del journal, no `/dev/kmsg`.

Sin el grupo, `journalctl` sale con código 0 mostrando solo los mensajes del propio usuario:
el agente reconoce el aviso («not seeing messages from other users») y lo informa como
`no_permission` en lugar de «0 eventos».

auditd: Sentra **no** lee `/var/log/audit/audit.log` (exige root). Solo usa los registros de
auditoría que llegan al journal; si no llega ninguno, `auditd` queda `unavailable`, que no es
un error.

## Cobertura

El agente envía con los eventos (o en un lote solo de cobertura) el estado de cada fuente:
`active`, `unavailable` (no instalada o sin journal), `no_permission`, `error`, `disabled`.
Se reenvía al cambiar o cada hora. El servidor la guarda en `assets.event_coverage` y la
muestra en la pestaña **Events** del activo. El riesgo 4I la usa para la confianza:

| Situación | Cobertura del riesgo |
|---|---|
| Sin cobertura o informada hace más de 2 h | parcial: «Sin eventos del sistema de este equipo Linux» |
| `journal = no_permission` | parcial: «Journal de Linux sin permiso de lectura» |
| journal no activo | parcial |
| sshd o sudo con error o sin permiso | parcial (no disponible = no instalado, no penaliza) |
| journal activo | completa, «con journal (sin auditd)» o «con journal, auditd» |

## Aislamiento de fallos

`pending()` nunca lanza: cada fuente falla por separado (estado `error` en la cobertura,
registrado una vez en el log). El runner además protege la llamada: un colector roto nunca
afecta a heartbeat, telemetría ni inventario.

## Detección

Mismo motor 4H, reglas por plataforma (un fallo SSH nunca abre AUTH-001 ni un 4625 abre
LIN-AUTH-001). Ver [detection-engine.md](detection-engine.md).

| Regla | Qué | Señales |
|---|---|---|
| LIN-AUTH-001 | Varios fallos SSH/PAM de la misma cuenta en la ventana de autenticación | `auth_failure` |
| LIN-AUTH-002 | Acceso SSH correcto tras ≥ umbral de fallos; `critical` si después usa sudo o entra en un grupo privilegiado | `auth_failure`, `auth_success`, `sudo_command`, `group_member_added` |
| LIN-SYS-001 | Evento crítico del kernel (OOM, sistema de ficheros, hardware, BUG) | `oom_kill`, `filesystem_error`, `hardware_error`, `kernel_bug` |
| ACCT-001 / ACCT-002 / ACCT-003 | Cuenta creada (el UID queda en los datos) / añadida a `sudo`, `wheel`, `admin` o `root` / borrada, bloqueada, retirada de un grupo privilegiado | `account_*`, `group_member_*` |
| SYS-002 | Servicio systemd que falla repetidamente | `service_failed` |
| PER-001 | Servicio nuevo (T1543.002) | inventario (unidades systemd), como antes |

Decisión: los ejemplos «LIN-ACC-001» y «LIN-PER-001» de la especificación no son reglas
nuevas. Las cuentas y grupos Linux alimentan las mismas señales que Windows (ACCT-001/002/003,
deduplicadas con el inventario) y las unidades nuevas ya las detecta PER-001 por inventario;
duplicarlas daría dos detecciones del mismo cambio.

## Limitaciones

- El formato de los mensajes varía entre versiones de OpenSSH, sudo, shadow-utils y systemd;
  los tests cubren Debian/Ubuntu/Mint actuales y formas genéricas de RHEL/Fedora.
  **Pendiente de validar en Linux real** con journald, sshd, sudo y auditd.
- Las reglas personalizadas y Sigma (5A) siguen siendo de canales Windows.
- La inteligencia de amenazas (5C) no compara las IPs de origen SSH (solo 4624/4625 y
  conexiones).
- Sin journald (syslog clásico) no hay eventos: cobertura `unavailable`.
