# Telemetría de endpoint en el agente 0.5.0 (Fase 6E.3)

Qué recoge el agente sobre la actividad del equipo, cómo lo envía, qué cuesta y qué no ve.
El protocolo exacto está en `docs/fase-6e-contracts.md`; aquí se explica el lado del agente.

## Colectores

| Colector | Fuente | Plataformas | Categoría / acciones | Intervalo por defecto |
|---|---|---|---|---|
| `process` | psutil (sondeo) | Windows, Linux, macOS | `process` / `start`, `stop` | `process_poll_seconds` = 5 s |
| `network` | psutil `net_connections` | Windows, Linux, macOS (root) | `network` / `connect`, `listen` | con cada pasada de procesos |
| `service` | servicios de Windows, unidades systemd | Windows, Linux | `service` / `created`, `modified`, `deleted`, `started`, `stopped` | 120 s |
| `scheduled_task` | `schtasks /query /fo csv /v`, temporizadores systemd | Windows, Linux | `scheduled_task` / `created`, `modified`, `deleted` | 120 s |
| `persistence` | claves Run y carpeta Inicio; cron y `/etc/systemd/system`; LaunchAgents y LaunchDaemons del sistema | Windows, Linux, macOS | `persistence` / `created`, `modified`, `deleted` | 300 s |
| `protection` | `Get-MpComputerStatus` (Defender) | Windows | `protection` / `state` | 300 s |
| `firewall` | `Get-NetFirewallProfile`; `ufw.conf` o `systemctl is-active firewalld`; `socketfilterfw` | Windows, Linux, macOS | `firewall` / `state` | 300 s |
| `sysmon` | canal `Microsoft-Windows-Sysmon/Operational`, evento 1 | Windows con Sysmon | `process` / `start` (`source = sysmon`) | 10 s |
| `dns` | ninguna | ninguna en 0.5.0 | — | siempre `unavailable` |

Cada colector informa un estado real (`active`, `unavailable`, `permission_denied`,
`disabled`, `error`) en `stats.collectors` de cada lote y en `heartbeat.telemetry`. Un
colector que falla no detiene a los demás. Además, cada `health_seconds` (300 s) el agente
envía un evento `agent_health` / `state` con su CPU, memoria residente y tamaño de cola.

Persistencia y servicios: solo metadatos (nombre, ubicación, destino de un enlace, huella de
tamaño y fecha). Nunca se lee el contenido de un crontab, de una unidad ni de un plist.

### Primera ejecución y líneas base

- Procesos: la primera pasada informa los procesos ya en marcha como `start` con
  `data.preexisting = true` y `occurred_at` = momento de la observación (`started_at` lleva el
  inicio real). El servidor actual descarta `preexisting` (clave desconocida); se envía por si
  un servidor futuro la usa.
- Servicios, tareas y persistencia: la primera ejecución en un equipo solo guarda una línea
  base en `state_dir/baseline_<categoría>.json`; los cambios posteriores (también entre
  reinicios del agente) se informan como `created`, `modified` o `deleted`.
- Sysmon: la primera lectura solo fija el cursor (`sysmon_cursor.json`); no se reenvía la
  historia del canal.

### Identidad de proceso y padre

`instance_key` = primeros 32 hex de `sha256("{boot_id}|{pid}|{create_time_ms}")`, con
`create_time_ms = int(create_time * 1000)` (truncado, no redondeado; Sysmon `UtcTime` da la
misma clave). `boot_id` sale de `/proc/sys/kernel/random/boot_id` en Linux y de
`boot-{boot_time}` en el resto.

`parent_relation`:

- `observed`: el padre existe y arrancó antes que el hijo;
- `pid_reused`: hay un proceso con el PID del padre, pero arrancó después del hijo, así que no
  es su padre;
- `missing`: el padre ya no existe;
- `inferred`: solo en Sysmon, que da el PID del padre pero no su hora de inicio.

Un PID reutilizado entre dos pasadas produce un `stop` del proceso viejo y un `start` del nuevo,
con claves distintas.

### Línea de comandos y hashes

`[telemetry] cmdline`:

- `off`: no se envía;
- `redacted` (por defecto): se quitan los valores de `-p`, `--password`, `/p:`, `token=`,
  `api_key=`, `client_secret=`, cabeceras `Authorization: Bearer` y credenciales en URL;
- `full`: se envía completa.

En todos los casos se recorta a 1024 caracteres. El servidor vuelve a aplicar su propia
política y gana la más restrictiva.

`hash_executables = true` añade el SHA-256 del ejecutable de cada proceso nuevo, con tope
`hash_max_mb` y una caché por (ruta, mtime, tamaño). Está desactivado por defecto porque
cuesta lecturas de disco.

## Envío

- Cola persistente `state_dir/activity_queue.jsonl` (más `activity_queue.meta.json`), con
  tope `activity_queue_max_events` (20000). Si se llena se descartan los eventos más viejos,
  y el descarte se cuenta en `dropped_total` y `dropped_since_last`. Sobrevive a reinicios y
  a cortes del servidor; un evento se borra solo cuando el servidor confirma el lote.
- Lotes de hasta 1000 eventos y como mucho 5 lotes por ciclo, para que vaciar una cola
  larga no retrase el heartbeat. Un cuerpo de más de 8 KB viaja con
  `Content-Encoding: gzip`.
- 413: el tamaño del lote se reduce a la mitad y se reintenta.
- 404 (servidor anterior a 6E): se deja de enviar y de recolectar hasta reiniciar el agente.
  El resto del agente sigue igual y deja de anunciar `telemetry_activity`.
- Heartbeat: añade `telemetry` e `isolation`. Un servidor anterior los rechaza con 422
  `extra_forbidden`; el agente los quita y no los vuelve a enviar.
- El servidor valida cada evento por separado. `source` y la acción deben estar en el
  catálogo, y las claves desconocidas de `data` se descartan.
  `tests/test_activity_contract.py` carga el esquema del backend (si está en el checkout) y
  comprueba los eventos del agente contra él.

## Latencia y lo que no se ve

- El sondeo no ve un proceso que empieza y termina entre dos pasadas (menos de
  `process_poll_seconds`, 5 s por defecto). Con Sysmon instalado en Windows, el evento 1 sí
  lo ve: Sysmon es la fuente fiable de inicio de procesos.
- Las conexiones se ven solo si existen en el momento de la pasada. Cada pasada informa como
  mucho 500 conexiones nuevas, y una caché LRU de 8192 entradas evita repetir la misma.
- macOS como usuario normal: `net_connections` exige root. El colector `network` queda en
  `permission_denied` y no se anuncia `telemetry_process_network`.
- DNS no tiene colector en 0.5.0.

## Coste medido de una pasada del tracker

Medido en el contenedor de desarrollo de esta fase, con procesos y conexiones reales, sin
cifras estimadas. Script de medición: una pasada inicial y 30 pasadas en régimen estable con
`time.perf_counter` y `time.process_time`, más `tracemalloc` y el RSS del proceso.

Entorno: Linux, Python 3.12.3, psutil 7.2.2, 4 CPU (Xeon 2.10 GHz), 92 procesos y 80
conexiones inet en el momento de medir.

| Medida | Resultado |
|---|---|
| Primera pasada (todos los procesos nuevos: detalles, padres y conexiones) | 141.1 ms de reloj, 140.4 ms de CPU, 103 eventos |
| Pasada estable con procesos y red (n = 30) | mediana 14.53 ms, p95 16.66 ms, máximo 18.33 ms; CPU mediana 14.47 ms |
| Pasada estable solo procesos (red desactivada) | mediana 8.55 ms, máximo 16.32 ms |
| Memoria del tracker (`tracemalloc`, 6 pasadas) | 67 KiB en uso, pico de 269 KiB |
| RSS del proceso tras 31 pasadas | +624 KiB; `maxrss` 23108 KiB |

Con el intervalo por defecto de 5 s, unos 15 ms por pasada son alrededor del 0.3 % de una CPU.
El coste crece con el número de procesos, porque cada pasada lee pid, ppid, nombre y
create_time de todos. Los detalles caros (ejecutable, línea de comandos, usuario y hash) se
leen solo para los procesos nuevos. Un equipo con miles de procesos debe medirse en real; el
agente publica su propio coste (`last_pass_ms` y `max_pass_ms`) en `collect_diagnostics`.

## Validación pendiente en equipos reales

- Windows: Sysmon evento 1 con `wevtutil`, `schtasks` en un Windows en español,
  `Get-MpComputerStatus` como LocalSystem y con Defender sustituido por otro antivirus, y
  perfiles del firewall.
- Linux: `systemctl` en distribuciones sin systemd (el colector queda `unavailable`), y ufw y
  firewalld reales.
- macOS: `socketfilterfw` y conexiones con y sin root.
