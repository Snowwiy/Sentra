# Sentra Sensor

Runtime del **sensor distribuido** de Sentra (Fase 5F). Un sensor es un proceso desplegado
dentro de un *Site* (una red remota, posiblemente detrás de NAT) que observa esa red y ejecuta
tareas de descubrimiento **autorizadas** por el servidor.

No es el agente de endpoint (`agent/`): el agente monitoriza el host donde corre; el sensor
descubre otros equipos de la red del site. Son paquetes independientes y no comparten código.

## Principios de seguridad

- **Solo conexiones salientes HTTPS** hacia el servidor. El sensor no abre ningún puerto, así
  funciona tras NAT sin reglas de entrada.
- **TLS verificado siempre.** `ca_bundle` permite añadir una CA privada; no existe ninguna
  opción para desactivar la verificación. `http://` solo se acepta contra `127.0.0.1`, `::1` o
  `localhost` (servidor de desarrollo).
- **El servidor es la autoridad del alcance.** Las redes permitidas (`allowed_networks`) llegan
  en la configuración del servidor; no se configuran localmente. Aun así, el sensor vuelve a
  validar cada job (defensa en profundidad).
- **Catálogo cerrado de jobs**: `discovery_basic`, `discovery_advanced` (Fase 6A) y
  `snmp_inventory` (Fase 6B, ver más abajo); `discovery_basic` con esquema exacto (sin claves extra),
  `sensor_id`/`site_id` propios, sin caducar, target dentro de `allowed_networks`, nunca `/0`,
  número de hosts ≤ `max_hosts_per_job`, puertos 1..65535 sin duplicados. Un job rechazado no se
  ejecuta y se informa como `failed` con un error corto (`job_rejected:<motivo>`).
- **Nada de shell, eval/exec ni binarios recibidos.** TCP connect con `asyncio`. Si se usan
  `ping` o `arp` del sistema, el argv es fijo, construido localmente con la IP normalizada por
  `ipaddress`, sin shell, y se pueden desactivar (`allow_system_ping`, `allow_system_arp`).
- **Credencial protegida**: fichero `0600` creado con `os.open` y escritura atómica en Linux;
  DPAPI (ámbito de la cuenta del servicio) en Windows. Nunca se imprime ni se loggea; los logs
  redactan `Authorization`, tokens y credenciales conocidas.
- **Directorio de datos privado** (`sentra_sensor/fsperm.py`): `0700`/`0600` en POSIX; en
  Windows se lee y se fija la **DACL real** de NTFS (los bits de `st_mode` no la describen).
  Solo SYSTEM, Administradores, la cuenta que ejecuta el sensor, la cuenta virtual
  `NT SERVICE\SentraSensor` y el propietario pueden tener permisos; si hay cualquier otra
  entrada (Users, Everyone...) el sensor escribe una DACL protegida sin herencia. Aplica al
  directorio, a la credencial (antes de escribir el secreto, también tras rotarla), al estado
  y al spool con sus `-wal`/`-shm`. Si no puede protegerlos (p. ej. un volumen FAT o de red sin
  ACL), no arranca ni escribe (fail-closed). `diagnostics` lo muestra en `data_dir_permissions`
  y `credential_permissions`.

## Instalación (desarrollo)

```bash
python3.12 -m venv /home/user/sensorvenv
/home/user/sensorvenv/bin/pip install -e "./sensor[dev]"
```

Solo biblioteca estándar (Python ≥ 3.12). `dev` instala pytest, ruff y mypy.

## Uso

```bash
# 1. Enrolar con el token de un solo uso creado en Sentra (Sites > Sensores).
#    Mejor por fichero o stdin para que no quede en el historial del shell.
sentra-sensor --config /etc/sentra-sensor/sensor.toml enroll \
    --server https://sentra.example.com --token-file /root/sensor.token
# (también: --token-stdin, o --token TOKEN)

# 2. Ejecutar en primer plano (el servicio hace lo mismo).
sentra-sensor --config /etc/sentra-sensor/sensor.toml run

# Estado local, sin red: enrolado, sensor_id, site, modo, spool.
sentra-sensor --config /etc/sentra-sensor/sensor.toml status [--json]

# Diagnóstico: servidor alcanzable, TLS, credencial cargada (sin mostrarla), site, spool.
sentra-sensor --config /etc/sentra-sensor/sensor.toml diagnostics [--json]
```

Para re-enrolar (por ejemplo tras una revocación) se usa `enroll --force` con un token nuevo;
un sensor en marcha detecta el cambio de credencial en disco y vuelve a trabajar sin reinicio.

## Configuración

Ver [`sensor.example.toml`](sensor.example.toml). Claves:

| Clave | Descripción |
|-------|-------------|
| `server_url` | URL del servidor (https). |
| `data_dir` | Directorio de datos. Linux servicio: `/var/lib/sentra-sensor`; Windows: `%ProgramData%\Sentra\Sensor`. |
| `credential_path`, `spool_path`, `state_path` | Relativas a `data_dir` (o absolutas dentro de él). Se rechaza `..` y cualquier ruta que salga de `data_dir`, también vía symlink. |
| `ca_bundle` | PEM de una CA privada adicional. |
| `poll_interval_seconds`, `heartbeat_interval_seconds` | Valores iniciales; el servidor manda los efectivos en `config`. |
| `spool_max_mb`, `spool_max_items`, `spool_max_age_hours` | Límites del spool. |
| `retry_max_delay_seconds` | Tope del backoff exponencial con jitter. |
| `log_level`, `log_dir` | Logs JSON rotados (5 × 1 MB). |
| `allow_system_ping`, `allow_system_arp` | Permiten usar `ping`/`arp` del sistema. |

Las claves desconocidas son un error (una errata no debe ignorarse en silencio).

## Funcionamiento

1. **Heartbeat** periódico con metadatos seguros (versión, plataforma, hostname,
   capabilities, `queue_depth`, `spool_items`, `spool_bytes`, uptime,
   `last_successful_job_at`, `sent_at`). Nunca variables de entorno, tokens ni claves.
   La respuesta trae la configuración efectiva, `pending_jobs`, `cancel_job_ids` y
   `rotate_credential`.
2. **Poll** (`max_jobs=1`) solo si `config.jobs_enabled` y hay `pending_jobs` o venció
   `poll_interval_seconds`. Un job a la vez.
3. **start → scan → spool → flush**: el scan corre en un hilo aparte (los heartbeats siguen,
   así llegan cancelaciones y rotaciones). Cada tanda de hosts se encola en el spool y se
   envía en lotes que respetan `max_observations_per_batch` y `max_batch_bytes`. Al terminar
   se encola `complete` (`completed` / `cancelled` / `timed_out` / `failed`).
4. **Cancelación**: si el heartbeat trae el job en `cancel_job_ids` o un envío de resultados
   responde `cancel_requested=true`, el scan se interrumpe y se envía `complete` `cancelled`
   con lo observado.

Capabilities declaradas (solo lo implementado): `network.discovery.basic`, `network.tcp`,
`network.icmp`, `network.arp`.

### Spool y entrega

- SQLite (WAL, `synchronous=FULL`, fichero `0600`), FIFO por job: un `complete` nunca adelanta
  a los lotes de su job; un job atascado no bloquea a los demás.
- Acotado: al superar `spool_max_items` o `spool_max_mb` se descarta lo más antiguo; lo que
  supere `spool_max_age_hours` caduca. Todo descarte se registra (log + contador).
- **At-least-once**: cada lote lleva un `batch_id` UUID generado al encolar y guardado con el
  lote; los reintentos reenvían exactamente el mismo id y el servidor deduplica.
- Errores: red, 429 y 5xx → backoff exponencial con jitter (respeta `Retry-After`, tope
  `retry_max_delay_seconds`); 404 y 409 (`sensor_job_finished`/`sensor_job_expired`/...),
  413 y 422 → se descarta el elemento (registrado); 401/403 → no se descarta nada.
- Caída larga del servidor: lo observado queda en el spool; cuando el heartbeat vuelve a
  funcionar se reinicia el backoff y se entrega todo, sin duplicados.

### Estados

- `403 sensor_revoked`: el sensor deja de pedir trabajo y registra cómo re-enrolar (token
  nuevo + `enroll --force`). Comprueba el servidor con poca frecuencia.
- `403 sensor_disabled` (o heartbeat con `status: "disabled"`): solo heartbeats.
- `401`: credencial no aceptada; backoff, sin descartar datos.

### Rotación de credencial (dos fases)

El administrador marca la rotación en el servidor; el siguiente heartbeat trae
`rotate_credential=true`. El sensor llama a `POST /sensor/credential/rotate`, guarda la nueva
credencial de forma atómica y la usa desde ese momento. Si no puede guardarla, sigue con la
antigua y el servidor volverá a pedir la rotación.

## Servicio

### Linux (systemd)

[`packaging/linux/sentra-sensor.service`](packaging/linux/sentra-sensor.service): usuario
`sentra-sensor` sin privilegios, `NoNewPrivileges`, `ProtectSystem=strict`, sin capacidades.

```bash
useradd --system --home-dir /var/lib/sentra-sensor --shell /usr/sbin/nologin sentra-sensor
python3.12 -m venv /opt/sentra-sensor && /opt/sentra-sensor/bin/pip install ./sensor
install -d -m 0750 -g sentra-sensor /etc/sentra-sensor
install -m 0640 -g sentra-sensor sensor/sensor.example.toml /etc/sentra-sensor/sensor.toml  # editar server_url
install -d -m 0700 -o sentra-sensor -g sentra-sensor /var/lib/sentra-sensor
cp sensor/packaging/linux/sentra-sensor.service /etc/systemd/system/
# Enrolar COMO el usuario del servicio, para que la credencial sea suya:
sudo -u sentra-sensor SENTRA_SENSOR_SERVICE=1 /opt/sentra-sensor/bin/sentra-sensor \
    --config /etc/sentra-sensor/sensor.toml enroll --server https://sentra.example.com --token-stdin
systemctl daemon-reload && systemctl enable --now sentra-sensor
```

**ICMP y `CAP_NET_RAW`**: el `ping` del sistema funciona sin privilegios si el grupo del
servicio está en `net.ipv4.ping_group_range` (habitual en distribuciones recientes). Si no,
o se amplía ese sysctl (recomendado) o se descomentan en la unidad
`CapabilityBoundingSet=CAP_NET_RAW` y `AmbientCapabilities=CAP_NET_RAW` (con
`NoNewPrivileges=true`, las *file capabilities* de `/usr/bin/ping` no se aplican). También se
puede desactivar ICMP con `allow_system_ping = false`. TCP y ARP (`/proc/net/arp`) no
necesitan ninguna capacidad.

### Windows (servicio `SentraSensor`)

[`packaging/windows/install-sentra-sensor.ps1`](packaging/windows/install-sentra-sensor.ps1)
(como Administrador):

```powershell
.\install-sentra-sensor.ps1 -Server https://sentra.example.com -TokenFile C:\tmp\token.txt `
    -Python "C:\Program Files\SentraSensor\python\python.exe"
```

- El servicio habla con el SCM por `ctypes` (`sentra_sensor/winservice.py`, mismo patrón que el
  agente). **pywin32 no es necesario.**
- Corre con la cuenta virtual `NT SERVICE\SentraSensor`. `%ProgramData%\Sentra\Sensor` queda
  sin herencia y solo accesible para SYSTEM, Administradores y esa cuenta.
- La credencial se cifra con DPAPI en el ámbito de la cuenta del servicio. Por eso el
  enrollment lo hace **el propio servicio** en su primer arranque
  (`run --service --enroll-token-file ...`), y borra el fichero del token después.
  Consecuencia: `status` ejecutado por un administrador muestra el estado local, pero no puede
  descifrar la credencial (es lo esperado).
- ARP en Windows usa `arp -a` (argv fijo, sin shell) y ping usa `ping -n 1 -w <ms>`.

**Validación en Windows real pendiente**: arranque/parada bajo el SCM, reinicio por fallo,
DPAPI con la cuenta virtual y ACL del directorio solo se pueden comprobar en un Windows físico.

## SNMP (Fase 6B, extra opcional)

Inventario SNMP de solo lectura de switches, routers, APs y cortafuegos registrados en Sentra
(docs/snmp-network-intelligence.md). Requiere el extra `snmp` (pysnmp 7.1 + cryptography):

```bash
/opt/sentra-sensor/bin/pip install "./sensor[snmp]"          # Linux
"C:\Program Files\SentraSensor\python\python.exe" -m pip install ".\sensor[snmp]"   # Windows
```

- Sin el extra el sensor no declara `snmp.*` y el servidor nunca le envía jobs SNMP.
- El job trae nombres de módulo (`system`, `entity`, `interfaces`, `lldp`, `cdp`, `bridge`,
  `vlan`), nunca OIDs; el sensor solo consulta su catálogo cerrado
  (`sentra_sensor/snmp/catalog.py`) con GET y GETBULK. No hay ninguna operación SET.
- Una sola dirección dentro de las redes del site; SNMPv3 siempre authPriv (SHA + AES); v2c
  solo si el servidor lo envía; SNMPv1 nunca.
- La credencial llega solo en la respuesta de `start` del job, debe coincidir con el perfil,
  la revisión y la versión del job, vive solo en memoria y se añade al filtro de logs. Nunca
  se escribe en el spool, el estado ni los logs.
- Límites del job revalidados por el sensor: timeout, reintentos, repeticiones de GETBULK,
  varbinds totales, filas por tabla y plazo; cancelable desde el servidor. Un agente que
  devuelve OIDs que no avanzan se corta como respuesta malformada.
- Solo UDP saliente al puerto SNMP del equipo; no necesita privilegios ni raw sockets.

## Pruebas y calidad

```bash
cd sensor
/home/user/sensorvenv/bin/pytest
/home/user/sensorvenv/bin/ruff check .
/home/user/sensorvenv/bin/ruff format --check .
/home/user/sensorvenv/bin/mypy
/home/user/sensorvenv/bin/mypy --platform win32   # tipos de la rama Windows (ctypes)
```

Las pruebas no usan la red real: el servidor es un transporte falso en memoria y, para el
camino HTTP real, un servidor en `127.0.0.1`. Los probers del scanner se inyectan.
