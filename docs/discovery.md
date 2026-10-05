# Hybrid monitoring: network discovery and agentless preparation

Sentra knows hosts in two complementary ways:

| Method | Label in the UI | What Sentra knows |
|---|---|---|
| `discovered` | **Discovered** | What can be observed from the Sentra server over the network: address, MAC (same segment only), reverse DNS name, reachable TCP ports, probable type |
| `agentless` | **Monitored** | Reserved for remote collection without agent (WinRM/WMI, SSH, SNMP). Contracts only, nothing collects yet |
| `agent` | **Managed** | Everything the Sentra agent reports (telemetry, inventory, processes, events) plus the network view |

The path is DISCOVERED → MONITORED → MANAGED. Installing the agent on a discovered host
does not create a second asset: both records converge into one (see Reconciliation).

The agent-based flow is unchanged: agents use the same protocol and see no difference.

## Safety rules (read first)

- **Nothing is probed unless you list networks** in `DISCOVERY_ALLOWED_NETWORKS`. The
  default is empty: discovery is disabled.
- Refused at startup (the API does not start with an invalid allowlist) and for every
  target: `0.0.0.0/0`/`::/0`, networks larger than `DISCOVERY_MAX_HOSTS_PER_NETWORK`
  (default 1024 addresses, hard cap 65536), multicast/reserved/unspecified/broadcast space,
  networks with host bits set (`192.168.1.10/24`), and **public Internet space** unless
  `DISCOVERY_ALLOW_PUBLIC_NETWORKS=true`.
- An explicit target (`discover --target`) must be inside an allowed network.
- `DISCOVERY_EXCLUDED` addresses are never probed.
- What a probe is: a full TCP connect that is closed immediately (no data sent, no banner
  read), one ICMP echo through the operating system's `ping`, a read of the server's own
  neighbour (ARP) table, and a reverse DNS lookup. Desde la Fase 4E, a los hosts vivos se
  les piden además los nombres que ellos mismos publican (mDNS, NetBIOS y SSDP/UPnP, ver
  "Identificación de dispositivos"); se puede desactivar con `DISCOVERY_IDENTIFY=false`.
  **No** raw packets, SYN/stealth scans,
  fragmentation, spoofing, evasion, banner grabbing, OS fingerprinting, credentials,
  brute force or exploitation. No elevated privileges are needed or requested.
- Load is bounded: `DISCOVERY_CONCURRENCY` probes in flight (default 64),
  `DISCOVERY_MAX_PROBES_PER_SECOND` started per second (default 200), a timeout per probe
  (`DISCOVERY_TIMEOUT_MS`, default 800) and per run (`DISCOVERY_JOB_TIMEOUT_MINUTES`).
- Runs are started from the dashboard (**Red → Iniciar descubrimiento**, Fase 4D), by the
  periodic job or from the server CLI. Starting and cancelling over HTTP only exist behind
  the local console guard (`/api/v1/console/discovery`, see below): from another machine
  of the LAN they answer 403. The public `/api/v1/discovery/*` routes are read-only.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DISCOVERY_ALLOWED_NETWORKS` | empty (off) | Comma separated CIDRs/addresses Sentra may probe |
| `DISCOVERY_EXCLUDED` | empty | Addresses/networks never probed |
| `DISCOVERY_ALLOW_PUBLIC_NETWORKS` | `false` | Allow globally routable ranges you own |
| `DISCOVERY_MAX_HOSTS_PER_NETWORK` | `1024` | Largest network accepted (1–65536) |
| `DISCOVERY_PORTS` | `common` | Profiles `minimal`, `common`, `windows`, `printers`, `web` and/or ports and ranges (`common,8081,9000-9005`, max 1024 ports) |
| `DISCOVERY_TIMEOUT_MS` | `800` | Per probe (50–10000) |
| `DISCOVERY_CONCURRENCY` | `64` | Probes in flight (1–256) |
| `DISCOVERY_MAX_PROBES_PER_SECOND` | `200` | Rate limit (1–5000) |
| `DISCOVERY_ICMP` | `true` | Use the system `ping` (skipped automatically if missing) |
| `DISCOVERY_REVERSE_DNS` | `true` | Reverse lookups of live hosts |
| `DISCOVERY_IDENTIFY` | `true` | Sondas de nombre de hosts vivos: mDNS, NetBIOS y SSDP/UPnP (Fase 4E) |
| `DISCOVERY_OUI_FILE` | vacío | Ficheros OUI del IEEE (`oui.csv`, `mam.csv`, `oui36.csv`) separados por coma para el fabricante de la NIC. Vacío: fabricante desconocido |
| `DISCOVERY_INTERVAL_MINUTES` | unset (manual) | Periodic runs over every allowed network (≥ 5) |
| `DISCOVERY_JOB_TIMEOUT_MINUTES` | `30` | A run stops here; its results are kept as partial |
| `DISCOVERY_OFFLINE_AFTER_MISSES` | `3` | Complete runs without seeing a host before it is offline |

Example (`.env`):

```
DISCOVERY_ALLOWED_NETWORKS=192.168.1.0/24,10.0.10.0/24
DISCOVERY_EXCLUDED=192.168.1.250
DISCOVERY_INTERVAL_MINUTES=60
```

## Descubrimiento desde el dashboard (Fase 4D)

El uso normal ya no necesita PowerShell: **Sentra → Red → Iniciar descubrimiento**.

### Flujo

1. La página Red muestra las redes autorizadas que devuelve el servidor (`GET
   /api/v1/discovery/scope`, con el número de direcciones de cada una) y el estado del
   descubrimiento automático (`GET /api/v1/discovery/schedule`).
2. **Iniciar descubrimiento** abre un modal: redes autorizadas, red a analizar (lista
   cerrada, sin texto libre), alcance (direcciones, puertos, ritmo máximo, exclusiones),
   estado de esa red y la advertencia de que solo se analizan redes autorizadas.
3. **Iniciar** llama a `POST /api/v1/console/discovery/jobs` con `{"target": "<red>"}`. La API
   valida el target con la misma allowlist que la CLI, crea el job **en cola** y responde al
   momento con `202` y el job. No hay ninguna petición HTTP abierta durante el scan.
4. El scan corre en segundo plano en el proceso de la API (`DiscoveryRunner`, mismo
   `DiscoveryService` que la CLI y el scheduler). La web consulta `GET
   /api/v1/discovery/jobs/{job_id}` cada 1,5 s mientras el job está activo.
5. Al terminar se muestra el resultado; el historial y la tabla Red se refrescan solos.

Si `DISCOVERY_ALLOWED_NETWORKS` está vacío, la página dice: «El descubrimiento de red está
desactivado. Configure DISCOVERY_ALLOWED_NETWORKS en el servidor.» y el botón queda
deshabilitado. Las variables de entorno no se pueden cambiar desde el navegador.

### Estados

| Estado | Significado |
|---|---|
| `queued` | Pedido desde el dashboard, esperando al runner. Ya reserva su red. |
| `running` | Escaneando. Avanzan los contadores reales. |
| `completed` | Scan completo: el único que permite conclusiones negativas. |
| `failed` | Error (`stop_reason=error`) o proceso desaparecido (`interrupted`). |
| `cancelled` | Parado antes de terminar: `operator`, `shutdown` o `timeout`. Resultado parcial. |

Los jobs del dashboard se ejecutan **de uno en uno** por proceso de la API: el segundo
espera en cola, así la carga sobre la red nunca supera la de un scan. Una red solo puede
tener un job en cola o en curso (índice único parcial): un segundo «Iniciar» sobre la misma
red, la CLI o el scheduler reciben «ocupado» (`409 discovery_busy`) o la saltan.

### Progreso

Mientras corre, el job publica cada segundo valores reales: hosts evaluados / total
(`hosts_scanned` / `hosts_total`), encontrados (`hosts_alive`), errores y fase (`progress`).

- En la fase de **liveness** el total es exacto (todas las direcciones): se muestra barra.
- En la fase de **detalle** (puertos y DNS de los hosts vivos) la barra usa como total los
  hosts vivos encontrados.
- Sin un total exacto (preparando, guardando) **no se inventa un porcentaje**: spinner y
  contadores. Tampoco hay porcentaje global, porque el peso de cada fase depende de cuántos
  hosts respondan.
- Nuevos y actualizados solo se conocen al aplicar el resultado, al final.

### Cancelación

**Cancelar** llama a `POST /api/v1/console/discovery/jobs/{job_id}/cancel`.

- Un job en cola se cancela en el acto y nunca se ejecuta.
- En uno en curso se guarda `cancel_requested_at` en la base de datos; el hilo de progreso
  lo lee en el siguiente latido (≈1 s) y el scanner deja de lanzar sondas. Al estar en la
  base de datos funciona aunque la petición llegue a otro worker de la API.
- Un job terminado responde `409 discovery_job_finished`.
- **Un scan cancelado, fallido o incompleto nunca genera `asset_disappeared` ni
  `port_closed`**, ni suma fallos (`network_misses`, `misses` de puerto). Lo que sí vio
  (hosts nuevos, puertos abiertos) se guarda: es evidencia positiva.
- Sin huérfanos: al apagar la API se cancela el scan en curso (`shutdown`) y los jobs en
  cola se cierran como cancelados. Si el proceso muere sin apagarse, el latido
  (`heartbeat_at`) deja de avanzar y a los 5 minutos el job pasa a `failed` / `interrupted`,
  liberando la red.

### Baseline

Sin cambios de semántica: el **primer scan completo** de una red es la línea base y no
genera alertas de nuevos activos ni puertos. Un primer scan cancelado no es línea base.

Bug corregido en esta fase: un primer scan cancelado fijaba la línea base de exposición de
los hosts con los pocos puertos de liveness que llegó a sondear, y el siguiente scan completo
alertaba `port_exposed` de todos los demás puertos que ya estaban abiertos. Ahora la línea
base de exposición de un activo solo la fija un scan completo.

### Resultado e historial

El resultado muestra hosts evaluados, dispositivos encontrados, nuevos, actualizados,
nuevos puertos, puertos cerrados y duración, con las acciones **Ver dispositivos** (tabla
Red filtrada por esa red, los más recientes primero), **Ver cambios** (activos nuevos y
cambios de red/exposición de ese job) y **Ejecutar nuevamente**.

**Ejecuciones recientes** lista fecha/hora, red, estado, encontrados, nuevos, actualizados,
duración, perfil (puertos, ICMP, DNS) y origen (Dashboard, CLI, Programado). Cada fila abre
su detalle. El historial no se puede borrar desde el navegador.

### Descubrimiento automático

Solo lectura: ON/OFF, intervalo, última ejecución y próxima ejecución prevista. Se configura
con `DISCOVERY_INTERVAL_MINUTES` (y requiere redes autorizadas y tareas en segundo plano
activas). La próxima ejecución es la estimación del proceso de la API que atiende la
petición.

### Seguridad

- Iniciar y cancelar requieren sesión con permiso `discovery:run` (roles admin y analyst),
  `Origin` permitido y `X-CSRF-Token` ([authentication.md](authentication.md)). Un viewer
  solo ve los resultados (`GET /discovery/*`, `monitoring:read`); sin sesión, `401`.
- `ADMIN_API_KEY` nunca llega al navegador; el frontend no guarda nada en `localStorage`,
  `sessionStorage` ni cookies.
- El target se valida siempre en el backend (`422 discovery_target_refused`): fuera de la
  allowlist, `0.0.0.0/0`, Internet, multicast, broadcast, reservadas, demasiado grandes o
  con bits de host. Antes de escanear, el runner vuelve a validar el target del job.
- Cada petición queda en el log (`discovery requested`, `discovery cancel requested`) con
  red, vía y job, sin cabeceras ni credenciales, y en la auditoría (`discovery_started`,
  `discovery_cancelled`) con el usuario.
- Mismo motor defensivo: sin fuerza bruta, evasión, paquetes raw, credenciales ni
  fingerprinting agresivo.

### API

| Método y ruta | Acceso | Uso |
|---|---|---|
| `GET /api/v1/discovery/scope` | lectura | Redes autorizadas (`networks` con tamaño), puertos, límites |
| `GET /api/v1/discovery/schedule` | lectura | Estado del scheduler |
| `GET /api/v1/discovery/jobs` | lectura | Historial (campos nuevos: `requested_via`, `hosts_total`, `hosts_updated`, `ports_opened`, `ports_closed`, `cancel_requested`, `stop_reason`, `progress`, `parameters`) |
| `GET /api/v1/discovery/jobs/{job_id}` | lectura | Estado, progreso, resultado, `new_assets`, `changes` |
| `POST /api/v1/console/discovery/jobs` | consola local | Encola un job (`202`) |
| `POST /api/v1/console/discovery/jobs/{job_id}/cancel` | consola local | Cancela |

### Limitaciones

- Una cola en memoria por proceso de la API; con varios workers cada uno tiene la suya
  (la reserva por red en la base de datos evita escanear dos veces la misma red).
- El progreso se publica cada segundo: lo mostrado puede ir un segundo por detrás.
- La cancelación de un job en curso tarda hasta un latido más las sondas que ya estaban en
  vuelo (como mucho `DISCOVERY_TIMEOUT_MS`).
- La configuración (redes, intervalo, puertos) sigue en variables de entorno.

### CLI como alternativa administrativa

`python -m app.cli discover` queda como herramienta administrativa y de depuración: mismo
servicio, misma allowlist, ejecuta en primer plano sin pasar por la cola de la API y aparece
en el historial con origen CLI.

## Identificación de dispositivos (Fase 4E)

Después de cada scan Sentra responde, para cada activo: **qué es, cómo se llama, qué tipo
tiene, qué fabricante parece tener, qué evidencia lo sustenta y con qué confianza**. Todo
se calcula en `app/discovery/classify.py` (función pura, sin red) a partir de lo que el scan
ya observó, y se guarda en el activo (`services/identification.py`).

### Campos

| Campo (API) | Significado |
|---|---|
| `device_name` / `name_source` | Nombre resuelto y de dónde sale. Null si nada lo nombra |
| `device_type` | `pc`, `laptop`, `server`, `mobile`, `tablet`, `console`, `printer`, `router`, `network_switch`, `access_point`, `iot`, `voice_assistant`, `smart_tv`, `nas`, `virtual_machine`; null = desconocido. La UI los muestra en español |
| `device_vendor` / `device_model` | Fabricante y modelo **del dispositivo**, solo con evidencia real |
| `vendor` / `network_adapter_vendor` | Organización OUI de la MAC y su marca corta: fabricante **de la NIC** |
| `probable_os` | SO deducido desde la red, sin versión. Null con agente (manda `os_name`) |
| `classification_confidence` | `low`, `medium`, `high` |
| `classification_evidence` | `[{"source": "...", "value": "..."}]`: el porqué |

### Prioridad del nombre

1. Nombre manual: no existe todavía (Sentra no permite renombrar activos).
2. Hostname reportado por el agente (MANAGED).
3. Nombre DHCP: Sentra no es servidor DHCP; el DNS del router suele registrar esos
   nombres y llegan por el punto siguiente.
4. DNS inverso (sin el dominio local `.lan`, `.home`, `.local`...; se descartan nombres de
   relleno como `192-168-1-20` o `localhost`).
5. mDNS. 6. NetBIOS. 7. `friendlyName` UPnP. 8. Fabricante + modelo si ambos son seguros.
9. Sin nombre: la UI muestra el tipo ("Consola probable") o "Dispositivo desconocido" y la
   IP como dato secundario. En alertas, eventos y CLI `display_name` sigue cayendo en la
   IP, que ahí es más útil que un texto genérico.

### Confianza

Cada pista tiene una fuerza (débil, media, fuerte, autoritativa) y se suman por tipo:

- **high**: fuente autoritativa (agente, gateway por defecto del servidor, UPnP
  `InternetGatewayDevice`) o pistas independientes que se confirman. Ejemplo: hostname
  `MNA-LX9` (código de modelo Huawei) + OUI Huawei → Móvil, Huawei, modelo MNA-LX9.
- **medium**: una pista clara o varias débiles coherentes (`MNA-LX9` con MAC aleatoria).
- **low**: una pista débil (un solo puerto de Windows → "PC probable").
- Pistas incompatibles empatadas → tipo desconocido; no se elige al azar.

La UI presenta como "probable" todo lo que no es confianza alta.

### El fabricante de la NIC no es el del dispositivo

`app/discovery/vendors.py` separa fabricantes de dispositivos (Huawei, Apple, Nintendo...)
de fabricantes de chips/NICs (Realtek, Intel, Broadcom...). Un Nintendo Switch con un
adaptador USB-Ethernet Realtek muestra **NIC Realtek** y, sin más evidencia, tipo
desconocido; con un nombre `Nintendo-Switch` pasa a **Consola probable** con fabricante
Nintendo. Las MAC aleatorias (bit localmente administrado, típicas de móviles) no tienen
fabricante y quedan como evidencia propia. `52:54:00` se reconoce como NIC virtual QEMU/KVM.

### Fuentes agentless

| Fuente | Qué se hace | Límite |
|---|---|---|
| ARP | Lectura de la tabla del propio servidor | Solo mismo segmento L2 |
| DNS inverso | Resolver del sistema | `DISCOVERY_TIMEOUT_MS` (mín. 1 s) |
| mDNS | Pregunta PTR unicast al puerto 5353 del host (RFC 6762 §6.7) | `DISCOVERY_TIMEOUT_MS`, respuesta acotada |
| NetBIOS | Consulta NBSTAT (como `nbtstat -A`), solo el nombre del equipo | `DISCOVERY_TIMEOUT_MS` |
| SSDP/UPnP | Un M-SEARCH por scan con TTL 1 y lectura del XML de descripción que anuncia el dispositivo | 2 s de escucha; XML ≤ 64 KB, sin DTD, solo `http://` a la misma IP que respondió (anti-SSRF) |
| OUI | Fichero local del IEEE, en memoria y cacheado | Sin consultas a Internet |
| Puertos | Los del scan de exposición | Pistas débiles |

No hay explotación, fuerza bruta, credenciales, evasión ni fingerprinting de paquetes. Las
sondas de nombre usan la misma concurrencia, ritmo y timeout que el resto y solo se envían a
hosts vivos dentro de la allowlist; un fallo de una sonda es un error del job, no del scan.

### Base OUI (fabricante de la NIC)

Sentra no incluye el registro OUI completo (varios MB) ni lo descarga solo. Para activarlo:

```powershell
# Descarga manual del registro público del IEEE (MA-L; opcionalmente mam.csv y oui36.csv).
New-Item -ItemType Directory -Force C:\ProgramData\Sentra\oui | Out-Null
Invoke-WebRequest https://standards-oui.ieee.org/oui/oui.csv -OutFile C:\ProgramData\Sentra\oui\oui.csv
```

y en `.env`: `DISCOVERY_OUI_FILE=C:\ProgramData\Sentra\oui\oui.csv`. Formatos aceptados: CSV
del IEEE (`Registry,Assignment,Organization Name,...`) y `oui.txt`. El fichero se relee solo
cuando cambia su fecha de modificación. Sin fichero, el fabricante queda desconocido.

### Cambios de clasificación

Un cambio de tipo (por ejemplo Móvil → Consola) se registra como cambio del activo
(`identity` / `reclassified`) con el job que lo detectó; **nunca** como alerta. La primera
clasificación tras actualizar no se registra (no cambió el dispositivo, cambiaron las
reglas). `python -m app.cli reclassify-assets` recalcula todos los activos con los datos
guardados, sin sondear la red (útil tras configurar la base OUI).

### Reconciliación

Al instalar el agente en un host descubierto se conserva todo (historial, exposición,
fechas, alertas) y también lo observado en la red (`identity_observations`); el agente pasa
a ser la fuente autoritativa: "PC probable" deducido de la red se convierte en el hostname,
tipo y SO que reporta el agente.

## Running it (CLI)

```powershell
cd backend
.venv\Scripts\python.exe -m app.cli discovery-scope          # what would be probed (no probing)
.venv\Scripts\python.exe -m app.cli discover                 # every allowed network, now
.venv\Scripts\python.exe -m app.cli discover --target 192.168.1.0/28
```

Each run over one network is a **job** (`GET /api/v1/discovery/jobs`): start/end time,
network, hosts scanned/up/new, open ports, probes, errors, duration, whether it was the
baseline. A database index allows only one queued or running job per network, so two
schedulers, API workers or a manual run cannot scan the same network at the same time. A
job left queued or running by a crashed process is marked failed (`interrupted`) once its
heartbeat is 5 minutes old.

A /24 with the `common` profile (27 ports) takes about 35 s at the default rate limit
(6858 probes; measured on loopback, where every address answers). Dead addresses cost
little: only a few liveness ports are tried before the full port list, and only for live
hosts.

## What a run does

1. **Liveness** per address: ping (if available) and a TCP connect to a few likely ports.
   An echo reply, an accepted connection or a refusal (RST) proves the host is up.
2. **Neighbour table**: complete entries mark silent hosts on the same segment as up and
   give their MAC.
3. **Ports and name**: the remaining configured ports and reverse DNS, for live hosts.
4. **Persistence**: hosts are matched to existing assets, ports compared with the baseline,
   changes and alerts recorded.

### Baseline and changes

- The **first complete run of a network** records what is there and raises **no** alert;
  so does the first port scan of any single asset. This avoids hundreds of alerts on day one.
- Later runs record changes in the asset's change history (category `exposure` or
  `network`) and raise alerts:

| Rule | Severity | When |
|---|---|---|
| `asset_discovered` | info | A new host with a name or a probable type appears |
| `unknown_device` | warning | A new host with neither appears ("previously unknown device") |
| `asset_disappeared` | warning | A discovered host was not seen for `DISCOVERY_OFFLINE_AFTER_MISSES` complete runs (resolves when seen again) |
| `port_exposed` | critical for remote administration, file sharing and databases (22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985/5986, 6379, 9200, 27017), warning otherwise | A port became reachable |
| `port_closed` | info | A port open before was not reachable in 2 consecutive complete runs of a live host |
| `monitoring_lost` | warning | An agent asset answers on the network but its agent stopped reporting (resolves with the next agent contact) |

An open port is a **signal of exposure or change, not an attack**. While a port stays open
it raises nothing more; `port_exposed`/`port_closed`/new-asset alerts resolve themselves
after `ALERT_EVENT_QUIET_MINUTES` without new occurrences, like event-based alerts.

Negative conclusions (port closed, host gone) are only drawn from **complete** runs: a
cancelled or timed-out run did not probe everything.

### Device type

Only from evidence, always with the reason shown, otherwise unknown (null):

- reported by the agent (Windows / Linux);
- default gateway of the Sentra server → network device;
- 9100 (JetDirect) or 515 (LPD) open → printer;
- 135 (MSRPC), 3389 (RDP) or 5985/5986 (WinRM) open → Windows.

SSH alone, or web ports alone, say nothing reliable and are not guessed. The vendor (OUI)
column stays empty until an OUI database is added. Service names next to ports are the
IANA name for the port number (a hint: the service is never contacted).

### Reconciliation (one asset per host)

- Discovery matches a host to an existing asset by **MAC** first (including the MACs of
  the agent's network interfaces), then by **address** when the MACs do not contradict each
  other. The same address with a different known MAC is another device (e.g. DHCP reuse).
- When an agent enrolls (by address) or sends its inventory (by interface MACs and
  addresses), a matching discovered record is **merged** into the agent's asset: first
  discovery time, ports and their baseline, change history and alerts move over, and the
  discovered record is deleted. Ambiguous matches (several candidates) are not merged and
  are logged.
- Agent data (hostname, OS…) is never overwritten by network observations.

### Agent + network correlation

`GET /api/v1/assets/{id}/exposure` (tab **Exposure**) shows each reachable port with the
process the agent sees listening on it (PID, name, executable and user from the process
snapshot), and the agent's listening ports with whether the network can reach them
(reachable / not reachable, e.g. bound to 127.0.0.1 or firewalled / not probed because the
port is not in `DISCOVERY_PORTS`).

## Agentless monitoring (prepared, not implemented)

`backend/app/agentless/` defines the contracts every future remote collector must follow:

- **Read only**: there is no write/execute capability in the contract. Adapters never
  enable WinRM, change TrustedHosts, firewall rules or policies, start/stop services or
  install anything.
- **Credentials**: adapters receive a `CredentialRef` (an opaque id, never the secret) and
  ask a `SecretProvider` at the moment of use; `Secret` values do not appear in `repr` or
  logs. No provider is shipped, so nothing can authenticate yet. Options to decide later:
  Windows Credential Manager/DPAPI on the Sentra server, an OS keyring, or HashiCorp Vault.
  Never plain text in `.env` or the database.
- **Explicit opt-in per asset**: an open 5985 port is not a reason to try WinRM.
- **Same data shape as the agent**, so change detection and alert rules apply unchanged.

Planned adapters and their read-only operations are listed in `app/agentless/adapters.py`:
WinRM, WMI/CIM, remote Event Log, SSH (systemd, journald, dpkg/rpm), SNMP (switches,
routers, printers, access points, UPS, NAS; SNMPv3 authPriv preferred, never SET).
Discovery does not depend on any of them.

## 🪟 VALIDACIÓN LOCAL EN WINDOWS

Tested here on Linux (real TCP on loopback; Windows tool output from captured samples):

- `PING.EXE` success detection (needs "TTL=" in the reply; exit code alone lies), `ARP.EXE -a`
  and `ROUTE.EXE print -4` parsing in Spanish/English.
- Windows connect error codes (10061 refused, 10051/10065 unreachable).
- **Sentra server on Windows: refusals arrive late.** Windows retries the SYN after a RST
  before reporting "connection refused" (about 1–2 s; confirmed on Windows 11 loopback, where
  a probe with a 1 s timeout returns `filtered`). With the default `DISCOVERY_TIMEOUT_MS=800`
  closed ports are therefore reported as `filtered` instead of `closed`. Consequences:
  - exposure is unaffected: open ports are found, and "port closed" counts `filtered` too;
  - liveness loses one signal: a host that only answers with refusals (no open configured
    port, no ping reply) is not seen as up, unless it is on the same segment (ARP finds it).
  - If that matters, raise `DISCOVERY_TIMEOUT_MS` (e.g. 2500) at the cost of longer scans;
    a Linux Sentra server does not have this behaviour.
- Windows Defender Firewall blocks inbound ICMP echo by default on many profiles: hosts may
  be found by TCP/ARP only.
- Identificación (Fase 4E), pendiente de validar en Windows real:
  - mDNS y NetBIOS usan UDP sobre el ProactorEventLoop; un "port unreachable" llega como
    WSAECONNRESET y se trata como "sin respuesta". Probado solo en Linux (loopback real).
  - SSDP: el M-SEARCH multicast necesita que el firewall de Windows permita las respuestas
    UDP entrantes a python.exe (perfil Privado). Si las bloquea, el scan sigue igual pero
    sin datos UPnP (fabricante/modelo de Smart TVs, NAS, routers).
  - NetBIOS sobre TCP/IP debe estar activo en el adaptador del servidor para recibir
    respuestas NBSTAT de otros equipos Windows.
