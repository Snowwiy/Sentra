# Helper de aislamiento seguro (Fase 6E.7)

> Modelo decidido por Jesus el 2026-10-22 (helper separado y privilegiado). Afecta a privilegios
> y a acciones automáticas sobre activos. No se instala ni se activa sin una decisión
> explícita del administrador de cada equipo.

## Modelo de privilegios

- El agente sigue sin privilegios y nunca toca el firewall.
- El aislamiento lo aplica un servicio separado y opcional:
  - Windows: servicio `SentraIsolation` como LocalSystem;
  - Linux: unidad systemd `sentra-isolation` como root, con
    `CapabilityBoundingSet=CAP_NET_ADMIN CAP_DAC_OVERRIDE CAP_CHOWN`.
- El helper no habla con la red. Se comunica con el agente solo por ficheros en un directorio
  de intercambio local.
- La política del helper es local y la escribe un administrador del equipo. El servidor no
  la puede cambiar:
  - Windows: `%ProgramData%\Sentra\Isolation\isolation.toml`;
  - Linux: `/etc/sentra-agent/isolation.toml`.

```toml
enabled = false          # desactivado por defecto
max_minutes = 240        # 1-1440; duración máxima de un aislamiento
allow_dns = true         # los DNS configurados en el equipo siguen accesibles
extra_allow = []         # IPs o redes extra (como mucho /8 en IPv4 y /16 en IPv6)
agent_config = '/etc/sentra-agent/agent.toml'
```

Una clave desconocida, un tipo incorrecto o una red demasiado ancha invalidan la política.
Una política inválida cuenta como desactivada: el helper informa `helper = error` y
`error_code = policy_invalid`.

## Qué queda permitido

El helper calcula lo permitido solo con datos locales:

- las IPs del host de `api_url` del `agent.toml` local, resueltas en el momento de aislar (si
  no se resuelven, no aísla: `server_unresolvable`);
- loopback y el broadcast DHCP `255.255.255.255`;
- el servidor DHCP actual en Windows; en Linux, los puertos UDP 67 y 68;
- los DNS configurados, si `allow_dns` (en Linux también los de
  `/run/systemd/resolve/resolv.conf`);
- `extra_allow`;
- si el servidor tiene IPv6, `fe80::/10` y `ff02::/16` (sin descubrimiento de vecinos no
  hay ruta IPv6).

La petición del agente tiene claves exactas: `session_id`, `action`, `expires_at` y
`requested_at`. Una petición con cualquier otra clave, por ejemplo una lista de direcciones,
se descarta sin aplicar nada.

## Cómo se aplica

### Windows: Firewall de Windows Defender

- Reglas de bloqueo de entrada y salida, por familia IPv4 e IPv6, en el grupo propio
  `Sentra Isolation`, hacia el complemento de lo permitido. En Windows un bloqueo prevalece
  sobre cualquier permiso, así que se bloquea "todo menos X" calculando los rangos que no son
  X; no se escribe "bloquear todo + permitir X".
- No desactiva el firewall, no cambia perfiles ni toca reglas ajenas.
- Si el perfil de la red activa está desactivado, no aísla (`firewall_disabled`): las
  reglas no harían nada.
- Crea además una tarea programada de respaldo `\Sentra\SentraIsolationExpiry`, como SYSTEM
  y a la hora de expiración, que borra el grupo aunque el helper esté parado. Si la tarea no
  se puede crear, el helper revierte y falla (`backup_task_failed`).
- Los scripts de PowerShell solo contienen valores validados: rangos generados por
  `ipaddress` y comprobados con una expresión regular estricta, el UUID de la sesión y una
  fecha formateada por el helper.

### Linux: nftables

- Tabla propia `inet sentra_isolation` con las cadenas `input` y `output`, prioridad
  `filter - 5` y política `drop`.
- Acepta loopback, los conjuntos `allow4` y `allow6`, el descubrimiento de vecinos ICMPv6 y
  DHCP por puertos.
- Se aplica en una transacción con `nft -f`. No toca las tablas de firewalld, ufw ni de
  nadie más: un paquete debe aceptarse en todas las cadenas base del gancho, así que la
  cadena propia basta.
- Sin el binario `nft` (solo iptables-legacy) no hay aislamiento (`nftables_unavailable`).
- La tabla no se guarda en `/etc/nftables.conf`: un reinicio del equipo la borra, y el helper
  lo informa como `rules_lost` sin volver a aplicarla.

### macOS

No hay aislamiento en 0.5.0, y el agente nunca anuncia `isolate_host` ni
`release_isolation`.

## Verificación, expiración y recuperación

- Antes de tocar el firewall, el helper guarda el estado `applying` en su directorio
  privado. Después aplica las reglas, las lee de vuelta y compara nombres, sentido, acción y
  rangos. Si no coinciden, revierte (`verification_failed`).
- La expiración la aplica el propio helper, sin depender del agente ni del servidor; en
  Windows también la tarea de respaldo.
- Al arrancar, el helper revierte cualquier estado caducado, a medio aplicar (`applying`,
  `reverting`, `failed`) o con la política desactivada. Si la política se desactiva
  durante un aislamiento, también revierte.
- Cada 60 s comprueba que sus reglas siguen presentes. Si alguien las borró fuera de Sentra,
  informa `rules_lost`.
- Una sola sesión a la vez:
  - otra sesión distinta recibe `already_isolated`;
  - la reentrega del mismo comando no se aplica dos veces;
  - un `release` de otra sesión recibe `session_mismatch`.
- El estado que permite revertir vive en el directorio privado del helper:
  - Windows: `%ProgramData%\Sentra\Isolation\state`;
  - Linux: `/var/lib/sentra-isolation`.

  El `state.json` del directorio de intercambio es solo una copia informativa: un agente
  comprometido no puede fabricar un estado que el helper vaya a usar.

## Directorio de intercambio

| | Windows | Linux |
|---|---|---|
| Ruta | `%ProgramData%\Sentra\Agent\isolation\` | `/var/lib/sentra-agent/isolation/` |
| Permisos | SYSTEM y Administradores, control total; el agente puede leer y crear ficheros | `root:sentra-agent`, modo `1770` (sticky) |
| Quién escribe | el agente crea `request.json`; el helper escribe `status.json` y `state.json` | igual |

- El agente crea `request.json` en exclusiva (`O_EXCL`). Si ya hay una petición pendiente,
  responde `helper_busy`; nunca la sustituye.
- En Linux, el helper trabaja sobre el descriptor del directorio con `O_NOFOLLOW`. Antes de
  usarlo comprueba que el directorio es de root. Un `request.json` que sea un enlace simbólico
  se borra sin seguirlo, y una petición de más de 4 KiB se rechaza.
- Una petición que aún no es JSON válido se trata como "a medio escribir" durante 5 s.

`status.json` contiene:

- los campos de `heartbeat.isolation`;
- `updated_at`, para que el agente detecte un helper parado: con más de
  `status_max_age_seconds` (180 s) informa `helper = error`, `error_code = helper_stale` y
  deja de anunciar la capacidad;
- `allowed` y `rules`, que van al resultado del comando;
- `last_action`: `{session_id, action, outcome, error_code, at}`. El agente espera hasta
  `wait_seconds` (60 s) a que coincida con su petición; si no, responde `helper_timeout`.

## Códigos de error del resultado

| Lado | Códigos |
|---|---|
| Agente | `helper_absent`, `helper_disabled`, `helper_stale`, `helper_busy`, `helper_timeout`, `invalid_params`, `duration_exceeds_policy` |
| Helper | `helper_disabled`, `duration_exceeds_policy`, `already_isolated`, `session_mismatch`, `server_unresolvable`, `agent_config_missing`, `agent_config_unreadable`, `verification_failed`, `revert_failed`, `firewall_disabled`, `firewall_state_unknown`, `nftables_unavailable`, `backup_task_failed`, `firewall_command_failed`, `permission_denied`, `not_supported`, `invalid_request` |

## Instalación, activación y retirada

### Windows

1. Instala el helper con
   `install-sentra-agent.ps1 ... -InstallIsolationHelper`. El instalador:
   - registra el servicio `SentraIsolation`;
   - crea la política desactivada;
   - fija las ACL del directorio de intercambio con `icacls`.
2. Para activarlo, edita `%ProgramData%\Sentra\Isolation\isolation.toml` (`enabled = true`)
   y reinicia el servicio.
3. `uninstall-sentra-agent.ps1` primero ejecuta la reversión del helper y después borra el
   servicio. Con `-Purge` borra también `Sentra\Isolation`.

### Linux

1. El paquete instala `/lib/systemd/system/sentra-isolation.service` y
   `/opt/sentra-agent/share/isolation.toml.example`, pero no habilita el servicio.
2. Para activarlo:

   ```bash
   sudo cp /opt/sentra-agent/share/isolation.toml.example /etc/sentra-agent/isolation.toml
   sudo editor /etc/sentra-agent/isolation.toml      # enabled = true
   sudo systemctl enable --now sentra-isolation
   ```

3. Para retirar las reglas a mano:
   `sudo /opt/sentra-agent/bin/sentra-agent isolation-helper revert`.
4. `prerm` revierte y deshabilita el helper, y `postrm purge` borra `/var/lib/sentra-isolation`
   y `/var/log/sentra-isolation`.

Estado del helper en ambas plataformas: `sentra-agent isolation-helper status` (Linux) o
`python -m sentra_agent.isolation_helper status` con el runtime del agente (Windows).

## Riesgos conocidos y validación pendiente

- Todo lo que toca el firewall está probado con dobles. Hay que validar en un Windows físico
  como administrador:
  - `New-NetFirewallRule` con rangos IPv6;
  - la lectura de vuelta con `Get-NetFirewallAddressFilter`;
  - la tarea de respaldo;
  - el comportamiento con varias redes activas.
- Hay que validar en Linux real:
  - `nft -f` y `nft -j list table`, en Debian 12, Ubuntu 22.04/24.04 y RHEL 9;
  - la convivencia con firewalld y ufw.
- Un aislamiento corta también el acceso remoto de administración (RDP, SSH) salvo que su
  origen esté en `extra_allow`.
- Si el servidor Sentra cambia de IP durante un aislamiento, el equipo pierde el contacto hasta
  la expiración. La expiración local es la garantía.
