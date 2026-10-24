# Sensor 0.6.0: actualización y fuentes DHCP locales (Fase 6E)

El sensor 0.6.0 añade un único tipo de job, `dhcp_leases` (capacidad `dhcp.leases.file`): lee
un fichero de leases DHCP **que el operador del equipo del sensor ha declarado** en su
`sensor.toml` y envía al servidor los leases normalizados (IP, MAC, hostname saneado,
client_id resumido, inicio, fin y estado). Con ellos el servidor puede dar nombre a equipos que
no responden a mDNS/NetBIOS/DNS (ver la sección 6E.2 de
[fase-6e-architecture.md](fase-6e-architecture.md) y el contrato en
[fase-6e-contracts.md](fase-6e-contracts.md)).

El resto del sensor no cambia: mismo protocolo, misma credencial, mismo spool. Un sensor 0.5.x
no anuncia `dhcp.leases.file` y el servidor nunca le asigna este job.

## Actualizar desde 0.5.x

No hay migraciones locales: el estado, la credencial y el spool de 0.5.x se usan tal cual.

Linux (systemd):

```bash
systemctl stop sentra-sensor
/opt/sentra-sensor/bin/pip install --upgrade ./sensor          # o "./sensor[snmp]" si usa SNMP
sudo -u sentra-sensor /opt/sentra-sensor/bin/sentra-sensor --config /etc/sentra-sensor/sensor.toml status
systemctl start sentra-sensor
```

Windows (PowerShell como Administrador):

```powershell
Stop-Service SentraSensor
& "C:\Program Files\SentraSensor\python\python.exe" -m pip install --upgrade .\sensor
Start-Service SentraSensor
```

Después, en Sentra → Sensores, el sensor debe mostrar la versión `0.6.0` y la capacidad
`dhcp.leases.file`. Si no se configura ninguna fuente DHCP, el sensor se comporta exactamente
como 0.5.x (el job solo puede fallar con `dhcp_source_unknown`).

`status` y `diagnostics` muestran ahora una entrada por fuente DHCP (nombre, formato, ruta, si
existe, si la cuenta del servicio la puede abrir y su tamaño). Nunca muestran el contenido.
`diagnostics` marca `FAIL` una fuente que el job no podría leer en ese momento.

## Configurar fuentes DHCP

En el `sensor.toml` (Linux `/etc/sentra-sensor/sensor.toml`, Windows
`%ProgramData%\Sentra\Sensor\sensor.toml`), después de la sección `[sensor]`:

```toml
[sensor]
server_url = "https://sentra.example.com"
# Tope de tamaño de cada fichero, en KiB (1..65536). Por defecto 4096.
dhcp_max_file_kb = 4096

[[dhcp_lease_files]]
name = "lan-dnsmasq"                       # ^[a-z0-9_-]{1,64}$, único
path = "/var/lib/misc/dnsmasq.leases"      # siempre absoluta
format = "dnsmasq"                         # dnsmasq | isc_dhcpd | kea_csv | windows_dhcp_csv | generic_csv
```

Reglas (se validan al arrancar; un error impide que el sensor arranque, para no descubrirlo
horas después):

- `name`: minúsculas, dígitos, `_` y `-`, de 1 a 64 caracteres, sin repetir. Es lo único que
  el servidor conoce de la fuente: el job solo lleva `{"source_name": "lan-dnsmasq"}`.
- `path`: absoluta. El servidor **nunca** envía rutas; no puede pedir al sensor que lea otro
  fichero. Que el fichero exista no se exige al arrancar (el servidor DHCP puede crearlo más
  tarde).
- `format`: uno de los cinco formatos de abajo. Claves desconocidas en la tabla = error.
- También se acepta `[[sensor.dhcp_lease_files]]`, pero no las dos formas a la vez.

En Sentra, la fuente se registra en el site como `sensor_file` con **el mismo nombre** y el
mismo formato; el servidor programa el job `dhcp_leases` para ese sensor.

Tras editar el fichero, reiniciar el servicio (`systemctl restart sentra-sensor` o
`Restart-Service SentraSensor`) y comprobar con `diagnostics`.

### Qué hace el job

1. Busca `source_name` en la configuración local; si no existe, falla con
   `dhcp_source_unknown`.
2. Abre el fichero sin seguir FIFOs ni dispositivos (`dhcp_file_unreadable`), comprueba el
   tamaño antes y durante la lectura (`dhcp_file_too_large`) y distingue fichero ausente
   (`dhcp_file_missing`) de sin permiso (`dhcp_file_unreadable`).
3. Parsea con el formato declarado. Una línea mal formada cuenta como `skipped` y nunca
   rompe el job. Si el fichero tiene registros pero ninguno es legible (formato equivocado) o
   un CSV no tiene la cabecera esperada, falla con `dhcp_format_invalid`.
4. Deja una sola entrada por IP (la última aparición gana: ISC y Kea añaden un registro nuevo
   cada vez que un lease cambia) y envía lotes de hasta 5000 leases (o menos si el servidor
   fija un tope de lote menor). Se puede cancelar desde el servidor entre lotes.
5. Completa con el resumen `dhcp`: `format`, `lines` (registros examinados), `parsed` (leases
   únicos enviados), `skipped`, `truncated`, `file_mtime` y `error_code`.

Normalización: MAC `aa:bb:cc:dd:ee:ff` (se descartan la nula, la de difusión y las
multicast); hostname sin caracteres de control ni invisibles, como mucho 255 caracteres, y
`*` o vacío pasan a `null`; `client_id` es `null` si es la propia MAC con tipo `01` y, si no,
`sha256:` + 16 hexadecimales del valor (permite correlacionar sin publicarlo); fechas en ISO
8601 UTC o `null` (lease infinito o desconocido); `state` es `active`, `expired`, `released`
o `unknown`.

Topes de trabajo además del tamaño: 200 000 líneas, 100 000 leases únicos y 8192 caracteres
por línea. Si se alcanza un tope, `truncated` es `true` y se envía lo leído hasta ese punto.

## Ejemplos por servidor DHCP

### dnsmasq (Linux) y OpenWrt

Formato de línea: `<fin en epoch> <mac> <ip> <hostname> <client_id>` (fin `0` = infinito).
La línea `duid ...` se ignora; los leases DHCPv6 (sin MAC) cuentan como `skipped`.

```toml
[[dhcp_lease_files]]
name = "lan-dnsmasq"
path = "/var/lib/misc/dnsmasq.leases"     # Debian/Ubuntu; en otras: /var/lib/dnsmasq/dnsmasq.leases
format = "dnsmasq"
```

OpenWrt guarda los leases en `/tmp/dhcp.leases` **del router**. El sensor no se conecta al
router: si se quiere usar ese fichero, el operador debe copiarlo periódicamente al equipo del
sensor por su cuenta (por ejemplo, una tarea cron en el equipo del sensor que lo traiga con
`scp` usando una clave restringida) a una ruta como `/var/lib/sentra-dhcp/openwrt.leases`, y
declarar esa ruta con `format = "dnsmasq"`. Las fechas de fin dependen del reloj del router:
conviene que tenga NTP.

### ISC dhcpd

```toml
[[dhcp_lease_files]]
name = "isc-main"
path = "/var/lib/dhcp/dhcpd.leases"
format = "isc_dhcpd"
```

Se leen los bloques `lease <ip> { ... }`: `starts`/`ends` (UTC, `never` o `epoch N`),
`binding state` (`active`/`bootp` según la hora de fin, `free`/`expired`/`reset` →
`expired`, `released` → `released`, otros → `unknown`), `hardware ethernet`, `uid` y
`client-hostname`. Las cabeceras, `server-duid`, `failover`, `host`, `class` y los bloques
IPv6 se ignoran. Un bloque sin MAC, con una fecha imposible o sin cerrar cuenta como `skipped`.

### Kea (memfile lease4)

```toml
[[dhcp_lease_files]]
name = "kea-v4"
path = "/var/lib/kea/kea-leases4.csv"
format = "kea_csv"
```

Cabecera `address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,...`.
`state` 0 → `active` o `expired` según `expire`; 1 (declinado) → `unknown`; 2 (caducado y
recuperado) → `expired`. `valid_lifetime` 4294967295 = infinito. Kea escapa las comas como
`&#x2c`, que se deshace en el hostname.

Compactación (LFC): cada `lfc-interval` Kea renombra el fichero activo a
`kea-leases4.csv.2`, abre uno nuevo y deja el resultado compactado en `kea-leases4.csv.1`.
Por eso, justo después de una compactación, los leases que no han cambiado desde entonces
solo están en `.1`. Para tener la vista completa se declara también ese fichero como una
segunda fuente (`name = "kea-v4-lfc"`, `path = "/var/lib/kea/kea-leases4.csv.1"`), registrada
igual en Sentra.

### Servidor DHCP de Windows (exportación programada a CSV)

El servidor DHCP de Windows no escribe un fichero de leases legible: se exporta con una tarea
programada en el propio servidor DHCP (o en un equipo con RSAT y `-ComputerName`). Se
recomienda exportar solo las columnas necesarias y la hora en UTC ISO 8601, porque el formato
por defecto de `LeaseExpiryTime` depende del idioma del sistema (`10/11/2026` es ambiguo).
El sensor acepta ISO 8601 y el formato en-US con AM/PM; otros formatos regionales dejan
`ends_at` en `null`.

1. Carpeta de exportación solo modificable por administradores y legible por el servicio del
   sensor (si el sensor corre en el mismo equipo):

   ```powershell
   $dir = 'C:\ProgramData\Sentra\DhcpExport'
   New-Item -ItemType Directory -Force -Path $dir | Out-Null
   icacls $dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' `
       'NT SERVICE\SentraSensor:(OI)(CI)RX' /Q
   ```

2. Script `C:\ProgramData\Sentra\DhcpExport\export-dhcp-leases.ps1`. Escribe primero a un
   temporal y luego lo renombra, para que el sensor nunca lea un fichero a medias:

   ```powershell
   $dir = 'C:\ProgramData\Sentra\DhcpExport'
   $tmp = Join-Path $dir 'leases.csv.tmp'
   $out = Join-Path $dir 'leases.csv'
   Get-DhcpServerv4Scope |
       ForEach-Object { Get-DhcpServerv4Lease -ScopeId $_.ScopeId -AllLeases } |
       Select-Object IPAddress, ClientId, HostName, AddressState,
           @{ Name = 'LeaseExpiryTime'; Expression = {
               if ($_.LeaseExpiryTime) { $_.LeaseExpiryTime.ToUniversalTime().ToString('o') } } } |
       Export-Csv -LiteralPath $tmp -NoTypeInformation -Encoding UTF8
   Move-Item -LiteralPath $tmp -Destination $out -Force
   ```

3. Tarea programada cada 15 minutos como `SYSTEM` (el script vive en una carpeta que solo
   pueden modificar los administradores: si otra cuenta pudiera editarlo, ejecutaría código
   como SYSTEM):

   ```powershell
   $script = 'C:\ProgramData\Sentra\DhcpExport\export-dhcp-leases.ps1'
   $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
       -Argument "-NoProfile -NonInteractive -File `"$script`""
   $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
       -RepetitionInterval (New-TimeSpan -Minutes 15)
   $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
   Register-ScheduledTask -TaskName 'Sentra DHCP lease export' -Action $action `
       -Trigger $trigger -Principal $principal
   ```

4. En el `sensor.toml` (barras `/` o `\\` en TOML):

   ```toml
   [[dhcp_lease_files]]
   name = "dc01-dhcp"
   path = "C:/ProgramData/Sentra/DhcpExport/leases.csv"
   format = "windows_dhcp_csv"
   ```

Columnas usadas: `IPAddress`, `ClientId` (la MAC con guiones; por eso `client_id` sale
`null`), `HostName`, `AddressState` (`Active`/`ActiveReservation` → `active`, `Expired` →
`expired`, el resto → `unknown`) y `LeaseExpiryTime`. También se admite una exportación
completa sin `Select-Object`, con la línea `#TYPE` de Windows PowerShell 5.1 y en UTF-16.

Si el sensor está en otro equipo, se puede apuntar `path` a una ruta UNC
(`//dhcp01/SentraExport/leases.csv`); la cuenta virtual del servicio accede a la red como la
cuenta de equipo del sensor (`DOMINIO\SENSOR01$`), que es a quien hay que dar lectura en el
recurso compartido.

### CSV genérico

Para cualquier otra fuente que el operador sepa convertir: cabecera `ip,mac,hostname` y,
opcional, `expires` (vacío = sin fin; epoch en segundos o ISO 8601, sin zona = hora local).
Las MAC se aceptan como `aa:bb:..`, `aa-bb-..`, `aabb.ccdd.eeff` o 12 hexadecimales.

```csv
ip,mac,hostname,expires
192.168.1.10,AA-BB-CC-DD-EE-10,kitchen-tablet,
192.168.1.11,aabb.ccdd.ee11,camera-garage,2026-10-23T00:00:00Z
```

## Permisos de lectura

El sensor solo necesita **leer** el fichero; nunca lo modifica. No dar más que eso.

### Linux

El servicio corre como `sentra-sensor`, sin privilegios.

- dnsmasq e ISC suelen dejar el fichero `0644`: legible sin cambios.
- Kea suele usar `0640` con grupo `_kea` o `kea`. Opciones, de más a menos recomendable:
  - ACL por defecto en el directorio, que sobrevive a la rotación y reescritura del fichero
    (Kea LFC y dhcpd lo recrean con `rename`, así que una ACL solo en el fichero se pierde):

    ```bash
    setfacl -m u:sentra-sensor:x /var/lib/kea
    setfacl -d -m u:sentra-sensor:r /var/lib/kea
    setfacl -m u:sentra-sensor:r /var/lib/kea/kea-leases4.csv
    ```

  - Añadir `sentra-sensor` al grupo del servidor DHCP (`usermod -aG _kea sentra-sensor`).
    Es más amplio: da acceso a todo lo que ese grupo pueda leer.
- La unidad systemd del sensor usa `ProtectSystem=strict` (lectura permitida),
  `ProtectHome=true` (no ve `/home` ni `/root`) y `PrivateTmp=true` (no ve el `/tmp` real).
  No poner las fuentes en esas rutas; si no hay otra opción, añadir en un *drop-in*
  (`systemctl edit sentra-sensor`) `BindReadOnlyPaths=/ruta/al/fichero`.
- `diagnostics` debe mostrar `[OK] dhcp_source:<nombre>`. Ejecutarlo **como el usuario del
  servicio** (`sudo -u sentra-sensor ...`), no como root: root lee cualquier cosa.

### Windows

El servicio corre con la cuenta virtual `NT SERVICE\SentraSensor`.

- Dar lectura a esa cuenta en la carpeta de exportación (ejemplo de arriba) o en el fichero:
  `icacls <fichero> /grant "NT SERVICE\SentraSensor:R"`.
- No poner el CSV dentro de `%ProgramData%\Sentra\Sensor` (el directorio de datos del
  sensor): el sensor reescribe su DACL para que sea privada y la tarea de exportación podría
  dejar de tener acceso.
- `diagnostics` comprueba abriendo de verdad el fichero (los bits de modo no reflejan las ACL
  de NTFS), pero con la cuenta de quien lo ejecuta, normalmente un administrador. La prueba
  definitiva con la cuenta del servicio es lanzar el job desde Sentra y revisar su
  `error_code` (`dhcp_file_unreadable` = falta el permiso de lectura).

## Qué NO hace

- No consulta APIs ni interfaces web de routers o servidores DHCP (por ejemplo, un router
  doméstico como el Archer GX90 no publica sus leases por una API oficial; integrar uno
  concreto sería una decisión aparte).
- No captura ni escucha tráfico DHCP de la red (sin sockets en escucha ni modo promiscuo).
- No lee ninguna ruta que no esté en su `sensor.toml`, ni acepta rutas, globs o comandos del
  servidor.
- No modifica, rota ni borra el fichero de leases.
- No envía el contenido bruto del fichero ni el `client_id` en claro; tampoco los escribe en
  los logs (solo nombre de fuente, formato, contadores y código de error).
- No asocia leases a activos: eso lo decide el servidor con sus reglas (6E.2).
