# Identidad avanzada y fuentes DHCP (Fase 6E.2)

> Estado: implementado en el backend (`app/dhcp/`, `app/api/v1/routes/dhcp.py`, migración
> 0040) y en el sensor 0.6.0 (job `dhcp_leases`, ver
> [sensor-upgrade-0.6.md](sensor-upgrade-0.6.md)). Probado con ficheros sintéticos
> (`tests/test_dhcp_identity.py`); pendiente de verificar en equipos reales con servidores
> DHCP de verdad.

Muchos equipos de una red doméstica o de oficina no publican su nombre por mDNS, NetBIOS ni
DNS, pero sí se lo dicen al servidor DHCP al pedir dirección. Este módulo permite que un admin
declare **fuentes DHCP autorizadas, de solo lectura**, y que Sentra use el hostname de los
leases para nombrar activos con reglas estrictas. Completa lo descrito en
[asset-identity-labels.md](asset-identity-labels.md) (Corrección 6C), donde los nombres DHCP
solo llegaban de forma indirecta por el DNS del router.

## Principios

- **Solo fuentes declaradas por un admin.** Un fichero que el admin sube (`lease_import`) o un
  fichero local de un sensor (`sensor_file`) que el operador del sensor declaró en su
  `sensor.toml`. Nada consulta routers, paneles web ni APIs, ni escucha tráfico DHCP.
- **Sin rutas en el servidor.** Una fuente de sensor se refiere por el nombre de su entrada
  `[[dhcp_lease_files]]`; el servidor nunca guarda ni envía rutas, así que un servidor
  comprometido no puede pedir al sensor que lea otro fichero.
- **Solo una coincidencia exacta da nombre.** MAC **e** IP iguales a las del activo.
- **Nunca crea ni fusiona activos**, y nunca asocia un lease por IP sola.
- **La etiqueta personalizada siempre gana.** El nombre DHCP es una fuente del nombre
  automático; `custom_label` va en otra columna y ninguna identificación automática la toca.
- **Una lectura parcial no es una desaparición.** Un lease que una lectura no trae no se
  borra; solo lo purga la retención.

## Modelo (migración 0040)

| Tabla | Contenido |
|---|---|
| `dhcp_sources` | Fuente por site: `name` (único en el site), `kind`, `format`, `sensor_id` y `sensor_source_name` (solo `sensor_file`), `poll_interval_minutes`, `status` (`pending`, `ok`, `error`, `disabled`), `last_requested_at`, `last_import_at`, `last_error_code`, `last_stats`, `version` |
| `dhcp_leases` | Un lease por (fuente, IP, MAC): `ip`, `mac`, `hostname` saneado, `client_id` (huella), `starts_at`, `ends_at`, `state` (`active`, `expired`, `released`, `unknown`), `asset_id`, `match`, `first_seen_at`, `last_seen_at` |
| `asset_identity_history` | Cambio de identidad de un activo: `field`, `old_value`, `new_value`, `source`, `confidence`, `observed_at` |

Un par (sensor, `sensor_source_name`) identifica una única fuente (índice único parcial).
La misma IP con otra MAC en la misma fuente es otro lease (reutilización de dirección). Borrar
una fuente borra sus leases (`CASCADE`).

## Fuentes

### `lease_import`

El admin sube el **texto** del fichero en JSON (el navegador lo lee y lo envía como texto):

```http
POST /api/v1/dhcp/sources/{id}/import
Content-Type: application/json

{"content": "1767225600 aa:bb:cc:dd:ee:01 192.168.1.10 portatil-ana *\n...", "version": 3}
```

- Tope: `DHCP_IMPORT_MAX_KB` (2048 KiB por defecto, rango 16-3072) sobre el contenido en UTF-8,
  y siempre dentro de `MAX_REQUEST_BYTES` (4 MiB por defecto) para el cuerpo entero.
- Solo fuentes `lease_import` (409 `dhcp_source_kind`) y no deshabilitadas (409
  `dhcp_source_disabled`). `version` obsoleta: 409 `dhcp_source_conflict`.
- Más de `DHCP_IMPORT_MAX_KB`: 422 `dhcp_file_too_large`.
- Formato ilegible (cabecera CSV ausente, o hay líneas pero ningún lease legible): 422
  `dhcp_format_invalid`; la fuente queda `status=error` con ese `last_error_code`.
- Una importación correcta deja `status=ok` y `last_stats` con `lines`, `parsed`, `skipped`,
  `truncated`, `matched`, `named` y `ambiguous`. Se audita `dhcp_leases_imported` (bytes y
  contadores, nunca el contenido); un formato inválido también se audita como fallo.
- Reimportar el mismo fichero es idempotente (actualiza los mismos leases).

### `sensor_file`

Requiere un sensor 0.6.0 del mismo site, activo, no revocado ni deshabilitado y que anuncie la
capacidad `dhcp.leases.file`. La fuente se declara con `sensor_id` y `sensor_source_name`
(`^[a-z0-9_-]{1,64}$`, el mismo `name` que en `[[dhcp_lease_files]]` del sensor).

- `POST /api/v1/dhcp/sources/{id}/read` crea un job `dhcp_leases` con parámetros
  `{"source_name": "<nombre>"}` (es todo lo que admite el esquema del sensor). Responde 202
  con `sensor_job_id`. Errores: 409 `dhcp_source_kind`, `dhcp_source_disabled`,
  `dhcp_sensor_unavailable` (sensor ausente, inactivo o sin la capacidad) y
  `dhcp_read_in_progress` (ya hay un job abierto para esa fuente). Auditado
  (`dhcp_read_requested`).
- Lectura periódica: con `poll_interval_minutes` > 0 (máximo 1440), el mantenimiento de
  sensores encola un job cuando ha pasado el intervalo desde `last_requested_at`, si no hay
  otro abierto y el sensor está listo. 0 = solo a demanda.
- Cada lote que llega por `/sensor/jobs/{id}/results` se aplica al recibirlo. Si la fuente se
  borró o se deshabilitó mientras el sensor leía, el lote no se aplica.
- Al cerrar el job, la fuente queda `ok` o `error` con el `error_code` del sensor
  (`dhcp_source_unknown`, `dhcp_file_missing`, `dhcp_file_unreadable`,
  `dhcp_file_too_large`, `dhcp_format_invalid`), `sensor_failed` si el sensor falló sin
  código o `dhcp_batches_missing` si faltan lotes. `last_stats` añade `file_mtime`.

Qué lee el sensor, con qué permisos y con qué topes: [sensor-upgrade-0.6.md](sensor-upgrade-0.6.md).

## Formatos

Los dos lados (importación en `app/dhcp/parsers.py` y sensor en `sentra_sensor/dhcp.py`)
admiten los mismos cinco formatos:

| format | Entrada |
|---|---|
| `dnsmasq` | `<fin epoch> <mac> <ip> <hostname> [client_id]` (fin `0` = sin caducidad; la línea `duid` se ignora) |
| `isc_dhcpd` | Bloques `lease <ip> { ... }` de `dhcpd.leases`: `starts`, `ends`, `binding state`, `hardware ethernet`, `client-hostname`, `uid` |
| `kea_csv` | memfile `lease4`: columnas obligatorias `address`, `hwaddr`; usa `client_id`, `valid_lifetime`, `expire`, `hostname`, `state` |
| `windows_dhcp_csv` | `Get-DhcpServerv4Lease \| Export-Csv`: obligatorias `IPAddress`, `ClientId` (la MAC con guiones); usa `HostName`, `AddressState`, `LeaseExpiryTime`. Admite la línea `#TYPE` |
| `generic_csv` | Cabecera `ip,mac[,hostname][,expires]` (`expires` en ISO 8601 o epoch) |

Reglas comunes de la importación manual:

- Solo se extraen IP, MAC, hostname, client id, inicio, fin y estado.
- Una línea o bloque mal formado cuenta como `skipped` y no rompe la importación.
- Hostname sin caracteres de control, como mucho 255 caracteres; `*` o vacío es «sin nombre».
- `client_id` igual a la propia MAC con tipo `01` se descarta; uno opaco se guarda como
  `sha256:` + 16 hexadecimales (el mismo cálculo que el sensor).
- Más de 200 000 líneas: se corta y `truncated=true`.
- Una entrada por IP: la última aparición gana.
- Un lease activo cuya fecha de fin ya pasó se guarda como `expired`.

Diferencias conocidas entre la importación manual y el sensor 0.6.0 (las dos deberían coincidir
y hoy no lo hacen del todo; afectan al `state` y a la hora, no a la asociación por MAC e IP):

- `isc_dhcpd`: `free` → `released` en la importación, `expired` en el sensor.
- `windows_dhcp_csv`: `Inactive` e `InactiveReservation` → `released` en la importación,
  `unknown` en el sensor.
- Fechas sin zona horaria (`generic_csv`, `windows_dhcp_csv`): la importación las toma como
  UTC; el sensor, como hora local de su equipo.

## Asociación lease → activo

`app/dhcp/matching.py`, solo con activos del mismo site y no archivados:

| match | Condición | Activo | Da nombre |
|---|---|---|---|
| `expired` | Lease `expired` o `released` | No | No |
| `ambiguous` | Varios activos con esa MAC (duplicados; los resuelve la reconciliación de 5C.2 con revisión humana) | No | No |
| `mac_ip` | Un activo con esa MAC **y** esa IP | Sí, confianza alta | Sí |
| `randomized_mac` | MAC aleatoria (bit de administración local) sin coincidencia exacta | No | No |
| `mac_moved` | Un activo con esa MAC pero otra IP | Sí, confianza media, como evidencia | No |
| `ip_only` | Ninguna MAC coincide pero hay un activo con esa IP | No | No |
| `no_asset` | Nada coincide | No | No |

El orden de la tabla es el de evaluación. Una MAC aleatoria con coincidencia exacta de MAC e IP
sí es `mac_ip`: en ese momento identifica al equipo. Un `ip_only` nunca enlaza el lease al
activo: una IP se reasigna y no identifica a nadie.

### Cuándo un `mac_ip` no da nombre

El hostname del lease se descarta si:

- es un nombre por defecto de SO o firmware (la lista de `classify.py`: `linux`, `android`,
  `ubuntu`, `raspberrypi`, `espressif`, `localdomain`, `generic`...);
- es genérico de DHCP: `localhost`, `unknown`, `none`, `*`, `iphone`, `ipad`, `android-<hex>`,
  `galaxy`, `dhcp-N...`, `host-N...`, `client-N...` (se compara la primera etiqueta, sin
  dominio);
- el mismo site lo da a la vez, en leases `active`, a más de una MAC (un nombre repetido no
  distingue a un equipo de otro).

En ese caso, si esa misma fuente había dado nombre al activo, el nombre se retira.

### Qué se guarda en el activo

Con un `mac_ip` y hostname válido, el servicio escribe `identity_observations["dhcp_lease"]`
(`hostname`, nombre e id de la fuente, `ip`, `mac`) con su fecha en `seen_at` y recalcula la
identidad (`refresh_identity`). Hay una sola observación `dhcp_lease` por activo: si dos
fuentes coinciden, gana la última aplicada.

Si después el lease deja de coincidir (el equipo cambió de IP), el nombre DHCP ya guardado
sigue como evidencia hasta que pasan `NAME_STALE_DAYS` (30) sin que ninguna lectura lo repita;
entonces queda marcado antiguo y pierde frente a cualquier nombre reciente. Borrar la fuente
retira en el acto los nombres que dio y reidentifica esos activos (auditado
`dhcp_source_deleted` con `assets_renamed`).

## Prioridad del nombre

Nombre visible (`display_name`): `custom_label` → nombre automático → hostname → DNS inverso →
IP (sin cambios respecto a la Corrección 6C).

Nombre automático (`app/discovery/classify.py`):

- Activo con agente: el hostname que reporta el agente.
- Sin agente, entre los candidatos no genéricos, por este orden de criterios:
  1. los recientes antes que los antiguos (`stale`, más de 30 días sin repetirse);
  2. los no desmentidos antes que un DNS inverso que no resuelve a esta IP;
  3. el orden de fuentes `agent_hostname`, `dhcp_lease`, `reverse_dns`, `mdns`, `netbios`,
     `upnp`, fabricante + modelo.

El nombre del lease se muestra sin el sufijo de dominio local (`.lan`, `.home`...) y aparece
en `observed_names` con `source=dhcp_lease` y `kind=dhcp`. El fabricante OUI nunca es un
nombre: como mucho se usa fabricante + modelo del dispositivo cuando no hay ningún otro.

Reimportar no toca `custom_label`: el test `test_reimport_is_idempotent_and_custom_label_wins`
lo comprueba.

## Motivos de «sin identificar»

`GET /assets/{id}/identity` devuelve `unidentified_reasons` vacío si el activo tiene nombre
automático (o hostname de agente). Si no, una lista con:

| Código | Significado |
|---|---|
| `no_name_sources` | Ninguna fuente dio un nombre |
| `only_generic_names` | Solo nombres genéricos |
| `names_stale` | Los nombres no genéricos son todos antiguos |
| `randomized_mac` | La MAC del activo es aleatoria |
| `dhcp_source_missing` | El site no tiene ninguna fuente DHCP habilitada |
| `dhcp_no_lease` | Hay fuente, pero ningún lease del activo (por `asset_id` o por su MAC) |
| `dhcp_lease_unusable_name` | Hay leases, pero ninguno `mac_ip` con un hostname válido |
| `only_vendor` | Solo se conoce el fabricante |

## Historial de identidad

Un listener `before_flush` de SQLAlchemy (`app/dhcp/history.py`) registra en
`asset_identity_history` cada cambio de estas columnas del activo, venga de donde venga
(discovery, agente, inventario, fusión, DHCP o etiqueta manual), en la misma transacción:

| field | Columna | source / confidence |
|---|---|---|
| `name` | `device_name` | `name_source` del activo (`agent_hostname`, `dhcp_lease`, `mdns`...) o `agent`/`discovery`; `high` si es `agent_hostname` o `dhcp_lease`, si no `medium` |
| `label` | `custom_label` | `manual`, `high` |
| `ip` | `primary_ip` | `agent`/`high` con agente, `discovery`/`medium` sin él |
| `mac` | `mac_address` | igual que `ip` |
| `vendor` | `vendor` | `oui`, `medium` |
| `device_type` | `device_type` | `classification`, la confianza de la clasificación |

No registra la creación de un activo (no hay valor anterior). Los cambios de asociación Wi-Fi
(AP, SSID) no están aquí: los registra `network_changes` de 6E.1
([topology-history.md](topology-history.md)) con su evidencia.

## Permisos

- Leer fuentes, leases, identidad e historial de identidad: `monitoring:read` (todos los
  roles).
- Crear, cambiar y borrar fuentes, importar y pedir lecturas: `dhcp:manage` (solo admin). Una
  fuente decide qué nombre ven todos para cada equipo.

## API (`/api/v1`)

| Método y ruta | Permiso | Notas |
|---|---|---|
| `GET /dhcp/sources?site_id=` | `monitoring:read` | Todas o las de un site, con `lease_count` |
| `POST /dhcp/sources` | `dhcp:manage` | 201. Ver cuerpo abajo |
| `GET /dhcp/sources/{id}` | `monitoring:read` | 404 `dhcp_source_not_found` |
| `PATCH /dhcp/sources/{id}` | `dhcp:manage` | `{"version", "enabled"?, "format"?, "poll_interval_minutes"?}` |
| `DELETE /dhcp/sources/{id}?version=` | `dhcp:manage` | 204. Borra la fuente y sus leases y retira sus nombres |
| `POST /dhcp/sources/{id}/import` | `dhcp:manage` | Solo `lease_import` |
| `POST /dhcp/sources/{id}/read` | `dhcp:manage` | 202. Solo `sensor_file` |
| `GET /dhcp/leases` | `monitoring:read` | `site_id`, `source_id`, `match`, `search` (IP o MAC exactas, o parte del hostname; 1-64), `limit` 1-500 (100), `offset` |
| `GET /assets/{id}/identity` | `monitoring:read` | Nombre visible, etiqueta, nombre automático y su fuente, nombres observados, IP, MAC, `mac_randomized`, fabricante, tipo, hasta 10 leases, asociación Wi-Fi presente y `unidentified_reasons` |
| `GET /assets/{id}/identity/history` | `monitoring:read` | `field`, `before_id` (cursor), `limit` 1-200 (50); del más reciente al más antiguo, `next_before_id` |

Creación:

```json
{
  "site_id": "uuid o null (site por defecto)",
  "name": "LAN router",
  "kind": "sensor_file",
  "format": "dnsmasq",
  "sensor_id": "uuid",
  "sensor_source_name": "lan-dnsmasq",
  "poll_interval_minutes": 60
}
```

- `name`: `^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$`; repetido en el site: 409
  `dhcp_source_name_taken`.
- `sensor_file` exige `sensor_id` y `sensor_source_name`; `lease_import` no admite ninguno de
  los dos ni intervalo (422). Cambiar el intervalo de una `lease_import` a un valor distinto de
  0: 422 `dhcp_source_not_polled`.
- Sensor de otro site, revocado o inexistente: 404 `sensor_not_found`. Par (sensor, nombre)
  ya declarado: 409 `dhcp_sensor_source_taken`. Site no activo: 409 `site_not_active`.
- `version` obsoleta en `PATCH`, `DELETE` o importación: 409 `dhcp_source_conflict` con
  `details: [{"version": <actual>}]`.
- Deshabilitar (`enabled: false`) deja `status=disabled`; rehabilitar la deja `pending`.
- Auditoría: `dhcp_source_created`, `dhcp_source_updated` (solo si algo cambia),
  `dhcp_source_deleted`, `dhcp_leases_imported`, `dhcp_read_requested`.

Ningún endpoint acepta ni devuelve rutas de fichero.

## Retención

En el job `retention` de 6E (`purge_dhcp`):

| Variable | Defecto | Qué se borra |
|---|---|---|
| `DHCP_LEASE_RETENTION_DAYS` | 90 | Leases cuyo `last_seen_at` (última lectura que los trajo) es anterior al plazo |
| `ASSET_IDENTITY_HISTORY_RETENTION_DAYS` | 365 | Filas de historial de identidad con `observed_at` anterior al plazo |

Vacío = sin purga. Purgar un lease no retira el nombre que ya dio al activo; ese nombre
envejece con la regla de 30 días.

## TP-Link Archer GX90

El caso de la red de pruebas actual (192.168.50.1): el router doméstico Archer GX90 reparte las direcciones y conoce
los hostnames, pero:

- **No se depende de SNMP.** El diagnóstico SNMP de ese router está pendiente
  ([fase-6d-known-issues.md](fase-6d-known-issues.md)) y nada de este módulo lo usa.
- **Nada en Sentra se conecta al router.** Ni el servidor ni el sensor leen su panel web, su
  API o sus ficheros, y no se ha añadido ninguna integración con TP-Link. No se asume que el
  router ofrezca una API local documentada.
- **Las vías soportadas** son las mismas que para cualquier otro servidor DHCP:
  1. **Importación**: el admin obtiene la lista de clientes DHCP y la sube a una fuente
     `lease_import`. Si el router no permite exportarla en uno de los formatos admitidos, el
     formato `generic_csv` (`ip,mac,hostname`) admite una lista preparada a mano a partir de
     la tabla de clientes que muestra su panel.
  2. **Sensor**: si el DHCP lo sirve otro equipo (por ejemplo, dnsmasq o Kea en un servidor de
     la LAN, con el DHCP del router desactivado), un sensor 0.6.0 en ese equipo lee su fichero
     de leases (`sensor_file`).

No se ha verificado si el firmware del Archer GX90 permite exportar la lista de clientes DHCP a
un fichero. Las dos vías están pendientes de verificar en el equipo real.

## Pruebas

`tests/test_dhcp_identity.py`: parsers de los cinco formatos, huella del client id igual a la
del sensor, reglas de asociación, hostnames genéricos, prioridad del nombre en `classify`,
importación que solo nombra con coincidencia exacta, reimportación idempotente con etiqueta
que gana, errores de importación, borrado de fuente que retira nombres, motivos de «sin
identificar», filtros de leases, permisos, flujo del job del sensor, fallos del sensor y
capacidad, lecturas periódicas, retención y listener del historial de identidad.

## Validación pendiente en equipos reales

1. Aplicar la migración 0040 en `sentra_test` y, tras revisar, en producción.
2. Crear una fuente `lease_import`, importar la lista de clientes DHCP del Archer GX90 (o un
   `generic_csv` preparado a mano) y comprobar `matched`, `named` y los activos nombrados.
3. Comprobar que un equipo con etiqueta personalizada la conserva y que el nombre DHCP aparece
   en «Nombres observados».
4. Con un sensor 0.6.0 junto a un servidor dnsmasq, Kea, ISC o Windows DHCP: declarar el
   fichero, crear la fuente `sensor_file`, pedir una lectura y revisar `last_stats`.
5. Revisar `unidentified_reasons` en un móvil con MAC aleatoria.
