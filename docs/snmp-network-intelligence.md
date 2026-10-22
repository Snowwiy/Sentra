# SNMP, LLDP, CDP e inventario de switches (Fase 6B)

Sentra consulta por SNMP, en modo solo lectura, los equipos de red que un administrador
registra (switches, routers, puntos de acceso, cortafuegos) y guarda su inventario: identidad,
interfaces, vecinos LLDP/CDP, VLANs y tablas MAC. Todo es evidencia observada, con su
procedencia (MIB, sensor y hora), y nunca se presenta como algo más fuerte de lo que es.

## Arquitectura

```
Dashboard ──/api/v1/network──► API ──► PostgreSQL (perfiles cifrados, equipos, inventario)
                                │
                                └── job snmp_inventory ──► Sensor 0.3.0 del site ──SNMP──► equipo
                                     (sin secretos)        (credencial solo en el start)
```

- El servidor nunca habla SNMP. Cada consulta es un job `snmp_inventory` del catálogo de
  sensores (Fase 5F) dirigido a un sensor del MISMO site que el equipo.
- El job lleva nombres de módulo, no OIDs: `system`, `entity`, `interfaces`, `lldp`, `cdp`,
  `bridge`, `vlan`. El sensor los traduce con su propio catálogo cerrado
  (`sensor/sentra_sensor/snmp/catalog.py`). Nadie con acceso a la API puede pedir un OID
  arbitrario ni una operación SET: el código del sensor no contiene ninguna.
- El sensor devuelve registros normalizados (`records`) por lotes idempotentes; el servidor
  los guarda en staging (`network_poll_records`) y los aplica al cerrar el job
  (`app/network/apply.py`). La interpretación (tipo de puerto, VLAN de una MAC, clasificación)
  la hace solo el servidor con todos los datos juntos; el sensor no interpreta nada.
- Backend: `app/network/` (catálogo, aplicación, clasificador), `app/services/network_jobs.py`
  (polls y protocolo), `network_device_service.py`, `snmp_profile_service.py`,
  `app/core/secret_box.py`, rutas en `app/api/v1/routes/network.py`. Migración 0034.

### Biblioteca SNMP

El sensor usa **pysnmp 7.1** (BSD-2, Python puro, mantenida por LeXtudio) como extra opcional
`snmp`, con `cryptography` para el cifrado AES de SNMPv3. Alternativas descartadas: net-snmp
por subprocess (binario externo en Windows, credenciales en la línea de comandos del proceso)
y easysnmp (extensión C sin wheels para Windows). Solo `snmp/pysnmp_adapter.py` importa
pysnmp; el resto del colector trabaja contra una interfaz mínima (`get`, `get_bulk`) y se
prueba con un agente simulado en memoria y con un agente pysnmp real en `127.0.0.1`.

## Credenciales SNMP

- Los perfiles (`snmp_credential_profiles`) pertenecen a un site. Un equipo solo puede usar un
  perfil de su site y el servidor solo entrega la credencial a un sensor de ese site.
- Los secretos (passphrases de SNMPv3 o comunidad de v2c) son de solo escritura: entran al
  crear o rotar y la API nunca los devuelve. Tampoco aparecen en logs, auditoría, informes,
  URLs ni argumentos de procesos.
- Cifrado en reposo con AES-256-GCM (`cryptography`). El fichero de claves
  (`SNMP_CREDENTIAL_KEY_FILE`, fuera del repositorio y de la base) tiene una clave por línea
  `kid:base64`; la primera es la activa. Cada blob lleva como datos asociados (AAD) el perfil y
  el site: copiar un blob a otro perfil o site no lo descifra.
- Por qué AES-GCM con fichero de claves y no DPAPI ni el keyring del sistema: el servidor
  corre en Windows y en Linux, en varios workers, y la copia de seguridad debe poder
  restaurarse en otra máquina. Con DPAPI la base restaurada sería ilegible fuera del equipo
  original.
- Entrega al sensor: solo en la respuesta de `POST /sensor/jobs/{id}/start` de un job SNMP
  autorizado, y solo si el perfil sigue activo y en el site del sensor. El sensor comprueba que
  perfil, revisión y versión coinciden con el job; si no, no lo ejecuta. Nunca guarda la
  credencial en disco (ni spool ni estado) y la registra en su filtro de logs.

### Crear el fichero de claves

```powershell
# PowerShell elevado (administrador).
# 1. Primero el directorio, sin herencia y con herencia hacia lo que se cree dentro (OI)(CI).
New-Item -ItemType Directory -Force C:\ProgramData\Sentra\secrets | Out-Null
icacls C:\ProgramData\Sentra\secrets /inheritance:r /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" "NT SERVICE\SentraAPI:(OI)(CI)RX"
# 2. Después el fichero: la CLI comprueba el directorio y lo crea con su propia DACL protegida.
cd backend
.venv\Scripts\python.exe -m app.cli snmp-keygen --file C:\ProgramData\Sentra\secrets\snmp.keys
```

**Comprobación fail-closed en Windows (fix 2).** El modo 0600 no restringe nada en NTFS, así
que el backend comprueba la seguridad real con la API de Windows (por SID, nunca por nombres
ni por la salida de `icacls`), cada vez que carga el fichero y antes de leer su contenido:

- Fichero (su DACL se lee del descriptor ya abierto, el mismo que se lee): solo SYSTEM,
  Administradores, TrustedInstaller y la cuenta del propio proceso pueden tener derechos;
  `NT SERVICE\SentraAPI` y los SID de `SNMP_CREDENTIAL_KEY_READERS` solo lectura. Cualquier
  otra entrada, heredada o explícita (Users, Authenticated Users, Everyone, otro usuario), con
  algo más que leer atributos o la DACL, lo invalida. También un propietario que no sea de
  confianza, una DACL nula o una entrada condicional para otro principal.
- Directorio contenedor: nadie más puede crear, borrar ni renombrar entradas ni cambiar su
  DACL o propietario.
- Antecesores (hasta la raíz del disco): nadie más puede borrar o renombrar el siguiente
  componente ni cambiar su seguridad. Por eso `C:\ProgramData\Sentra\secrets` es válido, pero
  no una carpeta creada directamente en `C:\` (hereda «Modificar» para Authenticated Users).
- Ningún componente de la ruta puede ser un enlace simbólico, junction o punto de montaje.
- Si algo no se puede comprobar (sin permiso para leer una DACL, error de la API), no se usa.

Las entradas heredadas de un directorio bien protegido son válidas. Las DENY solo se acreditan
si van antes y son del mismo SID o de Everyone (no se resuelve la pertenencia a grupos). Si el
fichero no es seguro, la API responde 503 en las operaciones con credenciales y el motivo
(SID y máscaras, nunca la clave) queda en el log del servidor.

La CLI (`snmp-keygen` y `--add`) exige primero un directorio seguro (precondición que prepara
el administrador, paso 1) y crea cada fichero, también el temporal de la rotación, con una
DACL protegida desde el primer byte (`CreateFileW` con descriptor de seguridad): SYSTEM y
Administradores con control total, `NT SERVICE\SentraAPI` y los lectores configurados con
lectura y, si quien la ejecuta no es administrador elevado, también esa cuenta. Ejecutada
como administrador elevado, el propietario es el grupo Administradores, que la cuenta del
servicio acepta. Antes de sustituir el fichero verifica el temporal con las mismas reglas que
la API y que contiene todas las claves anteriores. Si la API corre con una cuenta local propia
en lugar de la virtual, pon su SID en `SNMP_CREDENTIAL_KEY_READERS`
(`(Get-LocalUser nombre).SID.Value`). El backend nunca cambia por su cuenta la DACL de un
fichero existente.

En Linux el fichero se crea con permisos 0600 y el servidor se niega a usarlo si el grupo u
otros pueden leerlo. La CLI nunca imprime la clave.

### Rotación, revocación, copia y recuperación

- **Rotar el secreto de un perfil**: Configuración del perfil → Rotar (o
  `POST /network/snmp-profiles/{id}/rotate`). Sube `secret_revision`; las consultas encoladas
  o en curso con la revisión anterior se cancelan y hay que volver a pedirlas. Cambia primero
  la credencial en el equipo.
- **Revocar un perfil**: borra el secreto cifrado, cancela las consultas abiertas y deja sus
  equipos en «credenciales pendientes». No se puede reactivar: se crea un perfil nuevo.
- **Rotar la clave maestra**: `python -m app.cli snmp-keygen --add --kid k2` (la nueva pasa a
  ser la activa y las anteriores siguen descifrando) y después `python -m app.cli snmp-rekey`
  para volver a cifrar todos los perfiles (cada blob nuevo se verifica descifrándolo antes de
  guardarlo). Solo cuando `snmp-rekey` informa `unreadable 0` (y termina con código 0) se puede
  retirar la clave vieja del fichero.
- **Copia de seguridad**: el fichero de claves se copia APARTE de la base (otro soporte, acceso
  restringido). Una copia de la base sin el fichero no expone secretos; el fichero sin la base
  tampoco.
- **Recuperación**: restaurar la base y colocar el mismo fichero de claves en
  `SNMP_CREDENTIAL_KEY_FILE`. Si el fichero se pierde, los secretos son irrecuperables: el
  estado del perfil seguirá visible y basta con rotar cada perfil con la credencial del equipo.

## SNMPv3 (recomendado)

- Siempre `authPriv`: autenticación SHA (SHA-1, SHA-224, SHA-256, SHA-384, SHA-512) y cifrado
  AES (128, 192, 256). MD5, DES, `noAuthNoPriv` y `authNoPriv` no se aceptan.
- Passphrases de 8 a 128 caracteres y distintas entre sí (con la misma, romper una da la otra).
- Configuración típica en el equipo: un usuario de solo lectura con vista limitada a
  SNMPv2-MIB, IF-MIB, ENTITY-MIB, LLDP-MIB, BRIDGE-MIB, Q-BRIDGE-MIB y CISCO-CDP-MIB, y una
  ACL que solo permita la IP del sensor.
- AES-192/256 usan la extensión de clave de Blumenthal (la de Net-SNMP). Algunos equipos
  Cisco usan otra variante ("Reeder"): con ellos, usar AES-128.

## Política de SNMPv2c

- Desactivado por defecto (`SNMP_ALLOW_V2C=false`). La comunidad viaja en claro por la red.
- Solo para equipos heredados sin SNMPv3, por decisión expresa del administrador. Las
  comunidades de fábrica `public` y `private` se rechazan.
- Si se desactiva después, los perfiles v2c existentes se conservan pero no se consultan
  (bloqueo `v2c_disabled`).
- SNMPv1 no existe en Sentra.

## Módulos y MIBs

| Módulo | MIB | Qué se guarda |
|--------|-----|---------------|
| system | SNMPv2-MIB, IP-MIB | sysDescr, sysObjectID, sysName, sysLocation, uptime, sysServices, ipForwarding |
| entity | ENTITY-MIB | chassis y stacks: modelo, serie, fabricante, firmware |
| interfaces | IF-MIB | ifTable/ifXTable (nombre, tipo, estado, velocidad, MTU, MAC, contadores 64 bits si existen) e ifStackTable (miembros de LAG) |
| lldp | LLDP-MIB | identidad local, puertos locales, vecinos remotos y sus direcciones de gestión |
| cdp | CISCO-CDP-MIB | caché de vecinos CDP |
| bridge | BRIDGE-MIB, Q-BRIDGE-MIB | dirección del bridge, mapa puerto → ifIndex, tabla MAC (Q-BRIDGE si existe; si no, la clásica) |
| vlan | Q-BRIDGE-MIB | VLANs estáticas y actuales, puertos con y sin etiqueta, PVID |
| wlan (Fase 6C.3, sensor 0.4.0, capacidad `snmp.wlan`) | IEEE802dot11-MIB, AIRESPACE-WIRELESS-MIB, UBNT-UniFi-MIB | APs, radios, BSS, WLANs y clientes; ver [wlan-discovery.md](wlan-discovery.md) |

La evidencia en bruto (registros por módulo, `network_poll_records`) se guarda aparte de la
interpretación (tablas de inventario). Un módulo que el equipo no implementa es
`unsupported`, no un error.

## Clasificación

`app/network/classify.py` clasifica en `managed_switch`, `router`, `access_point`,
`firewall` o `unclassified`, con confianza (`high`, `medium`, `low`, `none`) y la lista de
evidencias que la sostienen:

1. Capacidades LLDP habilitadas (bridge, router, wlanAccessPoint): confianza alta.
2. Sin LLDP: BRIDGE-MIB con suficientes puertos, ipForwarding + sysServices de capa 3, o
   interfaces 802.11: confianza media o baja.
3. Número de empresa de un fabricante de cortafuegos: solo si nada más fuerte lo contradice.

Nunca se clasifica por un puerto TCP abierto ni por el texto libre de sysDescr. El fabricante
sale de una tabla IANA cerrada o de entPhysicalMfgName; modelo, serie y firmware solo de
ENTITY-MIB. Si no hay dato, se muestra vacío: no se adivina.

## Interfaces

- La identidad de una interfaz es (equipo, ifIndex): el ifIndex no es global ni estable entre
  equipos, y algunos equipos lo renumeran al reiniciar (se muestra el nombre junto al índice).
- Tipo de puerto (`port_kind`) a partir de IANAifType: physical, lag, vlan, logical,
  loopback, tunnel, wireless u other (lo desconocido es `other`).
- Las interfaces que dejan de aparecer se marcan como ausentes (`present=false`), no se
  borran.

## LLDP y CDP

- Cada vecino guarda protocolo, puerto local (con cómo se ha emparejado: ifIndex, ifName,
  ifDescr o sin emparejar), datos remotos tal como los informa el equipo, sensor y hora.
- La valoración es siempre `reported_by_device`: es lo que el equipo dice, no un enlace
  confirmado. Se marca `reciprocal` si el otro extremo, también registrado, informa del enlace
  inverso.
- El equipo remoto solo se enlaza con otro equipo registrado del MISMO site (por MAC del
  chassis, dirección de gestión o sysName, en ese orden). Sin grafo de topología ni enlaces
  inferidos: los datos quedan listos para la Fase 6D.

## Tablas MAC y VLAN

- Solo MACs unicast. La VLAN de cada MAC sale del mapa FDB → VLAN de Q-BRIDGE
  (`fdb_vlan_map`); si el equipo no lo publica se asume FDB = VLAN y se indica
  (`fdb_id_assumed`).
- Ubicación (`location`), nunca «confirmada»:
  - `uplink_or_shared` en LAGs y sus miembros, trunks (puertos con VLANs etiquetadas),
    puertos con un vecino LLDP/CDP o con más de `SNMP_EDGE_PORT_MAX_MACS` MACs;
  - `edge_candidate` solo en un puerto físico de acceso con pocas MACs;
  - `unknown` en puertos lógicos, sin mapear o ausentes, y para las MACs propias del equipo.
- La búsqueda por MAC (`GET /network/mac-locations?mac=`) devuelve las apariciones por site,
  nunca las fusiona entre sites y ordena primero los candidatos de acceso.
- Si el módulo bridge vino parcial (tope de filas), la lista se marca `truncated`.

## Integración con sites

- El site de un equipo, de su perfil y de su sensor debe ser el mismo; el servidor lo deriva
  del sensor y del job, nunca de lo que diga el sensor. Un sensor de otro site no puede
  iniciar ni enviar resultados a un job ajeno.
- La dirección de gestión debe estar dentro de las redes habilitadas del site; las
  direcciones públicas se rechazan.
- Se permiten rangos privados solapados entre sites: la misma IP en dos sites son dos equipos.
- Relación con la Fase 6A: los activos descubiertos con tipo router, switch, AP o cortafuegos
  aparecen como candidatos a registrar. Sentra nunca prueba credenciales ni configura nada
  solo; un equipo sin credencial está en «credenciales pendientes», no en error.

## Estado y frescura

- `monitoring_status` se deriva al leer: archived, disabled, credentials_pending,
  sensor_pending, polling, never_polled, ok, partial o failing.
- `freshness`: `recent` si la última consulta correcta es de los últimos
  max(60 min, 3 × intervalo de consulta); si no, `historical` (la UI no presenta el equipo
  como disponible); `none` si nunca hubo una consulta correcta.

## Permisos y auditoría

- `monitoring:read`: ver equipos e inventario. `network:poll` (analista y admin): pedir y
  cancelar consultas. `network:manage` (admin): registrar, editar y archivar equipos.
  `snmp_credentials:manage` (admin): perfiles.
- Auditoría: `snmp_profile_created|updated|rotated|revoked`, `snmp_profiles_rekeyed`,
  `network_device_created|updated|archived`,
  `network_poll_requested|cancelled|rejected|finished`, `snmp_authentication_failed`,
  `network_inventory_changed` (altas y bajas de interfaces y vecinos, cambios de estado y de
  clasificación) y los accesos denegados del RBAC común. Ningún evento lleva secretos.

## Despliegue del sensor

- Sensor 0.3.0 con el extra: `pip install ".[snmp]"` en el entorno del sensor (o el paquete de
  la versión). Sin el extra, el sensor no declara `snmp.*` y nunca recibe jobs SNMP.
- Los sensores 0.1.x y 0.2.x no declaran `snmp.*`: siguen funcionando con discovery y nunca
  reciben jobs SNMP.
- Windows: el servicio `SentraSensor` mantiene sus protecciones NTFS (Fase 5F); la credencial
  SNMP nunca toca el disco. Permitir UDP saliente al puerto 161 de los equipos.
- Linux: el servicio systemd sin privilegios es suficiente (SNMP no necesita raw sockets).

## Variables de entorno

Ver `.env.example`: `SNMP_CREDENTIAL_KEY_FILE`, `SNMP_ALLOW_V2C`,
`SNMP_POLL_INTERVAL_MINUTES`, `SNMP_TIMEOUT_MS`, `SNMP_RETRIES`, `SNMP_MAX_VARBINDS_PER_JOB`,
`SNMP_MAX_ROWS_PER_TABLE`, `SNMP_JOB_DEADLINE_SECONDS`, `SNMP_EDGE_PORT_MAX_MACS`,
`SNMP_HISTORY_RETENTION_DAYS`. El sensor revalida todos los límites con sus topes propios.

## Seguridad

- Solo lectura por construcción: catálogo cerrado de OIDs en el sensor, comprobado antes de
  cada petición; sin SET en el código; el servidor no envía OIDs.
- Límites: timeout, reintentos, varbinds por job, filas por tabla, plazo total y cancelación
  comprobados antes de cada petición; OIDs que no avanzan (agente en bucle) cortan la tabla.
- Credenciales cifradas, ligadas a perfil y site, entregadas solo al sensor del job.
- Errores diferenciados: `timeout`, `host_unreachable`, `auth_failed`, `unsupported_version`,
  `oid_unavailable`, `partial`, `credentials_unavailable`, `sensor_offline`, `sensor_lost`,
  `job_expired`, `job_rejected`, `cancelled`, `limit_exceeded`, `malformed_response`,
  `internal`.

## Troubleshooting

| Código | Causa probable | Qué hacer |
|--------|----------------|-----------|
| timeout | ACL del equipo, firewall, IP o puerto erróneos, SNMP desactivado; en v2c, comunidad incorrecta | Comprobar desde el host del sensor que llega UDP/161 y la ACL SNMP del equipo |
| auth_failed | Usuario, passphrase o protocolo SNMPv3 distintos en el equipo | Rotar el perfil con los datos correctos; revisar el evento `snmp_authentication_failed` |
| unsupported_version | El equipo no admite authPriv o el protocolo elegido | Probar SHA/AES-128; v2c solo si el equipo no tiene v3 |
| oid_unavailable | La vista SNMP del usuario no incluye SNMPv2-MIB | Ampliar la vista de solo lectura |
| partial | Algún módulo falló o se recortó | Ver el detalle de módulos de la consulta |
| limit_exceeded | Tablas MAC muy grandes | Subir `SNMP_MAX_VARBINDS_PER_JOB` o `SNMP_MAX_ROWS_PER_TABLE` con cuidado |
| credentials_unavailable | Fichero de claves ausente o perfil revocado durante el job | Revisar `SNMP_CREDENTIAL_KEY_FILE` y el perfil |
| sensor_offline / sensor_lost | El sensor no está conectado o no cerró el job | Revisar el servicio del sensor |
| internal | Fallo interno del colector del sensor (no dice nada del equipo) | Revisar el log del sensor (`snmp module crashed`, con el tipo de error); actualizar el sensor a 0.5.1 |

## Diagnóstico por equipo y pausa automática (Fase 6D)

Cada cierre de consulta fija `snmp_status` del equipo en una taxonomía propia; nunca se
muestra el nombre de una excepción:

| snmp_status | Significado |
|-------------|-------------|
| `unverified` | Nunca se ha consultado |
| `compatible` | Respondió por SNMP (consulta correcta o parcial) |
| `no_response` | Sin respuesta y sin ningún éxito previo: SNMP no disponible o compatibilidad sin confirmar. Con SNMPv3, un equipo sin servicio SNMP es indistinguible de uno que descarta la petición |
| `timeout` | Sin respuesta, pero el equipo respondió antes |
| `unreachable` | El sensor no puede llegar a la dirección |
| `auth_failed` | Usuario, claves o protocolos del perfil rechazados |
| `unsupported_version` | Versión o nivel de seguridad no admitidos |
| `malformed_response` | Respuesta SNMP mal formada |
| `collector_error` | Fallo interno del colector del sensor; no es un diagnóstico del equipo |

Los fallos que no hablan del equipo (sensor caído, job caducado o rechazado, cancelación,
credencial no entregable) no cambian el diagnóstico.

**Pausa automática.** Tras `SNMP_AUTO_PAUSE_FAILURES` (3; 0 = nunca) fallos seguidos con
diagnóstico `no_response`, `unreachable`, `auth_failed` o `unsupported_version`, el
programador deja de consultar el equipo (`monitoring_paused_at`, `monitoring_pause_reason`,
estado `paused`, evento `network_monitoring_paused`). Un `collector_error` nunca pausa. La
consulta manual sigue disponible; una consulta correcta, `POST
/network/devices/{id}/monitoring/resume` (admin) o reactivar la monitorización levantan la
pausa (`network_monitoring_resumed`) y ponen a cero los fallos seguidos.

**Verificación de compatibilidad.** `POST /network/devices/{id}/compatibility-check`
(`network:poll`) encola una consulta con solo el módulo `system` (trigger `check`) para saber
si el equipo tiene SNMP utilizable con su perfil antes de activar la monitorización. Solo
actualiza el diagnóstico (`snmp_status`), los fallos seguidos y la pausa: no cambia
`last_poll_at`, `last_success_at` ni `last_modules`, porque no es una consulta completa y no
debe hacer pasar por recientes interfaces, LLDP o FDB antiguos ni retrasar la consulta
periódica.

### Caso Archer GX90 (`snmp error: KeyError`)

Causa reproducida en el sensor: cuando un lector de módulo lanzaba una excepción que no era
un error SNMP, el colector la registraba con `extra={"module": ...}`; `module` es un atributo
reservado de `logging.LogRecord`, así que el propio log lanzaba `KeyError`, que escapaba del
colector y sustituía al fallo real. No tiene relación con AES ni con el almacén de secretos.
Sensor 0.5.1: la clave del log es `snmp_module`, un fallo interno de un módulo se informa
como `internal` (y si es `system`, el job falla con ese motivo), y un test recorre todas las
llamadas de log del sensor para impedir claves reservadas. El servidor muestra los mensajes
antiguos («snmp error: KeyError», guardados por sensores <= 0.5.0) como error interno del
colector. Con el router sin servicio SNMP, el resultado esperado tras actualizar es
`no_response` y, tras tres intentos periódicos, la pausa automática.

## Limitaciones conocidas

- La topología (Fase 6D, docs/topology-engine.md) usa LLDP/CDP y las tablas MAC como evidencia; nunca infiere enlaces por subred. Sin SNMP traps, sin syslog, sin sondeo de
  rendimiento continuo (los contadores son una foto por consulta).
- La VLAN de una MAC depende de que el equipo publique el mapa FDB → VLAN; si no, se asume
  y se indica.
- CDP solo IPv4. LLDP-MED, LLDP-V2-MIB, VTP y tablas propietarias de fabricantes no se leen.
- Equipos con varios contextos SNMPv3 (una FDB por VLAN en algunos Cisco) solo informan del
  contexto por defecto.
- AES-192/256 «Reeder» no soportado (usar AES-128).
- Comprobación de la DACL en Windows: no resuelve pertenencia a grupos (una DENY para un
  grupo distinto del que tiene el ALLOW no se acredita, y el fichero se rechaza) y no evalúa
  la DACL de recursos compartidos SMB ni el propietario de la raíz del disco más allá de las
  reglas generales. En Linux no se comprueba el propietario ni los directorios, solo el modo.
- Validado con un agente simulado y con un agente pysnmp real en loopback; pendiente la
  prueba con switches reales.

## QA manual

1. Crear el fichero de claves y fijar `SNMP_CREDENTIAL_KEY_FILE`; reiniciar la API.
2. Instalar un sensor 0.3.0 con el extra `snmp` en el site del switch y comprobar en
   Sensores que declara las capacidades `snmp.*`.
3. Configurar en el switch un usuario SNMPv3 authPriv de solo lectura con ACL para la IP del
   sensor.
4. Infraestructura → Perfiles SNMP: crear el perfil v3. Comprobar que la respuesta y el
   detalle no muestran ninguna passphrase.
5. Infraestructura → Equipos: registrar el switch con el perfil y el sensor; pulsar
   Consultar. Ver progreso y resultado.
6. Revisar identidad, clasificación con sus evidencias, interfaces (LAG, trunks, PVID),
   vecinos LLDP/CDP, VLANs y tabla MAC (los puertos de uplink no son ubicación de endpoints).
7. Cambiar la passphrase solo en el switch y consultar: debe salir `auth_failed` y el evento
   de auditoría. Rotar el perfil y volver a consultar.
8. Buscar una MAC conocida en «Buscar MAC» y comprobar el puerto de acceso.
9. Como analista: puede consultar pero no ver perfiles ni registrar equipos. Como lector:
   solo lectura.
10. Revocar el perfil: el equipo pasa a «credenciales pendientes» y no se puede consultar.
11. Revisar los logs de la API y del sensor: no debe aparecer ninguna passphrase.
