# Inventario Wi-Fi / AP / WLAN autorizado (Fase 6C.3)

Inventario de puntos de acceso (AP), BSS (cada BSSID emitido), SSIDs y clientes inalámbricos
de las redes de la organización, construido sobre la arquitectura de la Fase 6B (sites,
sensores, inventario SNMP de solo lectura, ver [snmp-network-intelligence.md](snmp-network-intelligence.md))
y sobre el inventario de los agentes. No es un motor nuevo: el módulo SNMP `wlan` viaja en el
mismo job `snmp_inventory` y se aplica en el mismo cierre de consulta (`PollApplier`).

```
Sensor 0.4.0 (snmp.wlan) ──job snmp_inventory, módulo "wlan"──► AP / controladora (GET/GETBULK)
        │  registros wlan_* (staging)
        ▼
Servidor: PollApplier ──► WlanApplier ──► wlan_access_points / wlan_bss / wlan_clients
                                           wlan_configured_networks / wlan_observations
Agente ──POST /inventory {"wireless": ...}──► ingest_agent_wireless ──► wlan_bss / wlan_clients
                                                                        wlan_agent_reports
Dashboard ──/api/v1/network/wlan/*──► WlanService (monitoring:read / network:manage)
```

## Alcance y límites de seguridad

Solo entornos autorizados y solo observación:

- SNMP de solo lectura (GET/GETBULK) contra columnas concretas de un catálogo cerrado en el
  sensor; nunca SET. SNMPv3 authPriv preferido; SNMPv2c solo con `SNMP_ALLOW_V2C=true`
  (mismas reglas que 6B; el módulo no cambia nada de credenciales ni de transporte).
- El agente solo informa lo que el sistema operativo ya sabe (system_profiler, netsh, nmcli):
  sin escaneo activo propio, sin modo monitor, sin inyección de tramas.
- Nunca: desautenticación, captura de handshakes o credenciales, ataques a WPA/WEP, lectura
  de claves WEP (la tabla `dot11WEPDefaultKeysTable` no está en el catálogo), nombres de
  usuario o IPs de los clientes de la controladora (columnas excluidas del catálogo), comandos
  arbitrarios desde la UI ni URLs arbitrarias.
- Aislamiento estricto por site: cada fila pertenece al site del equipo consultado o del
  activo del agente. La misma MAC en dos sites son dos filas; las vinculaciones nunca cruzan
  sites.
- Ningún AP se marca como "rogue" automáticamente. La autorización empieza en `unknown` y
  solo la cambia un operador con `network:manage`.

## Fuentes

| Fuente (`source`) | Origen | Confianza (`confidence`) | Qué aporta |
|---|---|---|---|
| `snmp_ieee802dot11` | IEEE802dot11-MIB (AP autónomo) | `reported_by_device` | El AP es el equipo consultado; por radio: BSSID, SSID, privacidad/RSNA, tipo de PHY, canal |
| `snmp_airespace` | AIRESPACE-WIRELESS-MIB (controladora Cisco AireOS) | `reported_by_device` | APs de la controladora (nombre, modelo, serie, firmware, ubicación, IP, MAC Ethernet, estado), radios (banda, canal, estado, clientes), WLANs configuradas (SSID, clientes) y clientes asociados (MAC, AP, radio, WLAN, estado, protocolo) |
| `snmp_unifi` | UBNT-UniFi-MIB (AP UniFi) | `reported_by_device` | Modelo, firmware e IP del AP; VAPs (BSSID, SSID, canal, radio, clientes) |
| `agent` | Campo `wireless` de POST /inventory | `observed` | Redes cercanas vistas por el SO y la conexión propia del activo |

### Módulo SNMP `wlan` (sensor 0.4.0)

- Capacidad `snmp.wlan`. El servidor solo añade `"wlan"` a los módulos del job cuando el
  sensor la declara: un sensor 0.3.0 rechazaría un módulo desconocido, así que sigue
  recibiendo exactamente los mismos jobs que antes.
- Necesita `system` (como el resto de módulos). El estado del módulo es el de 6B:
  `complete`, `partial` (tope de filas/varbinds, plazo o fallo de un adaptador tras datos
  parciales), `unsupported` (ninguna de las tres MIBs responde: es lo normal en un switch) o
  `failed` (autenticación o transporte).
- Un adaptador por MIB, cada uno con su estado (registro `wlan_source`). Cada adaptador
  comprueba primero una columna clave; si el equipo no la tiene o la vista VACM del usuario
  SNMP no la incluye, el adaptador es `unsupported` y no pide nada más.
- La lista autorizada es por columna (no por tabla), para que una petición nunca alcance una
  columna sensible de una tabla permitida. OIDs autorizados:

| MIB | Tabla / objeto | Columnas |
|---|---|---|
| IEEE802dot11-MIB `1.2.840.10036` | dot11StationConfigEntry `.1.1.1` | 1 StationID, 9 DesiredSSID, 10 DesiredBSSType |
| | dot11PrivacyEntry `.1.5.1` | 1 PrivacyInvoked, 4 ExcludeUnencrypted, 7 RSNAEnabled |
| | dot11OperationEntry `.2.1.1` | 1 MACAddress |
| | dot11PhyOperationEntry `.4.1.1` | 1 PHYType |
| | dot11PhyDSSSEntry `.4.5.1` / dot11PhyOFDMEntry `.4.11.1` | 1 CurrentChannel / CurrentFrequency (nº de canal) |
| AIRESPACE `1.3.6.1.4.1.14179` | bsnAPEntry `.2.2.1.1` | 3 nombre, 4 ubicación, 6 estado, 8 software, 16 modelo, 17 serie, 19 IP, 33 MAC Ethernet |
| | bsnAPIfEntry `.2.2.2.1` | 2 tipo de radio, 4 canal, 12 estado, 15 clientes |
| | bsnDot11EssEntry `.2.1.1.1` | 2 SSID, 38 clientes |
| | bsnMobileStationEntry `.2.1.4.1` | 4 MAC del AP, 5 radio, 6 WLAN, 7 SSID, 9 estado, 25 protocolo (nunca 2 IP ni 3 usuario) |
| UBNT-UniFi `1.3.6.1.4.1.41112.1.6` | unifiVapEntry `.1.2.1` | 2 BSSID, 4 canal, 6 ESSID, 7 nombre, 8 clientes, 9 radio |
| | unifiApSystem `.3` | 1.0 IP, 3.0 modelo, 6.0 versión |

- Topes propios además del de filas del job: 64 radios dot11, 4096 APs por controladora, 8
  radios por AP, 512 WLANs, 128 VAPs. Al alcanzar un tope el adaptador es `partial`.
- El sensor no interpreta: entrega enteros de la MIB, MACs/IPs canónicas y texto saneado.
  Banda, protección, estándar y estado los decide el servidor (`app/network/wlan_catalog.py`)
  con tablas cerradas; un valor desconocido queda `null` o `unknown`, nunca se supone.
- Un GETBULK puede devolver OIDs contiguos fuera de la columna pedida; el caminante los
  descarta y nunca se guardan.

### Campo `wireless` del agente

Contrato en [agent-protocol.md](agent-protocol.md#wi-fi-campo-wireless-de-post-inventory-fase-6c3).
Resumen de la interpretación en el servidor (`app/services/wlan_ingest.py`):

- Confianza `observed`: ver un BSSID no prueba que el AP sea de la organización, así que el
  agente nunca crea APs ni autoriza nada. Crea o actualiza BSS (si hay BSSID) y no pisa la
  identidad que da la infraestructura SNMP (SSID, canal, AP); sí rellena lo que esté a null,
  precisa la protección (p. ej. RSN → WPA2) y aporta la señal, que solo da el agente.
- Un informe más antiguo que el último guardado para ese activo se ignora entero.
- Un BSSID repetido en el mismo informe cuenta una vez (gana el conectado o el de más señal).
  Un BSSID bien formado pero inutilizable (todo ceros, multicast) se descarta sin rechazar el
  inventario; una MAC mal formada es 422.
- El campo no se guarda en el documento de inventario ni genera cambios de inventario.

## Entidades e identidad

| Tabla | Clave natural (idempotencia) | Notas |
|---|---|---|
| `wlan_access_points` | `(site_id, ap_key)`: `mac:<MAC de radio>` (controladora) o `device:<uuid>` (AP autónomo o UniFi = el equipo consultado) | Nunca se borra por retención |
| `wlan_bss` | `(site_id, bssid)` | Compartido entre SNMP y agentes; `sources` acumula las fuentes que lo vieron |
| `wlan_clients` | `(site_id, client_key)`: `mac:<MAC>` o `asset:<uuid>:<interfaz>` | |
| `wlan_configured_networks` | `(device_id, source, network_key)` | WLANs configuradas en una controladora |
| `wlan_observations` | — | Historial con procedencia: exactamente una de AP/BSS/cliente, más consulta, sensor, equipo o activo del agente, `observed_at` y `received_at` |
| `wlan_agent_reports` | `asset_id` | Último estado del informe Wi-Fi de cada agente (indicadores de disponibilidad) |

Todas las escrituras son `INSERT ... ON CONFLICT DO NOTHING` + `SELECT ... FOR UPDATE` por
clave natural: repetir una consulta o un informe no duplica filas. El historial solo crece
cuando cambian los datos observados o ha pasado al menos una hora desde la última
observación de esa entidad y fuente (`OBSERVATION_MIN_INTERVAL`).

### Confianza de la identidad de los clientes (`identity_confidence`)

- `confirmed`: el propio agente informa de su conexión (`correlation_basis = agent_self`).
- `probable`: la MAC global del cliente que informa la controladora coincide con la MAC de un
  activo del mismo site (`mac_match`), o un agente informa de la MAC aleatoria con la que
  está conectado y la controladora la ve (`agent_reported_mac`).
- `observation_only`: cualquier otro caso.

Una MAC localmente administrada (bit `0x02` del primer octeto, típica de la aleatorización
de iOS, Android y Windows) nunca identifica un dispositivo por sí sola: no se correlaciona
con activos por coincidencia de MAC (`mac_randomized = true`). Lo mismo para BSSIDs
(`bssid_randomized`), que solo se señalan.

## Presencia y frescura

- `present` solo pasa a `false` con evidencia autoritativa: una consulta SNMP completa (job
  `completed`, sin lotes perdidos), con el módulo `wlan` `complete` y el adaptador de esa
  fuente `complete`, que ya no informa del AP/BSS/cliente/WLAN de ese mismo equipo. Una
  consulta parcial, cancelada, fallida o con plazo agotado solo aporta evidencia positiva:
  nunca hace "desaparecer" nada. Nada se borra al dejar de verse.
- Los agentes nunca marcan ausencias de redes (una exploración de radio siempre es parcial).
  Lo único que un agente sabe con autoridad es su propia conexión: con `status = ok`, una
  conexión propia que ya no informa pasa a `present = false`, `state = disassociated`.
- `freshness` (`recent` / `historical`) se deriva al leer: SNMP dentro de
  `max(60 min, 3 × SNMP_POLL_INTERVAL_MINUTES)`, agente dentro de 24 h. La UI no debe
  presentar como activo algo `historical`.

## Autorización

`authorization_status` de APs y BSS: `unknown` (por defecto), `authorized` o `external`
(vecino u otra organización). Solo la cambia un operador con `network:manage`, con motivo
opcional y concurrencia optimista (`version`; 409 `wlan_version_conflict`). Se audita como
`wlan_authorization_changed` con `{from, to, reason}`. Sobrevive a nuevas consultas. No
existe el estado "rogue" ni ninguna clasificación automática: decidir que un AP es hostil es
una decisión de producto y de seguridad pendiente de decisión de Jesus.

## Vinculación AP ↔ activo / equipo de red

- Automática solo con evidencia y dentro del site: la IP de gestión o la MAC Ethernet (global,
  nunca aleatoria) del AP coinciden con un único activo (`primary_ip`, `mac_address`) o equipo
  de red activo (`management_address`, `base_bridge_address`, `lldp_chassis_id`) del mismo
  site, o el AP es el propio equipo consultado (`source_device`). Con dos candidatos no se
  vincula nada. Nunca sustituye un vínculo existente. La evidencia se guarda (`link_evidence`:
  `basis`, `value`, `method`, `at`, `by`).
- Manual (`POST .../link`) exige la misma evidencia: sin ella 409
  `wlan_link_evidence_insufficient`; otro site 409 `wlan_link_site_mismatch`. Auditado como
  `wlan_access_point_linked`.
- `POST .../unlink` quita el vínculo y fija `link_suppressed`, para que la siguiente consulta
  no vuelva a vincular sola. Un `link` manual posterior lo levanta. Auditado como
  `wlan_access_point_unlinked`.
- La identidad (`access_point_id`) e historial del AP no cambian al vincular o desvincular.

## Configuraciones inseguras

Red abierta (`open_network`), WEP (`wep`), WPA1 (`wpa1`), WPA/WPA2 mixto (`wpa1_allowed`),
privacidad heredada sin RSNA (`legacy_privacy`) y TKIP permitido (`tkip_allowed`) se exponen
como `findings` (severidad `info`) en BSS, AP y SSIDs y en la vista general
(`insecure_bss`, `findings_by_code`).

**No contribuyen al Risk Engine** (`contributes_to_risk: false`,
`risk_engine_contribution: false`): una red abierta puede ser una red de invitados aislada a
propósito, y no hay una política aprobada que convierta estas observaciones en riesgo de un
activo. Integrarlas en el Risk Engine queda pendiente de decisión de Jesus.

## API

Prefijo `/api/v1/network/wlan`, mismos permisos que 6B, sin roles nuevos:

| Método y ruta | Permiso |
|---|---|
| `GET /overview` | `monitoring:read` |
| `GET /access-points`, `GET /access-points/{id}`, `GET /access-points/{id}/observations` | `monitoring:read` |
| `POST /access-points/{id}/authorization`, `/link`, `/unlink` | `network:manage` |
| `GET /bss`, `GET /bss/{id}`, `GET /bss/{id}/observations` | `monitoring:read` |
| `POST /bss/{id}/authorization` | `network:manage` |
| `GET /ssids` | `monitoring:read` |
| `GET /clients` | `monitoring:read` |

Listas con paginación en servidor (`limit` 1–200, por defecto 50; `offset`), respuesta
`{items, total, limit, offset}`. `site_id` desconocido: 404 `site_not_found`. Errores
propios: `wlan_access_point_not_found`, `wlan_bss_not_found` (404), `wlan_version_conflict`,
`wlan_link_site_mismatch`, `wlan_link_evidence_insufficient` (409), `invalid_mac` (422).

La vista general incluye `sources`: disponibilidad de datos por fuente (`snmp`, `agent`) con
`available`, `partial`, `unavailable` o `not_configured`, el número de informantes, el
recuento por estado del módulo o del informe y la última vez vista, para que la UI explique
por qué no hay datos (ningún sensor 0.4.0, equipos sin MIB Wi-Fi, agentes sin adaptador o
con permisos limitados).

## Retención

Opt-in con `WLAN_HISTORY_RETENTION_DAYS` (vacío por defecto = no se purga nada). Con un
valor, el mantenimiento de red periódico borra observaciones más antiguas que el plazo,
clientes no vistos desde entonces, BSS solo observados por agentes (sin AP y con autorización
`unknown`) y WLANs configuradas ausentes. Los APs y todo lo que un operador clasificó se
conservan.

## Permisos y auditoría

Lectura: `monitoring:read` (todos los roles). Gestión: `network:manage` (admin). Eventos de
auditoría: `wlan_authorization_changed`, `wlan_access_point_linked`,
`wlan_access_point_unlinked`; los intentos sin permiso los audita `require_permission`.

## Limitaciones conocidas

- Sin validación con hardware real: los adaptadores se han probado con MIBs sintéticas. Los
  números de columna de AIRESPACE (estado de radio 12, clientes 15, clientes de WLAN 38,
  protocolo 25) y de UniFi deben validarse contra una controladora AireOS y un AP UniFi
  reales; Catalyst 9800 (IOS-XE) usa CISCO-LWAPP-* y no está cubierto.
- VLAN de cada BSS siempre `null`: ninguna de las fuentes la da de forma verificable.
- Los clientes de la controladora no traen BSSID (`bssid = null`); la banda se toma del
  protocolo o, si no se conoce, de la radio del AP.
- La vinculación automática hace una consulta por AP (aceptable con los topes actuales).
- Un agente con `wireless` contra un servidor anterior a 6C.3 recibe 422 `extra_forbidden`;
  el mecanismo de compatibilidad del agente quita el campo y reintenta.

## Interfaz web

Página `/wlan` («Wi-Fi», grupo Infraestructura del menú, permiso `monitoring:read`), en
`frontend/src/pages/WlanPage.tsx` y `frontend/src/components/wlan/`:

- Resumen (`/overview`): recuentos que abren la pestaña correspondiente, aviso informativo de
  configuraciones inseguras (abierta, WEP, WPA1, TKIP; sin efecto en el riesgo ni acciones) y
  una tarjeta por fuente (SNMP y agentes) con su disponibilidad, reporteros, última
  observación y aviso de consulta parcial. Sin datos en el ámbito no se muestran pestañas y se
  explica cómo obtenerlos (sensor con `snmp.wlan` y perfil SNMP, o agentes con `wireless`).
- Pestañas Puntos de acceso, Redes (SSID), BSS y Clientes, paginadas en el servidor, con el
  alcance de site de la cabecera (o un filtro de site propio si no hay alcance elegido) y
  filtros de autorización, banda, seguridad, fuente, confianza, frescura y presencia. La
  búsqueda de clientes envía `bssid` si el texto es una MAC y `ssid` exacto en otro caso.
- Detalle de un AP en un panel lateral (`?ap=<id>`, enlazable) con identidad, procedencia,
  vínculos y su evidencia, radios, BSS e historial de observaciones paginado.
- Solo con `network:manage`: clasificar AP o BSS (unknown / authorized / external, nunca
  «rogue») y vincular o desvincular un AP, siempre tras un diálogo de confirmación; se envía
  la `version` leída y un 409 recarga los datos.
- Reglas de presentación: «Evidencia histórica» no es «desaparecido»; solo `present = false`
  se muestra como «No visto en la última consulta completa». Una MAC aleatoria se marca y
  nunca se usa como nombre del cliente.

## QA manual

1. Actualizar un sensor del site a 0.4.0 con el extra `snmp` y comprobar en Sensores que
   declara `snmp.wlan`.
2. Registrar una controladora AireOS (o un AP autónomo/UniFi) como equipo de red con un
   perfil SNMPv3 de solo lectura y lanzar una consulta: el módulo `wlan` debe salir
   `complete` y `GET /network/wlan/access-points` listar sus APs con `source` y `confidence`.
3. Apagar un AP en la controladora y repetir: tras una consulta completa pasa a
   `present = false`; cancelar una consulta a mitad no debe cambiar nada.
4. En un agente con Wi-Fi, enviar inventario con `wireless` y comprobar BSS `observed`,
   el cliente propio `confirmed` y la fuente `agent` disponible en `/overview`.
5. Marcar un AP como `external` y comprobar el evento de auditoría y que persiste tras otra
   consulta. Desvincular un AP y comprobar que la siguiente consulta no lo revincula.
