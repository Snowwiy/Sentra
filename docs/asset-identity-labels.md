# Identidad automática, etiquetas y acceso a servicios (Corrección 6C)

Corrección sobre la Fase 6C, antes de 6D. Tres cosas: que Sentra identifique mejor los
dispositivos sin inventar nada, que una persona pueda ponerles un nombre propio que nada
sobrescribe, y que desde los puertos abiertos se pueda abrir un servicio web o copiar el
destino de los demás. Migración 0037, sensor 0.5.0, sin dependencias nuevas ni variables de
entorno nuevas.

## El caso que la motivó

`192.168.50.78`: DNS inverso `linux.local` y NIC con OUI de Amazon. Es un Echo (Linux
embebido). Antes Sentra podía presentarlo como «linux» o empujar el tipo hacia PC. Ahora:

- `linux` es un **nombre genérico** de sistema operativo: se guarda como evidencia, pero
  nunca se elige como nombre ni vota tipo ni SO.
- El OUI de Amazon solo dice quién fabricó la NIC. Por sí solo da **IoT probable** con
  confianza baja y fabricante Amazon; nunca un modelo ni un nombre «Alexa».
- Si una persona le pone la etiqueta «Alexa Sala», se muestra «Alexa Sala» en todas las
  vistas, búsquedas e informes, y el nombre automático y toda la evidencia original siguen a
  la vista en el detalle.

## Nombres observados con procedencia

`app/discovery/classify.py` reúne los nombres de todas las fuentes y los clasifica
(`observed_names` en la API, columna `assets.observed_names`):

| kind | Qué es | Ejemplo |
|---|---|---|
| `agent` | Hostname reportado por el agente | `SALON-PC` |
| `device` | Publicado por el propio equipo: mDNS, NetBIOS, UPnP, o un DNS inverso `.local` (el resolvedor del sistema contesta con mDNS/LLMNR) | `Echo-Salon` |
| `dhcp` | DNS inverso sin dominio o con dominio local (`.lan`, `.home`, `.home.arpa`...): es el nombre que el router registró por DHCP o la etiqueta que alguien le puso en su panel. Es una **inferencia**: Sentra no ve el DHCP | `pc-salon.lan` |
| `dns` | DNS inverso con dominio real | `nas.empresa.es` |
| `generic` | Valor por defecto de un SO o de un firmware (`linux`, `android`, `ubuntu`, `raspberrypi`, `espressif`, `busybox`, `localdomain`...) | `linux.local` |

Cada nombre lleva `source`, `selected` (el elegido como nombre automático), `confirmed`
(confirmación directa del DNS inverso: el nombre resuelve otra vez a esta IP; `null` si no
aplica o no se comprobó) y `stale` (ninguna fuente lo repite desde hace 30 días).

### Elección del nombre automático

1. Nunca un nombre `generic`.
2. Primero los recientes; después los no desmentidos (un DNS inverso que **no** resuelve a
   esta IP pasa al final y queda la evidencia «no confirmado»).
3. A igualdad, el orden de siempre: agente, DNS inverso, mDNS, NetBIOS, UPnP, fabricante +
   modelo.

### Una evidencia débil no pisa a una fuerte

`services/identification.py`:

- Un nombre genérico no sustituye a uno específico guardado de la misma fuente (salvo que
  el específico lleve más de 30 días sin verse).
- Un DNS inverso no confirmado no sustituye a uno confirmado (misma excepción).
- Cuando el nombre cambia de verdad, la confirmación anterior se descarta: nunca se hereda.
- Las observaciones guardan su fecha (`*_seen_at`) para poder decidir por vigencia.

### Clasificación con evidencia limitada

- Un solo puerto nunca decide el tipo: 9100 solo no es impresora (hacen falta dos puertos
  de impresora o otra pista), 3389 solo no es «PC Windows» (hacen falta dos puertos de
  Windows o una pista de familia), y 554/1883/8008/8009/5000/5001 solo suman si ya hay una
  pista de la misma familia.
- Un fabricante ambiguo no decide: Amazon da como mucho «IoT probable» bajo; Google o
  Samsung, sin más evidencia, no dan tipo.
- Las contradicciones se conservan: fabricantes distintos entre OUI y UPnP o pistas de tipos
  incompatibles quedan como evidencia `conflict` y bajan la confianza; no se elige al azar.
- Fabricantes IoT añadidos al catálogo: Ring, Arlo, Wyze, Reolink, EZVIZ, iRobot, Ecovacs,
  Netatmo, tado y Bose.

## Fuentes de nombre en el sensor (0.5.0)

El sensor replica las sondas del discovery local (mismos parsers y criterios, solo
biblioteca estándar): PTR mDNS unicast, NBSTAT NetBIOS (solo IPv4), un M-SEARCH SSDP por job
(solo IPv4, filtrado a direcciones del target) y la descripción UPnP solo por `http://` a la
misma IP que respondió (anti-SSRF, XML ≤ 64 KB, sin DTD).

- Job `discovery_advanced` con `schema_version: 2`: añade `identify` y `max_name_queries`
  (tope: `max_dns_queries` del servidor). El sensor rechaza claves que no sean exactamente
  las de su versión.
- Capacidad nueva `network.discovery.names`. A un sensor 0.4.x se le sigue enviando el
  esquema 1, sin sondas de nombre.
- El lote lleva un campo `identity` opcional por observación (`mdns_name`, `netbios_name`,
  `ssdp_server`, `upnp`); el servidor lo revalida (`SensorIdentityIn`) y lo guarda en
  `sensor_observations.identity`. No cambia el digest de un lote sin identidad.
- Sin sockets en escucha (lo vigila `test_security`); las sondas respetan el presupuesto, la
  concurrencia y el ritmo del job.

### DHCP, router y TP-Link Archer GX90

Desde la Fase 6E hay fuentes DHCP de solo lectura (importación de leases y fichero leído por
un sensor), con nombre `dhcp_lease` solo cuando MAC e IP coinciden: ver
`docs/dhcp-identity.md`. Lo que sigue describe el comportamiento de 6C, que se mantiene para
el DNS inverso.

Sin una fuente DHCP configurada, los nombres DHCP solo llegan indirectamente
por el DNS del router y se marcan como inferidos (`dhcp`). No se ha añadido ninguna
integración con routers. En concreto **no se asume** que el TP-Link Archer GX90 ofrezca SNMP
ni una API local documentada: cualquier integración con TP-Link requiere una evaluación de
viabilidad aparte (modelo y firmware reales, qué expone, autenticación sin credenciales en
código, solo lectura) y una decisión de Jesus. Tampoco se usa el `sysName` del inventario
SNMP como nombre de activo, para no cambiar el almacenamiento ni el comportamiento de 6B.

## Etiqueta personalizada

Columna `assets.custom_label` (≤ 64 caracteres, nunca vacía) con `custom_label_version`,
`custom_label_updated_at` y `custom_label_updated_by`.

- `PATCH /api/v1/assets/{id}/label` con `{"label": "Alexa Sala" | null, "version": n}`.
  `null` la quita. Requiere `assets:manage` (admin); la API devuelve el activo actualizado.
- Validación: NFC, espacios repetidos compactados, sin controles, saltos de línea,
  caracteres invisibles, de uso privado ni de cambio de dirección (`Alexa‮ala S`).
  Vacía o > 64 → 422.
- Concurrencia optimista: si `version` no es la actual, 409 `asset_label_conflict` con
  `details: [{"current_version", "custom_label"}]` y no se guarda nada. La UI enseña el
  valor ajeno y obliga a confirmar otra vez.
- Auditoría `asset_label_changed` (from/to/versión) solo si cambia; los intentos fallidos
  también se auditan con su código de error; un 403 deja `permission_denied`.
- Nada automático la escribe: discovery, sensores, heartbeats, inventario del agente ni
  `reclassify-assets`.
- Cambios de IP: la etiqueta va en el activo, así que se conserva cuando el mismo activo
  cambia de IP (misma MAC o agente).
- Reconciliación: al fusionar dos activos (agente sobre descubierto, o reconciliación manual
  de 5C.2) el superviviente adopta la etiqueta del otro **solo si no tiene una propia**. No
  se fusiona nada de forma automática por coincidir la etiqueta.

### Dónde se usa

`display_name` = etiqueta → nombre resuelto → hostname → DNS inverso → IP. Se aplica en el
listado y la búsqueda de activos (también busca por etiqueta), riesgo, incidentes,
vulnerabilidades, informes (fila «Etiqueta personalizada» en la identidad del activo),
alertas, eventos y el contexto de IA (con la misma redacción que los hostnames). En la UI:
título del detalle, tabla de Red (botón «Etiquetar»/«Editar» para admin, con el nombre
automático debajo) y sección Identificación (etiqueta, nombre automático y nombres
observados con su procedencia).

## Puertos con acceso a servicios

`frontend/src/lib/services.ts` y `PortList` (`components/NetworkBadges.tsx`):

- 80 y 443: HTTP/HTTPS. 8000, 8008, 8080, 8081, 8888 (HTTP) y 8443, 9443 (HTTPS) se marcan
  «probable» (`8080/HTTP?`): es lo habitual en ese puerto, no está comprobado.
- Enlace «Abrir servicio» a `http(s)://IP:PUERTO/`, construido y verificado con `URL`
  (esquema, host y puerto exactos, sin credenciales), `target="_blank"` y
  `rel="noopener noreferrer"`. Nunca se abre solo, no se hace ninguna petición al backend ni
  desde el navegador para «probar» el puerto, no se salta ningún aviso TLS ni se autentica.
- En el detalle, si el DNS inverso está confirmado, no es genérico ni antiguo, se ofrece
  además «por nombre» (útil con certificados emitidos para el nombre). El texto dice que el
  nombre resuelve a la IP, no que el puerto pertenezca a ese dominio.
- SSH, DNS, SMB, RDP y el resto: se muestra el protocolo y un botón copia `IP:PUERTO`
  (`[IPv6]:PUERTO`). Puertos desconocidos: solo el número (y copiar en el detalle).
- Límite de puertos visibles como antes (8 en tablas, 20 en el detalle) con `+N`.
- Aplicado en la tabla de Red, el panel Red del detalle y las observaciones de red.
- Los enlaces apuntan a la IP tal y como la ve el servidor de Sentra: desde otro segmento
  el navegador puede no llegar.

## Pruebas

- Backend: `tests/test_asset_identity_labels.py` (regresión del Echo de punta a punta,
  nombres genéricos, clases de nombre, prioridad, vigencia, conflicto, una evidencia débil no
  pisa, etiqueta: editar, quitar, auditoría, 409, validación, RBAC, 404, fusión con el
  agente y heartbeats) y `tests/test_identification.py`.
- Sensor: `tests/test_names.py` (parsers, esquema v2, presupuesto, v1 sin sondas, IPv6).
- Frontend: `lib/services.test.ts`, `components/NetworkBadges.test.tsx`,
  `components/asset/AssetLabelDialog.test.tsx`, `components/DeviceIdentity.test.tsx` y
  `lib/identity.test.ts`.

## Validación pendiente en la red real

1. Aplicar la migración 0037 sobre `sentra_test` y luego, tras revisar, en producción.
2. Lanzar un discovery y comprobar `192.168.50.78`: IoT probable, Amazon, sin nombre
   inventado; ponerle «Alexa Sala» como admin y comprobar tabla, detalle, búsqueda e informe.
3. Repetir el discovery y comprobar que la etiqueta sigue y que «linux» sigue como evidencia.
4. Actualizar un sensor a 0.5.0, comprobar que declara `network.discovery.names` y lanzar un
   `standard` desde él.
5. Abrir el panel del router por «Abrir servicio» y copiar un destino SSH.
