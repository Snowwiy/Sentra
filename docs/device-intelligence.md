# Inteligencia de dispositivos sin agente ni SNMP (Fase 7A.4)

Sentra identifica teléfonos, tabletas, televisores, cámaras, grabadores, impresoras, NAS y
equipos de red sin instalar nada en ellos y sin perfiles SNMP. Lo hace con lo que el propio
equipo publica en la red, siempre dentro de las redes autorizadas del site y con los límites
del discovery. Esta fase amplía el motor de identidad de la Corrección 6C
([asset-identity-labels.md](asset-identity-labels.md)) y la identidad DHCP de la 6E
([dhcp-identity.md](dhcp-identity.md)).

## Qué se identifica

Nombre, fabricante probable, tipo, modelo (solo si el equipo lo declara), sistema operativo
probable, servicios anunciados, IP y MAC observadas, confianza y el historial de cambios de
identidad. Si la evidencia no basta, el resultado es honesto: tipo desconocido o confianza
baja. **Sentra no inventa marca, modelo ni nombre**: un modelo solo aparece si el equipo lo
publica (UPnP `modelName`, mDNS `_device-info` `model=`), nunca se deduce de una página web.

## Clases de dispositivo

`pc`, `laptop`, `server`, `mobile`, `tablet`, `smart_tv`, `game_console`, `router`,
`network_switch`, `access_point`, `printer`, `ip_camera`, `dvr_nvr`, `iot`,
`voice_assistant`, `nas`, `network_device` y desconocido (sin tipo).

Nuevas en 7A: `ip_camera`, `dvr_nvr` y `network_device` (un equipo de red cuya función
concreta, router, switch o AP, no se puede afirmar). Las familias compatibles (por ejemplo
cámara, grabador e IoT, o router, switch, AP y equipo de red) no se cuentan como conflicto
entre sí: una pista de "cámara" no contradice a otra de "grabador".

## Fuentes

| Fuente | Qué aporta | Cómo se obtiene |
| --- | --- | --- |
| Agente | hostname, SO (autoritativos) | el propio agente |
| DHCP | hostname pedido al servidor DHCP, vendor class | fuentes DHCP autorizadas (6E); lectura automática tras cada discovery |
| DNS inverso y directo | nombre y su confirmación | resolvedor del sistema |
| mDNS | nombre `.local` | consulta unicast al 5353 del host |
| mDNS DNS-SD | tipos de servicio (`_ipp._tcp`, `_googlecast._tcp`...) y modelo `_device-info` | consulta unicast `_services._dns-sd._udp.local` al 5353 del host |
| NetBIOS | nombre de equipo | consulta de estado al 137 del host |
| SSDP / UPnP | fabricante, modelo y nombre declarados | M-SEARCH filtrado por el target y descripción del propio host |
| OUI | fabricante de la tarjeta de red | base OUI local; una MAC aleatoria no aporta fabricante |
| HTTP | cabecera `Server` y `<title>` (solo en un 200 HTML) | `GET /` en el primer puerto web abierto |
| TLS | CN y O del sujeto del certificado, y si es autofirmado | saludo TLS 1.2 en el primer puerto TLS abierto |
| Puertos | servicios con puerto abierto | el propio scan |
| Manual | tipo fijado por un admin | `PATCH /assets/{id}/device-type` |

### Huellas HTTP y TLS: límites de seguridad

- Solo hosts dentro del target autorizado y solo puertos que el propio scan encontró
  abiertos. Como mucho un puerto web y uno TLS por host.
- HTTP: una petición `GET / HTTP/1.0` sin credenciales, sin cuerpo, sin seguir redirecciones y
  leyendo como mucho 32 KiB.
- TLS: se envía un ClientHello TLS 1.2 y se corta la conexión en cuanto llega el certificado,
  antes del intercambio de claves. No se negocia ninguna sesión TLS, así que no hay validación
  de certificado que desactivar. Un servidor que solo habla TLS 1.3 cifra su certificado y no
  aporta esta huella.
- Todo el texto recibido se limpia (imprimible, acotado) antes de guardarse.
- Solo en los perfiles `standard` y `deep`, y solo con `DISCOVERY_FINGERPRINT=true` (valor
  por defecto). `quick` nunca toma huellas.

## Cómo se decide el tipo

Cada fuente vota un tipo con una fuerza de 1 a 3 (a veces 4, autoritativa), y el motor suma
por tipo. Gana el tipo con más votos solo si supera al mejor tipo incompatible; un empate con
un tipo incompatible deja el tipo desconocido. La confianza es alta con al menos 4 puntos y 2
de margen, media con 2 y 2 de margen, y baja en el resto.

Reglas que evitan los errores conocidos:

- **Una marca sola no decide el tipo.** "Hikvision", "Synology", "QNAP", "Ubiquiti",
  "Brother" o el fabricante OUI aportan la marca; el tipo tiene que salir de un producto o
  firmware concreto (`DS-2CD...`, `DNVRS-Webs`, "DiskStation", "Synology Router Manager",
  `_ipp._tcp`...). El fabricante de la tarjeta de red no tiene por qué ser el del equipo.
- **Un puerto no decide el tipo** (Corrección 6C): 80, 443 o 9100 solos no hacen una
  impresora.
- **Varias pistas de la misma fuente no se suman**: `_ipp._tcp` e `_ipps._tcp`, o el título y
  la cabecera de la misma web, cuentan una vez (la más fuerte).
- **Una pista no se corrobora a sí misma**: la marca que sale de la misma huella que el tipo no
  sube la confianza de ese tipo.
- **MAC aleatoria**: se marca como tal, no aporta fabricante y la identidad se apoya en las
  demás fuentes.
- **Contradicciones**: dos fabricantes o dos tipos incompatibles respaldados quedan como
  evidencia `conflict` visible, nunca se resuelven al azar.

Ejemplos con evidencia suficiente: un equipo que anuncia `_ipp._tcp` es una impresora; un
servidor web `App-webs/` con RTSP abierto es una cámara Hikvision; `DNVRS-Webs` es un
grabador; un Mac que publica `MacBookPro18,3` en `_device-info` es un portátil Apple con
macOS. Un `nginx` con título "Welcome" no identifica nada.

## Vigencia de la evidencia

Cada fuente guarda cuándo se vio por última vez. Pasados 30 días sin volver a verla, su
evidencia se conserva con la marca "(antiguo)" pero deja de votar: un equipo que cambió de
uso no arrastra lo que fue. Los nombres siguen la misma regla (6C).

## Tipo manual

Un admin (`assets:manage`) puede fijar el tipo de un activo:

```http
PATCH /api/v1/assets/{asset_id}/device-type
{"device_type": "ip_camera", "version": 3}
```

- `device_type: null` vuelve a la identificación automática.
- `version` es el mismo token de concurrencia que la etiqueta personalizada
  (`custom_label_version`); una versión vieja responde 409.
- El tipo manual manda sobre cualquier inferencia, pero no borra la evidencia: si la
  inferencia apunta a otro tipo, queda una entrada `conflict` visible.
- Auditoría `asset_device_type_changed` (éxito y fallo), y el cambio entra en el historial de
  identidad.

## DHCP sin pulsar nada

Al terminar con éxito un discovery de un site, Sentra encola la lectura de sus fuentes DHCP
de tipo `sensor_file` activas cuyo sensor esté listo, siempre que no haya ya una lectura en
curso ni una reciente (como mucho una cada 10 minutos por fuente). Los jobs quedan con
`created_by = "discovery"`. Las importaciones manuales (`lease_import`) siguen siendo
manuales porque dependen de un fichero que sube una persona. Sentra no asume acceso a los
leases de un router: solo lee fuentes declaradas y autorizadas (ver
[sensor-upgrade-0.6.md](sensor-upgrade-0.6.md)).

## Sensor 0.7.0

- Nueva capability `network.discovery.fingerprint` y esquema `discovery_advanced` v3 (v2 más
  la clave `fingerprint`). El servidor solo envía v3 a sensores que declaran la capability y
  solo si el perfil identifica y toma huellas; un sensor 0.5.x o 0.6.x sigue recibiendo v2 o
  v1 exactamente igual que antes.
- Las huellas comparten el presupuesto `max_name_queries` de las sondas de nombre.
- El lote de observaciones añade `identity.mdns_services`, `identity.mdns_model` e
  `identity.web` (como mucho 2 entradas); el servidor los valida con un esquema exacto.
- El sensor sigue sin abrir puertos de escucha y sin ningún contexto TLS sin verificar (lo
  comprueba `tests/test_security.py`).

## Configuración

| Variable | Defecto | Uso |
| --- | --- | --- |
| `DISCOVERY_FINGERPRINT` | true | Huellas DNS-SD, HTTP y TLS en `standard` y `deep` (requiere `DISCOVERY_IDENTIFY`). |

## Datos

- Migración 0045: `assets.manual_device_type`, `manual_device_type_at` y
  `manual_device_type_by`.
- `assets.identity_observations` guarda `mdns_services`, `mdns_model` y `web` con su
  `seen_at`.

## Limitaciones conocidas

- Servidores solo TLS 1.3: sin huella de certificado.
- Las tablas de pistas (servicios DNS-SD, productos web, nombres por defecto) cubren los
  equipos domésticos y de pyme habituales; un equipo fuera de ellas queda con tipo
  desconocido o con el que den las demás fuentes.
- Las huellas no se han probado todavía contra cámaras, grabadores e impresoras reales; los
  tests usan servidores locales y respuestas construidas.
