# Fase 7F.2: Syslog (RFC 5424 y RFC 3164)

Sentra recibe Syslog con un receptor opcional del **sensor** (0.9.0). El backend no abre puertos Syslog: el sensor enmarca y acota los mensajes, los guarda en un spool propio y los reenvía por HTTPS (`POST /api/v1/sensor/siem/batches`). La interpretación de la cabecera y la clasificación las hace el conector `syslog` del servidor (versión 1.0.0).

## Activación (doble control)

1. En el host del sensor, el operador declara la entrada en `sensor.toml`:

   ```toml
   [siem]
   enabled = true

   [[siem.inputs]]
   name = "fw-syslog"
   type = "syslog"
   protocol = "tls"          # tcp | tls | udp
   bind = "0.0.0.0"
   port = 6514
   allowed_peers = ["10.0.10.1/32"]
   tls_cert = "/etc/sentra-sensor/syslog.crt"
   tls_key = "/etc/sentra-sensor/syslog.key"
   ```

2. En Sentra, un admin (`siem:manage`) registra una fuente `syslog` con transporte `sensor`, elige el sensor del mismo site, escribe el alias `fw-syslog` y la habilita.

El sensor solo escucha cuando se cumplen las dos condiciones. El servidor envía únicamente el alias y el identificador de la fuente. Nunca envía puertos, direcciones, rutas, certificados ni órdenes. Si el servidor aprueba un alias que el host no declaró, no se abre nada: la entrada aparece como `not_declared` y la fuente pasa a `error`.

## Reglas de seguridad del receptor

| Regla | Motivo |
|---|---|
| Desactivado por defecto; sin `[siem] enabled = true` no se declara la capacidad `siem.ingest` ni se crea `siem-spool.sqlite3`. | Ningún puerto nuevo sin decisión del operador del host. |
| `allowed_peers` es obligatorio y no admite `/0`. | Lista blanca explícita de emisores. |
| Sin TLS solo se admiten pares en 10/8, 172.16/12, 192.168/16, 127/8, 169.254/16, ::1, fc00::/7 y fe80::/10. | Una fuente remota por Internet exige TLS. |
| UDP solo con `allow_udp = true`. | **La dirección de origen de un datagrama UDP se falsifica sin esfuerzo y no autentica a nadie.** El filtro de pares en UDP reduce ruido; no es una defensa. |
| El par se comprueba antes del handshake TLS y antes de leer. | Una conexión no permitida no consume CPU de TLS. |
| TLS 1.2 como mínimo; certificado y clave del host con rutas absolutas **locales según la plataforma del sensor** (7F-Windows-Fix1): en Linux y macOS `/etc/...`; en Windows con letra de unidad (`C:/ProgramData/SentraSensor/syslog.crt`). En Windows se rechazan `/etc/...` (sin unidad no es absoluta), las rutas UNC y de dispositivo; en todas, `..`, relativas y NUL. | Ni el directorio de trabajo del servicio ni un recurso de red deciden qué certificado o clave se carga. El receptor no implementa autenticación de cliente por certificado (mTLS) en esta fase. |
| `max_message_bytes` (480..65536, por defecto 8192), `max_connections` (por defecto 32), `idle_timeout_seconds`, `max_records_per_second`. | Memoria, hilos y CPU acotados. |
| Exceso de ritmo: en TCP/TLS contrapresión (se deja de leer); en UDP se descarta y se cuenta (`dropped_rate`). | TCP tiene control de flujo; UDP no. |
| El texto se decodifica como UTF-8 con sustitución, los NUL se sustituyen y no se interpreta nada en el sensor. | El contenido es dato no confiable. |

## Enmarcado

- TCP y TLS: RFC 6587 en sus dos variantes, detectadas mensaje a mensaje. Son el recuento de octetos (`LEN SP MSG`, el mismo que exige RFC 5425 sobre TLS) y la variante no transparente con LF final. Un mensaje demasiado grande se descarta entero (`dropped_oversize`) y el resto de la conexión sigue llegando.
- UDP: un datagrama es un mensaje. Se lee con un búfer de 65 537 bytes, mayor que cualquier datagrama UDP, así que su tamaño real se conoce en todas las plataformas: si supera `max_message_bytes` se descarta entero y se cuenta en `dropped_oversize` (nunca se reenvía un trozo). El error WSAEMSGSIZE de Windows también cuenta como sobredimensionado; los demás errores de recepción (por ejemplo WSAECONNRESET por un ICMP) se cuentan aparte en un contador local del sensor (`receive_errors`, no se envía al servidor) y se registran como mucho una vez por minuto (7F-Windows-Fix1).

## Normalización en el servidor

| Campo Syslog | Evento Sentra |
|---|---|
| PRI | `data.facility`, `data.syslog_severity`, `source_severity`; sin PRI válida (o > 191) se usa user.notice (13) y `data.pri_missing = true` |
| TIMESTAMP (RFC 5424) | `timestamp` con `time_quality = source`; un valor inválido rechaza el registro (`invalid_timestamp`) |
| TIMESTAMP (RFC 3164) | **No se usa** (no tiene año ni zona). El evento toma la hora de recepción del sensor (`time_quality = receiver`) y la cabecera se guarda en `data.header_timestamp` |
| HOSTNAME | `hostname` (contexto escrito por el emisor, nunca identidad) y `data.header_hostname` |
| APP-NAME / TAG | `process_name`, `data.app_name` |
| PROCID, MSGID | `data.procid`, `data.msgid` |
| STRUCTURED-DATA | `data.structured_data` (como mucho 8 elementos y 16 parámetros cada uno; valores de 256 caracteres como máximo) |
| MSG | `message` (texto limpio de 1000 caracteres como máximo) |
| Dirección del emisor | `data.peer_ip` (contexto; en UDP no está autenticada) |

### Clasificación conservadora

Solo unos pocos patrones conocidos cambian el tipo de evento:

- `sshd`: `Failed password/publickey ... for [invalid user] X from IP port N` → `auth.failure`; `Invalid user X from IP` → `auth.failure`; `Accepted ... for X from IP port N` → `auth.success`.
- `sudo`: `usuario : ... COMMAND=` → `privilege.sudo`.
- Registros tipo netfilter con `SRC=` y `DST=`: `firewall.deny` si el prefijo dice DROP, DENY, REJECT o BLOCK; `firewall.allow` si dice ACCEPT, ALLOW o PASS; si no, `firewall.log`.

Todo lo demás es `syslog.message` (categoría `system`, confianza `low`).

### Política de severidad por defecto

| Syslog | Sentra |
|---|---|
| emerg, alert | high |
| crit | medium |
| err, warning | low |
| notice, info, debug | informational |

Ningún mensaje llega a `critical` por defecto: un mensaje desconocido no puede convertirse en una alerta crítica. Un admin puede ajustar la política por fuente (`config.severity_policy`) y limitar los tipos de evento aceptados (`config.event_types`).

### Deduplicación

La identidad de un mensaje es su `record_id` en el receptor: un prefijo aleatorio por arranque más un contador. No se usa el texto, porque dos fallos de login idénticos son dos eventos. Los reintentos del sensor reenvían el mismo `record_id` y el servidor los descarta como duplicados. En una importación manual, la identidad es la línea del fichero (`upload:<sha16>#<línea>`), así que reimportar el mismo fichero no duplica nada.

## Estado de la fuente

El heartbeat del sensor informa, por alias:

- `state` (`running`, `degraded`, `error`, `stopped`, `not_declared`) y `error_code` (`bind_failed`, `tls_config_invalid`, `input_not_declared`);
- `degraded_reasons`;
- contadores (`received`, `dropped`, `malformed`, `connections`) y `last_record_at`.

Nunca informa puertos ni pares. La fuente solo pasa a `healthy` con un informe reciente del receptor o un lote aceptado. Si deja de haber ambos durante `SIEM_SOURCE_OFFLINE_MINUTES`, la fuente pasa a `offline`.

## Limitaciones conocidas

- Fixtures sintéticos (ejemplos de RFC 5424 sección 6.5, RFC 3164 sección 5.4 y formatos habituales de sshd, sudo y netfilter). **No se ha validado con equipos reales** (firewalls, switches ni rsyslog o syslog-ng reales).
- Sin mTLS en el receptor: la autenticación del emisor es la lista de pares más TLS del servidor.
- RFC 3164 sin año ni zona: la hora del evento es la de recepción.
- Windows: el receptor usa sockets estándar de Python. La regla de Firewall de Windows para el puerto la crea el operador; está pendiente la QA física (docs/fase-7f-windows-qa.md).
