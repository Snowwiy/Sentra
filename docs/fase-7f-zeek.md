# Fase 7F.4: Zeek (logs JSON)

Zeek es una **fuente externa opcional**. Sentra no instala ni controla Zeek; lee sus logs en JSON (`LogAscii::use_json=T`, o el paquete json-streaming-logs). Lo hace con el lector de ficheros del sensor (`type = "file"`, `format = "zeek_json"`) o con una importación manual.

```toml
[[siem.inputs]]
name = "zeek"
type = "file"
format = "zeek_json"
allowed_dir = "/opt/zeek/logs/current"
paths = ["conn.log", "dns.log", "ssl.log", "http.log", "dhcp.log", "ssh.log"]
```

El lector aplica las mismas garantías que con Suricata (docs/fase-7f-suricata.md): rutas permitidas, sin enlaces, offsets, rotación, truncado y límites. Si una línea no trae `_path`, el sensor lo añade a partir del nombre del fichero (`conn.log` y `conn.2026-11-24-08-00-00.log` dan `conn`). El servidor también sabe inferir el tipo de log por sus campos.

## Logs soportados (conector `zeek_json` 1.0.0)

| Log | Evento Sentra | Campos que se conservan |
|---|---|---|
| conn | `network.connection` | 5-tupla, proto, service, conn_state, history, duración, bytes y paquetes, local_orig |
| dns | `dns.query` | query, qtype_name, rcode_name, answers (8 como máximo), trans_id |
| ssl | `tls.handshake` | server_name (SNI), versión, cipher, validation_status, ja3/ja3s, established → outcome |
| http | `http.request` | method, host, **ruta de la URI sin query string**, status_code, user_agent, longitudes de cuerpo (no los cuerpos) |
| dhcp | `dhcp.message` | mac, assigned_addr, client_addr, server_addr, host_name, msg_types, domain |
| ssh | `ssh.session` | auth_success → outcome, auth_attempts, direction, client, server |

Cualquier otro log se rechaza con `unsupported_log`. Eso incluye files, x509, notice, weird y extract: **no se aceptan ficheros extraídos ni cuerpos**. Las claves `post_body`, `request_body`, `response_body`, `extracted` y `data` se eliminan siempre.

- Hora: `ts` en epoch (segundos) o ISO 8601 con zona. Sin zona, el registro se rechaza.
- El **uid** de Zeek se conserva en `flow_ref` y `external_id`. Une los registros de la misma conexión entre logs.
- `community_id` (si Zeek carga la política community-id) se guarda en `data.community_id` y une la conexión con Suricata.
- Identidad para deduplicar: el registro canónico (claves ordenadas), así que reimportar el mismo log no duplica.

## Severidad

Zeek no juzga el tráfico: todo entra como `informational`, con confianza `unknown`, y **un registro de Zeek no genera detecciones por sí solo**. Es contexto para la búsqueda, la correlación y la investigación (7F.6).

## Correlación

- **Con NDR** (`five_tuple_time`): las mismas reglas conservadoras que Suricata. Si Zeek está detrás de un NAT o ve el tráfico de forma asimétrica, la 5-tupla no coincide y no hay enlace. No se intenta adivinar la traducción.
- **Con Suricata** (`community_id`, confianza `medium`) dentro de ±30 min en el mismo site.
- **Entre logs de Zeek** (`flow_ref` = uid) dentro de la misma fuente.

## Privacidad, permisos y retención

DNS (query, answers), SNI, host, ruta HTTP y user-agent son datos de navegación. Solo se ven con `siem:evidence` (analista o admin), nunca con `siem:read`. La retención es la de la fuente (`retention_days`) o `SIEM_EVENT_RETENTION_DAYS`. Si una organización no quiere conservar DNS o HTTP, puede excluirlos de la fuente con `config.event_types` (por ejemplo, solo `network.connection` y `ssh.session`): los registros excluidos se rechazan y se cuentan (`event_type_not_allowed`).

## Limitaciones conocidas

- Fixtures sintéticos con los campos documentados de Zeek 6/7. **Sin validación con un Zeek real.**
- Solo JSON: el formato TSV por defecto de Zeek no se lee.
- No se leen logs comprimidos (`*.log.gz`) del archivo de Zeek.
