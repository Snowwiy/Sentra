# Fase 7F.3: Suricata EVE JSON

Sentra integra Suricata como **fuente externa opcional**. Sentra no instala, configura ni controla Suricata. Lee su `eve.json` de dos formas:

- **Sensor 0.9.0**: lectura incremental de ficheros (entrada `type = "file"`, `format = "suricata_eve"`).
- **Importación manual**: un admin sube un `eve.json` exportado desde la página SIEM (fuente con transporte `upload`).

## Activación

```toml
[siem]
enabled = true

[[siem.inputs]]
name = "suricata"
type = "file"
format = "suricata_eve"
allowed_dir = "/var/log/suricata"
paths = ["eve.json"]
start_at = "end"
```

Después, un admin registra una fuente `suricata_eve` con transporte `sensor`, el sensor del mismo site y el alias `suricata`.

## Lector de ficheros del sensor

| Aspecto | Comportamiento |
|---|---|
| Rutas | Solo ficheros declarados (como mucho 16) dentro de `allowed_dir`. `..` se rechaza al cargar la configuración. Al abrir se comprueba la ruta real: un enlace simbólico o un punto de reanálisis en el fichero se rechaza (`symlink_refused`); un enlace de directorio que saca la ruta fuera de `allowed_dir` también (`path_outside_allowed_dir`). En POSIX se abre con `O_NOFOLLOW` y se comprueba que el fichero abierto es el que se validó. |
| Offsets | Se guardan en `siem-offsets.json` (directorio de datos del sensor), por fichero, con su identidad (dispositivo + inodo; en Windows, número de serie del volumen + índice de fichero) y una huella SHA-256 de los primeros 256 bytes ya leídos. Tras un reinicio se continúa donde se quedó. Un `siem-offsets.json` de 7F sin huella sigue valiendo; un valor dañado se lee como 0 (se relee y el servidor deduplica). |
| Primera lectura | `start_at = "end"` (por defecto) ignora el histórico; `beginning` lo lee entero. Solo aplica si no hay offset guardado. |
| Rotación | Linux/macOS: se termina el fichero anterior por su descriptor abierto y se empieza el nuevo desde el principio. Windows: el handle solo existe durante la pasada y se cierra siempre, también si la lectura falla, para no bloquear el renombrado del escritor (WinError 32). La rotación se detecta por identidad al reabrir. Lo pendiente del fichero anterior se recupera buscándolo por identidad y huella entre sus hermanos del mismo directorio (`eve.json.1`, `eve.json-fecha`...; como mucho 256 entradas). Esto mismo se hace en cualquier plataforma en la primera pasada tras un reinicio (7F-Windows-Fix2). |
| Truncado y sobrescritura | Misma identidad y tamaño menor que el offset, o tamaño suficiente pero huella distinta (reescrito en el sitio): se vuelve al principio y se cuenta `truncations`, con el descriptor abierto o cerrado entre pasadas (7F-Windows-Fix1: en Windows un truncado se contaba como rotación). Inaccesible (bloqueo de compartición, permisos, ausente durante la rotación): se anota `file_unreadable` o `file_missing` y el offset no cambia. |
| Líneas | Solo líneas completas. Una línea mayor que `max_line_bytes` (por defecto 64 KiB) se descarta entera (`dropped_oversize`); una línea que no es un objeto JSON se cuenta como `malformed` y no se envía. |
| Límites | Como mucho 1000 líneas y 8 MiB por fichero y pasada, `max_records_per_second` con contrapresión (las líneas pendientes se leen después; nada se descarta por ritmo) y lotes acotados por el servidor. |
| Entrega | Al menos una vez: el offset se guarda después de que el lote está en el spool. Tras una caída entre ambos pasos se reenvían unas líneas y el servidor las deduplica. |
| Payloads | `payload`, `payload_printable`, `packet`, `packet_info`, cuerpos HTTP, `stream` y el texto de la regla (`rule`) se eliminan **en el host**, antes de salir, y otra vez en el servidor. |

## Normalización (conector `suricata_eve` 1.0.0)

| `event_type` EVE | Evento Sentra | Categoría |
|---|---|---|
| alert | `ids.alert` | detection |
| anomaly | `ids.anomaly` | network |
| drop | `ids.drop` | network |
| flow, netflow | `network.flow` | network |
| dns | `dns.query` | dns |
| http | `http.request` | http |
| tls | `tls.handshake` | tls |
| ssh | `ssh.session` | ssh |
| dhcp | `dhcp.message` | dhcp |
| fileinfo | `file.observed` (solo metadatos: nombre, sha256, tamaño, magic) | file |
| smb | `network.smb` | network |
| krb5 | `auth.kerberos` | authentication |

Cualquier otro tipo (por ejemplo `stats`) se rechaza con `unsupported_event_type`. Un tipo nuevo se añade con su prueba; no entra con una forma desconocida.

- Hora: `timestamp` de EVE con zona; sin zona o inválida, el registro se rechaza (`invalid_timestamp`).
- `flow_id` → `flow_ref` y `external_id`; `community_id` → `data.community_id`.
- HTTP: la URL se guarda **sin query string ni fragmento** (pueden llevar tokens), también en el extracto.
- Identidad para deduplicar: el registro canónico sin payloads y con claves ordenadas.

### Severidad y confianza

- `alert.severity` → Sentra: 1 `high`, 2 `medium`, 3 `low`, 4 `informational`. Un valor fuera de ese rango da `unknown`. La política se puede ajustar por fuente.
- Los registros que no son alertas entran como `informational`.
- **Una alerta de Suricata es evidencia externa de una firma que coincidió, no una intrusión confirmada.** Entra con confianza `low`.

## Correlación con Sentra

1. **Atribución** (app/siem/identity.py): la IP de origen o destino identifica un activo solo si exactamente un activo no archivado del mismo site la tiene como IP principal. Si la comparten varios (NAT o duplicados), el veredicto es `ambiguous` y no hay activo. Si las dos IP son de activos inventariados, el veredicto es `multiple` y cada activo recibe su señal con su rol. Nunca se crea un activo a partir de una alerta.
2. **Flujos NDR** (`five_tuple_time`): misma 5-tupla en cualquier sentido, mismo protocolo, mismo site y la hora del evento dentro de la vida del flujo ±120 s. Con NAT o rutas asimétricas no hay enlace: se prefiere no enlazar a enlazar mal. Un candidato da confianza `high`; varios, `medium`.
3. **Mismo flujo en Suricata** (`flow_ref`) y **otras fuentes** (`community_id`, por ejemplo Zeek) en una ventana de ±30 min.
4. **Anomalías NDR** (`subject_time`, confianza `low`): una anomalía activa del mismo activo, con una de las IP del evento como sujeto y la misma ventana de tiempo. Es coincidencia temporal: **no demuestra causalidad**, y la explicación lo dice.

## Detección, riesgo e incidentes

No hay un segundo motor de detección. Las alertas con severidad `low` o superior que tienen un activo candidato generan una señal `siem_alert`, y la regla built-in **SIEM-EXT-001** (categoría `external`) la convierte en detección:

- Origen `imported`, confianza `low`. Si el sensor NDR de Sentra vio la misma comunicación, el origen es `correlated` y la confianza `medium`.
- Severidad: la de la política explícita de la fuente.
- Clave: (fuente, firma, rol, extremo). Las repeticiones forman una sola detección dentro del cooldown de 24 h.
- MITRE: solo si la firma trae `mitre_tactic_id` y `mitre_technique_id` en su metadata.
- Como mucho 200 señales por lote.

Sin doble conteo en el riesgo:

- Las detecciones SIEM-EXT-001 de un activo son una familia: cuenta la más fuerte, con crecimiento logarítmico por repetición.
- Una SIEM-EXT-001 enlazada a una anomalía NDR comparte su clave causal (`ndr:<id>`) con la NET-NDR-001 de esa anomalía, así que cuentan una vez.

Las detecciones siguen el flujo normal de alertas e incidentes (promoción a incidente, casos).

## Permisos y retención

- Los eventos (incluidos DNS, SNI, rutas HTTP y user-agent) solo son visibles con `siem:evidence` (analista o admin).
- Retención por fuente (`retention_days`) o global `SIEM_EVENT_RETENTION_DAYS` (30 días). Los enlaces se borran con su evento.

## Limitaciones conocidas

- Fixtures sintéticos con la estructura documentada de EVE JSON (Suricata 7). **Sin validación con un Suricata real.**
- No se leen ficheros comprimidos ni rotados (`eve.json.1.gz`).
- Si el fichero rotado sale del directorio (comprimido, archivado en otra carpeta o borrado) antes de la siguiente pasada, lo que quedaba pendiente en él no se puede recuperar. La QA física en Windows está pendiente.
- Un fichero reescrito en el sitio con los mismos primeros 256 bytes y tamaño mayor o igual que el offset no se distingue de uno con líneas añadidas. En sistemas de ficheros sin índice de fichero (st_ino = 0) una rotación se cuenta como truncado. En ambos casos no hay relecturas sin fin ni lecturas fuera de `allowed_dir`.
