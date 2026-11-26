# Fase 7F.6: correlación multifuente, hunting e investigación

## Principios

- **Relacionar no es atribuir causa.** Cada relación guarda su método, su confianza y una explicación legible. Una coincidencia solo de tiempo nunca crea un enlace. Cuando se muestra como contexto, se marca `time_only` y la explicación dice que no demuestra relación.
- **Identidad conservadora** (app/siem/identity.py): una IP identifica un activo solo si exactamente un activo no archivado del mismo site la tiene. El nombre de host es una pista (`hostname_hint`), nunca identidad. Nunca se crea un activo a partir de un evento externo.
- **Sin doble conteo.** La correlación entre fuentes añade enlaces, no detecciones. Cada alerta externa ya tiene su SIEM-EXT-001 (familia en el riesgo); las que solapan con el NDR comparten clave causal con NET-NDR-001. Las alertas de Wazuh que probablemente repiten una detección nativa no generan otra (`probable_match`, docs/fase-7f-wazuh.md).

## Enlaces (tabla `siem_event_links`)

| kind | method | Confianza | Regla |
|---|---|---|---|
| `ndr_flow` | `five_tuple_time` | high (1 candidato) / medium | Misma 5-tupla y protocolo, mismo site, dentro de la vida del flujo ±120 s |
| `ndr_anomaly` | `subject_time` | low | Alerta con activo; anomalía activa del mismo activo con una IP del evento como sujeto, ±10 min |
| `siem_event` | `flow_ref` | high | Mismo id de flujo en la misma fuente, ±30 min |
| `siem_event` | `community_id` | medium | Mismo community_id en otra fuente del site, ±30 min |
| `siem_event` | `shared_endpoints` | low | Otra fuente, mismos dos extremos (en cualquier sentido), ±15 min, y uno de los dos eventos es una alerta |
| `siem_event` | `same_user_asset` | low | Otra fuente, mismo usuario y mismo activo atribuido, ±15 min, eventos de alerta o autenticación |
| `detection` | `same_asset_topic_time` | medium | Wazuh: detección nativa del mismo activo, ±15 min, misma técnica MITRE o mismo tema |

Por lote: como mucho 300 eventos correlacionados (las alertas primero) y 5 candidatos por evento y método. Con NAT o rutas asimétricas no hay enlace: se prefiere no enlazar a enlazar mal.

## Hunting: `POST /api/v1/siem/search` (siem:evidence)

Filtro **tipado**. No hay lenguaje de consulta ni SQL. Cada campo se traduce a una condición fija:

- `since` y `until`, obligatorios, con zona horaria. Ventana máxima: `SIEM_SEARCH_MAX_DAYS` (31).
- Filtros por fuente: `site_id`, `source_ids`, `source_types`, `event_types`, `categories`, `severities`.
- Filtros de red: `ip` (origen o destino), `source_ip` y `destination_ip`, que aceptan IP o CIDR (como mínimo /8 en IPv4 y /16 en IPv6); `port`; `protocol`.
- Igualdades: `hostname` (sin distinguir mayúsculas), `username` (exacto), `rule_id`, `signature_id`, `external_id`, `flow_ref`, `mitre_technique`, `asset_id`.
- Atribución: `verdicts` y `origins`.
- `text`: texto literal en el mensaje (3-100 caracteres). `%` y `_` no son comodines.
- Paginación por cursor (keyset sobre hora + id, del más reciente al más antiguo). Es estable aunque lleguen eventos nuevos. `limit` va de 1 a 200.
- `count: true` devuelve un recuento acotado a `SIEM_SEARCH_COUNT_CAP` (10 000). `count_capped` avisa si hay más.
- Tiempo máximo: `SIEM_SEARCH_TIMEOUT_MS` (5000), aplicado con `statement_timeout` local a la transacción. Si se supera, PostgreSQL cancela la consulta (SQLSTATE 57014) y la API responde 503 `siem_search_timeout`. El límite no se queda en la conexión.

Búsquedas guardadas: `GET/POST /siem/searches` y `DELETE /siem/searches/{id}`. Son privadas de su autor (como mucho 50); la de otra cuenta responde 404. Se guarda el filtro validado, nunca SQL.

## Investigación

- `GET /siem/events/{id}/related` devuelve:
  - los eventos enlazados en los dos sentidos;
  - las detecciones de los activos candidatos (sin contar los que solo coinciden por nombre) en ±30 min, marcadas `topic` (misma técnica o tema) o `time_only` (solo contexto).
- `GET /siem/timeline?asset_id&since&until`: eventos SIEM atribuidos al activo y sus detecciones, ordenados. Como mucho 500, con aviso `truncated`.
- `POST /siem/events/export`: paquete `sentra-siem-evidence/1` con los eventos completos, el `evidence_hash` de cada registro original y `events_sha256`, que es el SHA-256 del JSON canónico de `events` (claves ordenadas, sin espacios). Como mucho `SIEM_EXPORT_MAX_EVENTS` (500). Queda auditado (`siem_evidence_exported`, con el hash).
- `POST /siem/events/{id}/incidents/{incident_id}` (siem:evidence + incidents:manage): añade el evento a un caso. Guarda una copia normalizada, su SHA-256 y una nota opcional. Es idempotente y anota la actividad del caso. La copia **sobrevive a la retención** de eventos SIEM (`event_id` pasa a NULL y `available` a false). `GET /siem/incidents/{id}/events` exige siem:evidence + incidents:read.
- `POST /ai/siem/events/{id}/analyze` (ai:use + siem:evidence): resumen con la IA local.
  - Es de solo lectura: no cambia el evento, su severidad ni su atribución.
  - El texto del evento viaja como dato, nunca como instrucción. Usuario, equipo e IPs se seudonimizan como en el resto de la IA.
  - Quien no tenga siem:evidence no puede leer el insight, ni en caché ni en el listado.

En la UI, la pestaña **SIEM → Búsqueda** ofrece:

- filtros y búsquedas guardadas;
- "Cargar más" para paginar;
- exportar lo mostrado como evidencia.

El detalle de un evento añade los relacionados, la línea de tiempo del activo (±1 h), la opción de añadirlo a un caso, la exportación y el resumen con IA.

## Pruebas adversariales (tests/test_siem_7f6_hunting.py)

- CIDR /0 y /7, IP inválida, cursor manipulado (también con comillas SQL), `limit` excesivo, técnica con comillas, NUL en el nombre y campos desconocidos: todo da 422.
- Ventana de 60 días o sin zona: 422.
- `%`, `_` y comillas en el texto se buscan literalmente.
- Una consulta lenta se cancela con 503, y la siguiente búsqueda funciona en la misma conexión.
- Un viewer no busca ni lee evidencia SIEM de un caso.
- Mismo minuto con extremos distintos: no se crea ningún enlace.
- Texto hostil ("IGNORE PREVIOUS INSTRUCTIONS") llega a la IA solo como dato.

## Limitaciones

- La correlación se calcula al ingerir. Un evento que llega tarde enlaza con los anteriores, y los anteriores lo ven como enlace entrante en "Relacionados".
- `hostname` busca por igualdad: "web01" no encuentra "web01.corp.local".
- Rendimiento medido en la nube con datos sintéticos (docs/fase-7f.md, sección Rendimiento); sin medir en el hardware de producción.
