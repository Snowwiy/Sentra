# Fase 7F: seguridad

## Modelo de amenazas

| Amenaza | Control |
| --- | --- |
| Emisor no autorizado envía Syslog | Receptor apagado por defecto; lista de pares obligatoria; TLS recomendado; UDP solo opt-in explícito |
| Inundación de eventos | Cuota por fuente (429 `siem_quota`), lotes por sensor y minuto, tamaño máximo por registro y por lote, spool acotado en el sensor |
| Registro hostil (inyección en logs, HTML, instrucciones a la IA) | Campos saneados y acotados; la UI pinta texto; la IA recibe el evento como dato seudonimizado y no puede cambiarlo |
| Inyección SQL en el hunting | Filtro tipado; cursor validado; `%` y `_` literales; sin SQL del usuario |
| Consulta que bloquea la base | `statement_timeout` local a la transacción, ventana máxima, tope del recuento, `limit` máximo 200 |
| Falsa atribución a un activo | IP solo si un único activo no archivado del site la tiene; el nombre de host es pista, nunca identidad; nunca se crean activos |
| Causalidad inventada | Una coincidencia solo de tiempo nunca crea un enlace; cada enlace explica su método y su confianza |
| Duplicar incidentes con Wazuh | `probable_match` enlaza con la detección nativa y no genera otra |
| Severidad impuesta por la fuente | Severidad de Wazuh solo con política explícita de la fuente |
| Fuga de datos por el Live SOC | Canales decididos en el servidor por permisos actuales; solo campos de catálogo; JSON en una línea `data:`; revalidación periódica; sin alargar la sesión |
| Manipulación de la evidencia | Hash SHA-256 del registro original; exportación con `events_sha256`; copia en el caso con su hash; auditoría |

## Privacidad

- No se guardan payloads de red: el lector EVE descarta `payload`, `packet` y similares.
- Del registro original se guarda un extracto acotado (`SIEM_RAW_STORE_BYTES`) y siempre el
  hash del registro completo.
- Retención por fuente y global, y tope de almacenamiento (`SIEM_MAX_STORED_EVENTS`).
- Los eventos son evidencia (`siem:evidence`): un viewer ve salud y agregados, no contenido.

## Auditoría

Altas, cambios y borrados de fuentes, importaciones, exportaciones de evidencia (con hash) y
eventos añadidos a casos quedan en el registro de auditoría.

## Lo que no hace

- No ejecuta acciones sobre activos ni sobre la red a partir de eventos externos.
- No guarda credenciales de Wazuh, Elastic ni otros SIEM.
- El servidor no abre puertos de recepción.
