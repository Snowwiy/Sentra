# Fase 7F: arquitectura

## Flujo

```
Emisor Syslog ──TCP/TLS/UDP──► Sensor 0.9.0 ([siem]) ──┐
Ficheros EVE / Zeek / Wazuh ──► lector con offsets ────┤ spool siem-spool.sqlite3
                                                       ▼
                                   POST /api/v1/sensor/siem/batches (credencial del sensor)
Importación manual ──► POST /siem/sources/{id}/import ─┤
                                                       ▼
          app/siem/ingest.py: fuente habilitada, cuota, lote idempotente (siem_batches)
                                                       ▼
          app/siem/normalizers/*: registro → contrato sentra.siem.event v1
                                                       ▼
          deduplicación (fuente, dedup_key) → siem_events (+ hash SHA-256 del original)
                                                       ▼
          analizadores (app/siem/analysis.py), en orden:
            identity.py    atribución conservadora a activos
            correlation.py enlaces explicados (siem_event_links)
            signals.py     señal SIEM-EXT-001 / probable_match → motor de detección 4H
                                                       ▼
          detecciones, riesgo, alertas e incidentes (motor existente)

Consola: SIEM (fuentes, eventos, búsqueda, investigación) y Live SOC (SSE, app/live/stream.py)
```

El backend nunca abre puertos de recepción: Syslog y ficheros llegan siempre por un sensor
registrado (Fase 5F), con su credencial y su spool. Así un fallo o una inundación del emisor
se queda en el sensor y el servidor solo ve lotes acotados.

## Componentes nuevos

| Ruta | Papel |
| --- | --- |
| `backend/app/siem/catalog.py` | Conectores conocidos (tipo, versión, transportes) |
| `backend/app/siem/contract.py`, `fields.py` | Contrato normalizado y saneado de campos |
| `backend/app/siem/ingest.py`, `service.py` | Pipeline, fuentes, importación, eventos |
| `backend/app/siem/normalizers/` | `sentra_json`, `syslog`, `suricata`, `zeek`, `wazuh` |
| `backend/app/siem/identity.py` | Atribución IP → activo; nombre de host solo como pista |
| `backend/app/siem/correlation.py` | Enlaces NDR, SIEM↔SIEM y detecciones |
| `backend/app/siem/signals.py` | Señales hacia el motor de detección, `probable_match` |
| `backend/app/siem/investigation.py` | Hunting, relacionados, línea de tiempo, exportación, casos |
| `backend/app/siem/retention.py`, `status.py` | Purga por edad y tope; salud de fuentes |
| `backend/app/live/stream.py`, `api/v1/routes/live.py` | Live SOC |
| `sensor/sentra_sensor/siem/` | Receptor Syslog, lector de ficheros, spool |
| `frontend/src/pages/SiemPage.tsx`, `components/siem/`, `pages/LiveSocPage.tsx`, `lib/liveStream.ts` | UI |

## Tablas

| Tabla | Migración | Contenido |
| --- | --- | --- |
| `siem_sources` | 0057 | Fuente por site: tipo, transporte, sensor, habilitada, cuota, retención, salud |
| `siem_batches` | 0057 | Recibo idempotente de cada lote |
| `siem_events` | 0057 | Evento normalizado, procedencia, atribución, hash del original, extracto acotado |
| `siem_event_links` | 0058 | Enlace con método, confianza y explicación |
| `siem_saved_searches` | 0059 | Filtro tipado guardado, privado del autor |
| `incident_siem_events` | 0059 | Copia normalizada de un evento añadida a un caso, con SHA-256 |

## Decisiones

- **Sin Docker, Redis ni colas externas.** El backpressure es el spool del sensor más el 429.
  El Live SOC lee PostgreSQL con cursores por id.
- **Sin lenguaje de consulta.** El hunting es un filtro tipado que se traduce a condiciones
  fijas de SQLAlchemy: no hay superficie de inyección.
- **Sin doble conteo.** La correlación añade enlaces; solo SIEM-EXT-001 crea detecciones, y
  comparte clave causal con NET-NDR-001 cuando describen lo mismo.
- **Wazuh solo por fichero.** La API de Wazuh necesitaría guardar credenciales en Sentra
  (diseño de seguridad crítico): queda pendiente de una decisión de Jesus.
