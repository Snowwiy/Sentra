# Fase 7E: arquitectura de NDR

## Flujo de datos

```
interfaz (SPAN/TAP/segmento)
  -> sensor 0.8.0: backend de captura -> decodificador -> tabla de flujos + metadatos
  -> spool NDR propio (ndr-spool.sqlite3) -> POST /api/v1/sensor/ndr/batches
  -> servidor: NdrIngest (validación, cuotas, interfaz aprobada)
       -> ndr_flows, ndr_protocol_observations, ndr_ip_mac_bindings, ndr_batches
       -> analizadores en la misma transacción (ndr_analyzers):
            analyze_l2, analyze_dns, analyze_flows, analyze_ti, record_rule_signals
       -> record_finding -> ndr_anomalies (+ activo atribuido + señal NDR_ANOMALY)
  -> job ndr-engine (cada NDR_ENGINE_INTERVAL_SECONDS):
       líneas base horarias (ndr_baselines, cursor ndr_engine_cursors) y beaconing
  -> motor de detección (4H): NET-NDR-001 y reglas propias/Sigma de ndr_anomaly y ndr_dns
       -> detecciones -> riesgo, alertas, incidentes
  -> API /api/v1/ndr/* -> página "Red (NDR)"
```

## Sensor (`sensor/sentra_sensor/ndr/`)

Solo biblioteca estándar.

| Módulo | Responsabilidad |
| --- | --- |
| `config.py` | Sección `[ndr]` local (alias y dispositivos) y validación de lo que aprueba el servidor |
| `capture.py` | Backends: `af_packet` (Linux), libpcap/Npcap por ctypes, `pcap_file` (pruebas y `ndr-replay`) |
| `decode.py` | Ethernet, VLAN, IPv4/IPv6, TCP/UDP/ICMP, ARP, DHCP, DNS y ClientHello TLS (SNI), con límites de longitud |
| `flows.py` | Tabla de flujos bidireccionales con tiempos de inactividad y activo, banderas y segmentos |
| `pipeline.py` | Ventanas de exportación, límites de CPU y paquetes por segundo, lotes y spool |
| `tools.py` | `ndr-check` (backend e interfaces, sin red) y `ndr-replay` (pcap clásico, no envía nada) |

El sensor no guarda payload: de DNS solo el nombre, tipo, rcode y respuestas; de TLS solo el
SNI. Sin `[ndr] enabled = true` no declara la capacidad ni abre ningún dispositivo.

## Servidor (`backend/app/ndr/`)

| Módulo | Responsabilidad |
| --- | --- |
| `config.py` | Configuración de captura por sensor (revisión, concurrencia optimista) |
| `ingest.py` | Validación del lote, cuota por sensor, idempotencia por `(sensor, batch_id)` (un reenvío devuelve `duplicate=true`), inserción en bloque |
| `analysis.py` | Lista ordenada de analizadores que corren en la transacción del lote |
| `detect_l2.py` | ARP-001/002/003, MITM-001, DHCP-001 y asociaciones IP-MAC |
| `detect_dns.py` | DNS-001/002/003 |
| `detect_net.py` | SCAN-001, PROTO-001, PROTO-002 |
| `engine.py` | Job `ndr-engine`: BEH-001/002 (líneas base) y BEH-003 (beaconing) |
| `detect_ti.py` | NDR-TI-001 con la misma consulta de indicadores activos de la Fase 5C |
| `rule_signals.py` | Señales `ndr_dns` solo si hay reglas activas de ese logsource |
| `anomalies.py` | `record_finding`: deduplicación, escalado de veredicto y severidad, atribución y señal |
| `addresses.py` | Clasificación interna/externa explícita (RFC 1918, ULA, enlace local) |
| `anomaly_service.py` | Lectura, contexto de correlación, triaje, plan de respuesta y solicitudes de control |
| `response.py` | Sugerencias de respuesta por regla (función pura de la anomalía) |
| `retention.py` | Purga por días de flujos, metadatos, lotes, anomalías cerradas, asociaciones y líneas base |

## Tablas

| Tabla | Migración | Contenido |
| --- | --- | --- |
| `ndr_capture_configs` | 0053 | Configuración aprobada por sensor (alias, límites, metadatos activados, revisión) |
| `ndr_batches` | 0053 | Registro de lotes recibidos (idempotencia y estadísticas) |
| `ndr_flows` | 0053 | Flujos (sin payload) |
| `ndr_protocol_observations` | 0053 | Metadatos ARP/DHCP/DNS/TLS agregados por clave |
| `ndr_anomalies` | 0054, 0056 | Anomalías; índice único parcial sobre las activas por `(site_id, rule_id, dedup_key)`; `asset_id` y `signaled_rank` desde 0056 |
| `ndr_ip_mac_bindings` | 0054 | Asociaciones IP-MAC vistas por ARP y DHCP |
| `ndr_baselines` | 0055 | Media y varianza (Welford) por IP y métrica sobre valores horarios |
| `ndr_engine_cursors` | 0055 | Última hora agregada por site |

## Veredicto y deduplicación

Cada hallazgo tiene una clave de deduplicación propia de la regla. Mientras la anomalía está
activa (`open` o `acknowledged`), un hallazgo con la misma clave actualiza la existente: suma
ocurrencias, amplía la evidencia acotada y solo sube veredicto y severidad, nunca los baja.
Cerrada, la siguiente ocurrencia abre una anomalía nueva.

## Correlación (7E.4)

- Activo: por MAC primero, después por IP principal, en el mismo site, no archivado; si hay
  varios gana el más reciente. Se fija la primera vez y no se recalcula.
- Señal `NDR_ANOMALY` (`source_type = "ndr"`) una vez por cada subida de veredicto a partir
  de `suspicious` (`signaled_rank`). La regla integrada NET-NDR-001 la convierte en detección
  con clave `ndr:<anomaly_id>`, que alimenta riesgo, alertas e incidentes como cualquier otra.
- El contexto de lectura (puerto del switch por la tabla MAC de SNMP, detecciones e
  incidentes) se calcula al leer: no se duplica en la anomalía.

## Respuesta (7E.7)

- `GET /ndr/anomalies/{id}/response-plan`: sugerencias derivadas de la evidencia
  (`app/ndr/response.py`) e incidentes que ya incluyen su detección.
- `POST /ndr/anomalies/{id}/network-controls`: reutiliza
  `CaseOperationsService.request_control` (Fase 7A.6). Solo acepta una sugerencia del plan de
  tipo control; el alcance es el site de la anomalía y la justificación añade el origen.
- Acción `collect_ndr_context` (LOW, servidor, activo, solo lectura) y playbook integrado
  `investigate_network_anomaly`: contexto NDR, timeline, reevaluación de detecciones,
  recálculo de riesgo y resumen de evidencia.

## Sincronizar Dev de forma segura

La base es `main` en `46be5a2` (Dev `f8b68da` tiene el mismo árbol). Para llevar 7E a Dev:

1. `git fetch origin` y comprobar que `git diff origin/main origin/Dev --stat` está vacío.
2. Si lo está, aplicar los parches sobre Dev en orden con `git apply --check` antes de cada
   `git apply`. Si no lo está, aplicar sobre `main` en una rama propia y llevar a Dev con un
   merge revisado, nunca con push forzado.
3. Ejecutar las comprobaciones de CLAUDE.md y `alembic upgrade head` en una base de pruebas
   antes de publicar.
