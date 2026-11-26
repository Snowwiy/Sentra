# Fase 7F: integración SIEM y Live SOC

Sentra recibe telemetría de fuentes externas autorizadas (Syslog, Suricata, Zeek, Wazuh y
JSON propio), la normaliza a un contrato único, la relaciona con su propia evidencia sin
inventar causalidad, permite buscarla e investigarla, y muestra en directo lo que entra.
Sentra sigue siendo el núcleo: las integraciones son opcionales y están apagadas por defecto.

Versiones: servidor y frontend 0.9.0, sensor 0.9.0, agente 0.7.1 sin cambios. Migraciones
0057 a 0059 (cabeza 0059, siguiente libre 0060).

Documentos:

- [fase-7f-architecture.md](fase-7f-architecture.md): componentes, flujo y tablas.
- [fase-7f-security.md](fase-7f-security.md): amenazas, permisos y privacidad.
- [fase-7f-syslog.md](fase-7f-syslog.md), [fase-7f-suricata.md](fase-7f-suricata.md),
  [fase-7f-zeek.md](fase-7f-zeek.md), [fase-7f-wazuh.md](fase-7f-wazuh.md): conectores.
- [fase-7f-correlation.md](fase-7f-correlation.md): correlación, hunting e investigación.
- [fase-7f-live-soc.md](fase-7f-live-soc.md): stream SSE y página Live SOC.
- [fase-7f-migrations.md](fase-7f-migrations.md): migraciones y vuelta atrás.
- [fase-7f-windows-qa.md](fase-7f-windows-qa.md): pruebas manuales pendientes.
- [fase-7f-known-issues.md](fase-7f-known-issues.md): limitaciones conocidas.

## Subfases

| Subfase | Qué añade |
| --- | --- |
| 7F.1 | Catálogo de conectores, fuentes por site (deshabilitadas por defecto, `siem:manage`), contrato `sentra.siem.event` v1, pipeline de ingesta con lotes idempotentes, deduplicación, cuotas (429 con `Retry-After`), retención y tope de almacenamiento, importación manual, página SIEM |
| 7F.2 | Receptor Syslog en el sensor: TCP, TLS y UDP (opt-in), lista de pares, RFC 5424 y 3164, spool propio. El backend no abre puertos |
| 7F.3 | Lector de ficheros EVE de Suricata en el sensor (offsets, rotación, sin payloads), conector `suricata_eve`, enlaces con flujos y anomalías NDR, señal SIEM-EXT-001 sin doble conteo con NET-NDR-001 |
| 7F.4 | Conector `zeek_json` (conn, dns, http, ssl, notice, weird...) con el mismo lector de ficheros |
| 7F.5 | Conector `wazuh_alerts` de solo lectura: campos de la alerta, MITRE, severidad solo con política explícita, el nombre del agente es una pista y no identidad, `probable_match` con detecciones nativas, procedencia en la UI |
| 7F.6 | Correlación entre fuentes (enlaces con método, confianza y explicación), hunting tipado con paginación, límites y timeout, búsquedas guardadas, relacionados, línea de tiempo, exportación con hashes, añadir a un caso, resumen con IA local de solo lectura |
| 7F.7 | Stream SSE `/api/v1/live/stream` y página Live SOC |

## Puesta en marcha

1. Aplicar los parches y migrar una base de pruebas propia (docs/fase-7f-migrations.md).
2. Como admin, en SIEM → Fuentes, registrar una fuente (tipo, site, transporte, sensor si
   aplica) y habilitarla. Sin fuente habilitada, el servidor rechaza todo lote.
3. Para Syslog o ficheros, configurar `[siem]` en el sensor 0.9.0 (sensor.example.toml).
   Para una prueba sin sensor, usar "Importar" en la fuente.
4. Abrir SIEM → Búsqueda y Live SOC.

## Permisos

| Permiso | Roles | Uso |
| --- | --- | --- |
| `siem:read` | viewer, analyst, admin | Catálogo, fuentes, salud y agregados |
| `siem:evidence` | analyst, admin | Eventos normalizados, búsqueda, exportación, relacionados, canal `siem` del Live SOC |
| `siem:manage` | admin | Registrar, cambiar, habilitar y borrar fuentes; importar |

## Endpoints

Ver docs/api-reference.md (sección Fase 7F).

## Rendimiento (nube, datos sintéticos)

`qa/perf_siem.py` contra PostgreSQL 16 en un contenedor Linux de la nube, 20 000 eventos EVE
sintéticos (10 % alertas), 20 repeticiones por consulta. **No es hardware de producción**.

| Medida | Resultado |
| --- | --- |
| Ingesta completa (normalización, deduplicación, atribución, correlación, señales) | 269 eventos/s; lote de 1000: p50 3,8 s, p95 4,4 s |
| Búsqueda, ventana 24 h, página de 50 | p50 6,0 ms, p95 7,3 ms |
| Búsqueda con recuento | p50 11,3 ms, p95 14,0 ms |
| Solo alertas | p50 8,9 ms, p95 9,4 ms |
| IP exacta | p50 19,7 ms, p95 25,3 ms |
| CIDR /16 | p50 7,6 ms, p95 8,5 ms |
| Puerto | p50 7,6 ms, p95 9,8 ms |
| Texto en el mensaje | p50 10,8 ms, p95 15,0 ms |
| Consulta del Live SOC desde el presente | p50 5,9 ms, p95 7,6 ms |
| Consulta del Live SOC con atraso | p50 12,3 ms, p95 13,7 ms |

La ingesta es el cuello de botella: cada lote correlaciona y genera señales dentro de la misma
transacción. Para fuentes ruidosas, el sensor hace backpressure con su spool (429 con
`Retry-After`), no se pierde nada en silencio.
