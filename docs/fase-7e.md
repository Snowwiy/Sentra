# Fase 7E: Network Detection & Response (NDR)

Sentra observa la red de cada site con sus sensores distribuidos, de forma pasiva y solo
cuando un admin lo aprueba, y convierte lo observado en anomalías con veredicto, correlación
con el inventario, inteligencia de amenazas, MITRE ATT&CK y un plan de respuesta que nunca
toca la red por sí mismo.

Versiones: servidor y frontend 0.8.0, sensor 0.8.0, agente 0.7.1 sin cambios. Migraciones
0053 a 0056 (cabeza 0056). Documentos relacionados:

- [fase-7e-architecture.md](fase-7e-architecture.md): componentes, flujo de datos y tablas.
- [fase-7e-security.md](fase-7e-security.md): modelo de amenazas, permisos y privacidad.
- [fase-7e-ndr-detections.md](fase-7e-ndr-detections.md): catálogo de reglas y veredictos.
- [fase-7e-migrations.md](fase-7e-migrations.md): migraciones y vuelta atrás.
- [fase-7e-windows-qa.md](fase-7e-windows-qa.md): pruebas manuales en Windows y en red real.
- [fase-7e-known-issues.md](fase-7e-known-issues.md): limitaciones conocidas.

## Subfases

| Subfase | Qué añade |
| --- | --- |
| 7E.1 | Captura pasiva en el sensor (AF_PACKET, Npcap, libpcap), flujos y metadatos ARP/DHCP/DNS/TLS, lotes por `POST /sensor/ndr/batches`, aprobación por sensor, retención, permisos NDR |
| 7E.2 | Anomalías con veredicto: ARP, suplantación de la puerta de enlace, DHCP no habitual, ráfagas NXDOMAIN, túnel DNS, resolvedor no anunciado; asociaciones IP-MAC |
| 7E.3 | Barridos, protocolos en claro, movimiento lateral, líneas base horarias por IP y beaconing (job `ndr-engine`) |
| 7E.4 | Atribución a activos (MAC, luego IP), puerto del switch por la tabla MAC de SNMP, detección NET-NDR-001 que alimenta riesgo, alertas e incidentes |
| 7E.5 | Indicadores de Threat Intelligence sobre flujos, DNS y SNI (NDR-TI-001); MITRE por regla; logsources `ndr_anomaly` y `ndr_dns` para reglas propias y Sigma `category: dns` |
| 7E.6 | Página "Red (NDR)": resumen, sensores, aprobación de captura, anomalías con correlación y triaje, evidencia y catálogo de reglas |
| 7E.7 | Plan de respuesta por anomalía, solicitudes de control de red registradas en un incidente, acción `collect_ndr_context` y playbook `investigate_network_anomaly` |

## Puesta en marcha

1. Aplicar las migraciones: `alembic upgrade head` (0056).
2. Actualizar el sensor a 0.8.0 en el equipo que ve el tráfico (puerto SPAN, TAP o el propio
   segmento). Comprobar el backend de captura con `sentra-sensor ndr-check`.
   - Linux: instalar el drop-in `sensor/packaging/linux/sentra-sensor-ndr.conf`
     (CAP_NET_RAW, sin CAP_NET_ADMIN).
   - Windows: Npcap instalado por el operador (Sentra no lo instala ni lo distribuye).
   - macOS: libpcap del sistema con acceso a `/dev/bpf*`.
3. Declarar las interfaces en `[ndr]` de `sensor.toml` con un alias (el servidor nunca recibe
   nombres de dispositivo, solo alias).
4. En "Red (NDR)", un admin pulsa "Aprobar captura", elige los alias, describe el punto de
   observación y confirma que la captura es pasiva y está autorizada. DNS y TLS (SNI) van
   apagados por defecto: activarlos es una decisión de privacidad.
5. El sensor recoge la configuración en su siguiente heartbeat, captura y envía lotes.

Sin aprobación no se captura nada. Hay doble control: el operador del host decide qué
dispositivos pueden observarse (`[ndr] enabled = true` y sus alias) y el admin decide qué alias
se capturan. Un alias aprobado que el host no declaró se ignora, y el servidor rechaza
(`NdrNotAuthorizedError`) lotes de una interfaz que no tiene aprobada.

## Ajustes del servidor (opcionales)

| Variable | Defecto | Uso |
| --- | --- | --- |
| `NDR_INGEST_MAX_PER_MINUTE` | 120 | Lotes por sensor y minuto (429 con `Retry-After`) |
| `NDR_MAX_RECORDS_PER_BATCH` | 1000 | Registros por lote que se ordenan y aceptan |
| `NDR_FLOW_RETENTION_DAYS` | 7 | Días de flujos |
| `NDR_OBSERVATION_RETENTION_DAYS` | 30 | Días de metadatos ARP/DHCP/DNS/TLS |
| `NDR_BATCH_RETENTION_DAYS` | 7 | Días del registro de lotes |
| `NDR_ANOMALY_RETENTION_DAYS` | 180 | Días de anomalías cerradas (las activas no se purgan) |
| `NDR_BINDING_RETENTION_DAYS` | 30 | Días de asociaciones IP-MAC sin actividad |
| `NDR_ENGINE_INTERVAL_SECONDS` | 300 | Periodo del job `ndr-engine` (0 lo desactiva) |
| `NDR_BASELINE_MIN_SAMPLES` | 24 | Horas aprendidas antes de que una línea base pueda alertar |

Todas están fijadas en `backend/tests/conftest.py` para que los tests no dependan del `.env`.

## Permisos

| Permiso | Roles | Qué permite |
| --- | --- | --- |
| `ndr:read` | viewer, analyst, admin | Estado de sensores, agregados, anomalías, reglas y plan de respuesta |
| `ndr:evidence` | analyst, admin | Flujos y metadatos individuales; acción `collect_ndr_context` |
| `ndr:triage` | analyst, admin | Reconocer, resolver o marcar falso positivo (cerrar exige nota) |
| `ndr:manage` | admin | Aprobar o cambiar la captura de un sensor |

Registrar una solicitud de control desde una anomalía exige además `incidents:manage`, y
aprobarla `network_controls:approve` (admin), igual que en la Fase 7A.6.

## API (`/api/v1`)

| Método y ruta | Permiso |
| --- | --- |
| `POST /sensor/ndr/batches` | Credencial propia del sensor (el servidor guarda solo su SHA-256) |
| `GET /ndr/overview` | `ndr:read` |
| `GET /ndr/sensors` | `ndr:read` |
| `PUT /ndr/sensors/{sensor_id}/config` | `ndr:manage` |
| `GET /ndr/flows`, `GET /ndr/observations`, `GET /ndr/bindings` | `ndr:evidence` |
| `GET /ndr/rules` | `ndr:read` |
| `GET /ndr/anomalies`, `GET /ndr/anomalies/{id}` | `ndr:read` |
| `POST /ndr/anomalies/{id}/status` | `ndr:triage` |
| `GET /ndr/anomalies/{id}/response-plan` | `ndr:read` |
| `POST /ndr/anomalies/{id}/network-controls` | `ndr:read` + `incidents:manage` |

## Respuesta (7E.7)

El plan de respuesta de una anomalía se deriva de su evidencia con reglas fijas por regla
NDR. Hay tres tipos de sugerencia:

- Solicitud de control: un `block_address`, `block_domain` o `block_port` ya validado con las
  reglas de la Fase 7A.6 (prefijos mínimos, dominios completos, sentido). Se registra en un
  incidente como `pending_approval`; un admin la aprueba o rechaza y alguien la aplica fuera
  de Sentra con las instrucciones. Sentra no integra cortafuegos, DNS ni switches.
- Paso manual: lo que solo puede hacer una persona (aislar un puerto del switch, activar
  DHCP snooping, confirmar un escáner autorizado).
- Playbook: `investigate_network_anomaly` (solo lectura y reevaluaciones) sobre el activo
  atribuido.

Una anomalía `observed` solo sugiere revisar. Nunca se sugiere bloquear una IP interna.
