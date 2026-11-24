# Fase 7E: catálogo de detecciones NDR

Las reglas viven en `backend/app/ndr/rules.py` y se exponen en `GET /api/v1/ndr/rules`
(pestaña "Reglas" de la página NDR). Los identificadores `NDR-*` son estables y no
coinciden con el catálogo de detecciones del host (`NET-*`, `WIN-*`, `LIN-*`...). Cambiar los
umbrales de una regla sube su `version`.

## Veredictos

| Veredicto | Significado |
| --- | --- |
| `observed` | Hecho sin juicio (un resolvedor distinto, un servicio en claro, un barrido autorizado) |
| `suspicious` | Patrón compatible con un ataque, con explicación benigna plausible |
| `probable` | Varios umbrales o indicios a la vez; requiere revisión prioritaria |
| `confirmed` | Indicios independientes suficientes; hoy solo NDR-MITM-001 |

El veredicto y la severidad de una anomalía activa solo suben. A partir de `suspicious` cada
subida genera una señal para la detección NET-NDR-001.

## Reglas

| Regla | Categoría | Veredictos | MITRE |
| --- | --- | --- | --- |
| NDR-ARP-001 Cambio de la MAC asociada a una IP | arp | suspicious: la IP pasó a otra MAC con la anterior activa. probable: las dos MAC alternan en la misma ventana | TA0006 T1557.002 |
| NDR-ARP-002 Una MAC anuncia varias IP con respuestas ARP no solicitadas | arp | suspicious: 3 o más IP. probable: además 10 o más respuestas no solicitadas | TA0006 T1557.002 |
| NDR-ARP-003 MAC de trama distinta de la del mensaje ARP | arp | suspicious | TA0006 T1557.002 |
| NDR-MITM-001 Suplantación ARP de la puerta de enlace | mitm | probable: MAC nueva para la IP de la puerta de enlace con la anterior activa. confirmed: además la MAC nueva anuncia otras IP sin petición y la original sigue respondiendo en la misma ventana | TA0006 T1557.002 |
| NDR-DNS-001 Ráfaga de NXDOMAIN | dns | suspicious: 20 o más nombres y al menos la mitad de las respuestas. probable: 50 o más de 10 o más dominios padre | TA0011 T1568.002 |
| NDR-DNS-002 Indicios de túnel DNS | dns | suspicious: 30 o más subdominios largos o de alta entropía, o 20 TXT/NULL. probable: ambas a la vez | TA0011 T1071.004 |
| NDR-DNS-003 Resolvedor distinto del anunciado por DHCP | dns | observed | sin técnica |
| NDR-DHCP-001 Servidor DHCP no habitual | dhcp | suspicious: servidor nuevo con uno establecido. probable: además entrega otra puerta de enlace o DNS | TA0006 T1557.003 |
| NDR-SCAN-001 Barrido de puertos o equipos | scan | observed: coincide con un discovery de Sentra. suspicious: 50 o más destinos sin saludo TCP. probable: 200 o más | TA0007 T1046 |
| NDR-PROTO-001 Protocolo de administración en claro | protocol | observed: el servidor respondió en Telnet, FTP o TFTP | sin técnica |
| NDR-PROTO-002 Sesiones de administración contra muchos equipos | lateral | suspicious: 5 o más equipos internos en el mismo servicio. probable: 15 o más | TA0008 T1021 |
| NDR-BEH-001 Volumen de salida muy superior a lo habitual | behavior | suspicious: media + 4 desviaciones y más de 50 MB en la hora. probable: media + 8 y más de 500 MB | TA0010 T1048 |
| NDR-BEH-002 Número de destinos muy superior a lo habitual | behavior | suspicious: media + 4 desviaciones y 50 o más destinos | TA0007 T1046 |
| NDR-BEH-003 Conexiones periódicas a un destino externo | behavior | suspicious: 12 o más conexiones en 6 h con variación de intervalos inferior al 15 % | TA0011 T1071 |
| NDR-TI-001 Tráfico con un indicador de Threat Intelligence | threat_intel | suspicious: indicador activo (o red cidr). probable: malicious, confianza alta, fuente oficial o de confianza, valor exacto | sin técnica |

Las reglas de higiene (PROTO-001, DNS-003) y de contexto externo (TI-001) no llevan técnica
MITRE: asignarles una sería inventar intención.

## Notas por regla

- Un flujo TCP sin respuesta o con RST no cuenta como sesión establecida (evita falsos
  positivos de movimiento lateral durante un barrido).
- Interno y externo se deciden con rangos explícitos (`app/ndr/addresses.py`): RFC 1918,
  ULA, enlace local e IPv4 mapeada son internas; los rangos de documentación cuentan como
  externos.
- BEH-001 y BEH-002 usan una línea base por IP y métrica sobre valores horarios (Welford) y no alertan
  hasta tener `NDR_BASELINE_MIN_SAMPLES` muestras.
- TI-001 comprueba IPs remotas de flujos interno-externo, nombres DNS consultados y SNI
  (incluidos los dominios padre) contra los indicadores activos de la Fase 5C. Los destinos
  internos nunca se consultan.

## Integración con el motor de detección

- NET-NDR-001 (categoría `network`) convierte cada anomalía `suspicious` o superior en una
  detección con la técnica MITRE de la regla NDR, deduplicada por anomalía.
- Logsource `ndr_anomaly` para reglas propias (campos `ndr.rule_id`, `ndr.category`,
  `ndr.verdict`, `ndr.severity`, `ndr.subject_ip`, `ndr.subject_mac`).
- Logsource `ndr_dns` (parcial) para reglas propias y Sigma `category: dns`: `query`,
  `record_type`, `src_ip` y `dst_ip` se traducen a `dns.query`, `dns.query_type`,
  `dns.client_ip` y `dns.resolver_ip`. Solo se guardan señales DNS si hay al menos una regla
  activa de este logsource, y solo de equipos inventariados.

## Respuesta sugerida por regla

| Regla | Sugerencia |
| --- | --- |
| Veredicto `observed` | Revisar y documentar; PROTO-001 además restringir el puerto en claro entrante |
| ARP-*, MITM-001, DHCP-001 | Paso manual: localizar y aislar el puerto del switch, DAI y DHCP snooping |
| SCAN-001, PROTO-002 | Paso manual: contener el equipo de origen |
| BEH-001 | Paso manual: revisar destinos del volumen enviado |
| BEH-003 | Bloquear la salida hacia la IP externa (/32 o /128) |
| DNS-002 | Bloquear la resolución del dominio padre |
| DNS-003 | Bloquear la salida hacia el resolvedor externo |
| TI-001 | Bloquear la IP, la red o el dominio del indicador |
| Con activo atribuido y veredicto distinto de `observed` | Playbook `investigate_network_anomaly` |
