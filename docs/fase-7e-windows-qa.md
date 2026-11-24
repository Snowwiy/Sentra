# Fase 7E: pruebas manuales en Windows y en red real

Nada de esto se ha ejecutado todavía: la Fase 7E se ha probado en la nube con Linux, tráfico
generado por los tests (protocolo real del sensor), ficheros pcap construidos en los tests y
dos capturas reales sobre loopback (AF_PACKET y libpcap). Ninguna captura se ha probado contra
una interfaz física, Npcap ni libpcap de macOS.

## 0. Preparación

1. Base de pruebas propia (no `sentra`): `alembic upgrade head` y `alembic current` = 0056.
2. Suites completas según CLAUDE.md (backend, sensor, agente, frontend con Node 22 y 24),
   incluidos `mypy app tests` y `mypy --platform win32 .` en el sensor.
3. Servidor y frontend 0.8.0 arrancados.

## 1. Sensor 0.8.0 en Windows con Npcap

1. Instalar Npcap (sin modo compatible con WinPcap). Sentra no lo instala.
2. `sentra-sensor ndr-check` sin `[ndr]`: el informe muestra `"enabled": false`.
3. Añadir `[ndr] enabled = true` y una interfaz con alias, copiando el dispositivo
   `\Device\NPF_{GUID}` de `available_devices`. Esperado: backend `libpcap` con `ok`, la
   interfaz `present` y `"ok": true`.
4. Desinstalar Npcap y repetir: esperado el error `npcap_missing`, sin excepciones.
5. Ejecutar el servicio con su cuenta de servicio y confirmar que puede abrir el dispositivo.

## 2. Aprobación y captura

1. En "Red (NDR)", como viewer: se ven sensores y anomalías, no "Aprobar captura" ni la
   pestaña de flujos.
2. Como admin: "Aprobar captura" exige alias, punto de observación y la confirmación;
   comprobar el evento de auditoría.
3. Tras un heartbeat, el sensor pasa a `capturing` y llegan lotes (Resumen: flujos, bytes,
   paquetes vistos y descartados).
4. Activar DNS y TLS: aparecen consultas y SNI en "Flujos y metadatos" (analyst).
5. Desaprobar: el sensor deja de capturar en el siguiente heartbeat.

## 3. Detecciones en un laboratorio aislado

Solo en una red de laboratorio propia, nunca en la red de producción:

- Barrido con `nmap -sS` de un /24 del laboratorio: NDR-SCAN-001 `suspicious` o `probable`;
  con un discovery de Sentra en marcha a la vez, `observed`.
- Sesiones SMB o RDP a varios equipos: NDR-PROTO-002.
- Telnet o FTP de prueba: NDR-PROTO-001 `observed` con su sugerencia.
- Consultas a dominios inexistentes en bucle: NDR-DNS-001.
- Un segundo servidor DHCP en el segmento: NDR-DHCP-001.
- Las pruebas de suplantación ARP (ARP-*, MITM-001) solo con herramientas propias del
  laboratorio y autorización expresa; Sentra no genera ese tráfico.

## 4. Correlación, TI y Sigma

1. Una anomalía de un equipo inventariado muestra el activo, el puerto del switch (si hay
   sondeo SNMP con tabla MAC) y la detección NET-NDR-001 enlazada.
2. Importar un IOC local con una IP de prueba controlada y conectarse a ella: NDR-TI-001.
3. Importar una regla Sigma `category: dns`, activarla y consultar el dominio: detección
   con la técnica de la regla.

## 5. Respuesta

1. En el detalle de una anomalía TI o de beaconing, "Respuesta sugerida" muestra el bloqueo
   con instrucciones.
2. Con un incidente que incluya la detección, "Registrar solicitud" crea un control
   `pending_approval` en el incidente; un admin lo aprueba y lo marca aplicado tras aplicarlo
   en el cortafuegos.
3. Ejecutar el playbook "Investigar anomalía de red" sobre el activo y revisar la evidencia
   de `collect_ndr_context`.

## 6. Rendimiento

Medir con tráfico real: CPU y memoria del sensor con el límite aprobado, paquetes
descartados, tamaño de `ndr_flows` por día y duración del job `ndr-engine`.
