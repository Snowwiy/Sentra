# Fase 7E: limitaciones conocidas

## Sin validar en plataforma real

- La captura no se ha probado contra ninguna interfaz física. En la nube (Linux) pasan dos
  capturas reales sobre loopback, con AF_PACKET y con libpcap por ctypes; Npcap en Windows y
  libpcap en macOS solo tienen tests con dobles, y el decodificador se prueba con tramas
  construidas en los tests. No se puede afirmar que la captura funcione en Windows, macOS ni
  en una interfaz física Linux hasta pasar [fase-7e-windows-qa.md](fase-7e-windows-qa.md).
- Rendimiento sin medir con tráfico real. El decodificador es Python puro: en enlaces muy
  cargados los límites de paquetes por segundo y CPU descartarán tramas (se cuentan y se
  muestran como descartados) antes que saturar el equipo.
- Las reglas ARP, MITM y DHCP se han probado con metadatos enviados por el protocolo real
  del sensor, no con un ataque real en un laboratorio.

## Alcance de la captura

- Enlaces Ethernet II con hasta dos etiquetas VLAN, loopback (DLT_NULL/LOOP), IP sin enlace
  (DLT_RAW) y Linux cooked (SLL). Wi-Fi en modo monitor (802.11/radiotap) no se decodifica.
  `ndr-replay` lee pcap clásico, no pcapng.
- Sin payload por diseño: no se reconstruyen sesiones ni ficheros, ni se inspecciona HTTP.
- DNS cifrado (DoH, DoT) y TLS con ECH no exponen nombres: esas consultas no aparecen en los
  metadatos y las reglas DNS no las ven.
- El sensor ve lo que llega a su interfaz: sin puerto SPAN o TAP solo observa su propio
  tráfico y difusiones del segmento.
- La aprobación del punto de observación es declarativa: Sentra no puede comprobar que la
  captura esté autorizada en ese segmento; lo afirma el admin y queda auditado.

## Detecciones

- Las líneas base de comportamiento son una sola media por IP y métrica sobre valores
  horarios, sin estacionalidad diaria ni semanal: un equipo con picos nocturnos legítimos
  puede generar `suspicious` hasta que la media los absorba.
- Interno y externo se decide por rangos fijos; redes públicas usadas internamente se tratan
  como externas.
- El activo de una anomalía se atribuye una vez (MAC, luego IP); si el activo se crea después,
  las anomalías ya abiertas no se reatribuyen.
- Las señales `ndr_dns` solo se guardan para equipos inventariados y si hay alguna regla
  activa de ese logsource. Sigma `category: dns` es soporte parcial (cuatro campos).
- NDR-TI-001 consulta los indicadores importados localmente; sin sincronización de fuentes
  externas solo detecta lo que el analista importe.

## Respuesta

- Sentra no integra cortafuegos, DNS, proxies ni switches: los controles se registran y se
  aplican a mano fuera de Sentra.
- La solicitud se registra en un incidente que ya incluya la detección de la anomalía; si no
  hay ninguno, hay que abrirlo antes (desde la detección NET-NDR-001 o desde Respuesta).
- El playbook `investigate_network_anomaly` necesita un activo atribuido.

## Fuera de alcance

- El `ValueConstraintError` de SNMP conocido no se trata en esta fase.
- Sin aislamiento automático, sin cuarentena de VLAN automática ni bloqueos automáticos.
