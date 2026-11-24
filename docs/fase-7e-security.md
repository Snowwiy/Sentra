# Fase 7E: seguridad y privacidad de NDR

## Principios

- Captura estrictamente pasiva. Ningún backend abre un socket de envío ni llama a
  `pcap_inject` o `pcap_sendpacket`. No hay envenenamiento ARP, suplantación DNS,
  descifrado TLS ni inyección de ningún tipo.
- Apagada por defecto y con doble control. El operador del host declara qué dispositivos
  pueden observarse y un admin (`ndr:manage`) aprueba qué alias se capturan, escribiendo el
  punto de observación y confirmando expresamente que la captura es pasiva y está autorizada
  en ese segmento. Cada cambio queda auditado con su revisión.
- Sin payload. El sensor guarda cabeceras y contadores de flujo; de DNS el nombre, tipo,
  rcode y respuestas; de TLS el SNI del ClientHello. No se guardan cuerpos, cookies,
  certificados de cliente ni credenciales. Los protocolos en claro (Telnet, FTP, TFTP) se
  detectan por puerto y respuesta, sin leer lo que transportan.
- DNS y SNI son opcionales y vienen apagados: revelan con quién habla cada equipo.
- Ninguna acción automática sobre la red. Las solicitudes de control se registran en un
  incidente, las aprueba un admin y se aplican fuera de Sentra.

## Permisos separados de `monitoring:read`

Los flujos y nombres consultados son datos personales de uso de la red. Por eso NDR tiene sus
propios permisos (`ndr:read`, `ndr:evidence`, `ndr:triage`, `ndr:manage`). Un viewer ve
agregados, anomalías y planes; solo analyst y admin ven flujos y metadatos individuales.
La acción `collect_ndr_context` exige `ndr:evidence` además de `monitoring:read` y
`response:execute`.

## Superficie del sensor

- Linux: solo `CAP_NET_RAW` y la familia `AF_PACKET` mediante drop-in de systemd; sin
  `CAP_NET_ADMIN` ni root. El modo promiscuo lo pide el socket solo si el servidor lo aprueba
  y el sistema lo retira al cerrarlo.
- Windows: Npcap instalado por el operador, cargado por ruta absoluta desde
  `%SystemRoot%\System32\Npcap\wpcap.dll`; nunca desde el directorio de trabajo ni WinPcap.
  Sentra no distribuye ni instala controladores.
- macOS: libpcap del sistema; sin permisos sobre `/dev/bpf*` el backend informa
  `permission_denied` en lugar de pedir privilegios.
- El decodificador acota longitudes, profundidad de VLAN, número de respuestas DNS y tamaño de
  nombres; una trama malformada se descarta y se cuenta, no detiene la captura.
- Límites de memoria y CPU aprobados por el servidor y además acotados en el sensor: un
  servidor comprometido no puede pedir una tabla de flujos ilimitada.
- El servidor solo envía alias: nunca nombres de dispositivo, rutas, filtros BPF ni comandos.

## Superficie del servidor

- `POST /sensor/ndr/batches` exige la credencial del sensor, cuota por sensor y minuto (429
  con `Retry-After`), tamaño máximo de petición y de registros, e interfaz aprobada.
- Todo lo recibido se valida con modelos Pydantic estrictos (IPs, MACs, puertos, nombres DNS
  saneados); los textos se muestran escapados en la UI.
- Los analizadores corren en la misma transacción del lote: si fallan, el lote no queda a
  medias.
- Retención por días configurable para cada tipo de dato; las anomalías activas no se purgan.

## Veredictos y falsos positivos

`confirmed` solo existe donde la regla reúne indicios independientes (hoy NDR-MITM-001).
Las reglas de comportamiento esperan `NDR_BASELINE_MIN_SAMPLES` horas antes de alertar.
Un discovery autorizado de Sentra en el site rebaja un barrido a `observed`. La
inteligencia de amenazas solo llega a `probable` con un indicador malicioso de confianza alta
de una fuente oficial o de confianza sobre un valor exacto.

## Respuesta

- Las sugerencias son una función pura de la anomalía con reglas fijas. No hay modelo de IA
  ni inferencia.
- Los objetivos de control pasan por la misma validación que la Fase 7A.6 (prefijos mínimos,
  dominios completos, sentido); un objetivo que no la supera no se sugiere.
- Nunca se sugiere bloquear una IP interna: la contención de equipos internos es un paso
  manual o el flujo de aislamiento con doble confirmación.
- Pedir un control exige `incidents:manage`; aprobarlo, `network_controls:approve`. Los
  intentos fallidos quedan auditados (`network_control_requested`, resultado `failure`).
