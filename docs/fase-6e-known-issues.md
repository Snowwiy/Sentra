# Fase 6E: problemas conocidos y pendientes

Registro de limitaciones aceptadas al cerrar la fase. Ninguna bloquea la publicación; cada una
indica por qué se deja así.

## Pendiente de decisión de Jesus

(El modelo de privilegios del aislamiento quedó decidido el 2026-10-22: helper separado y
privilegiado.)

- Aprobación del aislamiento por un solo admin: la confirmación escrita del mismo admin es la
  aprobación (estados `requested` y `approved` se auditan por separado). Doble aprobación
  (cuatro ojos) queda para una fase posterior si Jesus la quiere.

## Pendiente de validar con hardware real

Nada de lo siguiente se ha ejecutado fuera de la nube; las pruebas usan agentes, sensores y
helpers simulados.

- Aislamiento: nunca se ha ejecutado sobre un equipo real (instrucción explícita). Antes de
  activarlo: prueba controlada en un equipo de laboratorio Windows y otro Linux, con duración
  corta, comprobando la reversión local al caducar y tras reiniciar.
- Recogida forense real en Windows, Linux y macOS (agente 0.5.0), y el paquete ZIP abierto en
  Windows.
- Telemetría de actividad del agente 0.5.0 en Windows (con y sin Sysmon) y Linux: coste real de
  CPU y memoria, volumen por equipo.
- Lectura DHCP por sensor 0.6.0 en Windows (exportación del servidor DHCP) y Linux
  (`dhcpd.leases`, dnsmasq); importación de un fichero real del Archer GX90 si su panel lo
  permite. El GX90 no depende de SNMP en ningún caso.
- Suites completas en Windows (Python 3.14/3.15) y frontend con Node 24 en el PC.

## Limitaciones aceptadas

- Preservación de snapshots: `TopologyHistoryService.preserve_for` existe y lo respeta la
  retención, pero 6E no lo llama desde incidentes ni investigaciones. Hasta conectarlo, un
  snapshot solo queda preservado si alguien lo marca; los demás caducan con la retención.
- `network_changes.source` hoy siempre vale `topology_diff`: los valores `identity`, `dhcp` y
  `discovery` están reservados en el modelo pero ningún productor los usa aún. Los cambios de
  identidad van a `asset_identity_history`.
- Excepciones de reglas conductuales: no pueden casar con BEH-005 ni BEH-006 (sus señales no
  tienen el campo por el que se excluye), y el contador `hits` de una excepción cuenta señales
  omitidas, no detecciones evitadas.
- Fechas DHCP sin zona horaria: la importación por API las toma como UTC; el sensor, como hora
  local del equipo que lee el fichero. Para ficheros sin zona, preferir la lectura por sensor
  en el propio servidor DHCP.
- El sondeo de procesos (5 s por defecto) no ve procesos que viven menos que el intervalo, salvo
  con Sysmon en Windows. Las reglas conductuales heredan ese punto ciego.
- Sin colector DNS en el agente 0.5.0: la categoría `dns` se acepta en el contrato pero no
  llega.
- Sin aislamiento en macOS ni en dispositivos sin agente: la UI muestra «Aislamiento no
  disponible para este dispositivo» y recomendaciones manuales.
- La evidencia forense no se purga automáticamente ni tiene endpoint de borrado; `legal_hold`
  queda registrado para una limpieza futura.
- El paquete de evidencia se genera en memoria y se limita con `FORENSICS_PACKAGE_MAX_MB` (64).
- Las notas `ai_summary` las escribe el analista: 6E no genera resúmenes de IA por su cuenta.

## Corregido durante la fase

- `/agents/activity` contaba el cupo por `agent_id` antes de autenticar: cualquiera que conociera
  un `agent_id` podía agotar el cupo del agente real. Ahora autentica primero (test
  `test_unauthenticated_batches_do_not_consume_the_agent_quota`).
- `test_identity_history_listener_records_agent_and_discovery_changes` dejaba un activo en la
  base y hacía fallar después `test_assets_list_mixes_managed_and_discovered`; ahora usa el
  fixture `client`, que vacía las tablas al terminar.
