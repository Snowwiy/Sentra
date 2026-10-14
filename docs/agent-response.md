# Comandos de Response en el agente (Fase 5D, agente 0.3.0)

El agente recibe del servidor **comandos tipados de una allowlist cerrada** y nunca ejecuta
nada más. No hay shell, ni `subprocess` nuevo, ni rutas, ni argumentos: cada tipo está
mapeado a un handler en `agent/sentra_agent/runner.py` que reutiliza los colectores de solo
lectura que el agente ya tenía.

| Tipo | Qué hace | Plataformas |
|------|----------|-------------|
| `collect_inventory` | Recolecta y envía el inventario (incluye red y conexiones) | Windows, Linux |
| `collect_processes` | Envía una instantánea de procesos | Windows, Linux |
| `collect_events` | Envía ya los eventos pendientes (Visor de eventos / journal) | Windows, Linux |
| `collect_telemetry` | Envía una muestra de telemetría | Windows, Linux |
| `collect_diagnostics` | Versión, plataforma, intervalos, buffer, cobertura de eventos, campos no aceptados por el servidor | Windows, Linux |

El diagnóstico nunca incluye tokens, claves de enrollment, rutas de credenciales ni la
configuración completa.

## Capacidades

El agente declara en `register` y `heartbeat` (`host.capabilities`) los tipos que soporta en
su sistema (`commands.capabilities()`; `collect_events` solo en Windows y Linux). El servidor
las filtra con su propia allowlist y las guarda en `assets.agent_capabilities`. Una acción de
agente se bloquea si:

- el agente no declaró capacidades (`agent_capabilities_unknown`: agentes anteriores a 0.3.0),
- no declaró esa en concreto (`unsupported_capability`),
- la plataforma del activo no está soportada (`unsupported_platform`).

Un servidor anterior a 5D responde 422 `extra_forbidden` al campo `capabilities`; el agente lo
quita y reintenta (mecanismo existente `_send_adapting`), así que 0.3.0 funciona con
servidores antiguos.

## Protocolo

1. El heartbeat responde `pending_commands` (comandos en cola para ESTE agente en ESTE activo).
   Si es 0 o no viene (servidor antiguo), el agente no consulta nada: sin polling extra.
2. `POST /agents/commands/poll` con `agent_id` y su Bearer token: el servidor devuelve como
   mucho `max_commands` (≤10) comandos `{request_id, type, params, deadline_at}` y los marca
   entregados con un lease. Un 404 (servidor antiguo) desactiva la consulta hasta reiniciar.
3. El agente valida cada comando (`commands.parse_command`): `request_id` UUID, tipo de la
   allowlist y sin parámetros. Si no cumple, responde `rejected` (`unknown_command`,
   `invalid_params`) sin ejecutar nada. Un `request_id` inválido se ignora.
4. Ejecuta el handler y envía `POST /agents/commands/{request_id}/result` con
   `status` (`succeeded`/`failed`/`rejected`), `summary` (≤500), `data` y `error_code`. El
   `request_id` de la URL se reconstruye como UUID: nunca se interpola texto del servidor.
5. Los comandos van al final del ciclo: un comando lento nunca retrasa heartbeat ni telemetría.

## Duplicados, reentregas y cortes de red

- El agente recuerda los últimos 64 resultados por `request_id`. Si el servidor reentrega un
  comando (se perdió la respuesta), reenvía el resultado guardado sin recolectar otra vez.
- Si el envío del resultado falla por red, queda en una cola acotada (32) y se reintenta al
  principio del siguiente ciclo. Lo más antiguo se descarta: ya habrá caducado en el servidor.
- Errores del colector: `failed` con `collector_failed` (la traza va al log local con
  secretos redactados, nunca al servidor). Rechazo de los datos por el servidor:
  `server_rejected`.

## Seguridad en el servidor

- Autenticación con el token del agente; el poll solo devuelve comandos con `asset_id` del
  activo autenticado y `agent_id` igual a su agente actual.
- Un resultado para un comando de otro agente/activo es 404 (indistinguible de inexistente);
  para uno no entregado, 409; repetido, `duplicate: true`; caducado o cancelado,
  `accepted: false`. Nada de eso cambia la ejecución.
- TTL de cola (`RESPONSE_COMMAND_TTL_MINUTES`) y lease por entrega; como mucho una reentrega
  (`max_deliveries = 2`) y solo en acciones idempotentes.
- Un agente revocado o histórico (reconciliación 5C.2) no autentica y la política bloquea
  cualquier acción hacia él.

## Pruebas

`agent/tests/test_response_commands.py`: comando allowlisted ejecutado de verdad, rechazo de
tipos desconocidos y de parámetros, `request_id` malformado, reentrega sin recolectar dos
veces, servidor antiguo sin endpoint, capacidades declaradas y memoria acotada. El servidor
falso de `agent/tests/conftest.py` implementa el protocolo.

Pendiente en hardware real: ejecutar cada tipo en Windows (servicio `SentraAgent`) y en Linux
(systemd) con el agente 0.3.0 empaquetado.
