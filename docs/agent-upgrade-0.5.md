# Actualizar el agente a 0.5.0 (Fase 6E)

## Qué cambia

- **Actividad del endpoint** (`POST /api/v1/agents/activity`): procesos con padre e
  `instance_key`, conexiones por proceso, servicios, tareas programadas, persistencia,
  antivirus, firewall, Sysmon (Windows) y salud del agente. Está activa por defecto y se
  desactiva con `[telemetry] enabled = false`. Detalle: `docs/endpoint-telemetry-agent.md`.
- **Acciones forenses de solo lectura**, nueve tipos `forensic_*`:
  - devuelven un artefacto `sentra-forensic/1` con su SHA-256 y, si hace falta, recortado;
  - `forensic_file_metadata` solo mira dentro de `[forensics] allowed_roots` y fuera de las
    rutas sensibles (credenciales del sistema y estado del propio agente);
  - nunca lee contenido salvo para el hash, que tiene tope.
- **Aislamiento de red** mediante un helper separado y opcional, desactivado por defecto:
  `docs/safe-isolation-helper.md`.
- **Heartbeat**: campos nuevos `telemetry` e `isolation`, y capacidades nuevas.

## Compatibilidad con servidores anteriores

| Servidor | Comportamiento del agente 0.5.0 |
|---|---|
| Sin `/agents/activity` (404) | deja de enviar y de recolectar actividad hasta reiniciar; el resto funciona igual |
| Rechaza `telemetry` o `isolation` en el heartbeat (422 `extra_forbidden`) | quita esos campos y no los vuelve a enviar |
| No conoce las capacidades nuevas | las ignora (las guarda solo si las conoce) |
| No envía comandos `forensic_*` ni `isolate_host` | nada cambia |

No hace falta volver a enrolar: la identidad, el token y la configuración existente se
conservan. Las secciones nuevas son opcionales; sin ellas valen los valores por defecto.

## Capacidades anunciadas

| Capacidad | Windows | Linux | macOS |
|---|---|---|---|
| `collect_*` de 5D | sí | sí | sí |
| `forensic_processes`, `_connections`, `_services`, `_persistence`, `_sessions`, `_network_config`, `_firewall_state`, `_file_metadata` | sí | sí | sí |
| `forensic_scheduled_tasks` | sí | sí (temporizadores systemd) | no |
| `telemetry_activity` | si la telemetría está activa y el servidor tiene el endpoint | igual | igual |
| `telemetry_process_tree` | si el colector de procesos está `active` | igual | igual |
| `telemetry_process_network` | si las conexiones son legibles | igual | solo como root |
| `telemetry_sysmon` | si el canal de Sysmon existe y es legible | no | no |
| `isolate_host`, `release_isolation` | solo con el helper instalado, habilitado y con `status.json` reciente | igual | nunca |

## Pasos

### Windows

1. Ejecuta `install-sentra-agent.ps1 -Upgrade` con el zip 0.5.0, como en versiones
   anteriores.
2. Opcional: añade `-InstallIsolationHelper` para instalar el helper (queda desactivado).

### Linux

1. Instala el `.deb` o el tarball 0.5.0 (`install-sentra-agent.sh --upgrade`).
2. La unidad `sentra-isolation` se instala, pero no se habilita.

### macOS

1. Instala el `.pkg` 0.5.0.
2. Sin aislamiento. La red por proceso requiere root, y el LaunchDaemon ya corre como root.

### Después de actualizar

Lanza `collect_diagnostics` desde la consola y comprueba:

- `telemetry.collectors`: el estado de cada colector;
- `telemetry.tracker.last_pass_ms`: el coste de una pasada del tracker;
- `activity_supported_by_server`;
- `isolation`: el estado del helper.

## Configuración nueva

Las tres secciones están comentadas en `agent/agent.example.toml`. Cada clave también se puede
fijar con `SENTRA_AGENT_<SECCION>_<CLAVE>`. Una clave desconocida o un valor fuera de rango
hacen que el agente no arranque, con un error claro (igual que el resto de la configuración).

| Sección | Claves |
|---|---|
| `[telemetry]` | `enabled`, `process_poll_seconds` (2-300), `network_enabled`, `cmdline` (`off`, `redacted`, `full`), `hash_executables`, `hash_max_mb`, `activity_queue_max_events`, `services_poll_seconds`, `persistence_poll_seconds`, `state_poll_seconds`, `sysmon_enabled`, `sysmon_poll_seconds`, `health_seconds` |
| `[forensics]` | `allowed_roots`, `max_artifact_kb` (64-16384), `hash_max_mb` |
| `[isolation]` | `exchange_dir`, `policy_file`, `wait_seconds` (5-300), `status_max_age_seconds` (30-3600) |

## Ficheros nuevos en `state_dir`

| Fichero | Contenido |
|---|---|
| `activity_queue.jsonl`, `activity_queue.meta.json` | cola de actividad pendiente |
| `baseline_service.json`, `baseline_scheduled_task.json`, `baseline_persistence.json` | líneas base de los colectores con diff |
| `sysmon_cursor.json` | último registro de Sysmon leído |

Volver a 0.4.0 deja estos ficheros sin uso; se pueden borrar sin consecuencias.

## Limitaciones

- La recogida de procesos es por sondeo: un proceso de vida más corta que
  `process_poll_seconds` puede no verse sin Sysmon.
- No hay colector DNS.
- Las reglas de firewall (Windows y nftables), Sysmon, `schtasks` y Defender están probados
  con dobles y salidas de ejemplo, pero falta validarlos en equipos reales. La lista está en
  las guías de telemetría y del helper.
- El modelo de privilegios del aislamiento está pendiente de confirmación por el propietario.
