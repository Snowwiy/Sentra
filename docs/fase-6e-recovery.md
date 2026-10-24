# Fase 6E: recuperación y vuelta atrás

## Desactivar sin desinstalar

| Funcionalidad | Cómo apagarla | Efecto |
|---|---|---|
| Aislamiento | `ISOLATION_ENABLED=false` (por defecto) y/o `enabled = false` en `isolation.toml` del helper | No se crean sesiones nuevas; el helper revierte lo aplicado al caducar. |
| Response (incluye forense y aislamiento) | `RESPONSE_ENABLED=false` | No se encolan comandos; el sondeo de comandos devuelve vacío. |
| Telemetría de actividad | En el agente: `[telemetry] enabled = false` o `SENTRA_AGENT_TELEMETRY_ENABLED=false` (ver `docs/endpoint-telemetry-agent.md`) | El agente deja de enviar `/agents/activity`; el resto sigue igual. |
| Línea de comandos | `TELEMETRY_CMDLINE_POLICY=off` | El servidor descarta la línea de comandos de los eventos nuevos. |
| Detección conductual puntual | Excepción en `/detection-exclusions` (auditada, revocable) | La regla no abre detecciones para ese valor. |
| Lecturas DHCP de sensor | Deshabilitar la fuente (`PATCH /dhcp/sources/{id}` `enabled=false`) | No se programan lecturas; los leases ya importados se conservan. |

## Aislamiento atascado

1. Mirar el estado en la UI o en `GET /assets/{id}/isolation` y `assets.isolation_status`.
2. Liberar desde la UI (`release`). Si el agente no responde, el helper revierte solo al
   caducar (`expires_at`); el servidor no puede acortar ese plazo.
3. En el equipo, como administrador local y solo si hace falta antes de caducar:
   - Windows: borrar solo las reglas del grupo `Sentra Isolation` del firewall de Windows
     (`uninstall-sentra-agent.ps1` también revierte antes de quitar el servicio).
   - Linux: `sudo /opt/sentra-agent/bin/sentra-agent isolation-helper revert` o
     `nft delete table inet sentra_isolation` (la tabla no es persistente: un reinicio también
     la elimina).
4. Con el equipo ya limpio, el siguiente heartbeat cierra la sesión (`restored`, `expired` o
   `failed` con `isolation_lost`) y resuelve la alerta `isolation_state`.

## Volver a 6D (0.2.0)

1. Levantar cualquier aislamiento vivo y esperar a `restored`.
2. Exportar los paquetes de evidencia que haya que conservar.
3. Parar API y workers.
4. `alembic downgrade 0038` (ver `docs/fase-6e-migrations.md`: se pierden historial de
   topología, DHCP, actividad, árbol de procesos, excepciones, evidencia y sesiones).
5. Desplegar el código 0.2.0 del backend y el frontend.
6. Agentes 0.5.0 contra un servidor 0.2.0: el endpoint `/agents/activity` responde 404 y el
   agente desactiva la actividad durante esa ejecución; los campos nuevos del heartbeat se
   eliminan solos (`_unknown_fields`). Sensores 0.6.0: no anuncian nada que un servidor 0.2.0
   use, salvo la capacidad `dhcp.leases.file`, que este ignora.

## Restaurar una copia de seguridad posterior a 6E

Si se restaura una base anterior a un aislamiento que sigue vivo en un equipo, ese equipo
informará `state=isolated` sin sesión: se abre la alerta `isolation_state` y el helper lo
revierte al caducar.
