# Aislamiento seguro (Fase 6E.7, servidor)

Este documento cubre el servidor y la UI. El helper local del equipo (instalación, política
`isolation.toml`, reglas de firewall, reversión) está en `docs/safe-isolation-helper.md`.

Decisión (Jesus, 2026-10-22): helper separado y privilegiado; el agente sigue sin
privilegios; sin aislamiento en macOS. Nada de esto se ha ejecutado sobre equipos reales: todas las pruebas usan fakes.

## Principios

- Desactivado por defecto en dos sitios: `ISOLATION_ENABLED=false` en el servidor y
  `enabled = false` en la política local del helper. Hacen falta los dos.
- Solo admin (`containment:isolate`), con motivo, duración acotada
  (`ISOLATION_MAX_MINUTES`, 240) y confirmación escrita: el nombre exacto del equipo.
- El servidor solo envía `{session_id, expires_at}` (y `{session_id}` para liberar). Nunca
  envía direcciones: el helper calcula qué se permite (servidor Sentra a partir de la URL del
  agente, loopback, DHCP, DNS si su política lo permite, `extra_allow` local).
- Reversión local: el helper revierte solo al caducar aunque el servidor no responda.
- El servidor nunca marca `isolated` sin la confirmación verificada del helper.
- `isolate_host` y `release_isolation` existen en el catálogo de Response, pero una ejecución
  suelta se bloquea (`isolation_session_required`): solo salen de este flujo. Tampoco pueden
  ser pasos de playbook.

## Disponibilidad

`GET /api/v1/assets/{id}/isolation` (containment:preview, analista y admin) devuelve
`available`, `reasons`, impacto, recomendaciones manuales, nombre a confirmar, duraciones y
la sesión viva.

| Código | Motivo | Mensaje permanente |
|---|---|---|
| `no_agent` | dispositivo sin agente Sentra | «Aislamiento no disponible para este dispositivo» |
| `unsupported_platform` | macOS u otra plataforma | «Aislamiento no disponible para este dispositivo» |
| `isolation_disabled` | `ISOLATION_ENABLED=false` | |
| `response_disabled` | `RESPONSE_ENABLED=false` | |
| `asset_archived` | activo archivado | |
| `agent_credential_inactive` | agente revocado o sin credencial | |
| `helper_unavailable` | el agente no anuncia `isolate_host` (helper ausente, desactivado o sin estado reciente) | |
| `agent_offline` | sin contacto reciente (la política de Response decide al ejecutar) | |
| `isolation_active` | ya hay una sesión viva | |

En dispositivos sin agente la UI muestra además recomendaciones manuales (desconectar el
cable o el Wi-Fi, VLAN de cuarentena, bloqueo en el router o firewall perimetral).

## Estados

```
requested → approved → applying → isolated → reverting → restored
                          ↘ failed     ↘ unknown    ↘ expired
```

| Estado | Cuándo |
|---|---|
| `requested` / `approved` | Petición registrada; la confirmación escrita del admin es la aprobación (se auditan por separado). |
| `applying` | Ejecución `isolate_host` encolada. |
| `isolated` | El helper aplicó y verificó leyendo sus reglas de vuelta (resultado del comando o heartbeat). |
| `reverting` | Liberación pedida. |
| `restored` | El helper confirmó que borró sus reglas (resultado o heartbeat con `state=none`). |
| `failed` | El helper rechazó o deshizo el intento, o el comando caducó sin entregarse. |
| `expired` | Caducó y el equipo informa que ya no está aislado (reversión local). |
| `unknown` | Servidor y equipo discrepan: reglas desaparecidas antes de caducar (`rules_lost`), otra sesión (`session_mismatch`), sin verificar (`verification_failed`), comando entregado sin resultado (`no_result`) o liberación fallida o bloqueada. |

Una sesión `unknown` abre la alerta crítica `isolation_state` y se resuelve sola cuando el
equipo vuelve a coincidir. Un equipo que informa aislamiento sin sesión en Sentra también
abre la alerta. Solo una sesión viva por activo (índice único parcial).

## Conciliación

- Resultado del comando (`data.isolation` del contrato) → `apply_isolation_result`.
- Heartbeat del agente 0.5.0 (`isolation`: helper, state, session_id, verified...) →
  `reconcile_report`. Se guarda en `assets.isolation_status`. Si el helper no está `ready` ni
  `disabled`, no se mueve la sesión por suposición.
- Barrido de Response (`run_response_engine`) → `sweep_isolation`: sesiones `applying` o
  `reverting` cuyo comando terminó sin resultado pasan a `failed` (nunca entregado) o
  `unknown` (entregado).

## API

| Método y ruta | Permiso |
|---|---|
| `GET /assets/{id}/isolation` | containment:preview |
| `GET /assets/{id}/isolation/sessions` | containment:preview |
| `GET /isolation/sessions` (sesiones vivas) | containment:preview |
| `POST /assets/{id}/isolation` `{duration_minutes, reason, confirm_name}` | containment:isolate (+ response:execute/manage) |
| `POST /assets/{id}/isolation/release` `{version, reason}` | containment:release (+ response:execute/manage) |

Errores: `isolation_disabled` (409), `isolation_unavailable` (409, con motivos),
`isolation_active` (409), `isolation_confirmation_mismatch` (422),
`isolation_duration_exceeds_policy` (422), `isolation_state_conflict` (409),
`response_blocked` (409, la política de Response lo bloqueó; la sesión queda `failed`).

Auditoría (`target_type=isolation_session`): `isolation_requested`, `isolation_approved`,
`isolation_dispatched`, `isolation_applied`, `isolation_failed`, `isolation_state_unknown`,
`isolation_release_requested`, `isolation_release_blocked`, `isolation_restored`,
`isolation_expired`.

## Activación (solo en laboratorio)

1. Leer `docs/safe-isolation-helper.md` e instalar el helper en un equipo de laboratorio.
2. `enabled = true` en su `isolation.toml` local y reiniciar el helper.
3. `ISOLATION_ENABLED=true` en el servidor.
4. Comprobar en la UI que el equipo muestra el helper `ready` y aislar con duración corta.

No activar en producción sin una prueba controlada en laboratorio.
