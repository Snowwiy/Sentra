# Fase 6E: contratos agente, sensor y servidor

Contratos de protocolo nuevos de la Fase 6E. Todo es aditivo: un agente 0.4.0 o un sensor 0.5.x
siguen funcionando con su contrato anterior, y un agente 0.5.0 contra un servidor 0.2.0 elimina
los campos que el servidor no conoce (mecanismo `_unknown_fields` existente) y no usa endpoints
que respondan 404.

## Capacidades del agente 0.5.0

El heartbeat sigue enviando `capabilities` (patrón `^[a-z][a-z0-9_]{1,47}$`, máximo 32). El
servidor guarda solo las que conoce (`AGENT_KNOWN_CAPABILITIES`). Nuevas:

| Capacidad | Significado | Se anuncia solo si |
|---|---|---|
| `telemetry_activity` | envía `POST /agents/activity` | siempre en 0.5.0 (se puede desactivar en config) |
| `telemetry_process_tree` | eventos de inicio/fin con `instance_key` y padre | colector de procesos activo |
| `telemetry_process_network` | conexiones por proceso | psutil puede listar conexiones con pid |
| `telemetry_sysmon` | inicio de proceso desde Sysmon (Windows) | el canal Sysmon existe y es legible |
| `forensic_processes` ... `forensic_file_metadata` | acciones forenses (ver abajo) | la acción funciona en esa plataforma |
| `isolate_host`, `release_isolation` | aislamiento | helper instalado, habilitado y sano |

## POST /api/v1/agents/activity

Cabeceras: `Authorization: Bearer <token>`; opcional `Content-Encoding: gzip` (el servidor
descomprime con tope `max_request_bytes`; más grande = 413 `payload_too_large`).

```json
{
  "agent_id": "uuid",
  "batch_id": "uuid",
  "boot_id": "texto <= 64",
  "events": [
    {
      "event_uid": "uuid",
      "seq": 0,
      "category": "process",
      "action": "start",
      "occurred_at": "2026-10-22T10:00:00.123+00:00",
      "source": "psutil_poll",
      "instance_key": "32 hex o null",
      "data": {}
    }
  ],
  "stats": {
    "queued": 0,
    "dropped_total": 0,
    "dropped_since_last": 0,
    "oldest_queued_at": null,
    "process_poll_seconds": 5,
    "collectors": {"process": "active", "network": "active", "service": "active",
                   "scheduled_task": "unavailable", "persistence": "active",
                   "protection": "permission_denied", "firewall": "active",
                   "sysmon": "unavailable", "dns": "unavailable"}
  }
}
```

- `events`: 1 a 1000. `event_uid` único por activo: un reenvío cuenta como `duplicates`.
- `category`: `process`, `network`, `service`, `scheduled_task`, `persistence`, `auth`, `dns`,
  `protection`, `firewall`, `agent_health`.
- `source`: `psutil_poll`, `sysmon`, `security_4688`, `journald`, `proc`, `unified_log`,
  `service_poll`, `task_poll`, `persistence_poll`, `firewall_poll`, `protection_poll`, `agent`.
- Estados de colector: `active`, `unavailable`, `permission_denied`, `disabled`, `error`.
- Respuesta 200: `{"asset_id", "accepted", "duplicates", "rejected": [{"index", "code"}]}`.
  Un evento mal formado se rechaza solo (código por índice), no todo el lote.
- 401/403 igual que el resto de llamadas del agente; 429 con `Retry-After`.

`data` por categoría y acción (campos opcionales pueden ser `null`; el servidor descarta claves
desconocidas y acota longitudes):

| category / action | data |
|---|---|
| process / start | `pid`, `ppid`, `parent_instance_key`, `parent_relation` (`observed`, `inferred`, `missing`, `pid_reused`), `name`, `exe`, `cmdline`, `username`, `started_at`, `sha256`, `signer`, `integrity` |
| process / stop | `pid`, `name`, `ended_at` |
| network / connect, listen | `pid`, `protocol` (`tcp`, `udp`), `local_address`, `local_port`, `remote_address`, `remote_port`, `state`, `direction` (`outbound`, `inbound`, `listen`) |
| service / created, modified, deleted, started, stopped | `name`, `display_name`, `start_type`, `status`, `exe`, `username` |
| scheduled_task / created, modified, deleted | `name`, `path`, `exe`, `enabled`, `trigger` |
| persistence / created, modified, deleted | `mechanism` (`run_key`, `startup_folder`, `systemd_unit`, `cron`, `launch_agent`, `launch_daemon`), `location`, `name`, `target` |
| auth / success, failure | `user`, `logon_type`, `source_ip` |
| protection / state | `product`, `realtime_enabled`, `antivirus_enabled`, `tamper_protection`, `signature_age_days` |
| firewall / state | `profile`, `enabled`, `default_inbound`, `default_outbound` |
| dns / query | `query`, `record_type`, `answers` (máx. 8) |
| agent_health / state | `cpu_percent`, `rss_bytes`, `queued`, `dropped_total` |

`instance_key` = primeros 32 hex de `sha256("{boot_id}|{pid}|{create_time_ms}")`.
`cmdline` llega ya redactada según la política del agente (`off`, `redacted`, `full`); el servidor
vuelve a aplicar la suya (gana la más restrictiva).

## Heartbeat: campos nuevos (opcionales)

```json
{
  "telemetry": {"queued": 0, "dropped_total": 0, "collectors": {"process": "active"}},
  "isolation": {
    "helper": "absent | disabled | ready | error",
    "state": "none | applying | isolated | reverting | failed",
    "session_id": "uuid o null",
    "applied_at": "iso o null",
    "expires_at": "iso o null",
    "method": "windows_firewall | nftables | null",
    "verified": true,
    "error_code": null
  }
}
```

## Comandos nuevos (POST /agents/commands/poll)

Los cinco tipos de 5D siguen sin parámetros. Los nuevos:

| type | params | riesgo |
|---|---|---|
| `forensic_processes` | ninguno | low |
| `forensic_connections` | ninguno | low |
| `forensic_services` | ninguno | low |
| `forensic_scheduled_tasks` | ninguno | low |
| `forensic_persistence` | ninguno | low |
| `forensic_sessions` | ninguno | low |
| `forensic_network_config` | ninguno | low |
| `forensic_firewall_state` | ninguno | low |
| `forensic_file_metadata` | `{"path": str <= 1024, "hash": bool}` | medium (admin) |
| `isolate_host` | `{"session_id": uuid, "expires_at": iso}` | critical (admin) |
| `release_isolation` | `{"session_id": uuid}` | high (admin) |

El agente valida de nuevo: claves exactas, tipos, `path` absoluto, sin `..`, dentro de
`forensics.allowed_roots` de su configuración local; `expires_at` en el futuro y no más allá de
`isolation.max_minutes` local. Cualquier otro parámetro: `invalid_params` sin ejecutar nada.

### Resultado de una acción forense

```json
{
  "status": "succeeded",
  "summary": "312 procesos",
  "data": {
    "artifact": {
      "schema": "sentra-forensic/1",
      "kind": "forensic_processes",
      "collected_at": "iso",
      "agent_version": "0.5.0",
      "platform": "windows",
      "content": {},
      "sha256": "hex de sha256(json canónico de content)",
      "truncated": false
    },
    "limitations": [{"code": "permission_denied", "detail": "texto corto"}]
  }
}
```

JSON canónico: `json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)`
codificado en UTF-8. El contenido completo tiene tope `forensics.max_artifact_kb` (2048) en el
agente; si se supera se recorta la lista y `truncated=true`.

### Resultado de aislamiento

```json
{
  "status": "succeeded | failed",
  "summary": "texto",
  "data": {
    "isolation": {
      "state": "isolated | restored | failed",
      "session_id": "uuid",
      "applied_at": "iso",
      "expires_at": "iso",
      "method": "windows_firewall | nftables",
      "allowed": ["203.0.113.10"],
      "rules": [{"name": "...", "direction": "inbound|outbound", "action": "block", "remote": "..."}],
      "verified": true,
      "error_code": null
    }
  },
  "error_code": "helper_absent | helper_disabled | firewall_disabled | duration_exceeds_policy | ..."
}
```

## Helper de aislamiento (local, sin red)

- Directorio de intercambio: Windows `%ProgramData%\Sentra\Agent\isolation\`, Linux
  `/var/lib/sentra-agent/isolation/`. El agente escribe `request.json`
  (`{"session_id", "action": "isolate|release", "expires_at", "requested_at"}`); el helper
  escribe `status.json` (mismo formato que `heartbeat.isolation`) y `state.json` (lo aplicado).
- Política local del helper: Windows `%ProgramData%\Sentra\Isolation\isolation.toml`, Linux
  `/etc/sentra-agent/isolation.toml`: `enabled = false`, `max_minutes = 240`,
  `allow_dns = true`, `extra_allow = []`, `agent_config = <ruta de agent.toml>`.
- El helper calcula las direcciones permitidas: IPs resueltas del host de `api_url` del agente,
  loopback, DHCP (broadcast y servidor DHCP actual), DNS configurados si `allow_dns`, y
  `extra_allow`. Nunca usa direcciones que vengan en la petición.
- El helper aplica la expiración por su cuenta y, al arrancar, revierte un estado caducado.

### Precisiones del agente 0.5.0

Estas precisiones amplían el contrato, no lo cambian. Las añadió la sesión del agente para
cubrir lo que el formato inicial no resolvía.

- `status.json` lleva, además de los campos de `heartbeat.isolation`:
  - `updated_at`: sin él, el agente no distingue un helper parado de uno sano;
  - `allowed` y `rules`: van al resultado del comando;
  - `last_action` (`{session_id, action, outcome, error_code, at}`): permite casar el
    resultado con la petición sin un segundo fichero.

  El agente solo reenvía los campos del contrato en el heartbeat.
- `state.json` del directorio de intercambio es una copia informativa. El estado con el que
  el helper revierte vive en su directorio privado, para que un agente comprometido no pueda
  fabricarlo.
- `allowed` usa una IP suelta para un host (`203.0.113.10`) y CIDR para una red
  (`127.0.0.0/8`).
- `data.isolation.state = "restored"` tras un `release_isolation` correcto.
- Comandos rechazados por el agente: `status = "rejected"` con `error_code`
  `unknown_command`, `invalid_params` o `path_not_allowed` (`forensic_file_metadata` fuera de
  `allowed_roots` o en una ruta sensible).
- `content` de las acciones forenses de lista: `{"items": [...], "total": N}`;
  `forensic_network_config` añade `gateways`, `dns_servers` y `hostname`. `total` es el
  número real aunque `items` se haya recortado.
- `process/start` puede llevar `data.preexisting = true` (procesos ya en marcha en la primera
  pasada; `occurred_at` es entonces el momento de la observación). El servidor la descarta
  como clave desconocida.

## Sensor 0.6.0: job `dhcp_leases`

Capacidad `dhcp.leases.file`. Parámetros del job: `{"source_name": str <= 64}`. El sensor busca
ese nombre en `[[dhcp_lease_files]]` de su `sensor.toml` (`name`, `path`, `format`); si no
existe: fallo `dhcp_source_unknown`. Formatos: `dnsmasq`, `isc_dhcpd`, `kea_csv`,
`windows_dhcp_csv`, `generic_csv`. Tope de fichero `dhcp_max_file_kb` (4096).

Protocolo: el job usa los endpoints existentes (`/sensor/jobs/poll`, `/start`, `/results`,
`/complete`). `POST /sensor/jobs/{id}/results` admite un campo nuevo `leases` (máx. 5000 por lote,
nunca junto con `observations` ni `records`):

```json
{"batch_id": "uuid", "attempt": 1,
 "leases": [{"ip": "192.168.50.23", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "pixel-7",
             "client_id": null, "starts_at": null, "ends_at": "iso", "state": "active"}]}
```

`POST /sensor/jobs/{id}/complete` admite `dhcp`:

```json
{"attempt": 1, "outcome": "completed", "batches_sent": 1,
 "dhcp": {"format": "dnsmasq", "lines": 40, "parsed": 38, "skipped": 2, "truncated": false,
          "file_mtime": "iso o null", "error_code": null}}
```

Códigos de error del job: `dhcp_source_unknown`, `dhcp_file_missing`, `dhcp_file_unreadable`,
`dhcp_file_too_large`, `dhcp_format_invalid`. `state`: `active`, `expired`, `released`, `unknown`.
Un sensor 0.5.x no anuncia `dhcp.leases.file` y el servidor nunca le asigna el job.

Precisiones del sensor 0.6.0 (compatibles con lo anterior):

- `dhcp.format` es `null` solo cuando el error es `dhcp_source_unknown` (el sensor no conoce
  el formato de una fuente que no tiene). En los demás casos es el formato configurado.
- `dhcp.lines` cuenta registros examinados (líneas de datos, filas CSV sin cabecera o bloques
  de `dhcpd.leases`); `dhcp.parsed`, leases únicos enviados (una entrada por IP: la última
  aparición gana); `dhcp.skipped`, registros mal formados. Las repeticiones de una IP no
  cuentan como `skipped`, así que `lines >= parsed + skipped`.
- `mac` nunca es `null`: un lease sin MAC Ethernet válida (p. ej. DHCPv6 por IAID) se cuenta
  como `skipped`. `client_id` opaco = `"sha256:" + 16 hex`.
- En un fallo, `errors` del complete lleva el mismo código que `dhcp.error_code`. El complete
  conserva los campos comunes existentes (`hosts_scanned`, `hosts_checked`, `probes`,
  `unprobed`) a 0, igual que `snmp_inventory`.
- Un lote de `leases` respeta además `max_observations_per_batch` y `max_batch_bytes` de la
  configuración del servidor si son menores que 5000 leases.
