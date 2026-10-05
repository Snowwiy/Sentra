# Agent protocol (v1)

How a Sentra agent talks to the API. JSON over HTTP, base path `/api/v1`.
All timestamps are ISO 8601 **with timezone offset**; the server stores them in UTC.

## Identity and authentication

- On first run the agent generates a random UUID (`agent_id`) and keeps it locally.
- **Enrollment** (`POST /agents/register`) needs one of two credentials:
  - **Recommended: a one-time enrollment token** in the header `X-Enrollment-Token`. An
    operator creates it on the server (dashboard Agentes page, `python -m app.cli
    create-enrollment-token`, or `POST /api/v1/agent-enrollment-tokens` with `X-Admin-Key`). It starts with `sentra_et_`,
    expires after `ENROLLMENT_TOKEN_TTL_MINUTES` (15 by default), works for one agent by
    default (`max_uses`), can be restricted to a platform (`windows`/`linux`) and a hostname,
    and can be revoked while unused. The server stores only its SHA-256 hash and consumes it
    in the same transaction as the enrollment (a row lock stops two hosts racing with one
    token). Unknown, expired, revoked, used-up and mismatching tokens all answer the same 401
    "Invalid enrollment token"; the reason is in the server log (token id, never the token).
    When this header is present the shared key is not consulted.
  - **Legacy: the shared key** in `X-Enrollment-Key` (the server's `AGENT_ENROLLMENT_KEY`).
    Still supported for existing installations. Without a configured key, key-based
    enrollment answers 403; token-based enrollment still works.
- The one-time token is **only** an enrollment credential. Heartbeat, telemetry, inventory,
  processes and events accept nothing but the per-agent token.
- Enrollment returns an `agent_token` **once**. The server stores only its SHA-256 hash.
- Every other agent call sends `Authorization: Bearer <agent_token>` and its `agent_id`.
  Unknown agent, missing token and wrong token all answer 401 (no hint about which).
- Enrolling an existing `agent_id` again (valid key required) rotates its token (200) and keeps
  the asset and its history. This is how an agent recovers after losing its token.
- **Revocation** is per agent and done by an operator on the server
  (`python -m app.cli revoke-agent <asset_id>`, `reinstate-agent`, `list-agents`). It deletes
  the token hash: the agent gets 401, tries to enroll and receives **403 `agent_revoked`**
  until reinstated. Other agents and the enrollment key are unaffected. The revocation state
  is only revealed to callers holding a valid enrollment key.
- The server records `agent_token_issued_at` for a future rotation policy (not enforced yet).
- The agent keeps the token encrypted with DPAPI (Windows) and never logs it.
- Agent side: the one-time token comes from `SENTRA_AGENT_ENROLLMENT_TOKEN` or, preferably,
  a file (`enrollment_token_file` / `--enrollment-token-file`; not a command-line value,
  which other users can see). After a successful enrollment, or when the server refuses
  the token, the agent forgets it and deletes the file; it is tried at most once per run.
- The server assigns a separate public `asset_id` used by the UI and query endpoints.

## Lifecycle

```
start ─► POST /agents/register      (only when the agent has no token)
every 30 s ─► POST /agents/heartbeat
           └► POST /telemetry       (buffered samples first, oldest first)
every 60 s ─► POST /events          (new Windows Event Log warnings/errors)
          └► POST /processes       (processes_interval_seconds, default 60)
every 15 min ─► POST /inventory
any 401 ─► enroll again with the same agent_id, retry once
403 / enrollment 401 ─► stop, log reason, retry at max backoff (300 s)
5xx, 408, 409, 429, network ─► exponential backoff + jitter, buffer samples (Retry-After honored)
```

The server reports an asset `offline` after `HEARTBEAT_TIMEOUT_SECONDS` (default 90) without
contact. Every authenticated agent call counts as contact (heartbeat, telemetry, events,
inventory, processes): it sets the asset `online` and resolves its offline alert. `last_seen_at`
never moves backwards, so a delayed or out-of-order request cannot make a live asset look
older than it is.

## POST /agents/register

Header `X-Enrollment-Key: <key>`.

```json
{
  "agent_id": "3f6c1c1e-6b1a-4c55-9e0e-2a7f1c9d8b10",
  "hostname": "PC-ADMIN-01",
  "os_name": "Windows",
  "os_version": "11 (build 10.0.26200)",
  "architecture": "AMD64",
  "primary_ip": "192.168.1.20",
  "agent_version": "0.1.0",
  "installation_method": "windows_service"
}
```

`installation_method` (Fase 4F) es opcional: lo envían solo los agentes instalados por un
instalador que lo configura (`windows_service`); patrón `^[a-z][a-z0-9_]{0,31}$`. Si un
servidor anterior lo rechaza (422 `extra_forbidden`), el agente deja de enviarlo en esa
ejecución y sigue funcionando.

| Status | Meaning |
|--------|---------|
| 201 | New agent. Body: `asset_id`, `agent_id`, `status` (`unknown`), `first_seen_at`, `agent_token` |
| 200 | Existing agent re-enrolled; same body with a new `agent_token` (old one revoked) |
| 401 | Missing or wrong enrollment key |
| 403 | Enrollment disabled on the server (`forbidden`) or agent revoked (`agent_revoked`) |
| 422 | Invalid payload (unknown fields are rejected) |

## POST /agents/heartbeat

`{"agent_id": "...", "host": {...}}` → 200 with `asset_id`, `status` (`online`), `last_seen_at`.
`host` is optional (same fields as registration minus `agent_id`) and refreshes the asset's
hostname, OS, IP, agent version and installation method (null when the agent no longer
reports it).

## POST /telemetry

```json
{
  "agent_id": "3f6c1c1e-6b1a-4c55-9e0e-2a7f1c9d8b10",
  "sample_id": "9b2f0c1e-0d4a-4f3e-8c55-1f2e3d4c5b6a",
  "timestamp": "2026-10-04T01:30:00+00:00",
  "cpu_percent": 24.0,
  "ram_percent": 61.0,
  "disk_percent": 48.0,
  "uptime_seconds": 86400
}
```

Percentages within 0–100, `uptime_seconds` ≥ 0, `timestamp` with offset and at most 5 minutes in
the future. Every sample is stored (history). `sample_id` (optional UUID, generated by the
agent once per sample) makes retries idempotent: resending the same id answers 201 with
`"stored": false` and writes nothing. 201, 401, 413, 422.

## POST /events

`{"agent_id": "...", "events": [...]}` with 1–500 events:
`source` (`windows_eventlog`), `channel`, `record_id`, `event_code`, `provider`,
`level` (`info|warning|error|critical`), `message` (≤ 4000 chars), `occurred_at`, and
optionally `computer` (the `<Computer>` name recorded in the event, ≤ 255 chars).
Opcional desde la Fase 4H: `data`, objeto con campos estructurados del evento (máximo 16; claves
`[A-Za-z][A-Za-z0-9 _.-]{0,63}`; valores texto ≤ 512 sin NUL). El agente solo envía los campos de
una lista permitida por canal y evento (`DATA_FIELDS` en `agent/sentra_agent/events.py`) y
nunca el contenido de scripts. Los usa el motor de detección (docs/detection-engine.md). Un
servidor anterior a la 4H rechaza `data` (422): actualizar el servidor antes que los agentes.
Idempotent per (`asset`, `channel`, `record_id`): resending a batch stores nothing twice; the
response reports `received` and `stored`. 201, 401, 422. Only newly stored events feed the
event-based alerts (critical events, error bursts), so a resend never counts twice.

Channels read by the Windows agent: `System` and `Application` (warning and above, plus
System 104 "log cleared" and 7045 "service installed"), `Security` (a fixed list of account,
group, logon-failure and audit events; needs administrator rights, otherwise reported once in
the agent log as unavailable and skipped) and `Microsoft-Windows-PowerShell/Operational`
(warning and above, **without the message text**, which can contain script code) y, desde la
Fase 4H, `Microsoft-Windows-Windows Defender/Operational` (1116–1119, 5001, 5010, 5012) y
Security 4624 solo para inicios interactivos, RDP y con credenciales en caché (tipos 2, 10 y
11; consulta con cursor propio `Security:4624`).

## POST /inventory

Body: `agent_id`, `collected_at` and the lists `interfaces`, `users`, `processes`, `services`,
`software`, `disks`, `connections`, `accounts`, plus the object `network` (fields and limits in
`backend/app/schemas/inventory.py`). The newest snapshot per asset wins; an older
`collected_at` never overwrites a newer one. 201, 401, 422.

- `services[]`: `name`, `display_name`, `status`, `start_type`, `pid` (optional).
- `software[]`: `name`, `version`, `publisher`, `install_date` (`YYYY-MM-DD`, optional),
  `architecture` (≤ 16 chars, optional).
- `accounts[]`: local accounts with `name`, `enabled`, `is_admin`, `last_logon` (all but `name`
  nullable when the host does not tell). **Never passwords, hashes, tokens or other secrets.**
- `network`: `{"gateways": [...], "dns_servers": [...]}` (IPv4/IPv6 addresses, ≤ 16 each).

When a snapshot replaces an older one, the server records the differences in
`GET /assets/{id}/changes`: services added/removed/started/stopped/start type changed,
software added/removed/version changed, accounts added/removed/enabled/disabled/admin
granted/revoked. An empty or missing section is not compared (a failed collector is not
"everything removed"); start/stop is only recorded for automatic services and not during the
first 10 minutes after boot. A watched service that is not running opens a `service_stopped`
alert; an administrator change opens `admin_changed`.

## POST /processes

```json
{
  "agent_id": "3f6c1c1e-6b1a-4c55-9e0e-2a7f1c9d8b10",
  "collected_at": "2026-10-04T01:30:00+00:00",
  "processes": [
    {"pid": 4242, "ppid": 812, "name": "chrome.exe", "exe": "C:\\Program Files\\...\\chrome.exe",
     "username": "PC\\ana", "cpu_percent": 3.1, "memory_bytes": 104857600,
     "started_at": "2026-10-04T00:10:00+00:00", "status": "running"}
  ]
}
```

At most 2000 processes. `cpu_percent` is 0–100 of the whole machine (null on the first
sample of a process). Only the latest snapshot per asset is kept (no history): 201 with
`"stored": false` when a newer one is already stored. 201, 401, 422.

## Compatibility between agent and server versions

Upgrade the **server first**. An agent newer than its server still works: when a 422 consists
only of `extra_forbidden` errors, the agent drops those fields (top-level sections or nested
item fields) and retries once, remembering them for the rest of the run; a 404 on
`/processes` disables process snapshots until the agent restarts.

## Limits

Request bodies above `MAX_REQUEST_BYTES` (default 4 MiB) are refused with 413
`payload_too_large`, before authentication.

Strings must not contain NUL (U+0000): PostgreSQL cannot store it, so any field carrying it is
refused with 422 `validation_error` (pointing at the field). The agent removes NUL from the OS
strings it reports (inventory) so one malformed value does not cost the whole snapshot.

## Request ids and response headers

`X-Request-ID` is echoed back and logged when it is 1–128 characters of `A-Z a-z 0-9 . _ : -`;
any other value is replaced by a server-generated UUID. Responses carry
`Cache-Control: no-store` (enrollment answers with the agent token) and
`X-Content-Type-Options: nosniff` (an unhandled 500 is answered before that layer and may lack
them).

## Errors

```json
{"error": {"code": "unauthorized", "message": "Invalid or missing agent credentials"}}
```

Validation errors add `details` with the failing fields.
