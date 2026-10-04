# Agent management from the dashboard

The **Agentes** page of Sentra Web enrolls, watches and revokes agents without the backend
CLI. It reuses the one-time enrollment tokens (Fase 4A) and the Linux installer (Fase 4B).

## Enabling it (once)

In the root `.env` of the Sentra server, then restart the API:

```ini
DASHBOARD_ADMIN_ENABLED=true
# Optional: URL the agents use to reach this server (shown in the install command).
# Unset: suggested from this machine's network addresses.
# AGENT_SERVER_URL=http://192.168.50.201:8000
```

`CORS_ORIGINS` must list the dashboard origin (the default `.env.example` lists
`http://localhost:5173`). To let agents on other machines reach the API, it must listen on
the network: `.\scripts\start_backend.ps1 -BindHost 0.0.0.0` (and allow the port in the
firewall). The dashboard itself is still opened **on the server**, at `http://localhost:5173`.

## Add a Linux agent

1. **Agentes → + Añadir agente → Linux → Continuar.** Windows shows "Próximamente" until its
   installer exists.
2. Check the **server URL** (suggested, editable; never `localhost`, which on the Linux host
   is the Linux host itself). Over `http://` the page warns: *HTTP no cifra las credenciales
   durante el transporte. Use HTTPS en producción.* It is allowed (LAN/development).
3. Optionally set the **expected hostname**: the token then only enrolls a host reporting
   that name.
4. **Generar token de instalación**: a one-time token for platform `linux`, one use, 15
   minutes (`ENROLLMENT_TOKEN_TTL_MINUTES`). It is shown **once**, with the warning *Este token
   solo puede utilizarse una vez y expira en 15 minutos.* and a countdown.
5. Copy the commands to the Linux machine (with the package copied there):
   - **Recommended (file)**: the token is pasted at a silent prompt into a `0600` file
     (`enrollment.token`), then `sudo ./install-sentra-agent.sh --server … --token-file
     ./enrollment.token`. The token never appears in a command line, the shell history or
     `ps`; the installer deletes the file once enrolled.
   - **Quick (`--token`)**: one command with the token in it. It stays in the shell history;
     the page says so.
   - Tarball or `.deb` (`sudo sentra-agent-setup …`).
6. The installer enrolls the host and starts the `sentra-agent` systemd service. The dialog
   checks the token every 5 s and shows **Equipo registrado** with a link to the asset; the
   token becomes **Consumed** and can never be used again. The agent appears **Online /
   Managed** with CPU, RAM and disk as soon as it reports (the page refreshes by itself every
   15 s).

## What the page shows

- Cards: **Total, Online, Offline, Revoked, Pending** (enrolled, not reported yet). Revoked
  agents are counted only as revoked.
- Agents: hostname, IP, OS, platform, agent version, state, last contact, enrollment date,
  monitoring method, agent ID, **credential status**:
  - `Active`: the agent holds a valid token of its own;
  - `Revoked`: cut off by an operator;
  - `Re-enrollment required`: not revoked, but without a valid token (after reinstating);
    it needs a new installation token.
- **Tokens de instalación**: created, expiry, platform, expected hostname, state (`Active`,
  `Consumed`, `Expired`, `Revoked`), origin (dashboard/CLI/API) and the asset that used it.
  The token value is never listed; **Revocar** only on active tokens.
- Asset detail (managed assets), **Agent** section: agent ID, version, platform, enrolled
  at, credential issued at, last heartbeat, credential status, installation method ("No
  reportado": the agent does not report it yet). **Reiniciar agente** is disabled on purpose:
  Sentra has no remote control (monitoring only).

Nothing on the page shows agent tokens, hashes, enrollment tokens (after creation) or any
other secret; the API responses do not contain them.

## Revoke an agent

**Revocar** (table) or **Revocar agente** (detail) → confirmation: *El agente X dejará de poder
enviar telemetry, heartbeat, inventory y events.* Then:

- its token is destroyed: every call gets 401, and enrolling again is refused (403
  `agent_revoked`), even with a valid one-time token;
- **nothing is deleted**: the asset stays visible with its telemetry, events, inventory,
  changes, alerts and discovery/exposure history, for audit.

## Bring a revoked agent back (re-enrollment)

The old credential is never restored. **Reactivar…** → confirmation → the block is lifted
(credential `Re-enrollment required`) and the wizard opens with the hostname prefilled for a
**new** one-time token. Run the installer again on that host with the new token: the agent
keeps its `agent_id`, so it is the **same asset** with its history, and its credential is
`Active` again. (If the agent still holds its old, now dead, token, the installer's
enrollment step notices it with one heartbeat and enrolls with the new token.)

Reinstating alone lets nothing in: the host still needs a new token issued by the operator
(or the legacy shared key, if configured). If the host is gone, leave it revoked.

## Security model (temporary)

There is no dashboard login yet. The administration API (`/api/v1/agent-enrollment-tokens`)
stays protected by `X-Admin-Key` = `ADMIN_API_KEY` and is **not** used by the browser: the
key is not in the frontend source, the Vite build, browser storage or any request.

Instead, the dashboard calls the **console** endpoints (`/api/v1/console/...`), and the API
performs the operation itself with the same services (backend-for-frontend). They answer
only when all of these hold (`backend/app/api/console.py`):

1. `DASHBOARD_ADMIN_ENABLED=true` (off by default: `403 console_disabled`);
2. the TCP peer is loopback (`127.0.0.1`/`::1`): the browser runs on the server. Requests
   from the network get `403 console_not_local`, whatever headers they carry (including
   `X-Admin-Key`). The Vite dev server, bound to localhost, forwards as loopback;
3. the `Host` header is a loopback name (stops DNS rebinding);
4. a browser `Origin`, if sent, is in `CORS_ORIGINS` or is the API's own origin (another
   site open in the operator's browser cannot use it, not even another local one);
5. the `X-Sentra-Console: 1` header is present (forms and simple cross-site requests cannot
   set it). It is a marker, not a secret.

Limits, by design of this stopgap:

- Anyone with a session **on the server machine** can use the console (as they could read
  `.env` or run the CLI there). Do not enable it on a shared multi-user server.
- Behind a reverse proxy on the same machine, the proxy must send `X-Forwarded-For`
  (uvicorn trusts it from 127.0.0.1), or remote users would look local.
- Read endpoints (`GET /agents`, `GET /assets/{id}/agent`) are unauthenticated like the
  rest of the dashboard API, and return no secrets.

**To be replaced** by dashboard authentication with roles (RBAC) and sessions: the console
routes stay, `require_local_console` becomes a role check, and the page can then be used
from any workstation.

## API

| Method | Path | |
|---|---|---|
| GET | `/api/v1/agents` | Agents + summary (read-only, no secrets) |
| GET | `/api/v1/assets/{asset_id}/agent` | The asset's agent (404 without agent) |
| GET | `/api/v1/console` | Console available (200) or why not (403); TTL and suggested server URLs |
| POST | `/api/v1/console/enrollment-tokens` | Create a one-time token (the only response with the token) |
| GET | `/api/v1/console/enrollment-tokens` | Tokens and their state (never the token) |
| POST | `/api/v1/console/enrollment-tokens/{id}/revoke` | Revoke an unused token (409 if consumed) |
| POST | `/api/v1/console/agents/{asset_id}/revoke` | Revoke an agent (keeps its history) |
| POST | `/api/v1/console/agents/{asset_id}/reinstate` | Lift a revocation (409 if not revoked); re-enrollment required |

Console responses are `Cache-Control: no-store`, like every API response. Token creation and
agent revocation/reinstatement are logged with ids, never with the token.

The CLI keeps working for the same operations: `create-/list-/revoke-enrollment-token`,
`list-agents`, `revoke-agent`, `reinstate-agent`.
