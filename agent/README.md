# Sentra agent

Python agent that reports this host to the Sentra API. Windows first, Linux-compatible
(all collection goes through `psutil`). Protocol: [docs/agent-protocol.md](../docs/agent-protocol.md).

## What it does

- Generates a persistent identity (`agent_id`) on first run and enrolls with a **one-time
  enrollment token** created on the server (`SENTRA_AGENT_ENROLLMENT_TOKEN`, or better a file
  given with `--enrollment-token-file` / `enrollment_token_file`, deleted once enrolled), or
  with the legacy shared enrollment key (`SENTRA_AGENT_ENROLLMENT_KEY`), receiving its own
  token. The one-time token is used for enrollment only and forgotten afterwards. On 401 it enrolls
  again with the same identity. If the server answers 403 (agent revoked by an operator,
  enrollment disabled) or 401 to the enrollment key, it logs the reason and retries only at
  `max_backoff_seconds`.
- The token is encrypted at rest with Windows DPAPI (current-user scope, via `crypt32.dll`):
  `identity.json` holds only the encrypted blob. Older plain-text identity files are migrated on
  start. Known secrets and `Bearer ...` values are redacted from every log line.
- Every 60 s: sends new warnings/errors from the Windows Event Log (System, Application,
  PowerShell/Operational without message text) and selected Security events (account, group
  and logon-failure changes). Security needs administrator rights: as a standard user the
  agent logs once that the channel is not readable and skips it; it never changes privileges.
- Every `processes_interval_seconds` (default 60, 15–3600): sends a process snapshot (pid,
  parent, name, executable, user, CPU %, memory, start time; at most 2000). The server keeps
  only the latest one.
- Every `interval_seconds` (default 30): collects CPU, RAM, system disk and uptime, sends a
  heartbeat and the telemetry sample.
- API down (network, timeout, 5xx, 408/409/429): keeps up to `buffer_size` samples, mirrored to
  `telemetry_buffer.json` so they survive an agent restart, and retries with exponential backoff
  and jitter (30 s → 60 s → … capped at 300 s, honoring `Retry-After`); sends the buffered
  samples in order once the API is back. Each sample carries a `sample_id` fixed when it is
  measured, so a resend after a lost response is not stored twice. 413/422 are never retried.
- Sends an inventory snapshot at start-up and every 15 min: network interfaces, disks,
  logged-in users, top 100 processes by memory, services with their pid (Windows services;
  systemd units on Linux), installed software with install date and architecture (Windows
  registry, read-only; dpkg or rpm on Linux), local accounts with enabled/administrator state
  (`Get-LocalUser`/`Get-LocalGroupMember` on Windows, `/etc/passwd` + `/etc/group` on Linux;
  never passwords or hashes), default gateways and DNS servers, and network
  connections (listeners + established TCP, with owning
  process; read from the OS tables, no capture, no admin). Sections or fields the server does not know
  yet are dropped automatically (422 `extra_forbidden`) so the rest still arrives.
- JSON logs to the console and to a rotating file (5 × 1 MB).

State (identity, encrypted token, telemetry buffer, event cursor and logs) lives in `%LOCALAPPDATA%\Sentra\Agent` on Windows and
`~/.local/state/sentra-agent` on Linux.

## Install on Linux (no repository, no venv, no pip)

```bash
sudo ./install-sentra-agent.sh --server http://SERVER:8000 --token-file ./enrollment.token
```

From the tarball or `.deb` built by `packaging/linux/build.sh`: installs only the agent as the
systemd service `sentra-agent` running as the unprivileged user `sentra-agent`. Full guide,
upgrade and uninstall/purge: [docs/agent-linux-installation.md](../docs/agent-linux-installation.md).

## Run

```powershell
.\scripts\start_agent.ps1                       # foreground, Ctrl+C to stop
.\scripts\start_agent.ps1 -Once                 # single cycle
.\scripts\start_agent.ps1 -ApiUrl http://server:8000 -Interval 15
```

Configuration (`agent.example.toml`): defaults < TOML file < `SENTRA_AGENT_*` environment
variables < CLI flags.

## Development

```powershell
cd agent
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe -m ruff check .
.venv\Scripts\python.exe -m mypy sentra_agent tests
```

## Not yet

On Windows it still runs as the current user in the foreground: no Windows service,
installer or auto-update yet (Linux has a package and a systemd service, see above).
A service running under another account will re-enroll once (same `agent_id`) because the
DPAPI blob is bound to the Windows user. No mTLS; use https for non-loopback API URLs (the
agent warns otherwise).
