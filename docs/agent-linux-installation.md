# Sentra Agent on Linux: installation

For Ubuntu 24.04, Linux Mint 22 and other Debian-compatible distributions with
`python3 >= 3.12` and systemd (amd64; arm64 builds are possible). The package contains only
the agent: no Sentra server code, no database, no secrets. Nothing is downloaded during
installation and no `pip`, `venv`, `git` or compiler is needed.

## 1. Get a one-time enrollment token (on the Sentra server)

```bash
cd backend
python -m app.cli create-enrollment-token --platform linux --note "PC de Ana"
```

It is shown once, expires in 15 minutes and enrolls one agent. Put it in a file on the
Linux machine, readable only by you:

```bash
umask 077; nano enrollment.token     # or copy the file over; one line, the token only
```

## 2. Install (one command)

From the tarball (`sentra-agent-<version>-linux-x86_64.tar.gz`):

```bash
tar xzf sentra-agent-*-linux-x86_64.tar.gz
cd sentra-agent-*-linux-x86_64
sudo ./install-sentra-agent.sh --server http://SERVER:8000 --token-file ../enrollment.token
```

or from the Debian package:

```bash
sudo apt install ./sentra-agent_<version>_amd64.deb
sudo sentra-agent-setup --server http://SERVER:8000 --token-file ./enrollment.token
```

The installer:

1. checks Linux, the architecture and `python3 >= 3.12`;
2. creates the system user `sentra-agent` (no login shell, no home);
3. installs the runtime in `/opt/sentra-agent` and writes `/etc/sentra-agent/agent.toml`
   (server URL only: no secrets);
4. enrolls with the one-time token: the agent stores its **own** token in
   `/var/lib/sentra-agent/identity.json` (0600, owner `sentra-agent`) and the one-time token
   file is **deleted**;
5. installs, enables and starts the systemd service `sentra-agent` and checks it is active.

`--token TOKEN` also works, but the token then stays in your shell history: prefer
`--token-file`. If the server cannot be reached, the token file is kept so you can run the
same command again; if the server refuses the token (expired, used, revoked), create a new
one.

With `http://` the tokens travel unencrypted on your network: use `https://` in production.

## Status, logs, restart

```bash
systemctl status sentra-agent
journalctl -u sentra-agent            # also /var/log/sentra-agent/agent.log
sudo systemctl restart sentra-agent
sudo systemctl stop sentra-agent
sudo systemctl enable --now sentra-agent
```

The service starts at boot, restarts after a crash (10 s delay, at most 5 times in 5
minutes) and stops cleanly on `systemctl stop`.

To point the agent at another server: edit `api_url` in `/etc/sentra-agent/agent.toml`, then
`sudo systemctl restart sentra-agent`.

## Upgrade

```bash
sudo ./install-sentra-agent.sh --upgrade          # from the new tarball
sudo apt install ./sentra-agent_<new>_amd64.deb   # or the new .deb
```

Configuration and identity are kept: no new token is needed and the host stays the same
asset in Sentra. Running the normal install again on an enrolled host also keeps the
identity (the token is not used).

## Uninstall

```bash
sudo /opt/sentra-agent/uninstall-sentra-agent.sh           # or ./uninstall-sentra-agent.sh
sudo /opt/sentra-agent/uninstall-sentra-agent.sh --purge
```

| | uninstall | `--purge` |
|---|---|---|
| service and runtime (`/opt/sentra-agent`, unit) | removed | removed |
| `/etc/sentra-agent` (configuration) | kept | deleted |
| `/var/lib/sentra-agent` (identity, agent token, buffer) | kept | deleted |
| `/var/log/sentra-agent` (logs) | kept | deleted |
| user `sentra-agent` | kept | deleted |
| reinstall later | same asset, no token needed | needs a new token; new asset |

With the .deb: `sudo apt remove sentra-agent` (= uninstall) or `sudo apt purge sentra-agent`.
After a purge you can revoke the old agent on the server:
`python -m app.cli revoke-agent <asset_id>`.

## Files

| Path | Owner / mode | Contents |
|---|---|---|
| `/opt/sentra-agent/` | root, 0755 | runtime (agent + psutil), launcher, uninstaller |
| `/etc/sentra-agent/agent.toml` | root:sentra-agent, 0640 | server URL and paths (no secrets) |
| `/var/lib/sentra-agent/` | sentra-agent, 0700 | identity and agent token (0600), telemetry buffer, event cursor |
| `/var/log/sentra-agent/` | sentra-agent, 0750 | rotating log, 5 × 1 MB |
| `/etc/systemd/system/sentra-agent.service` | root, 0644 | service (`/lib/systemd/system/` with the .deb) |

## Privileges

The service runs as the unprivileged user `sentra-agent` with no capabilities and systemd
hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, …). Everything the
dashboard shows by default works like this (CPU, RAM, disk, uptime, heartbeat, interfaces,
services, packages, local accounts, listening ports). Without root some details of **other
users'** processes are not readable and are reported empty rather than guessed: executable
path, process owner on some kernels, and the PID behind another user's network socket.
Account lock state (from `/etc/shadow`) is reported as unknown. Running the agent as root is
not needed and not done by the installer.

## Machines where the agent was run by hand before

A manual run (`python -m sentra_agent`) keeps its identity in `~/.local/state/sentra-agent`;
the service uses `/var/lib/sentra-agent`, so installing the package creates a **new** asset
unless you carry the identity over **before** the first start:

```bash
# Stop the manual run first, then (no token: it is not needed to keep an identity):
sudo ./install-sentra-agent.sh --server http://SERVER:8000   # stops at "not enrolled yet"
sudo install -o sentra-agent -g sentra-agent -m 0600 ~/.local/state/sentra-agent/identity.json \
  /var/lib/sentra-agent/identity.json
sudo ./install-sentra-agent.sh --server http://SERVER:8000   # "already enrolled": starts
```

Otherwise revoke the old asset on the server (`python -m app.cli revoke-agent <asset_id>`).
Never run the manual agent and the service with the same identity at the same time.

## Running by hand (development)

`python -m sentra_agent` from `agent/` keeps working as before for development and debugging.

## Building the package

```bash
agent/packaging/linux/build.sh                 # dist/*.tar.gz, *.deb and .sha256
agent/packaging/linux/build.sh --arch aarch64
```

`dist/` is not tracked by git. Builds are reproducible (fixed timestamps, sorted archive,
pinned psutil wheel).

## Status of validation

Validated in a Linux container (Ubuntu 24.04, root, **without** systemd as PID 1): build,
installation with the real `useradd`/`runuser`, enrollment against a real Sentra server as
the `sentra-agent` user, permissions, agent running as that user and reporting, upgrade
keeping the identity, uninstall and purge, `.deb` install/remove/purge, and
`systemd-analyze verify` of the unit. **Pending physical validation**: the service actually
started by systemd at boot on a real machine (enable/restart/stop/reboot) and the effect of
the hardening options there.
