# Hybrid monitoring: network discovery and agentless preparation

Sentra knows hosts in two complementary ways:

| Method | Label in the UI | What Sentra knows |
|---|---|---|
| `discovered` | **Discovered** | What can be observed from the Sentra server over the network: address, MAC (same segment only), reverse DNS name, reachable TCP ports, probable type |
| `agentless` | **Monitored** | Reserved for remote collection without agent (WinRM/WMI, SSH, SNMP). Contracts only, nothing collects yet |
| `agent` | **Managed** | Everything the Sentra agent reports (telemetry, inventory, processes, events) plus the network view |

The path is DISCOVERED → MONITORED → MANAGED. Installing the agent on a discovered host
does not create a second asset: both records converge into one (see Reconciliation).

The agent-based flow is unchanged: agents use the same protocol and see no difference.

## Safety rules (read first)

- **Nothing is probed unless you list networks** in `DISCOVERY_ALLOWED_NETWORKS`. The
  default is empty: discovery is disabled.
- Refused at startup (the API does not start with an invalid allowlist) and for every
  target: `0.0.0.0/0`/`::/0`, networks larger than `DISCOVERY_MAX_HOSTS_PER_NETWORK`
  (default 1024 addresses, hard cap 65536), multicast/reserved/unspecified/broadcast space,
  networks with host bits set (`192.168.1.10/24`), and **public Internet space** unless
  `DISCOVERY_ALLOW_PUBLIC_NETWORKS=true`.
- An explicit target (`discover --target`) must be inside an allowed network.
- `DISCOVERY_EXCLUDED` addresses are never probed.
- What a probe is: a full TCP connect that is closed immediately (no data sent, no banner
  read), one ICMP echo through the operating system's `ping`, a read of the server's own
  neighbour (ARP) table, and a reverse DNS lookup. **No** raw packets, SYN/stealth scans,
  fragmentation, spoofing, evasion, banner grabbing, OS fingerprinting, credentials,
  brute force or exploitation. No elevated privileges are needed or requested.
- Load is bounded: `DISCOVERY_CONCURRENCY` probes in flight (default 64),
  `DISCOVERY_MAX_PROBES_PER_SECOND` started per second (default 200), a timeout per probe
  (`DISCOVERY_TIMEOUT_MS`, default 800) and per run (`DISCOVERY_JOB_TIMEOUT_MINUTES`).
- Runs are started from the server (CLI) or by the periodic job, **never over HTTP**: the
  dashboard has no authentication yet, and probing the network is an active operation.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `DISCOVERY_ALLOWED_NETWORKS` | empty (off) | Comma separated CIDRs/addresses Sentra may probe |
| `DISCOVERY_EXCLUDED` | empty | Addresses/networks never probed |
| `DISCOVERY_ALLOW_PUBLIC_NETWORKS` | `false` | Allow globally routable ranges you own |
| `DISCOVERY_MAX_HOSTS_PER_NETWORK` | `1024` | Largest network accepted (1–65536) |
| `DISCOVERY_PORTS` | `common` | Profiles `minimal`, `common`, `windows`, `printers`, `web` and/or ports and ranges (`common,8081,9000-9005`, max 1024 ports) |
| `DISCOVERY_TIMEOUT_MS` | `800` | Per probe (50–10000) |
| `DISCOVERY_CONCURRENCY` | `64` | Probes in flight (1–256) |
| `DISCOVERY_MAX_PROBES_PER_SECOND` | `200` | Rate limit (1–5000) |
| `DISCOVERY_ICMP` | `true` | Use the system `ping` (skipped automatically if missing) |
| `DISCOVERY_REVERSE_DNS` | `true` | Reverse lookups of live hosts |
| `DISCOVERY_INTERVAL_MINUTES` | unset (manual) | Periodic runs over every allowed network (≥ 5) |
| `DISCOVERY_JOB_TIMEOUT_MINUTES` | `30` | A run stops here; its results are kept as partial |
| `DISCOVERY_OFFLINE_AFTER_MISSES` | `3` | Complete runs without seeing a host before it is offline |

Example (`.env`):

```
DISCOVERY_ALLOWED_NETWORKS=192.168.1.0/24,10.0.10.0/24
DISCOVERY_EXCLUDED=192.168.1.250
DISCOVERY_INTERVAL_MINUTES=60
```

## Running it

```powershell
cd backend
.venv\Scripts\python.exe -m app.cli discovery-scope          # what would be probed (no probing)
.venv\Scripts\python.exe -m app.cli discover                 # every allowed network, now
.venv\Scripts\python.exe -m app.cli discover --target 192.168.1.0/28
```

Each run over one network is a **job** (`GET /api/v1/discovery/jobs`): start/end time,
network, hosts scanned/up/new, open ports, probes, errors, duration, whether it was the
baseline. A database index allows only one running job per network, so two schedulers,
API workers or a manual run cannot scan the same network at the same time. A job left
"running" by a crashed process is marked failed after twice the job timeout.

A /24 with the `common` profile (27 ports) takes about 35 s at the default rate limit
(6858 probes; measured on loopback, where every address answers). Dead addresses cost
little: only a few liveness ports are tried before the full port list, and only for live
hosts.

## What a run does

1. **Liveness** per address: ping (if available) and a TCP connect to a few likely ports.
   An echo reply, an accepted connection or a refusal (RST) proves the host is up.
2. **Neighbour table**: complete entries mark silent hosts on the same segment as up and
   give their MAC.
3. **Ports and name**: the remaining configured ports and reverse DNS, for live hosts.
4. **Persistence**: hosts are matched to existing assets, ports compared with the baseline,
   changes and alerts recorded.

### Baseline and changes

- The **first complete run of a network** records what is there and raises **no** alert;
  so does the first port scan of any single asset. This avoids hundreds of alerts on day one.
- Later runs record changes in the asset's change history (category `exposure` or
  `network`) and raise alerts:

| Rule | Severity | When |
|---|---|---|
| `asset_discovered` | info | A new host with a name or a probable type appears |
| `unknown_device` | warning | A new host with neither appears ("previously unknown device") |
| `asset_disappeared` | warning | A discovered host was not seen for `DISCOVERY_OFFLINE_AFTER_MISSES` complete runs (resolves when seen again) |
| `port_exposed` | critical for remote administration, file sharing and databases (22, 23, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 5985/5986, 6379, 9200, 27017), warning otherwise | A port became reachable |
| `port_closed` | info | A port open before was not reachable in 2 consecutive complete runs of a live host |
| `monitoring_lost` | warning | An agent asset answers on the network but its agent stopped reporting (resolves with the next agent contact) |

An open port is a **signal of exposure or change, not an attack**. While a port stays open
it raises nothing more; `port_exposed`/`port_closed`/new-asset alerts resolve themselves
after `ALERT_EVENT_QUIET_MINUTES` without new occurrences, like event-based alerts.

Negative conclusions (port closed, host gone) are only drawn from **complete** runs: a
cancelled or timed-out run did not probe everything.

### Device type

Only from evidence, always with the reason shown, otherwise unknown (null):

- reported by the agent (Windows / Linux);
- default gateway of the Sentra server → network device;
- 9100 (JetDirect) or 515 (LPD) open → printer;
- 135 (MSRPC), 3389 (RDP) or 5985/5986 (WinRM) open → Windows.

SSH alone, or web ports alone, say nothing reliable and are not guessed. The vendor (OUI)
column stays empty until an OUI database is added. Service names next to ports are the
IANA name for the port number (a hint: the service is never contacted).

### Reconciliation (one asset per host)

- Discovery matches a host to an existing asset by **MAC** first (including the MACs of
  the agent's network interfaces), then by **address** when the MACs do not contradict each
  other. The same address with a different known MAC is another device (e.g. DHCP reuse).
- When an agent enrolls (by address) or sends its inventory (by interface MACs and
  addresses), a matching discovered record is **merged** into the agent's asset: first
  discovery time, ports and their baseline, change history and alerts move over, and the
  discovered record is deleted. Ambiguous matches (several candidates) are not merged and
  are logged.
- Agent data (hostname, OS…) is never overwritten by network observations.

### Agent + network correlation

`GET /api/v1/assets/{id}/exposure` (tab **Exposure**) shows each reachable port with the
process the agent sees listening on it (PID, name, executable and user from the process
snapshot), and the agent's listening ports with whether the network can reach them
(reachable / not reachable, e.g. bound to 127.0.0.1 or firewalled / not probed because the
port is not in `DISCOVERY_PORTS`).

## Agentless monitoring (prepared, not implemented)

`backend/app/agentless/` defines the contracts every future remote collector must follow:

- **Read only**: there is no write/execute capability in the contract. Adapters never
  enable WinRM, change TrustedHosts, firewall rules or policies, start/stop services or
  install anything.
- **Credentials**: adapters receive a `CredentialRef` (an opaque id, never the secret) and
  ask a `SecretProvider` at the moment of use; `Secret` values do not appear in `repr` or
  logs. No provider is shipped, so nothing can authenticate yet. Options to decide later:
  Windows Credential Manager/DPAPI on the Sentra server, an OS keyring, or HashiCorp Vault.
  Never plain text in `.env` or the database.
- **Explicit opt-in per asset**: an open 5985 port is not a reason to try WinRM.
- **Same data shape as the agent**, so change detection and alert rules apply unchanged.

Planned adapters and their read-only operations are listed in `app/agentless/adapters.py`:
WinRM, WMI/CIM, remote Event Log, SSH (systemd, journald, dpkg/rpm), SNMP (switches,
routers, printers, access points, UPS, NAS; SNMPv3 authPriv preferred, never SET).
Discovery does not depend on any of them.

## 🪟 VALIDACIÓN LOCAL EN WINDOWS

Tested here on Linux (real TCP on loopback; Windows tool output from captured samples):

- `PING.EXE` success detection (needs "TTL=" in the reply; exit code alone lies), `ARP.EXE -a`
  and `ROUTE.EXE print -4` parsing in Spanish/English.
- Windows connect error codes (10061 refused, 10051/10065 unreachable).
- **Sentra server on Windows: refusals arrive late.** Windows retries the SYN after a RST
  before reporting "connection refused" (about 1–2 s; confirmed on Windows 11 loopback, where
  a probe with a 1 s timeout returns `filtered`). With the default `DISCOVERY_TIMEOUT_MS=800`
  closed ports are therefore reported as `filtered` instead of `closed`. Consequences:
  - exposure is unaffected: open ports are found, and "port closed" counts `filtered` too;
  - liveness loses one signal: a host that only answers with refusals (no open configured
    port, no ping reply) is not seen as up, unless it is on the same segment (ARP finds it).
  - If that matters, raise `DISCOVERY_TIMEOUT_MS` (e.g. 2500) at the cost of longer scans;
    a Linux Sentra server does not have this behaviour.
- Windows Defender Firewall blocks inbound ICMP echo by default on many profiles: hosts may
  be found by TCP/ARP only.
