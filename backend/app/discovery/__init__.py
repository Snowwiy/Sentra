"""Agentless network discovery: find hosts on explicitly authorized networks.

Defensive inventory only. Hosts are found with ordinary, non-invasive means: a full TCP
connect (immediately closed, nothing sent), the system `ping`, the operating system's own
neighbour (ARP) table and reverse DNS. No raw packets, no stealth or fragmented scans, no
banner grabbing, no credentials. Every target must be inside DISCOVERY_ALLOWED_NETWORKS
(see targets.py); nothing is scanned when that list is empty, which is the default.

Modules:
- targets: allowlist parsing and validation, host enumeration;
- ports: port profiles and port-number service hints;
- probes: TCP connect, ping, neighbour table, reverse DNS, default gateways;
- scanner: bounded, rate-limited, cancellable asyncio scan;
- classify: conservative device-type inference from what was observed.
"""
