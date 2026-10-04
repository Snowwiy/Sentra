"""Agentless monitoring (MONITORED assets): contracts for future remote collectors.

Nothing here collects yet. The contracts fix the rules every adapter must follow before it
is implemented:

- READ ONLY. An adapter only reads state (inventory, services, events, counters). It never
  changes configuration, starts/stops services, installs software, enables WinRM, opens
  firewall ports or edits policies on the remote host.
- Credentials are never stored or passed around in plain text. Adapters receive a
  `CredentialRef` (an opaque reference) and ask a `SecretProvider` for the secret at the
  moment of use; no provider is shipped yet (see docs/agentless.md for the options).
- Explicit opt-in per asset: no adapter runs against a host just because discovery saw a
  port open (5985 open does not mean "use WinRM there").
- Same output shape as the agent: collectors return data in the agent inventory format
  (app/schemas/inventory.py) so the existing change detection and alert rules apply.
"""
