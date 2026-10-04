#!/usr/bin/env bash
# Remove Sentra Agent from this Linux host.
#
#   sudo ./uninstall-sentra-agent.sh           # stop + remove service and runtime; KEEP
#                                              # config, identity (agent token) and logs
#   sudo ./uninstall-sentra-agent.sh --purge   # also delete config, identity, logs and user
#
# Without --purge a later reinstall keeps the same identity: the host reappears as the same
# asset without a new enrollment token. With --purge the host must be enrolled again (and
# the old asset can be revoked on the server: python -m app.cli revoke-agent <asset_id>).
#
# Test hook: SENTRA_ROOT, as in install-sentra-agent.sh.

set -euo pipefail

ROOT="${SENTRA_ROOT:-}"
SERVICE_USER="sentra-agent"
PURGE=0

say() { printf 'sentra-agent: %s\n' "$*"; }
die() { printf 'sentra-agent: ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help)
      sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'
      exit 0 ;;
    *) die "unknown option: $1 (use --purge to delete everything)" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run as root (sudo)"

have_systemd() { [ -n "$ROOT" ] || [ -d /run/systemd/system ]; }

if have_systemd; then
  systemctl disable --now sentra-agent >/dev/null 2>&1 || true
fi
# Only the unit this installer wrote; a .deb removes its own with dpkg.
rm -f "$ROOT/etc/systemd/system/sentra-agent.service"
if have_systemd; then
  systemctl daemon-reload || true
  systemctl reset-failed sentra-agent >/dev/null 2>&1 || true
fi
rm -rf "$ROOT/opt/sentra-agent"
say "service and runtime removed"

if [ "$PURGE" = "1" ]; then
  rm -rf "$ROOT/etc/sentra-agent" "$ROOT/var/lib/sentra-agent" "$ROOT/var/log/sentra-agent"
  if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    userdel "$SERVICE_USER" || say "could not delete user $SERVICE_USER; remove it by hand"
  fi
  say "purged: configuration, identity, logs and the $SERVICE_USER user are gone"
else
  say "kept: $ROOT/etc/sentra-agent (config), $ROOT/var/lib/sentra-agent (identity), $ROOT/var/log/sentra-agent (logs)"
  say "reinstalling keeps this identity; use --purge to delete them"
fi
