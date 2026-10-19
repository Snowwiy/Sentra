#!/bin/bash
# Desinstala Sentra Agent de este Mac.
#
#   sudo /Library/Sentra/Agent/share/uninstall-sentra-agent.sh          # para y quita el
#        LaunchDaemon y el runtime; CONSERVA configuración, identidad (y su token en el
#        keychain del sistema) y logs
#   sudo /Library/Sentra/Agent/share/uninstall-sentra-agent.sh --purge  # además borra
#        configuración, identidad, el token del keychain del sistema y los logs
#
# Sin --purge una reinstalación conserva la identidad: el equipo vuelve como el mismo activo
# sin token nuevo. Con --purge hay que enrolar otra vez (y el activo antiguo se puede revocar
# en el servidor: python -m app.cli revoke-agent <asset_id>).
#
# El token se borra con `security delete-generic-password`, que nunca recibe ni muestra el
# secreto (solo el servicio com.sentra.agent).
# Gancho de tests: SENTRA_ROOT, como en install-sentra-agent.sh.

set -euo pipefail

ROOT="${SENTRA_ROOT:-}"
LABEL="com.sentra.agent"
PREFIX="$ROOT/Library/Sentra/Agent"
LOG_DIR="$ROOT/Library/Logs/Sentra"
SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"
PURGE=0

say() { printf 'sentra-agent: %s\n' "$*"; }
die() { printf 'sentra-agent: ERROR: %s\n' "$*" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1 (use --purge to delete everything)" ;;
  esac
done

[ "$(id -u)" = "0" ] || die "run as root (sudo)"

if launchctl print "system/$LABEL" >/dev/null 2>&1; then
  launchctl bootout "system/$LABEL" 2>/dev/null || true
fi
launchctl disable "system/$LABEL" 2>/dev/null || true
rm -f "$ROOT/Library/LaunchDaemons/$LABEL.plist" "$ROOT/etc/newsyslog.d/$LABEL.conf"
rm -rf "$PREFIX/lib" "$PREFIX/bin" "$PREFIX/share" "$PREFIX/VERSION"
# Recibo del .pkg (si se instaló así): sin él, macOS no cree que siga instalado.
pkgutil --forget "$LABEL" >/dev/null 2>&1 || true
say "LaunchDaemon and runtime removed"

if [ "$PURGE" = "1" ]; then
  # Todos los elementos del servicio (uno por agent_id que haya tenido este equipo).
  removed=0
  while security delete-generic-password -s "$LABEL" "$SYSTEM_KEYCHAIN" >/dev/null 2>&1; do
    removed=$((removed + 1))
    [ "$removed" -lt 50 ] || break
  done
  rm -rf "$PREFIX" "$LOG_DIR"
  rmdir "$ROOT/Library/Sentra" 2>/dev/null || true
  say "purged: configuration, identity, $removed keychain item(s) and logs are gone"
else
  say "kept: $PREFIX/agent.toml (config), $PREFIX/state (identity; token in the System keychain), $LOG_DIR (logs)"
  say "reinstalling keeps this identity; use --purge to delete them"
fi
