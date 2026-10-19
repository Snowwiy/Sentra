#!/bin/bash
# Diagnóstico de Sentra Agent en macOS: estado del LaunchDaemon, versión, configuración,
# identidad, Keychain, Python, conectividad y últimas líneas del log.
#
#   sudo /Library/Sentra/Agent/share/diagnose-sentra-agent.sh
#
# Solo lee. Nunca muestra secretos: de identity.json solo agent_id, asset_id y el tipo de
# almacén del token; del Keychain solo si existe el elemento (sin -w ni -g, que mostrarían el
# secreto); el log del agente ya llega con los secretos redactados.
# Gancho de tests: SENTRA_ROOT, como en install-sentra-agent.sh.

set -uo pipefail

ROOT="${SENTRA_ROOT:-}"
LABEL="com.sentra.agent"
PREFIX="$ROOT/Library/Sentra/Agent"
CONFIG_FILE="$PREFIX/agent.toml"
IDENTITY="$PREFIX/state/identity.json"
LOG_DIR="$ROOT/Library/Logs/Sentra"
SYSTEM_KEYCHAIN="/Library/Keychains/System.keychain"

section() { printf '\n== %s ==\n' "$*"; }

[ "$(id -u)" = "0" ] || { echo "run as root (sudo) to read the daemon state" >&2; exit 1; }

section "System"
sw_vers 2>/dev/null || echo "sw_vers unavailable"
echo "hardware arm64: $(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)"

section "Agent"
if [ -f "$PREFIX/VERSION" ]; then cat "$PREFIX/VERSION"; else echo "not installed ($PREFIX/VERSION missing)"; fi
if [ -x "$PREFIX/bin/sentra-agent" ]; then
  echo "launcher: $(sed -n 's/^exec "\([^"]*\)".*/python: \1/p' "$PREFIX/bin/sentra-agent")"
  "$PREFIX/bin/sentra-agent" --version 2>&1 | head -1 | sed 's/^/runtime version: /'
fi

section "LaunchDaemon"
if daemon="$(launchctl print "system/$LABEL" 2>&1)"; then
  printf '%s\n' "$daemon" | grep -E '^[[:space:]]*(state|pid|last exit code|runs) =' || true
else
  echo "not loaded (sudo launchctl bootstrap system /Library/LaunchDaemons/$LABEL.plist)"
fi

section "Configuration"
if [ -f "$CONFIG_FILE" ]; then
  # Solo claves sin secretos (la configuración generada no tiene ninguno).
  grep -E '^(api_url|state_dir|log_dir|credential_store|wireless_enabled|installation_method)' \
    "$CONFIG_FILE"
else
  echo "missing: $CONFIG_FILE"
fi

section "Identity"
if [ -f "$IDENTITY" ]; then
  sed -n -E 's/^ *"(agent_id|asset_id|scheme|token_issued_at)": *"?([^",]*)"?,?$/\1: \2/p' "$IDENTITY"
else
  echo "no identity yet (not enrolled)"
fi
if security find-generic-password -s "$LABEL" "$SYSTEM_KEYCHAIN" >/dev/null 2>&1; then
  echo "keychain: item for $LABEL present in the System keychain"
else
  echo "keychain: no item for $LABEL in the System keychain"
fi

section "Connectivity"
API_URL="$(sed -n 's/^api_url = "\(.*\)"/\1/p' "$CONFIG_FILE" 2>/dev/null)"
if [ -n "$API_URL" ]; then
  # Solo la comprobación pública de salud: sin token. curl verifica el certificado.
  code="$(curl -sS -m 10 -o /dev/null -w '%{http_code}' "$API_URL/api/v1/health" 2>&1)"
  echo "GET $API_URL/api/v1/health -> $code"
fi

section "Recent log (redacted by the agent)"
tail -n 20 "$LOG_DIR/agent.log" 2>/dev/null || echo "no $LOG_DIR/agent.log yet"
tail -n 5 "$LOG_DIR/launchd.log" 2>/dev/null || true
