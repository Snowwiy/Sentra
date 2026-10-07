#!/usr/bin/env bash
# Install, enroll and start Sentra Agent on Linux (Debian/Ubuntu/Mint, amd64/arm64).
#
#   sudo ./install-sentra-agent.sh --server http://SERVER:8000 --token-file ./enrollment.token
#   sudo ./install-sentra-agent.sh --upgrade            # new version, same identity
#
# What it does (and nothing else): creates the `sentra-agent` system user, copies the agent
# runtime to /opt/sentra-agent, writes /etc/sentra-agent/agent.toml (no secrets), enrolls
# with the one-time token (the agent then holds its own token in /var/lib/sentra-agent and
# the one-time token is deleted), installs and starts the systemd service `sentra-agent`.
# No git, no pip, no venv, no downloads: the runtime is inside this package and only the
# system python3 (>= 3.12) is used.
#
# Test hook: SENTRA_ROOT=/some/dir installs under that directory instead of / (used by the
# test suite with fake systemctl/useradd/chown). Never needed in real use.

set -euo pipefail
umask 077

ROOT="${SENTRA_ROOT:-}"
SERVICE_USER="sentra-agent"
OPT_DIR="$ROOT/opt/sentra-agent"
ETC_DIR="$ROOT/etc/sentra-agent"
STATE_DIR="$ROOT/var/lib/sentra-agent"
LOG_DIR="$ROOT/var/log/sentra-agent"
CONFIG_FILE="$ETC_DIR/agent.toml"
UNIT_DIR="$ROOT/etc/systemd/system"
UNIT_FILE="$UNIT_DIR/sentra-agent.service"
ENROLL_COPY="$STATE_DIR/enrollment.token"
MIN_PYTHON="3.12"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVER=""
TOKEN_FILE=""
TOKEN_INLINE=""
UPGRADE=0
NO_START=0
PACKAGE_MODE=""   # "" (tarball), "postinst" or "configure" (the .deb owns the runtime)
PYTHON=""

say() { printf 'sentra-agent: %s\n' "$*"; }
warn() { printf 'sentra-agent: WARNING: %s\n' "$*" >&2; }
die() { printf 'sentra-agent: ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./install-sentra-agent.sh --server URL (--token-file FILE | --token TOKEN) [options]
       sudo ./install-sentra-agent.sh --upgrade [--server URL]

  --server URL       Sentra server, e.g. http://192.168.50.201:8000 (https in production)
  --token-file FILE  file with a one-time enrollment token (preferred; deleted once used)
  --token TOKEN      the token itself (discouraged: it stays in your shell history)
  --upgrade          replace the runtime, keep configuration and identity, restart
  --no-start         install and enroll, but do not enable/start the service
  --python PATH      python3 interpreter to use (>= 3.12; default: auto-detect)
  -h, --help         this help

Create the token on the server: python -m app.cli create-enrollment-token --platform linux
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) SERVER="${2:-}"; shift 2 ;;
      --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
      --token) TOKEN_INLINE="${2:-}"; shift 2 ;;
      --upgrade) UPGRADE=1; shift ;;
      --no-start) NO_START=1; shift ;;
      --python) PYTHON="${2:-}"; shift 2 ;;
      --package-postinst) PACKAGE_MODE="postinst"; shift ;;
      --package-configure) PACKAGE_MODE="configure"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
}

require_root() {
  [ "$(id -u)" = "0" ] || die "run as root (sudo)"
}

check_platform() {
  [ "$(uname -s)" = "Linux" ] || die "this installer is for Linux"
  local machine expected
  machine="$(uname -m)"
  case "$machine" in
    x86_64|amd64) machine="x86_64" ;;
    aarch64|arm64) machine="aarch64" ;;
    *) die "unsupported architecture: $machine (supported: x86_64, aarch64)" ;;
  esac
  if [ -z "$PACKAGE_MODE" ] && [ -f "$HERE/VERSION" ]; then
    expected="$(sed -n 's/^arch=//p' "$HERE/VERSION")"
    [ "$expected" = "$machine" ] || die "this package is for $expected, this host is $machine"
  fi
}

find_python() {
  local candidate
  for candidate in ${PYTHON:+"$PYTHON"} python3 python3.13 python3.12; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c "import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)" 2>/dev/null; then
      PYTHON="$(command -v "$candidate")"
      return 0
    fi
  done
  die "python3 >= $MIN_PYTHON not found (Ubuntu 24.04 / Mint 22 ship it; Debian 12 does not)"
}

check_server() {
  [ -n "$SERVER" ] || return 0
  case "$SERVER" in
    http://*|https://*) ;;
    *) die "--server must start with http:// or https:// (got: $SERVER)" ;;
  esac
  SERVER="${SERVER%/}"
  # No spaces, quotes or path tricks in what goes into the config file.
  printf '%s' "$SERVER" | grep -Eq '^https?://[][A-Za-z0-9.:_-]+(/[A-Za-z0-9._~/-]*)?$' \
    || die "--server is not a valid URL: $SERVER"
  case "$SERVER" in
    http://127.*|http://localhost*|http://\[::1\]*) ;;
    http://*) warn "the server URL is not https: tokens travel unencrypted on the network (use https in production)" ;;
  esac
}

read_token() {
  if [ -n "$TOKEN_INLINE" ] && [ -n "$TOKEN_FILE" ]; then
    die "use --token-file or --token, not both"
  fi
  if [ -n "$TOKEN_INLINE" ]; then
    warn "--token puts the token in your shell history; --token-file is preferable"
  fi
  if [ -n "$TOKEN_FILE" ]; then
    [ -f "$TOKEN_FILE" ] || die "token file not found: $TOKEN_FILE"
    [ -s "$TOKEN_FILE" ] || die "token file is empty: $TOKEN_FILE"
    TOKEN_INLINE="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  fi
  if [ -n "$TOKEN_INLINE" ]; then
    case "$TOKEN_INLINE" in
      sentra_et_*) ;;
      *) die "that is not a Sentra enrollment token (expected sentra_et_...)" ;;
    esac
  fi
}

create_user() {
  if getent passwd "$SERVICE_USER" >/dev/null 2>&1; then
    return 0
  fi
  local nologin=/usr/sbin/nologin
  [ -x "$nologin" ] || nologin=/sbin/nologin
  useradd --system --user-group --no-create-home --home-dir "$STATE_DIR" \
    --shell "$nologin" --comment "Sentra Agent" "$SERVICE_USER"
  say "created system user $SERVICE_USER (no login shell)"
}

# Fase 5C.1: leer el journal del sistema (eventos Linux) sin root. Se usa el grupo
# systemd-journal (solo lectura del journal); `adm` solo si no existe, porque además da
# lectura de /var/log. Nunca root, CAP_SYS_ADMIN ni permisos sobre los ficheros del
# journal. Sin grupo el agente sigue funcionando e informa la cobertura "no_permission".
# El grupo se aplica al (re)iniciar el servicio, que este instalador hace a continuación.
grant_journal_access() {
  local group
  for group in systemd-journal adm; do
    getent group "$group" >/dev/null 2>&1 || continue
    if id -nG "$SERVICE_USER" 2>/dev/null | tr ' ' '\n' | grep -qx "$group"; then
      return 0
    fi
    if usermod -a -G "$group" "$SERVICE_USER"; then
      say "added $SERVICE_USER to group $group (read-only access to the system journal)"
    else
      warn "could not add $SERVICE_USER to $group: Linux events will report no permission"
    fi
    return 0
  done
  warn "no systemd-journal or adm group: Linux events will report no permission"
}

create_dirs() {
  install -d -m 0755 "$OPT_DIR" "$OPT_DIR/bin"
  install -d -m 0750 "$ETC_DIR"
  chown "root:$SERVICE_USER" "$ETC_DIR"
  install -d -m 0700 "$STATE_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
  install -d -m 0750 "$LOG_DIR"
  chown "$SERVICE_USER:$SERVICE_USER" "$LOG_DIR"
}

install_runtime() {
  [ -d "$HERE/payload/lib/sentra_agent" ] || die "package payload missing next to the installer"
  # Replace the runtime in one move: never a half-copied mix of two versions.
  rm -rf "$OPT_DIR/lib.new"
  cp -R "$HERE/payload/lib" "$OPT_DIR/lib.new"
  chmod -R u=rwX,go=rX "$OPT_DIR/lib.new"
  rm -rf "$OPT_DIR/lib.old"
  [ -d "$OPT_DIR/lib" ] && mv "$OPT_DIR/lib" "$OPT_DIR/lib.old"
  mv "$OPT_DIR/lib.new" "$OPT_DIR/lib"
  rm -rf "$OPT_DIR/lib.old"
  [ -f "$HERE/VERSION" ] && install -m 0644 "$HERE/VERSION" "$OPT_DIR/VERSION"
  install -m 0755 "$HERE/uninstall-sentra-agent.sh" "$OPT_DIR/uninstall-sentra-agent.sh"
}

write_launcher() {
  local launcher="$OPT_DIR/bin/sentra-agent"
  # The runtime lives in /opt/sentra-agent/lib; -s ignores per-user site-packages so nothing
  # from a home directory can shadow it. Run by the service as the sentra-agent user.
  cat > "$launcher.new" <<EOF
#!/bin/sh
# Generated by install-sentra-agent.sh. Sentra Agent launcher (system python3).
PYTHONPATH=$OPT_DIR/lib
export PYTHONPATH
exec $PYTHON -s -m sentra_agent "\$@"
EOF
  chmod 0755 "$launcher.new"
  mv "$launcher.new" "$launcher"
}

write_config() {
  if [ -f "$CONFIG_FILE" ] && [ -z "$SERVER" ]; then
    say "keeping existing configuration $CONFIG_FILE"
    return 0
  fi
  [ -n "$SERVER" ] || die "--server is required for a first installation"
  # No secrets here: the agent's own token lives in the state directory, the one-time token
  # is never written to the configuration.
  cat > "$CONFIG_FILE.new" <<EOF
# Sentra Agent configuration (generated by install-sentra-agent.sh).
# Change api_url here, then: sudo systemctl restart sentra-agent
api_url = "$SERVER"
state_dir = "$STATE_DIR"
log_dir = "$LOG_DIR"
EOF
  chmod 0640 "$CONFIG_FILE.new"
  chown "root:$SERVICE_USER" "$CONFIG_FILE.new"
  mv "$CONFIG_FILE.new" "$CONFIG_FILE"
  say "configuration written: $CONFIG_FILE (api_url = $SERVER)"
}

install_unit() {
  install -d -m 0755 "$UNIT_DIR"
  install -m 0644 "$HERE/sentra-agent.service" "$UNIT_FILE"
}

have_systemd() {
  [ -n "$ROOT" ] || [ -d /run/systemd/system ]
}

stop_service() {
  if have_systemd && systemctl is-active --quiet sentra-agent 2>/dev/null; then
    systemctl stop sentra-agent
    say "service stopped for the upgrade"
  fi
}

run_as_service_user() {
  runuser -u "$SERVICE_USER" -- "$@"
}

enroll() {
  local status=0 output
  if [ -n "$TOKEN_INLINE" ]; then
    # Hand the token to the agent in a file only the service user can read; the agent
    # deletes it after enrolling. Never on a command line (visible in ps).
    rm -f "$ENROLL_COPY"
    printf '%s' "$TOKEN_INLINE" > "$ENROLL_COPY"
    chmod 0600 "$ENROLL_COPY"
    chown "$SERVICE_USER:$SERVICE_USER" "$ENROLL_COPY"
    TOKEN_INLINE=""
    output="$(run_as_service_user "$OPT_DIR/bin/sentra-agent" --config "$CONFIG_FILE" \
      --enroll --enrollment-token-file "$ENROLL_COPY" 2>/dev/null)" || status=$?
  else
    output="$(run_as_service_user "$OPT_DIR/bin/sentra-agent" --config "$CONFIG_FILE" \
      --enroll 2>/dev/null)" || status=$?
  fi
  # The agent prints one result line on stdout; its JSON logs are in $LOG_DIR/agent.log.
  # Whatever happened, no copy of the one-time token stays on disk.
  rm -f "$ENROLL_COPY"
  case "$status" in
    0)
      say "${output##*$'\n'}"
      if [ -n "$TOKEN_FILE" ] && [ -f "$TOKEN_FILE" ]; then
        rm -f "$TOKEN_FILE"
        say "one-time token used; deleted $TOKEN_FILE"
      fi
      ;;
    3) die "the agent is not enrolled yet: pass --token-file with a one-time enrollment token" ;;
    4) die "the server refused the enrollment token (expired, already used, revoked, or not for this host). Create a new one. Details: ${output##*$'\n'}" ;;
    5) die "cannot reach the server at the configured api_url; check --server and the network, then run the installer again with the same token file. Details: ${output##*$'\n'}" ;;
    *) die "enrollment failed (exit $status); see $LOG_DIR/agent.log" ;;
  esac
}

start_service() {
  if ! have_systemd; then
    warn "systemd is not running here: service installed but not started"
    return 0
  fi
  systemctl daemon-reload
  if [ "$NO_START" = "1" ]; then
    say "service installed; start it with: sudo systemctl enable --now sentra-agent"
    return 0
  fi
  systemctl enable sentra-agent >/dev/null 2>&1 || systemctl enable sentra-agent
  systemctl restart sentra-agent
  local tries=0
  until systemctl is-active --quiet sentra-agent; do
    tries=$((tries + 1))
    if [ "$tries" -ge 10 ]; then
      systemctl status --no-pager sentra-agent || true
      die "the service did not become active; see: journalctl -u sentra-agent"
    fi
    sleep 1
  done
  say "service sentra-agent is active and enabled at boot"
}

main() {
  parse_args "$@"
  require_root
  check_platform
  find_python
  if [ "$PACKAGE_MODE" = "postinst" ]; then
    # .deb postinst: user, directories and launcher; enrollment comes with sentra-agent-setup.
    create_user
    grant_journal_access
    create_dirs
    write_launcher
    have_systemd && systemctl daemon-reload || true
    say "installed; enroll with: sudo sentra-agent-setup --server URL --token-file FILE"
    return 0
  fi
  check_server
  read_token
  if [ "$UPGRADE" = "1" ] && [ ! -f "$CONFIG_FILE" ]; then
    die "--upgrade needs an existing installation (no $CONFIG_FILE)"
  fi
  create_user
  grant_journal_access
  create_dirs
  stop_service
  if [ -z "$PACKAGE_MODE" ]; then
    install_runtime
    install_unit
  fi
  write_launcher
  write_config
  enroll
  start_service
  say "done. Status: systemctl status sentra-agent | Logs: journalctl -u sentra-agent"
}

main "$@"
