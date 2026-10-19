#!/bin/bash
# Instala, enrola y arranca Sentra Agent en macOS (Apple Silicon arm64 o Intel x86_64).
#
#   sudo ./install-sentra-agent.sh --server https://SERVER --token-file ./enrollment.token
#   sudo ./install-sentra-agent.sh --upgrade               # versión nueva, misma identidad
#   sudo /Library/Sentra/Agent/bin/sentra-agent-setup --server URL --token-file FILE  # tras el .pkg
#
# Qué hace (y nada más): comprueba macOS, arquitectura y un Python >= 3.12 seguro para root;
# copia el runtime a /Library/Sentra/Agent; escribe /Library/Sentra/Agent/agent.toml (sin
# secretos); enrola con el token de un solo uso LEÍDO DE UN FICHERO (el agente guarda su
# propio token en el keychain del sistema y el fichero se borra); instala el LaunchDaemon
# com.sentra.agent y comprueba que corre. Sin descargas, sin pip, sin git, sin compilador.
#
# Compatible con el bash 3.2 que trae macOS: sin arrays asociativos ni la conversión de
# mayúsculas de bash 4.
# Gancho de tests: SENTRA_ROOT=/dir instala bajo ese directorio en lugar de / (la suite lo
# usa con launchctl, chown, sw_vers... falsos). Nunca hace falta en un uso real.

set -euo pipefail
umask 077

ROOT="${SENTRA_ROOT:-}"
LABEL="com.sentra.agent"
PREFIX="$ROOT/Library/Sentra/Agent"
LIB_DIR="$PREFIX/lib"
BIN_DIR="$PREFIX/bin"
SHARE_DIR="$PREFIX/share"
CONFIG_FILE="$PREFIX/agent.toml"
STATE_DIR="$PREFIX/state"
LOG_DIR="$ROOT/Library/Logs/Sentra"
PLIST_DIR="$ROOT/Library/LaunchDaemons"
PLIST="$PLIST_DIR/$LABEL.plist"
NEWSYSLOG_DIR="$ROOT/etc/newsyslog.d"
ENROLL_COPY="$STATE_DIR/enrollment.token"
MIN_MACOS_MAJOR=13

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

SERVER=""
TOKEN_FILE=""
TOKEN=""
UPGRADE=0
NO_START=0
PACKAGE_MODE=""   # "" (carpeta), "postinstall" (.pkg) o "configure" (sentra-agent-setup)
PYTHON=""
CREDENTIAL_STORE=""
ALLOW_ADMIN_PYTHON=0

say() { printf 'sentra-agent: %s\n' "$*"; }
warn() { printf 'sentra-agent: WARNING: %s\n' "$*" >&2; }
die() { printf 'sentra-agent: ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
Usage: sudo ./install-sentra-agent.sh --server URL --token-file FILE [options]
       sudo ./install-sentra-agent.sh --upgrade [--server URL]

  --server URL              Sentra server, e.g. https://sentra.example.com (https in production)
  --token-file FILE         file with a one-time enrollment token (deleted once used)
  --upgrade                 replace the runtime, keep configuration and identity, restart
  --no-start                install and enroll, but do not load the LaunchDaemon
  --python PATH             python3 >= 3.12 to use (default: python.org framework, auto-detect)
  --credential-store MODE   auto (Keychain, default) or file (0600 file, only if no Keychain)
  --allow-admin-writable-python
                            accept a Python writable by the admin group (python.org default);
                            weaker: any admin process could run code as root
  -h, --help                this help

The token is never accepted on the command line (it would be visible in ps and the shell
history). Create it on the server: python -m app.cli create-enrollment-token --platform macos
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --server) SERVER="${2:-}"; shift 2 ;;
      --token-file) TOKEN_FILE="${2:-}"; shift 2 ;;
      --token) die "--token is not supported on macOS: put the token in a file and use --token-file" ;;
      --upgrade) UPGRADE=1; shift ;;
      --no-start) NO_START=1; shift ;;
      --python) PYTHON="${2:-}"; shift 2 ;;
      --credential-store) CREDENTIAL_STORE="${2:-}"; shift 2 ;;
      --allow-admin-writable-python) ALLOW_ADMIN_PYTHON=1; shift ;;
      --package-postinstall) PACKAGE_MODE="postinstall"; shift ;;
      --package-configure) PACKAGE_MODE="configure"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) usage >&2; die "unknown option: $1" ;;
    esac
  done
  case "$CREDENTIAL_STORE" in
    ""|auto|file) ;;
    *) die "--credential-store must be auto or file" ;;
  esac
}

require_root() {
  [ "$(id -u)" = "0" ] || die "run as root (sudo)"
}

check_platform() {
  [ "$(uname -s)" = "Darwin" ] || die "this installer is for macOS"
  local version major arch expected
  version="$(sw_vers -productVersion 2>/dev/null || true)"
  major="${version%%.*}"
  case "$major" in
    ''|*[!0-9]*) die "cannot read the macOS version (sw_vers)" ;;
  esac
  [ "$major" -ge "$MIN_MACOS_MAJOR" ] \
    || die "macOS $version is not supported (macOS $MIN_MACOS_MAJOR Ventura or later)"
  # Arquitectura del Mac, no la de este shell: en un Terminal bajo Rosetta uname -m dice
  # x86_64 aunque el equipo sea Apple Silicon.
  if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then
    arch="arm64"
  else
    arch="x86_64"
  fi
  if [ -f "$HERE/VERSION" ]; then
    expected="$(sed -n 's/^arch=//p' "$HERE/VERSION")"
    if [ -n "$expected" ] && [ "$expected" != "$arch" ]; then
      die "this package is for $expected, this Mac is $arch"
    fi
  fi
  say "macOS $version on $arch"
}

check_script() {
  if [ -f "$HERE/check-python.py" ]; then
    printf '%s' "$HERE/check-python.py"
  else
    printf '%s' "$SHARE_DIR/check-python.py"
  fi
}

find_python() {
  local candidate output check flags reasons=""
  check="$(check_script)"
  [ -f "$check" ] || die "check-python.py missing next to the installer"
  flags=""
  [ "$ALLOW_ADMIN_PYTHON" = "1" ] && flags="--allow-admin-writable"
  # Gancho de tests: bajo SENTRA_ROOT el propietario exigido es el usuario de la suite.
  [ -n "$ROOT" ] && flags="$flags --owner-self"
  local candidates
  if [ -n "$PYTHON" ]; then
    # Elegido por el administrador: solo ese, sin buscar otros.
    [ -x "$PYTHON" ] || die "--python $PYTHON is not an executable file"
    candidates="$PYTHON"
  else
    # python.org primero (framework de root); Homebrew se prueba, pero al ser propiedad del
    # usuario no pasa la comprobación y el mensaje explica por qué.
    candidates="/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14
/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13
/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12
/usr/local/bin/python3.14 /usr/local/bin/python3.13 /usr/local/bin/python3.12
/opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12"
  fi
  PYTHON=""
  for candidate in $candidates; do
    [ -x "$candidate" ] || continue
    # Modo aislado, como el daemon: el resultado no depende del entorno de quien instala.
    # shellcheck disable=SC2086
    output="$("$candidate" -I -S "$check" $flags 2>&1)" && {
      PYTHON="$candidate"
      say "python: ${output#ok }"
      return 0
    }
    reasons="$reasons
  $candidate: $(printf '%s' "$output" | head -3)"
  done
  die "no safe python3 >= 3.12 found. Install Python from python.org (3.12 or later).
A root daemon must not run an interpreter other users can modify. Rejected:$reasons
For the python.org framework (group admin writable) either harden it:
  sudo chmod -R go-w /Library/Frameworks/Python.framework && sudo chown -R root:wheel /Library/Frameworks/Python.framework
or accept the risk with --allow-admin-writable-python (see docs/agent-macos-installation.md)."
}

check_server() {
  [ -n "$SERVER" ] || return 0
  case "$SERVER" in
    http://*|https://*) ;;
    *) die "--server must start with http:// or https:// (got: $SERVER)" ;;
  esac
  SERVER="${SERVER%/}"
  printf '%s' "$SERVER" | grep -Eq '^https?://[][A-Za-z0-9.:_-]+(/[A-Za-z0-9._~/-]*)?$' \
    || die "--server is not a valid URL: $SERVER"
  case "$SERVER" in
    http://127.*|http://localhost*|http://\[::1\]*) ;;
    http://*) warn "the server URL is not https: tokens travel unencrypted on the network (use https in production)" ;;
  esac
}

read_token() {
  [ -n "$TOKEN_FILE" ] || return 0
  [ -f "$TOKEN_FILE" ] || die "token file not found: $TOKEN_FILE"
  [ -s "$TOKEN_FILE" ] || die "token file is empty: $TOKEN_FILE"
  TOKEN="$(tr -d '[:space:]' < "$TOKEN_FILE")"
  case "$TOKEN" in
    sentra_et_*) ;;
    *) TOKEN=""; die "that is not a Sentra enrollment token (expected sentra_et_...)" ;;
  esac
}

create_dirs() {
  install -d -m 0755 "$ROOT/Library/Sentra" "$PREFIX" "$BIN_DIR" "$SHARE_DIR"
  chown root:wheel "$ROOT/Library/Sentra" "$PREFIX" "$BIN_DIR" "$SHARE_DIR"
  # Estado (identidad, búfer, cursores): solo root. Con credential_store = "file" el agente
  # exige además que siga siendo 0700 y de root antes de guardar el token.
  install -d -m 0700 "$STATE_DIR"
  chown root:wheel "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
  # Logs legibles por administradores en Consola.app; el agente nunca escribe tokens.
  install -d -m 0750 "$LOG_DIR"
  chown root:admin "$LOG_DIR"
}

install_runtime() {
  [ -d "$HERE/payload/lib/sentra_agent" ] || die "package payload missing next to the installer"
  # Sustitución en un solo paso: nunca una mezcla de dos versiones a medio copiar.
  rm -rf "$PREFIX/lib.new" "$PREFIX/lib.old"
  cp -R "$HERE/payload/lib" "$PREFIX/lib.new"
  chmod -R u=rwX,go=rX "$PREFIX/lib.new"
  chown -R root:wheel "$PREFIX/lib.new"
  [ -d "$LIB_DIR" ] && mv "$LIB_DIR" "$PREFIX/lib.old"
  mv "$PREFIX/lib.new" "$LIB_DIR"
  rm -rf "$PREFIX/lib.old"
  local script
  for script in install-sentra-agent.sh uninstall-sentra-agent.sh diagnose-sentra-agent.sh; do
    install -m 0755 "$HERE/$script" "$SHARE_DIR/$script"
  done
  install -m 0644 "$HERE/check-python.py" "$SHARE_DIR/check-python.py"
  install -m 0644 "$HERE/$LABEL.plist" "$SHARE_DIR/$LABEL.plist"
  install -m 0644 "$HERE/$LABEL.newsyslog.conf" "$SHARE_DIR/$LABEL.newsyslog.conf"
  [ -f "$HERE/VERSION" ] && install -m 0644 "$HERE/VERSION" "$PREFIX/VERSION"
  chown -R root:wheel "$SHARE_DIR"
}

write_launcher() {
  local launcher="$BIN_DIR/sentra-agent"
  # -I -S: sin variables PYTHON*, sin site-packages (ni .pth), sin el directorio actual en
  # sys.path. Solo se carga la biblioteca estándar y el runtime de $LIB_DIR (de root).
  cat > "$launcher.new" <<EOF
#!/bin/sh
# Generado por install-sentra-agent.sh. Lanzador de Sentra Agent (lo ejecuta launchd como root).
exec "$PYTHON" -I -S -c 'import sys; sys.path.insert(0, "$LIB_DIR"); from sentra_agent.__main__ import main; sys.exit(main())' "\$@"
EOF
  chmod 0755 "$launcher.new"
  chown root:wheel "$launcher.new"
  mv "$launcher.new" "$launcher"
  cat > "$BIN_DIR/sentra-agent-setup.new" <<EOF
#!/bin/sh
# Enrola y arranca el agente instalado con el .pkg: --server URL --token-file FICHERO
exec /bin/bash "$SHARE_DIR/install-sentra-agent.sh" --package-configure "\$@"
EOF
  chmod 0755 "$BIN_DIR/sentra-agent-setup.new"
  chown root:wheel "$BIN_DIR/sentra-agent-setup.new"
  mv "$BIN_DIR/sentra-agent-setup.new" "$BIN_DIR/sentra-agent-setup"
}

write_config() {
  if [ -f "$CONFIG_FILE" ] && [ -z "$SERVER" ]; then
    if [ -n "$CREDENTIAL_STORE" ]; then
      warn "--credential-store needs --server to rewrite $CONFIG_FILE; kept as it is"
    fi
    say "keeping existing configuration $CONFIG_FILE"
    return 0
  fi
  [ -n "$SERVER" ] || die "--server is required for a first installation"
  # Sin secretos: el token propio está en el keychain del sistema y el de un solo uso nunca
  # se escribe aquí.
  {
    echo "# Sentra Agent configuration (generated by install-sentra-agent.sh)."
    echo "# Change api_url here, then: sudo launchctl kickstart -k system/$LABEL"
    echo "api_url = \"$SERVER\""
    echo "state_dir = \"$STATE_DIR\""
    echo "log_dir = \"$LOG_DIR\""
    echo "installation_method = \"macos_launchd\""
    if [ "$CREDENTIAL_STORE" = "file" ]; then
      echo "# Elegido por el administrador: token en un fichero 0600 en lugar del Keychain."
      echo "credential_store = \"file\""
    fi
  } > "$CONFIG_FILE.new"
  chmod 0644 "$CONFIG_FILE.new"
  chown root:wheel "$CONFIG_FILE.new"
  mv "$CONFIG_FILE.new" "$CONFIG_FILE"
  say "configuration written: $CONFIG_FILE (api_url = $SERVER)"
}

install_daemon() {
  install -d -m 0755 "$PLIST_DIR"
  local source="$HERE/$LABEL.plist"
  [ -f "$source" ] || source="$SHARE_DIR/$LABEL.plist"
  # launchd rechaza un plist que otros puedan modificar: root:wheel 0644.
  install -m 0644 "$source" "$PLIST.new"
  chown root:wheel "$PLIST.new"
  if command -v plutil >/dev/null 2>&1; then
    plutil -lint "$PLIST.new" >/dev/null || die "invalid LaunchDaemon plist"
  fi
  mv "$PLIST.new" "$PLIST"
  local rotation="$HERE/$LABEL.newsyslog.conf"
  [ -f "$rotation" ] || rotation="$SHARE_DIR/$LABEL.newsyslog.conf"
  install -d -m 0755 "$NEWSYSLOG_DIR"
  install -m 0644 "$rotation" "$NEWSYSLOG_DIR/$LABEL.conf"
  chown root:wheel "$NEWSYSLOG_DIR/$LABEL.conf"
}

loaded() {
  launchctl print "system/$LABEL" >/dev/null 2>&1
}

stop_service() {
  if loaded; then
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    say "LaunchDaemon stopped for the upgrade"
  fi
}

enroll() {
  local status=0 output
  if [ -n "$TOKEN" ]; then
    # El token pasa al agente en un fichero que solo root puede leer y que el agente borra
    # al enrolarse. Nunca en la línea de comandos (visible en ps).
    rm -f "$ENROLL_COPY"
    ( umask 077; printf '%s' "$TOKEN" > "$ENROLL_COPY" )
    chmod 0600 "$ENROLL_COPY"
    TOKEN=""
    output="$("$BIN_DIR/sentra-agent" --config "$CONFIG_FILE" --no-console-log --enroll \
      --enrollment-token-file "$ENROLL_COPY" 2>/dev/null)" || status=$?
  else
    output="$("$BIN_DIR/sentra-agent" --config "$CONFIG_FILE" --no-console-log --enroll \
      2>/dev/null)" || status=$?
  fi
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
    5) die "cannot reach the server at the configured api_url; check --server and the network (https: is the CA trusted?), then run again with the same token file. Details: ${output##*$'\n'}" ;;
    6) die "the macOS Keychain is not usable (${output##*$'\n'}). Nothing was enrolled. Fix the System keychain, or reinstall with --credential-store file (see docs/agent-macos-installation.md)" ;;
    *) die "enrollment failed (exit $status); see $LOG_DIR/agent.log" ;;
  esac
}

start_service() {
  if [ "$NO_START" = "1" ]; then
    say "LaunchDaemon installed; start it with: sudo launchctl bootstrap system $PLIST"
    return 0
  fi
  launchctl enable "system/$LABEL" 2>/dev/null || true
  if loaded; then
    launchctl kickstart -k "system/$LABEL"
  else
    launchctl bootstrap system "$PLIST"
  fi
  local tries=0
  until launchctl print "system/$LABEL" 2>/dev/null | grep -q "state = running"; do
    tries=$((tries + 1))
    if [ "$tries" -ge 10 ]; then
      launchctl print "system/$LABEL" 2>/dev/null | head -30 || true
      die "the LaunchDaemon did not start; see $LOG_DIR/agent.log and $LOG_DIR/launchd.log"
    fi
    sleep 1
  done
  say "LaunchDaemon $LABEL is running and starts at boot"
}

main() {
  parse_args "$@"
  require_root
  check_platform
  find_python
  if [ "$PACKAGE_MODE" = "postinstall" ]; then
    # .pkg: el runtime ya está en $LIB_DIR. Permisos, lanzador y rotación; el enrolamiento
    # necesita el token y se hace con sentra-agent-setup (o es una actualización).
    create_dirs
    chown -R root:wheel "$LIB_DIR" "$SHARE_DIR"
    chmod -R u=rwX,go=rX "$LIB_DIR" "$SHARE_DIR"
    write_launcher
    install_daemon
    if [ -f "$CONFIG_FILE" ] && [ -f "$STATE_DIR/identity.json" ]; then
      start_service
      say "upgraded; same identity, no new enrollment"
    else
      say "installed; enroll with: sudo $BIN_DIR/sentra-agent-setup --server URL --token-file FILE"
    fi
    return 0
  fi
  check_server
  read_token
  if [ "$UPGRADE" = "1" ] && [ ! -f "$CONFIG_FILE" ]; then
    die "--upgrade needs an existing installation (no $CONFIG_FILE)"
  fi
  create_dirs
  stop_service
  if [ -z "$PACKAGE_MODE" ]; then
    install_runtime
  fi
  write_launcher
  write_config
  install_daemon
  enroll
  start_service
  say "done. Diagnose: sudo $SHARE_DIR/diagnose-sentra-agent.sh | Logs: $LOG_DIR/agent.log"
}

main "$@"
