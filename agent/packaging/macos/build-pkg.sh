#!/bin/bash
# Construye la distribución macOS de Sentra Agent (solo el agente: sin código del servidor ni
# secretos). SOLO funciona en macOS: necesita pkgbuild y productbuild (Xcode Command Line
# Tools). En otro sistema termina con un error explícito.
#
#   agent/packaging/macos/build-pkg.sh                       # arquitectura de este Mac
#   agent/packaging/macos/build-pkg.sh --arch x86_64         # Intel desde Apple Silicon
#   agent/packaging/macos/build-pkg.sh --psutil-wheel path/to/psutil-*.whl   # sin red
#
# Salidas en <repo>/dist (fuera de git):
#   sentra-agent-<versión>-macos-<arch>.tar.gz        instalador + runtime (carpeta)
#   sentra-agent-<versión>-macos-<arch>-unsigned.pkg  el mismo runtime como paquete
#   *.sha256
#
# FIRMA Y NOTARIZACIÓN: el .pkg sale SIN FIRMAR y SIN NOTARIZAR. Para distribución pública
# hacen falta una cuenta del Apple Developer Program y sus certificados (ver
# docs/agent-macos-installation.md, "Firma y notarización"). Las opciones --sign-app,
# --sign-installer y --notary-profile existen para ese momento pero NO se han probado.

set -euo pipefail

die() { printf 'build-pkg: ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(uname -s)" = "Darwin" ] || die "build-pkg.sh only works on macOS (pkgbuild/productbuild)"
command -v pkgbuild >/dev/null 2>&1 || die "pkgbuild not found (xcode-select --install)"
command -v productbuild >/dev/null 2>&1 || die "productbuild not found (xcode-select --install)"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$HERE/../.." && pwd)"
REPO_DIR="$(cd "$AGENT_DIR/.." && pwd)"
OUT_DIR="$REPO_DIR/dist"
if [ "$(sysctl -n hw.optional.arm64 2>/dev/null || echo 0)" = "1" ]; then ARCH="arm64"; else ARCH="x86_64"; fi
PSUTIL_VERSION="7.2.2"
PSUTIL_WHEEL=""
SIGN_APP=""
SIGN_INSTALLER=""
NOTARY_PROFILE=""
PYTHON_BUILD="${PYTHON:-python3}"
MIN_MACOS="13.0"
LABEL="com.sentra.agent"

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --psutil-wheel) PSUTIL_WHEEL="$2"; shift 2 ;;
    --sign-app) SIGN_APP="$2"; shift 2 ;;
    --sign-installer) SIGN_INSTALLER="$2"; shift 2 ;;
    --notary-profile) NOTARY_PROFILE="$2"; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

case "$ARCH" in
  arm64) WHEEL_PLATFORM="macosx_11_0_arm64" ;;
  x86_64) WHEEL_PLATFORM="macosx_10_9_x86_64" ;;
  *) die "unsupported --arch $ARCH (arm64, x86_64)" ;;
esac

VERSION="$(tr -d '\r' < "$AGENT_DIR/pyproject.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)"
case "$VERSION" in
  ''|*[!0-9A-Za-z.+~-]*) die "invalid version in pyproject.toml: '$VERSION'" ;;
esac
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$REPO_DIR" log -1 --format=%ct 2>/dev/null || echo 1790000000)"
fi
export SOURCE_DATE_EPOCH

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="sentra-agent-$VERSION-macos-$ARCH"
STAGE="$WORK/$NAME"
mkdir -p "$STAGE/payload/lib" "$OUT_DIR"

install_lf() {
  tr -d '\r' < "$2" > "$3"
  chmod "$1" "$3"
}

# 1. psutil: rueda binaria fijada para la arquitectura (abi3: una para todo CPython >= 3.6).
if [ -z "$PSUTIL_WHEEL" ]; then
  "$PYTHON_BUILD" -m pip download "psutil==$PSUTIL_VERSION" --no-deps --only-binary=:all: \
    --platform "$WHEEL_PLATFORM" --implementation cp --python-version 3.12 \
    -d "$WORK/wheels" -q
  PSUTIL_WHEEL="$(ls "$WORK"/wheels/psutil-*.whl)"
fi
"$PYTHON_BUILD" -m zipfile -e "$PSUTIL_WHEEL" "$STAGE/payload/lib"

# 2. El paquete del agente (solo código fuente: sin tests ni cachés).
cp -R "$AGENT_DIR/sentra_agent" "$STAGE/payload/lib/sentra_agent"
find "$STAGE/payload/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE/payload/lib" -name '*.pyc' -delete

if [ -n "$SIGN_APP" ]; then
  # SIN PROBAR (faltan certificados): firma Developer ID con hardened runtime de cada Mach-O.
  find "$STAGE/payload/lib" -name '*.so' -print0 | while IFS= read -r -d '' binary; do
    codesign --force --timestamp --options runtime --sign "$SIGN_APP" "$binary"
  done
fi

# 3. Instalador, LaunchDaemon, utilidades y documentación.
for script in install-sentra-agent.sh uninstall-sentra-agent.sh diagnose-sentra-agent.sh; do
  install_lf 0755 "$HERE/$script" "$STAGE/$script"
done
install_lf 0644 "$HERE/check-python.py" "$STAGE/check-python.py"
install_lf 0644 "$HERE/$LABEL.plist" "$STAGE/$LABEL.plist"
install_lf 0644 "$HERE/$LABEL.newsyslog.conf" "$STAGE/$LABEL.newsyslog.conf"
install -m 0644 "$REPO_DIR/docs/agent-macos-installation.md" "$STAGE/README.md"
printf 'version=%s\narch=%s\npsutil=%s\n' "$VERSION" "$ARCH" "$(basename "$PSUTIL_WHEEL")" \
  > "$STAGE/VERSION"
plutil -lint "$STAGE/$LABEL.plist" >/dev/null
(cd "$STAGE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum -a 256 \
  > "$WORK/MANIFEST.sha256")
mv "$WORK/MANIFEST.sha256" "$STAGE/MANIFEST.sha256"
find "$STAGE" -exec touch -h -t "$(date -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)" {} +

# 4. Carpeta empaquetada (instalación con install-sentra-agent.sh).
TARBALL="$OUT_DIR/$NAME.tar.gz"
COPYFILE_DISABLE=1 tar --uid 0 --gid 0 -C "$WORK" -czf "$TARBALL" "$NAME"
(cd "$OUT_DIR" && shasum -a 256 "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256")
echo "built $TARBALL"

# 5. Paquete .pkg: runtime en /Library/Sentra/Agent, LaunchDaemon en /Library/LaunchDaemons;
#    postinstall fija permisos y el lanzador; el enrolamiento es sentra-agent-setup.
PKG_ROOT="$WORK/pkgroot"
PREFIX="$PKG_ROOT/Library/Sentra/Agent"
mkdir -p "$PREFIX/share" "$PKG_ROOT/Library/LaunchDaemons" "$WORK/scripts"
cp -R "$STAGE/payload/lib" "$PREFIX/lib"
for file in install-sentra-agent.sh uninstall-sentra-agent.sh diagnose-sentra-agent.sh \
  check-python.py "$LABEL.plist" "$LABEL.newsyslog.conf" VERSION; do
  cp "$STAGE/$file" "$PREFIX/share/$file"
done
cp "$STAGE/VERSION" "$PREFIX/VERSION"
cp "$STAGE/$LABEL.plist" "$PKG_ROOT/Library/LaunchDaemons/$LABEL.plist"
install_lf 0755 "$HERE/scripts/preinstall" "$WORK/scripts/preinstall"
install_lf 0755 "$HERE/scripts/postinstall" "$WORK/scripts/postinstall"
COMPONENT="$WORK/$LABEL.pkg"
pkgbuild --root "$PKG_ROOT" --scripts "$WORK/scripts" --identifier "$LABEL" \
  --version "$VERSION" --install-location / --ownership recommended "$COMPONENT" >/dev/null
sed -e "s/@VERSION@/$VERSION/g" -e "s/@ARCH@/$ARCH/g" -e "s/@MIN_MACOS@/$MIN_MACOS/g" \
  "$HERE/distribution.xml.in" > "$WORK/distribution.xml"
if [ -n "$SIGN_INSTALLER" ]; then
  PKG="$OUT_DIR/$NAME.pkg"
  # SIN PROBAR (faltan certificados): firma con "Developer ID Installer: ...".
  productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" \
    --sign "$SIGN_INSTALLER" --timestamp "$PKG" >/dev/null
  if [ -n "$NOTARY_PROFILE" ]; then
    xcrun notarytool submit "$PKG" --keychain-profile "$NOTARY_PROFILE" --wait
    xcrun stapler staple "$PKG"
  fi
else
  PKG="$OUT_DIR/$NAME-unsigned.pkg"
  productbuild --distribution "$WORK/distribution.xml" --package-path "$WORK" "$PKG" >/dev/null
  echo "WARNING: $PKG is NOT signed and NOT notarized (no Apple Developer ID certificates)." >&2
fi
(cd "$OUT_DIR" && shasum -a 256 "$(basename "$PKG")" > "$(basename "$PKG").sha256")
echo "built $PKG"
