#!/usr/bin/env bash
# Build the Linux distribution of Sentra Agent (only the agent: no server code, no secrets).
#
#   agent/packaging/linux/build.sh                  # dist/ tarball + .deb, x86_64
#   agent/packaging/linux/build.sh --arch aarch64
#   agent/packaging/linux/build.sh --psutil-wheel path/to/psutil-*.whl   # offline
#
# Outputs in <repo>/dist (not tracked by git):
#   sentra-agent-<version>-linux-<arch>.tar.gz   installer + runtime
#   sentra-agent_<version>_<amd64|arm64>.deb     same runtime as a Debian package
#   *.sha256
# Reproducible: same sources + same psutil wheel + same SOURCE_DATE_EPOCH = same bytes.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(cd "$HERE/../.." && pwd)"
REPO_DIR="$(cd "$AGENT_DIR/.." && pwd)"
OUT_DIR="$REPO_DIR/dist"
ARCH="x86_64"
PSUTIL_VERSION="7.2.2"
PSUTIL_WHEEL=""
BUILD_DEB=1
PYTHON_BUILD="${PYTHON:-python3}"

while [ $# -gt 0 ]; do
  case "$1" in
    --arch) ARCH="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    --psutil-wheel) PSUTIL_WHEEL="$2"; shift 2 ;;
    --no-deb) BUILD_DEB=0; shift ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

case "$ARCH" in
  x86_64) DEB_ARCH="amd64"; WHEEL_PLATFORM="manylinux2014_x86_64" ;;
  aarch64) DEB_ARCH="arm64"; WHEEL_PLATFORM="manylinux2014_aarch64" ;;
  *) echo "unsupported --arch $ARCH (x86_64, aarch64)" >&2; exit 2 ;;
esac

VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' "$AGENT_DIR/pyproject.toml" | head -1)"
[ -n "$VERSION" ] || { echo "version not found in pyproject.toml" >&2; exit 1; }
# Fixed timestamps for reproducible archives: last commit time if available, else a constant.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$REPO_DIR" log -1 --format=%ct 2>/dev/null || echo 1790000000)"
fi
export SOURCE_DATE_EPOCH

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
NAME="sentra-agent-$VERSION-linux-$ARCH"
STAGE="$WORK/$NAME"
mkdir -p "$STAGE/payload/lib" "$OUT_DIR"

# 1. psutil: a pinned binary wheel (abi3: one wheel for every CPython >= 3.6).
if [ -z "$PSUTIL_WHEEL" ]; then
  "$PYTHON_BUILD" -m pip download "psutil==$PSUTIL_VERSION" --no-deps --only-binary=:all: \
    --platform "$WHEEL_PLATFORM" --implementation cp --python-version 3.12 \
    -d "$WORK/wheels" -q
  PSUTIL_WHEEL="$(ls "$WORK"/wheels/psutil-*.whl)"
fi
# A wheel is a zip: extracting it is a complete install for a library without scripts.
"$PYTHON_BUILD" -m zipfile -e "$PSUTIL_WHEEL" "$STAGE/payload/lib"

# 2. The agent package itself (source only, no tests, no caches).
cp -R "$AGENT_DIR/sentra_agent" "$STAGE/payload/lib/sentra_agent"
find "$STAGE/payload/lib" -name '__pycache__' -type d -prune -exec rm -rf {} +
find "$STAGE/payload/lib" -name '*.pyc' -delete

# 3. Installer, service and docs.
install -m 0755 "$HERE/install-sentra-agent.sh" "$HERE/uninstall-sentra-agent.sh" "$STAGE/"
install -m 0644 "$HERE/sentra-agent.service" "$STAGE/"
install -m 0644 "$REPO_DIR/docs/agent-linux-installation.md" "$STAGE/README.md"
printf 'version=%s\narch=%s\npsutil=%s\n' "$VERSION" "$ARCH" "$(basename "$PSUTIL_WHEEL")" \
  > "$STAGE/VERSION"
(cd "$STAGE" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum \
  > "$WORK/MANIFEST.sha256")
mv "$WORK/MANIFEST.sha256" "$STAGE/MANIFEST.sha256"

normalize() {
  find "$1" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  chmod -R u+rwX,go+rX,go-w "$1"
}

# 4. Tarball.
normalize "$STAGE"
TARBALL="$OUT_DIR/$NAME.tar.gz"
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
  --format=gnu -C "$WORK" -cf - "$NAME" | gzip -n -9 > "$TARBALL"
(cd "$OUT_DIR" && sha256sum "$(basename "$TARBALL")" > "$(basename "$TARBALL").sha256")
echo "built $TARBALL"

# 5. Debian package: same runtime under /opt, unit under /lib/systemd/system, and
#    `sentra-agent-setup` (= the installer in configure mode) to enroll and start.
if [ "$BUILD_DEB" = "1" ] && command -v dpkg-deb >/dev/null 2>&1; then
  DEB="$WORK/deb"
  mkdir -p "$DEB/DEBIAN" "$DEB/opt/sentra-agent/share" "$DEB/opt/sentra-agent/bin" \
    "$DEB/lib/systemd/system" "$DEB/usr/sbin" "$DEB/usr/share/doc/sentra-agent"
  cp -R "$STAGE/payload/lib" "$DEB/opt/sentra-agent/lib"
  install -m 0755 "$HERE/install-sentra-agent.sh" "$HERE/uninstall-sentra-agent.sh" \
    "$DEB/opt/sentra-agent/share/"
  install -m 0644 "$STAGE/VERSION" "$DEB/opt/sentra-agent/VERSION"
  install -m 0644 "$HERE/sentra-agent.service" "$DEB/lib/systemd/system/"
  install -m 0644 "$STAGE/README.md" "$DEB/usr/share/doc/sentra-agent/README.md"
  install -m 0755 "$HERE/debian/sentra-agent-setup" "$DEB/usr/sbin/sentra-agent-setup"
  for script in postinst prerm postrm; do
    install -m 0755 "$HERE/debian/$script" "$DEB/DEBIAN/$script"
  done
  sed -e "s/@VERSION@/$VERSION/" -e "s/@ARCH@/$DEB_ARCH/" \
    -e "s/@SIZE@/$(du -sk "$DEB/opt" | cut -f1)/" "$HERE/debian/control.in" > "$DEB/DEBIAN/control"
  normalize "$DEB"
  DEB_FILE="$OUT_DIR/sentra-agent_${VERSION}_${DEB_ARCH}.deb"
  dpkg-deb --root-owner-group -Zxz --build "$DEB" "$DEB_FILE" >/dev/null
  (cd "$OUT_DIR" && sha256sum "$(basename "$DEB_FILE")" > "$(basename "$DEB_FILE").sha256")
  echo "built $DEB_FILE"
fi
