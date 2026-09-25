#!/usr/bin/env bash

set -euo pipefail

VERSION="${1:?usage: build_deb.sh <version> [dist_dir] [arch]}"
DIST_DIR="${2:-dist}"
ARCH="${3:-amd64}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SRC="${DIST_DIR}/loglens"

[ -d "$SRC" ] || { echo "error: $SRC not found — run PyInstaller first." >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="${STAGE}/pkg"

install -d "${PKG}/opt/loglens" "${PKG}/usr/bin" "${PKG}/usr/lib/systemd/user" "${PKG}/DEBIAN"
cp -a "${SRC}/." "${PKG}/opt/loglens/"
ln -s /opt/loglens/loglens "${PKG}/usr/bin/loglens"
install -m 0644 "${ROOT}/packaging/linux/systemd/loglens.service" \
    "${PKG}/usr/lib/systemd/user/loglens.service"

INSTALLED_KB="$(du -sk "${PKG}" | cut -f1)"

cat > "${PKG}/DEBIAN/control" <<EOF
Package: loglens
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: Paras Rajput <pr8101999@gmail.com>
Installed-Size: ${INSTALLED_KB}
Homepage: https://github.com/LoglensAI/LogLens-AI
Description: LogLens AI - local, privacy-first log anomaly detection
 LogLens analyzes log files for anomalies entirely on your machine - no data
 leaves the host. Ships a self-contained runtime (no system Python needed) and
 a resident warm daemon so each run is near-instant. Includes neural (deep)
 mode built in.
EOF

# Enable the warm daemon per-user on first login (best-effort; never fails install).
cat > "${PKG}/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl --global enable loglens.service >/dev/null 2>&1 || true
fi
echo "LogLens installed. Try:  loglens analyze --source /path/to/your.log"
exit 0
EOF
chmod 0755 "${PKG}/DEBIAN/postinst"

cat > "${PKG}/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl --global disable loglens.service >/dev/null 2>&1 || true
fi
exit 0
EOF
chmod 0755 "${PKG}/DEBIAN/prerm"

OUT="loglens_${VERSION}_${ARCH}.deb"
# xz gives the smallest package for releases; override with DEB_COMPRESS for speed.
dpkg-deb --build --root-owner-group -Z"${DEB_COMPRESS:-xz}" "${PKG}" "${OUT}"
echo "built: ${OUT}"