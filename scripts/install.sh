#!/usr/bin/env sh
set -eu

REPO="LoglensAI/LogLens-AI"
VERSION="${LOGLENS_VERSION:-}"
PREFIX="${LOGLENS_INSTALL_DIR:-$HOME/.local}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:-}"; shift 2 ;;
    --dir)     PREFIX="${2:-}"; shift 2 ;;
    -h|--help)
      sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done

info() { printf '\033[1;36m[LogLens]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[LogLens]\033[0m %s\n' "$1" >&2; }
die()  { err "$1"; exit 1; }

os="$(uname -s)"
arch="$(uname -m)"
case "$os" in
  Darwin)
    case "$arch" in
      arm64|aarch64) asset="loglens-macos-arm64.tar.gz" ;;
      x86_64)        die "No prebuilt Intel-macOS binary (x86_64). Install from PyPI instead: pipx install loglens-ai" ;;
      *) die "Unsupported macOS arch '$arch'. Try: pipx install loglens-ai" ;;
    esac ;;
  Linux)
    case "$arch" in
      x86_64|amd64) asset="loglens-linux-x86_64.tar.gz" ;;
      *) die "No prebuilt Linux binary for '$arch'. Try: pipx install loglensai" ;;
    esac ;;
  *) die "Unsupported OS '$os'. See https://github.com/${REPO}#installation" ;;
esac

if [ -n "$VERSION" ]; then
  tag="v${VERSION#v}"
  url="https://github.com/${REPO}/releases/download/${tag}/${asset}"
else
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
fi

have() { command -v "$1" >/dev/null 2>&1; }
have curl || have wget || die "Need curl or wget to download LogLens."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

info "Downloading ${asset}…"
if have curl; then
  curl -fsSL "$url" -o "$tmp/pkg.tar.gz" \
    || die "Download failed: $url  (check the version exists on the Releases page)"
else
  wget -qO "$tmp/pkg.tar.gz" "$url" \
    || die "Download failed: $url  (check the version exists on the Releases page)"
fi

info "Unpacking…"
tar -xzf "$tmp/pkg.tar.gz" -C "$tmp"
[ -d "$tmp/loglens" ] || die "Unexpected archive layout (no loglens/ directory)."

libexec="$PREFIX/libexec"
bindir="$PREFIX/bin"
mkdir -p "$libexec" "$bindir" || die "Cannot create $PREFIX (try: LOGLENS_INSTALL_DIR=\$HOME/.local)"

rm -rf "$libexec/loglens"
mv "$tmp/loglens" "$libexec/loglens"
ln -sf "$libexec/loglens/loglens" "$bindir/loglens"
chmod +x "$libexec/loglens/loglens" 2>/dev/null || true

if [ "$os" = "Darwin" ] && have xattr; then
  xattr -dr com.apple.quarantine "$libexec/loglens" 2>/dev/null || true
fi

ver="$("$bindir/loglens" version 2>/dev/null | sed -n 's/.*version *//p' | head -1 || true)"
info "Installed LogLens ${ver:-} to $libexec/loglens"

case ":$PATH:" in
  *":$bindir:"*) : ;;  # already on PATH
  *)
    err "NOTE: $bindir is not on your PATH. Add it:"
    printf '      echo '\''export PATH="%s:$PATH"'\'' >> ~/.profile && export PATH="%s:$PATH"\n' "$bindir" "$bindir" >&2
    ;;
esac

info "Done. Try:  loglens analyze --source /path/to/your.log"