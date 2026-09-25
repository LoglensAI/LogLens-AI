#!/usr/bin/env sh
set -eu

REPO="LoglensAI/LogLens-AI"
CS_REPO="loglensai/loglensai-363o"  

info() { printf '\033[1;36m[LogLens]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[LogLens]\033[0m %s\n' "$1" >&2; }

os="$(uname -s)"
case "$os" in
  Linux)
    if command -v apt-get >/dev/null 2>&1; then
      info "Adding the LogLens APT repository via Cloudsmith (needs sudo)…"
      curl -1sLf "https://dl.cloudsmith.io/public/${CS_REPO}/setup.deb.sh" | sudo -E bash
      sudo apt-get install -y loglens
      info "Done. Run:  loglens analyze --source /path/to/your.log"
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
      info "Adding the LogLens YUM repository via Cloudsmith (needs sudo)…"
      curl -1sLf "https://dl.cloudsmith.io/public/${CS_REPO}/setup.rpm.sh" | sudo -E bash
      sudo dnf install -y loglens || sudo yum install -y loglens
      info "Done. Run:  loglens analyze --source /path/to/your.log"
    else
      err "No apt/dnf found. Download a binary from:"
      err "  https://github.com/${REPO}/releases/latest"
      exit 1
    fi
    ;;
  Darwin)
    if ! command -v brew >/dev/null 2>&1; then
      err "Homebrew is required. Install it from https://brew.sh then re-run."
      exit 1
    fi
    info "Installing via Homebrew…"
    brew tap loglensai/tap
    brew install loglens
    info "Done. Run:  loglens analyze --source /path/to/your.log"
    ;;
  *)
    err "Unsupported OS '$os'. See https://github.com/${REPO}#installation"
    exit 1
    ;;
esac