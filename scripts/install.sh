#!/usr/bin/env sh

set -eu

REPO="LoglensAI/LogLens-AI"
APT_HOST="https://loglensai.github.io/apt"

info() { printf '\033[1;36m[LogLens]\033[0m %s\n' "$1"; }
err()  { printf '\033[1;31m[LogLens]\033[0m %s\n' "$1" >&2; }

os="$(uname -s)"
case "$os" in
  Linux)
    if command -v apt-get >/dev/null 2>&1; then
      info "Adding the LogLens APT repository (needs sudo)…"
      sudo install -m 0755 -d /usr/share/keyrings
      curl -fsSL "${APT_HOST}/key.gpg" | sudo gpg --dearmor -o /usr/share/keyrings/loglens.gpg
      echo "deb [signed-by=/usr/share/keyrings/loglens.gpg] ${APT_HOST} stable main" \
        | sudo tee /etc/apt/sources.list.d/loglens.list >/dev/null
      sudo apt-get update
      sudo apt-get install -y loglens
      info "Done. Run:  loglens analyze --source /path/to/your.log"
    else
      err "No apt found. Download a binary from:"
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