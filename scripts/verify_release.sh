#!/usr/bin/env bash

set -uo pipefail

usage() { echo "usage: $0 VERSION [--pypi] [--installers] [--retries N]" >&2; exit 2; }

[ $# -ge 1 ] || usage
V="${1#v}"; shift
CHECK_PYPI=0; CHECK_INSTALLERS=0; RETRIES=1
while [ $# -gt 0 ]; do
  case "$1" in
    --pypi) CHECK_PYPI=1 ;;
    --installers) CHECK_INSTALLERS=1 ;;
    --retries) shift; RETRIES="${1:-}"; [[ "$RETRIES" =~ ^[0-9]+$ ]] || usage ;;
    *) usage ;;
  esac
  shift
done

REPO="${GITHUB_REPOSITORY:-LoglensAI/LogLens-AI}"
PYPI_NAME="loglensai"
TAG="v${V}"

# Keep in sync with the build matrix in .github/workflows/release-binaries.yml.
ASSETS=(
  "loglens-linux-x86_64.tar.gz"
  "loglens-macos-arm64.tar.gz"
  "loglens-windows-x86_64.zip"
  "loglens-windows-x86_64.msi"
  "loglens_${V}_amd64.deb"
)
# Only these are fetched via /releases/latest/download/ by the installers/docs.
LATEST_URL_ASSETS=(
  "loglens-linux-x86_64.tar.gz"
  "loglens-macos-arm64.tar.gz"
  "loglens-windows-x86_64.zip"
  "loglens-windows-x86_64.msi"
)
if [ "$CHECK_INSTALLERS" = 1 ]; then
  ASSETS+=("install.sh" "install.ps1")
fi

pass() { echo "  OK       $*"; }
fail() { echo "  MISSING  $*"; FAILED=1; }

check_static() {
  echo "== ${REPO} ${TAG}: tag and version"
  if gh api "repos/${REPO}/git/ref/tags/${TAG}" >/dev/null 2>&1; then
    pass "tag ${TAG} exists"
  else
    fail "tag ${TAG} does not exist"
    return
  fi
  local file_v
  file_v="$(gh api "repos/${REPO}/contents/src/loglens/_version.py?ref=${TAG}" --jq .content 2>/dev/null \
    | python3 -c 'import base64,re,sys; m=re.search(r"__version__\s*=\s*[\"\x27]([^\"\x27]+)", base64.b64decode(sys.stdin.read()).decode()); print(m.group(1) if m else "")')"
  if [ "$file_v" = "$V" ]; then
    pass "_version.py at ${TAG} = ${file_v}"
  else
    fail "_version.py at ${TAG} = '${file_v}', expected ${V}"
  fi
}

check_release() {
  echo "== GitHub Release ${TAG}"
  local rel
  if ! rel="$(gh api "repos/${REPO}/releases/tags/${TAG}" 2>/dev/null)"; then
    fail "no GitHub Release for ${TAG} (drafts are not visible to installers)"
    return
  fi
  if [ "$(jq -r .draft <<<"$rel")" = "true" ]; then
    fail "release ${TAG} is still a draft"
  fi
  for a in "${ASSETS[@]}"; do
    local size
    size="$(jq -r --arg n "$a" '[.assets[] | select(.name == $n) | .size][0] // 0' <<<"$rel")"
    if [ "${size:-0}" -gt 0 ]; then
      pass "asset ${a} ($(( size / 1048576 )) MB)"
    else
      fail "asset ${a}"
    fi
  done

  local latest
  latest="$(gh api "repos/${REPO}/releases/latest" --jq .tag_name 2>/dev/null || echo "")"
  if [ "$latest" = "$TAG" ]; then
    echo "== /releases/latest (${TAG} is the latest release)"
    for a in "${LATEST_URL_ASSETS[@]}"; do
      if curl -sfIL -o /dev/null "https://github.com/${REPO}/releases/latest/download/${a}"; then
        pass "releases/latest/download/${a}"
      else
        fail "releases/latest/download/${a} (404)"
      fi
    done
  else
    echo "== /releases/latest is ${latest:-<none>}, not ${TAG}: skipping latest-URL check"
  fi
}

check_pypi() {
  echo "== PyPI ${PYPI_NAME}"
  local pv
  pv="$(curl -sf "https://pypi.org/pypi/${PYPI_NAME}/json" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["info"]["version"])' 2>/dev/null || echo "")"
  if [ "$pv" = "$V" ]; then
    pass "PyPI latest = ${pv}"
  else
    fail "PyPI latest = '${pv}', expected ${V}"
  fi
}

command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

FAILED=0
check_static
STATIC_FAILED=$FAILED

attempt=1
while :; do
  FAILED=0
  check_release
  [ "$CHECK_PYPI" = 1 ] && check_pypi
  if [ "$FAILED" = 0 ] || [ "$attempt" -ge "$RETRIES" ]; then
    break
  fi
  echo "-- attempt ${attempt}/${RETRIES} incomplete; retrying in 30s"
  attempt=$(( attempt + 1 ))
  sleep 30
done

if [ "$FAILED" = 1 ] || [ "$STATIC_FAILED" = 1 ]; then
  echo
  echo "Release ${TAG} is NOT complete. See RELEASING.md > Recovery."
  exit 1
fi
echo
echo "Release ${TAG} is complete and consistent."
