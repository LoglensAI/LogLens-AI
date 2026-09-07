#!/usr/bin/env bash
set -euo pipefail

command -v git-cliff >/dev/null || { echo "install git-cliff first"; exit 1; }
command -v gh        >/dev/null || { echo "install gh (GitHub CLI) first"; exit 1; }

echo "→ Generating CHANGELOG.md from full history…"
git cliff -o CHANGELOG.md
echo "  done."

prev=""
while read -r tag; do
  [ -z "$tag" ] && continue
  if gh release view "$tag" >/dev/null 2>&1; then
    echo "→ $tag: release already exists, skipping"
  else
    range="${prev:+$prev..}$tag"
    git cliff "$range" --tag "$tag" --strip header -o /tmp/notes.md 2>/dev/null
    gh release create "$tag" --title "$tag" --notes-file /tmp/notes.md
    echo "→ $tag: release created"
  fi
  prev="$tag"
done < <(git tag --sort=version:refname | grep -E '^v[0-9]')

echo "✓ Backfill complete. Review CHANGELOG.md, then: git add CHANGELOG.md && git commit -m 'docs: add changelog'"