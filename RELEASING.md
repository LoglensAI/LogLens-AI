# Releasing LogLens AI

This is the end-to-end release checklist. The goal: the git tag, the version in
`src/loglens/_version.py`, the PyPI release, and the GitHub Release assets all
agree, so the one-line installers and `pip install loglensai` always work.

## Single source of truth

The version lives in `src/loglens/_version.py`. `pyproject.toml` reads it
dynamically, and the CI **consistency** job asserts
`hatch version == loglens.__version__ == loglens version (CLI)`. Never hand-edit
the version anywhere else.

## Steps

1. **Bump the version** in `src/loglens/_version.py` (e.g. `0.13.1` → `0.13.2`)
   and commit on `main`.

2. **Tag and push** the matching tag:

   ```bash
   git tag "v$(python -c 'import runpy;print(runpy.run_path("src/loglens/_version.py")["__version__"])')"
   git push origin main --tags
   ```

3. **Publish the GitHub Release** for that tag (Releases → Draft a new release →
   choose the tag → Publish). Publishing fires the `release-binaries` workflow on
   a `release` event, which builds **and attaches** every asset:
   - `loglens-linux-x86_64.tar.gz`
   - `loglens-macos-arm64.tar.gz`
   - `loglens-windows-x86_64.zip` and `loglens-windows-x86_64.msi`
   - `loglens_<version>_amd64.deb`

   > A manual **Run workflow** (`workflow_dispatch`) now also creates/updates the
   > release and uploads the assets, so a manual build is still installable — but
   > a published Release is the normal path.

4. **Publish to PyPI** via the `Publish to PyPI` workflow (or `hatch build &&
   twine upload dist/*`). `twine upload --skip-existing` is safe to re-run.

## Verify the release is consistent

After the workflows finish, confirm all four agree:

```bash
V=$(python -c 'import runpy;print(runpy.run_path("src/loglens/_version.py")["__version__"])')
echo "repo version: $V"
git describe --tags --abbrev=0                 # should be v$V
pip index versions loglensai | head -1          # PyPI latest should be $V
# every installer asset must resolve (no 404):
for a in loglens-linux-x86_64.tar.gz loglens-macos-arm64.tar.gz \
         loglens-windows-x86_64.zip loglens-windows-x86_64.msi; do
  curl -sfI "https://github.com/LoglensAI/LogLens-AI/releases/latest/download/$a" >/dev/null \
    && echo "OK  $a" || echo "MISSING  $a"
done
```

If any asset is `MISSING`, the release build didn't attach it — re-run
`release-binaries` for that tag, or download the asset from the workflow run and
upload it to the release manually.

## Recovery

- **Tag/version mismatch:** fix `_version.py`, delete the bad tag
  (`git tag -d vX && git push origin :refs/tags/vX`), re-tag, re-release.
- **PyPI ahead of GitHub (or vice-versa):** PyPI publishes are immutable, so bump
  to the next patch rather than trying to overwrite a version.
