# Releasing LogLens AI

The goal: the git tag, the version in `src/loglens/_version.py`, the PyPI
release, and the GitHub Release assets all agree, so the one-line installers and
`pip install loglensai` always work.

## Single source of truth

The version lives in `src/loglens/_version.py`. `pyproject.toml` reads it
dynamically, and the CI **consistency** job asserts
`hatch version == loglens.__version__ == loglens version (CLI)`. Never hand-edit
the version anywhere else; the release workflow bumps it.

## Cutting a release (one button)

1. Make sure the commit you want to ship is on `main` and its **CI** run is green.
2. Go to **Actions > Release > Run workflow**, pick `main`, choose the bump
   (`patch` / `minor` / `major`) and run it.

That one run (`.github/workflows/release.yml`) does everything, in order. Each
step only starts if the previous one succeeded:

| Job | What it does | Guards |
|---|---|---|
| `prepare` | Bumps `_version.py`, regenerates `CHANGELOG.md`, commits, tags `vX.Y.Z`, pushes, creates a **draft** GitHub Release | Must run on `main`; CI must be green on the commit (override: `skip_ci_check`); the new tag must not exist; the version must not already be on PyPI |
| `binaries` | Calls `release-binaries.yml`: builds Linux / macOS arm64 / Windows (zip + MSI) / .deb, smoke-tests each binary (Windows also through `install.ps1`), attaches them and `install.sh` / `install.ps1` to the draft, pushes .deb to Cloudsmith, updates the Homebrew tap and Scoop bucket | Any failed build stops the release before PyPI |
| `pypi` | Calls `publish-pypi.yml` for the same tag | Needs `PYPI_API_TOKEN`; skips files already uploaded |
| `publish` | Takes the release out of draft and marks it latest | Only after binaries and PyPI succeeded, so `/releases/latest` never points at a release without assets |
| `verify` | Runs `scripts/verify_release.sh X.Y.Z --pypi --installers` | Fails unless tag == `_version.py` == PyPI latest == every asset present and downloadable via `/releases/latest/download/` |

Expected assets on every release:

- `loglens-linux-x86_64.tar.gz`
- `loglens-macos-arm64.tar.gz`
- `loglens-windows-x86_64.zip` and `loglens-windows-x86_64.msi`
- `loglens_<version>_amd64.deb`
- `install.sh`, `install.ps1`

> **Why one workflow?** A release created by a workflow with the default
> `GITHUB_TOKEN` does not trigger other workflows, so the old flow (create the
> release, then hope `release-binaries` fires on the `release` event) left
> releases with no binaries. `release.yml` now calls the build and PyPI
> workflows directly.

## Checking any release by hand

```bash
GH_TOKEN=... scripts/verify_release.sh 0.13.2 --pypi --installers
```

It prints `OK` / `MISSING` per item and exits non-zero if anything is missing.
`release-binaries.yml` also runs it (without the PyPI check) at the end of every
`release`-event or manual run.

## Other ways builds run

- **Publishing a release from the GitHub UI** still fires `release-binaries` on
  the `release` event and attaches everything. PyPI is then a separate manual
  run of **Publish to PyPI**.
- **Manual "Run workflow" on `release-binaries`** builds for the version in
  `_version.py` (or the `version` input), creates the release if needed and
  uploads the assets, then verifies them.

## Recovery

- **A job after `prepare` failed** (build, PyPI, publish, verify): fix the cause
  (for code fixes, push to `main` first), then open the same run and click
  **Re-run failed jobs**. The tag and draft already exist, uploads use
  `--clobber`, and PyPI uploads use `--skip-existing`, so re-runs are safe.
- **An existing release is missing assets** (e.g. the verify step or the
  script reports `MISSING`): run **Actions > release-binaries > Run workflow**
  from `main` with `ref` set to the release tag (e.g. `v0.13.1`). It builds that
  tag's code (version taken from its `_version.py`), uploads to the existing
  release and then verifies it. Leave `ref` blank only if you mean to build the
  current branch.
- **Tag/version mismatch:** fix `_version.py`, delete the bad tag
  (`git tag -d vX && git push origin :refs/tags/vX`) and its release, then cut
  the release again.
- **PyPI ahead of GitHub (or vice versa):** PyPI versions are immutable, so bump
  to the next patch rather than trying to overwrite one.
- **Abandon a release before `publish`:** delete the draft release and the tag
  (`git push origin :refs/tags/vX.Y.Z`) and revert the `chore(release)` commit.
