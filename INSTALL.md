# Installing LogLens AI

LogLens ships as a **self-contained binary** (no system Python required) for
Linux, macOS and Windows. Neural `--deep` mode is bundled, and a warm daemon
keeps repeat runs fast. Pick whichever install path suits you - the one-line
installers are the most reliable because they pull the binary straight from
GitHub Releases and don't depend on any external package registry.

---

## macOS & Linux - one line (recommended)

```bash
curl -fsSL https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.sh | sh
```

- Detects your OS and CPU (Apple Silicon **and** Intel Macs, Linux x86-64).
- Installs to `~/.local` (no `sudo`); the `loglens` launcher lands in `~/.local/bin`.
- On macOS it clears the Gatekeeper quarantine bit so the unsigned binary runs.

Options:

```bash
# pin a version
LOGLENS_VERSION=0.13.0 sh -c "$(curl -fsSL .../install.sh)"
# or, after downloading install.sh:
sh install.sh --version 0.13.0 --dir /usr/local
```

If `~/.local/bin` isn't on your `PATH`, the installer prints the exact line to add.

---

## Windows - one line (PowerShell)

```powershell
irm https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.ps1 | iex
```

Installs to `%LOCALAPPDATA%\Programs\LogLens` and adds it to your user `PATH`
(restart the terminal afterward). Pin a version:

```powershell
$env:LOGLENS_VERSION="0.13.0"; irm https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.ps1 | iex
```

## Windows - MSI installer (machine-wide, double-click)

Download **`loglens-windows-x86_64.msi`** from the
[latest release](https://github.com/LoglensAI/LogLens-AI/releases/latest) and
run it. It installs to `Program Files\LogLens`, adds LogLens to the system
`PATH`, and cleanly uninstalls (and auto-upgrades) via *Add/Remove Programs*.

---

## Package managers

| Tool | Command |
|---|---|
| **Homebrew** (macOS) | `brew install loglensai/tap/loglens` |
| **winget** (Windows) | `winget install LoglensAI.LogLens` |
| **Scoop** (Windows) | `scoop bucket add loglens https://github.com/LoglensAI/scoop-bucket && scoop install loglens` |
| **APT** (Debian/Ubuntu) | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.deb.sh' \| sudo -E bash && sudo apt install loglens` |
| **DNF/YUM** (Fedora/RHEL) | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.rpm.sh' \| sudo -E bash && sudo dnf install loglens` |

Updates then arrive through that manager's normal upgrade command.

---

## Python (pip / pipx)

Great for developers and CI. Requires **Python 3.10+**.

```bash
pipx install loglensai            # or: pip install loglensai
pip install "loglensai[deep]"     # add transformer-based semantic detection
```

With `pip` the warm daemon is off by default - enable it with `LOGLENS_DAEMON=1`
or `loglens daemon start`.

---

## Docker

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
docker run --rm -v "$PWD:/data" loglensai/loglens:deep analyze --source app.log --deep
```

Multi-arch images for `linux/amd64` and `linux/arm64`.

---

## Portable tarball / zip

Every release attaches standalone archives you can unpack anywhere:

- `loglens-macos-arm64.tar.gz`, `loglens-macos-x86_64.tar.gz`
- `loglens-linux-x86_64.tar.gz`
- `loglens-windows-x86_64.zip`

Unpack and run `loglens/loglens` (or `loglens\loglens.exe`) directly.

---

## Verify

```bash
loglens version            # prints the installed version
loglens version --json     # version + commit + build date
loglens analyze --source /path/to/your.log
```

## Warm daemon

A resident process skips the ~1.7 s ML-import cost between runs. Native
installers start it automatically; manage it with
`loglens daemon start|stop|status|restart`.
