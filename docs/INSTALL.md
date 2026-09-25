# Installing LogLens AI

LogLens installs as a **self-contained binary** on Linux, macOS and Windows - no
Python, no `pip`, no virtualenv. Neural (`--deep`) mode is **built in**, and a
warm daemon starts automatically so repeat runs are near-instant.

Prefer `pip`? That works too and is great for developers - see [Python (pip)](#python-pip).

| Platform | One-liner | Details |
|---|---|---|
| **Linux (Debian/Ubuntu)** | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.deb.sh' \| sudo -E bash && sudo apt install loglens` | [Linux](#linux) |
| **Linux (Fedora/RHEL)** | `curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.rpm.sh' \| sudo -E bash && sudo dnf install loglens` | [Linux](#linux) |
| **macOS** | `brew install loglensai/tap/loglens` | [macOS](#macos) |
| **Windows** | `winget install LoglensAI.LogLens` | [Windows](#windows) |
| **Any (developers)** | `pipx install loglensai` | [Python](#python-pip) |
| **Docker** | `docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log` | [Docker](#docker) |

After installing, verify with:

```bash
loglens version
loglens help
loglens analyze --source /path/to/your.log
```

---

## Linux

Self-contained binary, neural mode built in, warm daemon registered as a systemd
user service. The apt/yum repo is hosted on Cloudsmith (packages are signed and
the key is installed for you).

### Debian / Ubuntu / Mint / Pop!_OS (APT)

```bash
# add the repo once (installs signing key + sources list)
curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.deb.sh' | sudo -E bash
# install
sudo apt install loglens
```

Updates then arrive normally:

```bash
sudo apt update && sudo apt upgrade      # get new versions
sudo apt remove loglens                  # uninstall
```

### Fedora / RHEL / openSUSE (RPM)

```bash
curl -1sLf 'https://dl.cloudsmith.io/public/loglensai/loglensai-363o/setup.rpm.sh' | sudo -E bash
sudo dnf install loglens                 # or: sudo yum install loglens
```

### One-liner (auto-detects apt/dnf)

```bash
curl -fsSL https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.sh | sh
```

### Portable tarball (any distro)

```bash
curl -fsSL -o loglens.tar.gz \
  https://github.com/LoglensAI/LogLens-AI/releases/latest/download/loglens-linux-x86_64.tar.gz
sudo tar -xzf loglens.tar.gz -C /opt
sudo ln -sf /opt/loglens/loglens /usr/local/bin/loglens
```

### The warm daemon (Linux)

The apt/rpm packages register a **systemd user service**, so the daemon is warm
after login:

```bash
systemctl --user status loglens      # running?
systemctl --user start  loglens      # start now
systemctl --user disable loglens     # opt out of autostart
loglens daemon status                # LogLens' own view
```

Even without the service, the first `loglens analyze` starts the daemon on
demand - you never manage it manually.

---

## macOS

Self-contained binary for **Apple Silicon** (M-series). Intel Macs: use
[pip](#python-pip).

### Homebrew (recommended)

```bash
brew tap loglensai/tap
brew install loglens
```

```bash
brew upgrade loglens                 # update
brew uninstall loglens               # remove
brew services start loglens          # keep the daemon warm across logins (optional)
```

### Portable tarball

```bash
curl -fsSL -o loglens.tar.gz \
  https://github.com/LoglensAI/LogLens-AI/releases/latest/download/loglens-macos-arm64.tar.gz
sudo tar -xzf loglens.tar.gz -C /usr/local/lib
sudo ln -sf /usr/local/lib/loglens/loglens /usr/local/bin/loglens
```

**Gatekeeper:** until the binaries are notarized, macOS may warn about an
"unidentified developer." Homebrew avoids this. For a manual download, allow it
once with `xattr -dr com.apple.quarantine /usr/local/lib/loglens`, or **System
Settings → Privacy & Security → Open Anyway**.

---

## Windows

Self-contained `loglens.exe`, neural mode built in, warm daemon starts on first run.

### winget (recommended)

```powershell
winget install LoglensAI.LogLens
winget upgrade LoglensAI.LogLens
winget uninstall LoglensAI.LogLens
```

### Scoop

```powershell
scoop bucket add loglens https://github.com/LoglensAI/scoop-bucket
scoop install loglens
scoop update loglens
```

### Installer (.exe)

Download **LogLens-Setup-x64.exe** from the
[latest release](https://github.com/LoglensAI/LogLens-AI/releases/latest) and run
it - the wizard can add `loglens` to `PATH` and start the daemon at logon.

**SmartScreen:** until the binaries are code-signed, Windows may show "Windows
protected your PC" on first run of the `.exe`. Click **More info → Run anyway**.
`winget`/`scoop` installs generally avoid this.

---

## Python (pip)

Great for developers, CI, and Intel Macs. Requires **Python 3.10+**.

```bash
pipx install loglensai          # isolated, recommended
# or:
pip install loglensai
pip install "loglensai[deep]"   # add neural (transformer) mode
```

> With `pip`, the daemon is **off by default**. Turn it on with
> `LOGLENS_DAEMON=1` or `loglens daemon start`. Native installer builds enable it
> automatically.

---

## Docker

Multi-arch images (amd64 + arm64):

```bash
docker run --rm -v "$PWD:/data" loglensai/loglens analyze --source app.log
```

---

## Environment toggles

| Variable | Effect |
|---|---|
| `LOGLENS_DAEMON=1` / `0` | Force the warm daemon on / off. (Installer builds: on by default; pip: off by default.) |
| `LOGLENS_WARNINGS=1` | Show all third-party warnings (suppressed by default). |
| `LOGLENS_MODEL_DIR=<dir>` | Use a local neural model directory instead of downloading. |

## Verify your install

```bash
loglens version                              # prints the version
loglens help                                 # lists all commands
loglens analyze --source app.log             # fast (TF-IDF)
loglens analyze --source huge.log --turbo    # parallel scan for big files
loglens analyze --source app.log --deep      # neural (bundled, offline)
loglens analyze --source app.log --format json --fail-on error   # CI/CD gating
```

Run `loglens <command> --help` (e.g. `loglens analyze --help`) to see a
command's flags and examples.

---

## Troubleshooting

- **`loglens: command not found`** - open a new shell so `PATH` reloads; for the
  portable tarball, ensure `/usr/local/bin` is on `PATH`.
- **See every warning again** - set `LOGLENS_WARNINGS=1`.
- **Force in-process (no daemon)** - set `LOGLENS_DAEMON=0`.
- **Windows daemon** - uses a loopback TCP socket guarded by a random token
  (Unix sockets on Linux/macOS); nothing is exposed off-machine.