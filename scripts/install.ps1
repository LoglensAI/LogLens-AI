<#
.SYNOPSIS
  LogLens AI installer for Windows.

.DESCRIPTION
  One-liner:
    irm https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.ps1 | iex

  Order of operations:
    1. Download the self-contained release zip for Windows x64 (no Python needed),
       install under %LOCALAPPDATA%\Programs\LogLens, add it to the user PATH.
    2. If that zip isn't on the release, fall back to PyPI (pip install loglensai)
       IF a real Python is present.
    3. If neither works, print clear next steps instead of crashing.

  Prefer the MSI (loglens-windows-x86_64.msi) for a machine-wide, double-click install.

  Pin a version / change location:
    $env:LOGLENS_VERSION="0.13.1"; irm .../install.ps1 | iex
    powershell -File install.ps1 -Version 0.13.1 -InstallDir "C:\Tools\LogLens"
#>
[CmdletBinding()]
param(
  [string]$Version    = $env:LOGLENS_VERSION,
  [string]$InstallDir = $(if ($env:LOGLENS_INSTALL_DIR) { $env:LOGLENS_INSTALL_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\LogLens' })
)

$ErrorActionPreference = 'Stop'
$Repo  = 'LoglensAI/LogLens-AI'
$Asset = 'loglens-windows-x86_64.zip'
$PyPI  = 'loglensai'

function Info($m) { Write-Host "[LogLens] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[LogLens] $m" -ForegroundColor Yellow }
function Fail($m) { Write-Host "[LogLens] $m" -ForegroundColor Red; exit 1 }

function Add-UserPath($dir) {
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -eq $dir })) {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $dir } else { "$userPath;$dir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$dir"
    Info "Added $dir to your user PATH (open a new terminal to pick it up)."
  }
}

# Run a native command WITHOUT letting its stderr turn into a terminating error
# (the Microsoft Store 'python' stub writes to stderr, which would otherwise crash
# the script under $ErrorActionPreference='Stop').
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
  $prev = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try {
    $out  = (& $Exe @Arguments 2>&1 | Out-String)
    $code = $LASTEXITCODE
  } catch {
    $out = "$_"; $code = 1
  } finally {
    $ErrorActionPreference = $prev
  }
  return [pscustomobject]@{ Code = $code; Out = $out }
}

# Return @(exe, preargs...) for a REAL Python 3.10+, or $null.
# Rejects the Microsoft Store alias stub (it exits non-zero with a 'not found' message).
function Get-WorkingPython {
  $cands = @(
    @{ Exe = 'py';      Pre = @('-3') },
    @{ Exe = 'python';  Pre = @() },
    @{ Exe = 'python3'; Pre = @() }
  )
  foreach ($c in $cands) {
    $cmd = Get-Command $c.Exe -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    $probe = Invoke-Native $cmd.Source (@($c.Pre) + '--version')
    if ($probe.Code -eq 0 -and $probe.Out -match 'Python\s+3\.(1[0-9]|[2-9]\d)' -and $probe.Out -notmatch 'was not found|Microsoft Store') {
      return (@($cmd.Source) + $c.Pre)
    }
  }
  return $null
}

function Install-FromPyPI {
  Warn 'Trying a PyPI install (pip install loglensai)…'

  # pipx first (isolated, manages PATH) — only exists if Python already does.
  $pipx = Get-Command pipx -ErrorAction SilentlyContinue
  if ($pipx) {
    Info 'Installing with pipx…'
    $r = Invoke-Native $pipx.Source @('install', '--force', $PyPI)
    if ($r.Out) { Write-Host $r.Out }
    if ($r.Code -eq 0) { Info 'Installed via pipx. Open a NEW terminal, then:  loglens version'; return }
    Warn 'pipx did not succeed; trying pip…'
  }

  $py = Get-WorkingPython
  if (-not $py) {
    Fail @"
No prebuilt Windows binary on the Releases page, and no working Python on this machine
(the 'python' here is the Microsoft Store stub, not a real install).

Pick one:
  1) Install Python 3.10+, then re-run this one-liner:
       winget install -e --id Python.Python.3.12
  2) Download the MSI or zip from the GitHub Releases page (once binaries are attached):
       https://github.com/$Repo/releases
  3) Have WSL / Git Bash?  Run inside it:
       pip install $PyPI
"@
  }

  $exe    = $py[0]
  $pyArgs = @(); if ($py.Count -gt 1) { $pyArgs = $py[1..($py.Count - 1)] }

  $ver = (Invoke-Native $exe (@($pyArgs) + '--version')).Out.Trim()
  Info "Using Python: $ver"

  Info "Installing $PyPI from PyPI (user site)…"
  $r = Invoke-Native $exe (@($pyArgs) + @('-m', 'pip', 'install', '--user', '--upgrade', $PyPI))
  if ($r.Out) { Write-Host $r.Out }
  if ($r.Code -ne 0) { Fail "pip install $PyPI failed. Try inside a venv:  pip install $PyPI" }

  # Add the user Scripts dir (where loglens.exe lands) to PATH.
  $scripts = (Invoke-Native $exe (@($pyArgs) + @('-c', 'import sysconfig; print(sysconfig.get_path(''scripts'',''nt_user''))'))).Out.Trim()
  if ($scripts -and (Test-Path $scripts)) { Add-UserPath $scripts }

  Info 'Done. Open a NEW terminal, then try:  loglens version'
}

if ([Environment]::Is64BitOperatingSystem -eq $false) {
  Warn 'Prebuilt binaries are 64-bit only; using the PyPI install instead.'
  Install-FromPyPI
  return
}

if ($Version) {
  $tag = 'v' + ($Version -replace '^v','')
  $url = "https://github.com/$Repo/releases/download/$tag/$Asset"
} else {
  $url = "https://github.com/$Repo/releases/latest/download/$Asset"
}

$tmp = Join-Path $env:TEMP ("loglens-" + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
$zip = Join-Path $tmp $Asset

try {
  Info "Downloading $Asset…"
  $downloaded = $true
  try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  } catch {
    $downloaded = $false
    Warn "No prebuilt zip at: $url"
  }

  if (-not $downloaded) {
    Install-FromPyPI
    return
  }

  Info 'Unpacking…'
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $src = Join-Path $tmp 'loglens'
  if (-not (Test-Path $src)) { Fail 'Unexpected archive layout (no loglens\ directory).' }

  Info "Installing to $InstallDir…"
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir) | Out-Null
  Move-Item $src $InstallDir

  Add-UserPath $InstallDir

  $exe = Join-Path $InstallDir 'loglens.exe'
  if (Test-Path $exe) {
    $ver = (& $exe version) 2>$null
    Info "Installed: $ver"
  }
  Info 'Done. Try:  loglens analyze --source C:\path\to\your.log'
}
finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}