<#
.SYNOPSIS
  LogLens AI installer for Windows.

.DESCRIPTION
  One-liner:
    irm https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.ps1 | iex

  Installs LogLens in two ways, automatically:
    1. Downloads the self-contained release zip for Windows x64 from GitHub
       Releases, installs it under %LOCALAPPDATA%\Programs\LogLens, and adds it
       to your user PATH. No Python needed.
    2. If the release zip isn't available, falls back to installing from PyPI
       (pip install loglensai) so the one-liner still works.

  Prefer the MSI (loglens-windows-x86_64.msi) for a machine-wide, double-click install.

  Pin a version or change the location:
    $env:LOGLENS_VERSION="0.13.0"; irm .../install.ps1 | iex
    powershell -File install.ps1 -Version 0.13.0 -InstallDir "C:\Tools\LogLens"
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
  # Idempotently add a directory to the user PATH (and this session's PATH).
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -eq $dir })) {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $dir } else { "$userPath;$dir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$dir"
    Info "Added $dir to your user PATH (restart your terminal to pick it up)."
  }
}

function Find-Python {
  foreach ($cand in @('py', 'python', 'python3')) {
    $cmd = Get-Command $cand -ErrorAction SilentlyContinue
    if ($cmd) {
      # `py` needs -3; the others are called directly.
      if ($cand -eq 'py') { return @($cmd.Source, '-3') } else { return @($cmd.Source) }
    }
  }
  return $null
}

function Install-FromPyPI {
  Warn 'Falling back to a PyPI install (pip install loglensai)…'

  # Prefer pipx (isolated + handles PATH) when present.
  $pipx = Get-Command pipx -ErrorAction SilentlyContinue
  if ($pipx) {
    Info 'Installing with pipx…'
    & $pipx.Source install --force $PyPI
    if ($LASTEXITCODE -eq 0) {
      Info 'Installed via pipx. Try:  loglens version'
      return $true
    }
    Warn 'pipx install did not succeed; trying pip…'
  }

  $py = Find-Python
  if (-not $py) {
    Fail "No prebuilt zip on the Releases page and no Python found. Install Python 3.10+ from https://python.org then run:  pip install $PyPI"
  }
  $py = @($py)                       # normalize to an array before indexing (PS 5.1 unwraps single-element arrays)

  $exe    = $py[0]
  $pyArgs = @()                      # NOTE: not $args — that is a reserved automatic variable
  if ($py.Count -gt 1) { $pyArgs = $py[1..($py.Count-1)] }

  $verText = (& $exe @pyArgs --version) 2>&1
  Info "Using Python: $verText"

  Info "Installing $PyPI from PyPI (user site)…"
  & $exe @pyArgs -m pip install --user --upgrade $PyPI
  if ($LASTEXITCODE -ne 0) { Fail "pip install $PyPI failed. Check your Python/pip, or install in a venv:  pip install $PyPI" }

  # Put the user Scripts dir (where loglens.exe lands) on PATH.
  $scripts = (& $exe @pyArgs -c "import sysconfig; print(sysconfig.get_path('scripts','nt_user'))") 2>$null
  if ($scripts -and (Test-Path $scripts)) { Add-UserPath $scripts }

  $loglensExe = if ($scripts) { Join-Path $scripts 'loglens.exe' } else { 'loglens' }
  if (Test-Path $loglensExe) {
    $ver = (& $loglensExe version) 2>$null
    Info "Installed: $ver"
  } else {
    Info 'Installed from PyPI.'
  }
  Info 'Done. Open a NEW terminal, then try:  loglens analyze --source C:\path\to\your.log'
  return $true
}

if ([Environment]::Is64BitOperatingSystem -eq $false) {
  Warn 'Prebuilt binaries are 64-bit only; using the PyPI install instead.'
  [void](Install-FromPyPI)
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
    # Release asset missing (e.g. not attached yet) — use PyPI instead.
    [void](Install-FromPyPI)
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