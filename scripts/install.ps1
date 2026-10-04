<#
.SYNOPSIS
  LogLens AI installer for Windows (direct binary download — no winget needed).

.DESCRIPTION
  One-liner:
    irm https://raw.githubusercontent.com/LoglensAI/LogLens-AI/main/scripts/install.ps1 | iex

  Downloads the self-contained release zip for Windows x64 from GitHub Releases,
  installs it under %LOCALAPPDATA%\Programs\LogLens, and adds it to your user PATH.
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

function Info($m) { Write-Host "[LogLens] $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "[LogLens] $m" -ForegroundColor Red; exit 1 }

if ([Environment]::Is64BitOperatingSystem -eq $false) {
  Fail 'LogLens prebuilt binaries are 64-bit only. Try: pip install loglensai'
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
  try {
    Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
  } catch {
    Fail "Download failed: $url  (check the version exists on the Releases page)"
  }

  Info 'Unpacking…'
  Expand-Archive -Path $zip -DestinationPath $tmp -Force
  $src = Join-Path $tmp 'loglens'
  if (-not (Test-Path $src)) { Fail 'Unexpected archive layout (no loglens\ directory).' }

  Info "Installing to $InstallDir…"
  if (Test-Path $InstallDir) { Remove-Item -Recurse -Force $InstallDir }
  New-Item -ItemType Directory -Force -Path (Split-Path $InstallDir) | Out-Null
  Move-Item $src $InstallDir

  # --- add to user PATH (idempotent) --------------------------------------- #
  $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
  if (-not ($userPath -split ';' | Where-Object { $_ -eq $InstallDir })) {
    $newPath = if ([string]::IsNullOrEmpty($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    $env:Path = "$env:Path;$InstallDir"
    Info 'Added LogLens to your user PATH (restart your terminal to pick it up).'
  }

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
