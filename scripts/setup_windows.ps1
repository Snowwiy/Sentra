#Requires -Version 5.1
<#
.SYNOPSIS
    Prepares a Windows development environment for Sentra.
.DESCRIPTION
    Creates the backend virtual environment, installs Python dependencies, creates .env from
    .env.example with a random database password, and installs frontend dependencies when
    the frontend project exists. Safe to run more than once.
#>
[CmdletBinding()]
param(
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$venv = Join-Path $backend ".venv"

Write-Host "==> Checking Python" -ForegroundColor Cyan
$version = & $Python -c "import sys; print('%d.%d' % sys.version_info[:2])"
if ([version]$version -lt [version]"3.12") {
    throw "Python 3.12 or newer is required (found $version)."
}

if (-not (Test-Path $venv)) {
    Write-Host "==> Creating virtual environment in backend\.venv" -ForegroundColor Cyan
    & $Python -m venv $venv
}
$venvPython = Join-Path $venv "Scripts\python.exe"

Write-Host "==> Installing backend dependencies" -ForegroundColor Cyan
& $venvPython -m pip install --upgrade pip --quiet
& $venvPython -m pip install -r (Join-Path $backend "requirements-dev.txt") --quiet
if ($LASTEXITCODE -ne 0) { throw "pip install failed." }

# The agent gets its own environment: it ships to monitored hosts separately from the API
# and must not depend on backend packages.
$agentDir = Join-Path $root "agent"
$agentVenv = Join-Path $agentDir ".venv"
if (-not (Test-Path $agentVenv)) {
    Write-Host "==> Creating virtual environment in agent\.venv" -ForegroundColor Cyan
    & $Python -m venv $agentVenv
}
Write-Host "==> Installing agent dependencies" -ForegroundColor Cyan
$agentPython = Join-Path $agentVenv "Scripts\python.exe"
& $agentPython -m pip install --upgrade pip --quiet
& $agentPython -m pip install -e "$agentDir[dev]" --quiet
if ($LASTEXITCODE -ne 0) { throw "agent pip install failed." }

$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) {
    Write-Host "==> Creating .env with a random database password" -ForegroundColor Cyan
    $chars = [char[]]"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    $bytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $password = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })

    # Installers pick another port (e.g. 5433) when 5432 is taken, so read the real one from
    # the local server config instead of assuming the default.
    $port = 5432
    $conf = Get-ChildItem "C:\Program Files\PostgreSQL\*\data\postgresql.conf" -ErrorAction SilentlyContinue |
        Sort-Object { [int]$_.Directory.Parent.Name } -Descending | Select-Object -First 1
    if ($conf) {
        $match = Select-String -Path $conf.FullName -Pattern '^\s*port\s*=\s*(\d+)' | Select-Object -First 1
        if ($match) { $port = [int]$match.Matches[0].Groups[1].Value }
    }
    Write-Host "    PostgreSQL port: $port"

    $keyBytes = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($keyBytes)
    $enrollmentKey = [Convert]::ToBase64String($keyBytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")

    # Replace the enrollment placeholder first: it also contains "change-me".
    (Get-Content (Join-Path $root ".env.example") -Raw).Replace("change-me-enrollment-key", $enrollmentKey).Replace("change-me", $password).Replace("127.0.0.1:5432/", "127.0.0.1:$port/") |
        Set-Content -Path $envFile -NoNewline -Encoding ascii
} else {
    Write-Host "==> .env already exists, leaving it unchanged" -ForegroundColor Yellow
}

$frontend = Join-Path $root "frontend"
if (Test-Path (Join-Path $frontend "package.json")) {
    Write-Host "==> Installing frontend dependencies" -ForegroundColor Cyan
    Push-Location $frontend
    try {
        npm install
        if ($LASTEXITCODE -ne 0) { throw "npm install failed." }
    } finally {
        Pop-Location
    }
}

Write-Host ""
Write-Host "Setup complete. Next: .\scripts\init_database.ps1" -ForegroundColor Green
