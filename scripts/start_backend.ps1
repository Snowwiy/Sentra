#Requires -Version 5.1
<#
.SYNOPSIS
    Starts the Sentra API with auto-reload for local development.
#>
[CmdletBinding()]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 8000,
    [switch]$NoReload
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$venvPython = Join-Path $backend ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPython)) { throw "Virtual environment missing. Run .\scripts\setup_windows.ps1 first." }
if (-not (Test-Path (Join-Path $root ".env"))) { throw ".env not found. Run .\scripts\setup_windows.ps1 first." }

# --no-proxy-headers (Fase 4M): X-Forwarded-For/Proto los interpreta Sentra segun
# TRUSTED_PROXIES (127.0.0.1 = el proxy de Vite), con la misma regla que en produccion.
$arguments = @("-m", "uvicorn", "app.main:app", "--host", $BindHost, "--port", $Port, "--no-proxy-headers")
if (-not $NoReload) { $arguments += @("--reload", "--reload-dir", "app") }

Push-Location $backend
try {
    Write-Host "Sentra API on http://${BindHost}:$Port (docs: /docs)" -ForegroundColor Green
    & $venvPython @arguments
} finally {
    Pop-Location
}
