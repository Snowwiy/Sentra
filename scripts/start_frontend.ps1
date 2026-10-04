<#
.SYNOPSIS
    Starts the Sentra frontend (Vite dev server) on Windows.

.DESCRIPTION
    Installs npm dependencies when node_modules is missing or package-lock.json changed,
    then runs the Vite dev server. Configuration is read from frontend/.env.local
    (see frontend/.env.example). The dev server proxies /api to the backend.

.PARAMETER Install
    Force a clean dependency install (npm ci) before starting.

.PARAMETER Build
    Type check and build a production bundle into frontend/dist instead of starting the dev server.
#>
[CmdletBinding()]
param(
    [switch]$Install,
    [switch]$Build
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$frontendDir = Join-Path (Split-Path -Parent $PSScriptRoot) "frontend"
$minNodeVersion = [version]"20.19.0"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "Node.js no encontrado. Instala Node.js $minNodeVersion o superior (https://nodejs.org) y vuelve a abrir la terminal."
}

$nodeVersion = [version]((node --version).TrimStart("v"))
if ($nodeVersion -lt $minNodeVersion) {
    throw "Node.js $nodeVersion es demasiado antiguo. Se requiere $minNodeVersion o superior."
}

Push-Location $frontendDir
try {
    $lockFile = Join-Path $frontendDir "package-lock.json"
    $installedLock = Join-Path $frontendDir "node_modules\.package-lock.json"
    $needsInstall = $Install -or -not (Test-Path $installedLock) -or
        ((Get-Item $lockFile).LastWriteTime -gt (Get-Item $installedLock).LastWriteTime)

    if ($needsInstall) {
        Write-Host "Instalando dependencias del frontend..." -ForegroundColor Cyan
        npm ci --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) { throw "npm ci falló (código $LASTEXITCODE)." }
    }

    if (-not (Test-Path (Join-Path $frontendDir ".env.local"))) {
        Write-Host "Sin frontend/.env.local: se usan los valores por defecto (API en http://localhost:8000)." -ForegroundColor Yellow
    }

    if ($Build) {
        npm run build
        if ($LASTEXITCODE -ne 0) { throw "El build del frontend falló (código $LASTEXITCODE)." }
        Write-Host "Build listo en frontend\dist" -ForegroundColor Green
    }
    else {
        Write-Host "Iniciando Sentra frontend (Ctrl+C para detener)..." -ForegroundColor Cyan
        npm run dev
    }
}
finally {
    Pop-Location
}
