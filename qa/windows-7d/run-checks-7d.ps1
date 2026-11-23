#Requires -Version 5.1
<#
.SYNOPSIS
    Fase 7D (7D.1 + 7D.2): comprobaciones estaticas y todas las suites en Windows 11.

.DESCRIPTION
    Ejecuta, componente a componente, lo mismo que el CI de GitHub (.github/workflows/ci.yml):
    ruff, ruff format, mypy (Windows y Linux simulado), pytest, alembic check, lint, typecheck,
    tests del frontend con Node 22/24 y build, auditoria de dependencias y repo-hygiene.

    La suite del backend usa TEST_DATABASE_URL (sentra_test). Nunca la base productiva: el script
    se niega a continuar si TEST_DATABASE_URL apunta a la base "sentra".

    Escribe un resumen en qa\windows-7d\out\checks-<fecha>.txt (sin secretos: solo nombres de
    paso, codigo de salida y duracion). Sin acentos en el fichero: PowerShell 5.1 lee los .ps1
    sin BOM como ANSI.

.EXAMPLE
    .\qa\windows-7d\run-checks-7d.ps1
    .\qa\windows-7d\run-checks-7d.ps1 -Skip backend   # p. ej. si ya se ejecuto (1 h 40 min)
#>
[CmdletBinding()]
param(
    [string[]]$Skip = @(),
    [switch]$NoAudit
)

$ErrorActionPreference = "Continue"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$summary = Join-Path $out ("checks-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".txt")
$results = New-Object System.Collections.Generic.List[string]

function Invoke-Step([string]$Component, [string]$Name, [string]$Dir, [scriptblock]$Command) {
    if ($Skip -contains $Component) { return }
    Push-Location (Join-Path $root $Dir)
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Command
        $code = $LASTEXITCODE
    } catch {
        Write-Host $_ -ForegroundColor Red
        $code = 99
    } finally {
        Pop-Location
    }
    $line = "{0,-8} {1,-48} exit={2} {3:n0}s" -f $Component, $Name, $code, $watch.Elapsed.TotalSeconds
    $color = if ($code -eq 0) { "Green" } else { "Red" }
    Write-Host $line -ForegroundColor $color
    $results.Add($line)
}

$testUrl = $env:TEST_DATABASE_URL
if ($testUrl -and $testUrl -match "/sentra(\?|$)") {
    throw "TEST_DATABASE_URL apunta a la base productiva 'sentra'. Usar sentra_test."
}

$py = ".venv\Scripts\python.exe"

Invoke-Step backend "ruff check" "backend" { & $py -m ruff check . }
Invoke-Step backend "ruff format --check" "backend" { & $py -m ruff format --check . }
Invoke-Step backend "mypy app tests (win32)" "backend" { & $py -m mypy --no-incremental app tests }
Invoke-Step backend "mypy app tests (linux)" "backend" { & $py -m mypy --no-incremental --platform linux app tests }
Invoke-Step backend "pytest (sentra_test)" "backend" { & $py -m pytest -q }

Invoke-Step agent "ruff check" "agent" { & $py -m ruff check . }
Invoke-Step agent "ruff format --check" "agent" { & $py -m ruff format --check . }
Invoke-Step agent "mypy (win32)" "agent" { & $py -m mypy --no-incremental sentra_agent tests }
Invoke-Step agent "mypy (linux)" "agent" { & $py -m mypy --no-incremental --platform linux sentra_agent tests }
Invoke-Step agent "mypy (darwin)" "agent" { & $py -m mypy --no-incremental --platform darwin sentra_agent tests }
Invoke-Step agent "pytest" "agent" { & $py -m pytest -q }

Invoke-Step sensor "ruff check" "sensor" { & $py -m ruff check . }
Invoke-Step sensor "ruff format --check" "sensor" { & $py -m ruff format --check . }
Invoke-Step sensor "mypy (win32)" "sensor" { & $py -m mypy --no-incremental . }
Invoke-Step sensor "mypy (linux)" "sensor" { & $py -m mypy --no-incremental --platform linux . }
Invoke-Step sensor "pytest" "sensor" { & $py -m pytest -q }

Invoke-Step frontend "npm ci --ignore-scripts" "frontend" { npm ci --ignore-scripts }
Invoke-Step frontend "lint" "frontend" { npm run lint }
Invoke-Step frontend "typecheck" "frontend" { npm run typecheck }
Invoke-Step frontend "vitest (Node local)" "frontend" { npm test }
Invoke-Step frontend "vitest (Node 22)" "frontend" { npx --yes node@22 node_modules/vitest/vitest.mjs run }
Invoke-Step frontend "build" "frontend" { npm run build }

if (-not $NoAudit) {
    Invoke-Step audit "npm audit (todas)" "frontend" { npm audit --audit-level=moderate }
    Invoke-Step audit "npm audit (produccion)" "frontend" { npm audit --omit=dev --audit-level=low }
    # pip-audit en un venv aparte, fuera del repositorio: no toca los venvs de desarrollo ni
    # deja ficheros no versionados que repo-hygiene tendria que revisar.
    $auditVenv = Join-Path $env:LOCALAPPDATA "sentra-audit-venv"
    Invoke-Step audit "pip-audit backend" "." {
        if (-not (Test-Path "$auditVenv\Scripts\python.exe")) {
            py -3.13 -m venv $auditVenv
            & "$auditVenv\Scripts\python.exe" -m pip install -q pip-audit==2.10.1
        }
        & "$auditVenv\Scripts\python.exe" -m pip_audit --progress-spinner off -r backend\requirements-dev.txt
    }
}

Invoke-Step hygiene "repo-hygiene --self-test" "." { & "backend\$py" scripts\ci\check_repo_hygiene.py --self-test }
Invoke-Step hygiene "repo-hygiene (incluye no versionados)" "." { & "backend\$py" scripts\ci\check_repo_hygiene.py --include-untracked }

$results | Set-Content -Encoding ascii $summary
$failed = @($results | Where-Object { $_ -notmatch "exit=0 " })
Write-Host ""
Write-Host "Resumen: $summary"
if ($failed.Count -gt 0) {
    Write-Host ("{0} pasos fallidos" -f $failed.Count) -ForegroundColor Red
    exit 1
}
Write-Host "Todos los pasos en verde" -ForegroundColor Green
