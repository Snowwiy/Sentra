#Requires -Version 5.1
<#
.SYNOPSIS
    Runs the Sentra agent in the foreground on this machine.
.DESCRIPTION
    Uses agent\.venv created by setup_windows.ps1. Runs as the current user (no admin rights).
    For a permanent installation use the Windows service (docs/agent-windows-installation.md).
    Stop it with Ctrl+C. Extra arguments are passed to the agent,
    e.g. -Once or -Config path\to\agent.toml.
#>
[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:8000",
    [int]$Interval = 30,
    [string]$Config,
    [switch]$Once,
    [switch]$AllowWithService
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$agentDir = Join-Path $root "agent"
$venvPython = Join-Path $agentDir ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { throw "Agent environment missing. Run .\scripts\setup_windows.ps1 first." }

# Con el servicio Windows instalado, el instalador pudo importar la identidad de esta
# ejecución manual: dos agentes con el mismo agent_id se enrolarían por turnos y se
# invalidarían el token mutuamente. -AllowWithService solo para quien sabe que no es el caso.
if ((Get-Service -Name SentraAgent -ErrorAction SilentlyContinue) -and -not $AllowWithService) {
    throw "El servicio Windows 'Sentra Agent' está instalado en este equipo: no ejecutes además el agente manual (usa Get-Service SentraAgent / logs en C:\ProgramData\Sentra\Agent\logs)."
}

# Development convenience: when the agent runs on the same machine as the API, take the
# enrollment key from the server's .env. Remote hosts set SENTRA_AGENT_ENROLLMENT_KEY instead.
# The key is passed through the process environment, never on the command line, so it does
# not show up in process listings.
if (-not $env:SENTRA_AGENT_ENROLLMENT_KEY) {
    $envFile = Join-Path $root ".env"
    if (Test-Path $envFile) {
        $line = Get-Content $envFile | Where-Object { $_ -match '^\s*AGENT_ENROLLMENT_KEY\s*=' } | Select-Object -First 1
        if ($line) { $env:SENTRA_AGENT_ENROLLMENT_KEY = ($line -split "=", 2)[1].Trim() }
    }
}

$arguments = @("-m", "sentra_agent", "--api-url", $ApiUrl, "--interval", $Interval)
if ($Config) { $arguments += @("--config", $Config) }
if ($Once) { $arguments += "--once" }

& $venvPython @arguments
exit $LASTEXITCODE
