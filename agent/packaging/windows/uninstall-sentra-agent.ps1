#Requires -Version 5.1
<#
.SYNOPSIS
    Desinstala Sentra Agent de este equipo Windows.

.DESCRIPTION
    En PowerShell como administrador:

        & 'C:\Program Files\Sentra Agent\uninstall-sentra-agent.ps1'          # conserva identidad
        & 'C:\Program Files\Sentra Agent\uninstall-sentra-agent.ps1' -Purge   # borra todo

    Por defecto detiene y elimina el servicio SentraAgent, quita su cuenta virtual del grupo
    "Event Log Readers" y borra los binarios (C:\Program Files\Sentra Agent). CONSERVA
    C:\ProgramData\Sentra\Agent: configuración, identidad (agent_id y token individual
    cifrado) y logs. Reinstalar después reutiliza esa identidad: el equipo vuelve como el
    mismo activo sin token de instalación nuevo.

    -Purge borra además C:\ProgramData\Sentra\Agent. Consecuencias: se pierde el agent_id y el
    token individual; una reinstalación necesita un token de instalación nuevo y aparece como
    un activo NUEVO en Sentra (el anterior queda con su historial; puedes revocarlo en
    Agentes). También se pierden los logs y el buffer de telemetría pendiente de enviar.

    El perfil de Windows de la cuenta virtual (creado por el sistema) no se toca.
#>
[CmdletBinding()]
param(
    [switch]$Purge
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$ServiceName = 'SentraAgent'
$EventLogReadersSid = 'S-1-5-32-573'

function Write-Step([string]$Message) { Write-Host "sentra-agent: $Message" }
function Write-Warn([string]$Message) { Write-Warning "sentra-agent: $Message" }

function Stop-Uninstall([string]$Message) {
    Write-Host "sentra-agent: ERROR: $Message" -ForegroundColor Red
    exit 1
}

function Invoke-Native {
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    [pscustomobject]@{ ExitCode = $code; Output = (@($output | ForEach-Object { "$_" }) -join "`n") }
}

function Get-UninstallLayout {
    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    [pscustomobject]@{
        InstallDir = Join-Path $programFiles 'Sentra Agent'
        DataDir    = Join-Path $programData 'Sentra\Agent'
        SentraDir  = Join-Path $programData 'Sentra'
    }
}

function Remove-AgentService {
    $service = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $service) {
        Write-Step 'el servicio SentraAgent no existe'
        return
    }
    if ($service.State -ne 'Stopped') {
        Write-Step 'deteniendo el servicio (espera a que termine el ciclo en curso)'
        $controller = Get-Service -Name $ServiceName
        $controller.Stop()
        try {
            $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(150))
        } catch {
            # Último recurso, solo en la desinstalación: el proceso del servicio no respondió
            # a la parada. Se termina ese PID concreto (el del servicio), nunca por nombre.
            $current = Get-CimInstance -ClassName Win32_Service -Filter "Name='$ServiceName'"
            if ($current.ProcessId) {
                Write-Warn "el servicio no se detuvo; se termina su proceso (PID $($current.ProcessId))"
                Stop-Process -Id $current.ProcessId -Force
                Start-Sleep -Seconds 2
            }
        }
    }
    $result = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments @('delete', $ServiceName)
    if ($result.ExitCode -ne 0) { throw "sc.exe delete falló ($($result.ExitCode)): $($result.Output)" }
    for ($i = 0; $i -lt 15 -and (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue); $i++) {
        Start-Sleep -Seconds 1
    }
    Write-Step 'servicio SentraAgent eliminado'
}

function Remove-EventLogAccess {
    # Quita solo la entrada de este servicio del grupo; el resto de miembros no se toca.
    $account = (New-Object Security.Principal.SecurityIdentifier($EventLogReadersSid)).Translate([Security.Principal.NTAccount]).Value
    $group = $account.Split('\')[-1]
    $member = "NT SERVICE\$ServiceName"
    $listing = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') -Arguments @('localgroup', $group)
    $isMember = $false
    foreach ($line in ($listing.Output -split "`n")) { if ($line.Trim() -ieq $member) { $isMember = $true } }
    if (-not $isMember) { return }
    $removed = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') -Arguments @('localgroup', $group, $member, '/delete')
    if ($removed.ExitCode -eq 0) {
        Write-Step "$member quitado de '$group'"
    } else {
        Write-Warn "no se pudo quitar $member de '$group': $($removed.Output)"
    }
}

function Invoke-Uninstall {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Uninstall 'ejecuta PowerShell como administrador'
    }
    $paths = Get-UninstallLayout
    # Si la consola está dentro de la carpeta que se va a borrar, Windows no puede eliminarla.
    Set-Location -LiteralPath $env:SystemRoot

    Remove-AgentService
    Remove-EventLogAccess
    if (Test-Path -LiteralPath $paths.InstallDir) {
        Remove-Item -LiteralPath $paths.InstallDir -Recurse -Force
        Write-Step "binarios eliminados: $($paths.InstallDir)"
    }

    if ($Purge) {
        if (Test-Path -LiteralPath $paths.DataDir) {
            Remove-Item -LiteralPath $paths.DataDir -Recurse -Force
        }
        # ProgramData\Sentra solo se borra si queda vacía (podría alojar otros componentes).
        if ((Test-Path -LiteralPath $paths.SentraDir) -and -not (Get-ChildItem -LiteralPath $paths.SentraDir -Force)) {
            Remove-Item -LiteralPath $paths.SentraDir -Force
        }
        Write-Step "purgado: configuración, identidad, token individual y logs eliminados ($($paths.DataDir))"
        Write-Step 'una reinstalación necesitará un token nuevo y será un activo nuevo en Sentra; revoca el anterior en Agentes si ya no se usa'
    } else {
        Write-Step "conservado: $($paths.DataDir) (configuración, identidad y logs)"
        Write-Step 'reinstalar reutiliza esta identidad (mismo activo); -Purge lo borra todo'
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Uninstall
    } catch {
        Stop-Uninstall $_.Exception.Message
    }
}
