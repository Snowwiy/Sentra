#Requires -Version 5.1
<#
.SYNOPSIS
    Fase 7B.0: recoge, SOLO LEYENDO, la evidencia local que la auditoría necesita y que el
    servidor no tiene (o no puede tener) para clasificar CORR-002, PER-001, SCR-001 y NET-001.

.DESCRIPTION
    Ejecutar en PowerShell como administrador (el registro Security y algunos procesos lo
    requieren; sin privilegios, lo que no se pueda leer queda como "unavailable"):

        powershell -NoProfile -File .\scripts\collect_7b_evidence.ps1 -RepoRoot C:\Users\hexan\Documents\Sentra

    Qué lee (y nada más):
      - el servicio SentraAgent (y cualquier servicio cuyo nombre o ruta contenga "sentra"):
        nombre, nombre visible, ImagePath, cuenta, estado, PID, proceso padre, SHA-256 y
        firma Authenticode del ejecutable;
      - la versión del agente que ejecuta el servicio (leída del __init__.py instalado junto al
        runtime) frente a la del repositorio y la de su .venv;
      - SHA-256 y firma de install-sentra-agent.ps1, init_database.ps1 y los demás .ps1 del
        repositorio, para registrar operaciones de mantenimiento con hashes de referencia;
      - eventos 4104 (Windows PowerShell y PowerShell 7), 7045 y 4688 de los últimos -Days días,
        solo sus campos estructurados. Nunca el texto del script (ScriptBlockText) ni la línea
        de comandos del 4688 (puede contener secretos): de esta solo dice si existe;
      - quién escucha en los puertos 8000, 5432 y 5433 (proceso, ruta, hash, firma, servicio);
      - si el registro de bloques de script y la línea de comandos del 4688 están habilitados
        por directiva (lectura del registro y de auditpol /get).

    No cambia Defender, el firewall, la directiva de ejecución, la auditoría, permisos ni
    servicios. Escribe un único archivo JSON (-Output) y un resumen por pantalla. El propio
    script puede generar eventos 4104 informativos al ejecutarse: es lo esperado.

.PARAMETER RepoRoot
    Carpeta del repositorio Sentra (por defecto, la carpeta padre de scripts\).

.PARAMETER Days
    Ventana de eventos (por defecto 30 días).

.PARAMETER MaxEvents
    Tope de eventos por canal (por defecto 500).

.PARAMETER Output
    Archivo JSON de salida (por defecto .\sentra-7b-evidence-<equipo>-<fecha>.json).
#>
[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [ValidateRange(1, 365)][int]$Days = 30,
    [ValidateRange(1, 5000)][int]$MaxEvents = 500,
    [string]$Output = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$since = (Get-Date).AddDays(-$Days)
$ports = @(8000, 5432, 5433)

function Get-Hash([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try { return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant() } catch { return $null }
}

function Get-Signature([string]$Path) {
    if (-not $Path -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        $signer = $null
        if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
        return [ordered]@{ status = "$($sig.Status)"; signer = $signer }
    } catch { return $null }
}

# Ejecutable de una ruta de servicio ("C:\a b\x.exe" -I -m mod -> C:\a b\x.exe).
function Get-Executable([string]$ImagePath) {
    if (-not $ImagePath) { return $null }
    $text = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim())
    if ($text.StartsWith('"')) { return $text.Substring(1, $text.IndexOf('"', 1) - 1) }
    $match = [regex]::Match($text, '^(.+?\.exe)\b', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }
    return $text.Split(' ')[0]
}

function Get-ProcessInfo([int]$ProcessId) {
    if ($ProcessId -le 0) { return $null }
    try { $p = Get-CimInstance Win32_Process -Filter "ProcessId = $ProcessId" } catch { return $null }
    if (-not $p) { return $null }
    $parent = $null
    try { $parent = Get-CimInstance Win32_Process -Filter "ProcessId = $($p.ParentProcessId)" } catch { }
    return [ordered]@{
        pid = [int]$p.ProcessId
        name = $p.Name
        path = $p.ExecutablePath
        sha256 = Get-Hash $p.ExecutablePath
        signature = Get-Signature $p.ExecutablePath
        started = if ($p.CreationDate) { $p.CreationDate.ToUniversalTime().ToString('o') } else { $null }
        parent = if ($parent) { [ordered]@{ pid = [int]$parent.ProcessId; name = $parent.Name; path = $parent.ExecutablePath } } else { $null }
    }
}

# Versión declarada en un __init__.py de sentra_agent, leída como texto (no se ejecuta nada).
function Get-AgentVersion([string]$InitFile) {
    if (-not (Test-Path -LiteralPath $InitFile -PathType Leaf)) { return $null }
    $match = Select-String -LiteralPath $InitFile -Pattern '__version__\s*=\s*"([^"]+)"' | Select-Object -First 1
    if ($match) { return $match.Matches[0].Groups[1].Value }
    return $null
}

function Read-Events([string]$Log, [int[]]$Ids, [scriptblock]$Project) {
    $result = [ordered]@{ log = $Log; status = 'ok'; events = @() }
    try {
        $raw = Get-WinEvent -FilterHashtable @{ LogName = $Log; Id = $Ids; StartTime = $since } -MaxEvents $MaxEvents -ErrorAction Stop
        $result.events = @($raw | ForEach-Object {
            $xml = [xml]$_.ToXml()
            $data = @{}
            # SelectNodes: con StrictMode, un evento sin EventData no rompe la lectura.
            foreach ($node in $xml.SelectNodes("//*[local-name()='Data']")) {
                $name = $node.GetAttribute('Name')
                if ($name) { $data[$name] = $node.InnerText }
            }
            $item = [ordered]@{
                time = $_.TimeCreated.ToUniversalTime().ToString('o')
                id = $_.Id
                record_id = $_.RecordId
                level = $_.LevelDisplayName
                pid = $_.ProcessId
                user_sid = if ($_.UserId) { $_.UserId.Value } else { $null }
            }
            foreach ($pair in (& $Project $data).GetEnumerator()) { $item[$pair.Key] = $pair.Value }
            [pscustomobject]$item
        })
    } catch [System.Exception] {
        $message = $_.Exception.Message
        if ($message -match 'No events were found|No se encontraron') { $result.status = 'no_events' }
        elseif ($message -match 'not exist|no existe|could not be found') { $result.status = 'channel_missing' }
        elseif ($message -match 'denied|denegado|unauthorized') { $result.status = 'access_denied' }
        else { $result.status = 'unavailable'; $result.error = $message }
    }
    return $result
}

$scriptProjection = {
    param($d)
    [ordered]@{
        path = $d['Path']
        script_block_id = $d['ScriptBlockId']
        part = $d['MessageNumber']
        parts = $d['MessageTotal']
        path_sha256 = Get-Hash $d['Path']
    }
}
$serviceProjection = {
    param($d)
    [ordered]@{
        service_name = $d['ServiceName']
        image_path = $d['ImagePath']
        start_type = $d['StartType']
        account = $d['AccountName']
        executable_sha256 = Get-Hash (Get-Executable $d['ImagePath'])
    }
}
$processProjection = {
    param($d)
    [ordered]@{
        new_process = $d['NewProcessName']
        parent_process = $d['ParentProcessName']
        subject_user = $d['SubjectUserName']
        new_process_id = $d['NewProcessId']
        # La línea de comandos puede llevar secretos: solo si la directiva la incluye.
        command_line_logged = [bool]$d['CommandLine']
    }
}

Write-Host "Sentra 7B.0: recogiendo evidencia (solo lectura) de los últimos $Days días..."

# --- Servicios ----------------------------------------------------------------------------
$services = @(Get-CimInstance Win32_Service | Where-Object {
    $_.Name -like '*sentra*' -or $_.DisplayName -like '*sentra*' -or $_.PathName -like '*sentra*'
} | ForEach-Object {
    $exe = Get-Executable $_.PathName
    [ordered]@{
        name = $_.Name
        display_name = $_.DisplayName
        image_path = $_.PathName
        executable = $exe
        executable_sha256 = Get-Hash $exe
        executable_signature = Get-Signature $exe
        account = $_.StartName
        state = $_.State
        start_mode = $_.StartMode
        process = Get-ProcessInfo ([int]$_.ProcessId)
    }
})

# --- Versión del agente: servicio frente a repositorio y .venv -------------------------------
$installed = @()
foreach ($service in $services) {
    if ($service.executable) {
        $dir = Split-Path -Parent (Split-Path -Parent $service.executable)
        $init = Get-ChildItem -LiteralPath $dir -Recurse -Filter '__init__.py' -ErrorAction SilentlyContinue |
            Where-Object { $_.Directory.Name -eq 'sentra_agent' } | Select-Object -First 1
        if ($init) { $installed += [ordered]@{ service = $service.name; file = $init.FullName; version = Get-AgentVersion $init.FullName } }
    }
}
$venvInit = Get-ChildItem -LiteralPath (Join-Path $RepoRoot 'agent\.venv\Lib\site-packages') -Recurse -Filter '__init__.py' -ErrorAction SilentlyContinue |
    Where-Object { $_.Directory.Name -eq 'sentra_agent' } | Select-Object -First 1
$versions = [ordered]@{
    service_runtime = $installed
    repository = Get-AgentVersion (Join-Path $RepoRoot 'agent\sentra_agent\__init__.py')
    # Instalación editable (pip -e): la .venv apunta al repositorio y no tiene copia propia.
    venv = if ($venvInit) { Get-AgentVersion $venvInit.FullName } else { 'editable_or_missing' }
}

# --- Scripts de referencia ----------------------------------------------------------------
$scriptFiles = @()
foreach ($folder in @('scripts', 'agent\packaging\windows', 'sensor\packaging\windows')) {
    $path = Join-Path $RepoRoot $folder
    if (Test-Path -LiteralPath $path) {
        $scriptFiles += @(Get-ChildItem -LiteralPath $path -Filter '*.ps1' -File | ForEach-Object {
            [ordered]@{ path = $_.FullName; sha256 = Get-Hash $_.FullName; signature = Get-Signature $_.FullName; modified = $_.LastWriteTimeUtc.ToString('o') }
        })
    }
}

# --- Eventos ------------------------------------------------------------------------------
$events = [ordered]@{
    powershell_4104 = Read-Events 'Microsoft-Windows-PowerShell/Operational' @(4104) $scriptProjection
    powershell_core_4104 = Read-Events 'PowerShellCore/Operational' @(4104) $scriptProjection
    service_7045 = Read-Events 'System' @(7045) $serviceProjection
    process_4688 = Read-Events 'Security' @(4688) $processProjection
}

# --- Puertos ------------------------------------------------------------------------------
$listeners = @()
try {
    $listeners = @(Get-NetTCPConnection -State Listen -ErrorAction Stop | Where-Object { $ports -contains $_.LocalPort } | ForEach-Object {
        $owner = $_.OwningProcess
        $svc = Get-CimInstance Win32_Service -Filter "ProcessId = $owner" -ErrorAction SilentlyContinue | Select-Object -First 1
        [ordered]@{
            port = $_.LocalPort
            address = $_.LocalAddress
            process = Get-ProcessInfo ([int]$owner)
            service = if ($svc) { [ordered]@{ name = $svc.Name; display_name = $svc.DisplayName; image_path = $svc.PathName } } else { $null }
        }
    })
} catch { $listeners = @([ordered]@{ error = $_.Exception.Message }) }

# --- Directivas de registro (solo lectura) ------------------------------------------------
function Get-PolicyValue([string]$Key, [string]$Name) {
    try { return (Get-ItemProperty -LiteralPath $Key -Name $Name -ErrorAction Stop).$Name } catch { return $null }
}
$auditpol = $null
try { $auditpol = (& (Join-Path $env:SystemRoot 'System32\auditpol.exe') /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' 2>&1 | Out-String).Trim() } catch { $auditpol = $_.Exception.Message }
$policies = [ordered]@{
    script_block_logging = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' 'EnableScriptBlockLogging'
    script_block_logging_core = Get-PolicyValue 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\ScriptBlockLogging' 'EnableScriptBlockLogging'
    process_creation_command_line = Get-PolicyValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' 'ProcessCreationIncludeCmdLine_Enabled'
    process_creation_audit = $auditpol
}

$report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    computer = $env:COMPUTERNAME
    window_days = $Days
    read_only = $true
    elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    services = $services
    agent_versions = $versions
    scripts = $scriptFiles
    events = $events
    listeners = $listeners
    policies = $policies
}

if (-not $Output) {
    $Output = Join-Path (Get-Location) ("sentra-7b-evidence-{0}-{1}.json" -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $Output -Encoding UTF8

Write-Host ""
Write-Host "Servicios Sentra: $($services.Count)"
foreach ($s in $services) { Write-Host ("  {0} ({1}) {2} cuenta={3} sha256={4}" -f $s.name, $s.display_name, $s.state, $s.account, $s.executable_sha256) }
Write-Host ("Versión del agente: servicio={0} repositorio={1} venv={2}" -f (($installed | ForEach-Object { $_.version }) -join ','), $versions.repository, $versions.venv)
foreach ($key in $events.Keys) { Write-Host ("Eventos {0}: {1} ({2})" -f $key, @($events[$key].events).Count, $events[$key].status) }
foreach ($l in $listeners) { if ($l.Contains('port')) { Write-Host ("Puerto {0} en {1}: {2}" -f $l.port, $l.address, $(if ($l.process) { $l.process.path } else { 'proceso no legible' })) } }
Write-Host "Informe: $Output"
