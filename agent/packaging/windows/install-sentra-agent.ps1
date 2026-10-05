#Requires -Version 5.1
<#
.SYNOPSIS
    Instala, enrola y arranca Sentra Agent como servicio Windows ("Sentra Agent").

.DESCRIPTION
    Ejecutar en PowerShell como administrador, desde la carpeta del paquete descomprimido:

        powershell -NoProfile -ExecutionPolicy Bypass -File .\install-sentra-agent.ps1 -Server http://SERVIDOR:8000

    Pide el token de instalación de un solo uso (creado en Sentra Web -> Agentes -> Añadir
    agente -> Windows) en un aviso que no lo muestra, de modo que no queda en el historial de
    PowerShell ni en la línea de comandos de ningún proceso. -TokenFile lo lee de un archivo.

    Qué hace (y nada más):
      - comprueba Windows 10/11 o Server 2019+ de 64 bits y la integridad del paquete;
      - copia el runtime (Python embebido) y el agente a "C:\Program Files\Sentra Agent";
      - crea C:\ProgramData\Sentra\Agent\{config,state,logs} con ACL restringida
        (SYSTEM, Administradores y la cuenta del servicio);
      - escribe agent.toml (sin secretos);
      - crea el servicio estándar "SentraAgent" (inicio automático retrasado, reinicio ante
        fallos) con la cuenta virtual NT SERVICE\SentraAgent, miembro del grupo integrado
        "Event Log Readers" para poder leer el registro Security sin ser administrador;
      - entrega el token al servicio en un archivo protegido; el servicio se enrola, cifra su
        token individual con DPAPI y borra el token de instalación;
      - espera el resultado del enrolamiento y lo informa.

    No abre puertos ni crea reglas de firewall (el agente solo hace conexiones salientes), no
    toca UAC, Defender ni directivas, y no oculta nada: el servicio aparece en services.msc.

    -ExecutionPolicy Bypass solo afecta a este proceso de PowerShell; no cambia la directiva
    del equipo.

.PARAMETER Server
    URL del servidor Sentra, p. ej. http://192.168.1.10:8000 (https en producción).
    Obligatoria en la primera instalación; en un upgrade, cambia api_url si se indica.

.PARAMETER TokenFile
    Archivo con el token de instalación (alternativa al aviso). Se borra tras enrolar.

.PARAMETER Upgrade
    Sustituye runtime y agente conservando configuración, identidad y token individual.
    No vuelve a enrolar. Es también lo que ocurre al ejecutar el instalador sobre una
    instalación existente sin token.

.PARAMETER Reenroll
    Pide un token nuevo aunque ya exista identidad (agente revocado y readmitido, o servidor
    reinstalado). Conserva el agent_id: el equipo sigue siendo el mismo activo.

.PARAMETER ServiceAccount
    Virtual (por defecto, mínimo privilegio) o LocalSystem (alternativa documentada si la
    cuenta virtual no funciona en un equipo concreto). Ver docs/agent-windows-installation.md.

.PARAMETER NoImportIdentity
    No reutilizar el agent_id de una ejecución manual previa (%LOCALAPPDATA%\Sentra\Agent).

.PARAMETER EnrollTimeoutSeconds
    Cuánto esperar el resultado del enrolamiento (por defecto 120 s).
#>
[CmdletBinding()]
param(
    [string]$Server,
    [string]$TokenFile,
    [switch]$Upgrade,
    [switch]$Reenroll,
    [ValidateSet('Virtual', 'LocalSystem')]
    [string]$ServiceAccount = 'Virtual',
    [switch]$NoImportIdentity,
    [ValidateRange(10, 900)]
    [int]$EnrollTimeoutSeconds = 120
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Dentro de una función $PSBoundParameters es el de la función: se guarda aquí el del script.
$script:ServiceAccountGiven = $PSBoundParameters.ContainsKey('ServiceAccount')

$SystemSid = 'S-1-5-18'
$AdministratorsSid = 'S-1-5-32-544'
# Windows 10 1809 / Server 2019: mínimo probado razonable para el Python embebido y wevtutil.
$MinBuild = 17763

function Write-Step([string]$Message) { Write-Host "sentra-agent: $Message" }
function Write-Warn([string]$Message) { Write-Warning "sentra-agent: $Message" }

function Stop-Install([string]$Message, [int]$Code = 1) {
    # Un único punto de salida con error: mensaje claro en rojo y código distinto de cero.
    Write-Host "sentra-agent: ERROR: $Message" -ForegroundColor Red
    exit $Code
}

function Invoke-Native {
    # En Windows PowerShell 5.1, con ErrorActionPreference=Stop, redirigir stderr de un
    # ejecutable nativo convierte la primera línea en un error terminante. Se relaja solo
    # aquí y se devuelve stdout/stderr/código para decidir con el código de salida.
    param([string]$FilePath, [string[]]$Arguments)
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = & $FilePath @Arguments 2>&1
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $previous
    }
    $stdout = @($output | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    $stderr = @($output | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    [pscustomobject]@{ ExitCode = $code; StdOut = ($stdout -join "`n"); StdErr = ($stderr -join "`n") }
}

function Invoke-Sc([string[]]$Arguments) {
    $result = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\sc.exe') -Arguments $Arguments
    if ($result.ExitCode -ne 0) {
        throw "sc.exe $($Arguments -join ' ') falló ($($result.ExitCode)): $($result.StdOut) $($result.StdErr)"
    }
}

function Assert-Administrator {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Stop-Install 'ejecuta PowerShell como administrador (clic derecho -> Ejecutar como administrador)'
    }
}

function Assert-Platform {
    $version = [Environment]::OSVersion.Version
    if ([Environment]::OSVersion.Platform -ne 'Win32NT' -or $version.Major -lt 10 -or $version.Build -lt $MinBuild) {
        Stop-Install "Windows no compatible ($version): se necesita Windows 10/11 o Windows Server 2019 o posterior"
    }
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
        Stop-Install "arquitectura no compatible ($env:PROCESSOR_ARCHITECTURE): el paquete es para Windows x64"
    }
    if (-not [Environment]::Is64BitProcess) {
        # PowerShell de 32 bits ve "Program Files (x86)" y otra rama del registro.
        Stop-Install 'usa Windows PowerShell de 64 bits (no "Windows PowerShell (x86)")'
    }
}

function Test-PackageIntegrity([string]$PackageDir) {
    # Integridad (no autenticidad): detecta un zip incompleto o archivos modificados tras el
    # build. La autenticidad del runtime se verificó al construir (firma de la PSF).
    $manifest = Join-Path $PackageDir 'MANIFEST.sha256'
    if (-not (Test-Path -LiteralPath $manifest -PathType Leaf)) {
        throw 'falta MANIFEST.sha256: el paquete está incompleto'
    }
    $count = 0
    foreach ($line in [IO.File]::ReadAllLines($manifest)) {
        if (-not $line.Trim()) { continue }
        if ($line -notmatch '^([0-9a-f]{64})  (.+)$') { throw "línea no válida en MANIFEST.sha256: $line" }
        $expected = $Matches[1]
        $relative = $Matches[2]
        if ($relative -match '(^|/)\.\.(/|$)' -or $relative.StartsWith('/')) { throw "ruta no válida en MANIFEST.sha256: $relative" }
        $path = Join-Path $PackageDir ($relative -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "falta el archivo del paquete: $relative" }
        $actual = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $expected) { throw "el archivo $relative no coincide con MANIFEST.sha256 (paquete dañado o modificado)" }
        $count++
    }
    if ($count -eq 0) { throw 'MANIFEST.sha256 está vacío' }
    return $count
}

function Invoke-Winsetup([string]$Python, [string[]]$Arguments) {
    # Toda la lógica pura (rutas, agent.toml, línea del servicio, validaciones) vive en
    # sentra_agent.winsetup y está cubierta por pytest; aquí solo se ejecuta.
    $result = Invoke-Native -FilePath $Python -Arguments (@('-I', '-m', 'sentra_agent.winsetup') + $Arguments)
    if ($result.ExitCode -ne 0) {
        $detail = if ($result.StdErr) { $result.StdErr } else { $result.StdOut }
        throw $detail.Trim()
    }
    return ($result.StdOut | ConvertFrom-Json)
}

function Get-ServiceInfo([string]$Name) {
    return Get-CimInstance -ClassName Win32_Service -Filter "Name='$Name'" -ErrorAction SilentlyContinue
}

function Wait-ServiceState([string]$Name, [string]$State, [int]$Seconds) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service) { return $false }
    try {
        $service.WaitForStatus($State, [TimeSpan]::FromSeconds($Seconds))
        return $true
    } catch {
        return $false
    }
}

function Stop-AgentService([string]$Name) {
    $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if (-not $service -or $service.Status -eq 'Stopped') { return }
    Write-Step 'deteniendo el servicio (espera a que termine el ciclo en curso)'
    $service.Stop()
    # El agente para entre ciclos; un ciclo puede tardar (inventario, Event Log).
    if (-not (Wait-ServiceState -Name $Name -State 'Stopped' -Seconds 150)) {
        throw 'el servicio no se detuvo a tiempo; revisa C:\ProgramData\Sentra\Agent\logs\agent.log'
    }
}

function Set-DataDirectoryAcl($Plan, [string]$Account) {
    # Sin herencia de ProgramData (que da lectura a Users): solo SYSTEM y Administradores con
    # control total, y la cuenta del servicio con lo justo: leer la configuración y modificar
    # estado y logs. El token individual además va cifrado con DPAPI.
    foreach ($dir in @($Plan.data_dir, $Plan.config_dir, $Plan.state_dir, $Plan.log_dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $steps = @(
        @($Plan.data_dir, '/inheritance:r', '/grant:r', "*${SystemSid}:(OI)(CI)F", "*${AdministratorsSid}:(OI)(CI)F"),
        @($Plan.data_dir, '/setowner', "*$AdministratorsSid")
    )
    if ($Account -eq 'Virtual') {
        $sid = $Plan.service_sid
        $steps += , @($Plan.data_dir, '/grant:r', "*${sid}:(RX)")
        $steps += , @($Plan.config_dir, '/grant:r', "*${sid}:(OI)(CI)RX")
        $steps += , @($Plan.state_dir, '/grant:r', "*${sid}:(OI)(CI)M")
        $steps += , @($Plan.log_dir, '/grant:r', "*${sid}:(OI)(CI)M")
    }
    foreach ($arguments in $steps) {
        $result = Invoke-Native -FilePath $icacls -Arguments ($arguments + '/Q')
        if ($result.ExitCode -ne 0) { throw "icacls $($arguments -join ' ') falló: $($result.StdOut) $($result.StdErr)" }
    }
}

function Install-Runtime($Plan, [string]$PackageDir) {
    # Sustitución en dos fases: primero se copia todo a carpetas .new y solo entonces se
    # intercambian, para no dejar nunca una mezcla de dos versiones si la copia falla.
    $installDir = $Plan.install_dir
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    $stamp = [guid]::NewGuid().ToString('N').Substring(0, 8)
    $parts = @('runtime', 'lib')
    foreach ($part in $parts) {
        Copy-Item -LiteralPath (Join-Path $PackageDir "payload\$part") -Destination (Join-Path $installDir "$part.new-$stamp") -Recurse -Force
    }
    $swapped = @()
    try {
        foreach ($part in $parts) {
            $target = Join-Path $installDir $part
            if (Test-Path -LiteralPath $target) { Move-Item -LiteralPath $target -Destination "$target.old-$stamp" }
            Move-Item -LiteralPath "$target.new-$stamp" -Destination $target
            $swapped += $part
        }
    } catch {
        foreach ($part in $parts) {
            $target = Join-Path $installDir $part
            if (Test-Path -LiteralPath "$target.old-$stamp") {
                if ($swapped -contains $part) { Remove-Item -LiteralPath $target -Recurse -Force -ErrorAction SilentlyContinue }
                Move-Item -LiteralPath "$target.old-$stamp" -Destination $target -ErrorAction SilentlyContinue
            }
        }
        throw
    }
    foreach ($part in $parts) {
        Remove-Item -LiteralPath (Join-Path $installDir "$part.old-$stamp") -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath (Join-Path $installDir "$part.new-$stamp") -Recurse -Force -ErrorAction SilentlyContinue
    }
    foreach ($file in @('uninstall-sentra-agent.ps1', 'VERSION', 'README.md', 'MANIFEST.sha256')) {
        Copy-Item -LiteralPath (Join-Path $PackageDir $file) -Destination $installDir -Force
    }
    # Los archivos venían de un zip descargado (marca "Mark of the Web"). Ya se verificaron
    # contra MANIFEST.sha256, así que se quita la marca solo a la copia instalada.
    Get-ChildItem -LiteralPath $installDir -Recurse -File | Unblock-File
}

function Install-AgentService($Plan, [string]$Account) {
    $name = $Plan.service_name
    $existing = Get-ServiceInfo $name
    if (-not $existing) {
        # New-Service recibe la ruta por la API (sin pasar por la línea de comandos de
        # sc.exe), así las comillas de la ruta con espacios llegan intactas.
        New-Service -Name $name -BinaryPathName $Plan.binary_path -DisplayName $Plan.display_name `
            -Description $Plan.description -StartupType Automatic | Out-Null
        Write-Step "servicio $name creado"
    } else {
        if ($existing.PathName -ne $Plan.binary_path) {
            $result = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{ PathName = $Plan.binary_path }
            if ($result.ReturnValue -ne 0) { throw "no se pudo actualizar la ruta del servicio (Win32_Service.Change = $($result.ReturnValue))" }
        }
        Set-Service -Name $name -DisplayName $Plan.display_name -Description $Plan.description
    }
    # SID propio del servicio: necesario para la cuenta virtual y para que las ACL y el grupo
    # Event Log Readers puedan referirse solo a este servicio.
    Invoke-Sc @('sidtype', $name, 'unrestricted')
    if ($Account -eq 'Virtual') {
        Invoke-Sc @('config', $name, 'obj=', $Plan.virtual_account)
    } else {
        Invoke-Sc @('config', $name, 'obj=', 'LocalSystem')
    }
    # Inicio automático retrasado: arranca solo, sin sesión de usuario, cuando la red y el
    # DNS ya están listos, y sin competir con el arranque del sistema.
    Invoke-Sc @('config', $name, 'start=', 'delayed-auto')
    Invoke-Sc @('failure', $name, 'reset=', [string]$Plan.failure_reset_seconds, 'actions=', $Plan.failure_actions)
    # Recuperación también cuando el servicio se detiene con código de error (no solo si el
    # proceso muere): así un fallo controlado del agente también provoca el reinicio.
    Invoke-Sc @('failureflag', $name, '1')
    $configured = Get-ServiceInfo $name
    $expected = if ($Account -eq 'Virtual') { $Plan.virtual_account } else { 'LocalSystem' }
    if ($configured.StartName -ne $expected) {
        throw "la cuenta del servicio es '$($configured.StartName)' en lugar de '$expected'"
    }
}

function Get-EventLogReadersName([string]$GroupSid) {
    $account = (New-Object Security.Principal.SecurityIdentifier($GroupSid)).Translate([Security.Principal.NTAccount]).Value
    return $account.Split('\')[-1]
}

function Test-GroupMember([string]$Group, [string]$Member) {
    $result = Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') -Arguments @('localgroup', $Group)
    if ($result.ExitCode -ne 0) { return $false }
    foreach ($line in ($result.StdOut -split "`n")) {
        if ($line.Trim() -ieq $Member) { return $true }
    }
    return $false
}

function Grant-EventLogAccess($Plan) {
    # Mínimo privilegio: el canal Security solo lo leen SYSTEM, Administradores y el grupo
    # integrado "Event Log Readers" (S-1-5-32-573). Añadir solo el SID de este servicio a ese
    # grupo basta para recoger Security, System, Application y PowerShell/Operational sin
    # ejecutar como LocalSystem ni como administrador.
    $group = Get-EventLogReadersName $Plan.event_log_readers_sid
    if (Test-GroupMember -Group $group -Member $Plan.virtual_account) {
        Write-Step "$($Plan.virtual_account) ya es miembro de '$group'"
        return $true
    }
    try {
        Add-LocalGroupMember -SID $Plan.event_log_readers_sid -Member $Plan.service_sid -ErrorAction Stop
    } catch {
        # Respaldo: algunas versiones del módulo LocalAccounts no resuelven SID de servicio.
        Invoke-Native -FilePath (Join-Path $env:SystemRoot 'System32\net.exe') -Arguments @('localgroup', $group, $Plan.virtual_account, '/add') | Out-Null
    }
    if (Test-GroupMember -Group $group -Member $Plan.virtual_account) {
        Write-Step "$($Plan.virtual_account) añadido a '$group' (lectura del registro Security)"
        return $true
    }
    Write-Warn "no se pudo añadir $($Plan.virtual_account) a '$group': el canal Security no se recogerá (el resto sí)"
    return $false
}

function Find-ManualAgent([string]$InstallDir) {
    # Un agente lanzado a mano con start_agent.ps1 compartiría agent_id con el servicio tras
    # importar la identidad: ambos se enrolarían por turnos y se invalidarían el token.
    $found = @()
    foreach ($process in @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)) {
        $commandLine = [string]$process.CommandLine
        $executable = [string]$process.ExecutablePath
        if ($commandLine -match 'sentra_agent' -and -not $executable.StartsWith($InstallDir, [StringComparison]::OrdinalIgnoreCase)) {
            $found += $process.ProcessId
        }
    }
    return $found
}

function Read-JsonFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
    try {
        return (Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
    } catch {
        return $null
    }
}

function Test-IdentityHasToken([string]$IdentityFile) {
    $identity = Read-JsonFile $IdentityFile
    if ($null -eq $identity) { return $false }
    return ($null -ne $identity.PSObject.Properties['token'] -and $null -ne $identity.token)
}

function Wait-Enrollment($Plan, [int]$TimeoutSeconds) {
    # El servicio escribe enrollment-status.json tras cada intento (sin secretos). Se espera
    # a un estado final; "unreachable" se sigue esperando porque el servicio reintenta solo.
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = $null
    while ((Get-Date) -lt $deadline) {
        $status = Read-JsonFile $Plan.status_file
        if ($null -ne $status) {
            $last = $status
            if (@('enrolled', 'already_enrolled', 'rejected', 'no_credential') -contains $status.state) { return $status }
        }
        $service = Get-Service -Name $Plan.service_name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Stopped') {
            return [pscustomobject]@{ state = 'service_stopped'; message = 'el servicio se detuvo durante el enrolamiento' }
        }
        Start-Sleep -Seconds 2
    }
    if ($null -ne $last) { return $last }
    return [pscustomobject]@{ state = 'timeout'; message = 'el servicio no informó del enrolamiento a tiempo' }
}

function Resolve-ServiceAccount($Plan, $Existing) {
    # En una instalación existente se conserva su cuenta salvo que se pida otra: cambiarla
    # invalida el token individual (DPAPI lo cifró para la cuenta anterior).
    if ($script:ServiceAccountGiven) { return $ServiceAccount }
    if ($null -ne $Existing) {
        if ($Existing.StartName -eq 'LocalSystem') { return 'LocalSystem' }
        if ($Existing.StartName -eq $Plan.virtual_account) { return 'Virtual' }
    }
    return $ServiceAccount
}

function Invoke-Install {
    Assert-Administrator
    Assert-Platform

    $packageDir = $PSScriptRoot
    $python = Join-Path $packageDir 'payload\runtime\python.exe'
    if (-not (Test-Path -LiteralPath $python -PathType Leaf)) {
        Stop-Install 'no se encuentra payload\runtime\python.exe junto al instalador: descomprime el paquete completo'
    }
    try {
        $files = Test-PackageIntegrity $packageDir
    } catch {
        Stop-Install $_.Exception.Message
    }
    Write-Step "paquete verificado ($files archivos)"

    $programFiles = [Environment]::GetFolderPath('ProgramFiles')
    $programData = [Environment]::GetFolderPath('CommonApplicationData')
    $planArgs = @('plan', '--program-files', $programFiles, '--program-data', $programData)
    if ($Server) { $planArgs += @('--server', $Server) }
    $existingConfig = Join-Path $programData 'Sentra\Agent\config\agent.toml'
    if (Test-Path -LiteralPath $existingConfig -PathType Leaf) { $planArgs += @('--existing-config', $existingConfig) }
    try {
        $plan = Invoke-Winsetup -Python $python -Arguments $planArgs
    } catch {
        Stop-Install $_.Exception.Message
    }
    if ($plan.loopback) {
        Write-Warn "$($plan.api_url) apunta a este mismo equipo; los agentes de otros equipos no llegarán ahí"
    }
    if ($plan.insecure -and -not $plan.loopback) {
        Write-Warn 'la URL no es https: el token viaja sin cifrar por la red (usa https en producción)'
    }

    $existing = Get-ServiceInfo $plan.service_name
    if ($Upgrade -and $null -eq $existing) { Stop-Install '-Upgrade necesita una instalación existente (no existe el servicio SentraAgent)' }
    $account = Resolve-ServiceAccount -Plan $plan -Existing $existing
    $expectedStartName = if ($account -eq 'Virtual') { $plan.virtual_account } else { 'LocalSystem' }
    $accountChanged = $null -ne $existing -and $existing.StartName -ne $expectedStartName

    # ¿Hace falta un token de instalación? Primera instalación, -Reenroll, -TokenFile, una
    # identidad sin token individual, o un cambio de cuenta (el token cifrado con DPAPI para
    # la cuenta anterior no se puede descifrar con la nueva).
    $hasToken = Test-IdentityHasToken $plan.identity_file
    $needToken = $Reenroll -or [bool]$TokenFile -or $accountChanged -or -not $hasToken
    if ($Upgrade -and -not $Reenroll -and -not $TokenFile -and -not $accountChanged) { $needToken = $false }
    if ($accountChanged) { Write-Warn "la cuenta del servicio cambia de '$($existing.StartName)' a '$expectedStartName': hará falta un token nuevo" }

    # El token se pide (o se valida) antes de tocar nada: cancelar aquí no deja nada a medias.
    $secureToken = $null
    if ($needToken) {
        if ($TokenFile) {
            if (-not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) { Stop-Install "no existe el archivo de token: $TokenFile" }
            $TokenFile = (Resolve-Path -LiteralPath $TokenFile).Path
            try {
                Invoke-Winsetup -Python $python -Arguments @('check-token', '--file', $TokenFile) | Out-Null
            } catch {
                Stop-Install $_.Exception.Message
            }
        } else {
            $secureToken = Read-Host -AsSecureString -Prompt 'Token de instalación (sentra_et_..., no se muestra)'
        }
    }

    $manual = @(Find-ManualAgent $plan.install_dir)
    if ($manual.Count -gt 0) {
        Write-Warn "hay un agente Sentra ejecutándose a mano (PID $($manual -join ', ')). Detenlo (Ctrl+C en su ventana): dos agentes con la misma identidad se invalidan el token mutuamente."
    }

    if ($null -ne $existing) { Stop-AgentService $plan.service_name }
    Install-Runtime -Plan $plan -PackageDir $packageDir
    Write-Step "runtime instalado en $($plan.install_dir)"

    # El servicio debe existir antes de añadir su SID a grupos (las ACL usan el SID calculado).
    Install-AgentService -Plan $plan -Account $account
    Set-DataDirectoryAcl -Plan $plan -Account $account
    if ($null -ne $plan.config_text) {
        [IO.File]::WriteAllText($plan.config_file, $plan.config_text, (New-Object Text.UTF8Encoding($false)))
        Write-Step "configuración escrita: $($plan.config_file) (api_url = $($plan.api_url))"
    } else {
        Write-Step "se conserva la configuración existente: $($plan.config_file)"
    }
    $eventLogOk = $true
    if ($account -eq 'Virtual') { $eventLogOk = Grant-EventLogAccess $plan }

    # Reutilizar el agent_id de una ejecución manual mantiene el mismo activo en Sentra.
    if (-not (Test-Path -LiteralPath $plan.identity_file) -and -not $NoImportIdentity -and $env:LOCALAPPDATA) {
        $manualIdentity = Join-Path $env:LOCALAPPDATA 'Sentra\Agent\identity.json'
        if (Test-Path -LiteralPath $manualIdentity -PathType Leaf) {
            try {
                $imported = Invoke-Winsetup -Python $python -Arguments @('import-identity', '--source', $manualIdentity, '--dest', $plan.identity_file)
                Write-Step "identidad importada de la ejecución manual: agent_id $($imported.agent_id) (mismo activo en Sentra)"
            } catch {
                Write-Warn "no se importó la identidad manual: $($_.Exception.Message)"
            }
        }
    }

    Remove-Item -LiteralPath $plan.status_file -Force -ErrorAction SilentlyContinue
    if ($needToken) {
        # El token llega al servicio en un archivo dentro de state\ (ACL: SYSTEM,
        # Administradores y el servicio). El servicio lo borra al resolverse el enrolamiento.
        try {
            if ($TokenFile) {
                Invoke-Winsetup -Python $python -Arguments @('stage-token', '--source', $TokenFile, '--dest', $plan.token_file) | Out-Null
            } else {
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureToken)
                try {
                    [IO.File]::WriteAllText($plan.token_file, [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr), (New-Object Text.UTF8Encoding($false)))
                } finally {
                    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                }
                $secureToken = $null
                # Valida el formato y normaliza el archivo (sin espacios ni saltos de línea).
                Invoke-Winsetup -Python $python -Arguments @('stage-token', '--source', $plan.token_file, '--dest', $plan.token_file) | Out-Null
            }
        } catch {
            Remove-Item -LiteralPath $plan.token_file -Force -ErrorAction SilentlyContinue
            Stop-Install $_.Exception.Message
        }
    } elseif (-not $hasToken) {
        Write-Warn 'el agente no tiene token individual: necesitará -Reenroll con un token nuevo'
    }

    Start-Service -Name $plan.service_name
    if (-not (Wait-ServiceState -Name $plan.service_name -State 'Running' -Seconds 30)) {
        Stop-Install "el servicio no arrancó; revisa $($plan.log_dir)\agent.log y el Visor de eventos (Sistema)"
    }
    Write-Step 'servicio SentraAgent en ejecución (inicio automático, se reinicia ante fallos)'

    $exitCode = 0
    if ($needToken) {
        Write-Step 'enrolando con el servidor...'
        $status = Wait-Enrollment -Plan $plan -TimeoutSeconds $EnrollTimeoutSeconds
        switch ($status.state) {
            { @('enrolled', 'already_enrolled') -contains $_ } {
                Write-Step $status.message
                if ($TokenFile -and (Test-Path -LiteralPath $TokenFile)) {
                    Remove-Item -LiteralPath $TokenFile -Force
                    Write-Step "token de un solo uso usado; borrado $TokenFile"
                }
            }
            'rejected' {
                Stop-AgentService $plan.service_name
                Remove-Item -LiteralPath $plan.token_file -Force -ErrorAction SilentlyContinue
                Stop-Install "el servidor rechazó el token (caducado, ya usado, revocado o para otro equipo o plataforma). Genera uno nuevo y ejecuta otra vez el instalador. Detalle: $($status.message)"
            }
            'unreachable' {
                Write-Warn "no se puede contactar con el servidor: $($status.message)"
                Write-Warn 'el servicio sigue reintentando y se enrolará cuando el servidor responda, mientras el token no caduque; hasta entonces el token queda en state\ protegido por ACL'
                $exitCode = 2
            }
            default {
                Write-Warn "estado del enrolamiento: $($status.state) - $($status.message). Revisa $($plan.log_dir)\agent.log"
                $exitCode = 2
            }
        }
    } else {
        # Upgrade o reinstalación con identidad: no hay enrolamiento que esperar; basta con
        # comprobar que el servicio sigue en marcha tras arrancar.
        Start-Sleep -Seconds 5
        if ((Get-Service -Name $plan.service_name).Status -ne 'Running') {
            Stop-Install "el servicio se detuvo tras arrancar; revisa $($plan.log_dir)\agent.log"
        }
    }

    $service = Get-ServiceInfo $plan.service_name
    Write-Host ''
    Write-Step "listo. Servicio: $($service.DisplayName) ($($service.Name)) - $($service.State), inicio $($service.StartMode), cuenta $($service.StartName)"
    Write-Step "Configuración: $($plan.config_file) | Logs: $($plan.log_dir)\agent.log"
    if (-not $eventLogOk) { Write-Step 'Event Log Security: sin acceso (ver aviso anterior)' }
    Write-Step "Estado: Get-Service SentraAgent | Desinstalar: & '$($plan.install_dir)\uninstall-sentra-agent.ps1'"
    exit $exitCode
}

# Solo se ejecuta al invocar el script; al cargarlo con ". .\install-sentra-agent.ps1" (tests)
# solo se definen las funciones.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        Invoke-Install
    } catch {
        Stop-Install $_.Exception.Message
    }
}
