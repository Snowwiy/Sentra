<#
.SYNOPSIS
  Instala Sentra Sensor como servicio de Windows "SentraSensor".

.DESCRIPTION
  - Crea %ProgramData%\Sentra\Sensor con ACL restrictiva (SYSTEM, Administradores y la cuenta
    virtual del servicio; sin herencia), donde viven credencial, spool, estado y logs.
  - Escribe sensor.toml con la URL del servidor (las redes las decide el servidor).
  - Deja el token de enrollment en un fichero protegido por la misma ACL: el SERVICIO enrola
    en su primer arranque (`run --enroll-token-file`) para que la credencial quede cifrada
    con DPAPI bajo SU cuenta, y borra el fichero (el token es de un solo uso).
  - Registra el servicio con la cuenta virtual "NT SERVICE\SentraSensor" (sin contraseña,
    sin privilegios de administrador) y reinicio automático ante fallos.

  No usa pywin32: el sensor habla con el SCM por ctypes (sentra_sensor/winservice.py).
  pywin32 NO es necesario.

.EXAMPLE
  .\install-sentra-sensor.ps1 -Server https://sentra.example.com -TokenFile C:\tmp\token.txt `
      -Python "C:\Program Files\SentraSensor\python\python.exe"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$TokenFile,
    [Parameter(Mandatory = $true)][string]$Python,
    [string]$CaBundle
)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Ejecuta este script como Administrador.'
}
if ($Server -notmatch '^https://') { throw 'El servidor debe ser https://' }
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) { throw "No existe $Python" }
if (-not (Test-Path -LiteralPath $TokenFile -PathType Leaf)) { throw "No existe $TokenFile" }

$name = 'SentraSensor'
$dataDir = Join-Path $env:ProgramData 'Sentra\Sensor'
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
# /inheritance:r quita permisos heredados (p. ej. Users:Read de ProgramData).
& $icacls $dataDir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls falló' }

$configPath = Join-Path $dataDir 'sensor.toml'
$lines = @(
    '[sensor]',
    ('server_url = "{0}"' -f $Server),
    ('data_dir = "{0}"' -f ($dataDir -replace '\\', '\\'))
)
if ($CaBundle) { $lines += ('ca_bundle = "{0}"' -f ($CaBundle -replace '\\', '\\')) }
Set-Content -LiteralPath $configPath -Value $lines -Encoding UTF8

$tokenTarget = Join-Path $dataDir 'enroll.token'
Copy-Item -LiteralPath $TokenFile -Destination $tokenTarget -Force

$binary = '"{0}" -m sentra_sensor --config "{1}" run --service --enroll-token-file "{2}"' -f `
    $Python, $configPath, $tokenTarget
if (-not (Get-Service -Name $name -ErrorAction SilentlyContinue)) {
    New-Service -Name $name -BinaryPathName $binary -DisplayName 'Sentra Sensor' `
        -Description 'Sentra distributed network sensor (outbound HTTPS only)' -StartupType Automatic | Out-Null
}
$sc = Join-Path $env:SystemRoot 'System32\sc.exe'
& $sc config $name obj= "NT SERVICE\$name" | Out-Null
& $sc failure $name reset= 86400 actions= restart/10000/restart/30000/restart/60000 | Out-Null
& $sc failureflag $name 1 | Out-Null

# La cuenta virtual existe una vez registrado el servicio: ahora se le da acceso al directorio.
& $icacls $dataDir /grant:r "NT SERVICE\${name}:(OI)(CI)M" /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'icacls (cuenta del servicio) falló' }

Start-Service -Name $name
Write-Host "Servicio $name instalado y arrancado. Estado: Get-Service $name"
Write-Host "Diagnóstico: & '$Python' -m sentra_sensor --config '$configPath' status"
