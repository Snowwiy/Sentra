#Requires -Version 5.1
<#
.SYNOPSIS
    Fase 7B-Fix1: comprueba, SOLO LEYENDO, las instancias de servicio por usuario de este
    equipo con los mismos criterios que el servidor (backend/app/detection/service_identity.py).

.DESCRIPTION
    Ejecutar en PowerShell (mejor como administrador; sin privilegios, lo que no se pueda leer
    queda como "unavailable"):

        powershell -NoProfile -File .\scripts\qa_7b_fix1_services.ps1

    Para cada servicio con forma <plantilla>_<sufijo hexadecimal> (WpnUserService_6df11...):
      - si la plantilla existe;
      - el valor Type del registro y si lleva el bit 0x80 (SERVICE_USERSERVICE_INSTANCE);
      - si el ejecutable es exactamente %SystemRoot%\System32\svchost.exe y el grupo -k
        coincide con el de la plantilla;
      - el estado y el firmante Authenticode del ejecutable.
    Devuelve el veredicto esperado: verified, unverified o suspicious ("probable" solo existe
    en el servidor, con agentes anteriores a 0.6.2 que no envían estos datos).

    No cambia servicios, registro, firewall, Defender ni directivas. Escribe un único JSON
    (-Output) y una tabla por pantalla.

.PARAMETER Output
    Archivo JSON de salida (por defecto .\sentra-7b-fix1-services-<equipo>-<fecha>.json).
#>
[CmdletBinding()]
param(
    [string]$Output = ''
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

$InstanceBit = 0x80
$InstanceName = '^(?<template>[A-Za-z][A-Za-z0-9]{2,})_(?<suffix>[0-9a-fA-F]{4,8})$'
$SystemSvchost = Join-Path $env:SystemRoot 'System32\svchost.exe'

# Ejecutable de una ruta de servicio ("C:\a b\x.exe" -k grupo -> C:\a b\x.exe).
function Get-Executable([string]$ImagePath) {
    if (-not $ImagePath) { return $null }
    $text = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim())
    if ($text.StartsWith('"')) { return $text.Substring(1, $text.IndexOf('"', 1) - 1) }
    $match = [regex]::Match($text, '^(.+?\.exe)\b', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value }
    return $text.Split(' ')[0]
}

function Get-Group([string]$ImagePath) {
    if (-not $ImagePath) { return $null }
    $match = [regex]::Match($ImagePath, '\s-k\s+(\S+)', 'IgnoreCase')
    if ($match.Success) { return $match.Groups[1].Value.ToLowerInvariant() }
    return $null
}

function Get-ServiceKey([string]$Name) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    try { return Get-ItemProperty -LiteralPath $path -ErrorAction Stop } catch { return $null }
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

$services = @{}
foreach ($svc in Get-CimInstance -ClassName Win32_Service) { $services[$svc.Name.ToLowerInvariant()] = $svc }

$results = @()
foreach ($svc in $services.Values) {
    $match = [regex]::Match($svc.Name, $InstanceName)
    if (-not $match.Success) { continue }
    $templateName = $match.Groups['template'].Value
    $key = Get-ServiceKey $svc.Name
    $templateKey = Get-ServiceKey $templateName
    $type = $null
    if ($key -and ($key.PSObject.Properties.Name -contains 'Type')) { $type = [int]$key.Type }
    $image = $svc.PathName
    $exe = Get-Executable $image
    $signature = Get-Signature $exe
    $templateGroup = $null
    if ($templateKey -and ($templateKey.PSObject.Properties.Name -contains 'ImagePath')) {
        $templateGroup = Get-Group ([string]$templateKey.ImagePath)
    }
    $group = Get-Group $image

    $checks = [ordered]@{
        template     = if ($templateKey) { 'pass' } else { 'fail' }
        service_type = if ($null -eq $type) { 'unavailable' } elseif ($type -band $InstanceBit) { 'pass' } else { 'fail' }
        host_image   = if (-not $exe) { 'unavailable' } elseif ($exe -ieq $SystemSvchost) { 'pass' } else { 'fail' }
        host_group   = if (-not $group -or -not $templateGroup) { 'unavailable' } elseif ($group -eq $templateGroup) { 'pass' } else { 'fail' }
        signature    = if (-not $signature) { 'unavailable' } elseif ($signature.status -ne 'Valid') { 'fail' } elseif ($signature.signer -match 'O=Microsoft Corporation\b') { 'pass' } else { 'fail' }
    }
    $decisive = @('service_type', 'host_image', 'host_group', 'signature')
    $verdict = 'verified'
    if ($decisive | Where-Object { $checks[$_] -eq 'fail' }) { $verdict = 'suspicious' }
    elseif ($checks.template -ne 'pass') { $verdict = 'unverified' }
    elseif (@('service_type', 'host_image', 'signature') | Where-Object { $checks[$_] -ne 'pass' }) { $verdict = 'unverified' }

    $typeText = $null
    if ($null -ne $type) { $typeText = '0x{0:x}' -f $type }
    $results += [pscustomobject][ordered]@{
        name      = $svc.Name
        template  = $templateName
        state     = "$($svc.State)"
        type      = $typeText
        image     = $image
        signature = $signature
        checks    = $checks
        verdict   = $verdict
    }
}

if (-not $Output) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $Output = ".\sentra-7b-fix1-services-$($env:COMPUTERNAME)-$stamp.json"
}
$report = [ordered]@{
    generated_at = (Get-Date).ToUniversalTime().ToString('o')
    computer     = $env:COMPUTERNAME
    instances    = $results
}
$report | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $Output -Encoding UTF8

$results | Sort-Object verdict, name | Format-Table name, template, type, verdict -AutoSize
Write-Host "Instancias: $($results.Count). Sospechosas: $(@($results | Where-Object verdict -eq 'suspicious').Count)."
Write-Host "JSON: $Output (revíselo antes de compartirlo: contiene rutas de su equipo)."
