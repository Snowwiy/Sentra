#Requires -Version 5.1
<#
.SYNOPSIS
    Fase 7D: camino de migraciones 0050 -> 0051 -> 0052, rollback y restauracion sobre una base
    de PRUEBAS aislada.

.DESCRIPTION
    Nunca toca la base productiva "sentra" ni sentra_test: se niega si -Database es una de las
    dos. La base de pruebas debe existir y estar VACIA (crearla antes con pgAdmin o con
    `createdb -h localhost -p 5433 -U sentra sentra_qa_7d` si el rol tiene CREATEDB). El script
    no teclea ni pide la contrasena del superusuario postgres: usa el rol sentra, con la
    contrasena en PGPASSWORD o en %APPDATA%\postgresql\pgpass.conf.

    Pasos (cada uno se verifica con `alembic current` y consultas de solo lectura):
      1. upgrade 0050 (estado 7C-Fix2) y datos minimos (un activo agente).
      2. pg_dump de la base en 0050 (copia de seguridad de "antes").
      3. upgrade 0051 (7D.1) y 0052 (7D.2); alembic check sin diferencias.
      4. Se comprueba que ingest_quota_buckets existe con sus indices.
      5. downgrade 0051 (rollback de 7D.2): la tabla desaparece, el activo sigue.
      6. downgrade 0050 (rollback de 7D.1).
      7. upgrade head otra vez (re-aplicar es idempotente).
      8. Restauracion: esquema vacio, pg_restore de la copia de 0050 y upgrade head de nuevo.

.EXAMPLE
    $env:PGPASSWORD = "<contrasena del rol sentra>"   # no la del superusuario
    .\qa\windows-7d\test-migrations-7d.ps1 -Database sentra_qa_7d
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Database,
    [string]$DbHost = "localhost",
    [int]$Port = 5433,
    [string]$User = "sentra",
    [string]$PgBin = "C:\Program Files\PostgreSQL\18\bin"
)

$ErrorActionPreference = "Stop"
if ($Database -in @("sentra", "sentra_test", "postgres")) {
    throw "La base '$Database' no es una base de pruebas aislada. Usar p. ej. sentra_qa_7d."
}
if (-not $env:PGPASSWORD -and -not (Test-Path "$env:APPDATA\postgresql\pgpass.conf")) {
    throw "Falta la contrasena del rol $User (PGPASSWORD o pgpass.conf)."
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$backend = Join-Path $root "backend"
$py = Join-Path $backend ".venv\Scripts\python.exe"
$psql = Join-Path $PgBin "psql.exe"
$out = Join-Path $PSScriptRoot "out"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$dump = Join-Path $out ("$Database-0050-" + (Get-Date -Format "yyyyMMdd-HHmmss") + ".dump")

# Alembic lee DATABASE_URL del entorno antes que del .env. Se fija solo en este proceso: la
# contrasena va por PGPASSWORD (libpq), no en la URL ni en ningun fichero.
$previousUrl = $env:DATABASE_URL
$env:DATABASE_URL = "postgresql+psycopg://${User}@${DbHost}:${Port}/${Database}"

function Sql([string]$Query) {
    $result = & $psql -h $DbHost -p $Port -U $User -d $Database -v ON_ERROR_STOP=1 -At -c $Query
    if ($LASTEXITCODE -ne 0) { throw "psql fallo: $Query" }
    return $result
}

function Alembic([string[]]$Arguments) {
    Push-Location $backend
    try {
        & $py -m alembic @Arguments
        if ($LASTEXITCODE -ne 0) { throw "alembic $($Arguments -join ' ') fallo" }
    } finally {
        Pop-Location
    }
}

function Expect([string]$Label, [string]$Actual, [string]$Expected) {
    if ($Actual -ne $Expected) { throw "$Label : esperado '$Expected', obtenido '$Actual'" }
    Write-Host "OK  $Label = $Actual" -ForegroundColor Green
}

try {
    $tables = Sql "SELECT count(*) FROM pg_tables WHERE schemaname = 'public'"
    if ($tables -ne "0") { throw "La base $Database no esta vacia ($tables tablas). Usar una base nueva." }

    Write-Host "1. upgrade 0050" -ForegroundColor Cyan
    Alembic @("upgrade", "0050")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0050"
    Sql ("INSERT INTO assets (public_id, hostname, primary_ip, status, first_seen_at) " +
        "VALUES (gen_random_uuid(), 'qa7d-migration', '192.0.2.50', 'offline', now())") | Out-Null
    Expect "activo de prueba" (Sql "SELECT count(*) FROM assets WHERE hostname = 'qa7d-migration'") "1"

    Write-Host "2. copia de seguridad en 0050" -ForegroundColor Cyan
    & (Join-Path $PgBin "pg_dump.exe") -h $DbHost -p $Port -U $User -d $Database -Fc -f $dump
    if ($LASTEXITCODE -ne 0) { throw "pg_dump fallo" }

    Write-Host "3. upgrade 0051 y 0052" -ForegroundColor Cyan
    Alembic @("upgrade", "0051")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0051"
    Alembic @("upgrade", "0052")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0052"
    Alembic @("check")

    Write-Host "4. tabla e indices de 0052" -ForegroundColor Cyan
    Expect "ingest_quota_buckets" (Sql "SELECT to_regclass('public.ingest_quota_buckets') IS NOT NULL") "t"
    Expect "indices" (Sql ("SELECT count(*) FROM pg_indexes WHERE tablename = 'ingest_quota_buckets' " +
        "AND indexname IN ('ix_ingest_quota_buckets_agent_rejected', 'ix_ingest_quota_buckets_updated_at')")) "2"
    Expect "activo conservado" (Sql "SELECT count(*) FROM assets WHERE hostname = 'qa7d-migration'") "1"

    Write-Host "5. rollback de 7D.2 (downgrade 0051)" -ForegroundColor Cyan
    Alembic @("downgrade", "0051")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0051"
    Expect "tabla eliminada" (Sql "SELECT to_regclass('public.ingest_quota_buckets') IS NULL") "t"
    Expect "activo conservado" (Sql "SELECT count(*) FROM assets WHERE hostname = 'qa7d-migration'") "1"

    Write-Host "6. rollback de 7D.1 (downgrade 0050)" -ForegroundColor Cyan
    Alembic @("downgrade", "0050")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0050"

    Write-Host "7. upgrade head de nuevo" -ForegroundColor Cyan
    Alembic @("upgrade", "head")
    Expect "version" (Sql "SELECT version_num FROM alembic_version") "0052"
    Alembic @("check")

    Write-Host "8. restauracion de la copia de 0050 y upgrade head" -ForegroundColor Cyan
    # Restaurar sobre un esquema mas nuevo con --clean deja objetos de 0051/0052 y errores de
    # dependencias: se vacia el esquema public (solo de ESTA base de pruebas) y se restaura
    # entera, como en un rollback real por restauracion (MIGRACION-Y-ROLLBACK.md).
    Sql "DROP SCHEMA public CASCADE; CREATE SCHEMA public;" | Out-Null
    & (Join-Path $PgBin "pg_restore.exe") -h $DbHost -p $Port -U $User -d $Database --exit-on-error $dump
    if ($LASTEXITCODE -ne 0) { throw "pg_restore fallo" }
    Expect "version restaurada" (Sql "SELECT version_num FROM alembic_version") "0050"
    Alembic @("upgrade", "head")
    Expect "version final" (Sql "SELECT version_num FROM alembic_version") "0052"
    Expect "activo tras restaurar" (Sql "SELECT count(*) FROM assets WHERE hostname = 'qa7d-migration'") "1"

    Write-Host ""
    Write-Host "Camino de migraciones 0050 -> 0051 -> 0052, rollback y restauracion: PASS" -ForegroundColor Green
    Write-Host "Copia usada: $dump (borrarla cuando ya no haga falta)"
} finally {
    $env:DATABASE_URL = $previousUrl
}
