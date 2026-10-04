#Requires -Version 5.1
<#
.SYNOPSIS
    Creates the Sentra role and databases in a native PostgreSQL and applies migrations.
.DESCRIPTION
    Reads DATABASE_URL and TEST_DATABASE_URL from .env, then (as a PostgreSQL superuser)
    creates or updates the application role and creates both databases if missing.
    The superuser password is prompted for and never stored. Safe to run more than once.
#>
[CmdletBinding()]
param(
    [string]$SuperUser = "postgres",
    [string]$PsqlPath
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$envFile = Join-Path $root ".env"
if (-not (Test-Path $envFile)) { throw ".env not found. Run .\scripts\setup_windows.ps1 first." }

function Get-EnvValue([string]$name) {
    $line = Get-Content $envFile | Where-Object { $_ -match "^\s*$name\s*=" } | Select-Object -First 1
    if (-not $line) { throw "$name is missing from .env" }
    return ($line -split "=", 2)[1].Trim()
}

function ConvertFrom-DatabaseUrl([string]$url) {
    $pattern = '^postgresql(\+\w+)?://(?<user>[^:@/]+):(?<password>[^@/]+)@(?<host>[^:/]+):(?<port>\d+)/(?<db>[\w-]+)$'
    if ($url -notmatch $pattern) { throw "Unsupported database URL format: use user:password@host:port/db" }
    return [pscustomobject]@{
        User = $Matches.user; Password = [uri]::UnescapeDataString($Matches.password)
        Host = $Matches.host; Port = $Matches.port; Database = $Matches.db
    }
}

function Quote-Literal([string]$value) { return "'" + $value.Replace("'", "''") + "'" }

$main = ConvertFrom-DatabaseUrl (Get-EnvValue "DATABASE_URL")
$test = ConvertFrom-DatabaseUrl (Get-EnvValue "TEST_DATABASE_URL")
if ($main.User -ne $test.User -or $main.Host -ne $test.Host -or $main.Port -ne $test.Port) {
    throw "DATABASE_URL and TEST_DATABASE_URL must share user, host and port."
}
if ($main.Database -eq $test.Database) { throw "The test database must differ from the main one." }

if (-not $PsqlPath) {
    $cmd = Get-Command psql -ErrorAction SilentlyContinue
    if ($cmd) {
        $PsqlPath = $cmd.Source
    } else {
        $PsqlPath = Get-ChildItem "C:\Program Files\PostgreSQL\*\bin\psql.exe" -ErrorAction SilentlyContinue |
            Sort-Object { [int]$_.Directory.Parent.Name } -Descending |
            Select-Object -First 1 -ExpandProperty FullName
    }
}
if (-not $PsqlPath -or -not (Test-Path $PsqlPath)) { throw "psql.exe not found. Pass -PsqlPath." }

$user = Quote-Literal $main.User
$sql = @"
SELECT format('CREATE ROLE %I LOGIN', $user) WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = $user)\gexec
SELECT format('ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB PASSWORD %L', $user, $(Quote-Literal $main.Password))\gexec
SELECT format('CREATE DATABASE %I OWNER %I', $(Quote-Literal $main.Database), $user) WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = $(Quote-Literal $main.Database))\gexec
SELECT format('CREATE DATABASE %I OWNER %I', $(Quote-Literal $test.Database), $user) WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = $(Quote-Literal $test.Database))\gexec
"@

$secure = Read-Host "Password for PostgreSQL superuser '$SuperUser'" -AsSecureString
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $env:PGPASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    Write-Host "==> Creating role '$($main.User)' and databases '$($main.Database)', '$($test.Database)'" -ForegroundColor Cyan
    # The SQL goes through stdin so the application password never appears in a process list.
    $sql | & $PsqlPath -X -q -v ON_ERROR_STOP=1 -h $main.Host -p $main.Port -U $SuperUser -d postgres
    if ($LASTEXITCODE -ne 0) { throw "psql failed." }
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
}

Write-Host "==> Applying migrations" -ForegroundColor Cyan
$venvPython = Join-Path $root "backend\.venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) { throw "Virtual environment missing. Run .\scripts\setup_windows.ps1 first." }
Push-Location (Join-Path $root "backend")
try {
    & $venvPython -m alembic upgrade head
    if ($LASTEXITCODE -ne 0) { throw "alembic upgrade failed." }
} finally {
    Pop-Location
}

Write-Host ""
Write-Host "Database ready. Next: .\scripts\start_backend.ps1" -ForegroundColor Green
