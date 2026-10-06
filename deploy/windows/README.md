# Sentra en Windows Server (Fase 4M)

Linux con systemd es la plataforma de referencia para el servidor central
(`docs/production-deployment.md`). Windows Server también es válido; esta guía cubre lo que
cambia. Sin Docker ni contenedores.

## Cuentas y carpetas

| Elemento | Recomendación |
| --- | --- |
| Código | `C:\Sentra` (solo lectura para el servicio) |
| Configuración | `C:\ProgramData\Sentra\sentra.env` (ACL: Administradores + cuenta del servicio, lectura) |
| Logs | `C:\ProgramData\Sentra\logs` con `LOG_FILE=C:\ProgramData\Sentra\logs\sentra.log` (rotación propia por tamaño) |
| Copias | `D:\SentraBackups` u otro volumen, fuera de `C:\Sentra` y del webroot |
| Cuenta del servicio | cuenta virtual `NT SERVICE\SentraAPI` o una cuenta local sin privilegios, nunca `LocalSystem` ni un administrador |

ACL de la configuración (PowerShell como administrador):

```powershell
$env = "C:\ProgramData\Sentra\sentra.env"
icacls $env /inheritance:r
icacls $env /grant:r "Administrators:F" "NT SERVICE\SentraAPI:R"
```

## Servicio de la API

Windows no puede ejecutar `uvicorn` directamente como servicio. Se usa
[WinSW](https://github.com/winsw/winsw) (código abierto, configuración XML, sin servicios
de terceros ni telemetría): descargar `WinSW-x64.exe` de su página de releases, comprobar el
SHA-256 publicado, renombrarlo a `C:\Sentra\service\sentra-api.exe` y poner al lado
`sentra-api.xml`:

```xml
<service>
  <id>SentraAPI</id>
  <name>Sentra API</name>
  <description>Sentra API (solo 127.0.0.1; la publica Caddy por HTTPS)</description>
  <executable>C:\Sentra\backend\.venv\Scripts\python.exe</executable>
  <arguments>-m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-proxy-headers --no-server-header --timeout-graceful-shutdown 20</arguments>
  <workingdirectory>C:\Sentra\backend</workingdirectory>
  <startmode>Automatic</startmode>
  <depend>postgresql-x64-18</depend>
  <onfailure action="restart" delay="10 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="none"/>
  <stoptimeout>30 sec</stoptimeout>
  <log mode="roll-by-size"><sizeThreshold>10240</sizeThreshold><keepFiles>5</keepFiles></log>
</service>
```

Sentra lee la configuración de `.env` en `backend\` o en la raíz del código (`C:\Sentra\.env`).
Ese archivo lleva la ACL restringida de arriba (o se crea un enlace simbólico
`C:\Sentra\.env` -> `C:\ProgramData\Sentra\sentra.env`).

```powershell
C:\Sentra\service\sentra-api.exe install
# Cuenta virtual del servicio: sin contraseña que guardar y sin privilegios de administrador.
sc.exe config SentraAPI obj= "NT SERVICE\SentraAPI"
icacls C:\Sentra /grant "NT SERVICE\SentraAPI:(OI)(CI)RX"
icacls C:\ProgramData\Sentra\logs /grant "NT SERVICE\SentraAPI:(OI)(CI)M"
Start-Service SentraAPI
Get-Content C:\ProgramData\Sentra\logs\sentra.log -Tail 20
```

`--workers` con más de un proceso no está soportado por uvicorn en Windows en todas las
versiones; en Windows se recomienda un único worker (es suficiente para un servidor único).

## Caddy

`caddy.exe` de la página oficial (comprobar SHA-256), `Caddyfile` a partir de
`deploy/caddy/Caddyfile.example` cambiando las rutas (`root * C:\Sentra\frontend\dist`,
certificados en `C:\ProgramData\Caddy\certs`). Como servicio, otro XML de WinSW con
`caddy.exe run --config C:\ProgramData\Caddy\Caddyfile`.

## Copias programadas

Programador de tareas, diaria, con la cuenta del servicio:

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Sentra\backend\.venv\Scripts\python.exe" `
  -Argument "-m app.cli backup" -WorkingDirectory "C:\Sentra\backend"
$trigger = New-ScheduledTaskTrigger -Daily -At 2:30am
Register-ScheduledTask -TaskName "Sentra backup" -Action $action -Trigger $trigger `
  -User "NT SERVICE\SentraAPI"
```

En Windows, `pg_dump.exe` no suele estar en el `PATH`: `PG_BIN_DIR=C:\Program Files\PostgreSQL\18\bin`.
La carpeta de copias necesita ACL: solo Administradores y la cuenta del servicio.

## Cortafuegos

```powershell
New-NetFirewallRule -DisplayName "Sentra HTTPS" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow
New-NetFirewallRule -DisplayName "Sentra HTTP (redirección)" -Direction Inbound -Protocol TCP -LocalPort 80 -Action Allow
# 8000 (API) y 5432 (PostgreSQL) NO se abren: solo escuchan en 127.0.0.1.
```
