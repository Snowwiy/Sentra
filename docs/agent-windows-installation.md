# Sentra Agent en Windows: paquete, instalador y servicio

Sentra Agent se instala en Windows como un **servicio Windows estándar** ("Sentra Agent",
nombre interno `SentraAgent`), sin Git, sin Python instalado, sin venv, sin clave de
enrolamiento compartida y sin una ventana de PowerShell abierta. El paquete solo contiene el
agente: nada del servidor, del frontend, de PostgreSQL ni ningún `.env` o clave.

## Requisitos

- Windows 10/11 o Windows Server 2019 o posterior (build ≥ 17763), **x64**.
- Windows PowerShell 5.1 (incluido en Windows) y una cuenta de administrador para instalar.
- Que el equipo llegue al servidor Sentra (solo conexiones **salientes** a la URL de la API).

## Construir el paquete (una vez por versión)

En el PC de desarrollo (Windows), desde la raíz del repositorio:

```powershell
python agent\packaging\windows\build.py
```

Descarga el Python embebido oficial de python.org (`python-3.12.10-embed-amd64.zip` por
defecto, `--python-version` para otro) y la rueda de psutil, y genera:

```
dist\sentra-agent-<versión>-windows-x86_64.zip
dist\sentra-agent-<versión>-windows-x86_64.zip.sha256
```

Verificaciones del build: la rueda de psutil debe tener el SHA-256 publicado en PyPI (fijado
en `build.py`) y `python.exe`/`pythonXY.dll` deben tener firma Authenticode válida de la
**Python Software Foundation** (`Get-AuthenticodeSignature`). Fuera de Windows hay que pasar
`--python-embed-sha256` con el valor publicado en python.org; sin ninguna verificación el
build se niega. Sin conexión: `--python-embed-zip` y `--psutil-wheel` con archivos locales.

Contenido del zip:

```
sentra-agent-<versión>-windows-x86_64\
  install-sentra-agent.ps1     instalador / upgrade / re-enrolamiento
  uninstall-sentra-agent.ps1   desinstalación (con -Purge opcional)
  README.md                    esta guía
  VERSION                      versión, Python y psutil usados (con sus SHA-256)
  MANIFEST.sha256              hash de cada archivo; el instalador lo comprueba
  payload\runtime\             Python embebido (sys.path fijado por pythonXY._pth)
  payload\lib\                 sentra_agent + psutil
```

Por qué Python embebido y no PyInstaller o un MSI: es el runtime oficial y firmado, no hay
que compilar nada ni añadir herramientas de build, y el agente es el mismo código que en
Linux. La estructura (binarios en Program Files, datos en ProgramData, servicio con cuenta
propia) es la que tendría un MSI; empaquetarlo como MSI (WiX) más adelante no cambia el
agente ni las rutas.

## Instalar desde Sentra Web

1. **Agentes → + Añadir agente → Windows → Continuar.**
2. Revisa la **URL del servidor** (nunca `localhost`: en el equipo Windows sería él mismo) y,
   si quieres, el **hostname esperado** (`hostname` en PowerShell).
3. **Generar token de instalación**: token de un solo uso para la plataforma `windows`, válido
   15 minutos. Se muestra una vez.
4. Copia el zip al equipo, abre **PowerShell como administrador** en esa carpeta y ejecuta los
   comandos que muestra el asistente:

   ```powershell
   Expand-Archive -Path .\sentra-agent-*-windows-x86_64.zip -DestinationPath . -Force; Set-Location .\sentra-agent-*-windows-x86_64
   powershell -NoProfile -ExecutionPolicy Bypass -File .\install-sentra-agent.ps1 -Server 'http://192.168.50.201:8000'
   Get-Service SentraAgent
   ```

   El instalador pide el token en un aviso **que no lo muestra**: no queda en el historial de
   PowerShell ni en la línea de comandos de ningún proceso. Alternativa para despliegues:
   `-TokenFile .\enrollment.token` (el instalador borra ese archivo al registrarse).
   `-ExecutionPolicy Bypass` solo afecta a ese proceso de PowerShell; no cambia la directiva
   del equipo.
5. El asistente detecta el registro (**Equipo registrado**) y el agente aparece
   **Online / Managed** con CPU, RAM y disco; el detalle del agente muestra
   **Método de instalación: Servicio Windows**.

## Qué hace el instalador

1. Comprueba administrador, Windows compatible de 64 bits y la integridad del paquete
   (`MANIFEST.sha256`).
2. Pide (o valida) el token **antes** de cambiar nada.
3. Copia `runtime\` y `lib\` a `C:\Program Files\Sentra Agent\` (copia completa y después
   intercambio, para no dejar nunca una mezcla de versiones) y quita la marca "descargado de
   Internet" solo a esos archivos ya verificados.
4. Crea el servicio `SentraAgent`:
   - binario: `"C:\Program Files\Sentra Agent\runtime\python.exe" -I -m sentra_agent --service --config "C:\ProgramData\Sentra\Agent\config\agent.toml"` (rutas entre comillas: sin
     ellas, una ruta con espacios es la vulnerabilidad "unquoted service path");
   - cuenta: **`NT SERVICE\SentraAgent`** (cuenta virtual, ver Privilegios);
   - inicio **automático (retrasado)**: arranca sin sesión de usuario, con la red ya lista;
   - recuperación: reinicio a los 10 s, 30 s y 60 s; el contador se reinicia tras 1 día; también
     si el servicio termina con código de error (`failureflag`).
5. Crea `C:\ProgramData\Sentra\Agent\{config,state,logs}` con ACL sin herencia: SYSTEM y
   Administradores control total; el servicio lectura en `config\` y modificación en
   `state\` y `logs\`. Usuarios normales: sin acceso.
6. Escribe `config\agent.toml` (sin secretos) con `api_url`, rutas e
   `installation_method = "windows_service"`.
7. Añade `NT SERVICE\SentraAgent` al grupo integrado **Event Log Readers** (SID
   `S-1-5-32-573`, "Lectores del registro de eventos" en español).
8. Si existe una identidad de una ejecución manual previa (`%LOCALAPPDATA%\Sentra\Agent\identity.json`
   del administrador que instala), reutiliza su `agent_id` (no su token): el equipo sigue siendo
   **el mismo activo**. Avisa si detecta un agente manual aún en marcha (hay que pararlo).
9. Deja el token en `state\enrollment.token` y arranca el servicio. **El servicio se enrola**,
   cifra su token individual con DPAPI, borra el token de instalación y escribe el resultado en
   `state\enrollment-status.json` (sin secretos), que el instalador lee:
   - `enrolled` / `already_enrolled`: éxito; borra el `-TokenFile` del usuario si se usó.
   - `rejected` (caducado, usado, revocado, otro equipo o plataforma): para el servicio, borra
     el token y sale con error: genera otro token y repite.
   - `unreachable`: el servicio queda en marcha reintentando (con backoff) mientras el token no
     caduque; el token sigue en `state\` protegido por la ACL. Código de salida 2.

Por qué enrola el servicio y no el instalador: DPAPI cifra para la cuenta que guarda el token.
Si lo guardase el administrador que instala, la cuenta del servicio no podría descifrarlo.

Códigos de salida: `0` correcto, `1` error (mensaje en rojo), `2` instalado pero enrolamiento
pendiente (servidor inaccesible o sin respuesta a tiempo).

Parámetros: `-Server URL`, `-TokenFile ARCHIVO`, `-Upgrade`, `-Reenroll`,
`-ServiceAccount Virtual|LocalSystem`, `-NoImportIdentity`, `-EnrollTimeoutSeconds N`
(`Get-Help .\install-sentra-agent.ps1 -Full`).

## Rutas

| Qué | Dónde |
|-----|-------|
| Binarios (runtime + agente + desinstalador) | `C:\Program Files\Sentra Agent\` |
| Configuración | `C:\ProgramData\Sentra\Agent\config\agent.toml` |
| Estado: identidad, token cifrado, buffer, cursor de eventos | `C:\ProgramData\Sentra\Agent\state\` |
| Logs (JSON, rotación 5 × 1 MB) | `C:\ProgramData\Sentra\Agent\logs\agent.log` |

## Privilegios (mínimo privilegio)

El servicio **no** corre como LocalSystem ni como administrador. Usa la cuenta virtual
`NT SERVICE\SentraAgent`, que Windows gestiona sola (sin contraseña) y que solo tiene los
permisos de un usuario estándar más lo que el instalador le da:

| Recurso | Quién puede leerlo por defecto | Qué hace Sentra |
|---------|-------------------------------|-----------------|
| Event Log **Security** | SYSTEM, Administradores, **Event Log Readers** | añade la cuenta del servicio a Event Log Readers |
| Event Log System, Application | cualquier usuario autenticado | nada |
| Microsoft-Windows-PowerShell/Operational | usuarios autenticados / Event Log Readers | nada (sin texto de los scripts) |
| CPU, RAM, disco, red, servicios, software (registro HKLM), cuentas locales | usuario estándar | nada |
| `state\`, `logs\` | solo SYSTEM, Administradores y el servicio | ACL del instalador |

Así se resuelve el `Security (5): Access denied` de la ejecución manual sin elevar el agente:
la lectura del canal Security la concede el grupo integrado pensado para eso (el mismo que usa
Windows Event Forwarding), no un privilegio de administrador.

Limitaciones conocidas de no ser administrador: de los procesos de otras cuentas (SYSTEM,
otros usuarios) psutil puede no devolver la ruta del ejecutable o el usuario; se envían sin
esos campos, igual que en la ejecución manual.

**Alternativa LocalSystem** (`-ServiceAccount LocalSystem`): solo si la cuenta virtual no
funcionase en un equipo concreto (por ejemplo, una directiva que impida perfiles de cuentas de
servicio). LocalSystem lo puede todo en el equipo, por eso no es el valor por defecto. Cambiar
de cuenta invalida el token cifrado: el instalador lo detecta y pide un token nuevo.

Evolución futura: cuenta de servicio administrada de grupo (gMSA) en dominios, y MSI firmado.

## Credenciales

- **Token individual**: cifrado con DPAPI en el ámbito de la cuenta del servicio
  (`state\identity.json` solo guarda el blob cifrado). Copiar el archivo a otro equipo u otra
  cuenta no sirve. Nunca en el repositorio, en logs (todas las líneas pasan por el redactor de
  secretos), en argumentos de procesos ni en el frontend.
- **Token de instalación**: de un solo uso, caduca a los 15 minutos, pasa del aviso oculto (o
  `-TokenFile`) a `state\enrollment.token` y el servicio lo borra al resolverse el
  enrolamiento (éxito o rechazo). No se escribe en `agent.toml` ni en ningún log.
- **Clave compartida (legacy)**: no hace falta en Windows.

## Servicio

- Visible para administradores: `services.msc`, `Get-Service SentraAgent`,
  `sc.exe qc SentraAgent`, `sc.exe qfailure SentraAgent`. No se oculta ningún proceso.
- Parada limpia: el agente termina el ciclo en curso y para; mientras tanto informa al
  Service Control Manager (`STOP_PENDING`) para que no lo dé por colgado.
- El Service Control Manager registra arranques, paradas y fallos en el registro **Sistema**
  (eventos 7036, 7024, 7031). El agente no registra una fuente propia en el Event Log (exigiría
  escribir en el registro de Windows como administrador); sus logs están en `logs\agent.log`.

## Firewall

Ninguna regla. El agente solo abre conexiones salientes HTTP(S) hacia `api_url`; no escucha
en ningún puerto. Si un firewall de salida corporativo bloquea, hay que permitir el destino
del servidor Sentra, no abrir puertos en el equipo.

## Upgrade

Con el zip de la versión nueva, en PowerShell como administrador:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install-sentra-agent.ps1 -Upgrade
```

Para el servicio, sustituye `runtime\` y `lib\`, conserva configuración, `agent_id`, token
individual y logs, y lo arranca. **No vuelve a enrolar.** Ejecutar el instalador sobre una
instalación existente sin token hace lo mismo. `-Server URL` además cambia `api_url`.

## Re-enrolamiento (agente revocado)

1. En **Agentes**, **Reactivar…** el agente (queda *Re-enrollment required*) y el asistente
   genera un token Windows para ese hostname.
2. En el equipo: `install-sentra-agent.ps1 -Server URL -Reenroll` (el asistente ya añade
   `-Reenroll`).
3. El servicio vuelve a enrolar con el **mismo agent_id**: mismo activo, con su historial.

Un agente revocado y **no** reactivado recibe `rejected` (`agent revoked by an operator`).

## Desinstalar

```powershell
& 'C:\Program Files\Sentra Agent\uninstall-sentra-agent.ps1'          # conserva identidad
& 'C:\Program Files\Sentra Agent\uninstall-sentra-agent.ps1' -Purge   # borra todo
```

- **Por defecto**: para y elimina el servicio, quita la cuenta del grupo Event Log Readers y
  borra `C:\Program Files\Sentra Agent`. **Conserva** `C:\ProgramData\Sentra\Agent`
  (configuración, identidad y logs): reinstalar recupera el mismo activo sin token nuevo.
- **`-Purge`**: además borra `C:\ProgramData\Sentra\Agent`. Consecuencias: se pierden el
  `agent_id` y el token individual, los logs y la telemetría pendiente de enviar; una
  reinstalación necesita un token nuevo y aparece como **un activo nuevo** (el anterior se
  queda con su historial; revócalo en Agentes si ya no se usa). El perfil de Windows de la
  cuenta virtual, creado por el sistema, no se toca.

## De la ejecución manual al servicio (equipo de desarrollo)

1. Para el agente manual (Ctrl+C en la ventana de `start_agent.ps1`).
2. Genera un token Windows en Agentes e instala con el zip.
3. El instalador importa el `agent_id` de `%LOCALAPPDATA%\Sentra\Agent` y el servicio se
   enrola con él: el equipo sigue siendo el mismo activo. No vuelvas a lanzar el agente manual
   con la misma identidad mientras el servicio esté instalado.

## Solución de problemas

| Síntoma | Qué mirar |
|---------|-----------|
| `rejected` | Token caducado o usado, o generado para Linux u otro hostname: genera otro. |
| `unreachable` / código 2 | `api_url`, red y firewall de salida; la API debe escuchar en la red (`start_backend.ps1 -BindHost 0.0.0.0`). El servicio sigue reintentando. |
| El servicio no arranca | `logs\agent.log` y Visor de eventos → Registros de Windows → Sistema. `sc.exe qc SentraAgent`. |
| Sin eventos Security | `net localgroup "Event Log Readers"` debe listar `NT SERVICE\SentraAgent`; reinicia el servicio tras añadirlo. |
| La cuenta virtual falla | Reinstala con `-ServiceAccount LocalSystem -Reenroll` (documentado arriba). |

## Validación

**Validado en tests automáticos (pytest; ejecutados en Linux, sin un Windows real):** generación de rutas,
`agent.toml` y línea del servicio con espacios y comillas; validación de URL y token (con BOM
UTF-8/UTF-16); SID del servicio; importación de identidad sin token; enrolamiento por el
servicio (éxito, rechazo, servidor caído con token conservado, reintento, token no usado
borrado, re-enrolamiento tras revocar, revocado sin reactivar); upgrade sin re-enrolar;
estados del servicio ante el SCM (arranque, parada larga, fallo → recuperación); DPAPI simulado
(otra cuenta no descifra → re-enrolamiento); ausencia de secretos en logs, estado y archivos
generados; `installation_method` con servidores nuevos y antiguos; build del zip (contenido,
manifiesto, reproducibilidad, verificación obligatoria); sintaxis y funciones de los scripts
PowerShell con `pwsh`.

**Pendiente de validación física en Windows** (no se puede simular fuera de Windows):
creación real del servicio con la cuenta virtual, ACL, grupo Event Log Readers, DPAPI real
bajo la cuenta del servicio, lectura real del canal Security, reinicio del equipo,
recuperación del SCM y desinstalación. Checklist:

1. `python agent\packaging\windows\build.py` termina con `signature ok` y `built ...zip`.
2. En un Windows 10/11 limpio (o VM), copia el zip; Sentra Web → Agentes → Añadir agente →
   Windows → genera token.
3. PowerShell como administrador → comandos del asistente → pega el token. Debe terminar con
   `enrolled: agent_id=... asset_id=...` y código 0 (`$LASTEXITCODE`).
4. `Get-Service SentraAgent` → Running; `sc.exe qc SentraAgent` → `START_TYPE AUTO_START
   (DELAYED)`, `SERVICE_START_NAME NT SERVICE\SentraAgent`, ruta entre comillas;
   `sc.exe qfailure SentraAgent` → tres `RESTART`.
5. `Test-Path C:\ProgramData\Sentra\Agent\state\enrollment.token` → False;
   `Get-Content C:\ProgramData\Sentra\Agent\state\identity.json` → `"scheme": "dpapi-user"`,
   ningún token legible; `icacls C:\ProgramData\Sentra\Agent\state` → sin `BUILTIN\Users`.
6. Sentra Web: el agente aparece Online/Managed; CPU/RAM/disco; Método de instalación:
   **Servicio Windows**.
7. `net localgroup "Event Log Readers"` (o "Lectores del registro de eventos") lista
   `NT SERVICE\SentraAgent`; en `logs\agent.log` no aparece `event log channel not readable`
   para Security. Provoca un logon fallido (`runas /user:%COMPUTERNAME%\noexiste cmd`, contraseña
   cualquiera) y comprueba un evento 4625 en Sentra en ≤ 2 minutos.
8. Cierra la sesión de PowerShell; el agente sigue reportando.
9. Reinicia Windows; sin iniciar sesión, el agente vuelve a Online.
10. `Stop-Process -Id (Get-CimInstance Win32_Service -Filter "Name='SentraAgent'").ProcessId -Force`
    → a los ~10 s el servicio vuelve a Running (recuperación).
11. `Restart-Service SentraAgent` → para en < 2 min sin errores en el Visor de eventos.
12. Upgrade: sube `version` en `agent/pyproject.toml` y `sentra_agent/__init__.py`, reconstruye,
    ejecuta `-Upgrade` → mismo `agent_id`, sin registro nuevo en Tokens, sin activo duplicado.
13. Revoca el agente en Agentes → el log muestra `API refused agent credentials`. Reactívalo →
    nuevo token → `-Reenroll` → mismo activo, historial intacto.
14. Desinstala sin `-Purge` → servicio y Program Files fuera, ProgramData intacto; reinstala sin
    token → mismo activo. Desinstala con `-Purge` → `C:\ProgramData\Sentra\Agent` no existe.
15. Equipo de desarrollo con agente manual previo: instala → mensaje "identidad importada" y
    mismo activo en Sentra.
16. Get-NetFirewallRule | Where-Object DisplayName -like '*Sentra*' → nada.
