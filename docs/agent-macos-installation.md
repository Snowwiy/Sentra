# Sentra Agent en macOS: instalación (Fase 6C.5, agente 0.4.0)

Agente nativo para Mac con Apple Silicon (arm64) e Intel (x86_64). Corre como LaunchDaemon de
root (`com.sentra.agent`), envía heartbeat, telemetría, inventario, procesos, eventos
seleccionados del Unified Logging y, de forma pasiva, las redes Wi-Fi que el sistema ya
conoce. Protocolo: [agent-protocol.md](agent-protocol.md).

> **Estado de validación.** Todo lo de este documento se ha probado **solo con dobles y
> fixtures en Linux** (salidas reales de `sw_vers`, `ioreg`, `launchctl`, `dscl`, `log show`,
> `system_profiler` guardadas como ficheros, un Keychain simulado y un `launchctl` falso).
> **No se ha validado en un Mac físico.** Ver "Validación pendiente" al final.

## Requisitos

| | Soportado | Notas |
|---|---|---|
| macOS | 13 Ventura o posterior (probado con fixtures de 14 Sonoma y 15 Sequoia) | el instalador rechaza versiones anteriores |
| Arquitectura | arm64 (Apple Silicon) y x86_64 (Intel) | un paquete por arquitectura |
| Python | 3.12 o posterior, **del instalador oficial de python.org** | ver "Python del daemon" |
| Privilegios | administrador (sudo) para instalar | el daemon corre como root |

No hace falta Xcode, Homebrew, pip ni acceso a Internet en el Mac: el paquete trae el código
del agente y la rueda binaria de psutil de su arquitectura.

## 1. Token de instalación (en el servidor)

Igual que en Linux y Windows: un token de un solo uso, restringido a macOS si se quiere.

```bash
python -m app.cli create-enrollment-token --platform macos --hostname MAC-ANA
```

o en el panel, Agentes → Añadir agente. El token se muestra una vez.

## 2. Instalación

### Con el paquete `.pkg` (recomendado)

```bash
# 1. Token en un archivo privado (no se muestra ni queda en el historial; vale en zsh y bash)
(umask 077; printf 'Token de instalación: '; read -rs t && printf '%s\n' "$t" > enrollment.token); echo
# 2. Paquete (sin firmar: con doble clic Gatekeeper lo bloquea, por eso se usa installer)
sudo installer -pkg ./sentra-agent-0.4.0-macos-arm64-unsigned.pkg -target /
# 3. Registro y arranque (el archivo del token se borra al terminar)
sudo /Library/Sentra/Agent/bin/sentra-agent-setup --server https://sentra.example.lan --token-file ./enrollment.token
# 4. Comprobación
sudo launchctl print system/com.sentra.agent
```

El `.pkg` instala el runtime y el LaunchDaemon pero **no enrola**: un paquete no puede pedir
un token de forma segura. Si el Mac ya tenía identidad (actualización) el `postinstall`
reinicia el daemon y no hace falta el paso 3.

### Con el tarball

```bash
tar xzf sentra-agent-0.4.0-macos-arm64.tar.gz
sudo ./sentra-agent-0.4.0-macos-arm64/install-sentra-agent.sh --server https://sentra.example.lan --token-file ./enrollment.token
```

Opciones de `install-sentra-agent.sh`:

| Opción | Uso |
|---|---|
| `--server URL` | URL de la API (https salvo loopback) |
| `--token-file FILE` | token de un solo uso; **no existe `--token`** (quedaría en `ps` y en el historial) |
| `--upgrade` | instala la versión nueva conservando identidad y configuración |
| `--no-start` | deja el daemon instalado pero parado |
| `--python PATH` | intérprete concreto (debe pasar la comprobación de seguridad) |
| `--credential-store auto\|file` | dónde guarda el agente su token (por defecto Keychain del sistema) |
| `--allow-admin-writable-python` | acepta el Python de python.org tal cual (ver abajo) |

El instalador sale con 0 si todo fue bien y con 1 en cualquier error, con un mensaje que
explica la causa según el código del agente al enrolar (`python -m sentra_agent --enroll`):
3 sin enrolar y sin token, 4 token rechazado, 5 servidor inalcanzable, 6 Keychain no
disponible (no se enrola nada y el token no se gasta).

## Python del daemon (decisión de seguridad)

El daemon corre como root, así que **cualquiera que pueda modificar el intérprete o su
biblioteca podría ejecutar código como root**. Por eso el instalador ejecuta
`check-python.py` con el intérprete candidato y exige:

- Python ≥ 3.12;
- propietario root y sin escritura para "otros" en el ejecutable, la biblioteca estándar y sus
  directorios padre;
- sin escritura de grupo, salvo el grupo `admin` con `--allow-admin-writable-python`.

El instalador de python.org deja su framework escribible por el grupo `admin`: un usuario
administrador (que ya puede hacerse root con sudo) podría modificarlo sin contraseña. Para
aceptarlo hay que pasar `--allow-admin-writable-python` de forma explícita, o endurecerlo antes:

```bash
sudo chmod -R go-w /Library/Frameworks/Python.framework
sudo chown -R root:wheel /Library/Frameworks/Python.framework
```

**Con el `.pkg` hay que endurecerlo antes de instalar**: el `postinstall` no admite opciones y
nunca acepta un Python escribible por el grupo `admin`, así que con el framework de python.org
tal cual la instalación del paquete falla (sin dejar el daemon a medias). Quien prefiera no
tocar el framework puede usar el tarball con `--allow-admin-writable-python`. Lo mismo vale
para cada actualización de Python: el instalador de python.org vuelve a dejar el grupo `admin`
con escritura.

**Homebrew nunca se acepta** (sus ficheros son del usuario que lo instaló). El Python de
`/usr/bin/python3` de las Command Line Tools no se usa: depende de Xcode y su versión no la
controla Sentra.

El lanzador ejecuta `python -I -S`: sin variables `PYTHON*`, sin `site-packages` y sin el
directorio actual en la ruta de importación.

**Pendiente de decisión de Jesus:** empaquetar un Python propio firmado dentro del `.pkg`
(elimina la dependencia de python.org y el problema del grupo `admin`, pero hay que mantenerlo
y firmarlo) frente a seguir exigiendo el de python.org.

## Ficheros

| Ruta | Contenido |
|---|---|
| `/Library/Sentra/Agent/lib` | código del agente y psutil (root, 0755) |
| `/Library/Sentra/Agent/bin/sentra-agent` | lanzador (`python -I -S`) |
| `/Library/Sentra/Agent/bin/sentra-agent-setup` | enrolamiento tras el `.pkg` |
| `/Library/Sentra/Agent/share` | scripts de desinstalación y diagnóstico |
| `/Library/Sentra/Agent/agent.toml` | configuración, sin secretos |
| `/Library/Sentra/Agent/state` (0700) | `identity.json` (sin el token), cursores, búfer |
| `/Library/Logs/Sentra` (root:admin 0750) | `agent.log` (rotado por el agente) y `launchd.log` |
| `/Library/LaunchDaemons/com.sentra.agent.plist` | definición del servicio |
| `/etc/newsyslog.d/com.sentra.agent.conf` | rotación de `launchd.log` |

## Token del agente: Keychain del sistema

Tras enrolarse, el agente guarda **su propio token** en el keychain del sistema
(`/Library/Keychains/System.keychain`, servicio `com.sentra.agent`, cuenta
`agent-<agent_id>`) mediante Security.framework (ctypes, sin dependencias nuevas).
`identity.json` solo guarda la referencia (`{"scheme": "macos-keychain", "value": "agent-..."}`).

- El secreto **nunca** pasa por la línea de comandos: no se usa `security add-generic-password
  -w` (visible en `ps`).
- Se usa la API clásica `SecKeychain*` (obsoleta pero la única que un daemon root sin
  entitlements puede usar contra el keychain del sistema); se desactiva la interacción de
  usuario, así que nunca aparece un diálogo.
- Si el Keychain no funciona el agente **falla de forma explícita** (código 6, mensaje
  `credential store unavailable`) antes de gastar el token de un solo uso; **no** guarda el
  token en claro como respaldo.
- Si se quiere un fichero, hay que pedirlo: `--credential-store file` (o
  `credential_store = "file"` en `agent.toml`). El token queda en `identity.json` 0600 dentro
  de `state/` 0700, propiedad de root.
- La ACL del elemento queda ligada al binario que lo creó: **actualizar Python a otra ruta
  puede requerir re-enrolar** (pendiente de validar en un Mac).

## Eventos (Unified Logging)

`/usr/bin/log show --style ndjson` con un **predicado fijo** escrito en el agente: `sshd`,
`sshd-session`, `sudo`, `su`, Compartir pantalla (`screensharingd`) y fallos de autenticación
de `authd`. Nunca "todo el log" ni un predicado enviado por el servidor. Solo se envían los
mensajes que se reconocen; los datos que macOS marca como `<private>` se respetan. Cursor por
marca de tiempo, primer arranque limitado a la última hora (50 eventos), retraso máximo 24 h.

Como root no hace falta Acceso total al disco. El servidor guarda estos eventos con source
`macos_unified_log`; las reglas de detección de Linux/Windows **todavía no** se aplican a esa
fuente (pendiente de backend).

## Wi-Fi pasivo

`/usr/sbin/system_profiler SPAirPortDataType -json`: la red conectada y las redes del último
escaneo **del propio sistema**. Sin escaneo activo, sin contraseñas, sin perfiles. Desde macOS
14.4 el SSID/BSSID requieren permiso de Localización, que un daemon no tiene: llegan como
`null` y el estado es `permission_limited`. Desactivar con `wireless_enabled = false`.

## Estado, logs, reinicio

```bash
sudo launchctl print system/com.sentra.agent        # estado y pid
sudo launchctl kickstart -k system/com.sentra.agent # reiniciar
tail -f /Library/Logs/Sentra/agent.log              # log del agente (secretos redactados)
sudo /Library/Sentra/Agent/share/diagnose-sentra-agent.sh
```

El diagnóstico solo lee y nunca muestra secretos: de la identidad solo `agent_id`, `asset_id`
y el tipo de almacén; del Keychain solo si existe el elemento.

## Actualización

```bash
sudo installer -pkg ./sentra-agent-<nueva>-macos-arm64-unsigned.pkg -target /
# o con el tarball:
sudo ./sentra-agent-<nueva>-macos-arm64/install-sentra-agent.sh --upgrade
```

Conserva identidad, token y configuración; no hace falta token nuevo.

## Desinstalación

```bash
sudo /Library/Sentra/Agent/share/uninstall-sentra-agent.sh          # conserva identidad y logs
sudo /Library/Sentra/Agent/share/uninstall-sentra-agent.sh --purge  # borra todo, token incluido
```

## TLS

El agente siempre verifica el certificado del servidor. En macOS el Python de python.org no
lee el llavero del sistema, así que el agente añade también las raíces de `/etc/ssl/cert.pem`
(las públicas que trae macOS). **Una CA interna instalada solo en el llavero del sistema no se
reconoce todavía**: pendiente de decisión de Jesus (leer el llavero del sistema, o un fichero
de CA configurable).

## Construir el paquete (solo en un Mac)

```bash
agent/packaging/macos/build-pkg.sh                 # arquitectura del Mac
agent/packaging/macos/build-pkg.sh --arch x86_64   # Intel desde Apple Silicon
```

Produce `dist/sentra-agent-<v>-macos-<arch>.tar.gz` y `...-unsigned.pkg` con sus `.sha256`.

### Firma y notarización

El paquete sale **sin firmar y sin notarizar**. Para distribuirlo sin avisos de Gatekeeper hace
falta: cuenta del Apple Developer Program; certificados *Developer ID Application* (para las
`.so` de psutil) y *Developer ID Installer* (para el `.pkg`); `xcrun notarytool` con un perfil
de credenciales guardado; y `xcrun stapler staple`. `build-pkg.sh` tiene `--sign-app`,
`--sign-installer` y `--notary-profile` para ese momento, **sin probar**.

## Validación pendiente en un Mac físico

- Keychain del sistema como root: alta, lectura tras reinicio, rotación, borrado, ACL tras
  actualizar Python, comportamiento con FileVault.
- launchd: `bootstrap`, `KeepAlive`, `ThrottleInterval`, arranque tras reinicio, `--upgrade`.
- TCC: que como root no haga falta Acceso total al disco para `log show`, `dscl`,
  `/Applications` y los recibos de paquetes.
- Unified Logging: formato real de los mensajes de sshd/sudo/su/authd en 13, 14 y 15, y del
  `--start` con zona horaria.
- Wi-Fi: `system_profiler` con y sin Localización, Wi-Fi apagado, sin adaptador.
- `.pkg`: `installer`, `preinstall`/`postinstall`, `pkgutil --forget`, y la firma/notarización.
- Rosetta: un Python x86_64 en Apple Silicon (el agente informa la arquitectura nativa).
