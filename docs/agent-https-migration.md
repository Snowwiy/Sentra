# Migración de agentes de HTTP a HTTPS (Fase 7D.1, H04)

El agente 0.7.0 solo habla con Sentra por `https://`. Admite `http://` únicamente hacia el
propio equipo (127.0.0.0/8, `::1`, `localhost`). Por HTTP hacia otra máquina, la credencial
del agente viaja sin cifrar y cualquiera en la red puede copiarla y suplantar al equipo.

Esta guía migra un parque existente sin cortar la monitorización. Los agentes 0.6.x por
HTTP siguen enviando datos durante toda la migración: el servidor solo los marca.

## 0. Qué no pasa

- El servidor no corta a ningún agente por hablar HTTP. Lo marca como «HTTP en claro» y le
  pide rotar su credencial, pero solo se la entrega cuando hable por HTTPS.
- El instalador 0.7.0 no para el servicio si la configuración existente apunta a un HTTP
  remoto. Se niega antes y explica qué hacer.
- No hay ninguna opción para desactivar la verificación TLS.

## 1. Inventario

En el dashboard, **Agentes** muestra un aviso con el número de agentes que hablan por HTTP en
claro, y la columna **Transporte** de cada uno (`HTTPS`, `HTTP local` o `HTTP en claro`). La
misma información sale de la API en `GET /api/v1/agents` (`summary.insecure_transport` y el
campo `transport` de cada agente).

En cada equipo, la URL está en la configuración del agente:

| Sistema | Fichero |
|---------|---------|
| Windows | `C:\ProgramData\Sentra\Agent\config\agent.toml` |
| Linux | `/etc/sentra-agent/agent.toml` |
| macOS | `/Library/Sentra/Agent/agent.toml` |

La clave es `api_url`.

Anota también qué CA firmará el certificado: una pública o una CA interna. Con una CA
interna, cada equipo necesita su certificado raíz.

## 2. Publicar Sentra por HTTPS

Sigue docs/production-deployment.md. La referencia es Caddy delante de la API (plantillas en
`deploy/caddy`), con un certificado de una CA pública o de la CA interna. Comprueba:

- `TRUSTED_PROXIES` incluye la dirección del proxy (por defecto `127.0.0.1,::1`, que vale si
  Caddy corre en el mismo servidor). Sin esto, el servidor no ve `X-Forwarded-Proto: https`
  y seguirá clasificando a los agentes como HTTP.
- `AGENT_SERVER_URL=https://sentra.ejemplo.local` en el `.env` del servidor, para que el
  asistente «Añadir agente» genere comandos con la URL buena.
- Mientras dure la migración, el puerto HTTP antiguo de la API sigue abierto para los
  agentes 0.6.x que aún no se han migrado. Ciérralo en el paso 6.

## 3. Validar desde cada red

Desde un equipo de cada red o site, sin el agente:

```powershell
# Windows
Invoke-WebRequest https://sentra.ejemplo.local/api/v1/health -UseBasicParsing
```

```sh
# Linux / macOS
curl -fsS https://sentra.ejemplo.local/api/v1/health
```

Si falla la validación del certificado, falta la CA interna en el almacén del sistema. Con
el agente tienes dos opciones:

- instalar la CA en el almacén del sistema (recomendado);
- poner `ca_bundle = "/ruta/ca.pem"` en `agent.toml`, que la añade como CA de confianza
  adicional.

No uses la IP si el certificado se emitió para un nombre: la validación del nombre es
obligatoria.

## 4. Pasar los agentes a HTTPS

### Opción A: actualizar a 0.7.0 cambiando la URL

1. Edita `api_url` en `agent.toml` a `https://…` (y añade `ca_bundle` si hace falta).
2. Reinicia el agente 0.6.x y comprueba en el dashboard que su transporte pasa a `HTTPS`.
3. Instala el 0.7.0 encima. Conserva la identidad y la credencial.

### Opción B: reinstalar con la URL nueva

- Windows: `install-sentra-agent.ps1 -Server https://sentra.ejemplo.local -Reenroll`.
- Linux: `sudo sentra-agent-setup --server https://sentra.ejemplo.local --token-file FICHERO`.
- macOS: `sudo /Library/Sentra/Agent/bin/sentra-agent-setup --server https://… --token-file FICHERO`.

Un equipo que ya es un activo de Sentra **no** se puede volver a registrar con un token de
instalación ordinario. Necesita una autorización de recuperación (docs/fase-7d1-recovery.md).

### Qué hace el instalador 0.7.0 con una configuración HTTP

Si `agent.toml` apunta a `http://` hacia otra máquina, el instalador (PowerShell, `.sh`,
`.deb` o `.pkg`) termina con un error que cita esta guía **antes de parar el servicio**. El
agente anterior sigue funcionando hasta que corrijas la URL.

## 5. Rotar las credenciales expuestas

Toda credencial que viajó por HTTP en claro se considera expuesta.

- El servidor ya pidió la rotación de cada agente que vio por HTTP remoto (motivo
  `insecure_transport`). El agente 0.7.0 la hace solo en su primer heartbeat por HTTPS, sin
  corte: la credencial anterior vale hasta que se usa la nueva.
- También se puede pedir desde el dashboard (agente → **Rotar credencial…**) o en el equipo
  con `sentra-agent --rotate-credential`.
- Comprueba en el panel del agente que «Origen de la credencial» pasa a **Rotación**.

Un agente 0.6.x no sabe rotar: actualízalo a 0.7.0 primero.

## 6. Cerrar HTTP

Cuando el aviso de **Agentes** desaparezca (ningún agente en HTTP en claro durante al menos
un ciclo de heartbeat de todos los equipos, incluidos los portátiles que se conectan poco):

1. Cierra en el firewall el puerto HTTP de la API, o haz que la API escuche solo en
   loopback detrás de Caddy (`start_backend.ps1 -BindHost 127.0.0.1`).
2. Si usabas la clave compartida legacy, fija `AGENT_ENROLLMENT_KEY_EXPIRES_AT` y, cuando
   pase la fecha, elimina `AGENT_ENROLLMENT_KEY`.

## Diagnóstico

| Mensaje del agente | Causa | Qué hacer |
|--------------------|-------|-----------|
| `api_url uses http:// to … outside loopback` | URL http remota | Pasos 2 a 4 |
| `TLS verification failed: …` | CA desconocida o nombre incorrecto | Paso 3 |
| `HTTP 301 redirect to … refused` (o 302, 303, 307, 308) | El proxy redirige (por ejemplo, de http a https) | Pon directamente la URL final `https://…` |
| `https_required` (403) | Rotación o recuperación pedida por HTTP | Pasar a HTTPS |
| `agent_recovery_required` (403) | Reinstalación de un activo existente con un token ordinario | docs/fase-7d1-recovery.md |
