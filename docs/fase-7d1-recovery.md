# Recuperación de la identidad de un agente (Fase 7D.1, H01)

Desde 7D.1, un token de instalación ordinario (o la clave legacy) solo da de alta equipos
NUEVOS. Para que un equipo que ya es un activo de Sentra vuelva a registrarse con su misma
identidad hace falta una **autorización de recuperación**. Es el caso de un equipo con disco
nuevo, reinstalado, que perdió la credencial o que fue revocado y reactivado.

Así nadie con un token de alta puede quedarse con la identidad, el histórico y el site de
otro equipo enviando su `agent_id`.

## Cuándo NO hace falta

- Rotación rutinaria o credencial expuesta con el agente funcionando: **Rotar credencial…**
  en el dashboard o `sentra-agent --rotate-credential` en el equipo. No hay reinstalación
  ni corte.
- Actualizar el agente: el actualizador conserva la identidad y la credencial.
- Un equipo nuevo: un token de instalación ordinario.

## Procedimiento (dashboard)

1. Si el agente está **revocado**: Agentes, o la ficha del activo → **Reactivar…**. Al
   confirmar se abre directamente el paso 2.
2. **Recuperar identidad…** (en la tabla, «Recuperar…» aparece cuando el agente está en
   «Requiere volver a registrarse»; en la ficha del activo, siempre para un admin).
3. Escribe el motivo (al menos 10 caracteres; queda en la auditoría). Deja marcado
   «Solo válida si el equipo informa este nombre» salvo que el hostname haya cambiado.
4. Marca la confirmación explícita y pulsa **Autorizar recuperación**.
5. Copia la autorización. Se muestra una sola vez, sirve una sola vez y caduca a los 15
   minutos (`AGENT_RECOVERY_TOKEN_TTL_MINUTES`).
6. En el equipo, úsala como token de instalación, siempre con una URL `https://`:
   - Windows: `install-sentra-agent.ps1 -Server https://… -Reenroll` (aviso oculto), o con
     `-TokenFile`.
   - Linux: `sudo sentra-agent-setup --server https://… --token-file FICHERO`.
   - macOS: `sudo /Library/Sentra/Agent/bin/sentra-agent-setup --server https://… --token-file FICHERO`.
7. Comprueba en la ficha del activo que «Origen de la credencial» es **Recuperación
   autorizada** y que llegan heartbeats.

El historial de autorizaciones (estado, motivo, autor y fecha) aparece en el mismo diálogo.
Una autorización activa se puede revocar. Emitir una nueva revoca las anteriores del mismo
activo.

## Procedimiento (CLI del servidor)

Sin dashboard, desde la carpeta `backend` del servidor:

```powershell
.venv\Scripts\python.exe -m app.cli authorize-agent-recovery <asset_id> `
  --reason "Reinstalación tras cambio de disco" --confirm --hostname pc-ana
```

Sin `--confirm` no emite nada (código de salida 2). El token sale solo en la última línea de
la salida. No lo pegues en tickets ni en chats: pásalo al equipo con `--token-file` o con el
aviso oculto del instalador.

## Qué comprueba el servidor al usarla

- Que corresponde a ese `agent_id`, a ese activo y a su site, y al hostname si se fijó.
- Que no ha caducado, no se ha usado y no está revocada.
- Que llega por HTTPS o por loopback (si no, 403 `https_required` y no se consume).
- Que el activo no está revocado (primero «Reactivar») ni archivado.

Si algo no cuadra, se rechaza, se audita (`agent_recovery_rejected`) y la credencial
vigente del agente no cambia.

## Errores en el equipo

| Respuesta | Significado |
|-----------|-------------|
| 403 `agent_recovery_required` | Se usó un token ordinario para un activo existente. Pide una autorización de recuperación |
| 403 `https_required` | La URL es `http://` hacia otra máquina. Ver docs/agent-https-migration.md |
| 401 `unauthorized` | La autorización no vale: caducada, usada, revocada, de otro activo, site u hostname, o el activo está revocado o archivado. Por diseño la respuesta no dice cuál; el motivo exacto está en la auditoría (`agent_recovery_rejected`) |

## Plan para el parque existente

No hace falta reinstalar nada ni borrar agentes por 7D.1:

1. Los agentes en marcha conservan su credencial actual.
2. Solo se necesita recuperación cuando se reinstala un equipo concreto.
3. Los agentes registrados con la clave legacy aparecen en el aviso de **Agentes**. Rota sus
   credenciales (en 0.7.0) y fija `AGENT_ENROLLMENT_KEY_EXPIRES_AT` para retirar la clave.
   Pasada la fecha, quítala del `.env`.
