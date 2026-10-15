# Almacenamiento de informes (Fase 5E)

## Dónde

`REPORT_OUTPUT_DIR` (ruta **absoluta**). Sin valor:

- Windows: `%LOCALAPPDATA%\Sentra\reports` del usuario del servicio;
- Linux: `$XDG_STATE_HOME/sentra/reports` o `~/.local/state/sentra/reports`.

La carpeta debe estar **fuera del repositorio** y fuera de cualquier carpeta que sirva el
proxy (frontend/dist): el servidor se niega a usar una raíz dentro del repo. En producción,
`production-check` avisa (WARN) si no está configurada.

Recomendado en Windows Server: `D:\SentraData\reports` con ACL solo para la cuenta del
servicio y los administradores. En Linux: `/var/lib/sentra/reports`, propietario el usuario
del servicio, permisos 0700 (Sentra crea las carpetas con 0700).

## Estructura

```
<REPORT_OUTPUT_DIR>/
  .tmp/                      temporales de escritura (*.part)
  2026/10/<uuid32>.pdf       artefactos (año/mes/uuid del artefacto)
```

La clave guardada en la base de datos tiene exactamente la forma `AAAA/MM/<32 hex>.<ext>` y
se valida en cada lectura: sin `..`, sin rutas absolutas, sin barras invertidas, sin UNC,
sin nombres reservados de Windows. La ruta resuelta debe seguir dentro de la raíz y el
fichero no puede ser un enlace simbólico; si algo no cuadra, falla cerrado (410).

## Escritura atómica

Fichero temporal en `.tmp/` → escribir → `flush` → `fsync` → cerrar → `os.replace` al nombre
final (atómico en el mismo volumen, también en Windows). Un artefacto a medias nunca tiene el
nombre final ni llega a la base de datos. Los temporales huérfanos (proceso caído) se borran
en el siguiente barrido del worker.

## Retención

`REPORT_RETENTION_DAYS` **sin valor: se conserva todo**. Con valor, el worker borra el
fichero de los informes terminados hace más de N días (lotes de 100 por vuelta) y deja la
fila como rastro con estado `expired`: metadatos, resumen, checksum y auditoría
(`report_expired`). El snapshot JSON de un informe expirado o borrado también se elimina.

Borrado manual: `DELETE /api/v1/reports/{id}` (solo admin), mismo comportamiento.

## Copias de seguridad

`backup` (Fase 4M) copia la base de datos: metadatos, snapshots y checksums. Los ficheros de
`REPORT_OUTPUT_DIR` hay que incluirlos en la copia de ficheros del servidor si se quieren
conservar; tras una restauración sin ellos, los informes afectados responden 410 al
descargar y se pueden regenerar (los snapshots siguen en la base de datos).

## Espacio

Cada artefacto está limitado por `REPORT_MAX_ARTIFACT_MB` (25 MB por defecto) y cada tabla
por `REPORT_MAX_ROWS`. El snapshot se guarda en la base de datos (tope 16 MB).
