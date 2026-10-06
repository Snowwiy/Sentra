# Copias de seguridad y restauración (Fase 4M)

Sentra delega en las herramientas oficiales de PostgreSQL (`pg_dump` / `pg_restore`) y
añade lo que suele faltar: verificación, checksum, retención, destino seguro y una
restauración que no puede pisar una base en uso por accidente.

## Qué contiene una copia

Toda la base `sentra` en formato *custom* de `pg_dump` (comprimido, restaurable tabla a
tabla): activos, inventario, telemetría, eventos, alertas, detecciones, riesgo, incidentes,
contexto, IA (resultados y modelos registrados, no los archivos `.gguf`), usuarios
(hashes Argon2), sesiones, auditoría, hashes de credenciales de agentes y tokens de
inscripción (hash), y la revisión de Alembic.

No contiene: `sentra.env` (secretos), certificados TLS, el código, el build del frontend ni
los modelos de IA. Guardarlos aparte (los secretos en el gestor de secretos de la empresa).

**Una copia es tan sensible como la base**: contiene hashes de contraseñas, datos de
equipos y usuarios, IPs y eventos de seguridad. Por eso:

- `BACKUP_DIR` debe ser una ruta absoluta **fuera** del repositorio y del webroot
  (`check_destination` lo impone; `production-check` lo revisa).
- Linux: carpeta `700` y archivos `600`, del usuario del servicio. Windows: ACL solo para
  Administradores y la cuenta del servicio (`deploy/windows/README.md`).
- La contraseña nunca va en la línea de comandos ni en scripts: se pasa a `pg_dump` por la
  variable de entorno `PGPASSWORD` del proceso hijo, derivada de `DATABASE_URL`.
- Copia externa (otro equipo, cinta, almacenamiento de la empresa) cifrada y con acceso
  restringido: la copia local no protege frente a la pérdida del servidor.

## Crear una copia

```bash
cd /opt/sentra/backend
.venv/bin/python -m app.cli backup                 # usa BACKUP_DIR
.venv/bin/python -m app.cli backup --dir /mnt/otra # destino puntual
```

Pasos internos:

1. Valida el destino y crea la carpeta con permisos restringidos.
2. `pg_dump --format=custom --compress=6 --no-owner --no-privileges` a `*.partial`.
3. Verifica la copia (abajo). Si algo falla, borra el parcial y sale con código 1.
4. Renombra a `sentra-<base>-YYYYmmddTHHMMSSZ.dump` y escribe `<archivo>.sha256`.
5. Retención: borra copias más antiguas que `BACKUP_RETENTION_DAYS` (14 por defecto), pero
   **siempre conserva las 3 más recientes** aunque sean viejas (un servidor parado semanas
   no se queda sin copias).

Códigos de salida: 0 correcto, 1 fallo de copia o verificación, 2 falta `BACKUP_DIR`.
Programación: `deploy/systemd/sentra-backup.timer` (Linux) o el Programador de tareas
(Windows). Vigilar el código de salida (systemd marca el servicio como `failed`).

`pg_dump`/`pg_restore` deben ser de la misma versión mayor que el servidor o más nuevos. Si
no están en el `PATH` (habitual en Windows): `PG_BIN_DIR=C:\Program Files\PostgreSQL\18\bin`.

## Verificar una copia

```bash
.venv/bin/python -m app.cli verify-backup /var/backups/sentra/sentra-sentra-20261006T023000Z.dump
```

- el archivo existe y no está vacío;
- el SHA-256 coincide con el `.sha256` (detecta corrupción o manipulación);
- `pg_restore --list` lo lee entero;
- contiene las tablas clave de Sentra (`assets`, `system_events`, `detections`,
  `asset_risk`, `incidents`, `audit_events`, `ai_insights`, `asset_context`, `users`,
  `alembic_version`).

Verificar no es restaurar: la única prueba completa es restaurar (siguiente sección) al
menos una vez al mes en una base de prueba.

## Restaurar

La restauración solo escribe en una base **nueva y vacía**. Nunca sobre la base en uso.

1. Parar la API (`systemctl stop sentra`): `restore` se niega si hay otras conexiones.
2. Un administrador de PostgreSQL crea la base destino (el rol `sentra` no tiene
   `CREATEDB` por mínimo privilegio):

   ```sql
   CREATE DATABASE sentra_restored OWNER sentra ENCODING 'UTF8' TEMPLATE template0;
   ```

3. Restaurar, repitiendo el nombre para confirmar:

   ```bash
   .venv/bin/python -m app.cli restore /var/backups/sentra/<copia>.dump \
       --target-db sentra_restored --confirm sentra_restored
   ```

   Antes de tocar nada verifica la copia (checksum, `--list`, tablas clave) y que la base
   destino existe, está vacía y sin conexiones. `pg_restore --single-transaction
   --exit-on-error`: o se restaura todo o la base queda vacía.

4. Revisión: `restore` imprime la revisión de Alembic y el recuento de las tablas clave. Se
   puede repetir con `python -m app.cli integrity-check --database sentra_restored`.
5. Si el código es más nuevo que la copia: `DATABASE_URL` apuntando a la base restaurada y
   `alembic upgrade head`.
6. Cambiar `DATABASE_URL` a `sentra_restored` (o, como administrador, renombrar bases con la
   API parada) y arrancar. Comprobar `/api/v1/health/ready` y el dashboard.

La base anterior no se borra: se conserva hasta confirmar que la restaurada es correcta.

## Prueba periódica (recomendada mensual)

1. `backup` → `verify-backup`.
2. Crear `sentra_restore_test`, `restore ... --target-db sentra_restore_test --confirm sentra_restore_test`.
3. Comparar los recuentos de `integrity-check` con la base de producción.
4. `DROP DATABASE sentra_restore_test` (administrador).

La batería de QA de la Fase 4M hace exactamente este ciclo en una base temporal
(`docs/DEVELOPMENT_STATUS.md`).
