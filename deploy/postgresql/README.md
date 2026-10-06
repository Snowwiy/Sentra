# PostgreSQL para Sentra en producción (Fase 4M)

PostgreSQL es un servicio del sistema operativo, independiente de Sentra: Sentra nunca lo
arranca, lo para ni lo administra. Versión de referencia: PostgreSQL 18 (mínimo 16, por
`pg_input_is_valid`). Los clientes `pg_dump`/`pg_restore` deben ser de la misma versión
mayor que el servidor o más nuevos.

## 1. Rol y base dedicados (mínimo privilegio)

Como superusuario de PostgreSQL (una sola vez, por un administrador; Sentra nunca usa el
superusuario en ejecución):

```sql
-- Contraseña generada con: python -m app.cli generate-secret
CREATE ROLE sentra LOGIN PASSWORD '...' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION;
CREATE DATABASE sentra OWNER sentra ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE sentra FROM PUBLIC;
\c sentra
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO sentra;
```

- El rol es dueño de su base: Alembic crea y modifica tablas sin privilegios globales.
- `NOCREATEDB`: para restaurar, un administrador crea antes la base destino vacía
  (`docs/backup-restore.md`).
- `production-check` marca FAIL si la aplicación conecta como superusuario.

## 2. Escucha y acceso (`postgresql.conf`, `pg_hba.conf`)

Mismo servidor que la API (recomendado):

```conf
# postgresql.conf
listen_addresses = 'localhost'      # nunca '*' si la API está en la misma máquina
port = 5432                         # en el PC de desarrollo de Jesús: 5433
password_encryption = scram-sha-256
```

```conf
# pg_hba.conf: solo el rol sentra, solo a su base, solo por loopback y con SCRAM.
# TYPE  DATABASE  USER    ADDRESS        METHOD
host    sentra    sentra  127.0.0.1/32   scram-sha-256
host    sentra    sentra  ::1/128        scram-sha-256
# Sin líneas "all all 0.0.0.0/0". El superusuario, solo por socket local (peer) en Linux.
```

Base en otro servidor: `listen_addresses` con la IP interna concreta, `pg_hba` solo para la
IP del servidor de Sentra con `hostssl`, y en `DATABASE_URL` `?sslmode=verify-full` (o
`require` como mínimo). El cortafuegos solo deja el 5432 desde el servidor de Sentra.

## 3. Conexiones y tiempos

Cada worker de la API abre como máximo `DB_POOL_SIZE + DB_MAX_OVERFLOW` conexiones (10 + 10
por defecto), más una breve por job y por copia de seguridad. Con N workers:
`max_connections >= N x 20 + 10` (el valor por defecto, 100, sobra para 1-3 workers).

Recomendado en `sentra.env`:

```
DB_STATEMENT_TIMEOUT_SECONDS=30     # cancela consultas desbocadas de la API
DB_POOL_TIMEOUT_SECONDS=10          # sin conexión libre en 10 s -> 503 reintentable
```

El `statement_timeout` solo se aplica al pool de la API; las migraciones y las copias no lo
tienen. Opcional en el servidor: `idle_in_transaction_session_timeout = '5min'`.

## 4. Copias

`python -m app.cli backup` (programado con `deploy/systemd/sentra-backup.timer` o con el
Programador de tareas en Windows). Detalle y restauración: `docs/backup-restore.md`.
