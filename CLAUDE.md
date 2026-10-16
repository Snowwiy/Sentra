# Sentra: guía para Claude

Plataforma de monitorización de activos y eventos de seguridad en tiempo real que crece hacia
un SOC empresarial. El estado completo de cada fase, decisiones y limitaciones está en
`docs/DEVELOPMENT_STATUS.md`: léelo antes de empezar una fase.

## Reglas fijas (las decide Jesus)

- Git: Claude no hace commit, push, merge, rebase, tag ni PR; no toca ramas remotas, remotes,
  identidad ni credenciales Git, y no escribe en GitHub. Sin líneas `Co-Authored-By` ni
  atribuciones a Claude, Anthropic o bots. Jesus aplica y publica todo a mano.
- Entrega: parche incremental sobre el commit base que indique Jesus (variantes LF y CRLF; en
  la CRLF solo se convierten las líneas de contenido de los hunks), comprobado con
  `git apply --check` en un checkout limpio, más HANDOFF, MANIFEST, TEST-RESULTS,
  REVIEW_BEFORE_PUSH y SHA256SUMS. Nunca incluir `.env`, secretos, venvs, `node_modules`,
  `dist` ni cachés.
- Idioma: comentarios, docstrings y documentación nuevos en español; identificadores,
  endpoints, JSON y códigos de error en inglés. Sin emojis. Los comentarios explican el porqué.
- Cada tarea termina con un bloque REVIEW BEFORE PUSH.
- Nunca afirmar que un test pasa sin haberlo ejecutado.
- Base de datos: los tests y migraciones solo contra `sentra_test` o una base de pruebas
  propia; nunca contra la base real. No teclear la contraseña del superusuario `postgres`.
- Pedir permiso a Jesus antes de: cambios de arquitectura fundamentales, acciones destructivas,
  diseño de seguridad crítico (auth, claves, certificados, privilegios, ejecución remota,
  autoactualización, acciones automáticas sobre activos), dependencias de pago o decisiones de
  producto difíciles de revertir (multi-tenancy, licencias, SaaS, protocolo final del agente,
  auth empresarial). Las decisiones técnicas reversibles se toman sin preguntar.

## Stack

- Desarrollo nativo en Windows, sin Docker ni Redis.
- `backend/`: Python, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 18 (puerto 5433), Pydantic v2,
  pytest. Capas: `api` (routers finos) → `services` → `models`; `schemas` son los contratos.
- `agent/`: agente de host (Windows primero, Linux con systemd).
- `sensor/`: sensor distribuido, solo biblioteca estándar salvo el extra opcional `snmp`
  (pysnmp + cryptography).
- `frontend/`: React + TypeScript + Vite, vitest.
- `scripts/` (PowerShell), `deploy/` (plantillas de producción), `qa/` (e2e y rendimiento).

## Convenciones que evitan fallos conocidos

- Migraciones: la siguiente libre es la que sigue a la última en `backend/alembic/versions/`.
  Toda clave foránea lleva índice (lo comprueba `test_migrations`).
- Todo ajuste nuevo opcional se fija en `backend/tests/conftest.py`: los tests no pueden
  depender del `.env` de desarrollo. Un test con `Settings(_env_file=...)` fija también
  `DATABASE_URL`.
- Windows: los symlinks fallan con WinError 1314 (usar junctions en los tests); comprobar los
  tipos del sensor y del agente con `mypy --platform win32`; no calcular horas relativas al
  recoger los tests (parametrize o nivel de módulo), sino dentro del test; un 202 de un job
  puede llegar ya en `running`.
- Frontend: probar también con Node 24 (`npx -y node@24 ...`); con jsdom, leer blobs con
  FileReader si falta `arrayBuffer()`.

## Comprobaciones antes de entregar

```powershell
cd backend;  .venv\Scripts\python.exe -m pytest; ruff check .; ruff format --check .; mypy app
cd sensor;   .venv\Scripts\python.exe -m pytest; ruff check .; mypy .; mypy --platform win32 .
cd agent;    .venv\Scripts\python.exe -m pytest; ruff check .; mypy .
cd frontend; npm test; npm run typecheck; npm run lint; npm run build
```
