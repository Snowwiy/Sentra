# Fase 6E: migraciones 0039-0043

Base: `origin/main` e7a3ee6 (migraciones hasta 0038). Las cinco migraciones son aditivas: crean
tablas y columnas nuevas, no transforman datos existentes y no tocan ningún activo.

| Rev. | Fichero | Contenido | Downgrade |
|---|---|---|---|
| 0039 | `20261022_0039_topology_history.py` | `topology_snapshots`, `network_changes`; `topology_links.absent_builds/absent_since/removed_at` | Pierde el historial (snapshots y cambios). Enlaces y revisión de 6D se conservan. |
| 0040 | `20261022_0040_dhcp_identity.py` | `dhcp_sources`, `dhcp_leases`, `asset_identity_history` | Pierde fuentes, leases e historial de identidad. La clave `dhcp_lease` que quede en `identity_observations` la ignora el código anterior. |
| 0041 | `20261022_0041_endpoint_telemetry.py` | `endpoint_activity`, `process_instances`, `detection_exclusions`; `assets.telemetry_status/_at` | Pierde actividad, árbol de procesos y excepciones (quedan en la auditoría). |
| 0042 | `20261022_0042_forensics.py` | `investigations`, `forensic_artifacts`, `investigation_notes`, `evidence_packages`; `response_executions.investigation_id` | Pierde la evidencia forense. Exportar antes los paquetes necesarios. |
| 0043 | `20261022_0043_isolation.py` | `isolation_sessions`; `assets.isolation_status/_at`; valor `isolation_state` en el enum `alert_rule` | Levantar antes cualquier aislamiento vivo. Borra la tabla, las columnas y las alertas `isolation_state`; el valor del enum queda (inocuo). |

Siguiente migración libre: 0044.

## Aplicar

```powershell
cd backend
.venv\Scripts\python.exe -m alembic current          # debe decir 0038
.venv\Scripts\python.exe -m alembic upgrade head     # 0039 → 0043
.venv\Scripts\python.exe -m alembic current          # 0043 (head)
```

Antes: copia de seguridad de la base real (procedimiento de `deploy/postgresql/README.md`). Probar
primero sobre `sentra_test` o una copia.

## Comprobado en la nube

- `tests/test_migrations.py`: downgrade a base y upgrade a head, modelos iguales al esquema
  migrado (`compare_metadata`), toda FK con índice, una sola cabeza.
- La suite completa del backend corre cada sesión sobre una base migrada desde cero.

## Coste esperado

Todas las tablas nacen vacías y las columnas nuevas de `assets` y `response_executions` son
nullables sin valor por defecto: en PostgreSQL 11+ añadirlas no reescribe la tabla. El índice
parcial `ix_response_executions_investigation` se crea sobre filas existentes con
`investigation_id` NULL, así que no indexa nada al migrar.
