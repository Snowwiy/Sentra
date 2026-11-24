# Fase 7E: migraciones

Cuatro migraciones nuevas sobre la cabeza 0052 (Fase 7D.2). Siguiente libre: 0057.

| Revisión | Fichero | Subfase | Cambios |
| --- | --- | --- | --- |
| 0053 | `20261124_0053_7e1_ndr_observation.py` | 7E.1 | Tablas `ndr_capture_configs`, `ndr_batches`, `ndr_flows`, `ndr_protocol_observations` con sus índices |
| 0054 | `20261124_0054_7e2_ndr_anomalies.py` | 7E.2 | Tablas `ndr_anomalies` (índice único parcial sobre las activas) y `ndr_ip_mac_bindings` |
| 0055 | `20261124_0055_7e3_ndr_baselines.py` | 7E.3 | Tablas `ndr_baselines` y `ndr_engine_cursors` |
| 0056 | `20261124_0056_7e4_ndr_correlation.py` | 7E.4 | `ndr_anomalies.asset_id` (FK a `assets`, `ON DELETE SET NULL`, con índice) y `ndr_anomalies.signaled_rank` |

7E.5, 7E.6 y 7E.7 no tienen migración: los logsources, el mapeo MITRE, la acción de
respuesta y el playbook integrado viven en código (el playbook se sincroniza con la tabla
`playbooks` al leer el catálogo, como los de la Fase 5D).

Toda clave foránea nueva lleva índice (lo comprueba `tests/test_migrations.py`). Ninguna
migración modifica ni borra datos de tablas anteriores.

## Aplicar

```powershell
cd backend
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m alembic current   # 0056 (head)
```

Probar antes en una base de pruebas propia, nunca en `sentra`.

## Volver atrás

```powershell
.venv\Scripts\python.exe -m alembic downgrade 0052
```

El downgrade elimina las tablas NDR y con ellas los flujos, metadatos, anomalías, líneas base
y configuraciones de captura. Las detecciones NET-NDR-001 ya creadas, las solicitudes de
control registradas en incidentes y las ejecuciones del playbook se conservan porque viven en
tablas de fases anteriores. Antes de bajar:

1. Desaprobar la captura de cada sensor (o parar los sensores 0.8.0) para que no lleguen
   lotes a rutas sin tablas.
2. Hacer copia de seguridad (`docs/backup-restore.md`).
3. Volver al código de la versión anterior: el código 0.8.0 con la base en 0052 falla al
   arrancar por esquema atrasado, como en cualquier fase.

Bajar solo hasta 0055 (deshacer 7E.4) quita la atribución a activos y `signaled_rank`; una
subida posterior vuelve a crear las columnas vacías y las anomalías activas volverían a
señalizar su veredicto actual una vez.
