# Fase 7F: migraciones

Tres migraciones nuevas sobre la cabeza 0056 (Fase 7E). Siguiente libre: 0060.

| Revisión | Fichero | Subfase | Cambios |
| --- | --- | --- | --- |
| 0057 | `20261124_0057_7f1_siem_ingest.py` | 7F.1 | Tablas `siem_sources`, `siem_batches`, `siem_events` con sus índices |
| 0058 | `20261124_0058_7f3_siem_event_links.py` | 7F.3 | Tabla `siem_event_links` (sin FK al destino; se borra con su evento) |
| 0059 | `20261124_0059_7f6_siem_hunting.py` | 7F.6 | Tablas `siem_saved_searches` e `incident_siem_events`; índice parcial `ix_siem_events_site_username` |

7F.2, 7F.4, 7F.5 y 7F.7 no tienen migración. Toda clave foránea nueva lleva índice (lo
comprueba `tests/test_migrations.py`). Ninguna migración modifica ni borra datos existentes.

## Aplicar

Siempre primero en una base de pruebas propia, nunca en `sentra` ni en una base con datos que
deban conservarse:

```powershell
cd backend
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m alembic current   # 0059 (head)
```

El paquete de entrega no ejecuta migraciones (INSTALL.ps1 solo comprueba y aplica parches).

## Volver atrás

```powershell
.venv\Scripts\python.exe -m alembic downgrade 0056
```

| Bajar | Se pierde |
| --- | --- |
| 0059 → 0058 | Búsquedas guardadas y copias de eventos SIEM añadidas a casos (la actividad del caso queda) |
| 0058 → 0057 | Correlaciones calculadas (los eventos se conservan) |
| 0057 → 0056 | Fuentes, lotes y eventos SIEM |

Antes de bajar en una base con datos, hacer copia (docs/backup-restore.md). El código 0.9.0
necesita la cabeza 0059: bajar la base implica volver también al código 0.8.0.

## Comprobado en la nube

En PostgreSQL 16 (base desechable): `upgrade head`, `downgrade 0056` y de nuevo `upgrade head`,
más `tests/test_migrations.py`. No se ha probado en PostgreSQL 18 de Windows.
