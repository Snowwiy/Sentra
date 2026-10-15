# Reporting y exportación de evidencias (Fase 5E)

Sentra genera informes de seguridad reproducibles y auditables a partir de sus propios datos:
activos, riesgo, detecciones, alertas, incidentes, vulnerabilidades, inteligencia de
amenazas, Response y ciclo de vida. Todo se genera en el servidor, sin Internet y sin IA.

Ver también [report-security.md](report-security.md) (RBAC, redacción, contenido seguro) y
[report-storage.md](report-storage.md) (dónde se guardan los ficheros, retención, copias).

## Tipos de informe

Catálogo cerrado definido en código (`backend/app/reports/catalog.py`). No hay plantillas,
consultas ni tipos definidos por el usuario.

| id | Nombre | Formatos | Filtros | Generar |
|---|---|---|---|---|
| `executive_summary` | Resumen ejecutivo de seguridad | html, pdf | include_archived | admin |
| `technical` | Informe técnico de seguridad | html, pdf, evidence | activos, incidentes, severidades, plataformas, include_archived | analyst con activos o incidentes; global solo admin |
| `incident` | Informe de incidente | html, pdf, evidence | exactamente 1 incidente | analyst |
| `asset` | Informe de seguridad del activo | html, pdf, evidence | exactamente 1 activo, include_archived | analyst |
| `vulnerability` | Informe de vulnerabilidades | html, pdf, csv | activos, severidades, estados, plataformas, include_archived | analyst |
| `risk` | Informe de riesgo | html, pdf | activos, niveles de riesgo, plataformas, include_archived | analyst |
| `detection` | Informe de detecciones | html, pdf, csv, evidence | activos, detecciones, severidades, estados, plataformas, include_archived | analyst |
| `response_activity` | Actividad de Response | html, pdf, csv, evidence | activos, ejecuciones, playbooks, estados, include_archived | analyst |
| `lifecycle_change` | Ciclo de vida y cambios | html, pdf, csv | activos, plataformas, include_archived | analyst |

Cada tipo lleva `template_version` (hoy 1). Cambiar lo que muestra una plantilla obliga a
subirla; los informes ya generados conservan la versión con que se hicieron.

El resumen ejecutivo omite IDs, direcciones IP y evidencia técnica: solo cifras agregadas,
estado general, hallazgos principales y frases deterministas.

## Formatos

- **HTML**: documento autocontenido (CSS en línea, gráficos SVG en línea), sin scripts, sin
  recursos externos y con CSP `default-src 'none'`. Se puede abrir sin conexión.
- **PDF**: generado por un escritor PDF propio (`app/reports/render_pdf.py`), sin
  dependencias nuevas, sin navegador y sin Internet. Fuentes estándar Helvetica (WinAnsi),
  tablas con cabecera repetida en cada página, gráficos de barras vectoriales, cabecera con
  clasificación y pie con "Página X de Y". Sin enlaces, JavaScript ni ficheros incrustados.
- **CSV**: la tabla principal del tipo (`csv_table`), columnas fijas, UTF-8 con BOM (Excel
  abre bien los acentos) y fórmulas neutralizadas.
- **evidence** (ZIP): `manifest.json` (formato `sentra-evidence-bundle/1`, SHA-256 y tamaño
  de cada fichero, SHA-256 del snapshot), `report.html`, `report.pdf`, `snapshot.json` y
  `tables/*.csv`. Nombres fijos, sin rutas del cliente, fechas internas = hora de corte.

Sin DOCX: no aporta nada que el PDF/HTML no cubran y exigiría otra dependencia.

## Snapshot y reproducibilidad

1. La petición se valida y se guarda como trabajo `pending` (la petición HTTP no espera).
2. El worker lee todos los datos en **una sola transacción `REPEATABLE READ` de solo
   lectura**: todas las secciones ven la misma foto de la base de datos. `now()` de esa
   transacción es la **hora de corte** ("Datos a fecha de").
3. Los datos se guardan como snapshot JSON (en `reports.snapshot`) con su SHA-256
   (`snapshot_sha256`). El documento se renderiza **solo desde el snapshot**: re-renderizar
   el mismo snapshot produce exactamente los mismos bytes (probado en los tests).
4. El fichero se escribe de forma atómica y se registra su SHA-256 y tamaño.

Cambiar datos después no cambia un informe ya generado. Un informe nuevo con los mismos
filtros sí refleja los cambios.

Cada informe muestra: id, tipo, versión de plantilla, quién lo pidió, cuándo, hora de
generación, hora de corte, período, zona horaria (UTC), filtros, clasificación y alcance.

**Zona horaria**: todas las horas se muestran en UTC. Windows no trae la base de datos
tzdata de Python, y una zona local distinta según el servidor haría los informes menos
reproducibles.

## Trabajos

Estados: `pending` → `running` → `succeeded` | `failed` | `cancelled`; `expired` cuando se
borra el artefacto (a mano o por retención).

- **Idempotencia**: `idempotency_key` por diálogo; repetirla devuelve el mismo informe
  (`deduplicated: true`). Además, una petición idéntica del mismo usuario mientras la
  anterior sigue viva devuelve la viva (índice único parcial sobre `request_hash`).
- **Colas**: `REPORT_MAX_CONCURRENT` vivos por usuario y `REPORT_MAX_QUEUED_TOTAL` en total;
  al superarlos responde 429 `report_queue_full` con `Retry-After`.
- **Worker**: job `report-worker` cada `REPORT_WORKER_INTERVAL_SECONDS`, con advisory lock
  (una sola ejecución en todo el despliegue) y `FOR UPDATE SKIP LOCKED` al tomar trabajos.
- **Plazo**: `REPORT_JOB_TIMEOUT_SECONDS`; se comprueba entre secciones.
- **Huérfanos**: cada trabajo `running` tiene `lease_until`; si el proceso muere, la
  siguiente vuelta lo cierra como `failed` (`report_interrupted`).
- **Cancelar**: `pending` pasa a `cancelled` al momento; `running` se marca y el worker se
  detiene. La finalización toma un lock de fila: un trabajo cancelado nunca termina
  `succeeded` y el fichero ya escrito se borra.
- **Fallos**: `failed` con código y mensaje genéricos (sin trazas ni datos internos).

## Límites

| Variable | Defecto | Efecto |
|---|---|---|
| `REPORT_ENABLED` | `true` | Apagado: el catálogo dice `enabled=false` y generar responde 409 |
| `REPORT_OUTPUT_DIR` | sin valor | Ver report-storage.md |
| `REPORT_MAX_RANGE_DAYS` | 365 | Rango máximo del período |
| `REPORT_MAX_ASSETS` | 100 | Máximo de ids por filtro |
| `REPORT_MAX_ROWS` | 500 | Filas por tabla (el resto se cuenta y se avisa) |
| `REPORT_RETENTION_DAYS` | sin valor | Sin valor: se conserva todo |
| `REPORT_JOB_TIMEOUT_SECONDS` | 300 | Plazo de una generación |
| `REPORT_MAX_CONCURRENT` | 3 | Informes vivos por usuario |
| `REPORT_MAX_QUEUED_TOTAL` | 20 | Informes vivos en total |
| `REPORT_MAX_ARTIFACT_MB` | 25 | Tamaño máximo del fichero |
| `REPORT_WORKER_INTERVAL_SECONDS` | 5 | Frecuencia del worker |

El snapshot guardado tiene además un tope fijo de 16 MB.

## API (`/api/v1/reports`)

| Método y ruta | Permiso | Descripción |
|---|---|---|
| `GET /catalog` | reports:read | Tipos visibles para el rol, formatos, filtros y límites |
| `POST /preview` | reports:generate | Valida y estima el alcance; no crea nada |
| `POST /` | reports:generate | Crea el trabajo (202) |
| `GET /` | reports:read | Historial (`report_type`, `status`, `requested_by`, `created_from`, `created_to`, `limit`, `offset`) |
| `GET /{id}` | reports:read | Detalle |
| `GET /{id}/artifact` | reports:read | Descarga (adjunto, cabecera `X-Sentra-SHA256`) |
| `POST /{id}/cancel` | reports:generate | Propios; ajenos con reports:admin |
| `DELETE /{id}` | reports:admin | Borra el fichero y deja la fila `expired` como rastro |

Errores de validación (422): `report_type_unknown`, `report_format_unsupported`,
`report_filter_not_supported`, `report_filter_required`, `report_filter_invalid`,
`report_range_invalid`, `report_range_too_large`, `report_scope_too_large`,
`report_asset_archived`, `report_target_not_found`. 409: `reports_disabled`,
`report_conflict`, `report_invalid_state`, `report_not_ready`, `report_integrity_failed`.
410: `report_artifact_unavailable`. 429: `report_queue_full`.

## Resumen determinista

`app/reports/summary.py`: frases fijas en español construidas solo con cifras del snapshot
("3 activos presentan nivel de riesgo crítico.", "Ningún activo presenta…"). Mismos datos,
mismas frases. La IA (Fase 4J) no interviene en ningún informe.

## Analyst Console

`app/reports/tools.py`: registro cerrado `reports.catalog`, `reports.preview`,
`reports.generate`, `reports.status`, `reports.list` y `reports.download_metadata`, sobre el
mismo `ReportService` (misma validación, RBAC y auditoría). `download_metadata` devuelve
nombre, tamaño, SHA-256 y la ruta relativa de la API, nunca el contenido ni rutas del disco.

## UI

Menú **Informes**: catálogo, rango (24 h, 7 d, 30 d, 90 d o personalizado), filtros,
formato, clasificación, vista previa, generar, historial, detalle, descarga (verifica el
SHA-256 en el navegador) y checksum. Botones "Generar informe" en Incidente, Activo,
Detección y Response. La UI nunca renderiza el HTML de un informe dentro de la aplicación.
