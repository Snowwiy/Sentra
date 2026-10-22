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

Cada tipo lleva `template_version` (hoy 2, ver "Plantilla v2"). Cambiar lo que muestra una
plantilla obliga a subirla; los informes ya generados conservan la versión con que se hicieron.

El resumen ejecutivo omite IDs, direcciones IP y evidencia técnica: solo cifras agregadas,
estado general, hallazgos principales y frases deterministas.

## Plantilla v2 (Fase 6D.5)

Los informes nuevos se generan con la plantilla **v2**; los v1 ya generados no cambian.

**Cómo se versiona.** La versión vive donde ya vivía: la columna `reports.template_version`
y `snapshot.meta.template_version` (sin migración). El catálogo fija la de los informes
nuevos (`TEMPLATE_VERSION = 2` en `app/reports/catalog.py`) y `render_document` elige la
plantilla por la versión **del snapshot**, nunca por la del catálogo: un snapshot v1 guardado
se vuelve a renderizar con la plantilla y los renderers v1 y produce los mismos bytes que
antes (lo comprueban `tests/test_reports_v2.py` con hashes obtenidos del código anterior).
La petición no elige plantilla: no hay forma de pedir hoy un informe nuevo en v1.

**Datos adicionales.** Con v2 el snapshot lleva además `extended`, construido por
`app/reports/builders_v2.py` en la **misma** transacción REPEATABLE READ y con la misma hora
de corte. Las gráficas salen solo del snapshot: el render nunca consulta la base de datos.

| Gráfica | Tipos | Origen en el snapshot |
|---|---|---|
| Evolución del riesgo por activo (líneas, 0-100) | ejecutivo, técnico, riesgo, activo | `extended.risk_history` (snapshots del Risk Engine y último valor anterior al periodo) / `data.risk.history` |
| Detecciones por severidad y estado (apiladas) | técnico, activo, detecciones | `extended.detection_matrix` |
| Aportes al Risk Engine por categoría y por regla | técnico, riesgo, activo | `extended.risk_contributions` (suma de `asset_risk.contributions` vigentes) / `data.risk.contributions` |
| Tendencia diaria (semanal en rangos > 92 días) de eventos y detecciones | ejecutivo, técnico, activo, detecciones | `extended.activity` (cubos con ceros) |
| Comparativa de activos por criticidad y nivel | ejecutivo, técnico, riesgo | `extended.criticality` |
| Vulnerabilidades por severidad y evidencia, y exposición (puertos) | ejecutivo, técnico, activo, vulnerabilidades | datos v1 + `extended.exposure` |
| Topología verificada (diagrama estático) | técnico, activo | `extended.topology` (`app.topology.service.report_topology`) |
| Tendencias de Response y de activos nuevos, actividad del incidente | Response, ciclo de vida, incidente | `extended.executions`, `extended.new_assets`, filas del snapshot |

**Estructura del documento.** Portada técnica con identidad SENTRA (vectorial, sin
imágenes), índice con número de página, resumen ejecutivo con indicadores y hora de corte,
hallazgos prioritarios, metodología y alcance, análisis gráfico, secciones de detalle (las
tablas de v1 con estados legibles), topología verificada, trazabilidad del cálculo de riesgo
(si el Risk Engine guardó `breakdown.trace` y `details.nominal_breakdown`; si no, la sección no
aparece), evidencias y referencias, recomendaciones (cada una nombra el dato que la motiva),
conclusiones y anexo técnico (metadatos, versiones, tablas truncadas, serie temporal y
glosario). Todas las frases son deterministas y salen de cifras del snapshot.

**Estados de los datos.** Se distinguen siempre: `0` (medido y cero), "Sin datos en el
periodo" (la fuente existe pero no hay registros), "No medido" con el motivo (p. ej. eventos
sin ningún agente en el alcance, exposición de activos sin escaneo de puertos), "Desconocido"
y "Sin calcular" (activo aún no puntuado por el Risk Engine). Una serie no medida nunca se
dibuja como ceros.

**Gráficas.** Vectoriales y deterministas: SVG en línea en HTML y operadores vectoriales en
PDF, con título, unidad, ejes con marcas (enteras para recuentos), valores, leyenda y notas.
Como máximo 15 categorías por gráfica (las de más valor) y "Y N categorías más"; los valores
no finitos o negativos no se dibujan; los enormes se compactan (M, mil M, B).

**Topología.** Solo enlaces presentes, no rechazados y de clase física, lógica u observada
entre nodos del resultado; los candidatos y desconocidos no se dibujan y nunca se infiere un
enlace. La disposición se calcula al construir el documento: raíz = router/firewall (o la
infraestructura con más enlaces), capas por distancia, orden por baricentro y etiqueta, capas
anchas plegadas en filas de 8. Sin relaciones verificadas, una nota explícita. Si el motor de
topología no está disponible o falla, la sección lo dice y el informe se genera igualmente
(la llamada va en un SAVEPOINT). Tope de 60 nodos y 3 sites; debajo del diagrama, la tabla
completa de enlaces.

**Paginación del PDF v2.** Secciones principales en página nueva, títulos que se mantienen
con su primer bloque, gráficas que no se parten, tablas con la cabecera repetida en cada
página y el rótulo "(continuación)", filas que nunca se cortan entre páginas (las celdas muy
largas se acotan a 10 líneas con "…"; el HTML y el CSV conservan el texto completo) y
"Página X de Y" en todas las páginas.

**Caracteres en el PDF.** Sin fuentes incrustadas (licencia, tamaño y determinismo): se
mantienen Helvetica con WinAnsiEncoding (cp1252: español, €, comillas tipográficas, rayas,
viñetas). `app/reports/charset.py` translitera de forma determinista los símbolos frecuentes
(→ `->`, ≥ `>=`, ≤ `<=`, ≠ `!=`, ✓ `[OK]`, ✗ `[X]`, espacios especiales, guiones Unicode,
comillas angulares, superíndices `^n`, letras con diacríticos fuera de cp1252 vía NFKD) y lo
que siga sin representación se escribe como `[U+XXXX]` (nunca "?"). Limitación: el texto en
otras escrituras (cirílico, CJK, árabe…) y los emojis aparecen en el PDF como marcadores; el
HTML conserva siempre el Unicode completo. Solo v2: v1 conserva su "?".

## Formatos

- **HTML**: documento autocontenido (CSS en línea, gráficos SVG en línea), sin scripts, sin
  recursos externos y con CSP `default-src 'none'`. Se puede abrir sin conexión.
- **PDF**: generado por un escritor PDF propio (`app/reports/render_pdf.py`; v2 en
  `app/reports/render_pdf_v2.py`), sin
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

Errores de descarga (Fase 6D.6): el aviso «No se pudo conectar con la API de Sentra» indica que
la API no respondía en ese instante (normalmente un reinicio de uvicorn `--reload` o un 502 del
proxy), no que el informe falte. Diagnóstico, reproducción y la tabla de mensajes separados en
[report-download-errors.md](report-download-errors.md).
