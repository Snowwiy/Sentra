# Reglas de detección personalizadas (Fase 5A)

Sentra permite crear reglas propias e importar reglas Sigma **sobre el mismo motor de la
Fase 4H** ([detection-engine.md](detection-engine.md)). No hay un segundo motor: las reglas
personalizadas y Sigma se compilan a objetos que el motor evalúa junto a las built-in, con la
misma cola de señales, la misma deduplicación (`uq_detections_active_key`), el mismo cooldown,
las mismas evidencias (máximo 100), las mismas alertas `security_detection` y el mismo
recálculo de riesgo.

## Conceptos

| Concepto | Valores | Significado |
|---|---|---|
| Origen (`source`) | `builtin`, `custom`, `sigma` | Built-in: viven en el código y son de solo lectura. Custom: creadas en la UI/API. Sigma: importadas de un YAML |
| Identificador (`rule_id`) | `AUTH-001`, `SENTRA-CUSTOM-000001`, `SENTRA-SIGMA-000002` | Estable para siempre; el UUID de Sigma se guarda aparte (`sigma_id`) |
| Estado administrativo (`status`) | `draft`, `active`, `disabled`, `retired` | Lo decide un admin. Solo `active` se evalúa |
| Estado de compilación (`compile_status`) | `valid`, `partial`, `unsupported`, `invalid` | Lo decide el compilador. Solo `valid` y `partial` se pueden activar; `partial` exige confirmarlo (`acknowledge_partial`) |
| Versión | 1, 2, 3… | Cada cambio de contenido crea una versión nueva e **inmutable**. Restaurar v1 crea v(n+1) con el contenido de v1 |
| Revisión (`revision`) | entero | Concurrencia optimista: cada cambio la envía; si otro admin cambió la regla, 409 `detection_rule_conflict` |

Las reglas **no se borran**: se retiran (`retire`). Una regla retirada conserva sus versiones y
sus detecciones y se puede recuperar (`unretire`, vuelve desactivada).

Cada detección guarda `rule_id`, `rule_version` (la versión que la **creó**; la última que la
actualizó va en `details.rule_version`), `rule_source` y `rule_category`. Editar una regla
nunca reescribe detecciones antiguas.

## Formato declarativo `sentra-rule/1`

Una regla es **JSON declarativo**, nunca código. El backend lo valida con una allowlist
estricta: claves desconocidas, campos fuera del catálogo u operadores no permitidos se
rechazan (422 `detection_rule_invalid`) y la regla no se guarda.

```json
{
  "format": "sentra-rule/1",
  "logsource": "windows_security",
  "condition": {
    "all": [
      {"field": "event.code", "op": "equals", "value": 4625},
      {"not": {"field": "event.data.TargetUserName", "op": "ends_with", "value": "$"}}
    ]
  },
  "threshold": {"count": 10, "window_minutes": 5},
  "group_by": ["event.data.TargetUserName"],
  "cooldown_minutes": 30
}
```

- `condition`: un nodo `{"all": [...]}` (Y), `{"any": [...]}` (O), `{"not": nodo}` o una hoja
  `{"field", "op", "value", "case_sensitive"?}`.
- `threshold` (opcional): la regla solo detecta cuando hay `count` coincidencias en
  `window_minutes` para el mismo grupo (`group_by`) y el mismo activo. Sin `threshold`, cada
  coincidencia es una detección (deduplicada por grupo).
- `cooldown_minutes` (opcional): como en 4H; por defecto la ventana del umbral o 0.

### Operadores

| Operador | Tipos | Notas |
|---|---|---|
| `equals`, `not_equals` | texto, número, booleano | Texto sin distinguir mayúsculas salvo `case_sensitive: true` |
| `contains`, `starts_with`, `ends_with` | texto | |
| `in` | texto, número | Lista de valores (se guarda como `equals` con lista) |
| `regex` | texto | Subconjunto **seguro** (ver abajo) |
| `exists` | todos | `true`/`false`; es la única forma de pedir que un campo falte |
| `gt`, `gte`, `lt`, `lte` | número | |

Un campo ausente **nunca** coincide (tampoco con `not_equals`): un evento sin el campo no se
convierte en detección por accidente.

### Regex segura

Sin backtracking catastrófico: se rechazan grupos cuantificados (`(a+)+`), lookarounds,
backreferences, cuantificadores posesivos o anidados, más de un cuantificador ilimitado y
repeticiones de más de 32. Patrón máximo 128 caracteres, texto evaluado máximo 512 caracteres
y un modelo de coste que limita el peor caso (medido: ~3 ms). Máximo 4 regex por regla.

### Límites

| Límite | Valor |
|---|---|
| Nodos | 64 |
| Profundidad | 6 |
| Hijos por grupo | 32 |
| Valores por hoja / por regla | 50 / 500 |
| Longitud de un valor | 256 |
| Regex por regla | 4 |
| `group_by` | 3 campos (no del activo) |
| Umbral | 2 – 10 000 |
| Ventana | 1 – 1440 min, y nunca más que la retención de señales |
| Cooldown | 0 – 1440 min |

`GET /detection-rules/catalog` publica estos límites, los logsources, sus campos y operadores.

## Logsources y campos

El catálogo se basa en lo que Sentra **recoge de verdad** (un test compara los campos con lo
que envía el agente). Un campo que el agente no envía no existe en el catálogo: no se puede
escribir una regla que nunca coincidiría.

| Logsource | Soporte | Origen |
|---|---|---|
| `windows_security` | completo | Eventos Security que recoge el agente, con `event.data.*` (TargetUserName, LogonType, IpAddress…) |
| `windows_system` | completo | Warning/error/critical, 104 y 7045 |
| `windows_application` | completo | Solo id, nivel, proveedor y mensaje |
| `powershell` | parcial | Sin texto de script ni mensaje: solo id y nivel |
| `windows_defender` | completo | Amenazas (1116-1119) y protección desactivada (5001/5010/5012) |
| `authentication`, `account`, `service`, `audit`, `antimalware` | completo | Señales normalizadas de 4H |
| `network_exposure`, `discovery` | completo | Puertos nuevos y expuestos, activos descubiertos |
| `process` | parcial | Ejecutables **nuevos** por snapshot; no hay creación de procesos ni línea de comandos |

Todas las reglas pueden añadir campos del activo (`asset.hostname`, `asset.os`,
`asset.criticality`, `asset.role`, `asset.environment`, `asset.network_zone`,
`asset.internet_exposed`, de la Fase 4L) para acotar, pero una regla con **solo** condiciones
del activo se rechaza (`asset_context_only`): no describiría ningún suceso.

No soportado todavía: Sysmon, línea de comandos, ficheros, registro, DNS y red por conexión.

## Cómo se ejecuta

- **Eventos crudos.** Para logsources de eventos, la ingesta registra además una señal
  `event` por evento, pero **solo para canales con reglas activas** (caché de 5 s): sin reglas
  personalizadas, la ingesta no cambia.
- **Índice.** Las reglas activas se indexan por (tipo de señal, canal, id de evento): cada
  señal solo evalúa las reglas que podrían coincidir (fast path).
- **Recarga en caliente.** Cada lote del motor compara una huella de la tabla de reglas
  (número, suma de revisiones, última modificación). Si cambió, recarga. Funciona con varios
  workers sin Redis: la base de datos es la fuente de verdad. Activar o desactivar una regla
  surte efecto en el siguiente lote.
- **Evaluación en memoria.** La condición se evalúa primero en memoria (los campos `asset.*`
  salen de una caché por lote), sin tocar la base de datos. Casi todas las candidatas se
  descartan así; solo una coincidencia escribe (detección, evidencia, umbral).
- **Aislamiento de fallos.** Cada coincidencia se aplica en su propio savepoint: si falla, se registra
  (`detection_rule_stats.errors`, log estructurado sin datos del evento) y el resto sigue. Una
  regla que falla de forma repetida (10 errores seguidos) se señala en la UI y en los logs, pero
  **no se desactiva sola** (un atacante podría provocar errores para apagar reglas).
- **Umbrales.** Las coincidencias de reglas con umbral se guardan en
  `detection_rule_matches` (índice único por regla, versión y señal: reprocesar no cuenta dos
  veces) y se purgan con la retención de señales.
- **Métricas.** `/metrics` expone `sentra_detection_rule_{evaluations,matches,errors}_total` y
  `sentra_detection_rule_evaluation_seconds_total` por **origen** (nunca por regla, para no
  disparar la cardinalidad). El detalle por regla está en `detection_rule_stats` y en la UI.

## Pruebas sin efectos

- **Validar** (`POST /detection-rules/validate`, `rules:test`): compila sin guardar; errores,
  avisos y complejidad.
- **Prueba sintética** (`POST /detection-rules/test`, `rules:test`): hasta 100 eventos escritos
  a mano, evaluados en memoria. No toca la base de datos.
- **Prueba histórica** (`POST /detection-rules/test/historical`, `rules:manage`): ejecuta la
  regla sobre datos guardados (`system_events` para logsources de eventos, `detection_signals`
  para el resto). Garantías: transacción `READ ONLY` (PostgreSQL rechaza cualquier escritura),
  `statement_timeout` (`RULE_TEST_TIMEOUT_SECONDS`, 10), como mucho `RULE_TEST_MAX_ROWS`
  (20 000) filas y `RULE_TEST_MAX_HOURS` (72) horas, **una sola prueba a la vez** en todo el
  despliegue (advisory lock) y `RULE_TEST_PER_MINUTE` (6) por usuario. No crea detecciones,
  alertas ni incidentes, no recalcula riesgo y nunca usa la IA.

Todas las pruebas quedan en la auditoría (`rule_tested`).

## Permisos y auditoría

| Permiso | Roles | Permite |
|---|---|---|
| `rules:read` | viewer, analyst, admin | Listado, detalle, versiones, diff, exportación |
| `rules:test` | analyst, admin | Validar, prueba sintética, vista previa Sigma |
| `rules:manage` | admin | Crear, editar, activar, desactivar, retirar, restaurar, importar Sigma, prueba histórica |

La auditoría de una regla (`GET /detection-rules/{id}/audit`) exige `audit:read`. Acciones:
`rule_created`, `rule_updated`, `rule_version_created`, `rule_enabled`, `rule_disabled`,
`rule_retired`, `rule_unretired`, `rule_imported`, `rule_import_failed`, `rule_tested`. Los
intentos fallidos también quedan (resultado `failure`, con el código de error).

## API

| Método | Ruta | Permiso |
|---|---|---|
| GET | `/detection-rules?source=&status=&enabled=&compile_status=&severity=&logsource=&mitre=&q=&sort=&order=&limit=&offset=` | `rules:read` |
| GET | `/detection-rules/catalog` | `rules:read` |
| GET | `/detection-rules/{id}`, `/versions`, `/versions/{v}`, `/diff?from=&to=`, `/export`, `/sigma-source` | `rules:read` |
| GET | `/detection-rules/{id}/audit` | `audit:read` |
| POST | `/detection-rules/validate`, `/detection-rules/test` | `rules:test` |
| POST | `/detection-rules/test/historical` | `rules:manage` |
| POST | `/detection-rules` | `rules:manage` |
| PATCH | `/detection-rules/{id}` (con `revision`) | `rules:manage` |
| POST | `/detection-rules/{id}/enable`, `/disable`, `/retire`, `/unretire` (con `revision`) | `rules:manage` |
| POST | `/detection-rules/{id}/versions/{v}/restore` (con `revision`) | `rules:manage` |
| POST | `/sigma/preview` | `rules:test` |
| POST | `/sigma/import` | `rules:manage` |

`GET /detection-rules` sigue sirviendo a la UI de 4H (filtro por regla): es un superconjunto
del contrato anterior. Las built-in se gestionan como antes con `DETECTION_DISABLED_RULES`.

## Interfaz

Detecciones → **Reglas**: listado con filtros, orden y paginación en el servidor; detalle con
pestañas Resumen, Lógica, Versiones (diff y restaurar), Detecciones, Pruebas (histórica) y
Auditoría; editor estructurado (campos y operadores del catálogo, umbral, agrupación y modo
avanzado JSON) con validación y prueba sintética; e importación Sigma (pegar o subir, vista
previa, importar). Todo el contenido de las reglas se muestra como texto, nunca como HTML.

## Buenas prácticas

- Empezar con confianza **baja** y subirla cuando la regla demuestre pocos falsos positivos.
- Probar con datos históricos antes de activar.
- Preferir `equals`/`in` y condiciones sobre `event.code` (usan el fast path) a regex.
- Rellenar *por qué importa* y *qué revisar*: es lo que verá el analista.

## Base de datos

Migración `0025`: `detection_rules`, `detection_rule_versions`, `detection_rule_stats`,
`detection_rule_matches`, secuencia `detection_rule_uid_seq` y columnas `rule_source` y
`rule_category` en `detections`. El downgrade a `0024` **elimina las reglas personalizadas**
(sus detecciones se conservan).

## Rendimiento

`qa/perf_custom_rules.py` crea 1000 reglas activas (simples, umbral, regex y contexto del
activo) y 100 000 señales de evento y mide la carga del índice, el coste en la ingesta y el
rendimiento del job. Las reglas buscan usuarios concretos y solo ~1 % de las señales lleva
uno de ellos (tasa de coincidencia realista).

Medido en Linux (contenedor, PostgreSQL 16 local), 1000 reglas activas + 23 built-in:

| Medida | Resultado |
|---|---|
| Carga del índice (cada worker, al cambiar las reglas) | 288 ms |
| Reglas candidatas por señal 4625 | 67 de 1000 (búsqueda 0,6 µs) |
| Ingesta: lote de 50 eventos con registro de eventos crudos | mediana 20 ms, máx. 29 ms |
| Job del motor, 100 000 señales | 66 s (~1500 señales/s), 489 coincidencias, 0 errores |
| Evaluación de una candidata que no coincide | ~20 µs |
| Regla con contexto del activo (`asset.*`) | ~580 µs de media |

Cada coincidencia cuesta varios milisegundos (detección, evidencia, alerta, umbral). Con
reglas poco selectivas que coinciden con la mayoría de los eventos el rendimiento cae a
decenas o cientos de señales/s: conviene ver en la prueba histórica cuántas coincidencias
daría una regla antes de activarla.
