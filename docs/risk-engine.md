# Risk Engine (Fase 4I)

El Risk Engine resume en un número de 0 a 100 cuánto riesgo tiene cada activo **ahora**, a
partir de lo que Sentra ya sabe de él: las detecciones del motor 4H, la exposición de red que
ve discovery, la criticidad que le asigna un admin y su tipo. Es determinista, explicable y
auditable: el mismo estado da siempre el mismo score, cada punto tiene un origen visible y
cada cambio relevante queda en un historial. No hay IA ni servicios externos.

Lo que **no** es: un escáner de vulnerabilidades, una probabilidad de compromiso ni una
sustitución del criterio del analista. Un 85 significa "hay evidencia reciente y fuerte de
actividad peligrosa en un activo importante"; no significa "85 % de probabilidad".

## Qué se guarda por activo

| Campo | Significado |
|-------|-------------|
| `score` (0-100) | Valor del riesgo, redondeado |
| `level` | `informational`, `low`, `medium`, `high`, `critical` (por umbrales) |
| `confidence` | `low`, `medium`, `high`: cuánto fiarse del score. **Separada** del score |
| `calculated_at` / `changed_at` | Último cálculo / último cambio material (punto del historial) |
| `top_factor` | La contribución que más suma |
| `contributions` | Ledger de contribuciones (suma el score antes de redondear) |
| `breakdown` | Desglose numérico: puntos base, factores, reducciones, cobertura de datos |

Tablas (migración `0019`): `asset_risk` (estado actual, una fila por activo; también la cola
de recálculo `dirty_at`), `risk_snapshots` (historial) y `risk_contributions` (contribuciones
de cada snapshot, normalizadas y enlazadas a la detección con `ON DELETE SET NULL`).
`assets.criticality` es nueva y vale `medium` por defecto.

## Niveles

| Nivel | Rango por defecto |
|-------|-------------------|
| Informativo | 0-19 |
| Bajo | 20-39 |
| Medio | 40-59 |
| Alto | 60-79 |
| Crítico | 80-100 |

Los límites están en un solo sitio: `RISK_LEVEL_THRESHOLDS="20,40,60,80"` (inicio de bajo,
medio, alto y crítico; deben ser crecientes entre 1 y 100). La API devuelve los rangos
(`thresholds`) y el frontend los usa tal cual; nunca los duplica.

## Fórmula (versión 1)

Toda la aritmética está en `backend/app/risk/calculator.py` (función pura, sin base de datos
ni reloj) y los pesos en `backend/app/risk/config.py`.

### 1. Fuerza de cada detección

```
nominal = puntos_severidad × factor_confianza × factor_ocurrencias × factor_correlación
efectiva = nominal × factor_estado × factor_antigüedad
```

| Severidad | Puntos | | Confianza | Factor | | Estado | Factor |
|-----------|-------:|-|-----------|-------:|-|--------|-------:|
| informational | 3 | | low | 0,55 | | open | 1 |
| low | 12 | | medium | 0,8 | | acknowledged | 0,85 |
| medium | 35 | | high | 1,0 | | resolved | 0,5 × decay |
| high | 70 | | | | | | |
| critical | 90 | | | | | | |

- **Calibración**: una sola detección reciente y abierta cae en su propio nivel. high/high =
  70 (alto); critical/high ≈ 85 tras la saturación (crítico); una medium nunca llega sola a
  medio-alto. Una crítica con confianza baja (90 × 0,55 = 49,5) no llega sola a crítico.
- **Ocurrencias (persistencia)**: `min(1,35, 1 + 0,12 × log2 n)`. Crece despacio y está
  acotado: 1 → ×1, 2 → ×1,12, 8 → ×1,36 (tope 1,35). Las ocurrencias de 4H ya son oleadas
  separadas por el cooldown de la regla, no eventos sueltos.
- **Correlación**: ×1,15. Una correlación une varias señales independientes.
- **Reconocida no es mitigada**: solo baja un 15 %. Alguien la está mirando, pero el riesgo
  sigue ahí.
- **Antigüedad** (desde `last_seen_at` de la detección): `0,5^(edad / 24 h)`, con suelo de
  0,25 mientras no esté resuelta: una detección abierta nunca "desaparece" por vieja.
- **Resueltas**: memoria que decae. `0,5 × 0,5^(desde_resolución / 12 h)` multiplicado por
  la antigüedad; pasadas 72 h ya no cuentan. Resolver baja el riesgo enseguida a la mitad
  pero no lo borra: lo que acaba de pasar sigue siendo relevante unas horas.

### 2. Exposición (solo puertos sensibles abiertos vistos por discovery)

| Puertos | Puntos |
|---------|-------:|
| Administración remota: 22, 3389, 5900, 5985, 5986 | 10 |
| Telnet (23, administración en claro) | 12 |
| Datos o compartición (resto de `SENSITIVE_PORTS`: SMB, bases de datos…) | 7 |

Un puerto abierto hace menos de 24 h (`RISK_EXPOSURE_RECENT_HOURS`) pesa ×1,3. Un puerto no
sensible no suma nada: estar abierto no demuestra ninguna vulnerabilidad. La confianza de la
exposición es alta (0,85) porque Sentra la observa directamente.

### 3. Sin doble conteo (agrupación)

Antes de sumar, las contribuciones se agrupan (union-find, raíz determinista):

- Una **correlación** y las detecciones simples cuya evidencia comparte señales con ella
  (mismo `signal_id`) forman un grupo. Ejemplo: CORR-001 (fallos seguidos de un inicio de
  sesión correcto) absorbe la AUTH-001 de la misma ráfaga.
- Una **detección de puerto** (NET-001/NET-002) y la exposición de ese mismo puerto forman
  un grupo.

Un grupo vale lo que su miembro más fuerte. Los demás aparecen en las contribuciones con 0
puntos y `details.absorbed_by` (la UI muestra "Incluida en CORR-001 (sin doble conteo)").

### 4. Rendimientos decrecientes

Los grupos se ordenan por valor y el n-ésimo aporta `0,5^(n-1)`: 100 % el primero, 50 % el
segundo, 25 % el tercero… Con infinitas señales iguales la suma es, como mucho, el doble de
una sola. Así diez detecciones medianas no equivalen a una crítica.

### 5. Modificadores del activo (acotados, multiplicativos)

| Criticidad | Factor | | Tipo | Factor |
|------------|-------:|-|------|-------:|
| low | 0,8 | | server, nas, router, network_switch, access_point | 1,1 |
| medium (por defecto) | 1,0 | | cualquier otro, incluido desconocido | 1,0 |
| high | 1,2 | | | |
| critical | 1,4 | | | |

Multiplican el riesgo existente; nunca lo crean (un activo crítico sin evidencia sigue en 0).
Ningún tipo resta y un tipo desconocido es neutro: no estar identificado no es evidencia de
nada.

### 6. Saturación

```
x ≤ 70: score = x
x > 70: score = 70 + 30 × (1 − e^(−(x − 70) / 30))
```

Lineal hasta 70 y asintótica hacia 100: una avalancha de señales no lleva automáticamente a
100, y por encima de 70 cada punto adicional cuesta más. La reducción aparece como
contribución negativa "Saturación por encima de 70 puntos".

### Ledger de contribuciones

Cada factor que sube o baja el score aparece con sus puntos: detecciones, exposición,
criticidad, tipo, rendimientos decrecientes (negativos, en el detalle de cada contribución) y
saturación. La suma de `points` es el score antes de redondear (comprobado en los tests y en
el QA e2e). Se guardan las 40 de más peso; el desglose indica cuántas se omitieron.

### Ejemplo real (QA e2e contra una API real)

| Paso | Score | Nivel | Motivo del snapshot |
|------|------:|-------|---------------------|
| Activo nuevo, sin evidencia | 0 | Informativo | `initial` |
| DEF-001 (registro de seguridad borrado, high) | 70 | Alto | `level_change` ▲ |
| CORR-001 + AUTH-001 (absorbida) | 93 | Crítico | `level_change` ▲ (alerta `risk_critical`) |
| Criticidad del activo → crítica | 99 | Crítico | `material_change` |
| Todas las detecciones resueltas | 79 | Alto | `level_change` ▼ (alerta resuelta) |

Tras resolver, el score sigue bajando solo con el tiempo (decay) hasta 0 a las 72 h.

## Confianza (separada del score)

Responde a "¿cuánto fiarse de este número?":

1. Media de la confianza de la evidencia, ponderada por los puntos de cada grupo (detección
   low 0,35, medium 0,65, high 0,9; correlación +0,05; exposición 0,85).
2. +0,08 con señales de 2 categorías independientes; +0,12 con 3 o más.
3. −0,1 si la evidencia principal es antigua (antigüedad media ponderada < 0,5).
4. Cobertura de datos del activo: completa (agente Windows activo: eventos, inventario y
   procesos), parcial −0,05 (agente sin eventos del sistema, hoy Linux) o limitada −0,15
   (solo red, o datos del agente con más de `RISK_STALE_DATA_HOURS`).
5. Sin evidencia: depende solo de la cobertura (completa 0,8, parcial 0,6, limitada 0,4).
   "No vemos riesgo" vale más si vemos el activo entero.

Resultado: < 0,5 baja, < 0,75 media, resto alta. La UI siempre muestra score, nivel y
confianza juntos ("82 / Crítico — confianza baja"): un crítico de confianza baja pide
verificar antes de actuar.

## Criticidad del activo

`low`, `medium` (por defecto), `high`, `critical`. Solo **admin** la cambia (permiso
`assets:manage`), desde la sección Riesgo del activo o con
`PATCH /api/v1/assets/{id}/criticality {"criticality": "high"}`. Cada cambio queda en la
auditoría como `asset_criticality_changed` (valor anterior y nuevo; también el intento
sobre un activo inexistente; un viewer o analyst recibe 403, auditado como
`permission_denied`) y recalcula el riesgo del activo en la misma petición. Al fusionar un activo
descubierto con su agente se conserva la criticidad si el destino tenía la de por defecto.

## Cuándo se recalcula

Nunca por heartbeat ni por telemetría. Se encola (`asset_risk.dirty_at`, una fila por
activo: muchos eventos seguidos = un solo recálculo) cuando:

- el motor de detección crea o actualiza una detección del activo;
- un analista reconoce o resuelve una detección;
- discovery ve abrirse o cerrarse un puerto;
- cambia la criticidad (este caso recalcula en el momento);
- se fusiona un activo descubierto con su agente.

El job `risk-engine` (cada `RISK_EVAL_INTERVAL_SECONDS`, 15 s):

1. crea la fila de los activos que aún no tienen riesgo (activos nuevos);
2. procesa la cola por lotes de `RISK_BATCH_SIZE` (100) con `FOR UPDATE SKIP LOCKED`, un
   savepoint por activo (un fallo no tumba el lote: el activo vuelve a la cola y se cuenta en
   `error_count`) y commit por lote;
3. como mucho cada `RISK_DECAY_INTERVAL_MINUTES` (15), recalcula los activos con score > 0
   cuyo cálculo tiene más de 15 min (decay) y cualquiera de más de `RISK_FULL_REFRESH_HOURS`
   (6 h; cubre cambios que no avisan, como reclasificar un activo como servidor).

Todo en el propio proceso de la API, sin Redis ni Celery. Manual: `python -m app.cli run-risk`
(cola y decay) o `run-risk --all` (todos los activos).

## Historial y transiciones

Un snapshot por cálculo llenaría la base sin aportar nada. Se guarda un punto solo si:

| Motivo | Cuándo |
|--------|--------|
| `initial` | Primera evaluación del activo |
| `level_change` | Cambia el nivel (con `transition` `up`/`down`) |
| `material_change` | El score se mueve al menos `RISK_SNAPSHOT_MIN_DELTA` (5) desde el último punto |
| `new_contribution` | Aparece una detección nueva que aporta ≥ 3 puntos |
| `interval` | El score cambió algo y han pasado `RISK_SNAPSHOT_INTERVAL_MINUTES` (60) |

Cada snapshot guarda sus contribuciones (`/risk/assets/{id}/contributions?snapshot_id=`), así
se puede explicar un valor pasado. La tendencia de 24 h usa los puntos reales; 7 d y 30 d se
agregan en PostgreSQL (un punto por hora o por 4 h, el último de cada intervalo) y nunca se
devuelven más de 500 puntos. Retención opcional: `RISK_HISTORY_RETENTION_DAYS` (vacío =
conservar).

## Alertas

Opcionales (`RISK_ALERT_ENABLED=true`). Reutilizan las alertas existentes con la regla
`risk_critical` (severidad crítica):

- se abren solo al **cruzar** hacia crítico, no por cada cambio de score;
- nunca en la primera evaluación de un activo (desplegar la fase no debe generar una
  avalancha por detecciones antiguas);
- cooldown por activo de `RISK_ALERT_COOLDOWN_HOURS` (6) para que oscilar alrededor de 80 no
  genere spam;
- se resuelven solas al salir de crítico; las bajadas no alertan (quedan en el historial).

## API (sesión del dashboard; lectura para todos los roles)

| Método | Ruta | Descripción |
|--------|------|-------------|
| GET | `/api/v1/risk/overview` | Activos por nivel y confianza, factores principales, transiciones recientes, umbrales |
| GET | `/api/v1/risk/assets?level=&confidence=&device_type=&status=&criticality=&min_score=&q=&sort=&order=&limit=&offset=` | Listado paginado; `sort` = `score` (por defecto, desc), `changed_at`, `last_seen`, `name`, `criticality` |
| GET | `/api/v1/risk/assets/{id}` | Detalle: explicación determinista, contribuciones, detecciones activas, cambios recientes, tendencia 24 h |
| GET | `/api/v1/risk/assets/{id}/history?range=24h\|7d\|30d` | Tendencia |
| GET | `/api/v1/risk/assets/{id}/contributions?snapshot_id=` | Contribuciones actuales o de un punto del historial |
| PATCH | `/api/v1/assets/{id}/criticality` | **Solo admin**; auditado; devuelve el detalle de riesgo ya recalculado |

Estas respuestas son la base estructurada para incidentes (4K) y para AI Security Insights
(4J): todo lo que una capa posterior necesite explicar ya viene con sus números y su origen.

## Rendimiento (`qa/perf_risk.py`, datos sintéticos)

Contenedor Linux de desarrollo, PostgreSQL 16 local, 1000 activos, 20 200 detecciones (15 %
activas, 100 correlaciones) y 200 000 puntos de historial:

| Medida | Resultado |
|--------|-----------|
| Primera evaluación de 1000 activos | 8,9 s (112 activos/s), 5 sentencias SQL por activo |
| Recálculo completo sin cambios | 3,5 s (284 activos/s), 0 snapshots nuevos |
| Pasada de decay (+1 h) | 7,7 s, 604 snapshots, 48 transiciones |
| Resumen (`overview`) | 56 ms, 9 consultas |
| Listado (orden, filtros, página 10) | 4-9 ms, 2 consultas |
| Detalle | 9 ms, 7 consultas |
| Tendencia 24 h / 7 d / 30 d | 3,5 / 4 / 8 ms, 4 consultas |

Las lecturas del cálculo son por lote (constantes por lote, no por activo: sin N+1). Por
activo solo quedan las escrituras: un `UPDATE` de su fila y, si hay cambio material, el
snapshot y sus contribuciones. Índices: `asset_risk(score)`, `(level)`, cola parcial
`(dirty_at) WHERE dirty_at IS NOT NULL`, `(calculated_at)`;
`risk_snapshots(asset_id, calculated_at)` y `(calculated_at)`; `risk_contributions` por
snapshot y por detección; y `detections(asset_id, resolved_at) WHERE status = 'resolved'`
para la memoria de resueltas. La entrada por activo está acotada (500 detecciones como
mucho, las de actividad más reciente).

## Configuración

| Variable | Por defecto | Uso |
|----------|-------------|-----|
| `RISK_ENABLED` | `true` | Job del motor |
| `RISK_EVAL_INTERVAL_SECONDS` | 15 | Frecuencia del job (cola) |
| `RISK_DECAY_INTERVAL_MINUTES` | 15 | Frecuencia del decay |
| `RISK_FULL_REFRESH_HOURS` | 6 | Recalcular todo lo calculado hace más de esto |
| `RISK_BATCH_SIZE` | 100 | Activos por lote |
| `RISK_LEVEL_THRESHOLDS` | `20,40,60,80` | Umbrales de nivel |
| `RISK_ACTIVITY_HALF_LIFE_HOURS` | 24 | Semivida por antigüedad |
| `RISK_ACTIVE_FLOOR` | 0,25 | Suelo de antigüedad para no resueltas |
| `RISK_RESOLVED_HALF_LIFE_HOURS` | 12 | Semivida desde la resolución |
| `RISK_RESOLVED_MEMORY_HOURS` | 72 | Horas que cuenta una resuelta |
| `RISK_EXPOSURE_RECENT_HOURS` | 24 | Puerto "recién abierto" (×1,3) |
| `RISK_SNAPSHOT_MIN_DELTA` | 5 | Cambio mínimo de score para un snapshot |
| `RISK_SNAPSHOT_INTERVAL_MINUTES` | 60 | Snapshot periódico si el score cambió |
| `RISK_STALE_DATA_HOURS` | 24 | Datos del agente más viejos = cobertura limitada |
| `RISK_ALERT_ENABLED` | `true` | Alerta `risk_critical` |
| `RISK_ALERT_COOLDOWN_HOURS` | 6 | Cooldown por activo |
| `RISK_HISTORY_RETENTION_DAYS` | vacío | Retención del historial (vacío = conservar) |

Los pesos (puntos, factores, saturación) son constantes de `app/risk/config.py`. Cambiar uno
cambia lo que significa un score: hay que subir `FORMULA_VERSION`, que se guarda en cada
cálculo y en cada snapshot.

## Limitaciones conocidas

- La exposición solo cuenta los puertos sensibles que ve discovery desde el servidor; sin
  discovery configurado no hay exposición. No hay datos de vulnerabilidades (CVE).
- Linux no envía eventos del sistema: su confianza es como mucho parcial y su riesgo sale de
  inventario, procesos y red.
- La criticidad es manual: por defecto todo es `medium` hasta que un admin la ajusta.
- La primera evaluación tras desplegar no alerta, aunque un activo ya esté en crítico (se ve
  en la página Riesgo).
- Al fusionar un activo descubierto con su agente, 4H borra en cascada las detecciones del
  activo descubierto; su historial de riesgo sí se mueve al activo destino.
- Los pesos se han calibrado con escenarios sintéticos y el QA; conviene revisarlos con datos
  reales de la red antes de tomar decisiones automáticas sobre ellos.
