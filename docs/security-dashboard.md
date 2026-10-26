# Vista de seguridad del dashboard (Fase 7A.7)

`GET /api/v1/dashboard/security-overview` alimenta las gráficas del dashboard. Complementa a
`GET /api/v1/dashboard/summary` (contadores de la 4M), que sigue igual. Todo sale de datos
reales agregados en SQL; ninguna cifra se rellena con un valor de ejemplo.

| Parámetro | Valor |
| --- | --- |
| `site_id` | opcional; limita todo a los activos de ese site (404 `site_not_found`) |
| `days` | ventana del historial de riesgo, de 7 a 90 días (30 por defecto) |

Permiso: `monitoring:read`, como el resto del dashboard. `incidents_by_status` es `null` para
quien no tenga `incidents:read`.

## Qué devuelve

| Bloque | Origen | Notas |
| --- | --- | --- |
| `posture` | `asset_risk` + criticidad del activo | indicador global, ver abajo |
| `incidents_by_status` | `incidents` | todos los estados, también los cerrados y fusionados; con site, los casos con algún activo de ese site |
| `detections_recent` | `detections` | las 8 activas (open, acknowledged) más recientes por `last_seen_at` |
| `risk_history` | `risk_snapshots` (ledger del Risk Engine) | un punto por día UTC |
| `new_devices` | `assets.first_seen_at` | últimos 7 días: total y los 8 más recientes |
| `exposed_ports` | `asset_ports` en estado `open` | total, activos afectados y los 8 puertos con más activos |

Las gráficas de severidad, nivel de riesgo, tipo de activo y gestionados frente a
descubiertos usan los contadores de `/dashboard/summary` (`detections.by_severity`,
`risk.by_level`, `assets.by_device_type`, `assets.by_method`).

Población común: activos **actuales**, es decir, no archivados y, si se pide, del site
elegido. Los activos archivados conservan su historial pero no cuentan aquí, tampoco en el
historial de riesgo (que describe la flota actual hacia atrás, no la flota de cada día).

## Indicador global de postura (fórmula v1)

```
score = round( sum(score_i x peso_i) / sum(peso_i) )
```

- **Población:** activos actuales con riesgo calculado por el Risk Engine
  (`asset_risk.calculated_at` no nulo). `score_i` es su puntuación actual (0-100).
- **Pesos por criticidad del activo:** low 1, medium 2, high 3, critical 4. Un activo crítico
  pesa cuatro veces uno de criticidad baja: la postura refleja sobre todo lo que más importa,
  sin que un solo activo la decida.
- **Nivel:** el de `score` con los mismos umbrales del Risk Engine (`RISK_LEVEL_THRESHOLDS`,
  por defecto 20/40/60/80). La respuesta incluye los umbrales en vigor.
- **Datos que faltan:** un activo sin riesgo calculado no cuenta como cero; queda fuera de la
  media y baja la cobertura (`coverage = assets_scored / assets_current`).
  - Sin ningún activo con riesgo: `state = no_data` y `score = null`.
  - Cobertura menor del 50 %: `state = partial`. La UI debe avisar de que la media describe a
    una minoría de la flota.
  - En otro caso: `state = ok`.
- **Contrapesos:** la media puede ocultar un activo muy expuesto, por eso la respuesta trae
  también `peak_score` (el peor activo) y `high_or_critical` (cuántos están en high o
  critical).

La respuesta lleva la fórmula, la población, los pesos, el tratamiento de los datos que
faltan y los umbrales en `posture.method`, para que la interfaz los muestre junto al número.
Si la fórmula cambia, sube `formula_version`.

## Historial de riesgo

El Risk Engine solo escribe una fila en `risk_snapshots` cuando el riesgo de un activo cambia
de forma material. El valor de un activo en un día es su última instantánea anterior al final
de ese día (UTC); para el día actual, anterior al momento de la consulta.

Cálculo: una lectura del estado anterior a la ventana (`DISTINCT ON` por activo) y otra, en
orden, de las instantáneas dentro de la ventana. El coste depende del número de cambios, no
de días por historial completo.

Cada punto trae `assets_scored` (activos con algún valor conocido ese día), `average_score`
(media simple, sin ponderar, o `null` si no hay ninguno), `high` y `critical`. La media del
historial no está ponderada porque la criticidad de cada día no se guarda: ponderar el
pasado con la criticidad actual mezclaría dos momentos.

## Limitaciones

- Los dispositivos nuevos se cuentan por `first_seen_at`: un activo reconciliado conserva su
  primera fecha y no vuelve a contar como nuevo.
- Los puertos expuestos son los que ve el servidor o el sensor (la línea base de exposición),
  no los que escuchan solo en local.
- El historial no incluye activos ya archivados; para auditar el pasado completo está el
  informe de riesgo (Fase 5E).
