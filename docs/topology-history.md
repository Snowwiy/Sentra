# Historial de topología y cambios de red (Fase 6E.1)

> Estado: implementado en el backend (`app/topology/history.py`,
> `app/topology/history_service.py`, `app/api/v1/routes/topology_history.py`, migración 0039).
> Probado con datos sintéticos (`tests/test_topology_history.py`); pendiente de verificar en
> equipos reales (switches LLDP/CDP, tablas MAC y controladoras WLAN de verdad).

Amplía el motor de topología de 6D ([topology-engine.md](topology-engine.md)) con dos cosas:
qué aspecto tenía la red en cada momento (`topology_snapshots`) y qué cambió entre dos estados
(`network_changes`). Nada de este módulo consulta la red: todo sale de lo que cada
reconstrucción de 6D ya ha derivado.

## Principios

- **Un snapshot por estado distinto, no por reconstrucción.** Cada reconstrucción calcula el
  contenido compacto del grafo y su SHA-256. Si coincide con el último snapshot del site, solo
  se actualizan `confirmed_at` y `confirmations`. El historial crece con los cambios de la red,
  no con el intervalo del programador (`TOPOLOGY_REBUILD_INTERVAL_MINUTES`).
- **Misma transacción que los enlaces.** `record_history` se ejecuta dentro de
  `TopologyService.rebuild`: si la reconstrucción falla, no queda un snapshot de un estado que
  nunca se guardó.
- **Una ausencia no es una eliminación.** Un nodo o un enlace que falta en un snapshot se
  registra como «no observado». Las conclusiones fuertes (`device_disappeared`,
  `device_retired`, `link_removed`) exigen una evidencia concreta (ver más abajo).
- **El estado de entonces.** Un snapshot guarda los valores observados en ese momento (nombre,
  IP, MAC...); no se recalculan después con el inventario actual.
- **Sin riesgo ni criticidad en el snapshot.** Cambian por motivos que no son de red y
  llenarían el historial de ruido.

## Modelo (migración 0039)

### `topology_snapshots`

| Columna | Contenido |
|---|---|
| `public_id` | Identificador público (UUID) que usa la API |
| `site_id` | Site del snapshot |
| `sequence` | Número creciente por site (único por site); ordena sin depender del reloj |
| `content_hash` | SHA-256 del JSON canónico `{"nodes", "links"}` (claves ordenadas, sin espacios) |
| `build_id` | Reconstrucción que lo produjo (`SET NULL` si la retención borra la reconstrucción) |
| `nodes`, `links` | Contenido compacto en JSONB (ver abajo) |
| `node_count`, `link_count` | Totales |
| `quality` | `complete`, `partial` o `degraded` |
| `quality_detail` | `{"reasons": [...], "degraded_nodes": [...]}` (hasta 200 nodos) |
| `taken_at` | Cuándo se vio por primera vez este estado |
| `confirmed_at`, `confirmations` | Última reconstrucción que obtuvo el mismo hash y cuántas lo han obtenido |
| `preserved`, `preserve_reason` | Excluido de la retención |

Por nodo se guarda `kind`, `label` (nombre visible, incluida la etiqueta personalizada),
`ip`, `mac`, `vendor`, `device_type`, `role`, `status`, `managed`, `identity` (confianza de
identidad), `gateways` (de los agentes) y `wifi` (`{"ap", "ssid"}` si hay asociación WLAN).
Por enlace (clave = `link_key` de 6D): `s`, `t` (extremos), `k` (clase), `rel` (relación), `c`
(confianza), `med` (medio), `sp`, `tp` (puertos), `vlan` (leída de la evidencia de la tabla MAC)
e `id` (id público del enlace). Solo entran los enlaces `present` y no rechazados por un
revisor, y solo si sus dos extremos están en el catálogo de nodos.

Cualquier diferencia en ese contenido crea un snapshot nuevo, aunque no todas producen un
`network_change` (por ejemplo, un cambio de `identity`, `managed` o `med`).

### `network_changes`

| Columna | Contenido |
|---|---|
| `change_type` | Catálogo cerrado (tabla siguiente) |
| `subject_type`, `subject_key`, `subject_label` | `node` o `link`; clave de nodo (`asset:<uuid>`...) o `link_key` |
| `asset_id` | Activo afectado si el sujeto es (o toca) un activo |
| `before`, `after` | Valores antes y después (JSONB) |
| `evidence` | `[{"source", "detail", "observed_at"}]`, como mucho 8 entradas, `detail` ≤ 255 |
| `source` | Quién lo detectó. El código actual solo escribe `topology_diff` |
| `confidence` | `high`, `medium`, `low` |
| `status` | `detected` (inicial), `confirmed`, `dismissed` |
| `review_note`, `reviewed_by`, `reviewed_at`, `version` | Revisión humana con concurrencia optimista |
| `from_snapshot_id`, `to_snapshot_id` | Snapshots comparados (`SET NULL` si la retención los borra) |
| `detected_at`, `preserved` | Momento de detección y exclusión de la retención |

La migración añade además a `topology_links` las columnas `absent_builds`, `absent_since` y
`removed_at`, que sostienen la regla de `link_removed`.

## Calidad del snapshot

`snapshot_content` (`app/topology/service.py`) decide la calidad:

1. `partial` si la reconstrucción descartó enlaces por `TOPOLOGY_MAX_LINKS`
   (`links_truncated`) o hay más nodos que `TOPOLOGY_MAX_NODES` (`nodes_over_limit`).
2. Si no, `degraded` (`evidence_source_failed`) si algún nodo tiene la fuente de evidencia
   caída:
   - equipo de red no archivado con `snmp_status` en `no_response`, `timeout`, `unreachable`,
     `auth_failed`, `unsupported_version`, `malformed_response` o `collector_error`, o con la
     monitorización en pausa;
   - activo con agente (`managed`) cuyo estado no es `online` (un agente sin contacto no
     informa su gateway).
3. Si no, `complete`.

Solo un snapshot `complete` permite concluir `link_removed`. Los nodos degradados se guardan
en `quality_detail.degraded_nodes` también cuando la calidad es `partial`.

## Tipos de cambio y reglas de no falso cambio

El primer snapshot de un site es la línea base: no genera cambios. Después, cada snapshot
nuevo se compara con el anterior (`diff_snapshots`).

### Nodos

| change_type | Cuándo | confidence |
|---|---|---|
| `device_appeared` | El nodo está en el snapshot nuevo y no en el anterior | `high` |
| `device_retired` | El nodo falta y su activo está archivado (`archived_at`) | `high` |
| `device_not_observed` | El nodo falta sin archivado (activo borrado por la política de ciclo de vida, fusionado o equipo de red archivado) | `medium` |
| `device_not_observed` | El estado pasa a `unknown` | `low` |
| `device_disappeared` | El estado pasa a `offline` y el nodo **no** tiene agente. Sin agente, `offline` solo lo decide el discovery tras scans completos sin respuesta (`network_misses`) | `high` |
| `connectivity_changed` | Cualquier otro cambio de `status` (incluido un agente que pasa a `offline`) | `high` |
| `ip_changed`, `mac_changed`, `gateway_changed`, `role_changed` | Cambia el campo | `high` |
| `name_changed`, `vendor_changed`, `classification_changed` | Cambia `label`, `vendor` o `device_type` | `medium` |
| `wifi_ap_changed` | Cambia el AP de la asociación Wi-Fi | `medium` |
| `wifi_association_changed` | Aparece una asociación o cambia el SSID con el mismo AP | `medium` |

Reglas:

- Un valor que pasa a vacío (`null`, `""`, `[]`) no es un cambio del dispositivo: la fuente
  dejó de verlo. Se registra el siguiente valor real. La excepción son los `gateways`, cuya
  pérdida sí se registra.
- Un cambio de estado con el valor anterior o el nuevo a `null` no se registra.
- La pérdida de la asociación Wi-Fi (pasa a `null`) no se registra; solo una asociación nueva
  o distinta.

### Enlaces

| change_type | Cuándo | confidence |
|---|---|---|
| `link_added` | Enlace nuevo sin equivalente en el snapshot anterior | la del enlace (`c`) |
| `link_port_changed` | Misma pareja de nodos y misma familia de relación con otros puertos | `medium` |
| `link_vlan_changed`, `link_kind_changed`, `link_confidence_changed` | Cambia `vlan`, `k` o `c` del mismo enlace | `medium` |
| `link_not_observed` | El enlace no se derivó en la reconstrucción | `low` |
| `link_removed` | Ver la regla siguiente | `medium` |

- La comparación por «pareja + familia de relación» (`fdb_edge`, `fdb_shared` y
  `fdb_unmapped` son la misma familia `fdb`) evita que un cambio de boca del switch aparezca
  como «enlace eliminado + enlace nuevo».
- Una VLAN que deja de informarse (`null`) no es un cambio.
- **`link_removed`** solo se registra si se cumplen todas estas condiciones:
  1. el snapshot de esta reconstrucción es `complete`;
  2. `TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS` es mayor que 0 (por defecto 3);
  3. el enlace lleva al menos ese número de reconstrucciones seguidas sin derivarse
     (`topology_links.absent_builds`; se pone a 0 en cuanto vuelve a derivarse);
  4. ninguno de sus dos extremos está entre los nodos degradados de esta reconstrucción.

  El contador cuenta todas las reconstrucciones seguidas sin el enlace; la salud de la fuente
  y la calidad se comprueban en la reconstrucción que concluye. Cada eliminación se registra
  una sola vez (`removed_at`); si el enlace vuelve, `removed_at` se limpia. Esta regla se
  evalúa en cada reconstrucción, aunque el snapshot no cambie, y el cambio queda con
  `to_snapshot_id` = snapshot vigente y `from_snapshot_id` nulo.
- Compartir subred o gateway sigue sin crear enlace (regla de 6D), así que tampoco produce
  cambios de enlace.

## Revisión

`PATCH /api/v1/topology/changes/{change_id}/review` con:

```json
{"status": "confirmed", "note": "Cambio de puerto planificado", "version": 1}
```

- `status`: `confirmed`, `dismissed` o `detected` (volver a pendiente).
- `note`: opcional, ≤ 500 caracteres, sin caracteres de control.
- `version`: la que tiene el cliente. Si no es la actual: 409 `network_change_conflict` y no
  se guarda nada.
- Guarda `reviewed_by` y `reviewed_at`, incrementa `version` y audita
  `network_change_reviewed` (`from`, `to`, `change_type`).
- Revisar un cambio no modifica el grafo, los enlaces ni el inventario.
- Un cambio de otro site o inexistente: 404 `network_change_not_found`.

## Permisos

- Lectura (snapshots, diff, export, cambios, historial): `monitoring:read` (todos los roles).
- Revisar cambios y reconstruir a mano: `topology:manage` (solo admin).

## API (`/api/v1/topology`)

Todas las rutas aceptan `site_id` (UUID); sin él se usa el site por defecto. Site
inexistente: 404 `site_not_found`. Todo lo que no es del site responde el mismo 404 que lo
inexistente.

| Método y ruta | Parámetros | Respuesta |
|---|---|---|
| `GET /snapshots` | `start`, `end` (sobre `taken_at`), `before_sequence` (cursor), `limit` 1-200 (50) | `{"items": [...], "next_before_sequence"}`, del más reciente al más antiguo |
| `GET /snapshots/{snapshot_id}` | | Metadatos más `nodes`, `links` y `degraded_nodes`. 404 `topology_snapshot_not_found` |
| `GET /diff` | `from_snapshot` o `from_time` (obligatorio uno), `to_snapshot` o `to_time` (sin ninguno, el estado actual), `subnet` (CIDR) | `{"site_id", "from_snapshot", "to_snapshot", "summary": {"total", "by_type"}, "changes": [...]}` |
| `GET /diff/export` | Los mismos más `format` (`json`, por defecto, o `csv`) | Fichero con `X-Sentra-SHA256` |
| `GET /changes` | `change_type`, `status`, `subject` (clave exacta ≤ 96), `asset_id`, `start`, `end` (sobre `detected_at`), `subnet`, `limit` 1-200 (50), `offset` | `{"total", "items": [...]}`, del más reciente al más antiguo |
| `PATCH /changes/{change_id}/review` | Cuerpo de la sección anterior | El cambio actualizado |
| `GET /history/nodes/{node_id}` | `limit` 1-200 (100) | Periodos del nodo |
| `GET /history/links/{link_id}` | `limit` 1-200 (100) | Periodos del enlace (por su id de 6D) |

Detalles:

- **Diff por instante.** `from_time` y `to_time` eligen el último snapshot con
  `taken_at <= instante`. Si no hay ninguno: 404 `topology_snapshot_not_found`. Sin origen:
  422 `topology_diff_missing_from`.
- **El diff se recalcula** con las mismas reglas que el registro, entre los dos estados
  elegidos: comparar dos fechas lejanas resume los cambios intermedios en el estado final. Por
  eso un diff nunca contiene `link_removed` (esa conclusión depende de reconstrucciones
  sucesivas y solo está en `/changes`).
- **Filtro `subnet`** (CIDR, 3-49 caracteres; mal formado: 422 `topology_invalid_subnet`):
  en `/diff` se aplica a la IP de los nodos implicados en cualquiera de los dos snapshots; en
  `/changes`, a la IP **actual** del activo afectado, así que los cambios sin activo (por
  ejemplo, un enlace entre dos switches) quedan fuera.
- **Historial de nodo o enlace.** Cada entrada es un periodo con los mismos valores:
  `snapshot_id`, `sequence`, `since` (`taken_at`), `until` (`confirmed_at` del último snapshot
  del periodo), `present` y `value`. Devuelve los últimos `limit` periodos. Un `node_id` mal
  formado, de otro site o sin ninguna presencia: 404 `topology_history_not_found`.

### Export

- `json`: el `TopologyDiff` serializado en JSON canónico (claves ordenadas, sin espacios),
  `application/json`.
- `csv`: columnas `change_type, subject_type, subject_key, subject_label, confidence, before,
  after` (`before` y `after` en JSON canónico). Las celdas que empiezan por `=`, `+`, `-`, `@`,
  tabulador o retorno de carro se prefijan con `'` para que una hoja de cálculo no las ejecute
  como fórmula.
- Cabeceras: `Content-Disposition: attachment; filename="topology-diff-<seq_origen>-<seq_destino>.<format>"`,
  `X-Sentra-SHA256` (SHA-256 hexadecimal del cuerpo exacto) y `Cache-Control: no-store`.

`X-Sentra-SHA256` es un hash de integridad, no una firma: demuestra que el fichero no cambió
después de descargarlo si el hash se conserva por otra vía (por ejemplo, en el ticket del
caso). Comprobación:

```powershell
(Get-FileHash .\topology-diff-1-2.csv -Algorithm SHA256).Hash.ToLower()
```

## Retención

Job `retention` (cada `RETENTION_SWEEP_INTERVAL_SECONDS`, 3600 por defecto), función
`purge_topology_history`. A diferencia de las retenciones opt-in de 4M, estas vienen activas;
un valor vacío desactiva la purga de ese tipo.

| Variable | Defecto | Qué se borra | Qué se conserva siempre |
|---|---|---|---|
| `TOPOLOGY_BUILD_RETENTION_DAYS` | 30 | `topology_builds` iniciadas antes del plazo y no `running` | La última reconstrucción de cada site |
| `TOPOLOGY_SNAPSHOT_RETENTION_DAYS` | 180 | Snapshots con `confirmed_at` anterior al plazo | El último snapshot de cada site y los `preserved` |
| `NETWORK_CHANGE_RETENTION_DAYS` | 365 | Cambios con `detected_at` anterior al plazo | Los `preserved` |
| `TOPOLOGY_ABSENT_LINK_RETENTION_DAYS` | 90 | Enlaces `present=false` sin revisión humana (`unreviewed`), ausentes y sin verse desde antes del plazo | Enlaces aceptados o rechazados por una persona |

`preserved` existe en snapshots y cambios, y la retención lo respeta. El servicio incluye
`preserve_for` (marca el snapshot vigente en un instante y los cambios de ±24 h), pero en el
código actual ningún flujo de incidentes ni de investigaciones lo llama: hoy un registro solo
queda preservado si se marca a mano en la base de datos. Pendiente de conectar.

## Enfriamiento de la reconstrucción manual

`POST /api/v1/topology/rebuild` (`topology:manage`) responde 429 `topology_rebuild_cooldown`
con `Retry-After` si la última reconstrucción **manual** del site empezó hace menos de
`TOPOLOGY_MANUAL_REBUILD_COOLDOWN_SECONDS` (60 por defecto; 0 lo desactiva). La reconstrucción
programada no cuenta ni se ve frenada. Sigue vigente el 409 `topology_build_running` de 6D.

## Configuración

| Variable | Defecto | Rango |
|---|---|---|
| `TOPOLOGY_LINK_REMOVAL_CONFIRMATIONS` | 3 | 0-1000 (0 = nunca concluir `link_removed`) |
| `TOPOLOGY_BUILD_RETENTION_DAYS` | 30 | 1-36500 o vacío |
| `TOPOLOGY_SNAPSHOT_RETENTION_DAYS` | 180 | 1-36500 o vacío |
| `NETWORK_CHANGE_RETENTION_DAYS` | 365 | 1-36500 o vacío |
| `TOPOLOGY_ABSENT_LINK_RETENTION_DAYS` | 90 | 1-36500 o vacío |
| `TOPOLOGY_MANUAL_REBUILD_COOLDOWN_SECONDS` | 60 | 0-86400 |

## Rendimiento

No hay mediciones de rendimiento en el código ni en los tests de este módulo. Lo que se sabe
por el diseño:

- Una reconstrucción sin cambios solo actualiza una fila (`confirmed_at`).
- Cada snapshot nuevo guarda el grafo compacto completo del site: el espacio crece con
  (nodos + enlaces) × número de estados distintos dentro del plazo de retención.
- `/history/nodes` y `/history/links` leen la clave del sujeto en todos los snapshots del site
  que conserva la retención.

Pendiente de medir en un site real con muchos nodos y cambios frecuentes.

## Pruebas

`tests/test_topology_history.py`: hash por contenido, nodo ausente frente a retirado, `offline`
con y sin agente, valores vacíos, cambio de puerto, VLAN, clase y confianza, cambio de AP,
línea base y confirmación, cambio de IP con activo, `link_removed` solo tras las
confirmaciones con fuente sana, fuente degradada que nunca concluye eliminación, activo
archivado, API (snapshots, diff, export con hash, historial), listado y revisión de cambios,
enfriamiento y retención que conserva el último snapshot y lo preservado.

## Validación pendiente en equipos reales

1. Aplicar la migración 0039 en `sentra_test` y, tras revisar, en producción.
2. Reconstruir dos veces seguidas sin cambios en la red y comprobar que hay un solo snapshot
   con `confirmations` = 2.
3. Cambiar un equipo de boca en un switch con LLDP o tabla MAC y comprobar
   `link_port_changed` en lugar de alta + baja.
4. Apagar un switch consultado por SNMP y comprobar que el snapshot queda `degraded` y que sus
   enlaces no pasan a `link_removed`.
5. Descargar un export CSV y verificar su `X-Sentra-SHA256`.
