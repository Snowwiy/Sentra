# Asset Context y contexto de amenaza interno (Fase 4L)

Asset Context responde, para cada activo, a las preguntas que un SOC necesita para priorizar:
qué función tiene, quién responde, en qué entorno está, qué tan crítico es, qué datos maneja,
en qué zona lógica está, si está expuesto a Internet, si está gestionado y qué detecciones o
incidentes lo afectan. No es una CMDB: son pocos campos, todos opcionales, con su procedencia.

## Asset vs Asset Context

- **Asset** (`assets`) sigue siendo la identidad del equipo: agente, descubrimiento,
  identificación 4E, telemetría, exposición, criticidad 4I. No se crea otra tabla de
  dispositivos.
- **Asset Context** es información administrativa asociada al activo:
  - `asset_context`: una fila por activo (PK = `asset_id`, `ON DELETE CASCADE`) con rol,
    entorno, owner, equipo/departamento, sensibilidad, zona, exposición, justificación de la
    criticidad, procedencia por campo y `version` (concurrencia).
  - `asset_tags`: etiquetas normalizadas (PK `asset_id, tag`, índice por `tag`).
  - `asset_context_changes`: historial de cambios (campo, antes, después, origen, actor).
- La fila se crea en el primer PATCH. Un activo sin fila tiene todo en `unknown` (y
  `version = 0`): no se hace backfill y no se inventa nada.
- Al fusionar un activo descubierto con el del agente (reconciliación 4E), el contexto se
  conserva: por campo manda el valor conocido del superviviente, las etiquetas se unen hasta
  el límite y el historial se mueve.

## Campos

| Campo | Valores | Default |
|-------|---------|---------|
| `criticality` | `low`, `medium`, `high`, `critical` (la de 4I, en `assets.criticality`) | `medium` (4I) |
| `criticality_rationale` | texto ≤ 200 ("Servidor de autenticación") | vacío |
| `role` | `workstation`, `server`, `domain_controller`, `database`, `web_server`, `application_server`, `security_server`, `network_device`, `router`, `switch`, `firewall`, `wireless_ap`, `printer`, `iot`, `mobile`, `virtual_machine`, `container_host`, `unknown`, `other` | `unknown` |
| `environment` | `production`, `staging`, `development`, `testing`, `lab`, `personal`, `unknown` | `unknown` (nunca `production` por defecto) |
| `owner` | texto ≤ 128 | vacío |
| `department` | texto ≤ 64 (equipo/departamento) | vacío |
| `data_sensitivity` | `unknown`, `public`, `internal`, `confidential`, `restricted` | `unknown` |
| `network_zone` | `unknown`, `user`, `server`, `management`, `dmz`, `guest`, `iot`, `security`, `lab` | `unknown` |
| `internet_exposed` | `true`, `false`, `null` (= desconocido) | `null` |
| `tags` | hasta 20 por activo | ninguna |

### Criticidad

Se reutiliza la criticidad de 4I (`assets.criticality`), no hay un segundo concepto. 4L añade
la justificación y quién/cuándo la cambió (`criticality_updated_at/by`). El endpoint 4I
`PATCH /assets/{id}/criticality` sigue funcionando y también deja historial y procedencia en
el contexto (y sube su `version`). `criticality_confirmed` es `false` mientras sea el `medium`
por defecto sin que nadie lo haya fijado.

### Rol

El rol confirmado lo fija un admin. La identificación 4E (tipo de dispositivo) solo **sugiere**
un rol (`role_suggestion`: valor, origen `agent`/`discovery`, confianza y motivo). La
sugerencia se calcula al leer y **nunca se guarda en `role`**, así que ninguna heurística puede
sobrescribir el valor del admin. Correspondencia: pc/laptop → workstation, server → server,
mobile/tablet → mobile, printer, router, network_switch → switch, access_point → wireless_ap,
iot/voice_assistant/smart_tv → iot, virtual_machine. NAS y consolas no sugieren nada: un rol
específico (database, domain_controller...) nunca se infiere sin evidencia.

### Entorno, owner y equipo

Texto simple administrativo, sin directorio de empresa. El owner del activo no es un usuario
de Sentra. Los departamentos ya usados se ofrecen para autocompletar
(`GET /assets/context/options`) para mantener el texto "controlado".

### Sensibilidad de datos

Solo la configura un admin. Nada la infiere.

### Zona de red

Contexto lógico confirmado. **Una subred no es una VLAN**: Sentra no deduce VLAN ID ni zona
a partir de la IP.

### Exposición a Internet

Tri-estado y separada de los puertos abiertos: un puerto visto desde el servidor Sentra (LAN)
no demuestra exposición a Internet. `true` solo cuando el admin tiene evidencia (NAT,
publicación, firewall). `null` es desconocido y **no** equivale a `false` ni a `true`.

### Estado de gestión

Se reutiliza `monitoring_method`: `discovered` → DISCOVERED, `agentless` → MONITORED,
`agent` → MANAGED. `visibility_sources` dice de dónde viene la visibilidad (`agent`,
`discovery`, `manual`).

### Tags

Normalizadas igual en backend y frontend: minúsculas, espacios a `-`, sin duplicados,
patrón `^[a-z0-9][a-z0-9._-]{0,31}$`. Límites: 20 por activo y 500 etiquetas distintas en
toda la plataforma (`asset_tag_limit` al superarlo) para evitar el "tag flood".

## Provenance

Cada campo conocido guarda en `provenance` un sello `{source, kind, confidence,
updated_at, updated_by}`:

- `source`: hoy `manual` (todo lo que entra por la API) y `agent`/`discovery`/`inferred`
  en las sugerencias. El enum ya incluye `snmp`, `lldp`, `manufacturer` y `threat_intel`
  para fases futuras (no hay integraciones).
- `kind`: `configured` (persona), `observed` (Sentra lo vio), `inferred` (sugerencia).
- `confidence`: solo para datos inferidos; un dato manual nunca lleva confianza artificial.

La API no acepta `source` ni `provenance` en el PATCH (`extra="forbid"` → 422): un cliente no
puede falsificar el origen. Al volver un campo a `unknown`/vacío se borra su sello.

## Manual override

1. Lo que fija un admin solo lo cambia otro PATCH de un admin.
2. Las sugerencias (rol inferido) se muestran aparte con "no confirmado".
3. La fusión de activos nunca pisa un valor conocido del activo superviviente.
4. La IA no escribe contexto (solo lo lee).

## Historial y auditoría

- Cada cambio de campo añade una fila a `asset_context_changes` (valores recortados a 300
  caracteres; tags como lista separada por comas). No hay snapshots por heartbeat.
- Un PATCH genera **un único** evento de auditoría con diff seguro
  `{fields, changes: [{field, from, to}], version}` y actor. La acción es la específica si
  solo cambia un tipo (`asset_role_changed`, `asset_owner_changed`,
  `asset_environment_changed`, `asset_data_sensitivity_changed`,
  `asset_network_zone_changed`, `asset_internet_exposure_changed`, `asset_tags_changed`,
  `asset_criticality_changed`) o `asset_context_updated` si cambian varios. Los intentos
  fallidos se auditan como `asset_context_updated` con resultado `failure`.
- Un PATCH sin cambios reales no sube la versión ni audita.

## API

| Método | Ruta | Permiso |
|--------|------|---------|
| GET | `/api/v1/assets/{id}/context` | sesión (`monitoring:read`) |
| PATCH | `/api/v1/assets/{id}/context` | `assets:manage` (solo admin) + CSRF |
| GET | `/api/v1/assets/{id}/context/history?limit=&offset=` | sesión |
| GET | `/api/v1/assets/context/options` | sesión |
| GET | `/api/v1/assets/{id}/threat-summary` | sesión |
| GET | `/api/v1/assets?criticality=&role=&environment=&network_zone=&data_sensitivity=&internet_exposed=true\|false\|unknown&department=&tag=&method=&sort=name\|criticality&limit=&offset=` | sesión |

PATCH parcial: solo se cambian los campos presentes; `version` (la leída en el GET) es
obligatoria. `null` en `owner`, `department`, `criticality_rationale` o `internet_exposed`
borra el valor; los enums vuelven con `"unknown"` (null explícito → 422). Cuerpo sin campos →
422. Texto: se recortan y colapsan espacios; se rechazan caracteres de control y `<`/`>`.

### Concurrencia

Mismo patrón que 4K: se bloquea la fila del activo y la del contexto (`SELECT … FOR UPDATE`)
y se compara `version`. Si otro admin guardó antes → **409 `asset_context_conflict`**, sin
sobrescribir nada; la UI recarga y avisa. El endpoint de criticidad de 4I bloquea en el mismo
orden (activo y luego contexto), así que no hay interbloqueos entre ambos.

### Filtros y paginación

Los filtros de contexto se aplican en SQL. `unknown` incluye los activos sin fila de contexto.
`limit`/`offset` son opcionales (sin `limit` se devuelve todo, como antes de 4L). Con `limit` y
sin filtros que necesiten Python (estado efectivo, subred, búsqueda, tipo, método), la página y
el total se resuelven en SQL.

## Integración con el Risk Engine (4I)

No hay otro motor. `FORMULA_VERSION` pasa de 1 a 2. Tras criticidad y tipo de 4I, el contexto
confirmado multiplica la base de evidencia:

```
raw = base × criticidad × tipo × min(entorno × sensibilidad × exposición, 1,25)
```

| Factor | Valor |
|--------|-------|
| entorno `production` | ×1,1 (el resto ×1,0: un entorno no productivo no reduce riesgo) |
| sensibilidad `confidential` / `restricted` | ×1,05 / ×1,1 |
| `internet_exposed = true` | ×1,1 |
| tope del producto de contexto | 1,25 |

Garantías:

- **Solo si `base > 0`**: sin evidencia (detecciones, exposición) el contexto no suma nada.
  Un servidor crítico, de producción, con datos restringidos y expuesto, pero sin
  detecciones, sigue en 0.
- `unknown` y `null` valen ×1,0: lo desconocido nunca aumenta el riesgo.
- Nada de sumas fijas ("producción = +50") ni "restringido = crítico".
- Explicación explícita: cada factor aparece en el ledger con sus puntos
  ("Contexto: entorno de producción (x1,1)") y, si se supera el tope, una línea negativa
  "Tope del contexto de negocio (x1,25)". El ledger sigue sumando exactamente el score. La
  explicación incluye la lista `context` (criticidad, tipo y contexto de negocio), que la UI
  muestra como "Contexto del activo".
- Un cambio de criticidad, entorno, sensibilidad o exposición marca el activo para
  recálculo y lo recalcula al momento.

## Integración con incidentes (4K)

- El detalle del incidente muestra el contexto **actual** de cada activo (rol, criticidad,
  entorno, owner, zona, exposición) leído de Asset Context en una consulta, sin copiarlo.
- Snapshot mínimo en `incident_assets`: `context_snapshot` al vincular el activo (al crear o
  adjuntar) y `resolved_context_snapshot` al resolver. Solo criticidad, rol, entorno,
  sensibilidad, zona, exposición y fecha; sin owner ni tags.
- Una fusión de incidentes copia el snapshot.

## Detecciones (4H)

Las reglas no cambian. El detalle de una detección muestra aparte "Impacto en el negocio
(contexto del activo)": la severidad de la detección (qué pasó) se mantiene separada del
impacto en el negocio (a qué le pasó).

## Integración con la IA (4J)

- El context builder añade `business_context` al activo: `confirmed` (campo → valor y
  origen), `unknown` (lista de campos sin dato), tags y, solo si el rol es desconocido,
  `suggested_role` marcado como inferido.
- Regla 8 del prompt (`POLICY_VERSION = 2`): la IA solo puede afirmar lo que está en
  `confirmed`, debe decir "desconocido" para lo demás y presentar una sugerencia como
  "posible"; no puede inventar owner, departamento, rol, criticidad ni zona.
- Privacidad: owner y departamento pasan por el redactor con la categoría nueva `owners`
  (`AI_REDACT=…,owners`). Con un proveedor **no local** se seudonimizan siempre
  (`effective_redact`), aunque `AI_REDACT` no lo pida. No se debilita 4J.1: el destino y el
  bloqueo de externos no cambian.
- La huella de datos de los insights incluye la versión del contexto: un cambio de contexto
  marca el análisis como desactualizado.
- La IA nunca escribe contexto.

## Contexto de amenaza interno

`GET /assets/{id}/threat-summary` se calcula al vuelo de entidades existentes (nada se
persiste):

- `active_detection_count`, `high_critical_detection_count` (abiertas/reconocidas);
- `open_incident_count`, `highest_incident_severity` (incidentes activos);
- `current_risk` (score, nivel, confianza 4I);
- `recent_exposure_changes` (cambios de exposición en 7 días), `recent_context_changes`;
- `last_security_activity`;
- `criticality`, `environment`, `managed_state`.

Sin feeds externos: ni VirusTotal, ni AbuseIPDB, ni MISP, ni OTX, ni CVE remoto.

## Semántica de unknown

Desconocido es un dato que falta, no una amenaza: no suma riesgo, no se pinta en color de
alerta y la IA lo dice como desconocido. La completitud (`completeness`: porcentaje de 8
campos conocidos, "Contexto completo/incompleto") mide la calidad del inventario y **no** se
mezcla con el riesgo.

## UI

- Detalle del activo → pestaña **Contexto** (tras Riesgo): campos con procedencia, rol
  sugerido aparte, completitud, contexto de amenaza e historial. Admin edita (solo envía los
  campos cambiados con la versión leída); analyst y viewer leen.
- Lista de activos: solo una insignia de criticidad (si no es media) y el rol (si se
  conoce), más un bloque plegable de filtros (criticidad, rol, entorno, zona, Internet,
  gestión, equipo/departamento, tag y orden por criticidad). No se rediseña el dashboard.
- Riesgo del activo: columna "Contexto del activo" con la influencia en puntos.
- Incidente: sección "Contexto de los activos" y columna "Contexto actual" con snapshots.

## RBAC

Edición solo admin (`assets:manage`). Analyst no edita: criticidad, entorno, sensibilidad y
exposición son entradas del riesgo, y owner/departamento son datos administrativos; dejarlo
en el analyst le permitiría subir o bajar prioridades del SOC sin control de un admin.

## Migración 0023

Crea los enums `asset_role`, `asset_environment`, `asset_data_sensitivity`,
`asset_network_zone`, las tablas `asset_context`, `asset_tags`, `asset_context_changes` y las
columnas `incident_assets.context_snapshot` / `resolved_context_snapshot`. Sin backfill.

Índices solo donde ayudan: etiqueta (`ix_asset_tags_tag`), departamento sin mayúsculas,
exposición `true` (parcial), historial por activo/fecha y por usuario (FK). Los enums de baja
cardinalidad (rol, entorno, zona) no se indexan: con 10 000 activos el planificador recorre
igual la tabla, y la criticidad ya filtra sobre `assets`.

**Downgrade a 0022**: se pierden todo el contexto (rol, entorno, owner, departamento,
sensibilidad, zona, exposición, justificación y procedencia), las etiquetas, el historial de
contexto y los snapshots de contexto de los incidentes. Se conservan `assets.criticality`,
la auditoría, activos, detecciones, riesgo, incidentes, IA, usuarios y agentes. No hacer
downgrade sobre una base real sin copia de seguridad.

## Rendimiento

`qa/perf_asset_context.py` con 10 000 activos sintéticos (7 000 con contexto, 3 000 con
etiquetas, historial y 20 000 detecciones), medianas en el entorno de desarrollo Linux:

| Lectura | ms | SQL/petición |
|---------|----|--------------|
| lista página 50 (y página 100) | 23-29 | 6 |
| orden por criticidad | 20 | 6 |
| filtros (criticidad, rol, entorno+zona, Internet, departamento, tag) | 14-25 | 6 |
| detalle de activo | 5 | 5 |
| contexto | 2 | 3 |
| historial | 2 | 3 |
| opciones | 6 | 2 |
| resumen de amenaza | 6 | 7 |
| lista completa sin `limit` (como hoy el dashboard) | ~1 500 | 5 |

El número de consultas no crece con el tamaño de la página (sin N+1). La lista completa sin
paginar es el comportamiento previo del dashboard; con flotas grandes conviene que la UI pase
a paginar (pendiente).

## Limitaciones

- Sin edición masiva (tampoco de etiquetas).
- Sin directorio de owners: texto libre validado.
- El dashboard sigue pidiendo la lista completa de activos (la API ya pagina).
- El rol sugerido depende de la identificación 4E; sin tipo no hay sugerencia.
- Los pesos de contexto son iniciales: revisarlos con datos reales.

## Enriquecimiento futuro

El modelo de procedencia ya admite `snmp`, `lldp`, `manufacturer` y `threat_intel`. Fuera de
4L: Specs de hardware (CPU, RAM, GPU...), SNMP, LLDP, tablas de puertos de switch, VLAN,
búsqueda de fabricantes en Internet, firmware y Threat Intelligence externa.
