# Gestión de incidentes y flujo SOC (Fase 4K)

Un **incidente** es la unidad de trabajo del SOC: agrupa por referencia detecciones (4H),
correlaciones, alertas y activos, tiene un responsable, un estado explícito, notas, un
timeline y una resolución. Toda la lógica vive en el servidor de Sentra; el navegador solo
muestra y envía referencias, texto del analista y la `version` que leyó. Nada importante se
guarda en `localStorage` ni depende de `localhost`.

Fuera de alcance a propósito: playbooks, respuesta automática, SLA/MTTR, integraciones,
threat intel, SNMP/LLDP e inventario de hardware.

## Modelo

| Campo | Notas |
|-------|-------|
| `incident_id` | UUID público (la PK entera nunca sale de la API) |
| `number` / `key` | Secuencia PostgreSQL `incident_number_seq`; se muestra como `INC-000001`. Único, no es la PK y no se reutiliza |
| `severity` | Impacto: `low`/`medium`/`high`/`critical` |
| `priority` | Urgencia de trabajo, **independiente** de la severidad (sin mapeo 1:1) |
| `confidence` | Derivada de la evidencia real (la mayor confianza de sus detecciones); `null` si no hay detecciones. Nunca se inventa |
| `status` | Ver state machine |
| `owner` | Analyst o admin activo. Si su cuenta se desactiva después, se sigue mostrando como owner histórico (`active=false`) |
| `created_by`, `assigned_by`, `updated_by`, `resolved_by` | Quién hizo qué |
| `first_seen_at`, `last_seen_at` | Ventana de la evidencia vinculada (horas reales de detecciones/alertas) |
| `last_activity_at` | Última actividad del caso (ordena el listado) |
| `resolution_category`, `resolution_summary` | Obligatoria al resolver / opcional |
| `duplicate_of`, `merged_into` | Referencias a otro incidente (ver Duplicado vs fusión) |
| `risk_*_snapshot` | Riesgo de 4I al crear y al resolver |
| `version` | Token de concurrencia optimista |

Relaciones (`incident_detections`, `incident_alerts`, `incident_assets`): FK con
`ON DELETE SET NULL` más una **referencia mínima** (id público, regla, título, severidad,
nombre del activo). No se copian evidencias: si la retención purga una detección, el caso
conserva la referencia (`available=false`) y la evidencia se sigue leyendo del origen
mientras exista. Un índice único parcial impide vincular dos veces lo mismo al mismo caso.

`incident_notes` (append-only, texto plano), `incident_activity` (historial propio del caso:
creado, cambios, asignación, adjuntos, resolución, fusión, snapshot de riesgo) e
`incident_feedback` (feedback estructurado de falsos positivos).

## State machine

Centralizada en `backend/app/incidents/workflow.py` (la UI recibe `allowed_transitions`, pero
el backend valida siempre):

```
open ──► triage ──► investigating ◄──► contained
  └──────────────────►┘    │                │
triage / investigating / contained ──resolve──► resolved ──close (admin)──► closed
resolved ──PATCH──► investigating (anula la resolución)
closed ──reopen (admin)──► open
cualquier activo ──merge (admin)──► merged (terminal)
```

- `PATCH status` solo admite transiciones de trabajo (`triage`, `investigating`,
  `contained`). `resolved`, `closed`, `open` y `merged` exigen su acción (`/resolve`,
  `/close`, `/reopen`, `/merge`).
- Un caso `closed` o `merged` está congelado: no admite cambios, notas ni adjuntos (409
  `incident_invalid_state`). `closed → open` solo con `reopen` explícito.
- Un PATCH al mismo estado es un no-op.

## Creación

- **Manual** (`POST /incidents`, analyst/admin): título, severidad, prioridad, descripción y
  activos opcionales. Un activo inexistente → 422 `incident_invalid_reference`.
- **Desde una detección** (`POST /detections/{id}/incident`): reutiliza su activo; severidad
  desde la detección (`informational` → `low`); confianza desde la detección; prioridad
  **sugerida** (ver abajo) salvo que el analista la indique.
- **Desde una alerta** (`POST /alerts/{id}/incident`): reutiliza su activo y las detecciones
  que generaron esa alerta (`detections.alert_id`); severidad `info→low`, `warning→medium`,
  `critical→critical`.
- Si la detección/alerta ya está en un incidente activo → 409 `incident_already_linked` con
  la clave del incidente existente.

**Prioridad sugerida**: parte de la severidad y sube un escalón si el riesgo actual del
activo (4I) es `high`/`critical` o su criticidad de negocio es `high`. Nunca baja ni sube más
de un escalón: el riesgo informa, no decide. El analista puede cambiarla.

## Incidentes relacionados (deduplicación asistida)

`GET /detections/{id}/related-incidents` y `/alerts/{id}/related-incidents` devuelven como
mucho 10 incidentes **activos** con sus motivos y una puntuación:

| Motivo | Puntos |
|--------|--------|
| `already_linked` | 100 |
| `evidence_overlap` (comparten eventos de evidencia) | 40 |
| `same_asset` | 30 |
| `same_rule` | 25 |
| `correlation` | 20 |
| `same_account` | 20 |
| `time_window` (±24 h) | 10 |

Solo con `same_rule`/`same_account`/`correlation` no basta para sugerir. Nada se adjunta ni
se fusiona automáticamente: el analista elige "Adjuntar" (`POST /incidents/{id}/detections/{did}`
o `/alerts/{aid}`) o "Crear incidente". Adjuntar es idempotente. Crear desde una detección o
alerta ya vinculada a un caso activo se rechaza (409); adjuntarla a mano a un segundo caso sí
se permite, porque es una decisión explícita del analista (la sugerencia lo marca como
`already_linked`).

## Asignación

- Analyst: puede asignarse a sí mismo un caso sin responsable (o reafirmarse) y quitarse.
- Admin: asigna, reasigna y desasigna a cualquier analyst/admin **activo**.
- Nunca un viewer ni un usuario desactivado (422).

## Notas

Append-only, 1–5000 caracteres, texto plano no confiable (la UI lo pinta como texto; nunca
HTML). No cambian la `version` del caso (dos analistas pueden anotar a la vez) y la auditoría
solo guarda la longitud, no el texto.

## Timeline

`GET /incidents/{id}/timeline?limit=&cursor=&since=&until=` une con `UNION ALL`, sin copiar
datos, del más reciente al más antiguo:

- `incident` (actividad del caso), `note`;
- `detection` / `correlation` (primera vez vista), `event` (evidencias de esas detecciones);
- `alert` (apertura), `risk` (transiciones de nivel de riesgo de sus activos dentro de la
  ventana del caso ±24 h), `ai_insight`.

Cada elemento lleva hora real del origen, tipo, entidad, actor y resumen; lo que no tiene hora
propia no aparece. Paginación por cursor opaco (keyset por `(occurred_at, clave)`); un cursor
manipulado → 422.

## Evidencia

`GET /incidents/{id}/evidence` agrupa, siempre derivado en el servidor de las relaciones
validadas: detecciones, correlaciones, eventos de evidencia (máx. 200, con total),
exposición (puertos abiertos de sus activos), alertas y contribuciones de riesgo (4I).

## Resolución, falsos positivos y duplicados

- `POST /resolve` exige `category`: `true_positive`, `false_positive`, `benign_activity`,
  `duplicate`, `accepted_risk`, `other`; `summary` opcional.
- `false_positive` guarda una fila de `incident_feedback` por detección (regla y versión) como
  feedback estructurado. **No** cambia reglas, umbrales ni severidades.
- `duplicate` exige `duplicate_of` (otro incidente existente y no fusionado).

**Duplicado vs fusión**: *duplicado* es una resolución que solo **referencia** el caso
principal; no mueve nada. *Fusión* (`POST /merge`, solo admin) **absorbe** el caso: copia sus
detecciones, alertas y activos al destino, deja el origen en `merged` con `merged_into`, y el
destino muestra sus notas, actividad e insights (familia por CTE recursiva). Se rechaza
fusionar consigo mismo, con un caso fusionado o cerrado, en cadena circular o con versiones
obsoletas de origen o destino (409).

## Riesgo (4I)

El incidente **consume** 4I sin recalcular: en el detalle muestra el riesgo actual de sus
activos (score, nivel, confianza, top contribuciones, hora) y guarda un snapshot al crear y al
resolver (`risk_snapshot` en la actividad). Los cambios de nivel aparecen en el timeline.

## IA (4J, opcional y de solo lectura)

`POST /ai/incidents/{id}/analyze` con `task` = `summary`, `timeline`, `evidence` o
`next_steps` (permiso `incidents:read` + `ai:use`). El contexto se construye en el servidor
con lecturas cerradas (incidente, activos, detecciones, evidencias de las dos principales,
alertas, riesgo, notas y actividad); las notas viajan como **datos**. Las referencias se
validan como en 4J (I/N/D/E/A… → ids reales; inventadas → descartadas o 502
`ai_ungrounded_response`). La IA **nunca** cambia estado, owner, severidad, prioridad,
resolución, cierre ni fusión: el resultado es solo un insight (`ai_insights.incident_id`).
Con la IA desactivada (por defecto) todo el flujo funciona igual.

## Concurrencia

Cada mutación de campos lleva `version`. El servicio bloquea la fila (`SELECT … FOR UPDATE`),
compara y, si no coincide, responde **409 `incident_conflict`** con
`details: [{incident_id, current_version, status, updated_at, updated_by}]`. La UI muestra
quién lo cambió y un botón Recargar; nunca reintenta ni sobrescribe en silencio. La fusión
bloquea ambos casos en orden de id (sin deadlocks). Notas y adjuntos no cambian la versión.

## RBAC

| Permiso | viewer | analyst | admin |
|---------|:------:|:-------:|:-----:|
| `incidents:read` (listar, ver, timeline, evidencia, notas, auditoría del caso, relacionados) | ✓ | ✓ | ✓ |
| `incidents:manage` (crear, promover, PATCH, asignar, notas, adjuntar, resolver) | | ✓ | ✓ |
| `incidents:admin` (cerrar, reabrir, fusionar, asignar a otros) | | | ✓ |

Se aplica en el backend (`require_permission`, con CSRF en mutaciones); la UI solo oculta
botones.

## Auditoría

`audit_events` con `target_type="incident"`: `incident_created`, `incident_updated`,
`incident_status_changed`, `incident_assigned`, `incident_unassigned`, `incident_note_added`,
`incident_detection_attached`, `incident_alert_attached`, `incident_resolved`,
`incident_closed`, `incident_reopened`, `incident_merged`. Los intentos fallidos se auditan
con `result=failure`. `GET /incidents/{id}/audit` los lista (índice
`ix_audit_events_target`).

## API

| Método | Ruta | Permiso |
|--------|------|---------|
| GET | `/incidents?status=&active=&severity=&priority=&owner=me\|unassigned\|<uuid>&asset_id=&since=&until=&q=&sort=&order=&limit=&offset=` | read |
| GET | `/incidents/overview` (Abiertos, Triage, Investigando, Contenidos, Críticos, Sin asignar, Asignados a mí, edad media observada, actividad reciente) | read |
| GET | `/incidents/assignees` | manage |
| GET | `/incidents/{id}`, `/timeline`, `/evidence`, `/notes`, `/audit` | read |
| GET | `/detections/{id}/related-incidents`, `/alerts/{id}/related-incidents` | read |
| POST | `/incidents`, `/detections/{id}/incident`, `/alerts/{id}/incident` | manage |
| PATCH | `/incidents/{id}` | manage |
| POST | `/incidents/{id}/assign`, `/unassign`, `/notes`, `/resolve` | manage |
| POST | `/incidents/{id}/detections/{did}`, `/alerts/{aid}`, `/assets/{asset_id}` | manage |
| POST | `/incidents/{id}/close`, `/reopen`, `/merge` | admin |
| POST | `/ai/incidents/{id}/analyze` | read + `ai:use` |

`q` busca por número (`INC-000123`, `123`), título, hostname/nombre/IP de sus activos y título
de sus detecciones. `sort` solo admite `last_activity`, `created_at`, `severity`, `priority`,
`status`, `number` (mapa explícito; nunca SQL con texto del usuario). Las métricas de tiempo
(`age`, `time_to_triage`, `time_to_resolve`) son datos observados, no SLA.

## UI

- Navegación **Incidentes** (con `incidents:read`).
- Lista: tarjetas Abiertos / Triage / Investigando / Críticos / Sin asignar / Asignados a mí
  (filtran el listado), tabla con número, título, severidad y prioridad por separado,
  estado, responsable, activos y actividad; filtros, búsqueda, orden y paginación en servidor.
- Detalle: pestañas Resumen, Timeline, Evidencia, Detecciones, Activos (enlazan al detalle de
  activo existente), Notas, AI Insights y Auditoría; acciones según rol y estado; banner de
  conflicto 409.
- Detección y alerta: panel "Incidentes" con sugerencias, Adjuntar y Crear incidente.
- Dashboard: panel compacto de incidentes activos y actividad reciente (sin rediseño ni MTTR).

## Migración 0022

Solo añade (tablas, enums, secuencia, `ai_insights.incident_id`, índice de auditoría). Probada
`upgrade → downgrade 0021 → upgrade` con datos existentes (`tests/test_incidents.py`).
**El downgrade pierde**: todos los incidentes, relaciones, notas, actividad, feedback y la
numeración INC, y los insights de IA de tipo `incident_*`. Conserva la auditoría.

## Rendimiento

`qa/perf_incidents.py` (datos sintéticos; 10 000 incidentes, 50 000 relaciones, 100 000
elementos de actividad y 10 000 notas). Medido en el contenedor de desarrollo (PostgreSQL 16,
mediana de 5):

| Lectura | ms | SQL/petición |
|---------|---:|:------------:|
| overview | 11 | 3 |
| listado (por actividad, filtros, estado, sin asignar, página 100) | 8–10 | 3 |
| búsqueda INC / hostname / IP / título de detección | 67–86 | 3 |
| detalle | 25 | 11 |
| timeline página 1 / 2 | 9.5 | 4 |
| evidencia | 16 | 8 |
| notas | 4 | 4 |
| relacionados (detección) | 34 | 9 |

Sentencias constantes por petición (sin N+1). La búsqueda de texto usa `ILIKE` sobre el
título (sin pg_trgm): con muchos más casos convendría un índice trigram.

## Limitaciones conocidas

- Sin SLA, MTTR, playbooks ni respuesta automática (decisión de producto).
- El feedback de falsos positivos se guarda pero aún no ajusta nada (solo informa).
- La búsqueda de texto recorre títulos con `ILIKE` (ver Rendimiento).
- La UI sondea cada 15 s; no hay actualización en vivo (WebSockets/SSE).
