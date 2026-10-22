# Motor de topología de red (Fase 6D)

> Estado: contrato de la Fase 6D implementado en el backend (6D.1: `app/topology/`). Los
> nombres de campos, endpoints y códigos de error de este documento son el contrato que usan
> el frontend y los informes v2. Las precisiones de la implementación están al final
> ("Detalle de implementación").

## Principios

- **Sin inventario duplicado.** Los nodos no se guardan: son referencias a activos, equipos de
  red (`network_devices`), puntos de acceso WLAN (`wlan_access_points`) o identidades remotas
  sin resolver (`external`). Nombre, etiqueta, riesgo y criticidad se leen del inventario.
- **Solo evidencia verificable.** Persistimos ENLACES derivados de evidencia (`topology_links`),
  cada uno con clase, medio, relación, confianza y evidencia acotada.
- **Nunca** se crea un enlace físico porque dos equipos compartan subred o gateway. Compartir
  red es agrupación visual (grupos), no un enlace.
- **Aislamiento por site.** Los dos extremos de un enlace son del mismo site. Una MAC o IP
  privada repetida en dos sites no se cruza. Una MAC que coincide con varios activos del
  mismo site (duplicados) no crea enlace (se cuenta en `ambiguous_macs`).
- **Sin fusiones.** El motor nunca fusiona activos duplicados ni cambia identidades.
- **Sin borrados por ausencia.** Un enlace que deja de derivarse queda `present=false` con su
  historial (`first_seen_at`, `last_seen_at`). El historial temporal y la detección avanzada de
  cambios son de la Fase 6E.
- **Funciona sin SNMP.** Sin LLDP/CDP ni tablas de switches el grafo muestra lo que haya
  (gateways de agentes, WLAN, grupos por red) y nunca inventa enlaces.

## Clases de enlace (`kind`)

| kind | Qué demuestra | Ejemplos (`relation`) |
| --- | --- | --- |
| `physical` | Adyacencia física informada por un protocolo de enlace | `lldp`, `cdp` |
| `logical` | Relación de capa 3 o de gestión informada por una fuente; no implica cable directo | `default_gateway` (agente), `wlan_managed_by` (controladora → AP) |
| `observed` | Un equipo de red ve directamente al otro extremo | `fdb_edge` (MAC única en puerto de acceso), `wlan_association` |
| `candidate` | Evidencia compatible pero no concluyente | `fdb_shared` (puerto de acceso con varias MACs) |
| `unknown` | Hay relación pero no se sabe su naturaleza | `fdb_unmapped` (puerto de bridge sin interfaz resuelta) |

`medium`: `wired`, `wireless`, `unknown`. `confidence`: `high`, `medium`, `low`.

Reglas de derivación (por site, en una reconstrucción):

1. **LLDP/CDP** (`network_neighbors.present`): extremo local = nodo del equipo (o de su activo
   si `network_devices.asset_id`). Remoto: `remote_device_id`; si no, activo del MISMO site por
   dirección de gestión o MAC de chasis (solo si coincide con UN activo); si no, nodo
   `external` (clave determinista por chasis, si no sysName). Recíproco → `high`; resuelto
   sin reciprocidad → `medium`; remoto externo → `medium` (la adyacencia la informa el
   equipo, la identidad remota es desconocida). Ambos sentidos LLDP de un mismo cable son UN
   enlace (clave con extremos ordenados).
2. **Tabla MAC** (`network_mac_entries.present`, MAC de UN activo del mismo site):
   `location=edge_candidate` y el puerto tiene 1 MAC → `observed/fdb_edge` `medium`; con más
   MACs → `candidate/fdb_shared` `low`; `uplink_or_shared` → ningún enlace (un uplink ve todo
   lo que hay detrás); `unknown` → `unknown/fdb_unmapped` `low` solo si esa MAC no tiene otro
   enlace en el site.
3. **WLAN**: cliente presente con `asset_id` y AP resuelto → `observed/wlan_association`,
   `wireless`; `identity_confidence=confirmed` → `high`, `probable` → `medium`,
   `observation_only` → sin enlace. AP gestionado por una controladora registrada
   (`source_device_id`) → `logical/wlan_managed_by` `high`.
4. **Gateways de agentes** (`asset_inventories.data.network.gateways`): si el gateway es la
   IP de UN activo o equipo de red del mismo site → `logical/default_gateway` `medium` (`high`
   si el equipo de red informa `ip_forwarding=true`). Nunca `physical`.
5. **ARP, DNS, mDNS, NetBIOS, SSDP, OUI**: alimentan la identidad del nodo (nombre, fabricante,
   tipo) y la pertenencia a redes, nunca enlaces.

Grupos (`groups`): redes autorizadas del site (`site_networks`, habilitadas) que contienen la
IP principal del nodo; si ninguna la contiene, el grupo `unassigned`.

## Modelo

`topology_links` y `topology_builds` (migración 0038, ver `app/models/topology.py`).
Claves de nodo: `asset:<uuid>`, `network_device:<uuid>`, `wlan_ap:<uuid>`,
`external:<hex16>`. Un equipo de red con `asset_id` se representa SOLO como `asset:<uuid>`.

## Permisos

- Leer grafo, enlaces, nodos y estado: `monitoring:read` (todos los roles).
- Reconstruir y revisar enlaces: `topology:manage` (solo admin). Intentos sin permiso
  auditados por `require_permission`.

## API (`/api/v1/topology`)

Todas las respuestas usan el sobre de error de Sentra. `site_id` es opcional; sin él se usa el
site por defecto (`resolve_site`). Site inexistente → 404 `site_not_found`.

### `GET /topology/graph`

Query: `site_id` (uuid), `kinds` (lista separada por comas de kind, ≤100; por defecto todos;
un valor desconocido → 422 `topology_invalid_kind`),
`include_absent` (bool, false), `include_rejected` (bool, false), `device_type` (str ≤32),
`q` (str 1-100: IP, nombre, etiqueta o MAC; filtra nodos y deja sus enlaces).

```json
{
  "site": {"id": "uuid", "name": "Local"},
  "generated_at": "2026-10-21T10:00:00Z",
  "last_build": {"id": "uuid", "status": "succeeded", "trigger": "manual",
                  "started_at": "...", "finished_at": "...", "counts": {"links_present": 4}} ,
  "truncated": false,
  "limits": {"max_nodes": 1500, "max_links": 5000},
  "nodes": [{
    "id": "asset:uuid",
    "kind": "asset",
    "label": "Router oficina",
    "automatic_name": "archer-gx90",
    "custom_label": "Router oficina",
    "asset_id": "uuid",
    "network_device_id": null,
    "ip": "192.168.50.1",
    "mac": "AA:BB:CC:DD:EE:FF",
    "vendor": "TP-Link",
    "device_type": "router",
    "role": "infrastructure",
    "status": "online",
    "managed": false,
    "risk_score": 12,
    "risk_level": "low",
    "criticality": "high",
    "groups": ["network:192.168.50.0/24"],
    "sources": ["discovery", "snmp"],
    "identity_confidence": "medium",
    "link_count": 3
  }],
  "links": [{
    "id": "uuid",
    "source": "network_device:uuid",
    "target": "asset:uuid",
    "kind": "observed",
    "medium": "wired",
    "relation": "fdb_edge",
    "confidence": "medium",
    "source_port": "Gi1/0/3",
    "target_port": null,
    "evidence_sources": ["fdb"],
    "present": true,
    "first_seen_at": "...",
    "last_seen_at": "...",
    "last_evidence_at": "...",
    "review_state": "unreviewed"
  }],
  "groups": [{"id": "network:192.168.50.0/24", "kind": "network", "cidr": "192.168.50.0/24",
              "name": "LAN", "node_count": 12}]
}
```

- `last_build` es null si el site nunca se reconstruyó.
- `role`: `infrastructure` (router, switch, AP, firewall, equipo de red), `endpoint` o
  `unknown`. `status`: estado del activo (`online`, `offline`, `stale`...) o null.
- `identity_confidence`: `high` (agente o etiqueta manual), `medium`, `low`, `none`.
- Nodos `external`: `label` = sysName/chasis remoto informado, el resto de campos null,
  `sources=["lldp"]` o `["cdp"]`.
- Orden determinista: nodos por `id`, enlaces por `id` de enlace. Si se supera un límite,
  `truncated=true` y se priorizan los nodos con enlaces y la infraestructura.

### `GET /topology/links`

Query: `site_id`, `kind`, `confidence`, `node` (clave de nodo), `present` (bool, por defecto
true), `review_state`, `limit` (1-200, 50), `offset` (0-1 000 000).
Respuesta: `{"items": [TopologyLink], "total": int, "limit": int, "offset": int}`.

### `GET /topology/links/{link_id}`

Query opcional `site_id`: si se indica, un enlace de otro site es 404. Sin él no se aplica el
site por defecto (el UUID del enlace ya identifica su site y todos los roles leen todos los
sites); lo mismo para `PATCH .../review`.
`TopologyLink` + `evidence: [{"source": "lldp", "detail": "...", "observed_at": "..."}]`,
`target_external` (datos informados del remoto externo, o null), `review_note`,
`reviewed_by`, `reviewed_at`, `version`. 404 `topology_link_not_found`.

### `PATCH /topology/links/{link_id}/review` (`topology:manage`)

Cuerpo `{"review_state": "accepted"|"rejected"|"unreviewed", "note": str|null (≤500, sin
caracteres de control), "version": int}`. 409 `topology_link_conflict` si la versión cambió.
La revisión no cambia `kind` ni `confidence` (un humano no convierte un candidato en un
enlace físico); un enlace `rejected` se oculta del grafo por defecto. Auditado
`topology_link_reviewed`.

### `GET /topology/nodes/{node_id}`

Detalle de un nodo: el nodo (forma de `nodes[]`), `links` (sus enlaces presentes, máx. 200),
`observed_names` (del activo, si lo es) y `inventory_path` (ruta del frontend al detalle del
activo o equipo, p. ej. `/assets/<uuid>`). 404 `topology_node_not_found`; un nodo de otro
site o una clave mal formada → 404 (sin distinguir, evita enumerar).

### `POST /topology/rebuild` (`topology:manage`)

Cuerpo `{"site_id": "uuid"|null}` (null = site por defecto). Reconstruye en la petición
(acotado por `TOPOLOGY_MAX_LINKS`) y responde 200. 409 `topology_build_running` si ya hay una
en curso para el site. Un fallo interno responde 500 `topology_build_failed` (sin traza) y
queda registrado como build `failed` con `error_code=build_failed`.
Respuesta: `TopologyBuild` (`id`, `site_id`, `status`, `trigger`, `requested_by`,
`started_at`, `finished_at`, `duration_ms`, `counts`, `error_code`). Auditado
`topology_rebuilt`.

### `GET /topology/status`

Query `site_id`. `{"site": {...}, "last_build": TopologyBuild|null, "links_present": int,
"links_by_kind": {"physical": 0, ...}, "evidence_available": {"lldp_cdp": bool, "fdb": bool,
"wlan": bool, "agent_gateways": bool}}` para que la UI explique por qué el grafo está vacío.

## Configuración (opcional, fijada en `tests/conftest.py`)

- `TOPOLOGY_REBUILD_INTERVAL_MINUTES` (15; 0 desactiva la reconstrucción periódica).
- `TOPOLOGY_MAX_NODES` (1500), `TOPOLOGY_MAX_LINKS` (5000).

## Integración con informes v2

`app.topology.service.report_topology(session, site_id, asset_ids=None, max_nodes=60)` devuelve
solo enlaces presentes, no rechazados y de clase `physical`, `logical` u `observed`:

```json
{"nodes": [{"id": "...", "label": "...", "kind": "asset", "device_type": "router",
            "role": "infrastructure"}],
 "links": [{"source": "...", "target": "...", "kind": "physical", "relation": "lldp",
            "confidence": "high"}],
 "truncated": false, "built_at": "..."|null}
```

## Detalle de implementación (6D.1)

### Código

- `app/topology/builder.py`: derivación PURA (`derive_links(Snapshot, max_links)`) sobre
  dataclasses inmutables ya leídas. Sin sesión de base de datos: cada regla se prueba sin
  PostgreSQL (`tests/test_topology_builder.py`) y el resultado es determinista (mismas filas
  en cualquier orden → mismos enlaces en el mismo orden: clase y luego clave).
- `app/topology/service.py`: `load_snapshot()` (una consulta por tabla, solo columnas
  necesarias, todo filtrado por `site_id` en SQL; del inventario del agente solo se lee la
  ruta JSON `network.gateways`), `TopologyService` (reconstrucción y lecturas),
  `run_scheduled_rebuilds()` (job periódico) y `report_topology()`.
- `app/topology/errors.py`: `topology_link_not_found`, `topology_node_not_found`,
  `topology_build_failed`. Los 409 usan `SiteConflictError` con su código.
- `app/api/v1/routes/topology.py`: router fino; `app/schemas/topology.py`: contratos
  (`TopologyGraph`, `TopologyNode`, `TopologyLink`, `TopologyLinkDetail`, `TopologyLinkList`,
  `TopologyGroup`, `TopologyNodeDetail`, `TopologyBuild`, `TopologyStatus`,
  `TopologyReviewUpdate`, `TopologyRebuildRequest`).

### Clave de enlace y fusión

`link_key` = SHA-256 hex de `clase | familia | (nodo, puerto) ordenados`. Los puertos se
normalizan (minúsculas, espacios colapsados). Consecuencias:

- Los dos sentidos LLDP de un cable son una sola fila. Se emparejan si alguno informa del
  puerto del otro (por nombre de puerto local, ifName, ifDescr o ifAlias) o, si solo hay un
  sentido inverso y no hay puertos que lo contradigan, por ser el único. Emparejados, cada
  extremo usa su propio puerto local y el origen es el extremo con la clave menor.
- LLDP y CDP del mismo cable comparten familia (`link_layer`) y se fusionan en una fila:
  `relation=lldp` si alguno es LLDP, `evidence_sources=["cdp","lldp"]`.
- Un enlace unilateral usa el puerto remoto informado; si más tarde aparece el sentido
  inverso con otro nombre de puerto, la clave cambia: la fila antigua queda `present=false` y
  nace otra (historial, nunca borrado).
- Evidencia: como mucho 8 entradas por enlace, `detail` ≤255 caracteres; confianza = la mayor
  de las evidencias fusionadas; `last_evidence_at` = la más reciente.

### Precisiones de las reglas

- **Nodos**: un AP WLAN vinculado a un equipo (`network_device_id`) o a un activo se
  representa con el nodo de ese equipo/activo (como un equipo de red con `asset_id`): ningún
  dispositivo aparece dos veces. Pedir `network_device:<uuid>` de un equipo que es activo
  responde 404 (la clave canónica es `asset:<uuid>`).
- **LLDP remoto**: `remote_device_id` del site → su nodo; si apunta a un equipo que no está
  en el site se cuenta en `skipped_cross_site` y se sigue con la resolución local. Dirección
  de gestión: equipo de red con esa IP o UN activo. Chasis: equipo con ese `lldp_chassis_id`
  o `base_bridge_address`, o UN activo con esa MAC; varios activos → `ambiguous_macs` y nodo
  externo. Clave externa: `external:` + 16 hex de SHA-256 del chasis (MAC normalizada), si no
  del sysName en minúsculas; sin ninguno, de la observación.
- **FDB**: el número de MACs de un puerto se cuenta con las entradas presentes del propio
  puerto (`interface_id`, o el puerto de bridge si no se resolvió). Si LLDP/CDP ya da un
  enlace físico entre los mismos dos nodos, la tabla MAC no añade otro (sería redundante y
  más débil). `fdb_unmapped` solo si el activo no tiene ningún otro enlace en el site.
- **WLAN**: un cliente o AP que apunta a un activo/AP de otro site cuenta en
  `skipped_cross_site`. El AP que es el propio equipo consultado no crea `wlan_managed_by`.
- **Gateways**: IP normalizada; los candidatos son el equipo de red con esa dirección y los
  activos con esa IP, deduplicados por nodo (un equipo con activo es un único candidato).
  Más de un candidato → sin enlace.
- **Límite**: si se derivan más de `TOPOLOGY_MAX_LINKS`, se guardan los primeros por (clase,
  clave) y el resto se cuenta en `counts.links_dropped`.

### Reconstrucción

- Toda la reconstrucción de un site ocurre en UNA transacción que toma antes
  `pg_try_advisory_xact_lock(TOPOLOGY_SITE_LOCK_BASE + site_id)` (`app/db/locks.py`). Sin el
  lock → 409 `topology_build_running` (también para el job: salta ese site). El lock muere con
  la transacción, así un proceso caído no deja el site bloqueado. Por eso el estado
  `running` no llega a verse desde fuera: la fila se confirma ya `succeeded`; el índice único
  parcial sobre `running` queda como defensa en profundidad.
- Upsert por `(site_id, link_key)` sobre todas las filas del site (presentes y ausentes):
  las derivadas quedan `present=true`, `last_seen_at=ahora`, `last_evidence_at` de la
  evidencia; las nuevas nacen con `first_seen_at=ahora` y `unreviewed`; las no derivadas
  quedan `present=false` (sin borrar). `review_state`, `review_note`, `reviewed_*` nunca se
  tocan al reconstruir.
- `version` sube solo con un cambio material (clase, relación, confianza, medio, extremos o
  presencia): la actualización de `last_seen_at` de cada vuelta no da 409 a un revisor.
- `counts` (claves fijas): `links_created`, `links_updated` (cambio material, incluida la
  reaparición), `links_absent` (pasaron a ausentes en esta vuelta), `links_present`,
  `links_dropped`, `nodes` (nodos del site + externos), `ambiguous_macs`,
  `skipped_cross_site`.
- Error interno: rollback, fila `failed` con `error_code=build_failed`, auditoría `failure`
  si era manual, 500 `topology_build_failed`. La traza solo va al log.
- Job `topology-builder` (`app/services/background.py`, lock `_BASE + 17`): despierta cada
  60 s y reconstruye los sites activos (no archivados) cuya última reconstrucción, de
  cualquier tipo y resultado, es más antigua que `TOPOLOGY_REBUILD_INTERVAL_MINUTES`. Con 0
  no se registra el job. Las reconstrucciones periódicas no se auditan (quedan en
  `topology_builds`); las manuales sí (`topology_rebuilt`).

### Lecturas

- Nodos: activos no archivados del site, equipos de red activos sin activo, APs sin equipo ni
  activo y externos presentes en los enlaces devueltos. Un enlace cuyo extremo ya no es nodo
  (p. ej. activo archivado después de la última reconstrucción) no se muestra.
- Campos: `label` = `display_name` del activo (etiqueta personalizada, nombre resuelto,
  hostname, DNS inverso o la IP); `mac` en minúsculas `aa:bb:cc:dd:ee:ff` (formato del resto
  de la API). `sources`: `agent` (activo con agente), `discovery`, `snmp` (equipo de red),
  `wlan` (AP), `lldp`/`cdp` (externo). `identity_confidence`: `high` con agente o etiqueta
  manual; si no, la confianza de clasificación del activo o del equipo (`none` sin ella); AP
  `medium`; externo `none`. `risk_*` solo si el Risk Engine ya lo calculó.
- `q` busca (sin distinguir mayúsculas, por subcadena) en etiqueta, nombre resuelto,
  hostname, DNS inverso, IP, MAC (acepta `-` o `:`) y nombre/sysName del equipo; `q` y
  `device_type` devuelven los nodos que coinciden, sus enlaces y los extremos de esos enlaces.
- Grupos: todas las redes habilitadas del site que contienen la IP del nodo; sin ninguna (y
  los externos), `unassigned`.
- Truncado: enlaces ordenados por presentes, clase e id hasta `TOPOLOGY_MAX_LINKS`; nodos
  priorizados (con enlaces, infraestructura, id) hasta `TOPOLOGY_MAX_NODES`; nunca queda un
  enlace con un extremo fuera.
- `inventory_path`: `/assets/<uuid>`, `/network?device=<uuid>`,
  `/network?access_point=<uuid>` o null (externo).
- `GET /topology/nodes/{node_id}` y `GET /topology/links/{link_id}` reciben el id como texto:
  uno mal formado responde el mismo 404 que uno inexistente o de otro site.

### Informes v2

`report_topology(session, site_id, asset_ids=None, max_nodes=60)`: `site_id` y los
`asset_ids` admiten id interno (int) o UUID público. Con `asset_ids`, solo los enlaces que
tocan esos activos (filtrado en Python sobre los enlaces del site, sin listas IN gigantes).
Los nodos son los extremos de esos enlaces, priorizando infraestructura y grado; si superan
`max_nodes`, `truncated=true` y se descartan los enlaces con un extremo fuera. `built_at` =
fin de la última reconstrucción correcta (ISO 8601) o null. Orden determinista.
