# Selectores contextuales (Fase 7C.3)

En Sentra nadie tiene que teclear un identificador interno. Donde un formulario necesita un
activo, una detección o un caso, el usuario escribe lo que reconoce (nombre, etiqueta, IP, MAC,
regla, número de caso...) y elige de una lista. El id público se resuelve en el selector y es
lo único que viaja a la API, que sigue validando permisos y alcance como siempre.

## API: `GET /api/v1/lookup/{kind}`

`kind` = `asset`, `detection` o `incident`.

| Parámetro | Uso |
| --- | --- |
| `q` | Texto a buscar (1-128 caracteres) |
| `ids` | Repetible (hasta 20): devuelve la etiqueta de ids ya conocidos, p. ej. los de un enlace `?asset=<id>` |
| `site_id` | Limita al site elegido (activos y detecciones) |
| `limit` | 1-20, por defecto 8 |
| `include_archived` | Incluye activos archivados (por defecto no) |

Respuesta (`LookupResult`):

```json
{
  "kind": "asset",
  "query": "10.0.0.10",
  "resolution": "ambiguous",
  "items": [
    {
      "kind": "asset", "id": "<uuid>", "label": "pc-ventas",
      "secondary": "10.0.0.10 · Principal", "match_field": "ip", "exact": true,
      "archived": false, "site_name": "Principal", "ip": "10.0.0.10", "mac": null,
      "device_type": "workstation", "status": "online", "severity": null,
      "asset_id": null, "asset_label": null, "last_seen_at": "..."
    }
  ],
  "truncated": false
}
```

`resolution`:

- `exact`: una sola coincidencia exacta;
- `ambiguous`: varias coincidencias exactas (dos equipos con el mismo nombre o la misma IP en
  sites distintos). **La UI nunca elige sola**: muestra «Varias coincidencias exactas: elige la
  correcta»;
- `partial`: solo coincidencias parciales;
- `none`: nada.

Qué se compara:

| Tipo | Exacto | Parcial |
| --- | --- | --- |
| Activo | IP, MAC (cualquier formato), etiqueta personalizada, nombre, hostname, DNS inverso | Empieza por / contiene en los mismos campos, IP por prefijo, etiquetas administrativas, modelo |
| Detección | Título; id de regla (`SCR-001`) lista todas las de esa regla | Título, regla por prefijo, nombre o IP del activo («las detecciones de PC-14») |
| Caso | `INC-12`, `#12` o `12` (número) y título exacto | Título |

No es un lenguaje de consulta: el texto se compara por igualdad o con `LIKE` escapado contra
columnas conocidas, con tope de resultados. Sin efectos y sin auditoría, igual que los
listados y la búsqueda global.

Permisos: activos y detecciones con `monitoring:read`; casos con `incidents:read` (403 si
falta). Los casos no pertenecen a un site y se buscan siempre, como en la búsqueda global.

## Componentes de la UI

- `EntityPicker` (`frontend/src/components/lookup/EntityPicker.tsx`): combobox accesible
  (WAI-ARIA 1.2) con flechas, Intro y Escape; espera 250 ms entre pulsaciones; cada opción
  dice si la coincidencia es exacta o parcial y en qué campo. Un id pegado tal cual se resuelve
  directamente. Elegido, se muestra como ficha con el nombre y el botón «Cambiar». Un id que
  llega de fuera (URL, workspace) se muestra con su nombre; si no existe o no hay acceso, lo
  dice.
- `EntityMultiPicker`: varios elementos como fichas con «Quitar» y un selector para añadir;
  no duplica.

## Dónde se usa

| Pantalla | Campo |
| --- | --- |
| Analyst Console | Workspace (activo o detección) y los campos `asset_id`, `detection_id` e `incident_id` de cualquier herramienta del catálogo |
| Informes | Alcance por activos, casos y detecciones (los enlaces `?incident_id=` se ven con su número y título) |
| Casos › Tareas › Evidencia | Evidencia de tipo detección o activo |
| Detecciones › Excepciones | Equipo al que se limita la excepción |
| Activo › Ciclo de vida › Reconciliar | Otro activo existente, además de los candidatos sugeridos (mismo site) |

Mantenimiento, creación de casos, Response, Playbooks, identidad y Wi-Fi ya usaban la búsqueda
por nombre con lista desplegable de la Fase 7B (`useAssetOptions`), sin ids tecleados; se
mantienen. Quedan como identificador los campos que no son entidades buscables: ids de
ejecuciones y playbooks en informes, y evidencia de tipo alerta o resultado de herramienta en
las tareas del caso.

## Limitaciones

- La búsqueda de detecciones y casos no usa índices de texto completo; con el tope de 20 y
  orden por recencia es suficiente para el volumen esperado de un SOC pequeño o mediano.
- Un activo archivado solo aparece con `include_archived=true` (la reconciliación y las
  excepciones no lo piden).
