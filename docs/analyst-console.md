# Analyst Console (Fase 7B.4)

Consola de investigación construida **encima del Analyst Tool Engine de 7A**
(`docs/analyst-tool-engine.md`). No hay un segundo motor: cada consulta y cada acción es una
ejecución de una herramienta del catálogo 7A. Por eso conserva RBAC, el aislamiento por site,
los límites de concurrencia, la idempotencia, las cuotas, los plazos y el historial auditado.

Ruta de la UI: **Seguridad → Consola** (`/console`, requiere `tools:read`). Código:
`frontend/src/pages/ConsolePage.tsx` y `frontend/src/components/console/`.

## Qué no hace

- No ejecuta PowerShell, comandos del sistema, SQL libre ni scripts del usuario. El formulario
  solo rellena los campos que declara el JSON Schema cerrado de cada herramienta
  (`extra=forbid`), y el servidor vuelve a validarlo todo.
- No depende de la IA. La IA de 4J sigue siendo opcional y aparte; 7B no adelanta 7C.
- No interpreta la salida como HTML. Todo se pinta como texto (test con
  `<script>alert(1)</script>`).

## Funciones

| Función | Cómo |
|---|---|
| 1. Buscar | `GET /search?q=` (nuevo, `monitoring:read`). Ver detalle debajo de la tabla. |
| 2. Workspace | `?asset=<id>` o `?detection=<id>` en la URL: nombre de la entidad, atajos y enlaces a su ficha. Se abre desde la búsqueda, desde Red → Dispositivos («Investigar en la consola») o pegando la URL. |
| 3. Catálogo | `GET /tools`, agrupado por categoría (lectura, investigación, acción), con disponibilidad y permiso de cada herramienta. |
| 4. Herramientas de lectura | Formulario generado del `input_schema`; `POST /tools/{id}/execute`. |
| 5. Resultados y evidencias | Estado, duración, resumen, salida en tablas, hash de entrada y salida, truncado. |
| 6. Timelines | Herramienta `timeline.build` (7A). |
| 7. Relaciones | `detections.related` (nueva): detecciones del mismo script por hash, del mismo servicio o de la misma correlación, en cualquier activo. `attribution.explain` (nueva): veredicto 7B.1 con sus comprobaciones. `identity.candidates` (nueva): perfil de identidad y posibles duplicados. Más las de 7A (árbol de procesos, servicios, persistencia). |
| 8. Evidencias a casos | «Añadir al caso…»: `case.link_evidence` con vista previa y confirmación. |
| 9. Responsables y tareas | En el mismo diálogo, tarea «Analizar evidencia» con responsable (`/incidents/assignees`) y la evidencia adjunta (API de 7A.7). |
| 10. Historial | Últimas 20 ejecuciones (`GET /tools/executions`): estado, errores y quién las lanzó. La auditoría completa está en Administración → Auditoría. |
| 11. Preparar acciones | Las herramientas `preview_confirm` solo se lanzan con `POST /tools/{id}/preview`, que muestra efectos, bloqueos y avisos. |
| 12. Confirmación humana | «Confirmar y ejecutar» envía `{version, confirm: true, note}` a `/tools/executions/{id}/confirm`. «Descartar» cancela la vista previa. |

Detalle de la búsqueda (función 1):

- Detecta lo que se pega: IP, MAC (con dos puntos o guiones), SHA-256, id de regla
  (`SCR-001`), número de caso (`INC-12`) o texto.
- Busca activos, detecciones, casos y operaciones de mantenimiento (por hash).
- Los usuarios de Sentra solo aparecen para quien tiene `incidents:manage`, el mismo criterio
  que `/incidents/assignees`. Para un viewer `users_visible = false`.
- Como mucho 10 resultados por grupo, con LIKE escapado: `%` y `_` no son comodines.
- Respeta el site seleccionado. Los casos no son de un site y se buscan siempre.

Las acciones nunca aparecen como atajo: siempre pasan por el catálogo y su vista previa.

## Herramientas nuevas en el catálogo (7B)

| Id | Categoría | Entrada | Lee |
|---|---|---|---|
| `attribution.explain` | read | `detection_id` | Veredicto, comprobaciones, evidencia que falta y cómo obtenerla, operación aplicada e historial |
| `detections.related` | investigation | `detection_id` | Claves causales de la detección y detecciones que las comparten (con `shared`) |
| `identity.candidates` | read | `asset_id` | Perfil de identidad 7B.2 y candidatos con evidencia |

Ninguna escribe. Todas respetan el site del activo y los permisos del motor (`tools:execute`).

## Permisos

| Rol | Puede |
|---|---|
| viewer | Buscar (sin usuarios), ver el catálogo y el historial. No ejecuta; la UI lo dice. |
| analyst | Ejecutar lecturas e investigaciones, preparar acciones permitidas a su rol, añadir evidencias, crear tareas y asignarlas. |
| admin | Todo lo anterior y las acciones restringidas a admin del catálogo 7A. |

## Extensiones de la API documentadas

- `GET /search` (nuevo).
- Herramientas `attribution.explain`, `detections.related` e `identity.candidates` (nuevas en
  el catálogo, mismos endpoints de 7A).
- Ninguna ruta de 7A cambia de contrato.
