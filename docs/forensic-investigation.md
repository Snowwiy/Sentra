# Investigación forense remota (Fase 6E.6)

Recogida de evidencia de solo lectura desde el agente 0.5.0, organizada en investigaciones,
con SHA-256 verificado por el servidor, notas de interpretación separadas de la evidencia y
paquetes ZIP con manifiesto y cadena de custodia.

No hay shell, ni scripts, ni ejecución de nada en el equipo: cada recogida es una acción
cerrada del catálogo de Response (5D) que el agente vuelve a validar con su propia allowlist.

## Modelo

| Tabla (migración 0042) | Qué guarda |
|---|---|
| `investigations` | Caso por activo (título, estado `open`/`closed`, `legal_hold`, incidente opcional, quién y cuándo). Copia el id y el nombre del activo: sigue legible si el activo se borra. |
| `forensic_artifacts` | Una evidencia por recogida: acción, alcance (parámetros), operador, agente, `agent_sha256`, `sha256` recalculado, `integrity` (`verified`/`mismatch`), tamaño, contenido, `truncated`, limitaciones, versión y plataforma del agente, `collected_at`, `received_at`. |
| `investigation_notes` | Interpretaciones (`note` o `ai_summary`). Nunca se mezclan con la evidencia. |
| `evidence_packages` | Cada ZIP generado: SHA-256, tamaño, nº de artefactos, si incluía artefactos `mismatch`, quién y cuándo. |
| `response_executions.investigation_id` | Recogida (ejecución de Response) ligada a su investigación. |

El contenido se guarda como el JSON canónico exacto recibido (texto, no JSONB). JSONB reordena
claves y normaliza números, y entonces el hash ya no se podría volver a comprobar.

## Acciones

Todas son `scope=agent`, categoría `forensic`, y exigen una investigación abierta del mismo
activo (bloqueo `investigation_required`, `investigation_closed` o `investigation_mismatch`).

| Acción | Riesgo | Parámetros |
|---|---|---|
| `forensic_processes`, `forensic_connections`, `forensic_services`, `forensic_persistence`, `forensic_sessions`, `forensic_network_config`, `forensic_firewall_state` | low | ninguno |
| `forensic_scheduled_tasks` | low | ninguno (Windows y Linux; el agente no lo anuncia en macOS) |
| `forensic_file_metadata` | medium (solo admin, confirmación) | `{"path": str, "hash": bool}` |

`path` se valida en el servidor (absoluta, local, sin UNC, sin `..`, sin flujos alternativos,
sin caracteres de control, y con el estilo de la plataforma del activo: `path_platform_mismatch`)
y otra vez en el agente contra `forensics.allowed_roots` de su configuración local, que el
servidor no puede ampliar (`path_not_allowed`). Nunca se devuelve el contenido del fichero.

Las acciones forenses y de aislamiento no se pueden usar como pasos de playbook
(`playbook_action_not_allowed`).

## Flujo

1. `POST /api/v1/investigations` `{asset_id, title, incident_id?}` (forensics:acquire).
2. `POST /api/v1/response/executions` con `action_id` forense, `target_id` = activo e
   `investigation_id`. Misma política de 5D: agente activo y en línea, capacidad anunciada,
   plataforma, máximo de ejecuciones activas, permisos. El anti-duplicado incluye la
   investigación y los parámetros: dos casos distintos no se pisan.
3. El agente recoge, calcula `sha256` del JSON canónico
   (`json.dumps(content, sort_keys=True, separators=(",", ":"), ensure_ascii=False)` en UTF-8) y
   lo devuelve en `data.artifact` (contrato en `docs/fase-6e-contracts.md`).
4. El servidor comprueba esquema y tipo, recalcula el hash, guarda el artefacto y deja en el
   resultado de la ejecución solo la referencia (`artifact_id`, `sha256`, `integrity`, tamaño).
   - Hash distinto: el artefacto queda `mismatch`, se audita como fallo y se avisa en la UI.
   - Artefacto mal formado o de otro tipo: la ejecución falla con `artifact_invalid` o
     `artifact_missing` y no se guarda nada.
   - Mayor que `FORENSICS_ARTIFACT_MAX_KB` (2048): falla con `artifact_too_large`.

## Paquete de evidencia

`POST /api/v1/investigations/{id}/package` `{"acknowledge_mismatch": false}`
(forensics:download). Es POST porque genera un registro y una entrada de auditoría.

- Sin artefactos: 409 `evidence_empty`.
- Con algún `mismatch`: 409 `evidence_integrity_mismatch` salvo `acknowledge_mismatch=true`;
  el manifiesto y el registro lo marcan (`includes_mismatch`).
- Suma de artefactos mayor que `FORENSICS_PACKAGE_MAX_MB` (64): 413
  `evidence_package_too_large` (el ZIP se genera en memoria).

Contenido del ZIP:

- `manifest.json`: esquema `sentra-evidence-package/1`, investigación, artefactos (fichero,
  acción, alcance, operador, `sha256`, `agent_sha256`, `integrity`, `stored_hash_verified`
  recalculado al empaquetar, tamaños, limitaciones, fechas) y `chain_of_custody` (entradas de
  auditoría del caso, de sus artefactos y de sus recogidas, hasta 2000).
- `evidence/<fecha>-<acción>-<id>.json`: bytes exactos guardados.
- `interpretations/notes.json`: notas, etiquetadas como interpretación, no evidencia.

El SHA-256 del ZIP va en `X-Sentra-SHA256` y queda en `evidence_packages` y en la auditoría
(`evidence_package_downloaded`).

## API

| Método y ruta | Permiso |
|---|---|
| `GET /investigations?asset_id&status&site_id&limit&offset` | forensics:read |
| `POST /investigations` | forensics:acquire |
| `GET /investigations/{id}` (artefactos sin contenido, notas, recogidas, paquetes) | forensics:read |
| `GET /investigations/{id}/artifacts/{artifact_id}` (con contenido) | forensics:read |
| `POST /investigations/{id}/notes` `{kind, body}` | forensics:acquire |
| `POST /investigations/{id}/close` y `/reopen` `{version}` | forensics:manage |
| `POST /investigations/{id}/legal-hold` `{version, legal_hold}` | forensics:manage |
| `POST /investigations/{id}/package` | forensics:download |

Recoger exige además `response:execute` (y `response:manage` para `forensic_file_metadata`).
Roles: analista y admin tienen read/acquire/download; solo admin tiene manage. Viewer, nada.

Auditoría: `investigation_created`, `investigation_note_added` (sin el texto),
`investigation_closed`, `investigation_reopened`, `investigation_legal_hold`,
`forensic_artifact_received` (con ambos hashes), `evidence_package_downloaded`, y las de
Response de cada recogida.

## Retención

La evidencia forense no se purga automáticamente en 6E y no hay endpoint para borrarla. Las
FK a investigaciones son `RESTRICT`. `legal_hold` queda registrado para que cualquier limpieza
futura lo respete.

## Limitaciones

- Probado con agentes simulados en tests; la recogida real en Windows, Linux y macOS está
  pendiente de verificar en equipos reales (ver `docs/fase-6e-known-issues.md`).
- La aprobación de una acción medium es la confirmación del mismo admin; no hay doble
  aprobación.
- Las notas `ai_summary` las pega el analista: 6E no genera resúmenes de IA por su cuenta.
