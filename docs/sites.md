# Sites (Fase 5F)

Un **Site** es una ubicación monitorizada: oficina, sede, laboratorio, CPD. Sirve para que
las direcciones privadas dejen de ser globalmente únicas: dos sites pueden usar
`192.168.1.0/24` a la vez y `192.168.1.20` de cada uno son activos distintos.

Un Site **no es un tenant**. Todos los sites pertenecen a la misma instalación, el RBAC
sigue siendo global y un usuario ve todos los sites (con filtro opcional). Multi-tenant y
SaaS siguen fuera de alcance.

## Modelo

- `sites`: nombre único, `slug`, descripción, etiqueta de ubicación, zona horaria
  (informativa: la UI y los informes siguen en UTC), estado `active` / `disabled` /
  `archived`, `is_default` y `version` (concurrencia optimista).
- `site_networks`: redes autorizadas del site (CIDR normalizado, etiqueta, habilitada o no).
  Son **exactamente** lo que los sensores del site pueden escanear.
  - Solapamiento entre sites: permitido (es el caso normal con redes privadas).
  - Solapamiento dentro del mismo site: rechazado (`site_network_overlap`).
  - CIDR inválido, `/0`, o más hosts que `DISCOVERY_MAX_HOSTS_PER_NETWORK`: rechazado
    (422 `site_network_invalid`).
- `assets.site_id`, `discovery_jobs.site_id`: NOT NULL, con valor por defecto
  `sentra_default_site_id()`. Todo el código anterior a 5F (agentes, discovery local, CLI)
  sigue funcionando y sus datos caen en el site local.

## Site por defecto ("Local")

La migración 0032 crea el site `Local` (`slug=local`, `is_default=true`) y asigna a él
todos los activos y discovery jobs existentes. No se pierde ni se mueve nada más.

- No se puede archivar, deshabilitar ni borrar (`site_default_protected`).
- El discovery **local** (el servidor escaneando su propia red) solo existe en el site
  por defecto (`discovery_local_default_site_only`). El resto de sites se observa con
  sensores (ver [distributed-sensors.md](distributed-sensors.md)).
- Un agente enrolado con un token sin site cae en el site por defecto. Los tokens de
  enrolamiento de agentes pueden llevar `site_id`: el activo nuevo nace en ese site. Re-enrolar
  un agente nunca mueve su activo.

## Ciclo de vida

| Acción | Quién | Efecto |
|--------|-------|--------|
| Crear / editar | admin (`sites:manage`) | `version` obligatoria al editar; conflicto = 409 `site_conflict`. |
| Deshabilitar (`PATCH` con `status: disabled`) | admin | Se cancelan sus jobs de sensor abiertos, los sensores no reciben trabajo nuevo y no se pueden crear tokens. Los datos se conservan. |
| Archivar | admin | Igual que deshabilitar y oculto por defecto en los selectores. |
| Restaurar | admin | Vuelve a `active`. |
| Borrar | admin | Solo si el site no tiene **ningún** dato (activos, sensores, jobs, tokens). Con datos: 409 `site_has_data` y la indicación de archivarlo. |

Todas las acciones quedan auditadas (`site_*`) sin secretos.

## Activos y sites

- La identidad de un activo descubierto es **site + IP** (más MAC/hostname como evidencia).
  La misma IP en dos sites crea dos activos.
- La reconciliación y la detección de duplicados **nunca cruzan sites**: un candidato de
  otro site no se adopta automáticamente, y la evaluación manual muestra el bloqueo
  `different_site`.
- Mover un activo de site es una acción explícita de admin: `POST /assets/{id}/site` con
  `lifecycle_version` (409 si cambió), solo hacia un site activo, auditada como
  `asset_site_changed`. Reinicia `network_misses` porque las redes del site nuevo son otras.

## Filtro por site

Parámetro opcional `site_id` (UUID; desconocido = 404 `site_not_found`) en:
`/dashboard/summary`, `/assets`, `/agents`, `/alerts`, `/detections`, `/incidents`,
`/vulnerabilities/findings`, `/risk/assets`, `/response/executions`, `/discovery/jobs` y
`/sensors`. Los datos de seguridad no duplican el site: lo heredan de su activo.

Informes: `filters.site_id` limita los datos de activos del informe y aparece en el
alcance (`scope.site`). Un site inexistente devuelve 422 `report_target_not_found`.

La UI tiene un selector global de site en la cabecera (guardado por navegador). En
Incidentes, Riesgo y Vulnerabilidades las tarjetas de resumen siguen siendo globales (sus
endpoints de visión general no admiten filtro todavía) y una nota lo indica; las tablas sí
se filtran.

## Endpoints (`/api/v1`)

- Lectura (`monitoring:read`): `GET /sites` (con contadores de activos y sensores),
  `GET /sites/{id}`, `GET /sites/{id}/networks`.
- Gestión (`sites:manage`, solo admin): `POST /sites`, `PATCH /sites/{id}`,
  `POST /sites/{id}/archive`, `POST /sites/{id}/restore`, `DELETE /sites/{id}?version=N`,
  `POST /sites/{id}/networks`, `PATCH|DELETE /sites/{id}/networks/{network_id}`.
- `POST /assets/{id}/site` (`assets:manage`, solo admin).
