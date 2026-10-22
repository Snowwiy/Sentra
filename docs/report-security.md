# Seguridad de los informes (Fase 5E)

Un informe agrega datos sensibles (activos, IPs, usuarios, incidentes, evidencia). Esta es la
política que aplica el backend; ocultar botones en la UI es solo comodidad.

## Permisos

| Permiso | Roles | Permite |
|---|---|---|
| `reports:read` | viewer, analyst, admin | Catálogo, historial, detalle y descarga |
| `reports:generate` | analyst, admin | Vista previa, generar, cancelar los propios |
| `reports:admin` | admin | Resumen ejecutivo, técnico global, cancelar ajenos, borrar |

Además, cada tipo exige los permisos de **lectura de dominio** de los datos que contiene
(`domain_permissions` en el catálogo). Ver, listar o descargar un informe de un tipo cuyos
datos el rol no puede leer responde **404**, igual que uno inexistente (sin IDOR). Por
ejemplo, `lifecycle_change` exige `assets:duplicates_read`, que el viewer no tiene.

El worker vuelve a leer los permisos **actuales** de quien pidió el informe al generarlo: si
le quitaron el rol o desactivaron la cuenta entre medias, el informe falla
(`report_forbidden`) en lugar de generarse con permisos que ya no tiene.

El alcance de datos se aplica en un solo sitio (`app/reports/scope.py`, `DataScope`): hoy
todo o nada según `monitoring:read`; es el punto de extensión si en el futuro se limita por
grupo de activos.

## Lo que el cliente no puede controlar

- Solo ids del catálogo, formatos admitidos por el tipo y valores de filtros validados contra
  listas cerradas. Campos desconocidos: 422 (`extra=forbid`).
- Sin SQL, plantillas, rutas, nombres de fichero ni URLs en ninguna petición.
- La descarga es solo por id del informe. El nombre del fichero lo genera el servidor
  (`sentra-<tipo>-<fecha>-<fragmento de uuid>.<ext>`) sin títulos, hostnames ni datos.

## Redacción

Todo JSON libre que entra en un snapshot (evidencia de detecciones, evidencias de
clasificación) pasa por `app/reports/redaction.py`:

- claves con `password`, `secret`, `token`, `api_key`, `authorization`, `cookie`,
  `credential`, `enrollment_key`, `session_id`, `csrf`… se sustituyen por `[redacted]`;
- textos con `Authorization: …`, `Bearer …` o `password=…`/`token=…` se redactan;
- profundidad (6), elementos por nivel (50) y longitud de texto (1000) acotados.

Nunca se leen ni exportan hashes de tokens de agente, sesiones, claves de enrollment ni
credenciales. Los resultados de Response ya llegan saneados (Fase 5D).

## Contenido seguro

- **HTML**: todo valor se escapa con `html.escape`; CSP `default-src 'none'; style-src
  'unsafe-inline'; img-src data:`; sin scripts, sin manejadores de eventos, sin URLs
  externas; los SVG se construyen con valores numéricos y texto escapado.
- **Descarga**: `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`,
  `Cache-Control: no-store` y `Content-Security-Policy: sandbox; …`: si alguien abre el HTML
  directamente desde la API, el navegador lo aísla. La UI descarga como fichero y nunca
  renderiza el HTML dentro de la aplicación.
- **PDF**: sin acciones (`/URI`, `/JavaScript`, `/Launch`, `/OpenAction`), sin ficheros
  incrustados; el texto va como cadenas hexadecimales (sin problemas de escape).
- **Plantilla v2 (Fase 6D.5)**: mismas garantías. El HTML v2 no añade scripts, manejadores
  on*, `src` ni URLs; sus únicos enlaces son anclas internas del índice (`#s-N`) y los SVG
  solo llevan números, colores de una paleta cerrada y texto escapado. El PDF v2 sigue sin
  fuentes incrustadas, imágenes ni anotaciones (solo las tres Helvetica estándar). Las
  etiquetas de gráficas y los nombres de nodos de la topología pasan por la redacción dos
  veces (al entrar en el snapshot y al construir el documento). El resumen ejecutivo v2 sigue
  sin IDs, IPs, evidencia técnica, topología ni trazas de cálculo.
- **CSV**: toda celda de texto que empiece por `=`, `+`, `-`, `@`, tabulador o retorno de
  carro se prefija con `'` (CSV/formula injection). Columnas fijas por tabla.
- **ZIP**: nombres fijos, sin rutas absolutas, sin `..`, sin enlaces simbólicos, permisos
  0644, manifest con SHA-256 de cada fichero.

## Integridad

El SHA-256 del fichero se guarda al generarlo. Cada descarga lo recalcula: si no coincide,
responde 409 `report_integrity_failed`, no entrega el fichero y lo audita. La UI vuelve a
comprobar el SHA-256 con la cabecera `X-Sentra-SHA256`.

## Auditoría

Acciones: `report_requested`, `report_generated`, `evidence_bundle_generated`,
`report_downloaded`, `report_cancelled`, `report_failed`, `report_deleted`,
`report_expired`, `report_integrity_failed`. Detalles: tipo, formato, clasificación, filtros
(ids y valores de catálogo), tamaños del alcance, período, SHA-256 y tamaño. Nunca el
contenido del informe, ni secretos, ni trazas de error.

## Clasificación

`internal` (por defecto), `confidential` o `restricted`: aparece en la cabecera de cada
página y en el pie. Es una etiqueta para quien recibe el documento; no cifra ni cambia
permisos dentro de Sentra.
