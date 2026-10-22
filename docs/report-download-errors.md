# Descargas y mensajes HTTP del frontend (Fase 6D.6)

Diagnóstico del aviso «No se pudo conectar con la API de Sentra» que apareció al descargar un
informe cuyo PDF sí se había generado, y cómo se separan ahora los mensajes de error.

## De dónde salía el aviso

En `src/api/client.ts` ese texto solo se produce en dos sitios:

1. `fetch()` rechaza ANTES de recibir cabeceras (conexión rechazada o cortada, DNS, CORS
   bloqueado por el navegador). Antes se traducía siempre a `network_error` con estado 0.
2. `parseError()` recibe 502, 503 o 504 SIN el sobre de error de Sentra. Lo genera el proxy que
   hay delante de la API, no la API: Vite en desarrollo (`vite.config.ts`, proxy `/api`) o el
   proxy inverso en producción. Se muestra «No se pudo conectar con la API de Sentra (HTTP 502)».

Además había un tercer fallo sin traducir: `apiDownload()` hacía `await response.blob()` fuera de
cualquier `try`. Si la conexión se cortaba DESPUÉS de las cabeceras (cuerpo a medias), el botón
mostraba el `TypeError` del navegador («network error», «Failed to fetch», «terminated»).

Conclusión: el aviso significa que, en el instante de la descarga, el proceso de la API no
contestaba o cortó la conexión. Que el PDF existiera es coherente: lo genera antes el job
`report-worker`, y el fichero queda en `REPORT_OUTPUT_DIR`.

## Reproducción

Script `qa/report_download_repro.cjs` (Playwright + Chromium) contra Vite (`npx vite`) y la API
(`uvicorn app.main:app --port 8000`) con la base de desarrollo del contenedor:

| Escenario | Resultado observado |
| --- | --- |
| Descarga normal de un PDF (sin fallos) | 200, SHA-256 verificado, fichero guardado, sin avisos. El aviso NO se reproduce en el caso feliz. |
| API detenida justo antes de pulsar «Descargar» (`--wait-before-download-ms`, se para uvicorn) | Vite registra `http proxy error: /api/v1/reports/<id>/artifact` / `connect ECONNREFUSED 127.0.0.1:8000` y responde **502** sin cuerpo. Con el código anterior: «No se pudo conectar con la API de Sentra (HTTP 502)», exactamente el aviso observado; el indicador de salud pasa a «API no disponible» en el siguiente sondeo. |
| Conexión cortada en el navegador (`--abort-body`, `route.abort("connectionreset")`) | `fetch` rechaza: con el código anterior, «No se pudo conectar con la API de Sentra». |
| 502 / 504 simulados (`--gateway 502|504`) | Mensajes de proxy diferenciados (ver tabla de abajo). |

Causa más probable en el entorno de Jesus (Windows, desarrollo): `scripts/start_backend.ps1`
arranca uvicorn con `--reload --reload-dir app`. Cualquier cambio en `backend/app` (aplicar un
parche, editar código, cambiar de rama) reinicia el proceso; durante el reinicio (varios segundos
en Windows, porque importa toda la aplicación) Vite responde 502 a cada petición y el informe ya
generado sigue intacto en disco. Un reinicio por excepción no capturada o un cierre del proceso
dan el mismo síntoma. No se encontró ninguna ruta en la que la API respondiera bien y el frontend
mostrara ese texto: sin un 502/503/504 sin sobre o un `fetch` rechazado, el aviso no aparece.

Causas descartadas con evidencia:

- Proxy de Vite por tiempo de espera: `http-proxy` no tiene timeout por defecto y el servidor de
  Node solo limita la recepción de la petición, no la respuesta. Un 504 solo llegaría de un proxy
  inverso de producción con `proxy_read_timeout`; el artefacto se lee entero en memoria
  (máx. `REPORT_MAX_ARTIFACT_MB`, 25 MB) y se envía de golpe, así que es improbable.
- Cabeceras por CORS en despliegue con otro origen: el backend expone `X-Sentra-SHA256`
  (`expose_headers` en `app/main.py`) pero no `Content-Disposition`. No provoca el aviso: el
  nombre del fichero se toma de `report.artifact.filename` (JSON del informe) y el SHA-256 de la
  cabecera o, si faltara, de `report.artifact.sha256`. Si en el futuro se quiere el nombre de la
  cabecera en cross-origin, hay que añadir `Content-Disposition` a `expose_headers`.
- Nombre de fichero no ASCII en `Content-Disposition`: el servidor genera nombres ASCII
  (`_filename` en `report_service.py`).
- Sondeos concurrentes: el detalle del informe sondea cada 3 s mientras se genera y cada hora
  después; un fallo de sondeo se muestra como «Fallo al actualizar: …» en su propio banner y no
  usa el aviso del botón. Si la API se reinicia, ese banner y el indicador de salud también se
  pondrán en error: es correcto (la API no estaba disponible), no un falso positivo.

## Mensajes separados (desde 6D.6)

`apiDownload()` distingue ahora el corte del cuerpo (`download_interrupted`) y el plazo vencido
(`timeout`, `DOMException` `TimeoutError` de `AbortSignal.timeout`). `src/lib/download.ts`
(`describeDownloadError`) traduce cada caso; `DownloadReportButton` lo usa:

| Situación | Mensaje |
| --- | --- |
| API no disponible (`fetch` rechazado, estado 0) | «No se pudo conectar con la API de Sentra: comprueba que el servidor está en marcha y que hay conexión de red.» |
| Tiempo de espera | «La API de Sentra no respondió a tiempo. Vuelve a intentarlo en unos segundos.» |
| Sesión caducada (401) | «La sesión ha caducado. Inicia sesión de nuevo para descargar.» (además el AuthProvider vuelve a /login) |
| Rol insuficiente (403) | «Tu rol no permite descargar el informe.» |
| Error del servidor con sobre (5xx) | «Error del servidor (HTTP 500): <mensaje del servidor>» |
| Error del servidor sin sobre | «Error del servidor (HTTP 500) sin más detalle.» |
| Artefacto caducado o borrado (404/410) | El texto de `report_artifact_unavailable`, o «El informe ya no existe o ha caducado. Recarga la página…» |
| Proxy sin respuesta de la API (502/503 sin sobre) | «El proxy delante de la API no obtuvo respuesta de Sentra (HTTP 502)…» |
| Proxy por tiempo de espera (504 sin sobre) | «El proxy delante de la API cortó la descarga por tiempo de espera (HTTP 504)…» |
| Cuerpo cortado a mitad | «La descarga se interrumpió antes de completarse (conexión cortada). El fichero no se ha guardado…» |
| SHA-256 distinto | «El fichero descargado no coincide con su SHA-256: no se ha guardado…» (nunca se desactiva la verificación ni se ofrece el fichero) |
| Cancelación (desmontar la página o nuevo intento) | Sin aviso. |

El botón usa un `AbortController`: se cancela al desmontar, ignora resultados de descargas ya
canceladas y vuelve siempre a «Descargar» (sin spinner ni aviso colgados). Un 502 sin sobre
mantiene el código `network_error` del cliente para no cambiar el comportamiento del resto de la
consola (indicador de salud, banners de sondeo).

## Cómo repetir la reproducción

```bash
# API (base de desarrollo, nunca la real) y Vite con su proxy
cd backend && uvicorn app.main:app --port 8000
cd frontend && npx vite --host 127.0.0.1
# Escenarios (usuario admin de pruebas; contraseña solo en la variable de entorno)
NODE_PATH=/ruta/node_modules SENTRA_QA_ADMIN_PASSWORD=... node qa/report_download_repro.cjs
node qa/report_download_repro.cjs --format html --abort-body
node qa/report_download_repro.cjs --format html --gateway 504
node qa/report_download_repro.cjs --format html --wait-before-download-ms 8000   # parar la API mientras espera
```
