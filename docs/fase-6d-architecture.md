# Fase 6D: informe de arquitectura

Resumen de lo que añade la Fase 6D (servidor y frontend 0.2.0, sensor 0.5.1, agente 0.4.0 sin
cambios, migración 0038) y de cómo encaja con lo existente. El detalle de cada módulo está en
su documento propio; aquí se explica el porqué de las decisiones y cómo validarlas.

## Punto de partida (integración de 6C)

La base es `Dev` en `bc0ca47` (6A, 6B, 6C.0-6C.5 publicados) más el parche «Corrección 6C:
identidad, etiquetas y servicios» (migración 0037, sensor 0.5.0, `custom_label`, puertos con
servicio, regla «un solo puerto nunca decide el tipo»). El parche 6D es incremental sobre ese
árbol; se entrega además un parche acumulado sobre `bc0ca47` que incluye 6C identidad.

De 6C se reutiliza sin cambios: el inventario WLAN (`wlan_access_points`, clientes con
asociación `probable`), el catálogo NVD/OSV, la shell responsive y la identidad automática
(`automatic_name`, `custom_label`, nombres observados). 6D solo añade una regla: la etiqueta
manual sigue siendo el nombre principal tras cada redescubrimiento y el campo nuevo
`name_status` explica por qué un activo no tiene nombre.

## 6D.1 Motor de topología

- **Solo enlaces, no nodos.** Los nodos son referencias (`asset:<uuid>`,
  `network_device:<uuid>`, `wlan_ap:<uuid>`, `external:<hash>`) resueltas en cada lectura
  contra el inventario: la topología no duplica el inventario y un cambio de nombre o una
  etiqueta manual se ve al instante.
- **Clases separadas:** physical (LLDP/CDP recíproco o unilateral resuelto), logical
  (gateway de un agente con IP única en el site, gestión de una controladora WLAN), observed
  (FDB en un puerto de acceso con una sola MAC, asociación Wi-Fi), candidate (FDB en puerto
  compartido), unknown (evidencia que no identifica el otro extremo). Nunca se crea un enlace
  por compartir subred o gateway, nunca se fusionan activos duplicados y una referencia a otro
  site no se resuelve.
- **Persistencia:** `topology_links` con `link_key` (sha256 independiente del orden de los
  extremos), `present`, revisión humana (`accepted`/`rejected`, versión optimista) y
  `topology_builds`. La reconstrucción toma un bloqueo consultivo por site y bloquea (FOR
  UPDATE) los enlaces del site, de modo que una revisión concurrente nunca escribe sobre una
  versión obsoleta. Programada cada `TOPOLOGY_REBUILD_INTERVAL_MINUTES` (15) y acotada por
  `TOPOLOGY_MAX_NODES`/`TOPOLOGY_MAX_LINKS`.
- **Sin SNMP** la topología sigue funcionando con gateways de agentes y Wi-Fi; el estado
  (`/topology/status`) dice qué evidencia hay disponible.

## 6D.2 UI

Página Topología: lienzo SVG propio (sin dependencias nuevas), disposición determinista por
site y red, zoom, arrastre, selección por teclado, búsqueda por IP/nombre/MAC/etiqueta,
filtros por tipo, leyenda de clases y confianza, panel de nodo con enlaces al inventario y al
riesgo, revisión de enlaces (admin) y exportación SVG saneada.

## 6D.3 Identidad

`name_status` (`labelled`, `named`, `generic_only`, `unnamed`) explica el nombre. Causas
documentadas de nombres desconocidos: el perfil rápido no pregunta DNS ni nombres; mDNS es de
enlace local (un sensor en otra VLAN no lo ve); NetBIOS solo responde en Windows/SMB; routers
domésticos como el Archer GX90 no publican los nombres DHCP por DNS; los nombres genéricos
(`linux.local`, `localhost`, `android-...`) se rechazan como nombre principal cuando hay mejor
evidencia. No se añadió ningún sondeo nuevo.

## 6D.4 SNMP: causa del KeyError

Causa reproducida: el colector del sensor registraba el fallo de un módulo con
`extra={"module": ...}`; `module` es un atributo reservado de `logging.LogRecord`, así que el
propio log lanzaba `KeyError`, que sustituía al fallo real y llegaba al servidor como
«snmp error: KeyError». Corregido en el sensor 0.5.1 (con una prueba que recorre todo el
paquete buscando claves reservadas). El servidor clasifica cada cierre en `snmp_status`
(no_response, timeout, unreachable, auth_failed, unsupported_version, malformed_response,
collector_error, compatible, unverified), oculta nombres de excepción incluso del historial,
pausa las consultas periódicas tras `SNMP_AUTO_PAUSE_FAILURES` (3) fallos que indican que no
hay SNMP utilizable y ofrece «Verificar compatibilidad» (solo `system`, sin pisar el estado de
la última consulta completa). AES-GCM, el almacén de secretos y `SNMP_ALLOW_V2C=false` no
cambian.

## 6D.5 Informes v2

Misma cadena snapshot → documento neutro → HTML/PDF con SHA-256 y determinismo. Las plantillas
v2 añaden gráficas (siempre desde el snapshot): evolución del riesgo, detecciones por
severidad y estado, contribuciones del Risk Engine, tendencia de eventos y detecciones,
criticidad, exposición y topología estática (solo enlaces verificados). El PDF v2 translitera
a cp1252 y marca lo intransliterable como `[U+XXXX]` en lugar de `?`. Se distingue ausente,
no medido, desconocido y cero. Un snapshot v1 se sigue renderizando con las plantillas v1 y da
los mismos bytes.

## 6D.6 Descargas

El aviso «No se pudo conectar con la API de Sentra» indicaba que la API no respondía en ese
instante (reinicio de uvicorn `--reload` al aplicar un parche, o 502 del proxy de Vite). Ahora
se distinguen API caída, tiempo de espera, sesión caducada, rol, error del servidor, artefacto
caducado, proxy 502/504, cuerpo cortado y SHA-256 distinto (docs/report-download-errors.md).

## 6D.7 API 0.2.0

Versión del servidor 0.2.0 con `/api/v1` intacto; cambios solo aditivos
(docs/compatibility-matrix.md). Revisión de seguridad independiente: RBAC en cada endpoint
nuevo, CSRF heredado de `require_permission`, aislamiento por site, ids mal formados con el
mismo 404, límites de paginación y de búsqueda, sin trazas en errores, HTML de informes con
escape y CSP `default-src 'none'`, PDF con cadenas en hexadecimal.

## 6D.8 Riesgo 100 de ravenslg

Diagnóstico: CORR-002 tenía cooldown 0, así que cada reevaluación que añadía evidencia contaba
como una ocurrencia nueva. Con 4 ocurrencias: 70 puntos × factor de ocurrencias 1.24 ×
correlación 1.15 = 99.82, que la saturación lleva a 100. No se ha clasificado como falso
positivo. Cambios: las correlaciones pasan a versión 2 con cooldown igual a su ventana (una
oleada cuenta una vez) y el desglose del riesgo incluye `details.nominal_breakdown` y
`breakdown.trace` con cada factor. `FORMULA_VERSION` no cambia (5). Las detecciones ya abiertas
conservan su contador: el score de ravenslg baja cuando esas detecciones se cierren o caduquen,
no al aplicar el parche.

## Validación en el PC de Jesus

1. Aplicar el parche y la migración 0038 contra la base de desarrollo (nunca `sentra_test` con
   datos reales). Reiniciar API y frontend.
2. Topología: «Reconstruir» en cada site; comprobar que ningún enlace une dos equipos solo por
   estar en la misma subred; aceptar o rechazar un enlace y reconstruir de nuevo (la revisión se
   conserva).
3. Archer GX90: actualizar el sensor a 0.5.1, «Verificar compatibilidad»; tras 3 fallos el
   equipo queda pausado y se reanuda con «Reanudar» o con una consulta correcta.
4. Informes v2 en PDF y HTML: acentos, gráficas, topología; volver a descargar un informe v1
   antiguo y comprobar su SHA-256.
5. Riesgo de ravenslg: abrir la pestaña de riesgo y revisar la trazabilidad.
6. Suites completas en Windows (backend, sensor, agente, frontend con Node 24).
