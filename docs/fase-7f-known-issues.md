# Fase 7F: limitaciones conocidas

## Validación

- Todos los conectores se han probado con fixtures sintéticos. **Sin validación con Suricata,
  Zeek, Wazuh, firewalls ni servidores Syslog reales.**
- Sensor 0.9.0 sin ejecutar en Windows ni macOS; QA física pendiente
  (docs/fase-7f-windows-qa.md).
- Rendimiento medido solo en la nube con datos sintéticos.

## Conectores

- Syslog: sin mTLS; RFC 3164 sin año ni zona usa la hora de recepción.
- Ficheros: no se leen ficheros comprimidos ni rotados antiguos; en Windows pueden perderse
  líneas escritas justo antes de una rotación si el fichero rotado ya no está en el mismo
  directorio (7F-Windows-Fix2 recupera las que siguen en él). Una reescritura en el sitio
  que conserva los primeros 256 bytes y no acorta el fichero no se detecta
  (7F-Windows-Fix1).
- Rutas TLS y `allowed_dir`: en Windows solo rutas locales con letra de unidad (sin UNC).
- Zeek: solo JSON, no TSV.
- Wazuh: solo `alerts.json`; sin API (necesitaría guardar credenciales: decisión pendiente).

## Correlación e identidad

- Se calcula al ingerir; un evento tardío enlaza hacia atrás y los anteriores lo ven como
  enlace entrante.
- Con NAT o rutas asimétricas no hay enlace por 5-tupla (se prefiere no enlazar a enlazar mal).
- `probable_match` con detecciones nativas solo si la nativa ya existía al ingerir.
- `hostname` busca por igualdad exacta (sin distinguir mayúsculas).

## Ingesta

- Unos 270 eventos/s en la nube con todos los analizadores; una fuente muy ruidosa depende del
  spool del sensor y de la cuota.

## Live SOC

- Límites de streams por worker, no globales.
- Una fila confirmada con id menor que otra ya enviada puede no aparecer en el stream.
- El canal `siem` solo emite alertas.
- Contadores desde que se abrió la página; no hay histórico en la página.
