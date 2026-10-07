# Fuentes de Threat Intelligence (Fase 5C)

Contrato de las fuentes, formatos de fichero y cómo cargarlas con y sin Internet. Visión
general y semántica: [threat-intelligence.md](threat-intelligence.md).

## Adapters

Cada fuente usa un adapter (`app/threat_intel/providers.py`) que declara qué es y cómo
convierte lo descargado o importado en registros normalizados. Persistencia, locks,
auditoría, historial y staging son comunes (`sync.py`, `store.py`): un adapter nuevo no toca
rutas ni servicios.

| Adapter | Categoría | Red | Capacidades | Intervalo / stale por defecto |
|---------|-----------|-----|-------------|-------------------------------|
| `cisa_kev` | `exploitation` | sí (opcional) | `vulnerability_intel`, `conditional_requests`, `complete_feed` | 24 h / 120 h |
| `first_epss` | `exploitation` | sí (opcional) | `vulnerability_intel`, `conditional_requests`, `complete_feed` | 24 h / 120 h |
| `local_import` | `ioc` | nunca | `indicators`, `manual_import` | — |

`complete_feed`: el fichero es el catálogo entero; lo que deja de aparecer se marca inactivo
(nunca se borra) y deja historial. `local_import` no es completo: una importación nunca
desactiva indicadores ausentes.

Niveles de confianza de una fuente: `official` (organismo que publica el dato: CISA, FIRST),
`trusted` (espejo o proveedor elegido por la organización), `local` (lo importa un admin) y
`community`. La confianza la fija el admin y pesa en el riesgo y en la confianza de TI-001.

## CISA KEV

- Origen por defecto: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  (referencia: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>).
- JSON con `catalogVersion`, `dateReleased` y `vulnerabilities[]`. Se usan `cveID`,
  `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`,
  `requiredAction`, `dueDate`, `knownRansomwareCampaignUse` y `notes`; los campos
  desconocidos se ignoran (CISA puede añadir columnas) y los conocidos se acotan como texto no
  confiable. `knownRansomwareCampaignUse: "Unknown"` **no** quiere decir "sin ransomware".
- Se valida entero antes de tocar la base de datos. CVE con formato inválido → registro
  inválido (cuenta en el historial de la sincronización, no rompe la importación).
- Historial: `kev_added`, `kev_removed` (el registro queda inactivo), `kev_readded`,
  `kev_updated` (fecha límite, acción requerida, uso en ransomware...).

## FIRST EPSS

- Origen por defecto: `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz`
  (referencia: <https://www.first.org/epss/>). Es la ubicación de descarga que publica FIRST
  actualmente; si cambia, se fija otra con `THREAT_INTEL_SOURCE_URLS` sin tocar código.
- CSV (gzip o texto plano) con una primera línea de metadatos y cabecera:

  ```text
  #model_version:v2025.03.14,score_date:2025-03-15T00:00:00+0000
  cve,epss,percentile
  CVE-1999-0001,0.01141,0.77824
  ```

- Se procesa **en streaming** (~300 000 filas, nunca entero en memoria). Valores fuera de
  [0, 1] o CVE inválido → fila inválida.
- **Decisión de historial**: EPSS cambia cada día para casi todos los CVEs, así que no se
  guarda cada valor diario. Se guarda el valor actual y, en `data.previous`, el último valor
  anterior a un **cambio material**; cada cambio material deja una fila
  `epss_material_change`.
  Material = cambio de banda (elevada ≥ 0,1, alta ≥ 0,5) o variación absoluta ≥ 0,1.

## Sin Internet (servidor aislado)

1. En un equipo con Internet, descargar los ficheros oficiales (los de arriba).
2. Copiarlos al servidor y comprobar su integridad (sha256 que publique la organización o
   la que se apunte al descargar).
3. Importarlos:

   ```powershell
   cd backend
   .venv\Scripts\python.exe -m app.cli threat-intel-import --source cisa-kev known_exploited_vulnerabilities.json
   .venv\Scripts\python.exe -m app.cli threat-intel-import --source first-epss epss_scores-current.csv.gz
   ```

4. Activar las fuentes en `Inteligencia → Fuentes` (o ya estaban activas).

La CLI respeta los mismos límites (`THREAT_INTEL_MAX_DOWNLOAD_MB`,
`THREAT_INTEL_MAX_RECORDS`), el mismo staging atómico y el mismo historial que la
sincronización por red. Repetir con el mismo fichero no cambia nada.

## Con Internet o espejo interno

```dotenv
THREAT_INTEL_SYNC_ENABLED=true
# Opcional: espejo interno en la LAN (por defecto ninguna red privada es destino válido)
THREAT_INTEL_SOURCE_URLS=cisa-kev=https://mirror.corp.example/kev.json,first-epss=https://mirror.corp.example/epss.csv.gz
THREAT_INTEL_ALLOWED_NETWORKS=10.20.0.0/24
```

El job sincroniza cada fuente activada según su intervalo, con ETag/`If-Modified-Since`. Un
fallo (red, 5xx, fichero corrupto, feed demasiado pequeño) conserva la inteligencia anterior
y se ve en el historial de la fuente. El navegador nunca envía URLs; el admin solo crea la
fuente (clave, nombre, adapter, confianza) y el servidor decide de dónde descarga.

Un espejo "trusted" de KEV o EPSS se crea como otra fuente (`POST /threat-intel/sources` con
`provider: "cisa_kev"`) y su URL va en `THREAT_INTEL_SOURCE_URLS` con su clave. Si dos fuentes
dicen cosas distintas de un mismo CVE, la UI muestra ambas con su procedencia.

## Formato `sentra-ioc/1`

```json
{
  "format": "sentra-ioc/1",
  "description": "IOCs del aviso interno 2026-17",
  "indicators": [
    {
      "type": "ipv4",
      "value": "203.0.113.7",
      "classification": "malicious",
      "confidence": "high",
      "valid_from": "2026-10-01T00:00:00Z",
      "valid_until": "2026-12-31T00:00:00Z",
      "tags": ["botnet"],
      "description": "C2 observado en el aviso 2026-17",
      "references": ["https://intranet.example/avisos/2026-17"],
      "id": "aviso-2026-17-1"
    }
  ]
}
```

| Campo | Obligatorio | Notas |
|-------|-------------|-------|
| `type` | sí | `ipv4`, `ipv6`, `cidr`, `domain`, `hostname`, `url`, `sha256`, `sha1`, `md5`, `email` |
| `value` | sí | Se normaliza (IPv6 comprimida, dominio en minúsculas e IDNA, hash en minúsculas...) |
| `classification` | **sí** | `malicious`, `suspicious`, `benign`, `unknown`. Aparecer en el fichero no hace malicioso a un valor |
| `confidence` | no | `low`, `medium` (por defecto), `high` |
| `valid_from`, `valid_until` | no | ISO 8601 con zona. Fuera de plazo no casa |
| `revoked` | no | `true` retira el indicador (sus matches quedan como memoria) |
| `first_seen`, `last_seen` | no | Fechas de la fuente, informativas |
| `tags` | no | Hasta 20 cadenas sin caracteres de control |
| `description` | no | Texto acotado, mostrado siempre como texto |
| `references` | no | Solo URLs `http(s)`; nunca se visitan |
| `id` | no | Identificador externo de la fuente |

Claves desconocidas → registro inválido. Valores "defanged" (`hxxp://`, `ejemplo[.]com`) se
rechazan en vez de "arreglarlos". Una red CIDR más amplia que /8 (IPv4) o /32 (IPv6) se
rechaza: marcaría medio Internet. Un indicador repetido en el mismo fichero cuenta como
`duplicate_indicator`.

Tipos casables con datos de Sentra: IP, CIDR, dominio y hostname (ver
[threat-intelligence.md](threat-intelligence.md#matching-con-datos-locales)). URL, hashes y
email se guardan como contexto y la UI los marca como "unsupported" para el matching.

## TAXII 2.1 (no implementado)

Documentado como contrato, sin código en 5C. Un adapter `taxii21` sería:

- `network_required: true`, capacidades `indicators`, `conditional_requests`;
- configuración en el servidor (nunca desde el navegador): URL de la API root y colección en
  `THREAT_INTEL_SOURCE_URLS`, credenciales en un secreto del servidor;
- paginación con `added_after` y `next`, cada página por el mismo parser STIX
  ([stix-support.md](stix-support.md)) y el mismo staging;
- las mismas defensas SSRF de `http.py`, tamaño y número de objetos acotados.

Otros adapters previstos con el mismo contrato: avisos de fabricante y proveedores
comerciales opcionales. Ninguno es requisito para usar Sentra.
