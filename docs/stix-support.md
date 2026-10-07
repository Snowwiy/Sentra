# Soporte de STIX 2.x (Fase 5C)

Sentra importa un **subset seguro** de STIX 2.0 y 2.1 como indicadores (IOCs). No es una
plataforma STIX: no evalúa patrones, no hay motor de grafos ni TAXII (ver
[threat-intel-sources.md](threat-intel-sources.md#taxii-21-no-implementado)). Código:
`app/threat_intel/stix.py`.

## Qué se acepta

- Un bundle `{"type": "bundle", "objects": [...]}` o un sobre TAXII `{"objects": [...]}`.
- Objetos `indicator` con `pattern_type: "stix"` (o sin él, STIX 2.0) cuyo patrón es **una
  sola comparación de igualdad** de esta lista blanca:

  | Patrón | Tipo en Sentra |
  |--------|----------------|
  | `[ipv4-addr:value = '…']` | `ipv4` (o `cidr` si es una red) |
  | `[ipv6-addr:value = '…']` | `ipv6` (o `cidr`) |
  | `[domain-name:value = '…']` | `domain` |
  | `[url:value = '…']` | `url` |
  | `[email-addr:value = '…']` | `email` |
  | `[file:hashes.'SHA-256' = '…']`, `[file:hashes.sha256 = '…']` | `sha256` |
  | `[file:hashes.'SHA-1' = '…']`, `[file:hashes.sha1 = '…']` | `sha1` |
  | `[file:hashes.MD5 = '…']` | `md5` |

- `malware`, `threat-actor`, `campaign` e `intrusion-set` solo como **metadatos** (su
  nombre), unidos a un indicador mediante relaciones `indicates`. Se muestran en el detalle
  del indicador.

Del `indicator` se usan: `id` (identificador externo), `pattern`, `indicator_types` (2.1) o
`labels` (2.0) para la clasificación, `confidence` (0-100), `valid_from`, `valid_until`,
`revoked`, `created`/`modified` (primera/última vez), `labels` como etiquetas, `name` y
`description`, y `external_references` (solo URLs http(s), nunca se visitan).

### Clasificación

| `indicator_types` / `labels` | Clasificación |
|------------------------------|---------------|
| `malicious-activity`, `compromised`, `attribution` | `malicious` |
| `anomalous-activity`, `anonymization` | `suspicious` |
| `benign` | `benign` |
| nada o cualquier otro | `unknown` |

Aparecer en un bundle **no** hace malicioso a un valor: sin tipo declarado queda `unknown`,
que no aporta riesgo ni crea detecciones.

### Confianza

`confidence` 0-100 se traduce a `low` / `medium` / `high` (escala de STIX) y el valor original
se conserva. Sin `confidence`: `medium`, con el original vacío (no se inventa una cifra).

## Qué NO se acepta

Se cuenta en la previsualización como **unsupported** (`unsupported_pattern`) y no se
importa, sin error:

- patrones con `AND`, `OR`, `FOLLOWEDBY`, varias observaciones, operadores distintos de `=`
  (`!=`, `>`, `LIKE`, `MATCHES`, `IN`...), calificadores `WITHIN`, `REPEATS`, `START/STOP`;
- otros objetos o propiedades (`file:name`, `process:...`, `network-traffic:...`);
- `pattern_type` distinto de `stix` (Sigma, Snort, YARA, PCRE...);
- `observed-data`, `sighting`, `report`, `attack-pattern`, `course-of-action`... (se ignoran).

## Seguridad

- El patrón **nunca** se evalúa ni compila: se reconoce con una expresión regular anclada de
  la lista blanca y el valor se extrae como literal (escapes `\'` y `\\`).
- Lectura defensiva del JSON (`safe_json.py`): tamaño antes de parsear, profundidad medida
  antes de `json.loads` (un JSON muy anidado es 422 `intel_too_deep`, no un desbordamiento de
  pila), sin `NaN`/`Infinity`, sin claves duplicadas.
- Límites de número de objetos (`THREAT_INTEL_MAX_RECORDS`), longitud de patrón (1024),
  etiquetas (20), referencias (20) y relaciones por indicador (10).
- Nombres, etiquetas y descripciones son texto no confiable: se guardan acotados, sin
  caracteres de control, y la UI los pinta como texto (una etiqueta `<script>` es solo una
  cadena). La IA los recibe como datos, nunca como instrucciones.
- Los valores pasan por la misma validación y normalización que `sentra-ioc/1`.

## Ejemplo

```json
{
  "type": "bundle",
  "id": "bundle--5d0092c5-5f74-4287-9642-33f4c354e56d",
  "objects": [
    {
      "type": "indicator",
      "spec_version": "2.1",
      "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "created": "2026-10-01T00:00:00Z",
      "modified": "2026-10-01T00:00:00Z",
      "pattern": "[ipv4-addr:value = '203.0.113.7']",
      "pattern_type": "stix",
      "valid_from": "2026-10-01T00:00:00Z",
      "indicator_types": ["malicious-activity"],
      "confidence": 85
    },
    {
      "type": "malware",
      "spec_version": "2.1",
      "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b",
      "name": "ExampleBot",
      "is_family": true
    },
    {
      "type": "relationship",
      "spec_version": "2.1",
      "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
      "relationship_type": "indicates",
      "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
      "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b5891b"
    }
  ]
}
```

Importación: `Inteligencia → Importar` con formato STIX (previsualizar y confirmar) o
`python -m app.cli threat-intel-import --source local-iocs --format stix bundle.json`.
