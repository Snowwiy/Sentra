# Fase 7F.5: Wazuh (alertas exportadas)

Wazuh es una **integración opcional y de solo lectura**. Sentra no instala, configura ni controla Wazuh, no usa su API, no guarda credenciales de Wazuh y nunca escribe en él. Lee el `alerts.json` que el manager ya genera (una alerta JSON por línea) de dos formas:

- **Sensor 0.9.0**: lector de ficheros (`type = "file"`, `format = "wazuh_alerts"`), con las mismas garantías que Suricata (docs/fase-7f-suricata.md): rutas permitidas, sin enlaces, offsets, rotación, truncado y límites.
- **Importación manual**: un admin sube un `alerts.json` exportado (fuente con transporte `upload`).

```toml
[[siem.inputs]]
name = "wazuh"
type = "file"
format = "wazuh_alerts"
allowed_dir = "/var/ossec/logs/alerts"
paths = ["alerts.json"]
```

El usuario del sensor necesita permiso de lectura sobre ese fichero (grupo `wazuh` en Linux). Sentra no cambia permisos de Wazuh.

La API de Wazuh no se integra en esta fase: exigiría guardar credenciales de Wazuh en Sentra, que es diseño de seguridad crítico y necesita una decisión explícita.

## Campos (conector `wazuh_alerts` 1.0.0)

| alerts.json | Sentra |
|---|---|
| `id` | `external_id`, `data.alert_id` |
| `timestamp` | `observed_at` (con zona; sin zona o inválida se rechaza) |
| `rule.id` | `rule_id`, `signature_id` |
| `rule.level` | `source_severity` ("level N"), `data.rule_level`, `data.level_bucket` |
| `rule.description` | `message` |
| `rule.groups` | `tags`, `data.rule_groups` |
| `rule.firedtimes` | `data.firedtimes` |
| `rule.mitre.id` / `rule.mitre.tactic` | `mitre_techniques` / `data.mitre_tactic` (TA…) y `data.mitre_tactic_names` |
| `agent.id`, `agent.name`, `agent.ip` | `data.agent_id`, `hostname` y `data.agent_name`, `data.agent_ip` |
| `manager.name`, `decoder.name`, `location` | `data.manager`, `data.decoder`, `data.location` |
| `data.srcip`, `dstip`, `srcport`, `dstport`, `protocol` | 5-tupla |
| `data.dstuser` / `srcuser` / `user` | `username` |

Todos los eventos son `wazuh.alert`, categoría `detection`, confianza `low`: una regla de Wazuh que salta es evidencia externa, no una intrusión confirmada. Se rechazan registros sin `rule.id` o con un nivel fuera de 0-15 (`invalid_schema`). La IP `any` que Wazuh usa para el propio manager no es una dirección y se descarta. Identidad para deduplicar: id de la alerta, regla y hora; reimportar el mismo fichero no duplica.

La UI muestra estos datos en un bloque **"Según Wazuh"** del detalle del evento: lo que dice Wazuh, sin reinterpretar.

## Severidad: solo con política explícita

**Sin política no hay severidad.** Por defecto los cuatro tramos de nivel dan `unknown` y una alerta de Wazuh **no genera detecciones**. Un admin decide la traducción en la fuente (`config.severity_policy`). Recomendación de partida, basada en la escala documentada de Wazuh:

```json
{"severity_policy": {"0-3": "informational", "4-7": "low", "8-11": "medium", "12-15": "high"}}
```

Revísela con los niveles que su organización usa en reglas propias.

## Identidad: el nombre del agente no es identidad

- `agent.ip` (rol `host`, método `agent_ip`): identifica un activo solo si exactamente un activo del site la tiene como IP principal. Confianza baja; media si además el nombre del agente coincide con ese mismo activo.
- `agent.name` solo: veredicto `hostname_hint`. El activo se propone en la UI, pero el evento **no queda atribuido y no genera señal**. Un nombre se repite, se reutiliza y lo escribe el propio host.
- `data.srcip` / `dstip`: mismas reglas que Suricata (app/siem/identity.py).
- Nunca se crea un activo a partir de una alerta.

## Sin incidentes duplicados con las detecciones nativas

El agente de Sentra y Wazuh suelen ver los mismos eventos del host. Cada alerta queda con un **origen** (`attribution.origin`, visible en la UI):

| Origen | Significado | ¿Detección? |
|---|---|---|
| `native` | Detección del motor propio de Sentra (agente, NDR) | Es la detección nativa |
| `imported` | Alerta de Wazuh con activo atribuido, sin corroborar | SIEM-EXT-001, confianza baja |
| `correlated` | Además, el NDR de Sentra vio la misma comunicación | SIEM-EXT-001, confianza media |
| `probable_match` | Hay una detección nativa del mismo activo, en ±15 min, con la misma técnica MITRE (técnica padre o subtécnica) o el mismo tema | **No**: se guarda un enlace explicado a la detección nativa |
| `insufficient_evidence` | Sin activo atribuible, o solo el nombre del agente | No |

Temas reconocidos (grupo de Wazuh → categoría de regla nativa): `authentication_failed`, `authentication_failures`, `authentication_success`, `win_authentication_failed` → authentication; `adduser`, `account_changed`, `group_changed`, `sudo` → account; `service_installed` → persistence; `powershell` → scripting. Una coincidencia solo de tiempo no basta.

Las detecciones SIEM-EXT-001 siguen el flujo normal (alertas, incidentes, riesgo como familia, ver docs/fase-7f-suricata.md).

## Privacidad, permisos y retención

Usuario, nombre de equipo, mensaje, ubicación y extracto se consideran sensibles: solo con `siem:evidence`. Retención de la fuente o `SIEM_EVENT_RETENTION_DAYS`.

## Limitaciones conocidas

- Fixtures sintéticos con la estructura documentada de `alerts.json` de Wazuh 4.x. **Sin validación con un manager de Wazuh real.**
- La comparación con detecciones nativas se hace al ingerir: si la nativa llega después, existen las dos. La vista "Relacionados" del evento (7F.6) las muestra juntas con la explicación de la coincidencia; no se borra ninguna.
- No se lee `alerts.log` (texto) ni ficheros comprimidos del archivo de Wazuh.
- Sin API de Wazuh (ver arriba).
