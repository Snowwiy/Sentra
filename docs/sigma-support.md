# Soporte Sigma (Fase 5A)

Sentra importa reglas [Sigma](https://github.com/SigmaHQ/sigma) y las convierte al formato
declarativo `sentra-rule/1` ([custom-detection-rules.md](custom-detection-rules.md)). Admite
un **subconjunto** de Sigma: lo que Sentra no puede ejecutar fielmente con los datos que recoge
se marca como **no soportado**. Nunca se finge cobertura.

## Seguridad del importador

El YAML es contenido **no confiable**:

- Cargador YAML seguro propio: sin tags de Python ni tags no estándar (`yaml_tag`), sin
  anclas ni alias (`*x`, evita "billion laughs"), un solo documento, como mucho 64 KB, 12
  niveles de anidamiento y 4000 nodos. Las fechas quedan como texto.
- Nada del YAML se ejecuta, se evalúa como plantilla ni se interpreta como SQL. Las
  `references` se guardan como texto y **nunca se abren**.
- El YAML original se guarda (para trazabilidad) y la UI lo muestra como texto.
- Una regla importada queda **siempre en borrador** (`draft`): un admin la revisa, la prueba y
  la activa a mano.

## Resultado de una importación

| Resultado | Significado |
|---|---|
| `imported` | Soportada; guardada en borrador |
| `imported_with_warnings` | Soportada con avisos (p. ej. cobertura parcial del logsource) |
| `updated` | Mismo `id` Sigma con contenido distinto: versión nueva (requiere `on_duplicate=update` y la `revision` actual) |
| `unchanged` | Mismo `id` y mismo contenido: no se crea nada |
| `unsupported` | YAML válido pero con algo que Sentra no puede ejecutar: se guarda en borrador con `compile_status=unsupported` y **no se puede activar** |
| `rejected` | YAML malformado o peligroso: no se guarda nada (queda `rule_import_failed` en la auditoría) |

Sin `on_duplicate=update`, importar un `id` existente con otro contenido devuelve 409. La
vista previa (`POST /sigma/preview`) dice de antemano si es un duplicado (`none`,
`identical`, `changed`, `retired`). Al reimportar se conservan los textos locales (por qué
importa, recomendaciones), la confianza y la categoría que el admin haya ajustado.

La lógica de una regla Sigma solo cambia **reimportando** su YAML; en la UI se editan los
textos, la severidad y la confianza.

## Logsources

| Sigma | Sentra | Soporte |
|---|---|---|
| `product: windows, service: security` | `windows_security` | completo |
| `product: windows, service: system` | `windows_system` | completo |
| `product: windows, service: application` | `windows_application` | completo |
| `product: windows, service: powershell` | `powershell` | parcial (sin texto de script) |
| `product: windows, service: windefend` | `windows_defender` | completo |
| `category: process_creation` (windows/linux) | `process` | **parcial**: solo ejecutables nuevos por snapshot; una regla sobre un ejecutable habitual solo coincide la primera vez que aparece en el activo. Activarla exige confirmarlo |
| Resto (sysmon, file_event, registry_*, dns, network_connection, linux auditd…) | — | no soportado |

## Detección

Soportado:

- Selecciones como mapa (Y entre campos) o lista de mapas (O), valores únicos o listas (O).
- `condition` con `and`, `or`, `not`, paréntesis, `1 of sel*`, `all of sel*`, `1 of them`,
  `all of them`.
- Modificadores `contains`, `startswith`, `endswith`, `all`, `re` (regex segura), `cased`, `i`,
  `exists`, `gt`, `gte`, `lt`, `lte`. Comodines `*` al inicio/fin se traducen a
  `contains`/`starts_with`/`ends_with`.
- Agregación `| count() [by campo] > N` o `>= N` con `timeframe` (dentro de `detection`), que
  se convierte en umbral con agrupación.

No soportado (resultado `unsupported`, con el motivo):

- Campos que Sentra no recoge: `CommandLine`, `ParentImage`, `ParentCommandLine`,
  `OriginalFileName`, `Hashes`, `ScriptBlockText`, `IntegrityLevel`, `CurrentDirectory` y en
  general cualquier campo fuera del catálogo del logsource.
- Búsquedas de palabras clave sueltas (listas sin campo).
- Modificadores `base64`, `base64offset`, `utf16*`, `wide`, `windash`, `cidr`, `expand`,
  `fieldref` y similares.
- `near`, agregaciones distintas de `count()`, `count(campo)`, correlaciones Sigma.
- Regex que no pasan el filtro de regex segura.

## Metadatos

| Sigma | Sentra |
|---|---|
| `title`, `description` | título y descripción |
| `id` | `sigma_id` (el identificador de Sentra es `SENTRA-SIGMA-nnnnnn`) |
| `level` | severidad: informational → informational, low → low, medium → medium, high → high, critical → critical |
| (sin equivalente) | confianza inicial `SIGMA_DEFAULT_CONFIDENCE` (`low` por defecto): una regla de la comunidad no está validada en este entorno |
| `tags: attack.tXXXX[.YYY]`, `attack.<táctica>` | MITRE técnica/subtécnica y táctica (solo con la forma exacta de ATT&CK); el resto de tags se conservan como etiquetas |
| `author`, `status`, `references`, `falsepositives`, `date`, `modified` | `sigma_metadata` (texto, acotado) |

## Ejemplo

```yaml
title: Muchos fallos de inicio de sesión
id: 5f1c2a39-7a52-4d39-9d7e-2f1f0d5b8a11
tags: [attack.credential_access, attack.t1110.001]
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  condition: selection | count() by TargetUserName >= 5
  timeframe: 10m
level: high
```

Se importa como `windows_security`, `event.code = 4625`, umbral 5 en 10 minutos agrupado por
`event.data.TargetUserName`, severidad alta, confianza baja, MITRE TA0006 / T1110.001.
