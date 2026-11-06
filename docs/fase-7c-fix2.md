# 7C-Fix2: IA local con modelos "thinking" y revisión de detecciones de servicios Windows

Corrección incremental sobre Dev `8319d57` + Fase 7C + 7C-Security-Fix1. Servidor y frontend
**0.6.2**; agente 0.6.2 y sensor 0.7.0 sin cambios; sin migraciones (sigue en 0050, la
siguiente libre es 0051); sin dependencias nuevas. Todos los controles de 7C-Security-Fix1 se
conservan.

## 1. `ai_invalid_response` con llama.cpp

### Causa

Flujo: AI Security Insights → `AIInsightService._infer` → `OpenAICompatibleProvider.complete`
→ `answer_content` → `parse_json` (schema `RawInsight`) → `ground` (evidencia real).

Con un modelo "thinking" (Qwen y similares) llama.cpp devuelve el razonamiento en
`message.reasoning_content` y deja `message.content` vacío hasta que el modelo termina de
pensar. Sentra pedía `max_tokens = AI_MAX_OUTPUT_TOKENS` (1200) sin `reasoning_effort`: si el
razonamiento consume el presupuesto, el servidor corta (`finish_reason=length`) con `content`
vacío. Sentra lo trataba como "no es JSON", lo reintentaba una vez con el mismo presupuesto
(misma respuesta, el doble de espera) y devolvía `ai_invalid_response` sin decir por qué.

Encaja con las pruebas de Jesus: sin desactivar el razonamiento, `content` vacío; con
`reasoning_effort="none"`, respuesta inmediata y JSON válido. **Es una inferencia** a partir de
esas pruebas y del código: no se ha ejecutado con su llama.cpp ni con su modelo; en la nube se
reproduce con un servidor que imita a llama.cpp. No se ha visto relación con el tamaño de
contexto (un prompt que no cabe en llama.cpp da un error HTTP 400, que Sentra devuelve como
`ai_provider_unavailable`, no como respuesta inválida).

### Corrección

- `AI_REASONING_EFFORT` (opcional, vacío por defecto): si se fija (`none`, `minimal`, `low`,
  `medium`, `high`) se envía `reasoning_effort` en `/chat/completions`. Vacío = no se envía,
  así ningún otro proveedor recibe un parámetro que no conoce. `response_format=json_object`
  se mantiene (con `AI_JSON_MODE=true`). El modelo sigue saliendo de `AI_MODEL` (o del modelo
  activo del gestor 4J.2); no se fuerza ninguno ni se tocan los presets del servidor.
- El proveedor lee `finish_reason` y el tamaño de `reasoning_content`/`reasoning` (nunca guarda
  ni registra el texto). `content: null` ya no se rechaza como cuerpo inválido: se clasifica.
- `ai_invalid_response` lleva ahora un motivo en `details[0].reason`:
  `truncated_reasoning`, `truncated`, `reasoning_only`, `empty_answer`, `invalid_json`,
  `schema_mismatch`, `unexpected_body` (tabla en `docs/open-weight-model.md`).
- Las respuestas cortadas por `max_tokens` no se reintentan; las demás, como antes
  (`AI_MAX_RETRIES`).
- La auditoría `ai_analysis_failed` y el log `ai analysis failed` añaden el motivo,
  `finish_reason`, caracteres de salida y de razonamiento, tokens de salida e intentos. Nunca
  el prompt, la respuesta ni el razonamiento.
- Un JSON genérico (`{"status":"ok","message":"SENTRA_LOCAL_OK"}`) no es un análisis: falla con
  `schema_mismatch`. El grounding de evidencia no cambia.
- La UI (AI Insights y consola) explica el motivo sin nombrar variables de configuración.
- `AI_MAX_OUTPUT_TOKENS` sigue en 1200: con el razonamiento desactivado el análisis simulado
  cabe de sobra y no hay medidas con el modelo real que justifiquen cambiarlo. Si con el modelo
  real aparece `truncated`, se sube en el `.env`.

### Configuración recomendada para el caso de Jesus

```ini
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:18081/v1
AI_MODEL=qwen36-fast-80k
AI_REASONING_EFFORT=none
```

La consola usa la misma configuración y conserva todo lo de 7C-Security-Fix1 (apagada por
defecto, solo loopback con IP conectada comprobada, revisión con huella, 409 si cambia el
contexto, redacción, `tools:execute`, auditoría sin contenido, sin fallback, sin ejecutar
herramientas).

## 2. Detecciones recurrentes de servicios Windows (CORR-002, PER-001)

Revisión del código actual (CORR-002 v5 y PER-001 v3 de 7B-Fix1), sin cambios en reglas.

Ya cubierto y probado (`tests/test_service_identity_fix1.py`, `test_risk_v7.py`):

- Una instancia por usuario (`WpnUserService_*`, `OneSyncSvc_*`) vista en el **inventario** solo
  queda `verified` con el bit 0x80, el `svchost.exe` exacto de System32, el mismo grupo `-k`
  que la plantilla y firma válida de Microsoft; entonces PER-001 no abre nada. Con agente
  anterior a 0.6.2 queda `probable` (baja/baja, una detección por plantilla). Si algo no casa
  es `suspicious` (alta): el nombre nunca decide.
- CORR-002 exige relación causal (7045 posterior al script, hijo del PowerShell que ejecuta el
  binario del servicio, servicio sospechoso o modificado después del script). La coincidencia
  temporal sola queda como contexto en SCR-001. El 7045 y el inventario de la misma instalación
  comparten clave, y el riesgo v7 une SCR-001, PER-001 y CORR-002 de la misma cadena.

Hueco encontrado, **no corregido** por falta de evidencia:

- Un **evento 7045** siempre se clasifica como `installed/verified`
  (`rules.service_class`). Si llega un 7045 con nombre de instancia por usuario, PER-001 abre
  una detección media/alta con una clave por nombre (un sufijo nuevo en cada inicio de sesión
  da una detección nueva), y CORR-002 cuenta ese 7045 posterior a un 4104 sospechoso como
  relación fuerte. Además el agente envía `ServiceType` del 7045, pero el servidor no lo guarda.
- No se ha podido demostrar que Windows registre un 7045 al crear instancias por usuario (no
  hay un Windows en la nube ni una fuente que lo confirme). Cambiar la regla sin esa prueba
  sería rebajar detecciones a ciegas.
- Cómo comprobarlo en el equipo de Jesus: `qa/diagnose_service_detections.sql` (solo lectura)
  lista las PER-001 y CORR-002 con `sources`, clasificación y `causal_links`. Si las detecciones
  de `WpnUserService_*`/`OneSyncSvc_*` tienen `sources` con `service_installed` (7045), el hueco
  es real y la corrección propuesta para una fase posterior es: guardar `ServiceType` del 7045 y
  clasificarlo con el mismo verificador que el inventario (plantilla, grupo, `svchost.exe` de
  System32 y, en cuanto llegue el inventario, tipo y firma), sin exclusiones por nombre. Si
  vienen del inventario con `probable`, falta actualizar el agente a 0.6.2 en ese equipo; si
  vienen con `suspicious`, hay que revisarlas.

## Pruebas

- `backend/tests/test_ai_reasoning_fix2.py` (19): parámetro no enviado por defecto, `none` con
  modo JSON, proveedor estricto que rechaza el parámetro, validación de valores, `content: null`,
  siete casos de clasificación, JSON y schema (incluido el JSON genérico), Insights con motivo
  preciso y sin reintento, reintento de JSON inválido, Insights y consola de punta a punta con
  el proveedor HTTP real contra un llama.cpp simulado en 127.0.0.1, y cuerpo inesperado auditado con su motivo.
- `frontend/src/api/client.test.ts` (2) y `ConsoleAssistant.test.tsx` (1): mensajes por motivo.
- `qa/e2e_ai_insights_reasoning.py`: un análisis contra una API en marcha, con el motivo.
- `qa/console_assist_fake_llm.py --mode llamacpp`: simulador de llama.cpp con razonamiento.
