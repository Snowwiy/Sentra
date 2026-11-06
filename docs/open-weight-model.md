# Modelo open-weight opcional (Fase 7C.1 y 7C.2)

Sentra puede usar un modelo de lenguaje open-weight (Qwen, Llama, Mistral, Gemma, Phi,
DeepSeek...) servido en el propio equipo o en la red local para **ayudar al analista**:
resumir resultados, explicar el riesgo, proponer hipótesis y redactar borradores. Es una capa
opcional encima de lo que ya existe (AI Security Insights de la Fase 4J, gestor de modelos de
la 4J.2). No es parte del motor de detección ni de la evidencia.

Resumen de garantías:

- **Desactivado por defecto** (`AI_ENABLED=false`). Sin modelo, todo Sentra funciona igual.
- **Sin Internet**. El destino es siempre `AI_BASE_URL`; un destino externo solo con
  `AI_ALLOW_EXTERNAL=true` explícito y https. **Nunca hay fallback** a otro proveedor: si el
  modelo local no responde, la respuesta es un error claro.
- **Solo lectura**. El modelo no ejecuta herramientas, no confirma acciones, no escribe en
  casos ni cambia detecciones, alertas, riesgo o eventos. Lo que devuelve se guarda como un
  insight aparte, etiquetado como del modelo.
- **Grounding obligatorio**. Cada afirmación lleva referencias cortas (`R1`, `D2`...) que el
  servidor traduce a datos reales de Sentra; las inventadas se descartan con aviso y una
  respuesta sin ninguna referencia válida se rechaza (`ai_ungrounded_response`).
- **Mismos permisos que el usuario**. El asistente solo ve los resultados de herramientas
  que el usuario ya puede ver y respeta el site elegido.

**Política de privacidad estricta del asistente de la consola (7C-Security-Fix1, decisión de
Jesus del 2026-10-29)**, detalle en [fase-7c-security-fix1.md](fase-7c-security-fix1.md):

- **Activación administrativa explícita**: `AI_CONSOLE_ASSIST_ENABLED=false` por defecto; solo
  un administrador del servidor lo activa en el `.env`.
- **Solo loopback**: el asistente solo habla con un modelo en el propio servidor
  (`127.0.0.0/8`, `::1` o `localhost`), también comprobado con la IP conectada. Una LAN
  autorizada con `AI_LOCAL_NETWORKS` sirve para AI Insights, nunca para la consola.
- **Revisión antes de enviar**: el analista ve el documento exacto (`POST /ai/console/context`)
  y confirma; el envío lleva su huella y, si los datos cambiaron, no se envía nada.
- **Minimización**: solo los resultados que el analista marca (nada por defecto), acotados, y
  sin valores con aspecto de secreto.
- **RBAC**: `ai:use` y `tools:execute` (analyst y admin); un viewer no comparte datos.
- **Auditoría** de la revisión, del envío (con la huella), de los bloqueos y de las
  discrepancias, sin contenido.

## Arquitectura

```
Navegador ──> API de Sentra ──> AIService ──> AIProvider (stdlib, OpenAI-compatible)
                 │                  │                │
                 │                  │                └──> servidor de modelo local
                 │                  │                     (llama.cpp, Ollama, vLLM, LM Studio...)
                 │                  └── ContextBuilder: lecturas cerradas y acotadas
                 └── RBAC, site, rate limit, auditoría
```

Sentra nunca arranca, descarga ni para procesos del runtime: el servidor de modelo lo instala
y lo gestiona el administrador (ver [local-model-manager.md](local-model-manager.md)).

## Compatibilidad con modelos open-weight (7C.1)

Los modelos pequeños y medianos no siguen las instrucciones con la misma disciplina que uno
grande. Sentra lo tolera sin aflojar la validación:

| Problema típico | Qué hace Sentra |
| --- | --- |
| Bloques de razonamiento `<think>…</think>` (Qwen3, DeepSeek-R1, QwQ) | Se eliminan antes de interpretar la respuesta y nunca se guardan. Un bloque sin cerrar (el modelo agotó `max_tokens` pensando) acaba en `ai_invalid_response` con el motivo `truncated_reasoning` (7C-Fix2). |
| Razonamiento en un campo aparte (`reasoning_content` de llama.cpp, vLLM) con `content` vacío | 7C-Fix2: se clasifica con `finish_reason` (`truncated_reasoning`, `reasoning_only`). `AI_REASONING_EFFORT=none` pide al servidor que no razone; solo se envía si se fija. |
| JSON dentro de un bloque ```` ```json ```` o con prosa alrededor | Se localiza el primer objeto JSON equilibrado y válido (respetando cadenas y escapes, con tope de 256 KiB). Nunca se evalúa nada. |
| Plantilla de chat sin rol `system` (Gemma y similares) | `AI_SYSTEM_PROMPT_MODE=user_prefix`: las instrucciones van delante en el único mensaje de usuario, separadas de forma explícita del documento de datos (JSON escapado). |
| Ventana de contexto corta (4k-16k tokens) | `AI_MAX_PROMPT_CHARS` limita el documento que se envía; el contexto se recorta antes y la respuesta lo dice, en vez de que el runtime trunque en silencio. |
| Modelo activo del gestor 4J.2 | Si hay un modelo activo en Configuración → IA local → Modelos, se usa su id de runtime; `GET /ai/status` lo indica con `model_source = local_manager` (o `settings` si sale de `AI_MODEL`). |

`GET /ai/status` añade `model_source`, `system_prompt_mode`, `console_assist_available` y
`console_max_executions`. La UI de la consola muestra el modo (Local AI), el modelo, su estado
y de dónde sale.

## Asistente de la Analyst Console (7C.2)

Panel «Asistente IA local» en la columna derecha de la consola. El analista ejecuta primero
herramientas de lectura o investigación del catálogo 7A; después marca los resultados que
quiere compartir (ninguno va marcado por defecto, hasta `AI_CONSOLE_MAX_EXECUTIONS`), elige una
tarea, revisa el documento que se enviará y pulsa «Enviar al modelo local»:

| Tarea | `task` | Qué devuelve |
| --- | --- | --- |
| Resumir | `summary` | Qué muestran los resultados, con referencias |
| Explicar riesgo | `explain_risk` | Por qué el riesgo del activo es el que es, citando contribuciones |
| Hipótesis | `hypotheses` | Explicaciones posibles, cada una con evidencia y «cómo validarla» |
| Borrador de nota | `draft_note` | Texto para revisar, con la cabecera fija de texto generado por IA |

Dos pasos (7C-Security-Fix1):

1. `POST /api/v1/ai/console/context` con lo que se quiere analizar. No llama al modelo:
   devuelve el documento exacto que lo recibiría (`document`, sin la hora de la petición), los
   elementos incluidos, cuántos valores con aspecto de secreto se retiraron
   (`redacted_values`), qué se seudonimiza, el modelo, el destino (`loopback`) y
   `context_sha256`.

   ```json
   {
     "task": "hypotheses",
     "execution_ids": ["<uuid>", "<uuid>"],
     "asset_id": "<uuid o null>",
     "detection_id": "<uuid o null>",
     "question": "¿Qué debería comprobar primero?"
   }
   ```

2. `POST /api/v1/ai/console/assist` con el mismo cuerpo más `"context_sha256": "<huella>"`,
   `"confirm_send": true` y, opcionalmente, `"refresh": true`. El servidor reconstruye el
   documento y, si su huella no coincide con la revisada, responde 409
   `console_context_changed` sin enviar nada.

Responde un `Insight` (el mismo contrato de AI Insights) con `result.hypotheses`,
`result.draft`, `result.origin` (`model` o `sentra`) y `tool_execution_ids`.

Reglas del servidor:

- Solo ejecuciones `succeeded` con salida y que **no** sean acciones
  (`console_execution_not_usable`, 422). Una acción describe lo que se hizo, no lo observado.
- Ejecuciones ajenas solo con `tools:manage`; si no, 404 (no se revela que existen).
- Como máximo `AI_CONSOLE_MAX_EXECUTIONS` resultados; activo **o** detección, no ambos
  (`console_assist_invalid`, 422).
- Con `AI_CONSOLE_ASSIST_ENABLED=false` (por defecto) responde `ai_console_disabled` (409)
  aunque AI Insights siga activo.
- Con `AI_BASE_URL` fuera de loopback responde `ai_console_loopback_required` (409) y audita
  `ai_console_blocked`; no se envía nada.
- Sin `context_sha256` o sin `confirm_send` responde `console_context_review_required` (422).
- Las hipótesis siempre salen con certeza `possible`; una hipótesis sin evidencia válida se
  descarta con aviso. El borrador lleva la cabecera
  «[Borrador generado por IA local: revisar contra la evidencia antes de usarlo]» y nunca se guarda en un caso por
  sí solo: el analista lo copia si quiere.
- Sin datos sobre los que trabajar no se llama al modelo: la respuesta es determinista, de
  Sentra (`origin = sentra`) y lo dice («Respuesta de Sentra (sin modelo)»).
- Caché por huella: el insight se reutiliza mientras los resultados (`output_sha256`) y la
  pregunta no cambien; `refresh=true` lo regenera.
- Rate limit por usuario y global, concurrencia acotada y auditoría `ai_analysis_*`, igual que
  el resto de la IA.

Separación visual en la UI: la respuesta del modelo lleva la etiqueta «Sugerencia del
modelo» y el aviso «No es evidencia»; los datos de Sentra citados van en una lista aparte con
enlace a su origen; las hipótesis llevan la etiqueta «Posible».

## Cómo activarlo

1. Instala un servidor de modelo OpenAI-compatible en el mismo equipo que la API de Sentra
   (el asistente de la consola solo acepta loopback). Ejemplos (Windows nativo, sin Docker):
   - **llama.cpp**: `llama-server.exe -m D:\Models\qwen2.5-7b-instruct-q4_k_m.gguf --port 8080 -c 16384`
   - **Ollama**: `ollama pull qwen2.5:7b` (escucha en `http://127.0.0.1:11434/v1`).
   - **LM Studio** o **vLLM** (Linux) con su servidor OpenAI-compatible.
2. En el `.env` del backend:

   ```ini
   AI_ENABLED=true
   AI_BASE_URL=http://127.0.0.1:8080/v1
   AI_MODEL=qwen2.5-7b-instruct
   # Asistente de la consola: apagado por defecto, se activa de forma explícita.
   AI_CONSOLE_ASSIST_ENABLED=true
   # Opcionales de la Fase 7C:
   # AI_SYSTEM_PROMPT_MODE=system        # user_prefix para Gemma y plantillas sin rol system
   # AI_MAX_PROMPT_CHARS=24000           # bájalo con contextos de 4k-8k tokens
   # AI_CONSOLE_MAX_EXECUTIONS=6
   # AI_TIMEOUT_SECONDS=60               # súbelo en CPU sin GPU
   ```

   Un servidor en otra máquina de la LAN (con `AI_LOCAL_NETWORKS`) solo sirve para AI
   Insights; la consola lo rechaza con `ai_console_loopback_required`. Ver
   [ai-security-insights.md](ai-security-insights.md).
3. Reinicia la API y comprueba `GET /api/v1/ai/status` (`available: true`,
   `console_assist_available: true`) o el panel de la consola.

Modelos orientativos: 7-8B cuantizados Q4/Q5 (Qwen2.5 7B, Llama 3.1 8B, Mistral 7B) dan
respuestas útiles con 8-16 GB de RAM o VRAM; 3-4B (Phi-3.5 mini, Qwen2.5 3B) funcionan en CPU
pero con más respuestas descartadas por formato o grounding. El gestor de modelos (4J.2)
recomienda según el hardware.

Para apagarlo: `AI_ENABLED=false` (toda la IA) o `AI_CONSOLE_ASSIST_ENABLED=false` (solo el
asistente de la consola).

## Errores y qué significan

| Código | HTTP | Significado |
| --- | --- | --- |
| `ai_not_configured` | 409 | IA desactivada o sin `AI_BASE_URL`/`AI_MODEL` |
| `ai_console_disabled` | 409 | Asistente de la consola apagado |
| `ai_destination_blocked` | 409 | El destino no es loopback ni red autorizada (o es externo sin permiso) |
| `ai_provider_unavailable` | 502 | El servidor de modelo no responde o el modelo no está cargado |
| `ai_timeout` | 504 | Superó `AI_TIMEOUT_SECONDS` |
| `ai_provider_rate_limited` | 503 | El runtime del modelo está saturado |
| `ai_busy` | 429 | Demasiados análisis en curso en Sentra |
| `ai_invalid_response` | 502 | La respuesta no es JSON válido con el formato esperado. 7C-Fix2: `details[0].reason` dice por qué (ver abajo) |
| `ai_ungrounded_response` | 502 | Ninguna afirmación cita datos reales de Sentra |
| `console_execution_not_usable` | 422 | Resultado fallido, sin salida o de una acción |
| `ai_console_loopback_required` | 409 | El modelo no está en loopback; la consola no envía nada fuera del servidor |
| `console_context_review_required` | 422 | Falta la revisión previa o la confirmación explícita |
| `console_context_changed` | 409 | Los datos cambiaron desde la revisión; no se envió nada |
| `permission_denied` | 403 | Falta `ai:use` o `tools:execute` |

En todos los casos Sentra no prueba otro proveedor y el resto de la consola sigue funcionando.

Motivos de `ai_invalid_response` (7C-Fix2; van en la respuesta, en la auditoría
`ai_analysis_failed` y en el log, nunca con el texto del modelo):

| Motivo | Qué pasó | Qué hacer |
| --- | --- | --- |
| `truncated_reasoning` | `finish_reason=length` mientras el modelo razonaba: no llegó a responder | `AI_REASONING_EFFORT=none` si el servidor lo acepta, o más `AI_MAX_OUTPUT_TOKENS` |
| `truncated` | Respuesta cortada por `max_tokens` (JSON incompleto) | Subir `AI_MAX_OUTPUT_TOKENS` |
| `reasoning_only` | Terminó solo con razonamiento | `AI_REASONING_EFFORT=none` |
| `empty_answer` | Respuesta vacía | Revisar el servidor y el modelo cargado |
| `invalid_json` | Texto que no es un objeto JSON | `AI_JSON_MODE=true` si el servidor lo acepta; plantilla de chat |
| `schema_mismatch` | JSON sin la estructura del análisis (`RawInsight`) | Modelo más capaz; un JSON genérico nunca vale como análisis |
| `unexpected_body` | El servidor no responde como la API de chat | Revisar `AI_BASE_URL` |

Las respuestas cortadas (`truncated`, `truncated_reasoning`) no se reintentan: con temperatura
0 y el mismo presupuesto darían lo mismo. Las demás se reintentan `AI_MAX_RETRIES` veces contra
el mismo servidor, como antes. `qa/e2e_ai_insights_reasoning.py` pide un análisis contra una
API en marcha y enseña el motivo.

## Seguridad

- **Prompt injection**: los datos del host (nombres de proceso, rutas, líneas de comando) van
  dentro de un documento JSON escapado; las instrucciones dicen que todo lo de ese documento son
  datos. Aunque el modelo obedeciera un texto malicioso, no tiene herramientas que ejecutar ni
  permisos que escalar: su salida se valida, se filtra por referencias y se pinta como texto.
- **Privacidad**: la consola solo envía a loopback, tras revisión y sin secretos (ver arriba).
  Con `AI_REDACT` se seudonimizan además usuarios, hostnames, IPs, rutas y propietarios antes
  de enviar y se restauran al recibir.
- **Sin persistencia del razonamiento**: los bloques `<think>` se descartan.
- **Sin alteración de eventos**: la IA no puede ocultar, borrar ni modificar eventos,
  detecciones, alertas ni el ledger de riesgo; no hay endpoint que lo permita.
- **Auditoría**: cada análisis registra usuario, tipo, modelo, versión del prompt, duración y
  resultado (sin el contenido del prompt). En la consola, además: `ai_console_context_reviewed`
  (huella, ejecuciones, elementos, valores retirados), la huella en `ai_analysis_requested` y
  `ai_analysis_completed`, `ai_console_context_mismatch` y `ai_console_blocked`.

## Limitaciones

- Calidad dependiente del modelo: uno pequeño puede dar respuestas pobres o ser descartado por
  formato o grounding con frecuencia. Sentra lo dice en vez de rellenar.
- Probado en la nube con un servidor OpenAI-compatible simulado (`qa/console_assist_fake_llm.py`)
  que reproduce `<think>`, JSON en bloque y referencias inventadas. Falta la prueba con
  llama.cpp/Ollama reales en el hardware de Jesus.
- El asistente analiza resultados ya ejecutados; no propone ni lanza herramientas nuevas.
- Sin streaming: la respuesta llega completa al terminar.
