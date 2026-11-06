# 7C-Security-Fix1: privacidad estricta del asistente de la consola

Corrección incremental sobre la Fase 7C (Dev `8319d57` + parche 7C). Decisión de Jesus del
2026-10-29: la salida de herramientas solo se envía al modelo tras revisión explícita y solo
por loopback. Servidor y frontend **0.6.1**; sin migraciones (siguiente libre 0051) ni
dependencias nuevas; agente y sensor sin cambios.

## Qué había en 7C y qué cambia

| Control pedido | Estado en 7C | 7C-Security-Fix1 |
| --- | --- | --- |
| Proveedor local por loopback | El destino era `AI_BASE_URL` con las reglas de 4J.1: loopback **o** una LAN autorizada (`AI_LOCAL_NETWORKS`, `AI_LOCAL_HOSTS`), con comprobación de la IP conectada | El asistente de la consola solo acepta una URL de loopback (`127.0.0.0/8`, `::1`, `localhost`) y su proveedor se crea sin redes LAN ni externos: la IP conectada tiene que ser loopback (anti DNS rebinding). Error `ai_console_loopback_required` (409). AI Insights conserva sus reglas de 4J.1 |
| Sin fallback externo | Ya existía: un solo proveedor, sin reintento contra otro destino | Sin cambios; ahora también con `allow_external=False` forzado en la consola |
| Activación administrativa explícita | `AI_CONSOLE_ASSIST_ENABLED=true` por defecto (inactivo sin `AI_ENABLED=true`) | `AI_CONSOLE_ASSIST_ENABLED=false` por defecto; un administrador del servidor lo activa en el `.env` |
| Minimización de datos | Solo las ejecuciones elegidas, acotadas a `AI_MAX_PROMPT_CHARS`; seudonimización opcional (`AI_REDACT`). La UI marcaba por defecto los resultados más recientes | Ningún resultado marcado por defecto. Antes de construir el documento se sustituyen por `[REDACTED]` los valores con aspecto de secreto (claves `password`, `token`, `secret`, `cookie`, `authorization`...; `Bearer`; `usuario:clave@` en URLs) en salidas, resúmenes y detalles de detección, con el mismo redactor que los logs |
| Revisión del contexto compartido | No existía: el asistente enviaba al pulsar la tarea | `POST /ai/console/context` devuelve el documento exacto y su huella; `POST /ai/console/assist` exige `context_sha256` y `confirm_send=true`; si los datos cambiaron, 409 `console_context_changed` y no se envía nada. La UI muestra la revisión con «Enviar al modelo local» y «Cancelar» |
| RBAC | `ai:use` + `tools:read` (un viewer podía pedir un análisis del activo) | `ai:use` + `tools:read` + `tools:execute` (analyst y admin) en la revisión y el envío; ejecuciones ajenas solo con `tools:manage` (sin cambios) |
| Auditoría | `ai_analysis_requested/completed/failed` sin contenido | Además `ai_console_context_reviewed` (huella, ejecuciones, activo o detección, elementos, caracteres, valores retirados, destino), la huella y las ejecuciones en `ai_analysis_*`, `ai_console_context_mismatch` y `ai_console_blocked`. Nunca el contenido ni la pregunta |

## La huella (`context_sha256`)

SHA-256 de un JSON canónico (`sort_keys`) con la tarea, la versión del prompt, la pregunta tal
como se envía (seudonimizada si `AI_REDACT` lo pide) y el documento de datos completo salvo la
hora de la petición (`now`), que cambia en cada llamada. El documento se construye igual en la
revisión y en el envío (mismas lecturas, minimización, seudonimización y presupuesto), así que
las huellas coinciden mientras los datos no cambien. Si entre la revisión y el envío cambia el
estado de un activo, un resultado o una contribución de riesgo, la huella cambia y hay que
revisar de nuevo.

## API

| Método | Ruta | Uso |
| --- | --- | --- |
| POST | `/api/v1/ai/console/context` | Revisión: `{task, execution_ids, asset_id?, detection_id?, question?}` → `ConsoleContextPreview` (`context_sha256`, `destination: "loopback"`, `model`, `items`, `redacted_values`, `pseudonymized`, `chars`, `question`, `document`) |
| POST | `/api/v1/ai/console/assist` | Envío: el mismo cuerpo + `context_sha256`, `confirm_send: true`, `refresh?` |
| GET | `/api/v1/ai/status` | Nuevo `console_assist_reason` (por qué no está disponible) |

Errores nuevos: `ai_console_loopback_required` (409), `console_context_review_required` (422),
`console_context_changed` (409). Falta de `tools:execute`: 403 `permission_denied`.

## Compatibilidad

Cambio de contrato del asistente: un frontend 0.6.0 (7C original) contra un servidor 0.6.1
recibe `console_context_review_required` al pedir un análisis; hay que actualizar los dos a
la vez (van en el mismo parche). El resto de 7C no cambia.

## Activarlo (Windows)

```ini
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:8080/v1      # llama.cpp u Ollama en el mismo equipo
AI_MODEL=qwen2.5-7b-instruct
AI_CONSOLE_ASSIST_ENABLED=true             # activación explícita del asistente
```

Con `AI_BASE_URL` en otra máquina (aunque esté en `AI_LOCAL_NETWORKS`), AI Insights funciona y
la consola explica que solo usa un modelo en este servidor.

## Pruebas

- `backend/tests/test_console_privacy_fix1.py` (17): apagado por defecto, URLs de loopback
  frente a LAN, nombres y externos, IP conectada solo loopback, configuración del proveedor
  de la consola, envío sin revisión o sin confirmación, huella de otra tarea, datos cambiados,
  documento revisado igual al enviado, secretos fuera del documento y del envío, viewer 403 y
  auditoría sin contenido.
- `backend/tests/test_console_ai_7c.py` adaptado al flujo de revisión; `backend/tests/test_auth.py`
  ya no trata `/ai/console/assist` como análisis permitido al viewer (ahora 403).
- `frontend/src/components/console/ConsoleAssistant.test.tsx`: revisión, cancelar sin enviar,
  datos cambiados, motivo de no disponibilidad, nada marcado por defecto.
- `qa/e2e_console_assist.py`: 18 comprobaciones contra una API en marcha.
