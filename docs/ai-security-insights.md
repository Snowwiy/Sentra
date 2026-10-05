# AI Security Insights (Fases 4J y 4J.1)

Capa de interpretación asistida por IA sobre los datos que Sentra ya calculó. Ayuda al
analista a responder "¿qué está pasando?", "¿por qué importa?", "¿qué evidencia lo
respalda?" o "¿qué reviso primero?". **No sustituye** al Detection Engine (4H), al motor de
correlación ni al Risk Engine (4I): severidad, confianza, score y nivel de riesgo siempre
vienen de esos motores deterministas; el modelo solo los interpreta.

Está **desactivada por defecto** (`AI_ENABLED=false`). Sin IA, Sentra funciona exactamente
igual: ingesta, detecciones, riesgo, alertas y dashboard. La UI muestra "IA no configurada".

**Local-first (Fase 4J.1).** El modo recomendado es **Local AI**: un servidor de modelos en
la misma máquina o en una LAN privada autorizada. Ninguna función de Sentra necesita OpenAI,
Anthropic, Gemini, Azure OpenAI, AWS Bedrock ni ningún proveedor cloud, y por defecto ningún
dato de seguridad sale de la infraestructura de Sentra.

## Arquitectura recomendada: Sentra Server + Local Model Server

```
              red interna / misma máquina
┌──────────────────┐  POST /v1/chat/completions  ┌──────────────────────────┐
│  Sentra Server   │ ──────────────────────────> │  Local Model Server      │
│  (API + BD)      │ <────────────────────────── │  Ollama, llama.cpp,      │
│  AI_ENABLED=true │      JSON (análisis)        │  vLLM u otro compatible  │
└──────────────────┘                             └──────────────────────────┘
        ✗  sin tráfico a Internet: AI_ALLOW_EXTERNAL=false (por defecto)
```

- El servidor de modelos expone la API de chat compatible con OpenAI en `/v1`. Es solo un
  **protocolo**: Sentra no habla con OpenAI ni depende de ningún fabricante, y la UI lo
  presenta como "Local AI", nunca como "OpenAI".
- Funciona sin Internet y sin DNS externo si `AI_BASE_URL` usa una IP literal (`127.0.0.1`,
  `::1`, IP de la LAN) o `localhost`.
- Si el modelo local se apaga o no responde, solo falla la petición de análisis que lo pidió
  (`502 ai_provider_unavailable` / `504 ai_timeout`). Ingesta, detecciones, riesgo, alertas y
  dashboard siguen igual, y **no hay fallback automático** a otro proveedor (ni cloud).

## Arquitectura

```
petición del analista (sesión + monitoring:read + ai:use, CSRF)
  -> alcance determinista (app/ai/intent.py, sin IA)
  -> context builder: lecturas CERRADAS y acotadas (app/ai/context.py)
  -> huella de datos y caché (app/ai/freshness.py, tabla ai_insights)
  -> rate limit por usuario y global + tope de concurrencia
  -> proveedor (app/ai/provider.py, app/ai/openai_compat.py), sin conexión a BD abierta
  -> validación de schema (app/ai/output.py)
  -> validación de evidencias (grounding) y avisos
  -> persistencia + auditoría -> respuesta
```

| Pieza | Fichero | Responsabilidad |
|---|---|---|
| `AIProvider`, `AIRequest`, `AIResponse` | `app/ai/provider.py` | Contrato mínimo de proveedor y errores controlados |
| `OpenAICompatibleProvider` | `app/ai/openai_compat.py` | `POST {AI_BASE_URL}/chat/completions` con stdlib, timeouts y tope de tamaño |
| `ContextBuilder` | `app/ai/context.py` | Únicas lecturas de BD para la IA; acota, sanea, seudonimiza y asigna referencias |
| `resolve_scope` | `app/ai/intent.py` | Decide (sin IA) qué contexto usa una pregunta de Ask |
| Plantillas | `app/ai/prompts.py` | Política común + tarea por tipo, versionadas (`asset_summary_v1.p1`) |
| Validación | `app/ai/output.py` | Schema JSON, grounding, avisos de afirmaciones no respaldadas |
| `AIInsightService` | `app/services/ai_service.py` | Orquestación, caché, límites, persistencia, auditoría |
| `ai_insights` | migración `0020` | Resultados validados, huella de datos, métricas técnicas |

Nada de esto se ejecuta en la ingesta, en el job de detección ni en el de riesgo: no hay
inferencia por heartbeat, telemetría, evento o detección. Solo bajo demanda del usuario.

## Tipos de insight

| Tipo | Endpoint | Contexto |
|---|---|---|
| `asset_summary` | `POST /ai/assets/{id}/analyze` | Estado, detecciones activas (correlaciones y graves primero), riesgo 4I con contribuciones e historial, exposición, cambios 24 h, alertas activas |
| `detection_analysis` | `POST /ai/detections/{id}/analyze` | Detección, catálogo de la regla (qué detecta, por qué importa), últimas 15 evidencias, detecciones del mismo activo en ±24 h, riesgo del activo |
| `risk_explanation` | `POST /ai/risk/assets/{id}/analyze` | Explicación determinista 4I, contribuciones, cambios recientes, menos detecciones |
| `soc_summary` | `POST /ai/soc/analyze` (`window`: 24h/7d/30d) | Detecciones altas/críticas de la ventana, activos con más riesgo, transiciones de nivel, factores principales, alertas activas |
| `ask` | `POST /ai/ask` | El que decida `resolve_scope` (activo, detección o flota) |

Lecturas: `GET /ai/status`, `GET /ai/insights` (filtros `kind`, `asset_id`, `detection_id`) y
`GET /ai/insights/{id}`.

## Grounding y referencias de evidencia

- El context builder asigna a cada elemento citable un identificador corto: `A` activo,
  `D` detección, `E` evento, `V` evidencia (evento ya purgado), `X` exposición (puerto),
  `C` contribución de riesgo, `S` punto del historial de riesgo, `L` alerta, `H` cambio.
- El modelo solo puede citar esos identificadores. El servidor los traduce a referencias
  reales (`type`, `id` público de Sentra, etiqueta y activo) y **descarta cualquier otra**:
  un ID inventado, un UUID escrito por el modelo o un número suelto nunca llegan a la UI.
- Un hallazgo sin evidencia válida se descarta. Si el modelo daba hallazgos y ninguno
  sobrevive, la respuesta se rechaza (`502 ai_ungrounded_response`) y no se guarda.
- Cada hallazgo lleva una certeza de un vocabulario cerrado: `observed`, `detected`,
  `correlated`, `possible`, `requires_validation`. Un valor fuera del vocabulario se degrada
  a `requires_validation`, nunca sube.
- Si el texto afirma un compromiso confirmado ("fue comprometido", "is compromised"...) y el
  contexto no tiene una detección de confianza alta y severidad alta/crítica, se añade un aviso
  visible: la afirmación se presenta como hipótesis.
- Sin datos (p. ej. flota vacía) no se llama al modelo: se responde de forma determinista
  "No hay datos suficientes en Sentra para responder."

## Proveedores: local y externo

Un único protocolo: la API de chat compatible con OpenAI, que exponen servidores locales
(Ollama en `/v1`, llama.cpp server, vLLM, LM Studio, LocalAI...) y, opcionalmente, proveedores
externos. No hay SDK ni dependencia nueva, y no se asume ninguna plataforma concreta.
`AI_API_KEY` es opcional: sin clave no se envía `Authorization` (no hace falta clave dummy).

**Local vs externo** se decide solo con `AI_BASE_URL`, sin resolver DNS (fail closed):

- local: loopback (`127.0.0.0/8`, `::1`), `localhost`, una IP dentro de `AI_LOCAL_NETWORKS`
  o un nombre listado en `AI_LOCAL_HOSTS`;
- externo: cualquier otro nombre o IP. **Una IP privada fuera de `AI_LOCAL_NETWORKS` es
  externa**: la LAN se autoriza de forma explícita, no por estar en un rango privado.
- prohibido siempre (incluso con `AI_ALLOW_EXTERNAL=true`): link-local (incluye
  `169.254.169.254`, metadatos de nube), `0.0.0.0`, multicast y rangos reservados.

`AI_LOCAL_NETWORKS` solo acepta subredes de RFC 1918 (`10/8`, `172.16/12`, `192.168/16`) o ULA
(`fc00::/7`); Internet, link-local, CGNAT o `0.0.0.0/0` se rechazan al arrancar.

**Verificación de la IP real.** Tras conectar y antes de enviar ningún dato, el proveedor
comprueba la IP a la que conectó: un destino local debe ser loopback o estar en
`AI_LOCAL_NETWORKS`. Así un nombre de `AI_LOCAL_HOSTS` (o `localhost`) que resuelva a otra
dirección por DNS manipulado o un `/etc/hosts` erróneo no recibe nada
(`409 ai_destination_blocked`). En https el handshake TLS ocurre antes de esta comprobación
(sale el nombre del servidor, no datos de Sentra).

**Externos: solo opción explícita.** Con `AI_ALLOW_EXTERNAL=false` (por defecto) un proveedor
externo se rechaza (`409 ai_not_configured`) sin abrir ninguna conexión ni consultar DNS. Si un
admin lo activa a propósito, el externo exige `https`. Nunca es necesario para ninguna función.

Detalles del cliente HTTP: no sigue redirecciones, no usa los proxies del entorno (el destino
es exactamente `AI_BASE_URL`), timeout de conexión, de lectura por bloque y total (cada lectura
se acota con el tiempo restante), respuesta máxima 512 KB, TLS verificado con el almacén del
sistema. Un único destino por análisis: solo se reintenta ante JSON inválido y contra el mismo
servidor.

## Estado del proveedor (`GET /ai/status`)

| `state` | Significado | ¿Se conecta? |
|---|---|---|
| `disabled` | `AI_ENABLED=false` | No |
| `not_configured` | Falta `AI_BASE_URL` o `AI_MODEL` | No |
| `local_available` | Local y el servidor responde | Health check |
| `local_unavailable` | Local y el servidor no responde (apagado, puerto cerrado, 5xx) | Health check |
| `external_blocked` | Externo sin `AI_ALLOW_EXTERNAL`, IP privada no autorizada o destino prohibido | No |
| `external_available` / `external_unavailable` | Externo permitido explícitamente | Health check |

El health check es `GET {AI_BASE_URL}/models` sin datos de Sentra, con 3 s de conexión y 5 s en
total, cacheado 15 s por proceso (y se invalida tras un fallo real del modelo). Un `404` cuenta
como disponible (hay servidores sin `/models`). La respuesta incluye `mode_label` ("Local AI" /
"External AI"), `model`, `reachable`, `health_detail` y `checked_at`; nunca la URL, la clave ni
el cuerpo de la respuesta del servidor. La UI muestra, por ejemplo,
`Local AI · qwen2.5:14b-instruct · Disponible` y, si el servidor local está caído, avisa de que
Sentra sigue funcionando y de que no se usará ningún otro proveedor.

## Configuración

| Variable | Por defecto | Qué hace |
|---|---|---|
| `AI_ENABLED` | `false` | Activa los análisis bajo demanda |
| `AI_PROVIDER` | `openai_compatible` | Único valor soportado |
| `AI_BASE_URL` | — | URL base terminada en `/v1` (`http://127.0.0.1:11434/v1`, `http://192.168.10.20:8000/v1`) |
| `AI_MODEL` | — | Nombre del modelo en ese servidor |
| `AI_API_KEY` | — | Opcional (los servidores locales no la necesitan). Solo servidor; se envía como `Authorization: Bearer`. Nunca se registra, audita ni llega al navegador |
| `AI_TIMEOUT_SECONDS` | `60` | Tiempo total máximo por llamada |
| `AI_CONNECT_TIMEOUT_SECONDS` | `5` | Conexión |
| `AI_READ_TIMEOUT_SECONDS` | `45` | Espera máxima entre bloques de respuesta |
| `AI_MAX_CONTEXT_ITEMS` | `40` | Elementos citables por análisis |
| `AI_MAX_OUTPUT_TOKENS` | `1200` | `max_tokens` pedido al modelo |
| `AI_ALLOW_EXTERNAL` | `false` | Permite proveedores externos (opción explícita, no necesaria; exige https) |
| `AI_LOCAL_NETWORKS` | — | Redes privadas (CIDR) autorizadas para el servidor de IA en la LAN, p. ej. `192.168.10.0/24` |
| `AI_LOCAL_HOSTS` | — | Nombres de host del servidor de IA; deben resolver a loopback o a `AI_LOCAL_NETWORKS` |
| `AI_REDACT` | — | `usernames,hostnames,ips,paths` a seudonimizar |
| `AI_JSON_MODE` | `true` | Pide `response_format: json_object` (desactívalo si el servidor no lo soporta) |
| `AI_INSIGHT_TTL_MINUTES` | `60` | Caducidad de un insight (stale aunque los datos no cambien) |
| `AI_RATE_LIMIT_PER_USER_PER_MINUTE` | `6` | Llamadas reales al modelo por usuario |
| `AI_RATE_LIMIT_GLOBAL_PER_MINUTE` | `30` | Llamadas reales al modelo en total |
| `AI_MAX_CONCURRENT` | `2` | Llamadas simultáneas; el resto recibe `429 ai_busy` |
| `AI_MAX_RETRIES` | `1` | Reintentos ante JSON inválido |

Ejemplos (recomendado: modelo local, sin clave y sin Internet). Cualquier servidor compatible
sirve; los puertos son los habituales de cada uno.

Ollama en la misma máquina:

```env
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:11434/v1
AI_MODEL=qwen2.5:14b-instruct
```

llama.cpp server (`llama-server -m modelo.gguf --port 8080`) en la misma máquina:

```env
AI_ENABLED=true
AI_BASE_URL=http://127.0.0.1:8080/v1
AI_MODEL=modelo-local
# Si el servidor no acepta response_format:
# AI_JSON_MODE=false
```

vLLM en un servidor de la LAN, con redacción:

```env
AI_ENABLED=true
AI_BASE_URL=http://192.168.10.20:8000/v1
AI_LOCAL_NETWORKS=192.168.10.0/24
AI_MODEL=meta-llama/Llama-3.1-8B-Instruct
AI_REDACT=usernames,ips
```

Con nombre en vez de IP (necesita DNS interno o `hosts`; la IP resuelta debe estar en la red
autorizada):

```env
AI_BASE_URL=http://servidor-ia:8000/v1
AI_LOCAL_HOSTS=servidor-ia
AI_LOCAL_NETWORKS=192.168.10.0/24
```

Proveedor externo (solo si el admin lo decide explícitamente; los datos salen del servidor):

```env
AI_ALLOW_EXTERNAL=true
AI_BASE_URL=https://proveedor.example/v1
AI_API_KEY=...
```

El cliente nunca puede elegir proveedor, URL, modelo ni parámetros: los cuerpos de las
peticiones rechazan cualquier campo extra (`422`).

## Privacidad: qué sale del servidor

Por defecto (`AI_ENABLED=false`, `AI_ALLOW_EXTERNAL=false`) **ningún** dato sale de la
infraestructura de Sentra: ni telemetría, detecciones, eventos, hostnames, IPs, usernames,
procesos ni datos de riesgo. Con Local AI los datos solo viajan al servidor de modelos local
(loopback o LAN autorizada). El health check no envía datos de Sentra.

Solo cuando un usuario pide un análisis, y solo hacia `AI_BASE_URL`, sale:

- las instrucciones fijas de Sentra (sin datos);
- un documento JSON con el contexto acotado de ese análisis: nombre, IP, tipo, SO, estado y
  criticidad del activo; título, resumen, regla, severidad, confianza, estado, fechas y
  detalles acotados de detecciones; resúmenes y datos acotados de evidencias (pueden incluir
  cuentas, IPs de origen, nombres de proceso, rutas o líneas de comando); score, nivel,
  confianza, contribuciones y cambios de riesgo; puertos expuestos; cambios de inventario de
  las últimas 24 h (nombres de software/servicios/cuentas); alertas activas;
- la pregunta del analista (Ask).

No sale nunca: contraseñas, hashes, tokens de agente, sesiones, claves de enrollment, la
auditoría, usuarios del dashboard, telemetría cruda ni eventos que no formen parte de una
detección.

`AI_REDACT` seudonimiza antes de enviar (`[user-1]`, `[host-2]`, `[ip-3]`, `[path-4]`). Los
seudónimos son estables dentro de un análisis, así que el modelo sigue viendo que dos
evidencias hablan de la misma cuenta. Al volver, el servidor restaura los valores reales en el
texto que ve el analista. Limitación: en texto libre solo se sustituyen los valores que también
aparecen en campos estructurados (más IPv4 y rutas por patrón).

## Prompt injection

Hostnames, mensajes de eventos, nombres de proceso, líneas de comando, software, DNS y
usuarios vienen de los equipos monitorizados y pueden estar diseñados para atacar al modelo
("IGNORE ALL PREVIOUS INSTRUCTIONS..."). Defensas, en capas:

1. **Separación de canales**: el mensaje `system` contiene solo la política y la tarea
   versionadas, nunca datos. El mensaje `user` es un único documento JSON con tres claves fijas
   (`task`, `analyst_question`, `sentra_data`).
2. **Datos como valores JSON**: nada se concatena como texto libre ("Evento: " + raw). Los
   valores van serializados con `json.dumps`, que escapa comillas y saltos de línea: un valor no
   puede cerrar la estructura, añadir claves ni crear mensajes nuevos.
3. **Política explícita**: el sistema declara que todo `sentra_data` son datos no confiables y
   que un valor que parezca una instrucción se trata como dato sospechoso.
4. **Saneado y límites**: sin caracteres de control, longitudes acotadas, profundidad y número
   de claves limitados.
5. **Sin capacidades que abusar**: el modelo no tiene herramientas, no ejecuta SQL ni comandos,
   no abre URLs, no cambia estado. Aunque una inyección "funcionara", solo podría alterar texto,
   y ese texto pasa por el schema, el grounding y se muestra como texto plano marcado como
   "Análisis de IA".
6. **Salida inerte**: la UI no interpreta HTML ni Markdown, no genera enlaces desde el texto del
   modelo (solo desde referencias validadas a rutas propias) y no ofrece botones para copiar o
   ejecutar comandos.

Los tests `test_prompt_injection_in_data_travels_as_data` cubren hostname, usuario, proceso y
línea de comando maliciosos y una pregunta hostil.

## Sin ejecución de herramientas ni SQL

El modelo no consulta PostgreSQL ni elige consultas: `resolve_scope` decide de forma
determinista (referencia explícita de la UI, UUID en la pregunta, nombre exacto de un activo o
visión de flota con ventana y severidad por palabras clave) y el context builder ejecuta un
conjunto cerrado de lecturas. La IA de 4J no puede lanzar discovery, bloquear hosts, revocar
agentes, cambiar usuarios, resolver alertas ni modificar nada. Las acciones quedan para fases
posteriores y siempre con control humano.

## RBAC

Todas las rutas `/ai/*` exigen sesión, `monitoring:read` **y** `ai:use`. `ai:use` lo tienen
viewer, analyst y admin: la IA solo interpreta datos que el rol ya puede leer, así que nunca
amplía su alcance. Un rol sin cualquiera de los dos permisos recibe `403`. Los POST llevan CSRF.
Las preguntas de Ask son privadas de quien las hizo (otros usuarios no las ven en el historial
ni por id).

El gestor de modelos locales (`/ai/local/*`, Fase 4J.2) se lee con los mismos permisos, pero
cualquier cambio exige además `ai:manage`, que solo tiene admin: [local-model-manager.md](local-model-manager.md).

## Rate limiting y timeouts

- Por usuario (`AI_RATE_LIMIT_PER_USER_PER_MINUTE`) y global (`AI_RATE_LIMIT_GLOBAL_PER_MINUTE`),
  en memoria del proceso como el login. Solo cuentan las llamadas reales al modelo; las
  respuestas de caché no consumen cuota. `429 rate_limited` con `Retry-After`.
- `AI_MAX_CONCURRENT` llamadas simultáneas; el resto recibe `429 ai_busy` en vez de ocupar
  hilos de la API esperando.
- La conexión a PostgreSQL se libera antes de llamar al modelo: un modelo lento no agota el pool.
- Errores controlados, sin cuerpo del proveedor ni secretos: `ai_timeout` (504),
  `ai_provider_unavailable`, `ai_provider_auth_failed`, `ai_invalid_response`,
  `ai_ungrounded_response` (502), `ai_provider_rate_limited` (503), `ai_not_configured` y
  `ai_destination_blocked` (409).

## Caché y estado stale

Cada insight guarda una huella de los datos que lo respaldan (`data_version`):

- detección: estado, severidad, ocurrencias, `updated_at`, número de evidencias, nivel de riesgo
  del activo;
- activo: criticidad, nivel y último cambio material de riesgo, detecciones (número y último
  `updated_at`), puertos (aperturas/cierres), alertas activas;
- flota: detecciones activas, último punto de historial de riesgo, número de activos, alertas.

No incluye heartbeat, `last_seen` ni `calculated_at` del riesgo (cambian continuamente sin que
nada material cambie). La clave de caché es (tipo, entidad, huella, proveedor, modelo, versión
de prompt, redacción, pregunta y, en Ask, usuario). Un POST sin `refresh` devuelve el último
insight con esa clave si no ha caducado (`cached: true`). Al leer, un insight es `stale` si
caducó (`expired`), si la huella actual difiere (`data_changed`) o si la entidad ya no existe
(`entity_deleted`); la UI lo marca como "Desactualizado".

## Auditoría y métricas

`audit_events`: `ai_analysis_requested`, `ai_analysis_completed` (con `cached`) y
`ai_analysis_failed` (con el código de error), con actor, tipo, alcance, entidad, proveedor,
modelo, versión de prompt, elementos de contexto, latencia, evidencias y referencias
descartadas. Nunca la clave, tokens de sesión o de agente, el prompt, el contexto ni la
pregunta (solo su longitud).

Métricas técnicas por insight (tabla y log `sentra.ai`): elementos de contexto, latencia,
caracteres enviados y recibidos y uso informado por el proveedor.

## Rendimiento (qa/perf_ai.py)

Datos sintéticos de `qa/perf_risk.py` (1000 activos, 20 000 detecciones) en PostgreSQL 16 de
desarrollo, proveedor falso instantáneo:

| Medida | Resultado |
|---|---|
| Contexto de activo | ~28 ms, 14 SQL, 26 elementos, ~9.8 K caracteres |
| Contexto de detección | ~26 ms, 11 SQL, 9 elementos, ~5.6 K caracteres |
| Contexto de flota 24 h / 30 d | ~64 / ~85 ms, 14 SQL, 33 elementos, ~10.9 K caracteres |
| Análisis completo (contexto + validación + persistencia + auditoría) | ~31-38 ms |
| Respuesta desde caché | ~35 ms (reconstruye contexto para la huella) |
| Listado de 25 insights con stale | ~12 ms, 9 SQL |

La latencia real la domina el modelo (segundos) y no es un criterio universal: depende del
hardware y del proveedor.

## Limitaciones

- El estado `local_available` solo indica que el servidor responde; no comprueba que el modelo
  `AI_MODEL` esté cargado (algunos servidores ignoran el nombre). El primer análisis lo confirma.
- El rate limit y el tope de concurrencia son por proceso (como el login): con varios workers
  el límite efectivo se multiplica.
- La redacción del texto libre es por valores conocidos y patrones (IPv4, rutas), no un
  detector general de datos personales.
- `resolve_scope` reconoce activos por nombre exacto (hostname, nombre resuelto o IP); una
  pregunta ambigua usa la visión de flota.
- Linux todavía no envía eventos de seguridad: los análisis de equipos Linux se basan en
  inventario, exposición y riesgo.
- Los insights no tienen retención automática todavía (crecen solo por acciones de usuarios
  limitadas por rate limit).
- La calidad del texto depende del modelo; la validación garantiza formato y referencias, no
  que la interpretación sea acertada. Por eso la UI recuerda: "Análisis asistido por IA.
  Verifique la evidencia antes de tomar acciones."
