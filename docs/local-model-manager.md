# Gestor de modelos locales (Fase 4J.2)

Sentra AI es local-first (Fase 4J.1). Esta fase añade un gestor para el administrador:
detecta el hardware del servidor, habla con el runtime local configurado (llama.cpp, Ollama o
vLLM), registra modelos GGUF, estima cuánta memoria necesitan, recomienda modelos de forma
determinista, los selecciona con health check y mide su rendimiento real con un benchmark.

UI: **Configuración → IA local → Modelos** (`/settings/ai`). API: `/api/v1/ai/local/*`.

No reimplementa 4J/4J.1: reutiliza `AIConfig`, la política de destinos (loopback,
`AI_LOCAL_NETWORKS`, `AI_LOCAL_HOSTS`, IP real verificada antes de enviar, sin redirecciones ni
proxies) y el cliente `OpenAICompatibleProvider`. Todas las peticiones al runtime pasan por
ese cliente, así que heredan sus garantías.

## Qué hace y qué no

Hace:

- Detectar hardware (manual, con botón "Volver a detectar"; nunca en bucle).
- Consultar el runtime configurado en `AI_BASE_URL` (solo ese endpoint; no escanea la red).
- Registrar modelos: un `.gguf` dentro de `AI_MODEL_DIRECTORIES` o un modelo que ya sirve el
  runtime (p. ej. un tag de Ollama).
- Estimar memoria y recomendar, con razones en texto.
- Seleccionar el modelo activo con validación, health check y carga.
- Benchmark local bajo demanda.

No hace:

- No arranca ni para procesos del runtime ni ejecuta comandos construidos con datos del
  usuario. La única herramienta externa es `nvidia-smi` con argumentos fijos y timeout de 3 s.
- No descarga nada (ver "Diseño de descargas").
- No borra ficheros: "Quitar registro" solo borra la fila de Sentra.
- No usa nunca un proveedor externo como fallback. Si el runtime local falla, la operación
  falla con un error claro y el modelo anterior sigue activo.
- No hace routing entre modelos (solo deja preparado el contrato, ver "Routing futuro").

## Cuándo opera

El gestor solo habla con el runtime si `AI_ENABLED=true`, hay `AI_BASE_URL` y el destino es
**local** (loopback, `AI_LOCAL_NETWORKS` o `AI_LOCAL_HOSTS`). Con IA desactivada o un
proveedor externo, el gestor muestra el motivo y no abre ninguna conexión (cubierto por
tests). El hardware, los modelos registrados y las recomendaciones sí funcionan: son datos
del propio servidor. No se exige `AI_MODEL`, porque precisamente el gestor sirve para elegirlo.

Funciona **sin Internet**: no hay DNS, descargas ni consultas externas. El catálogo va dentro
del código (`backend/app/ai/local/catalog.json`).

## Permisos

| Rol | Puede |
|---|---|
| viewer | Ver estado, hardware, modelos y recomendaciones (sin rutas de fichero ni modelos descubiertos) |
| analyst | Lo mismo y usar la IA (AI Insights) |
| admin (`ai:manage`) | Además: re-detectar hardware, cambiar runtime, registrar, seleccionar, benchmark, cancelar, quitar registro |

La UI oculta las acciones, pero la API exige `ai:manage` igualmente.

## Auditoría

`ai_model_registered`, `ai_model_selected`, `ai_model_load_failed`,
`ai_model_benchmark_started`, `ai_model_benchmark_completed` (también fallido o cancelado,
con su estado), `ai_model_unregistered`, `ai_runtime_changed`. Sin claves, URLs ni
prompts.

## Detección de hardware

`backend/app/ai/local/hardware.py`, sin dependencias nuevas:

- SO, versión y arquitectura: `platform`.
- CPU: modelo y núcleos. Windows: registro (`HARDWARE\DESCRIPTION\System\CentralProcessor\0`)
  y `GetLogicalProcessorInformation` vía ctypes; Linux: `/proc/cpuinfo`.
- RAM total/disponible: `GlobalMemoryStatusEx` (Windows) o `/proc/meminfo` (Linux).
- GPU:
  - NVIDIA: `nvidia-smi --query-gpu=...` (VRAM total/libre exacta, driver).
  - AMD/Intel en Windows: adaptadores de pantalla del registro
    (`HardwareInformation.qwMemorySize`). En Linux: `/sys/class/drm/card*/device`
    (`mem_info_vram_total` para AMD).
  - Una AMD con menos de 2 GiB declarados se trata como memoria compartida (APU) y no cuenta
    para offload. Intel integrada siempre es compartida.
- Disco libre: en el primer directorio de modelos, o en el del servidor si no hay.

Cada fuente falla por separado: si algo no se puede leer, el perfil lo deja vacío y añade un
aviso, nunca inventa un valor. El perfil vive en memoria del proceso (no se persiste) y se
renueva solo con "Volver a detectar".

## Runtimes

Abstracción `LocalAIRuntime` (`backend/app/ai/local/runtimes.py`), separada de `AIProvider`:
`AIProvider` genera análisis y `LocalAIRuntime` gestiona modelos.

| Operación | llama.cpp (`llama-server`) | Ollama | vLLM | Genérico OpenAI |
|---|---|---|---|---|
| `health` | `/health` + `/props` | `/api/version` | `/health` + `/version` | `/v1/models` |
| `list_models` | `/v1/models` (fichero cargado, `n_params`, `n_ctx_train`) | `/api/tags`, `/api/ps` | `/v1/models` (`max_model_len`) | `/v1/models` |
| `load_model` | No (se carga al arrancar con `-m`) | Sí (`/api/generate` vacío) | No | No |
| `unload_model` | No | Sí (`keep_alive: 0`) | No | No |
| `benchmark` | Tiempos del runtime (`timings`) | Tiempos del runtime (ns) | Extremo a extremo | Extremo a extremo |
| Offload GPU→RAM | Sí | Sí | No | Desconocido |

`capabilities` dice qué puede hacer cada runtime de verdad; la UI lo muestra tal cual. Si el
runtime no puede cargar un modelo bajo demanda (llama.cpp, vLLM), seleccionar comprueba que el
modelo cargado es el elegido y, si no, falla con el comando a usar (`llama-server -m <fichero>`).

`AI_RUNTIME` fija el runtime por defecto; el admin puede cambiarlo en la UI (se guarda en
`ai_local_settings`). Al cambiarlo se desactiva el modelo activo, porque pertenece al anterior.
La detección automática solo prueba el endpoint configurado.

## GGUF y cuantización

`backend/app/ai/local/gguf.py` lee la cabecera GGUF v2/v3 con límites (claves, tensores,
longitud de cadenas, arrays y bytes totales de cabecera), sin cargar pesos ni ejecutar nada:

- arquitectura, nombre, contexto nativo, capas, cabezas, cabezas KV, dimensión, expertos (MoE);
- número de parámetros = suma de los elementos de todos los tensores (exacto);
- cuantización: `general.file_type`; si falta, el tipo de tensor dominante.

Cuantizaciones con bits por peso y factor de calidad conocidos: F32, F16, BF16, Q8_0, Q6_K,
Q5_K_M, Q5_K_S, Q5_0, Q5_1, Q4_K_M, Q4_K_S, Q4_0, Q4_1, Q3_K_L, Q3_K_M, Q3_K_S, Q2_K, Q2_K_S,
IQ4_XS, IQ4_NL, IQ3_M, IQ3_S, IQ3_XS, IQ3_XXS, IQ2_M, IQ2_S, IQ2_XS, IQ2_XXS, IQ1_M, IQ1_S.
Otra cuantización se muestra por su nombre; un GGUF registrado usa su tamaño real igualmente.

Los modelos partidos (`-00001-of-00003.gguf`) se registran por la primera parte; Sentra suma
el tamaño de todas. Registrar una parte intermedia da error.

El SHA-256 se calcula en segundo plano (un solo hilo); mientras tanto la UI muestra
"Calculando…".

### Importación segura

`resolve_model_path` (`backend/app/ai/local/paths.py`):

1. La ruta debe ser absoluta y estar dentro de una raíz de `AI_MODEL_DIRECTORIES`, primero de
   forma léxica y después de resolver enlaces (`realpath`): un symlink o junction que salga de
   la raíz se rechaza.
2. Rutas UNC (`\\servidor\recurso`) y de dispositivo (`\\?\`) se rechazan siempre.
3. Extensión `.gguf`, fichero regular y tamaño entre un mínimo y `AI_MODEL_MAX_FILE_GB`.
4. La cabecera debe ser GGUF válida.

El descubrimiento de ficheros sin registrar recorre como mucho 2 niveles, 5000 entradas y 500
ficheros por raíz, sin seguir enlaces que salgan de ella. Solo lo ven los admin.

## Estimación de memoria

Las cifras son **estimaciones** y la UI las marca como tales.

```
total = pesos + KV cache + overhead
pesos     = tamaño real del GGUF (o parámetros × bits por peso para el catálogo)
KV cache  = 2 × capas × contexto × cabezas KV × dim. por cabeza × 2 bytes (f16) × paralelo
overhead  = 512 MiB + 2 % de los pesos + 8 MiB por cada 1K de contexto
```

- **KV cache**: crece lineal con el contexto. A 100K+ puede superar a los pesos: un modelo de
  8B con 128K de contexto necesita del orden de 16 GiB solo de KV. Si faltan capas o cabezas,
  no se estima y el modelo queda "Sin datos suficientes".
- **VRAM útil** = VRAM de GPUs dedicadas − margen (`AI_MEMORY_SAFETY_MARGIN_PERCENT`, 10 %).
  Varias GPU NVIDIA suman si el runtime admite reparto entre GPUs.
- **RAM útil** = RAM total − máx(2 GiB, 15 %) (sistema, PostgreSQL y Sentra) − margen.

Colocación, en este orden:

1. `full_gpu`: todo cabe en VRAM.
2. `partial_offload`: parte de las capas en GPU y el resto en RAM, solo con runtimes que lo
   admiten. Se informa la fracción en GPU.
3. `cpu_only`: todo en RAM.
4. `does_not_fit`: no cabe.

## Contexto

La UI ofrece 8K, 16K, 32K, 64K, 100K, 128K y 256K. Nunca se recomienda un contexto mayor que
el nativo del modelo: el modelo pasa a "No recomendado" con la razón. El análisis normal de
Sentra usa `AI_DEFAULT_CONTEXT_TOKENS` (16K por defecto), porque Detection, Correlation y Risk
Engine ya resumen la evidencia. Los contextos de 100K+ se evalúan con su coste real de memoria
y velocidad: soportado no significa eficiente.

## Motor de recomendación

`backend/app/ai/local/engine.py`. Es **determinista**: ningún LLM decide. Con las mismas
entradas (hardware, modelo, runtime, contexto, perfil y benchmarks) da siempre la misma salida,
con razones, avisos y limitaciones en texto.

Estado por modelo:

| Estado | Cuándo |
|---|---|
| `recommended` | El mejor del perfil entre los que caben y no son lentos |
| `compatible` | Cabe en GPU, o en CPU con velocidad aceptable |
| `compatible_with_offload` | Cabe repartido entre GPU y RAM |
| `slow` | Cabe, pero la velocidad estimada o medida es lenta |
| `not_recommended` | No cabe, contexto mayor que el nativo, runtime incompatible o datos insuficientes |

Velocidad estimada (sin benchmark), heurística documentada en el código: en GPU es rápida;
con offload es moderada si al menos el 80 % está en GPU y lenta si no; en CPU es moderada con
pesos de hasta 5 GiB y lenta por encima. Un contexto de 64K+ fuera de la GPU baja una clase.
Los MoE cuentan 1/4 de los pesos. **Un benchmark sustituye a la estimación**: la medición pesa
más que la heurística.

Perfiles:

- **Menor uso de recursos** (`low_resource`): menos memoria total con un mínimo de 3B
  parámetros efectivos.
- **Equilibrado** (`balanced`): calidad (log2 de los parámetros efectivos) más bonus por
  velocidad.
- **Mejor calidad** (`quality`): el modelo más capaz que cabe sin ser lento.
- **Máxima velocidad** (`max_speed`): clase de velocidad y tokens/s medidos.
- **Sentra Security Analysis** (badge "Recommended for Sentra"): calidad con tope de 32B
  efectivos, más un bonus fuerte por velocidad y uno pequeño por estar todo en GPU. Un 14B
  rápido gana a un 32B con offload, pero un 32B que cabe entero en GPU gana a ambos.

No hay reglas especiales para 27B o 32B: todos los modelos se tratan igual, por memoria,
contexto y velocidad. Si ninguno cumple, no se fuerza una recomendación.

Catálogo: 14 modelos de referencia con su arquitectura (capas, cabezas KV, dimensión) para
estimar sin descargar nada. Es extensible: `AI_MODEL_CATALOG_FILE` apunta a un JSON con el
mismo formato que `catalog.json`; sus entradas se añaden y, si repiten `id`, sustituyen a las
incluidas.

## Selección del modelo activo

`POST /ai/local/models/{id}/select`, en este orden:

1. Validar el modelo (existe, es del runtime configurado, el fichero sigue en su sitio).
2. Hacer un health check del runtime.
3. Cargarlo si el runtime lo permite, o comprobar que es el que está cargado.
4. Enviar una completion mínima de prueba.

Solo si todo va bien se guarda como activo. Si algo falla, se audita `ai_model_load_failed`,
la API responde 409/502 y **el modelo anterior sigue activo**.

AI Insights usa el modelo activo en lugar de `AI_MODEL` (`effective_ai_config`), y solo
cuando el destino es local. Sin modelo activo, usa `AI_MODEL` como antes.

## Benchmark

`backend/app/ai/local/benchmark.py`:

- Prompt fijo sobre mínimo privilegio, sin datos de Sentra. 2 ejecuciones: la primera puede
  incluir la carga perezosa del modelo, así que la velocidad sale de la segunda ("en caliente").
  Como máximo `AI_BENCHMARK_MAX_TOKENS` tokens y `AI_BENCHMARK_TIMEOUT_SECONDS` en total.
- Mide tiempo de carga (si el runtime carga bajo demanda), TTFT, tokens/s de prompt y de
  generación, y pico de RAM/VRAM del sistema muestreado cada segundo. Es el pico de todo el
  sistema, no del proceso del runtime.
- llama.cpp y Ollama dan los tiempos medidos por el propio runtime. vLLM y el genérico se
  miden de extremo a extremo y la UI lo indica.
- Concurrencia 1: un segundo benchmark responde 409 `ai_benchmark_busy`.
- Se ejecuta en un hilo aparte, nunca en el hilo de la API ni al arrancar. Cancelación
  cooperativa. Los benchmarks que quedaron "en curso" tras un reinicio se marcan como
  fallidos.
- Al terminar actualiza la clase de rendimiento y la recomendación.

Clases de rendimiento por tokens/s de generación, configurables con
`AI_PERFORMANCE_THRESHOLDS` (por defecto `30,15,7`): Excelente ≥ 30, Bueno ≥ 15,
Usable ≥ 7, Lento por debajo.

## Diseño de descargas (no implementado)

En esta fase no hay descargas. La arquitectura prevista, para cuando Jesus lo decida:

- Un `DownloadManager` con una cola de un elemento, solo bajo acción explícita del admin.
- Fuentes permitidas configuradas por URL exacta. Requiere `AI_ALLOW_DOWNLOADS=true`, que hoy
  no existe.
- Descarga a `<directorio>/.partial` y verificación del SHA-256 esperado antes de mover el
  fichero a una raíz de `AI_MODEL_DIRECTORIES`. Después, el registro normal (cabecera GGUF).
- Reanudación por rango, límite de tamaño, comprobación de espacio libre previa y auditoría.

Esto toca red externa y la cadena de suministro, así que es decisión de seguridad de Jesus.

## Routing futuro

`GET /ai/local/runtime` devuelve `slots: ["default"]`. Un futuro router "fast"/"deep" añadiría
slots (p. ej. modelo rápido para resúmenes y profundo para Ask Sentra AI) sin cambiar el
contrato actual. No hay routing implementado.

## Persistencia

Migración `0021`:

- `ai_local_models`: modelos registrados con metadata, ruta, checksum y estado.
- `ai_model_benchmarks`: resultados de benchmark.
- `ai_local_settings`: fila única con el runtime elegido y el modelo activo
  (`ON DELETE SET NULL`).

## Variables de entorno

| Variable | Por defecto | Uso |
|---|---|---|
| `AI_RUNTIME` | `openai_compatible` | `llama_cpp`, `ollama`, `vllm` u `openai_compatible` |
| `AI_MODEL_DIRECTORIES` | vacío | Raíces permitidas separadas por `;`, rutas absolutas. Vacío = no se puede importar GGUF |
| `AI_MODEL_MAX_FILE_GB` | 256 | Tamaño máximo de un GGUF |
| `AI_MODEL_CATALOG_FILE` | — | JSON extra de catálogo |
| `AI_DEFAULT_CONTEXT_TOKENS` | 16384 | Contexto operativo para recomendar |
| `AI_MEMORY_SAFETY_MARGIN_PERCENT` | 10 | Margen sobre VRAM y RAM |
| `AI_BENCHMARK_MAX_TOKENS` | 128 | Tokens generados por ejecución |
| `AI_BENCHMARK_TIMEOUT_SECONDS` | 180 | Tiempo máximo total |
| `AI_PERFORMANCE_THRESHOLDS` | `30,15,7` | Umbrales tok/s para Excelente, Bueno y Usable |

## API

Todo bajo `/api/v1/ai/local`. Lectura con `monitoring:read` y `ai:use`; los cambios exigen
además `ai:manage`.

| Método | Ruta | Uso |
|---|---|---|
| GET | `/hardware` | Perfil de hardware (en caché) |
| POST | `/hardware/refresh` | Volver a detectar (admin) |
| GET | `/runtime` | Runtime, capacidades, health, modelo activo, External AI |
| PATCH | `/settings` | `{"runtime": "..."}` (admin) |
| GET | `/models` | Registrados y, para admin, descubiertos |
| POST | `/models/register` | `{"path": "..."}` o `{"runtime_model": "..."}` (admin) |
| GET | `/models/{id}?context=&profile=` | Detalle, evaluación y benchmarks |
| POST | `/models/{id}/select` | Activar (admin) |
| POST | `/models/{id}/unregister` | Quitar registro, nunca el fichero (admin) |
| POST | `/models/{id}/benchmark` | Iniciar benchmark (admin, 202) |
| GET | `/benchmarks/{id}` | Estado y resultado |
| POST | `/benchmarks/{id}/cancel` | Cancelar (admin) |
| GET | `/recommendations?profile=&context=&include_catalog=&limit=` | Recomendaciones |

Errores nuevos:

- `local_model_path_rejected` (422)
- `local_model_invalid_file` (422)
- `local_model_not_loaded` (409)
- `local_model_unavailable` (409)
- `local_model_runtime_mismatch` (409)
- `ai_benchmark_busy` (409)
- `ai_runtime_operation_unsupported` (409)

## Limitaciones

- Las estimaciones de memoria son aproximadas: el overhead real depende del runtime, el
  backend (CUDA, ROCm, Vulkan, Metal) y opciones como flash attention o KV cuantizado. El
  margen de seguridad lo cubre en parte, y el benchmark es la medida real.
- VRAM de AMD/Intel en Windows sale del registro: puede ser aproximada o faltar. Sin
  `nvidia-smi` no hay VRAM libre en tiempo real.
- El pico de RAM/VRAM del benchmark es del sistema, no del proceso del runtime.
- Sentra no arranca `llama-server` ni vLLM: cambiar de modelo en esos runtimes requiere
  reiniciarlos a mano con el modelo nuevo.
- Hardware, snapshot del runtime (15 s) y cola de benchmark viven en memoria del proceso:
  con varios workers de la API cada uno tiene los suyos.
- El catálogo es una referencia: los modelos reales pueden diferir en cabezas o contexto. Un
  GGUF registrado usa siempre su propia cabecera.
