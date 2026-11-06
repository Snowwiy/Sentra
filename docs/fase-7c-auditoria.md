# Auditoría de la Fase 7C

Revisión de seguridad y calidad de lo que añade la Fase 7C, hecha sobre el código de la
entrega (Dev `8319d57` + parche 7C). Cada punto dice qué se comprobó y con qué.

## 1. Modelo open-weight (7C.1)

| Riesgo | Control | Comprobado con |
| --- | --- | --- |
| Salida a Internet o fallback a otro proveedor | El destino es solo `AI_BASE_URL`, revalidado (loopback o `AI_LOCAL_NETWORKS`, externo solo con `AI_ALLOW_EXTERNAL` y https); sin segundo proveedor en el código | Tests 4J.1 existentes (sin cambios) y `test_console_ai_7c.py` (asistente apagado sin IA, error claro) |
| Razonamiento interno guardado o mostrado | `<think>`, `<thinking>`, `<reasoning>`, `<reflection>` se quitan antes de interpretar; nunca llegan al insight | `test_console_ai_7c.py`, QA con `qa/console_assist_fake_llm.py` (modo `thinking`) |
| Interpretar texto arbitrario como JSON de forma peligrosa | Búsqueda acotada (256 KiB) del primer objeto equilibrado, comprobado con `json.loads`; nunca `eval`; después validación Pydantic estricta | Tests de `extract_json_text` con prosa, bloques y llaves en cadenas |
| Modo `user_prefix` mezclando instrucciones y datos | Las instrucciones van antes de un separador explícito y los datos siguen siendo JSON escapado (`json.dumps`) | Test del mensaje generado en ambos modos |
| Ventana de contexto superada en silencio | `AI_MAX_PROMPT_CHARS` recorta el documento y el insight lo indica | Test de presupuesto |
| Ajustes nuevos que cambien los tests según el `.env` | Los cuatro ajustes están fijados en `backend/tests/conftest.py` | Suite completa |

## 2. Asistente de la consola (7C.2)

| Riesgo | Control | Comprobado con |
| --- | --- | --- |
| Ver resultados de otro usuario | Ejecuciones ajenas solo con `tools:manage`; si no, 404 sin revelar que existen (mismo criterio que `GET /tools/executions/{id}`) | `test_console_ai_7c.py` |
| Que la IA ejecute o confirme herramientas | El endpoint solo lee ejecuciones ya terminadas; no hay ruta que lance herramientas desde la IA; las acciones se rechazan (`console_execution_not_usable`) | Tests y `qa/e2e_console_assist.py` |
| Referencias inventadas o hipótesis sin evidencia | Grounding: referencias desconocidas descartadas con aviso; hipótesis sin evidencia válida descartadas; respuesta sin ninguna referencia válida rechazada | Tests y QA (R99 descartada) |
| Confundir sugerencia con evidencia | `origin` en el resultado; la UI pinta «Sugerencia del modelo», «No es evidencia», hipótesis «Posible» y los datos citados aparte | `ConsoleAssistant.test.tsx` |
| Borrador tomado por texto humano | Cabecera fija de texto generado por IA; el borrador es de solo lectura y no se guarda en el caso | Tests de backend y frontend |
| XSS con salida del modelo o del host | React pinta texto; sin `dangerouslySetInnerHTML`; la salida de herramientas se muestra como texto | `ConsolePage.test.tsx` (`<script>` como texto) y `ConsoleAssistant.test.tsx` |
| Abuso o saturación | Rate limit por usuario y global, concurrencia acotada, tope de ejecuciones por petición, caché por huella | Tests de AI Insights existentes y de la consola |
| Alterar eventos, detecciones o riesgo | El servicio solo inserta en `ai_insights` y en la auditoría | Revisión del código: ninguna escritura fuera de esas tablas |

## 3. Selectores contextuales (7C.3)

| Riesgo | Control | Comprobado con |
| --- | --- | --- |
| Inyección SQL o comodines | Consultas SQLAlchemy con parámetros; `LIKE` con `%`, `_` y `\` escapados y `ESCAPE '\'` | `test_lookup_7c.py` (comodines literales) |
| Fuga entre sites | `site_id` resuelto con `resolve_site` y aplicado a activos y detecciones, también al resolver ids | `test_lookup_7c.py` |
| Fuga de casos | `incidents:read` obligatorio (403) | `test_lookup_7c.py` |
| Elegir mal entre homónimos | `ambiguous` con varias coincidencias exactas; la UI nunca elige sola | Tests de backend, `EntityPicker.test.tsx`, QA (dos equipos con la misma IP) |
| Consultas caras | Tope de 20 resultados, texto de 1-128 caracteres, 250 ms entre pulsaciones en la UI | Revisión y tests |

## 4. Interfaz (7C.4) e informes (7C.5)

- Todo dato del panel sale de `/dashboard/summary` y `/dashboard/security-overview`; sin
  agentes los eventos son «no medido», no cero. Comprobado en `DashboardPage.test.tsx`.
- Sin scroll horizontal global de 320 a 3440 px de ancho (10 tamaños, los dos estilos de
  navegación y zoom al 200 %) en Panel, Consola e Informes con `qa/ui_responsive.cjs`.
- Informes v1 y v2 ya generados: mismos bytes (hashes de 6D.5 en `test_reports_v2.py`). El
  HTML v3 sigue sin scripts y con la misma CSP; el SVG lleva el desglose en `aria-label`.
- Las gráficas no inventan datos: sin recuentos no hay gráfica (`test_reports_v3_7c.py`).

## 5. Identidad (7C.6)

- Las señales nuevas son media (`same_dhcp_client_id`) y débil (`private_mac_rotation`); no
  hay fusión automática y la asociación sigue siendo manual, solo admin y auditada.
- Un nombre de producto da tipo con peso de nombre; una marca ambigua o una base de portátil no
  deciden el tipo ni la marca solas. Comprobado en `test_identity_7c.py` (29 casos, incluidos
  los negativos `galaxy-tab`, `galaxy-watch`, `shield`).
- Sin pestaña DHCP nueva: `/dhcp` sigue redirigiendo a Red › Identidad y evidencias.

## 6. Entrega

- Sin migraciones, sin dependencias nuevas, sin `.env`, secretos, bases de datos, venvs,
  `node_modules`, `dist` ni cachés en el parche (comprobado sobre la lista del MANIFEST).
- Compatibilidad: todos los campos nuevos son aditivos; un frontend 0.5.0 sigue funcionando con
  el servidor 0.6.0.

## Hallazgos abiertos

- Falta la prueba con un modelo real (llama.cpp u Ollama) en el hardware de Jesus: calidad,
  tiempos y proporción de respuestas descartadas.
- Las suites de Windows y la revisión visual en su navegador están pendientes.

## Revisión posterior: 7C-Security-Fix1

Tras confirmar Jesus la política de privacidad estricta (2026-10-29), el asistente de la
consola pasa a: solo loopback (URL e IP conectada), apagado por defecto, revisión del
documento con huella obligatoria antes de enviar, sin secretos ni resultados marcados por
defecto, `tools:execute` obligatorio y auditoría de revisión, envío, bloqueos y discrepancias.
Detalle y pruebas en [fase-7c-security-fix1.md](fase-7c-security-fix1.md).
