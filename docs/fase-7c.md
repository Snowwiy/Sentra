# Fase 7C: modelo open-weight opcional, selectores contextuales y rediseño

Servidor y frontend **0.6.0**. Agente 0.6.2 y sensor 0.7.0 sin cambios. **Sin migraciones**
(la cabeza sigue en 0050; la siguiente libre es 0051) y sin dependencias nuevas.

| Subfase | Qué hay | Documento |
| --- | --- | --- |
| 7C.1 | Integración del modelo open-weight: razonamiento `<think>` descartado, JSON tolerante, modo de prompt sin rol system, presupuesto de prompt, origen del modelo | [open-weight-model.md](open-weight-model.md) |
| 7C.2 | Asistente de la Analyst Console: resumir, explicar riesgo, hipótesis y borrador, con grounding y separación modelo/evidencia | [open-weight-model.md](open-weight-model.md) |
| 7C.3 | Selectores contextuales sin ids tecleados (`GET /lookup/{kind}`, `EntityPicker`) | [contextual-selectors.md](contextual-selectors.md) |
| 7C.4 | Rediseño de la consola y del panel con datos reales | Este documento |
| 7C.5 | Informes plantilla v3 con gráficas circulares y flujo por pasos | [reporting.md](reporting.md) |
| 7C.6 | Identidad de dispositivos sin SNMP: más nombres de producto y dos señales nuevas | [device-identity-wifi.md](device-identity-wifi.md) |

Auditoría de seguridad y calidad: [fase-7c-auditoria.md](fase-7c-auditoria.md). Política de
privacidad estricta del asistente (solo loopback, activación explícita, revisión antes de
enviar, minimización, RBAC y auditoría): [fase-7c-security-fix1.md](fase-7c-security-fix1.md)
(versión 0.6.1).

## 7C.4 Interfaz

Referencia visual: el vídeo de presentación de Sentra. Todo lo que se ve sale de la API; no
hay datos de ejemplo ni componentes decorativos que aparenten funciones inexistentes.

**Analyst Console** (`/console`), tres columnas que se apilan en pantallas estrechas:

- Cabecera con rol y site; búsqueda global con la interpretación detectada (IP, MAC, regla...).
- Catálogo agrupado por categoría (lectura, investigación, acción) con icono de candado en lo
  que el rol no puede ejecutar o necesita vista previa.
- Zona de trabajo: entidad del workspace (o selectores de activo y detección para elegirla),
  la herramienta elegida con su formulario y las tarjetas de resultado.
- Columna lateral: historial, permisos del rol y el asistente de IA local (7C.2).

**Panel** (`/`):

- Indicadores operativos con icono: activos monitorizados, alertas abiertas, detecciones por
  revisar y casos abiertos (si el rol los ve), cada uno enlazado a su vista.
- Actividad de las últimas 24 h por hora (`activity_24h` de `GET /dashboard/security-overview`):
  eventos de agentes y detecciones nuevas, con el pico marcado. Sin agentes en el alcance los
  eventos son «no medido», nunca un cero dibujado.
- Detecciones activas por severidad.
- Activo con más riesgo (`top_risk`): puntuación, nivel y los factores guardados por el Risk
  Engine con sus puntos (positivos y negativos) y enlace a la detección; nada se recalcula en
  el navegador. Aviso fijo: «Una alerta es un indicio a investigar, no un compromiso confirmado».
- Se mantienen la postura, los anillos, el historial de riesgo, detecciones recientes, puertos
  y dispositivos nuevos.

Gráficas en SVG propio, sin bibliotecas nuevas; cada una tiene resumen textual y tabla para
lectores de pantalla. Estilos en `frontend/src/styles/sentra7c.css` con los tokens del sistema
de diseño 6C (tema claro y oscuro) y cortes a 1399, 1099 y 899 px.

**Informes**: el formulario se presenta en tres pasos (tipo, alcance, formato y entrega) con el
contenido que llevará el informe y el alcance elegido por nombre (7C.3).

## 7C.5 Informes v3

Plantilla **v3** para los informes nuevos (`TEMPLATE_VERSION = 3`). Los v1 y v2 ya generados
se renderizan igual que antes, byte a byte (lo comprueban los tests con los hashes de 6D.5).
La v3 añade, al principio de la primera sección, un «Panel visual» con gráficas circulares
calculadas del mismo snapshot:

| Informe | Gráficas |
| --- | --- |
| Resumen ejecutivo y técnico | Activos por nivel de riesgo, detecciones del periodo por severidad, vulnerabilidades activas por severidad |
| Riesgo | Activos por nivel de riesgo, activos por estado |
| Detecciones | Por severidad y por estado |
| Vulnerabilidades | Por severidad y findings por evidencia |
| Activo | Detecciones por severidad |
| Incidente | Detecciones vinculadas por severidad |
| Actividad de Response | Ejecuciones por estado y por acción |

Sin datos no hay gráfica (se dice «Sin datos en el periodo.»); los ceros no se dibujan; más de
6 porciones se agrupan en «Otros». PDF con sectores anulares de Bézier en el escritor propio;
HTML con SVG accesible (`aria-label` con el desglose completo) y sin scripts.

## 7C.6 Identidad sin SNMP

- Nombres de producto nuevos en el clasificador (con peso de nombre, nunca deciden solos):
  tabletas Huawei MatePad/MediaPad, Lenovo Tab, Kindle/Fire, Xiaomi/Redmi Pad; móviles Huawei
  nova/Mate, Motorola, OPPO, realme, vivo; televisores Hisense/VIDAA, TCL, Philips, Xiaomi TV,
  Android TV, NVIDIA Shield, Apple TV y modelos Samsung QE/UE/QN/UN; base de Nintendo Switch
  (consola) y bases de portátil (solo una pista débil de portátil, sin marca); cámaras Tapo,
  EZVIZ, IMOU, Wyze, Arlo, Blink; enchufes y bombillas Sonoff, Meross, Kasa, WiZ; robots
  aspiradores. `galaxy-tab`, `galaxy-watch` o `galaxy-buds` ya no se toman por móvil y un
  `shield` a secas ya no es un NVIDIA Shield.
- Señal `same_dhcp_client_id` (media): el mismo identificador de cliente DHCP (opción 61) en
  los leases de dos registros; sobrevive a la MAC privada, pero una imagen clonada puede
  repetirlo, por eso no es fuerte.
- Señal `private_mac_rotation` (débil): dos MAC privadas distintas que nunca estuvieron activas
  a la vez. Solo apoya una hipótesis.
- Ninguna fusiona registros sola: aparecen como evidencia en los candidatos y la asociación
  sigue siendo manual y auditada (7B). No hay pestaña DHCP aparte: `/dhcp` redirige a
  Red › Identidad y evidencias.

## Instalación y actualización desde 0.5.0

1. Aplica el parche sobre Dev `8319d57` (ver HANDOFF del paquete).
2. Backend: no hay migraciones; `alembic upgrade head` no hace nada nuevo. Reinicia la API.
3. Frontend: `npm ci` no es necesario (sin dependencias nuevas); `npm run build`.
4. Opcional, IA local: sigue [open-weight-model.md](open-weight-model.md) («Cómo activarlo»).
   Sin `AI_ENABLED=true` la consola muestra el asistente como no configurado y todo lo demás
   funciona igual.

Variables nuevas (todas opcionales, fijadas en `backend/tests/conftest.py`):
`AI_CONSOLE_ASSIST_ENABLED`, `AI_SYSTEM_PROMPT_MODE`, `AI_MAX_PROMPT_CHARS`,
`AI_CONSOLE_MAX_EXECUTIONS`. Ver [configuration.md](configuration.md).

## QA

- `qa/console_assist_fake_llm.py`: servidor OpenAI-compatible simulado (solo loopback) que
  devuelve razonamiento, JSON en bloque y una referencia inventada, para probar el asistente
  sin modelo real.
- `qa/e2e_console_assist.py`: recorre `/lookup/asset`, una herramienta de lectura y
  `/ai/console/assist` contra una API en marcha.
- `qa/ui_responsive.cjs`: auditoría de desbordamiento horizontal (incluye consola, panel e
  informes).

## Pendiente en el equipo real

- Modelo real (llama.cpp u Ollama) con el asistente: calidad, tiempos y respuestas descartadas.
- Suites en Windows (backend con `mypy --platform win32` ya comprobado en la nube).
- Revisión visual en el navegador de Jesus (consola, panel, informes PDF en su visor).
- Identidad con dispositivos reales de la LAN (Huawei, Samsung, TV, bases) y leases DHCP con
  client id.
