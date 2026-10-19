# Auditoría responsive de la consola (Fase 6C.0)

## Método

`qa/ui_responsive.cjs` (Playwright + Chromium) inicia sesión en una instancia de pruebas, recorre
todas las rutas estáticas de la consola y el detalle de un activo, y en cada combinación mide:

- Desbordamiento global: `scrollWidth` del documento frente al ancho del viewport, con la lista de
  elementos que sobresalen (los «culpables»).
- Contenido recortado: controles, celdas o textos que quedan fuera de un ancestro con
  `overflow: hidden/clip`. Este caso no genera scroll pero deja contenido inalcanzable, así que se
  cuenta como fallo. Se excluyen los puntos suspensivos intencionados y la ocultación accesible
  (patrón sr-only).
- Errores de JavaScript en la página.

Viewports: 320×568, 360×800, 390×844, 768×1024, 1024×768, 1366×768, 1440×900, 1920×1080,
2560×1440 y 3440×1440 (ultrawide); zoom 200 % sobre 1366×768 (683×384 px CSS); y
redimensionado progresivo de 1600 a 320 px en pasos de 80 px. Con `--nav sidebar|topbar` se
fija el estilo de navegación.

```bash
NODE_PATH=/ruta/a/node_modules/globales SENTRA_QA_ADMIN_PASSWORD=... \
PLAYWRIGHT_CHROMIUM_PATH=/ruta/a/chromium node qa/ui_responsive.cjs --out DIR [--nav topbar] [--only /ruta]
```

Los resultados quedan en `DIR/results.json` y `DIR/summary.txt`. La instancia debe tener datos
(activos, agentes, eventos) para que las tablas tengan contenido real.

## Resultado antes de 6C

250 de 300 comprobaciones fallaban por desbordamiento horizontal de la página entera.

| Causa raíz | Dónde | Efecto |
| --- | --- | --- |
| La barra superior era una única fila flex con unos 20 enlaces que no podían encogerse ni pasar a otra línea. | `.topbar__nav` | Entre +136 px (1920) y +1288 px (768) de ancho extra en todas las páginas. |
| Indicador de salud y bloque de usuario con ancho fijo en la misma fila. | `.health`, `.userbar` | +143 a +213 px en móvil aunque el menú cupiera. |
| Tablas sin contenedor de scroll propio y celdas con `white-space: nowrap`. | Alertas, eventos, response, sites, usuarios | La tabla empujaba la página en tablet y móvil. |
| Campos en línea con `min-width` fijo. | IA local, informes | Controles cortados a 320–360 px. |
| Hijos de rejillas y flex sin `min-width: 0`. | Paneles y barras de filtros | Un texto largo (hash, URL, hostname) ensanchaba su columna. |

## Correcciones aplicadas

- Nuevo shell (`components/Layout.tsx`, `styles/shell.css`): menú lateral agrupado, barra
  superior que mueve a «Más» los grupos que no caben (medido con `ResizeObserver`) y drawer en
  móvil. Ningún elemento de la barra tiene ancho mayor que el viewport.
- Las tablas se desplazan dentro de su contenedor y en móvil se apilan como tarjetas con la
  etiqueta de cada columna, sin perder datos.
- `styles/responsive.css`: `min-width: 0` en hijos de paneles y pilas, campos en línea que pasan
  a otra línea, selects limitados al ancho disponible.
- Textos largos se parten (`overflow-wrap`) en párrafos y descripciones; en celdas solo entre
  palabras (`break-word`) para no cortar palabras normales.
- No se usa `overflow-x: hidden` global en `html`, `body` ni en el contenido: un desbordamiento
  real sigue siendo visible y detectable.

## Resultado después de 6C

Ver `TEST-RESULTS.md` de la entrega de 6C.2 para las cifras exactas de cada ejecución.
