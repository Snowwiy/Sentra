# Sistema de diseño de la consola (Fase 6C)

La consola usa un único tema oscuro: fondo azul muy oscuro, superficies algo más claras y cian
como color de acento. Todo valor visual sale de los tokens de `frontend/src/styles/tokens.css`;
los componentes no escriben colores ni medidas sueltas, para que un cambio de tema o de escala
se haga en un solo sitio.

## Hojas de estilo y orden de carga

`frontend/src/main.tsx` las importa en este orden, porque cada una puede apoyarse en la anterior:

| Fichero | Contenido |
| --- | --- |
| `styles/tokens.css` | Variables CSS: colores, tipografía, espaciado, radios, sombras y medidas del shell. |
| `styles/base.css` | Estilos base de documento, controles (`.button`, `.input`, `.iconbutton`), foco visible y `.sr-only`. |
| `styles/shell.css` | Shell de la aplicación: barra superior, menú lateral, drawer móvil, menú de usuario y área de contenido. |
| `index.css` | Estilos históricos de módulos que aún no se han migrado; ya no define tokens ni el shell. |
| `styles/components.css` | Componentes comunes: cabeceras de página, paneles, tablas, modales, formularios, pestañas y tarjetas. |
| `styles/responsive.css` | Correcciones de contención por anchura detectadas en la auditoría (ver `docs/ui-audit-6c.md`). |

## Tokens principales

- Color: `--bg` (`#060a12`), `--surface`, `--surface-2`, `--surface-3`, `--border`, `--text`, `--text-muted`,
  `--accent` (`#22d3ee`) y los semánticos `--ok`, `--warn`, `--crit`, `--info`. El texto sobre
  fondo oscuro mantiene contraste AA; el acento solo se usa para estado activo, foco y acciones.
- Escala tipográfica `--fs-xs` … `--fs-2xl` sobre una base de 15 px.
- Espaciado `--space-1` … `--space-8` y `--gutter` (con `clamp`, para que el margen lateral crezca con
  la pantalla sin pasar de un máximo).
- Shell: `--appbar-h` 56 px, `--sidebar-w` 248 px, `--sidebar-w-compact` 64 px,
  `--content-max` 1680 px (en ultrawide el contenido no se estira hasta líneas ilegibles).
- `--hit` 36 px: altura mínima de los controles táctiles.

## Puntos de corte

Definidos a la vez en `frontend/src/ui/useMediaQuery.ts` (`BREAKPOINTS`) y en el CSS:

| Tamaño | Anchura | Navegación automática |
| --- | --- | --- |
| Móvil | < 768 px | Botón de menú y drawer. |
| Tablet | 768 – 1199 px | Menú lateral compacto (solo iconos con tooltip); el botón abre el drawer completo. |
| Escritorio | ≥ 1200 px | Menú lateral expandido, contraíble con el botón de menú. |

## Navegación

- La lista de módulos vive en `frontend/src/navigation/navigation.ts` (`NAV_GROUPS`), agrupada en
  General, Infraestructura, Seguridad, Análisis y Administración. Cada entrada declara el permiso
  que exige; `visibleGroups` filtra con `auth.can`, así que ni el menú lateral, ni la barra
  superior, ni el menú «Más» muestran rutas que el usuario no puede abrir. La autorización real
  sigue estando en el backend.
- `Layout.tsx` resuelve el modo con `resolveNavigation(estilo, viewport, compacto)`.
- Preferencias en `frontend/src/ui/preferences.ts`, en `localStorage` bajo `sentra.ui.*`:
  estilo de navegación (`auto`, `sidebar`, `topbar`), menú compacto y grupos plegados. Solo se
  guardan preferencias de interfaz, nunca datos de sesión ni de activos. Si el almacenamiento
  está bloqueado, la preferencia se mantiene en memoria durante la sesión y la interfaz lo avisa.
  Un valor inválido se lee como el predeterminado.
- El estilo se cambia en Configuración → Interfaz y en el menú de usuario (siempre visible en la
  barra superior).
- Teclado: flechas, Inicio y Fin dentro de los menús; Escape cierra drawer y desplegables y
  devuelve el foco al botón que los abrió; el drawer y los modales atrapan el tabulador.

## Tablas

- Por defecto, una tabla `.table` dentro del contenido ocupa el ancho disponible y, si de verdad
  no cabe, se desplaza dentro de su contenedor, nunca la página entera.
- Entre 768 y 1199 px se ocultan las columnas marcadas con `.col-secondary`.
- Por debajo de 768 px las filas se apilan como tarjetas: `ui/stackTables.ts` copia el texto de
  cada cabecera al atributo `data-label` de sus celdas y el CSS lo muestra como etiqueta. Un
  `MutationObserver` mantiene las etiquetas al día cuando la tabla cambia. Las tablas que deben
  conservar su forma (por ejemplo matrices) llevan `.table--nostack`.

## Modales

`components/Modal.tsx` limita su tamaño al viewport con scroll interno, mantiene visible el botón
de cerrar y las acciones (`position: sticky`), atrapa el foco, bloquea el scroll del fondo y
devuelve el foco al elemento que lo abrió. En móvil se muestra como hoja inferior a pantalla
completa.

## Idioma

La interfaz está en español. Se conservan en inglés los términos técnicos habituales (SNMP, WLAN,
API, SOC, CVE, CVSS, EPSS, KEV, MAC, IP) y los identificadores que vienen del backend.

## Cómo añadir un módulo

1. Crear la página y su ruta en `App.tsx`.
2. Añadir la entrada a `NAV_GROUPS` con su grupo, icono (`components/icons.tsx`) y permiso.
3. Usar `.page-header`, `.panel` y `.table`; marcar con `.col-secondary` las columnas
   prescindibles en tablet.
4. Ejecutar `qa/ui_responsive.cjs --only /ruta` en los dos modos de navegación.
