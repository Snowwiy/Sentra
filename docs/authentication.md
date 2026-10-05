# Autenticación, sesiones y roles del dashboard (Fase 4G)

El dashboard exige iniciar sesión. Los usuarios son locales (PostgreSQL), cada uno con un rol,
y el backend comprueba el permiso en cada endpoint: ocultar un botón en la interfaz es solo
comodidad, nunca la protección.

## Primer administrador (bootstrap)

No hay credenciales por defecto. Tras aplicar la migración `0017`, en el servidor:

```powershell
cd backend
.venv\Scripts\python.exe -m alembic upgrade head
.venv\Scripts\python.exe -m app.cli create-admin            # pregunta el usuario
.venv\Scripts\python.exe -m app.cli create-admin --username admin
```

La contraseña se pide dos veces sin eco y se valida con la política. El comando queda en la
auditoría con actor `cli`. Después se abre `http://localhost:5173`, se inicia sesión y el
resto de usuarios se crea desde **Usuarios** (solo admin).

## Recuperación de un administrador

Si se olvida la contraseña, o todos los admins están desactivados, desde el servidor (quien
puede leer `.env` y la base de datos ya tiene ese control):

```powershell
.venv\Scripts\python.exe -m app.cli list-users
.venv\Scripts\python.exe -m app.cli reset-password admin             # nueva contraseña
.venv\Scripts\python.exe -m app.cli reset-password admin --activate  # y reactivarlo
```

`reset-password` cierra todas las sesiones de ese usuario. Si no queda ningún admin,
`create-admin` crea uno nuevo.

## Roles y permisos

Los permisos están en una sola tabla (`backend/app/core/permissions.py`); los endpoints piden
un permiso (`require_permission`), nunca un rol concreto.

| Permiso | viewer | analyst | admin | Qué permite |
|---|:-:|:-:|:-:|---|
| `monitoring:read` | ✓ | ✓ | ✓ | Ver activos, telemetría, eventos, alertas, agentes, descubrimiento |
| `alerts:manage` | | ✓ | ✓ | Reconocer y resolver alertas |
| `discovery:run` | | ✓ | ✓ | Iniciar y cancelar descubrimientos (solo redes autorizadas) |
| `detections:manage` | | ✓ | ✓ | Reconocer y resolver detecciones (Fase 4H) |
| `assets:manage` | | | ✓ | Cambiar la criticidad de un activo, entrada del riesgo (Fase 4I) |
| `agents:manage` | | | ✓ | Revocar y reactivar agentes |
| `enrollment:manage` | | | ✓ | Crear, listar y revocar tokens de instalación |
| `users:manage` | | | ✓ | Usuarios, roles, contraseñas y sesiones |
| `audit:read` | | | ✓ | Ver la auditoría |

Un cambio de rol se aplica en la siguiente petición (el permiso se calcula en cada una). Un
admin no puede quitarse su propio rol ni desactivarse; y nunca puede quedar el sistema sin
ningún admin activo (`409 last_admin`). Los usuarios no se borran: se desactivan, así la
auditoría conserva a quién se refiere.

## Contraseñas

- Argon2id (`argon2-cffi`, parámetros por defecto de la librería). Nunca se guardan ni
  registran en claro; si en el futuro suben los parámetros, el hash se renueva en el
  siguiente login.
- Política: de 12 a 256 caracteres, sin espacios al principio ni al final, no puede ser una
  contraseña obvia (lista local corta) ni contener el nombre de usuario. **Sin reglas de
  composición** (mayúsculas, símbolos): una frase larga es mejor que `P@ssw0rd!`.
- Nombres de usuario: 3 a 32 caracteres `a-z 0-9 . _ -`, normalizados (NFKC, minúsculas, sin
  espacios): `Admin` y `admin` son el mismo usuario.
- Cambiar la propia contraseña (`POST /auth/password`) pide la actual y cierra las demás
  sesiones. Un reset por un admin o por la CLI cierra todas las sesiones del usuario.

## Sesiones

- Al iniciar sesión el servidor crea un token aleatorio de 256 bits; en la base de datos solo
  se guarda su SHA-256 (`user_sessions`), igual que con los tokens de agente.
- Cookie `sentra_session` (o `__Host-sentra_session` cuando es `Secure`): `HttpOnly`,
  `SameSite=Strict` (configurable a `Lax`), `Path=/`. El navegador nunca puede leerla desde
  JavaScript y el frontend no guarda nada en `localStorage`, `sessionStorage` ni cookies.
- Caducidad absoluta `SESSION_TTL_HOURS` (12 h) e inactividad `SESSION_IDLE_MINUTES` (60 min).
- Rotación: cada login emite un token nuevo y revoca el anterior del mismo navegador.
- Revocación: logout, desactivar el usuario, cambio o reset de contraseña, y el botón
  **Cerrar sesiones** de la página Usuarios. Una sesión revocada falla en la siguiente
  petición (`401`) y el dashboard vuelve a `/login` avisando de que la sesión expiró.

## CSRF y origen

Toda petición que modifica algo (POST/PATCH) con sesión debe cumplir:

1. `Origin` igual al propio origen de la API o en `CORS_ORIGINS` (`null` se rechaza);
2. cabecera `X-CSRF-Token` igual a HMAC-SHA256(token de sesión). El token CSRF lo devuelve
   `/auth/login` y `/auth/me`; el frontend lo guarda solo en memoria.

Además `SameSite=Strict` impide que otra web envíe la cookie. El login exige `Origin` válido y
`Content-Type: application/json` (un formulario de otra web no puede iniciar sesión en nombre
del usuario). Fallos: `403 csrf_failed`.

## Límites de intentos

En memoria del proceso, ventana deslizante (`LOGIN_RATE_WINDOW_MINUTES`, 15 min):

| Límite | Por defecto |
|---|---|
| Fallos por usuario + IP | 5 (`LOGIN_MAX_FAILURES_PER_USER_IP`) |
| Intentos por IP | 30 (`LOGIN_MAX_ATTEMPTS_PER_IP`) |
| Fallos por usuario (cualquier IP) | 50 (`LOGIN_MAX_FAILURES_PER_USER`) |
| `POST /agents/register` por IP y minuto | 30 (`AGENT_REGISTER_MAX_PER_MINUTE`) |

Al superarlo: `429 rate_limited` con `Retry-After`. Un login correcto limpia los fallos de ese
usuario e IP. El error de login es siempre genérico (*Usuario o contraseña incorrectos.*) y
tarda lo mismo exista o no el usuario. Los heartbeats y la telemetría de agentes no se
limitan.

Limitación conocida: el contador vive en un solo proceso. Con varios workers de uvicorn cada
uno cuenta por separado; Sentra se ejecuta con uno.

## Credenciales separadas

| Credencial | Quién | Dónde | Sirve para |
|---|---|---|---|
| Sesión de usuario (cookie) | navegador | dashboard | lectura y acciones según rol |
| Token de instalación (un uso) | instalador | `POST /agents/register` | inscribir un equipo |
| Token de agente (Bearer) | agente | heartbeat, telemetría, inventario, eventos | reportar su propio equipo |
| `ADMIN_API_KEY` (`X-Admin-Key`) | scripts en el servidor | `/api/v1/agent-enrollment-tokens` | **legacy** |

Ninguna sirve en lugar de otra: un token de agente no abre el dashboard, una cookie de sesión
no reporta telemetría y `X-Admin-Key` no es aceptada en los endpoints del dashboard.

## Migración desde la Fase 4C

- `DASHBOARD_ADMIN_ENABLED` se elimina, junto con la consola local (`api/console.py`: peer
  loopback, `Host` loopback, `X-Sentra-Console`). Si sigue en `.env` se ignora. Las rutas
  `/api/v1/console/*` se mantienen, ahora protegidas por sesión y permiso, y se pueden usar
  desde cualquier equipo de la LAN.
- `ADMIN_API_KEY` se mantiene como **legacy** para automatizaciones en el servidor. El
  navegador nunca la recibe. Sus acciones quedan auditadas con actor `admin-api`.
- Las alertas ya se pueden reconocer y resolver desde el dashboard (`alerts:manage`); la CLI
  `ack-alert` / `resolve-alert` sigue disponible.

## HTTP (desarrollo) y HTTPS (producción)

- **Desarrollo / LAN de pruebas**: HTTP está permitido. La cookie no lleva `Secure`, así que
  la contraseña y la cookie viajan sin cifrar; la pantalla de login lo avisa cuando no se
  abre desde `localhost`.
- **Producción**: servir el dashboard y la API detrás de HTTPS (proxy inverso como IIS, Caddy
  o nginx, o una VPN). Con `ENVIRONMENT=production` la cookie es `Secure` y se llama
  `__Host-sentra_session`; también se puede forzar con `SESSION_COOKIE_SECURE=true`.
- Detrás de un proxy: uvicorn con `--proxy-headers` y `FORWARDED_ALLOW_IPS=<ip del proxy>`
  para que la IP del cliente (límites y auditoría) sea la real, y `ALLOWED_HOSTS` con los
  nombres del servidor (rechaza otros `Host`, `400`).

### Acceso desde otra PC de la LAN (desarrollo)

El servidor de Vite reenvía `/api` a la API conservando `Host` y añadiendo `X-Forwarded-For`
(uvicorn confía en él desde `127.0.0.1`), así la auditoría muestra la IP real:

```powershell
cd frontend
npm run dev -- --host        # http://<ip-del-servidor>:5173
```

Si el dashboard se sirve desde otro origen distinto al de la API, añadirlo a `CORS_ORIGINS`.

## Auditoría

Tabla `audit_events`: fecha, actor (usuario, `cli`, `admin-api` o `unknown`), acción,
objetivo, resultado (`success`, `failure`, `denied`), IP y detalles sin secretos (las claves
con `password`, `token`, `secret`, `key`, `cookie`, `session`, `csrf` o `hash` se descartan).
También se emite al logger `sentra.audit`. Se registran login correcto y fallido, logout,
cambios de contraseña, alta de usuarios, cambios de rol, activar/desactivar, cierre de
sesiones, tokens de instalación, revocar/reactivar agentes, descubrimientos, alertas y
mutaciones denegadas por permiso. Se consulta en **Usuarios → Auditoría** (`audit:read`).

## API

| Método | Ruta | Permiso |
|---|---|---|
| POST | `/api/v1/auth/login` | público (Origin + JSON, limitado) |
| POST | `/api/v1/auth/logout` | sesión |
| GET | `/api/v1/auth/me` | sesión: usuario, permisos, token CSRF, caducidad |
| POST | `/api/v1/auth/password` | sesión (pide la contraseña actual) |
| GET, POST | `/api/v1/users` | `users:manage` |
| PATCH | `/api/v1/users/{id}` | `users:manage` (rol, activo) |
| POST | `/api/v1/users/{id}/password` | `users:manage` |
| GET | `/api/v1/users/{id}/sessions` | `users:manage` |
| POST | `/api/v1/users/{id}/sessions/revoke` | `users:manage` |
| GET | `/api/v1/audit` | `audit:read` |
| POST | `/api/v1/alerts/{id}/acknowledge`, `/resolve` | `alerts:manage` |
| PATCH | `/api/v1/assets/{id}/criticality` | `assets:manage` |

Todos los `GET` del dashboard (activos, eventos, alertas, agentes, descubrimiento) requieren
sesión (`monitoring:read`). Siguen sin sesión: `GET /health` (sin datos) y los endpoints de
agente, que usan su propio token.
