# Seguridad de red, TLS y proxy (Fase 4M)

## Puertos

| Puerto | Servicio | Escucha en | Abrir en el cortafuegos |
| --- | --- | --- | --- |
| 443/tcp | Caddy (HTTPS: dashboard, API, agentes) | todas las interfaces | Sí, desde las redes autorizadas |
| 80/tcp | Caddy (solo redirige a HTTPS; validación ACME) | todas | Sí (o solo durante ACME) |
| 8000/tcp | API Sentra (uvicorn) | 127.0.0.1 | **No** |
| 5432/tcp | PostgreSQL | 127.0.0.1 | **No** (salvo base en otro servidor: solo desde Sentra) |
| 8080, 11434/tcp | runtime de IA local (llama.cpp, Ollama) | 127.0.0.1 | **No** |
| 2019/tcp | API de administración de Caddy | 127.0.0.1 | **No** |

Salientes del servidor: los que use el discovery hacia `DISCOVERY_ALLOWED_NETWORKS` (TCP
connect, ping, mDNS/NetBIOS/SSDP), DNS, NTP y, solo con certificado público, ACME.

### Redes autorizadas

Limitar el 443 a las redes desde las que trabajan analistas y agentes (LAN de oficinas, VPN):

```bash
# Linux (ufw)
sudo ufw default deny incoming
sudo ufw allow from 10.0.0.0/8 to any port 443 proto tcp
sudo ufw allow from 10.0.0.0/8 to any port 80 proto tcp
sudo ufw allow from 10.0.50.0/24 to any port 22 proto tcp   # administración
sudo ufw enable
```

Windows: `deploy/windows/README.md` (añadir `-RemoteAddress 10.0.0.0/8` a las reglas).

## TLS: tres casos

1. **Certificado público** (el nombre resuelve en Internet y el 80/443 son accesibles para la
   validación ACME): Caddy lo obtiene y renueva solo. Quitar la línea `tls` del Caddyfile.
2. **CA interna** (LAN/VPN, lo habitual en un SOC interno): la CA de la empresa emite un
   certificado para `sentra.empresa.lan` (SAN con el nombre y, si se usa, la IP). Caddy lo
   carga con `tls <crt> <key>`. Renovarlo antes de caducar (alertar a 30 días).
3. **Prueba** (`tls internal`): Caddy crea su propia CA. **No es producción**: sin HSTS,
   avisos en el navegador hasta instalar la raíz de Caddy, y no apto para agentes reales.

TLS 1.2 como mínimo (Caddy: 1.2 y 1.3 con cifrados seguros por defecto; nginx:
`ssl_protocols TLSv1.2 TLSv1.3`). No se toca la lista de cifrados.

**HSTS** (`Strict-Transport-Security: max-age=31536000`) solo cuando el certificado es
válido para todos los clientes (casos 1 y 2), nunca en desarrollo ni con `tls internal`:
durante un año el navegador no aceptará HTTP ni un certificado erróneo para ese nombre. No
se usa `includeSubDomains` ni `preload` por defecto.

### Instalar la CA interna en los agentes

El agente usa la verificación TLS estándar de Python contra el almacén del sistema, sin
opción para desactivarla.

- **Windows** (como administrador, o por GPO a todos los equipos):
  `Import-Certificate -FilePath ca-empresa.crt -CertStoreLocation Cert:\LocalMachine\Root`
- **Debian/Ubuntu**: copiar a `/usr/local/share/ca-certificates/ca-empresa.crt` y
  `sudo update-ca-certificates`.
- **RHEL/Fedora**: `/etc/pki/ca-trust/source/anchors/` y `sudo update-ca-trust`.

Comprobar desde el equipo: `curl https://sentra.empresa.lan/api/v1/health` sin `-k`.
Si falla con *certificate verify failed*, el agente tampoco conectará (y lo registra).

## Reverse proxy y cabeceras de confianza

- La API solo cree `X-Forwarded-For` y `X-Forwarded-Proto` si la conexión TCP viene de
  `TRUSTED_PROXIES` (por defecto `127.0.0.1,::1`, Caddy en la misma máquina). De cualquier
  otro origen se ignoran: un cliente que llegue directo no puede falsear su IP (para
  esquivar el rate limiting del login o ensuciar la auditoría) ni fingir HTTPS.
- `X-Forwarded-For` se recorre de derecha a izquierda y se queda la primera IP que no es un
  proxy de confianza. Caddy no reenvía el `X-Forwarded-For` del cliente (lo sustituye).
- `TRUSTED_PROXIES` no admite `0.0.0.0/0` ni nombres de host.
- uvicorn se arranca con `--no-proxy-headers`: una sola regla, la de Sentra.
- Con un balanceador delante de Caddy, añadir su red a `TRUSTED_PROXIES` **y** a
  `servers { trusted_proxies static <red> }` en Caddy.

## Comprobaciones de la API en producción

- **HTTPS obligatorio**: con `ENVIRONMENT=production`, toda petición que no llegó por HTTPS
  (directa o según el proxy de confianza) recibe `403 https_required`, salvo
  `/api/v1/health`, `/api/v1/health/ready` y `/api/v1/metrics` (sondas locales).
- **Host**: `ALLOWED_HOSTS` obligatorio y sin comodines (DNS rebinding, enlaces con Host
  falso). Caddy conserva el Host original.
- **Origin/CSRF**: toda petición mutable con sesión exige `X-CSRF-Token`; si el navegador
  envía `Origin`, debe ser el propio (`https://sentra.empresa.lan`, calculado con el esquema
  real detrás del proxy) o uno de `CORS_ORIGINS`.
- **CORS**: vacío si el dashboard se sirve en el mismo origen (recomendado). Nunca `*`; en
  producción solo orígenes `https://`.
- **Cookie de sesión**: `__Host-sentra_session`, `Secure`, `HttpOnly`, `SameSite=Strict`,
  `Path=/`, sin `Domain`. El token nunca va en el cuerpo ni en `localStorage`.
- **Cabeceras** (API): `X-Content-Type-Options`, `X-Frame-Options: DENY`,
  `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, CSP `default-src 'none'`.
  Frontend (Caddy): CSP solo `'self'`, `frame-ancestors 'none'`, `Permissions-Policy`.
- **Tamaño de cuerpo**: `MAX_REQUEST_BYTES` (4 MB) en la API y en el proxy.

## Rate limiting

Compartido entre workers y reinicios en PostgreSQL (`rate_limit_hits`, solo hashes de las
claves) con `ENVIRONMENT=production`. Respuesta `429` con `Retry-After` y código
`rate_limited`.

| Ámbito | Límite por defecto | Variable |
| --- | --- | --- |
| Login: fallos por usuario+IP / intentos por IP / fallos por usuario | 5 / 30 / 50 en 15 min | `LOGIN_*` |
| Inscripción de agentes por IP | 30/min | `AGENT_REGISTER_MAX_PER_MINUTE` |
| IA por usuario / global | 6 / 30 por min | `AI_RATE_LIMIT_*` |
| Mutaciones del dashboard por usuario (incidentes, discovery, contexto...) | 120/min | `API_MUTATIONS_PER_USER_PER_MINUTE` |
| Búsquedas (`?q=`) por usuario | 120/min | `API_SEARCHES_PER_USER_PER_MINUTE` |

Heartbeat y telemetría de agentes **no** se limitan (un agente legítimo nunca debe quedarse
fuera); se protegen con la credencial por agente.

## Secretos

| Secreto | Dónde | Notas |
| --- | --- | --- |
| Contraseña de PostgreSQL | `DATABASE_URL` | ≥ 16 caracteres; production-check rechaza ejemplos |
| `AGENT_ENROLLMENT_KEY` | `.env` | heredado (clave compartida); preferir tokens de un solo uso y dejarlo sin definir |
| `ADMIN_API_KEY` | `.env` | heredado (scripts en el servidor); nunca llega al navegador; sin definir = desactivado |
| `AI_API_KEY` | `.env` | solo si el runtime local la pide; nunca llega al navegador |
| `METRICS_TOKEN` | `.env` | ≥ 32 caracteres, para el recolector de métricas |
| Sesiones, tokens de agentes y de inscripción | base de datos | aleatorios; en la base solo su hash |

Generar con `python -m app.cli generate-secret`. `.env` fuera de Git (`.gitignore`), `600`
en Linux / ACL restringida en Windows. El frontend no recibe ningún secreto: `/auth/me` solo
devuelve usuario, rol, permisos, token CSRF y versión.

Los logs pasan por una redacción central (`app/core/redaction.py`): contraseñas, tokens,
cookies, CSRF, credenciales de agentes, claves de IA y la contraseña de `DATABASE_URL` se
sustituyen por `[REDACTED]` en mensajes, campos extra y trazas.
