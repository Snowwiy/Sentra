# Despliegue en producción: servidor central (Fase 4M)

Sentra se despliega en **un servidor central** de la organización. Los navegadores de los
analistas y los agentes Windows/Linux se conectan a él por **HTTPS**; los dispositivos sin
agente se descubren desde él. No hay Docker, Compose ni Kubernetes: todo es nativo (Linux con
systemd como referencia, Windows Server con `deploy/windows/README.md`).

```
 Navegadores (LAN/VPN) ─┐
 Agentes Windows/Linux ─┼── HTTPS :443 ──▶ Caddy (TLS, cabeceras, frontend estático)
                        │                     │  /api/*  ──▶ API Sentra 127.0.0.1:8000
 Dispositivos sin agente ◀── discovery ──────┘                 │
                                                              ├──▶ PostgreSQL 127.0.0.1:5432
                                                              └──▶ IA local opcional 127.0.0.1:8080
```

Reglas de la topología:

- Solo el **443** (y el 80, que redirige) se abren hacia la red. La API (8000), PostgreSQL
  (5432) y el runtime de IA (8080/11434) escuchan **solo en 127.0.0.1**.
- El navegador nunca habla con PostgreSQL ni con el runtime de IA: todo pasa por la API, que
  aplica sesión, permisos, límites y redacción.
- `localhost` solo existe dentro del servidor. Agentes y navegadores usan el nombre público
  del servidor (`https://sentra.empresa.lan`).

## 1. Requisitos del servidor

| Componente | Mínimo (≤ 500 activos) | Recomendado (≤ 10 000 activos) |
| --- | --- | --- |
| CPU | 4 núcleos | 8 núcleos |
| RAM | 8 GB | 16-32 GB |
| Disco | 100 GB SSD | 500 GB SSD (+ volumen aparte para copias) |
| SO | Ubuntu 24.04 / Debian 12 / RHEL 9, o Windows Server 2022 | igual |

La IA local es opcional y va aparte: un modelo de 7-8B cuantizado necesita ~8 GB de VRAM
o RAM adicionales (`docs/local-model-manager.md`). Sentra funciona completo sin ella.

Software: Python 3.12+, Node.js 22+ (solo para compilar el frontend), PostgreSQL 18
(mínimo 16), Caddy 2.8+ (o nginx), reloj sincronizado por NTP (`timedatectl` /
`w32tm /query /status`): las ventanas de detección, la caducidad de sesiones y los rate
limits dependen de la hora. Sentra guarda todo en UTC.

## 2. Instalación (Linux)

```bash
# Usuario de sistema sin login y carpetas
sudo useradd --system --home /opt/sentra --shell /usr/sbin/nologin sentra
sudo mkdir -p /opt/sentra /etc/sentra /var/backups/sentra
sudo chown sentra:sentra /var/backups/sentra && sudo chmod 700 /var/backups/sentra

# Código (copia del repositorio en la versión a desplegar)
sudo rsync -a --exclude .git --exclude node_modules --exclude .venv ./ /opt/sentra/
cd /opt/sentra/backend
sudo python3 -m venv .venv && sudo .venv/bin/pip install -r requirements.txt

# Frontend: compilar y servir estático (sin source maps por defecto)
cd /opt/sentra/frontend && npm ci && npm run build      # genera frontend/dist
```

PostgreSQL: rol y base dedicados, escucha en loopback y `pg_hba` restrictivo, según
`deploy/postgresql/README.md`.

### Configuración (`/etc/sentra/sentra.env`)

Partir de `.env.example`. Generar cada secreto con `python -m app.cli generate-secret`
(nunca valores de ejemplo; Sentra no genera secretos solo, para que no cambien al reiniciar).

```bash
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_FORMAT=json
DATABASE_URL=postgresql+psycopg://sentra:<secreto>@127.0.0.1:5432/sentra
# 127.0.0.1: sondas locales (systemd, Prometheus) que llaman a la API directamente. Es
# seguro: desde fuera solo llega lo que Caddy enruta, y Caddy solo sirve sentra.empresa.lan.
ALLOWED_HOSTS=sentra.empresa.lan,127.0.0.1
CORS_ORIGINS=                         # vacío: el dashboard se sirve en el mismo origen
TRUSTED_PROXIES=127.0.0.1,::1         # Caddy en la misma máquina
AGENT_SERVER_URL=https://sentra.empresa.lan
DB_STATEMENT_TIMEOUT_SECONDS=30
BACKUP_DIR=/var/backups/sentra
BACKUP_RETENTION_DAYS=14
# AGENT_ENROLLMENT_KEY y ADMIN_API_KEY: sin definir (tokens de un solo uso y login).
```

```bash
sudo chown root:sentra /etc/sentra/sentra.env && sudo chmod 640 /etc/sentra/sentra.env
```

El archivo no debe estar dentro de `/opt/sentra` ni en Git. No dejar un `.env` en
`/opt/sentra` ni en `/opt/sentra/backend`: Sentra también lo leería.

### Validar antes de arrancar

```bash
cd /opt/sentra/backend
sudo -u sentra env $(sudo cat /etc/sentra/sentra.env | xargs) .venv/bin/python -m app.cli production-check
```

Salida `PASS`/`WARN`/`FAIL` por comprobación: entorno, logs, hosts, CORS, cookie, proxies,
rate limiting, base (rol no superusuario, contraseña, TLS), migraciones, secretos heredados,
URL de agentes, métricas, IA, frontend compilado y sin `.map`, carpetas de logs y copias,
permisos de `.env`. Código de salida 1 si hay algún FAIL. La IA apagada es WARN, no FAIL.

Con `ENVIRONMENT=production` la API **se niega a arrancar** si queda algún FAIL de
configuración, con un mensaje que dice qué variable corregir y nunca su valor.

### Migraciones (siempre explícitas)

```bash
.venv/bin/python -m app.cli migration-status   # 0 al día, 1 pendientes, 2 error
.venv/bin/python -m app.cli backup             # antes de migrar, siempre
.venv/bin/alembic upgrade head
```

La API nunca migra al arrancar. `migration-status` falla si hay varias heads o si la base
está en una revisión que este código no conoce (código más viejo que la base).

### Servicios

```bash
sudo cp /opt/sentra/deploy/systemd/sentra.service /opt/sentra/deploy/systemd/sentra-backup.* /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentra sentra-backup.timer
curl -s http://127.0.0.1:8000/api/v1/health/ready      # {"status":"ready",...}
```

Caddy: `deploy/caddy/Caddyfile.example` -> `/etc/caddy/Caddyfile`, elegir el caso de TLS,
`caddy validate`, `systemctl reload caddy`. Detalle de TLS, cortafuegos y CA interna en
`docs/network-security.md`.

Crear el primer administrador: `.venv/bin/python -m app.cli create-admin`.

## 3. Comprobación final

1. `https://sentra.empresa.lan` abre el login con candado válido; `http://` redirige.
2. `curl -I https://sentra.empresa.lan/` muestra `Strict-Transport-Security`,
   `Content-Security-Policy`, `X-Content-Type-Options`.
3. `curl -i http://<ip-servidor>:8000/api/v1/health` desde otra máquina: no conecta.
4. `curl -i https://sentra.empresa.lan/api/v1/metrics`: 404.
5. Login, dashboard, un agente inscrito con token de un solo uso (sección 5).
6. `python -m app.cli production-check` sin FAIL.

## 4. Varios workers

Un worker basta para un servidor único con miles de activos (medidas en
`docs/DEVELOPMENT_STATUS.md`). Con `--workers N` (solo Linux):

- **Rate limiting**: compartido en PostgreSQL (`RATE_LIMIT_BACKEND=auto` en producción).
- **Jobs periódicos** (offline, detección, riesgo, retención, discovery programado): cada uno
  con un advisory lock de PostgreSQL; solo un worker ejecuta cada vuelta, los demás la saltan.
  Si un proceso muere, el lock se libera con su conexión.
- **Discovery manual**: un único job por red garantizado por índice único en la base.
- **Benchmark de IA**: uno a la vez entre todos los workers (comprobado en la base).
- **IA**: el límite de concurrencia `AI_MAX_CONCURRENT` es por proceso: con N workers el
  runtime puede recibir hasta N x AI_MAX_CONCURRENT peticiones simultáneas. Ajustarlo.
- **Pool**: cada worker abre hasta `DB_POOL_SIZE + DB_MAX_OVERFLOW` conexiones. Con el pool
  agotado la API responde 503 reintentable (contrapresión), nunca 500.

## 5. Agentes

- `AGENT_SERVER_URL=https://sentra.empresa.lan`: el comando de instalación del dashboard ya
  lleva esa URL. El agente avisa si se configura `http://` hacia otra máquina.
- El agente verifica siempre el certificado contra el almacén de confianza del sistema
  operativo (Windows: almacén de certificados; Linux: `/etc/ssl/certs`). No existe opción
  para desactivar la verificación. Con CA interna, instalar su raíz en cada equipo
  (`docs/network-security.md`).
- Credencial por agente: token aleatorio del que el servidor solo guarda el hash; se revoca
  desde la página Agentes. Inscripción con tokens de un solo uso (15 min).
- Sin autoactualización. Actualización manual con el paquete nuevo (`-Upgrade` en
  `docs/agent-windows-installation.md`, sección "Upgrade" de
  `docs/agent-linux-installation.md`): mismo `agent_id`, sin re-enrolar. Arranque automático como servicio en ambos sistemas.

## 6. Actualizar Sentra

1. Leer las notas de la versión (migraciones, variables nuevas).
2. `python -m app.cli backup` y `verify-backup` del archivo generado.
3. Parar la API: `systemctl stop sentra` (readiness pasa a 503 y los jobs se detienen).
4. Sustituir el código, `pip install -r requirements.txt`, `npm ci && npm run build`.
5. `migration-status`, `alembic upgrade head`, `production-check`.
6. `systemctl start sentra`, comprobar `/api/v1/health/ready` y el dashboard.

### Volver atrás (rollback)

Preferido: **restaurar la copia** hecha en el paso 2 en una base nueva y volver al código
anterior (`docs/backup-restore.md`). Las migraciones tienen `downgrade`, pero un downgrade
puede borrar columnas o tablas con datos nuevos; usarlo solo si la versión nueva no llegó a
escribir datos que se quieran conservar. Nunca arrancar código viejo sobre una base migrada:
`migration-status` y `production-check` lo marcan como FAIL.

## 7. Recuperación ante desastre

Servidor perdido: instalar uno nuevo (secciones 1-2) con el mismo nombre DNS y certificado,
crear rol y base vacía, `python -m app.cli restore <copia> --target-db sentra --confirm sentra`,
`alembic upgrade head` si el código es más nuevo, arrancar. Los agentes reconectan solos con
su credencial (está en la base restaurada). Lo que pasó después de la última copia se pierde:
la frecuencia de copias define cuántos datos se pueden perder (RPO). Ver
`docs/backup-restore.md` para la prueba periódica de restauración.

## 8. Retención y capacidad

- Por defecto no se borra nada. En producción definir `TELEMETRY_RETENTION_DAYS`,
  `EVENT_RETENTION_DAYS`, `CHANGE_RETENTION_DAYS`, `ALERT_RETENTION_DAYS` (solo resueltas),
  `DETECTION_RETENTION_DAYS` y `RISK_HISTORY_RETENTION_DAYS` según la política de la empresa.
- La auditoría (`audit_events`) **no se purga**: es el registro de quién hizo qué. Los
  incidentes y sus notas tampoco.
- Telemetría: ~1 muestra por agente y minuto (~0,5 KB): 1000 agentes x 90 días ≈ 65 GB con
  índices. Eventos: muy variable (Windows con mucho ruido); vigilar con
  `SELECT pg_size_pretty(pg_total_relation_size('system_events'))`.
- Copias: el tamaño de `pg_dump` comprimido suele ser 10-25 % de la base.
- Disco de PostgreSQL por debajo del 20 % libre: ampliar o reducir retención antes de llegar
  al 10 %.

## 9. Fuera del alcance de esta fase

Inventario de hardware detallado, SNMP/LLDP/topología, inteligencia de amenazas, respuesta
automática y cualquier dependencia de nube. Ver la hoja de ruta en `README.md`.
