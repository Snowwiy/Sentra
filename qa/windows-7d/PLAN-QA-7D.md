# Plan de QA conjunto de la Fase 7D (7D.1 + 7D.2) en Windows 11

Una sola validación para las dos entregas, sobre el árbol con 7D.1 y 7D.2 aplicados. Cada
paso indica qué se espera; anotar el resultado (PASS, FAIL o NO EJECUTADO, con el motivo) en
la tabla final y copiarla al TEST-RESULTS de 7D.

Reglas: nunca la base productiva `sentra` para pruebas destructivas; los tests usan
`sentra_test`; las migraciones de prueba, una base aislada (`sentra_qa_7d`). No teclear la
contraseña del superusuario `postgres`. Los servidores de carga son de laboratorio.

## 0. Preparación

1. Copia de seguridad de la base real (docs/backup-restore.md) antes de migrarla.
2. Crear la base vacía `sentra_qa_7d` con dueño `sentra` (pgAdmin, o `createdb` si el rol
   tiene CREATEDB).
3. Un servidor de laboratorio por HTTPS (Caddy de `deploy/` con la CA interna) en una
   máquina o puerto distinto del de desarrollo, con `ADMIN_API_KEY` propia del laboratorio.
4. Un equipo (o VM) con el agente 0.7.1 instalado como servicio contra ese servidor.

## 1. Comprobaciones estáticas y suites

```powershell
.\qa\windows-7d\run-checks-7d.ps1          # unos 110 min con el backend completo
```

Esperado: todos los pasos `exit=0`. Incluye ruff, ruff format, mypy (win32, linux y darwin
en el agente), pytest de backend/agente/sensor, lint, typecheck, vitest con el Node local y
con Node 22, build, `npm audit` (todas y producción), `pip-audit` y repo-hygiene.

## 2. Migraciones 0050 → 0051 → 0052, rollback y restauración

```powershell
$env:PGPASSWORD = "<contraseña del rol sentra>"
.\qa\windows-7d\test-migrations-7d.ps1 -Database sentra_qa_7d
Remove-Item Env:PGPASSWORD
```

Esperado: `PASS` al final. Luego, sobre la base real (tras la copia del paso 0):
`alembic upgrade head` (0050 o 0051 → 0052) y `alembic current` = `0052 (head)`.

## 3. Matriz H01-H08 (positivo y negativo)

| Id | Prueba positiva | Prueba negativa |
|----|-----------------|-----------------|
| H01 | Un agente nuevo se registra con un token de instalación; una autorización de recuperación emitida por un admin restablece un equipo reinstalado | Registrar con un token ordinario y el `agent_id` de un agente existente: 403 `agent_recovery_required`; la credencial original sigue funcionando |
| H02 | Un analista con `telemetry:read` ve línea de comando y hashes en detecciones e incidentes | Un viewer ve la detección sin esos campos (`content_withheld`); la búsqueda por SHA-256 no devuelve resultados protegidos |
| H03 | Un admin ve la salida completa de una ejecución de herramienta con detalle de endpoint | Tras quitar `telemetry:read` a un usuario, la misma ejecución aparece solo con metadatos; enlazarla a un caso da 403 |
| H04 | El agente 0.7.1 habla por `https://` con la CA interna (`ca_bundle`) | `api_url = "http://<IP remota>"`: el agente no arranca y el instalador lo rechaza sin parar el servicio; un agente 0.6.x por HTTP aparece marcado como inseguro |
| H05 | Tráfico normal sin redirecciones | Poner en el proxy una redirección 301/307 de `/api/v1/agents/heartbeat`: el agente registra `RedirectError` y no sigue el destino |
| H06 | Un agente sano sigue enviando mientras otro satura (sección 4) | El agente ruidoso recibe 429 con `Retry-After`; un token inválido da 401 sin gastar cupo de nadie |
| H07 | `npm ls minimatch` muestra solo 11.0.5 (override); `npm audit` = 0 | `npm audit fix --force` no se ha usado (el lockfile solo cambia minimatch y sus dependientes) |
| H08 | Un PR de prueba ejecuta los ocho checks y la fusión queda bloqueada hasta que estén en verde | Los pushes directos, el force-push y el borrado de `main` son rechazados (docs/github-rulesets.md, sección 5) |

## 4. Cuotas de ingesta con varios agentes (H06)

Contra el servidor de laboratorio, con límites bajos en su `.env` para que se note pronto:

```
AGENT_QUOTA_EVENTS_PER_MINUTE=2500
AGENT_QUOTA_BURST_MINUTES=1
RATE_LIMIT_BACKEND=database
```

Arrancarlo con **dos procesos** (`uvicorn ... --workers 2`) para probar el cupo compartido.

```powershell
$s = Read-Host "Clave admin del LABORATORIO" -AsSecureString
$env:SENTRA_ADMIN_KEY = [System.Net.NetworkCredential]::new("", $s).Password
py qa\windows-7d\qa_ingest_quota_load.py --server https://sentra-lab.lan --ca-file ca.pem --healthy 4 --seconds 60
Remove-Item Env:SENTRA_ADMIN_KEY
```

Esperado: código de salida 0 y en `checks` todo `true`: el ruidoso recibe 429
`agent_events` con `Retry-After`, su heartbeat sigue aceptado, los sanos no reciben 429 de su
cuota y el reenvío de un lote ya aceptado da `stored = 0`. En la consola: aviso «agentes han
superado su cuota» en Agentes y «Cuota de ingesta: Limitado …» en la ficha del ruidoso. En
`/api/v1/metrics` (si está activo): `sentra_ingest_quota_rejections_total`. Archivar después
los activos `qa7d2-*`.

## 5. Agente real 0.7.1 por HTTPS

| Paso | Esperado |
|------|----------|
| Instalar con `agent\packaging\windows\install-sentra-agent.ps1`, `https://` y la CA interna | Servicio en marcha, activo `online`, transporte `https` |
| Desconectar la red 5 min y reconectar | `agent-buffer.sqlite` crece; al volver se vacía en orden y no hay huecos en la telemetría |
| Bajar en el laboratorio `AGENT_QUOTA_REQUESTS_PER_MINUTE=5` y reiniciar la API | Log del agente: «API throttled the agent» con la espera; el activo sigue `online`; no hay re-registro ni revocación; al restaurar el límite, se pone al día sin duplicados |
| «Rotar credencial…» desde la consola | El agente rota en el siguiente heartbeat; la credencial anterior deja de valer (401) |
| Reinstalar el equipo con un token ordinario | 403 `agent_recovery_required`; con una autorización de recuperación, se recupera la misma identidad |
| `api_url` http a otra máquina | El agente no arranca y lo explica |
| Redirección en el proxy | `RedirectError` en el log, sin seguirla |

## 6. Funcional del SOC (regresión)

Dashboard, Activos (lista, ficha, riesgo), Detecciones (lista, detalle, excepciones), Incidentes
(crear, tareas, notas), Consola (herramientas, asistente de IA si está activado), Informes
(generar y descargar con verificación SHA-256), Red/topología, Mantenimiento y Agentes
(transporte, rotación, recuperación, cuota). Con un usuario admin, uno analista y uno viewer.

## 7. Rendimiento y resiliencia

| Prueba | Esperado |
|--------|----------|
| `python ..\qa\perf_endpoint.py` desde `backend\` (contra `sentra_test`) | Cifras del mismo orden que 6E/7A |
| Carga de la sección 4 durante 10 min | Latencia del dashboard sin degradación apreciable; CPU de PostgreSQL razonable |
| Parar PostgreSQL 30 s durante la carga | Las rutas de ingesta responden 503 (cuota cerrada en fallo); al volver, todo se recupera sin reiniciar la API ni los agentes |
| `python -m app.cli capacity-report` | Tamaños de tabla y días de retención; ningún dato sensible |
| `python -m app.cli purge-old-data` (en laboratorio) | Evento de auditoría `retention_purge` con los recuentos |

## 8. Resultados

| Sección | Resultado | Notas |
|---------|-----------|-------|
| 1. Estático y suites | | |
| 2. Migraciones | | |
| 3. H01-H08 | | |
| 4. Cuotas multiagente | | |
| 5. Agente real | | |
| 6. SOC | | |
| 7. Rendimiento | | |
